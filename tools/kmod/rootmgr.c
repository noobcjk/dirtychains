// SPDX-License-Identifier: GPL-2.0
/*
 * rootmgr.c —— 内核通信通道（仿 KernelSU 的匿名 inode 设计）
 *
 * 一、通信载体是匿名 inode，不是设备节点
 *   模块不会创建 /dev/xxx，也不会注册 /proc/xxx。真正的通道是：
 *
 *       anon_inode_getfile("[ksu_driver]", &rootmgr_fops, NULL, O_RDWR)
 *
 *   它没有路径、不挂在任何文件系统上，`ls /dev` 看不到，open(2) 也没法按
 *   名字打开。用户态唯一的入口就是**先拿到一个 fd**，之后 read/ioctl 都
 *   在这个 fd 上做。拿不到 fd 就完全碰不到驱动。
 *
 * 二、fd 怎么来：reboot(2) 的一对暗号
 *   用户态调用：
 *
 *       syscall(SYS_reboot, 0xDEADBEEF, 0xCAFEBABE, 0, NULL);
 *
 *   这两个数不是真想重启 —— 内核里 reboot 会先校验 magic1/magic2 是不是
 *   LINUX_REBOOT_MAGIC1/MAGIC2，对不上直接返回 -EINVAL，没有任何副作用。
 *   模块用一个 kretprobe 挂在 __x64_sys_reboot / __arm64_sys_reboot 上：
 *
 *     - entry  阶段：把 magic1、magic2 记到 ri->data 里；
 *     - return 阶段：发现是暗号，就给 current 装一个指向 [ksu_driver] 的
 *       fd，再把系统调用的返回值改写成这个 fd。
 *
 *   于是用户态看到的就是 reboot() 返回了一个 fd（负数表示失败）。
 *
 *   为什么用 kretprobe 而不是在入口用 kprobe：
 *   入口处要"吞掉"整个系统调用，得跳过原函数、伪造返回地址，栈和寄存器
 *   都不好收拾；挂在返回点只动返回值寄存器 ax / x0 一个字段，原函数该走
 *   的路照走（返回 -EINVAL），我们把它替换成 fd，最干净。
 *
 * 三、fd 要缓存
 *   每拿一次 fd 都要走一次异常 + 装 fd，完全没必要。用户态拿到后存进全局
 *   变量，后面所有通信都用同一个 fd。见 rootmgr_fd.h 里的 rootmgr_fd()。
 *
 * 构建 / 使用：
 *   make rootmgr
 *   sudo insmod rootmgr.ko
 *   ./rootmgr_fd_demo            # 演示拿 fd、缓存、ping
 *   sudo rmmod rootmgr
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/anon_inodes.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/ioctl.h>

#define ROOTMGR_VERSION "2.0"
#define ROOTMGR_NAME    "[ksu_driver]"

/* 用户态 reboot(2) 用的暗号 */
#define KSU_INSTALL_MAGIC1 0xDEADBEEF
#define KSU_INSTALL_MAGIC2 0xCAFEBABE

/* ioctl 命令（和用户态 rootmgr_fd.h 保持一致） */
#define ROOTMGR_IOCTL_MAGIC 'R'
#define ROOTMGR_CMD_PING    _IO(ROOTMGR_IOCTL_MAGIC, 0)
#define ROOTMGR_CMD_VERSION _IOR(ROOTMGR_IOCTL_MAGIC, 1, char[32])

/* -------------------------------------------------------------------------
 * 1. 匿名 inode 上的文件操作
 * ---------------------------------------------------------------------- */

static ssize_t rootmgr_read(struct file *filp, char __user *buf,
			    size_t count, loff_t *ppos)
{
	char tmp[64];
	int len;

	(void)filp;
	(void)ppos;

	/* 所有 fd 共享同一份 file，f_pos 不可靠，每次都从头给一遍 */
	len = scnprintf(tmp, sizeof(tmp), "rootmgr %s\n", ROOTMGR_VERSION);
	if ((size_t)len > count)
		len = count;
	if (copy_to_user(buf, tmp, len))
		return -EFAULT;

	return len;
}

static long rootmgr_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void __user *uarg = (void __user *)arg;

	(void)filp;

	switch (cmd) {
	case ROOTMGR_CMD_PING:
		return 0;

	case ROOTMGR_CMD_VERSION: {
		char ver[32];
		int len = scnprintf(ver, sizeof(ver), "%s", ROOTMGR_VERSION);

		if (!uarg)
			return -EINVAL;
		if (copy_to_user(uarg, ver, len + 1))
			return -EFAULT;
		return 0;
	}

	default:
		return -ENOTTY;
	}
}

static int rootmgr_release(struct inode *inode, struct file *filp)
{
	(void)inode;
	(void)filp;

	/* 对应 install 时的 try_module_get，保证还有 fd 时 rmmod 会被拒绝 */
	module_put(THIS_MODULE);
	return 0;
}

static const struct file_operations rootmgr_fops = {
	.owner          = THIS_MODULE,
	.read           = rootmgr_read,
	.unlocked_ioctl = rootmgr_ioctl,
#if IS_ENABLED(CONFIG_COMPAT)
	.compat_ioctl   = rootmgr_ioctl,
#endif
	.release        = rootmgr_release,
	.llseek         = noop_llseek,
};

/* -------------------------------------------------------------------------
 * 2. 给当前进程装一个指向 [ksu_driver] 的 fd
 * ---------------------------------------------------------------------- */

/*
 * 模块加载时就把这个匿名 inode 建好，之后每次只是 get_file() 加一个引用
 * 再 fd_install()。这样在 kretprobe 的钩子里完全不分配内存 —— 钩子跑在
 * 关中断的异常上下文，kmalloc(GFP_KERNEL) 会触发 "sleeping function" 警告。
 */
static struct file *rootmgr_file;

static int rootmgr_install_fd(void)
{
	int fd;

	if (!rootmgr_file)
		return -ENODEV;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		module_put(THIS_MODULE);
		return fd;
	}

	get_file(rootmgr_file);
	fd_install(fd, rootmgr_file);
	return fd;
}

/* -------------------------------------------------------------------------
 * 3. reboot(2) 上的钩子：识别暗号并改返回值
 * ---------------------------------------------------------------------- */

#if defined(CONFIG_X86_64)
#define ROOTMGR_REBOOT_SYMBOL "__x64_sys_reboot"
#define ROOTMGR_ARG0(r)       ((unsigned long)(r)->di)
#define ROOTMGR_ARG1(r)       ((unsigned long)(r)->si)
#elif defined(CONFIG_ARM64)
#define ROOTMGR_REBOOT_SYMBOL "__arm64_sys_reboot"
#define ROOTMGR_ARG0(r)       ((unsigned long)(r)->regs[0])
#define ROOTMGR_ARG1(r)       ((unsigned long)(r)->regs[1])
#else
#error "rootmgr: 只支持 x86_64 / arm64"
#endif

#if IS_ENABLED(CONFIG_KRETPROBES)

struct reboot_args {
	unsigned int magic1;
	unsigned int magic2;
	bool matched;
};

static int reboot_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct reboot_args *a = (struct reboot_args *)ri->data;

	a->magic1 = (unsigned int)ROOTMGR_ARG0(regs);
	a->magic2 = (unsigned int)ROOTMGR_ARG1(regs);
	a->matched = (a->magic1 == KSU_INSTALL_MAGIC1 &&
		      a->magic2 == KSU_INSTALL_MAGIC2);

	return 0;
}

static int reboot_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct reboot_args *a = (struct reboot_args *)ri->data;
	int fd;

	if (!a->matched)
		return 0;

	fd = rootmgr_install_fd();
	if (fd < 0) {
		pr_err("rootmgr: install fd failed: %d\n", fd);
		return 0;
	}

	/* 把 reboot() 原本的 -EINVAL 换成 fd，用户态直接拿到句柄 */
	regs_set_return_value(regs, fd);
	pr_info("rootmgr: pid %d got fd %d\n", task_pid_nr(current), fd);

	return 0;
}

static struct kretprobe reboot_krp = {
	.kp.symbol_name = ROOTMGR_REBOOT_SYMBOL,
	.entry_handler  = reboot_entry,
	.handler        = reboot_return,
	.data_size      = sizeof(struct reboot_args),
	.maxactive      = 64,
};

#endif /* CONFIG_KRETPROBES */

/* -------------------------------------------------------------------------
 * 4. 模块出入口
 * ---------------------------------------------------------------------- */

static int __init rootmgr_init(void)
{
#if !IS_ENABLED(CONFIG_KRETPROBES)
	pr_err("rootmgr: 内核没开 CONFIG_KRETPROBES，拿不到 fd，模块不加载\n");
	return -EOPNOTSUPP;
#else
	int ret;

	rootmgr_file = anon_inode_getfile(ROOTMGR_NAME, &rootmgr_fops, NULL,
					  O_RDWR | O_CLOEXEC);
	if (IS_ERR(rootmgr_file)) {
		ret = PTR_ERR(rootmgr_file);
		rootmgr_file = NULL;
		pr_err("rootmgr: anon_inode_getfile failed: %d\n", ret);
		return ret;
	}

	ret = register_kretprobe(&reboot_krp);
	if (ret) {
		pr_err("rootmgr: register_kretprobe(%s) failed: %d\n",
		       ROOTMGR_REBOOT_SYMBOL, ret);
		fput(rootmgr_file);
		rootmgr_file = NULL;
		return ret;
	}

	pr_info("rootmgr %s loaded: driver is %s, get fd via reboot(%#x, %#x)\n",
		ROOTMGR_VERSION, ROOTMGR_NAME,
		KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2);
	return 0;
#endif
}

static void __exit rootmgr_exit(void)
{
#if IS_ENABLED(CONFIG_KRETPROBES)
	unregister_kretprobe(&reboot_krp);
#endif
	if (rootmgr_file) {
		fput(rootmgr_file);
		rootmgr_file = NULL;
	}
	pr_info("rootmgr: unloaded\n");
}

module_init(rootmgr_init);
module_exit(rootmgr_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("rootmgr: anon-inode channel reachable only through a reboot(2) magic fd");
MODULE_VERSION(ROOTMGR_VERSION);
