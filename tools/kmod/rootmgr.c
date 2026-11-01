// SPDX-License-Identifier: GPL-2.0
/*
 * rootmgr.c —— 内核通信通道（仿 KernelSU 的匿名 inode + ioctl 设计）
 *
 * 一、通信载体是匿名 inode，不是设备节点
 *   模块不会创建 /dev/xxx，也不会注册 /proc/xxx。真正的通道是：
 *
 *       anon_inode_getfile("[ksu_driver]", &rootmgr_fops, NULL, O_RDWR)
 *
 *   它没有路径、不挂在任何文件系统上，`ls /dev` 看不到，open(2) 也没法按
 *   名字打开。用户态唯一的入口就是**先拿到一个 fd**，之后所有操作都在
 *   这个 fd 上做。拿不到 fd 就完全碰不到驱动。
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
 *   注意 fops 里没有 read/write：拿 fd 是 reboot 的事，通信只有 ioctl 一条路。
 *
 *   于是用户态看到的就是 reboot() 返回了一个 fd（负数表示失败）。
 *
 *   为什么用 kretprobe 而不是在入口用 kprobe：
 *   入口处要"吞掉"整个系统调用，得跳过原函数、伪造返回地址，栈和寄存器
 *   都不好收拾；挂在返回点只动返回值寄存器 ax / x0 一个字段，原函数该走
 *   的路照走（返回 -EINVAL），我们把它替换成 fd，最干净。
 *
 * 三、拿到 fd 之后，全部通信都是 ioctl
 *
 *       ioctl(fd, _IOC(..., 'K', nr, size), arg)
 *
 *   魔术字符固定是 'K'，和 KernelSU 的 supercall 保持一致：
 *
 *     nr 0  PING         探活，arg 忽略
 *     nr 1  GRANT_ROOT   给**调用者自己**提权到 root
 *     nr 2  GET_INFO     读通道信息（版本 / uid / 是否 root / 是否 manager）
 *     nr 3  GET_VERSION  只读版本号（__u32）
 *     nr 4  GRANT_PID    给指定 pid 提权（管理器用，arg 指向 __s32）
 *     nr 5  SET_APP_PROFILE  写一条程序授权（ino + dev + state）
 *     nr 6  GET_APP_PROFILE  读调用者自己的授权状态（ino + dev + state）
 *     nr 7  CLEAR_APP_PROFILE 清空整张表（管理器全量同步用）
 *
 *   分派时只比对 _IOC_TYPE + _IOC_NR，不比对 size 字段 —— 32 位进程走
 *   compat_ioctl 进来时 sizeof(struct) 会变，整串 cmd 就对不上了。
 *
 * 四、提权做到什么程度
 *   escape_to_root() 用 prepare_kernel_cred() 造一份全新 cred，把 uid/gid
 *   全置 0、cap_* 全开，再 commit_creds() 换掉当前进程的 real_cred/cred。
 *   这一层只改进程凭证，不动 SELinux 域：如果当前域本身被策略卡着，
 *   提权后仍然可能被 avc deny 拦，需要在策略侧放行（后续再补）。
 *
 * 五、谁能提权：三层判断，从硬到软
 *
 *   1) 程序被显式标成 DENY —— 谁都提不了，包括管理器自己。这一层是硬约束，
 *      用来"收回"一条已经被信任的程序。
 *   2) 程序被标成 ROOT —— 允许。识别方式是 exe 文件的 (i_ino, i_sb->s_dev)，
 *      不是路径字符串：换名字、软链接、替换文件名都骗不过去，绑的是 inode。
 *   3) 没记录 —— 只有 manager 能提；manager 的判据见模块参数 allow_uid
 *      （-1 要求 CAP_SYS_ADMIN，>=0 只认该 uid）。
 *
 *   授权表由管理器用 SET_APP_PROFILE 写入（最多 ROOTMGR_MAX_APPS 条），
 *   存在内核内存里，rmmod 后清空 —— 持久化交给用户态的 policy 文件，
 *   每次加载模块后由管理器重新灌一遍。
 *
 * 六、授权过的程序，执行时直接变成 root（exec 钩子）
 *   上面第五节只回答"这个进程能不能主动调 GRANT_ROOT"，程序本身不会自动
 *   变 root。要让授权真的有用，还得在 exec 这一步动手：
 *
 *     kprobe 挂在 security_bprm_check() 上（fs/exec.c 的执行路径里，
 *     bprm->file 已经打开、bprm->cred 已经备好，还没 commit）。
 *
 *   钩子里拿 bprm->file 的 (i_ino, s_dev) 去查授权表：
 *
 *     - 命中 ROOT  → 直接把 bprm->cred 改成 uid/gid 全 0 + 全 capability，
 *                    并把 bprm->secureexec 置 1（让动态链接器进入 AT_SECURE
 *                    模式，丢掉 LD_PRELOAD / LD_LIBRARY_PATH 这类注入面）；
 *                    begin_new_exec() 随后 commit_creds(bprm->cred)，
 *                    新程序从第一条用户态指令起就是 root。
 *     - 其他        → 什么都不做，行为跟没装模块完全一样。
 *
 *   选 security_bprm_check 而不是"exec 返回后再给 current 换 cred"：
 *   后者要调 prepare_kernel_cred()，而 kprobe 上下文里不能睡眠分配内存；
 *   改 bprm->cred 是纯内存写，不分配、不加锁睡眠，最稳。
 *
 *   注意两点：
 *     1) 语义等于"给这个文件加了个 setuid 位"。如果授权的是 sh / python
 *        这类通用解释器，任何人执行它都会拿到 root —— 管理器里给这类程序
 *        点 root 之前先想清楚。
 *     2) 只加不减：DENY 表示"不给 root"，不会把父进程已经继承下来的 root
 *        收回去。
 *   整个钩子可以用模块参数 exec_root=0 关掉。
 *
 * 构建 / 使用：
 *   make rootmgr
 *   sudo insmod rootmgr.ko [allow_uid=10123]
 *   ./rootmgr_fd_demo            # 演示拿 fd、缓存、ioctl 通信、提权
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
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <linux/pid.h>
#include <linux/version.h>
#include <linux/ioctl.h>
#include <linux/spinlock.h>
#include <linux/binfmts.h>

#define ROOTMGR_VERSION_STR "2.4"
#define ROOTMGR_VERSION_NUM 24000
#define ROOTMGR_NAME        "[ksu_driver]"

/* 用户态 reboot(2) 用的暗号 */
#define KSU_INSTALL_MAGIC1 0xDEADBEEF
#define KSU_INSTALL_MAGIC2 0xCAFEBABE

/* -------------------------------------------------------------------------
 * ioctl 协议：魔术字符 'K'（与用户态 rootmgr_fd.h 完全一致）
 * ---------------------------------------------------------------------- */

#define KSU_IOCTL_MAGIC 'K'

#define KSU_NR_PING         0
#define KSU_NR_GRANT_ROOT   1
#define KSU_NR_GET_INFO     2
#define KSU_NR_GET_VERSION  3
#define KSU_NR_GRANT_PID    4
#define KSU_NR_SET_APP_PROFILE 5
#define KSU_NR_GET_APP_PROFILE 6
#define KSU_NR_CLEAR_APP_PROFILE 7

/* GET_INFO 的载荷。前两个字段和 KernelSU 对齐，后面是自定的扩展。 */
struct ksu_get_info_cmd {
	__u32 version;      /* ROOTMGR_VERSION_NUM */
	__u32 flags;        /* bit0 已 root，bit1 是 manager */
	__u32 uid;          /* 调用者 real uid */
	__u32 euid;         /* 调用者 effective uid */
	__s32 manager_uid;  /* allow_uid，-1 表示按能力判断 */
	__u32 reserved;
};

#define KSU_FLAG_ROOT    (1u << 0)
#define KSU_FLAG_MANAGER (1u << 1)
#define KSU_FLAG_AUTOEXEC (1u << 2)   /* exec 钩子已挂上，授权程序启动即 root */

/*
 * 一条程序授权。程序的身份是 (ino, dev)：exe 文件的 inode 号 +
 * 它所在 superblock 的设备号（new_encode_dev 编码，和用户态 stat().st_dev
 * 一致）。不用路径，是因为路径可以被改名、被软链接、被替换。
 *
 * state = ASK 时表示"删除这条记录"。
 */
struct ksu_app_entry {
	__u64 ino;
	__u32 dev;
	__s32 state;    /* KSU_POLICY_ASK / ROOT / DENY */
	__u32 uid;      /* 记录归属用户，只用于展示 */
	__u32 reserved;
};

#define KSU_POLICY_ASK  0
#define KSU_POLICY_ROOT 1
#define KSU_POLICY_DENY 2

#define KSU_IOCTL_PING        _IOC(_IOC_NONE, KSU_IOCTL_MAGIC, KSU_NR_PING, 0)
#define KSU_IOCTL_GRANT_ROOT  _IOC(_IOC_NONE, KSU_IOCTL_MAGIC, KSU_NR_GRANT_ROOT, 0)
#define KSU_IOCTL_GET_INFO    _IOC(_IOC_READ, KSU_IOCTL_MAGIC, KSU_NR_GET_INFO, \
				   sizeof(struct ksu_get_info_cmd))
#define KSU_IOCTL_GET_VERSION _IOC(_IOC_READ, KSU_IOCTL_MAGIC, KSU_NR_GET_VERSION, \
				   sizeof(__u32))
#define KSU_IOCTL_GRANT_PID   _IOC(_IOC_WRITE, KSU_IOCTL_MAGIC, KSU_NR_GRANT_PID, \
				   sizeof(__s32))
#define KSU_IOCTL_SET_APP_PROFILE _IOC(_IOC_WRITE, KSU_IOCTL_MAGIC, \
				       KSU_NR_SET_APP_PROFILE, \
				       sizeof(struct ksu_app_entry))
#define KSU_IOCTL_GET_APP_PROFILE _IOC(_IOC_READ | _IOC_WRITE, KSU_IOCTL_MAGIC, \
				       KSU_NR_GET_APP_PROFILE, \
				       sizeof(struct ksu_app_entry))
#define KSU_IOCTL_CLEAR_APP_PROFILE _IOC(_IOC_NONE, KSU_IOCTL_MAGIC, \
					 KSU_NR_CLEAR_APP_PROFILE, 0)

/* allow_uid：-1 = 只认 CAP_SYS_ADMIN；>=0 = 只认这个 uid */
static int allow_uid = -1;
module_param(allow_uid, int, 0644);
MODULE_PARM_DESC(allow_uid, "manager uid：没登记过的程序只有它才能提权，-1 表示要求 CAP_SYS_ADMIN");

/* exec_root：1 = 被标成 ROOT 的程序 exec 时自动以 root 运行；0 = 只保留手动 GRANT_ROOT */
static int exec_root = 1;
module_param(exec_root, int, 0644);
MODULE_PARM_DESC(exec_root, "1 = 授权为 root 的程序执行时自动提权（等效 setuid），0 = 关闭 exec 钩子");

/* 统计 */
static atomic_t grant_count = ATOMIC_INIT(0);
static atomic_t exec_grant_count = ATOMIC_INIT(0);

/* 前置声明：第 1 节的凭据操作要用到第 2 节的授权表 */
static int task_exe_id(struct task_struct *t, u64 *ino, u32 *dev);
static int app_lookup(u64 ino, u32 dev);

/* exec 钩子是否真的挂上了（内核没这个符号时退化成纯手动提权） */
static bool exec_hook_ok;

/* -------------------------------------------------------------------------
 * 1. 凭据：造一份 root cred，换给目标 task
 * ---------------------------------------------------------------------- */

static struct cred *make_root_cred(struct task_struct *daemon)
{
	struct cred *new;

	/*
	 * 6.3 起 prepare_kernel_cred(NULL) 会 WARN 并返回 NULL，必须传 task；
	 * 5.x 传 NULL 表示复制 init_cred。两条路都能拿到一份可用的 cred，
	 * 下面的显式赋值保证不管哪条路，结果都是 uid=0 + 全 capability。
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	new = prepare_kernel_cred(daemon);
#else
	new = prepare_kernel_cred(NULL);
	(void)daemon;
#endif
	if (!new)
		return NULL;

	new->uid = GLOBAL_ROOT_UID;
	new->euid = GLOBAL_ROOT_UID;
	new->suid = GLOBAL_ROOT_UID;
	new->fsuid = GLOBAL_ROOT_UID;
	new->gid = GLOBAL_ROOT_GID;
	new->egid = GLOBAL_ROOT_GID;
	new->sgid = GLOBAL_ROOT_GID;
	new->fsgid = GLOBAL_ROOT_GID;

	new->securebits = SECUREBITS_DEFAULT;
	new->cap_inheritable = CAP_EMPTY_SET;
	new->cap_permitted = CAP_FULL_SET;
	new->cap_effective = CAP_FULL_SET;
	new->cap_bset = CAP_FULL_SET;
	new->cap_ambient = CAP_EMPTY_SET;

	return new;
}

/* 给自己提权：走 commit_creds，最正规的一条路 */
static int escape_to_root(void)
{
	struct cred *new;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
	int ret;
#endif

	if (uid_eq(current_uid(), GLOBAL_ROOT_UID) &&
	    uid_eq(current_euid(), GLOBAL_ROOT_UID))
		return 0;               /* 已经是 root，什么都不用做 */

	/*
	 * commit_creds() 里 BUG_ON(task->cred != old)：如果当前进程正处在
	 * override_creds() 区间（cred 和 real_cred 不相等），直接拒绝，
	 * 免得把内核打崩。
	 */
	if (current->cred != current->real_cred)
		return -EBUSY;

	new = make_root_cred(current);
	if (!new)
		return -ENOMEM;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
	commit_creds(new);              /* 6.5 起改成返回 void */
#else
	ret = commit_creds(new);
	if (ret) {
		put_cred(new);
		return ret;
	}
#endif

	atomic_inc(&grant_count);
	pr_info("rootmgr: pid %d (%s) -> root\n",
		task_pid_nr(current), current->comm);
	return 0;
}

/*
 * 给别的进程提权。commit_creds() 只作用于 current，所以这里只能直接换
 * 目标 task 的 real_cred / cred 指针 —— 和 KernelSU 老版 do_give 的做法
 * 一致。注意：目标进程如果已经缓存了 uid（比如 libc 里的 getuid 结果），
 * 它自己不一定立刻感知，重新 getuid() 或下一轮系统调用才会看到 0。
 */
static int grant_task(struct task_struct *t)
{
	struct cred *new;
	const struct cred *old_r, *old_c;

	new = make_root_cred(t);
	if (!new)
		return -ENOMEM;

	rcu_read_lock();
	old_r = t->real_cred;
	old_c = t->cred;
	get_cred(new);                  /* 两个指针各持一份引用 */
	rcu_assign_pointer(t->real_cred, new);
	rcu_assign_pointer(t->cred, new);
	rcu_read_unlock();

	put_cred(old_r);
	put_cred(old_c);

	atomic_inc(&grant_count);
	pr_info("rootmgr: pid %d (%s) granted by pid %d\n",
		task_pid_nr(t), t->comm, task_pid_nr(current));
	return 0;
}

static int escape_pid(pid_t pid)
{
	struct task_struct *t;
	int ret;

	rcu_read_lock();
	t = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (t)
		get_task_struct(t);
	rcu_read_unlock();

	if (!t)
		return -ESRCH;

	/* 不给内核线程换 cred：它们的 cred 是共享的 init_cred，改了会连累一片 */
	if (t->flags & PF_KTHREAD) {
		put_task_struct(t);
		return -EINVAL;
	}

	/* 被显式标成 DENY 的程序，谁都不能替它开这个口子 */
	{
		u64 ino;
		u32 dev;

		if (task_exe_id(t, &ino, &dev) == 0 &&
		    app_lookup(ino, dev) == KSU_POLICY_DENY) {
			put_task_struct(t);
			return -EPERM;
		}
	}

	ret = grant_task(t);
	put_task_struct(t);
	return ret;
}

/* -------------------------------------------------------------------------
 * 2. 授权表：程序身份 = exe 的 (ino, dev)
 * ---------------------------------------------------------------------- */

#define ROOTMGR_MAX_APPS 256

struct app_rec {
	u64 ino;
	u32 dev;
	int state;
	kuid_t uid;
};

static struct app_rec app_table[ROOTMGR_MAX_APPS];
static int app_count;

/*
 * 用自旋锁而不是 mutex：这张表不只在 ioctl（进程上下文）里查，exec 钩子
 * 也会查，而 kprobe 的 pre_handler 跑在关抢占的上下文里，mutex_lock 可能
 * 睡眠 —— 那会直接触发 "sleeping function called from invalid context"。
 * 临界区只有一次线性扫描，自旋锁完全够。
 */
static DEFINE_SPINLOCK(app_lock);

/* 某个 task 的可执行文件身份；内核线程、刚 exec 到一半的进程没有 exe_file */
static int task_exe_id(struct task_struct *t, u64 *ino, u32 *dev)
{
	struct file *exe;
	struct inode *i;
	struct mm_struct *mm = t->mm;

	if (!mm)
		return -ENOENT;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	mmap_read_lock(mm);
#else
	down_read(&mm->mmap_sem);
#endif
	exe = mm->exe_file;
	if (exe)
		get_file(exe);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	mmap_read_unlock(mm);
#else
	up_read(&mm->mmap_sem);
#endif

	if (!exe)
		return -ENOENT;

	i = file_inode(exe);
	*ino = i->i_ino;
	*dev = new_encode_dev(i->i_sb->s_dev);
	fput(exe);

	return 0;
}

static int current_exe_id(u64 *ino, u32 *dev)
{
	return task_exe_id(current, ino, dev);
}

/* 查表；未记录返回 KSU_POLICY_ASK */
static int app_lookup(u64 ino, u32 dev)
{
	unsigned long flags;
	int i, state = KSU_POLICY_ASK;

	spin_lock_irqsave(&app_lock, flags);
	for (i = 0; i < app_count; i++) {
		if (app_table[i].ino == ino && app_table[i].dev == dev) {
			state = app_table[i].state;
			break;
		}
	}
	spin_unlock_irqrestore(&app_lock, flags);

	return state;
}

/* 清空整张表。管理器做全量同步时先清后灌，省得算差异。 */
static void app_clear(void)
{
	unsigned long flags;

	spin_lock_irqsave(&app_lock, flags);
	app_count = 0;
	spin_unlock_irqrestore(&app_lock, flags);
}

/* 写一条记录；state == ASK 表示删除 */
static int app_set(const struct ksu_app_entry *e)
{
	unsigned long flags;
	int i;

	if (e->state != KSU_POLICY_ROOT && e->state != KSU_POLICY_DENY &&
	    e->state != KSU_POLICY_ASK)
		return -EINVAL;

	spin_lock_irqsave(&app_lock, flags);

	for (i = 0; i < app_count; i++) {
		if (app_table[i].ino == e->ino && app_table[i].dev == e->dev) {
			if (e->state == KSU_POLICY_ASK) {
				/* 删除：用最后一条填坑，顺序不重要 */
				app_table[i] = app_table[app_count - 1];
				app_count--;
			} else {
				app_table[i].state = e->state;
				app_table[i].uid = current_uid();
			}
			spin_unlock_irqrestore(&app_lock, flags);
			return 0;
		}
	}

	if (e->state == KSU_POLICY_ASK) {
		spin_unlock_irqrestore(&app_lock, flags);
		return 0;                       /* 本来就没有，删也算成功 */
	}

	if (app_count >= ROOTMGR_MAX_APPS) {
		spin_unlock_irqrestore(&app_lock, flags);
		return -ENOSPC;
	}

	app_table[app_count].ino = e->ino;
	app_table[app_count].dev = e->dev;
	app_table[app_count].state = e->state;
	app_table[app_count].uid = current_uid();
	app_count++;

	spin_unlock_irqrestore(&app_lock, flags);

	pr_info("rootmgr: app %#llx/%#x -> %s (%d entries)\n",
		(unsigned long long)e->ino, e->dev,
		e->state == KSU_POLICY_ROOT ? "root" : "deny", app_count);
	return 0;
}

/* -------------------------------------------------------------------------
 * 3. 权限判断
 * ---------------------------------------------------------------------- */

static bool is_manager(void)
{
	if (allow_uid >= 0)
		return uid_eq(current_uid(), KUIDT_INIT((uid_t)allow_uid));

	return capable(CAP_SYS_ADMIN);
}

/*
 * GRANT_ROOT 的总闸门。顺序很重要：
 *   - DENY 是硬约束，先判，manager 也挡；
 *   - ROOT 放行；
 *   - 没记录时才回落到 manager 判断。
 */
static bool may_escalate(void)
{
	u64 ino;
	u32 dev;
	int state;

	if (current_exe_id(&ino, &dev) != 0)
		return is_manager();

	state = app_lookup(ino, dev);
	if (state == KSU_POLICY_DENY)
		return false;
	if (state == KSU_POLICY_ROOT)
		return true;

	return is_manager();
}

/* -------------------------------------------------------------------------
 * 3. 匿名 inode 上的文件操作
 * ---------------------------------------------------------------------- */

static long rootmgr_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	unsigned int nr;

	(void)filp;

	if (_IOC_TYPE(cmd) != KSU_IOCTL_MAGIC)
		return -ENOTTY;

	/* 只按 nr 分派：compat 进程的 cmd 里 size 字段不一样 */
	nr = _IOC_NR(cmd);

	switch (nr) {
	case KSU_NR_PING:
		return 0;

	case KSU_NR_GRANT_ROOT:
		if (!may_escalate())
			return -EPERM;
		return escape_to_root();

	case KSU_NR_GET_INFO: {
		struct ksu_get_info_cmd info;

		if (!uarg)
			return -EINVAL;

		memset(&info, 0, sizeof(info));
		info.version = ROOTMGR_VERSION_NUM;
		info.uid = __kuid_val(current_uid());
		info.euid = __kuid_val(current_euid());
		info.manager_uid = allow_uid;
		if (uid_eq(current_euid(), GLOBAL_ROOT_UID))
			info.flags |= KSU_FLAG_ROOT;
		if (is_manager())
			info.flags |= KSU_FLAG_MANAGER;
		if (exec_hook_ok && READ_ONCE(exec_root))
			info.flags |= KSU_FLAG_AUTOEXEC;

		if (copy_to_user(uarg, &info, sizeof(info)))
			return -EFAULT;
		return 0;
	}

	case KSU_NR_GET_VERSION: {
		__u32 ver = ROOTMGR_VERSION_NUM;

		if (!uarg)
			return -EINVAL;
		if (copy_to_user(uarg, &ver, sizeof(ver)))
			return -EFAULT;
		return 0;
	}

	case KSU_NR_GRANT_PID: {
		__s32 pid;

		if (!uarg)
			return -EINVAL;
		if (copy_from_user(&pid, uarg, sizeof(pid)))
			return -EFAULT;
		if (pid <= 0)
			return -EINVAL;
		if (!is_manager())
			return -EPERM;
		return escape_pid((pid_t)pid);
	}

	case KSU_NR_SET_APP_PROFILE: {
		struct ksu_app_entry e;

		if (!uarg)
			return -EINVAL;
		if (copy_from_user(&e, uarg, sizeof(e)))
			return -EFAULT;
		if (!is_manager())
			return -EPERM;
		return app_set(&e);
	}

	case KSU_NR_CLEAR_APP_PROFILE:
		if (!is_manager())
			return -EPERM;
		app_clear();
		return 0;

	case KSU_NR_GET_APP_PROFILE: {
		struct ksu_app_entry e;
		u64 ino;
		u32 dev;
		int ret;

		if (!uarg)
			return -EINVAL;

		ret = current_exe_id(&ino, &dev);
		if (ret)
			return ret;

		memset(&e, 0, sizeof(e));
		e.ino = ino;
		e.dev = dev;
		e.state = app_lookup(ino, dev);
		e.uid = __kuid_val(current_uid());

		if (copy_to_user(uarg, &e, sizeof(e)))
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
	.unlocked_ioctl = rootmgr_ioctl,
#if IS_ENABLED(CONFIG_COMPAT)
	.compat_ioctl   = rootmgr_ioctl,
#endif
	.release        = rootmgr_release,
	.llseek         = noop_llseek,
};

/* -------------------------------------------------------------------------
 * 4. 给当前进程装一个指向 [ksu_driver] 的 fd
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
 * 5. reboot(2) 上的钩子：识别暗号并改返回值
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
 * 6. exec 钩子：授权为 root 的程序，执行时新 cred 直接就是 root
 * ---------------------------------------------------------------------- */

/*
 * 挂在 security_bprm_check() 上。选它作为落点的原因：
 *
 *   - 它在 bprm_execve() 里、do_open_execat() 之后被调用，此时 bprm->file
 *     已经指向"要执行的这个文件"，拿得到 inode；
 *   - 此时 bprm->cred 已经由 prepare_bprm_creds() 分配好、还没被
 *     begin_new_exec() 里的 commit_creds() 装上，改它来得及；
 *   - 再往后一点（exec 返回后）就只能给 current 换 cred，那要
 *     prepare_kernel_cred() 分配内存，kprobe 上下文里不允许睡眠。
 *
 * 这里只写内存，不分配、不等待，所以在 pre_handler 里是安全的。
 */
#if IS_ENABLED(CONFIG_KPROBES)

static int exec_bprm_check(struct kprobe *p, struct pt_regs *regs)
{
	struct linux_binprm *bprm;
	struct file *exe;
	struct inode *inode;
	struct cred *cred;
	u64 ino;
	u32 dev;

	(void)p;

	if (!exec_root)
		return 0;
	if (!READ_ONCE(app_count))
		return 0;               /* 表是空的：绝大多数 exec 走这条快路 */

	bprm = (struct linux_binprm *)ROOTMGR_ARG0(regs);
	if (!bprm || !bprm->file || !bprm->cred)
		return 0;

	exe = bprm->file;
	inode = file_inode(exe);
	ino = inode->i_ino;
	dev = new_encode_dev(inode->i_sb->s_dev);

	if (app_lookup(ino, dev) != KSU_POLICY_ROOT)
		return 0;

	/*
	 * 授权是按 inode 认的，但 inode 不变、内容可以变：一个谁都写得动的
	 * 文件（S_IWOTH）被授权成 root，等于原地放了个 root 后门。这种文件
	 * 一律不给自动提权。
	 */
	if (inode->i_mode & S_IWOTH) {
		pr_info_ratelimited("rootmgr: 跳过全局可写的 %s，不自动提权\n",
				    bprm->filename ? bprm->filename : "?");
		return 0;
	}

	/* 6.12 起这个字段被写成 const，显式转掉；反正 bprm->cred 是我们独占的 */
	cred = (struct cred *)bprm->cred;
	if (uid_eq(cred->euid, GLOBAL_ROOT_UID))
		return 0;               /* 本来就是 root，别重复干活 */

	cred->uid = GLOBAL_ROOT_UID;
	cred->euid = GLOBAL_ROOT_UID;
	cred->suid = GLOBAL_ROOT_UID;
	cred->fsuid = GLOBAL_ROOT_UID;
	cred->gid = GLOBAL_ROOT_GID;
	cred->egid = GLOBAL_ROOT_GID;
	cred->sgid = GLOBAL_ROOT_GID;
	cred->fsgid = GLOBAL_ROOT_GID;

	cred->securebits = SECUREBITS_DEFAULT;
	cred->cap_inheritable = CAP_EMPTY_SET;
	cred->cap_permitted = CAP_FULL_SET;
	cred->cap_effective = CAP_FULL_SET;
	cred->cap_bset = CAP_FULL_SET;
	cred->cap_ambient = CAP_EMPTY_SET;

	/*
	 * 等效于 setuid：让 AT_SECURE 生效。少了这一位，非特权用户可以
	 * 用 LD_PRELOAD 往这个即将变成 root 的进程里塞代码。
	 */
	bprm->secureexec = 1;

	atomic_inc(&exec_grant_count);
	pr_info("rootmgr: exec %s -> root (pid %d)\n",
		bprm->filename ? bprm->filename : "?", task_pid_nr(current));

	return 0;
}

static struct kprobe exec_kp = {
	.symbol_name = "security_bprm_check",
	.pre_handler = exec_bprm_check,
};

#endif /* CONFIG_KPROBES */

/* -------------------------------------------------------------------------
 * 7. 模块出入口
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

	/*
	 * exec 钩子挂不上不算致命：通道（拿 fd + ioctl）还能用，只是退回
	 * "程序自己调 GRANT_ROOT" 的老路子。比如 6.13 之后
	 * security_bprm_check 被拆掉的内核上就会走到这里。
	 */
#if IS_ENABLED(CONFIG_KPROBES)
	ret = register_kprobe(&exec_kp);
	if (ret) {
		pr_warn("rootmgr: register_kprobe(%s) failed: %d，exec 自动提权不可用\n",
			exec_kp.symbol_name, ret);
		exec_hook_ok = false;
	} else {
		exec_hook_ok = true;
	}
#endif

	pr_info("rootmgr %s loaded: %s, fd via reboot(%#x, %#x), ioctl magic 'K'\n",
		ROOTMGR_VERSION_STR, ROOTMGR_NAME,
		KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2);
	pr_info("rootmgr: allow_uid=%d (GRANT_ROOT %s), exec_root=%d (%s)\n",
		allow_uid,
		allow_uid < 0 ? "requires CAP_SYS_ADMIN" : "uid-restricted",
		exec_root,
		exec_hook_ok && exec_root ? "authorized exec runs as root"
					  : "manual GRANT_ROOT only");
	return 0;
#endif
}

static void __exit rootmgr_exit(void)
{
#if IS_ENABLED(CONFIG_KRETPROBES)
	unregister_kretprobe(&reboot_krp);
#endif
#if IS_ENABLED(CONFIG_KPROBES)
	if (exec_hook_ok) {
		unregister_kprobe(&exec_kp);
		exec_hook_ok = false;
	}
#endif
	if (rootmgr_file) {
		fput(rootmgr_file);
		rootmgr_file = NULL;
	}
	pr_info("rootmgr: unloaded after %d grant(s), %d via exec\n",
		atomic_read(&grant_count), atomic_read(&exec_grant_count));
}

module_init(rootmgr_init);
module_exit(rootmgr_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("rootmgr: anon-inode [ksu_driver] channel, ioctl magic 'K'");
MODULE_VERSION(ROOTMGR_VERSION_STR);
