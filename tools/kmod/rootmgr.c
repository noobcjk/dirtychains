// SPDX-License-Identifier: GPL-2.0
/*
 * rootmgr.c —— 常驻的 root 管理器（late-load 模式）
 *
 * 借鉴 KernelSU 的加载思路，不用它的代码：
 *   1) 模块在系统起来之后再 insmod，不改内核镜像、不刷机；
 *   2) 内核侧只留一条极窄的通道 —— 一个 proc 文件，不是整套系统调用 hook；
 *   3) 权限判定放在内核里：普通用户只能提权自己名下的进程。
 *
 * 用法：
 *   make rootmgr
 *   sudo insmod rootmgr.ko                 # 任意本地用户都能提权自己的进程
 *   sudo insmod rootmgr.ko allow_uid=1000  # 只允许 uid 1000 这么做
 *
 *   echo give <pid> > /proc/rootmgr        # 把 <pid> 的凭据换成 root
 *   cat /proc/rootmgr                      # 版本、allow_uid、已提权次数
 *
 * 例：普通用户的 shell 里
 *   echo give $$ > /proc/rootmgr && id     # 这个 shell 立刻变成 uid=0
 *
 * 原理：
 *   prepare_kernel_cred(target) 按目标进程的 user_ns 生成一份 init_cred 副本，
 *   把 uid/gid/caps 显式拉满后，用 rcu_assign_pointer 换掉 target 的
 *   real_cred / cred，旧凭据 put_cred。不 hook 系统调用、不碰 sys_call_table，
 *   也不依赖 target.h 里的偏移。
 *
 * 注意：
 *   - 这是研究/演示用的本地提权通道，装上等于给机器留了个后门，
 *     别在生产环境长期保留。用完 rmmod，/proc/rootmgr 就消失。
 *   - 6.x 上 prepare_kernel_cred() 的实现了改动，若编不过，把参数换成 NULL。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/pid.h>
#include <linux/capability.h>
#include <linux/uidgid.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/securebits.h>

#define ROOTMGR_VERSION   "1.0"
#define ROOTMGR_MAX_PIDS  16

static int allow_uid = -1;
module_param(allow_uid, int, 0644);
MODULE_PARM_DESC(allow_uid,
                 "只允许该 uid 提权自己名下的进程；-1 表示任意本地用户");

static pid_t given[ROOTMGR_MAX_PIDS];
static int given_n;
static unsigned long give_count;
static DEFINE_SPINLOCK(given_lock);

/* 记最近提权过的 pid，status 里能看到，方便确认有没有生效 */
static void note_pid(pid_t pid)
{
    int i;

    spin_lock(&given_lock);
    give_count++;
    for (i = 0; i < given_n; i++) {
        if (given[i] == pid)
            goto out;
    }
    if (given_n < ROOTMGR_MAX_PIDS) {
        given[given_n++] = pid;
    } else {
        memmove(given, given + 1, sizeof(given[0]) * (ROOTMGR_MAX_PIDS - 1));
        given[ROOTMGR_MAX_PIDS - 1] = pid;
    }
out:
    spin_unlock(&given_lock);
}

/*
 * 把 pid 的凭据换成 root。
 * 非 root 调用者只能操作和自己同 uid 的进程。
 */
static int do_give(pid_t pid)
{
    struct task_struct *t;
    const struct cred *old, *tc;
    struct cred *new;
    kuid_t caller = current_uid();

    if (pid <= 0)
        return -EINVAL;

    rcu_read_lock();
    t = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (t)
        get_task_struct(t);
    rcu_read_unlock();
    if (!t)
        return -ESRCH;

    if (!uid_eq(current_euid(), GLOBAL_ROOT_UID)) {
        if (allow_uid >= 0 && !uid_eq(caller, KUIDT_INIT(allow_uid))) {
            put_task_struct(t);
            return -EPERM;
        }
        tc = get_task_cred(t);
        if (!uid_eq(tc->uid, caller)) {
            put_cred(tc);
            put_task_struct(t);
            return -EPERM;
        }
        put_cred(tc);
    }

    new = prepare_kernel_cred(t);
    if (!new) {
        put_task_struct(t);
        return -ENOMEM;
    }

    new->uid  = new->euid  = new->suid  = new->fsuid = GLOBAL_ROOT_UID;
    new->gid  = new->egid  = new->sgid  = new->fsgid = GLOBAL_ROOT_GID;
    new->cap_inheritable = CAP_EMPTY_SET;
    new->cap_permitted   = CAP_FULL_SET;
    new->cap_effective   = CAP_FULL_SET;
    new->cap_bset        = CAP_FULL_SET;
    new->cap_ambient     = CAP_EMPTY_SET;
    new->securebits      = SECUREBITS_DEFAULT;

    rcu_read_lock();
    old = get_task_cred(t);
    rcu_assign_pointer(t->real_cred, new);
    rcu_assign_pointer(t->cred, new);
    rcu_read_unlock();
    put_cred(old);

    put_task_struct(t);
    note_pid(pid);
    pr_info("rootmgr: pid %d -> uid 0\n", pid);
    return 0;
}

static ssize_t rootmgr_read(struct file *f, char __user *buf, size_t len,
                            loff_t *off)
{
    char kb[256];
    int n, i, cnt;

    if (*off)
        return 0;

    n = scnprintf(kb, sizeof(kb), "rootmgr %s\nallow_uid=%d\ngive_count=%lu\ngiven=",
                  ROOTMGR_VERSION, allow_uid, give_count);

    spin_lock(&given_lock);
    for (i = 0; i < given_n && n < (int)sizeof(kb) - 16; i++)
        n += scnprintf(kb + n, sizeof(kb) - n, "%s%d", i ? "," : "", given[i]);
    cnt = given_n;
    spin_unlock(&given_lock);

    n += scnprintf(kb + n, sizeof(kb) - n, "\n(%d pids)\n", cnt);
    return simple_read_from_buffer(buf, len, off, kb, n);
}

static ssize_t rootmgr_write(struct file *f, const char __user *ubuf,
                             size_t len, loff_t *off)
{
    char buf[64], cmd[16];
    size_t n;
    int pid = 0, ret;

    n = len < sizeof(buf) - 1 ? len : sizeof(buf) - 1;
    if (copy_from_user(buf, ubuf, n))
        return -EFAULT;
    buf[n] = '\0';

    if (sscanf(buf, "%15s %d", cmd, &pid) < 1)
        return -EINVAL;

    if (!strcmp(cmd, "give"))
        ret = do_give(pid);
    else if (!strcmp(cmd, "version"))
        ret = 0;
    else
        ret = -EINVAL;

    return ret ? ret : (ssize_t)len;
}

static const struct proc_ops rootmgr_pops = {
    .proc_read  = rootmgr_read,
    .proc_write = rootmgr_write,
    .proc_lseek = noop_llseek,
};

static int __init rootmgr_init(void)
{
    if (!proc_create("rootmgr", 0622, NULL, &rootmgr_pops))
        return -ENOMEM;

    pr_info("rootmgr: loaded, allow_uid=%d, /proc/rootmgr ready\n", allow_uid);
    return 0;
}

static void __exit rootmgr_exit(void)
{
    remove_proc_entry("rootmgr", NULL);
    pr_info("rootmgr: unloaded\n");
}

module_init(rootmgr_init);
module_exit(rootmgr_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Late-load root manager: give <pid> via /proc/rootmgr");
MODULE_AUTHOR("dirtychains");
MODULE_VERSION(ROOTMGR_VERSION);
