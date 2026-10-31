// SPDX-License-Identifier: MIT
/*
 * cve_2026_43500_recon.c -- CVE-2026-43500 (rxrpc/rxkad "Dirty Frag")
 *                           可达性探测 PoC
 *
 * 目标: 判断本机是否具备触发 CVE-2026-43500 的条件, 并验证 splice 原语,
 *       为后续完整 PoC 提供环境结论。
 *
 * 漏洞摘要 (cve.org / NVD):
 *   rxrpc_input_call_event() 与 rxrpc_verify_response() 只在 skb_cloned()
 *   为真时才把 skb 复制成线性再进安全操作。若 skb 未被 clone、却带外部
 *   paged frag (splice() 进 UDP socket 时由 __ip_append_data 打上的
 *   SKBFL_SHARED_FRAG) 或 skb_has_frag_list(), 则会走原地解密路径,
 *   skb_to_sgvec() 把 frag 页直接绑进 AEAD/skcipher SGL, 解密结果写回
 *   页缓存 -> 形成写文件页缓存的原语。
 *
 *   修复: 把 unshare 门槛从只看 skb_cloned() 扩展为
 *         skb_has_frag_list() || skb_has_shared_frag()。
 *
 * 与 CVE-2026-43284 (xfrm/ESP) 同属 "Dirty Frag": 原语相同 (splice 共享页
 * -> 原地解密写页缓存), 只是协议栈不同 (rxrpc/rxkad vs xfrm/ESP)。
 *
 * ---------------------------------------------------------------------------
 * 本文件的范围 (务必读完):
 *
 *   [已实现 / 可运行]
 *     1. 内核配置检测: AF_RXRPC / AF_RXRPC_IPV4 / RXKAD  (y 或 m)
 *     2. 模块加载检测: rxrpc / rxkad
 *     3. AF_RXRPC socket 创建 + 本地 bind + rxkad key 设置测试
 *     4. splice(file -> pipe) 原语能力测试 (与 ESP 版共用同一原语)
 *
 *   [未实现 / 需按目标内核补全]
 *     5. rxkad 会话密钥握手 (challenge/response)
 *     6. rxrpc call 状态机 (client 发起 / server accept)
 *     7. 合法 DATA 包构造 (rxrpc 头 + rxkad 加密载荷) 并经 splice 共享页发出
 *     8. 回读校验 + 提权 payload 写入
 *
 *   第 5~8 步强依赖目标内核的 rxrpc 实现细节与包格式, 不同版本差异较大,
 *   本文件不做"猜测式"实现, 以免给出看似完整却不可用的 exploit。
 *   本工具的价值: 在你跑任何完整 PoC 之前, 先确认这台机器到底有没有
 *   触发条件 (尤其是 rxrpc 模块是否存在、AF_RXRPC socket 能否创建)。
 *
 * 仅限你拥有或已获授权的一次性测试环境使用。
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

/* ---- AF_RXRPC 相关 (自带定义, 避免 linux/rxrpc.h 与 netinet/in.h 冲突) ---- */
#ifndef AF_RXRPC
#define AF_RXRPC 33
#endif
#ifndef PF_RXRPC
#define PF_RXRPC AF_RXRPC
#endif
#ifndef SOL_RXRPC
#define SOL_RXRPC 272
#endif
#define RXRPC_SECURITY_KEY 1

struct rxrpc_sa {
	unsigned short srx_family;
	unsigned short srx_service;
	unsigned short transport_type;
	unsigned short transport_len;
	union {
		unsigned short family;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} transport;
};

/* ======================================================================== */

static void out(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	fflush(stdout);
}

static int color_on(void)
{
	static int c = -1;

	if (c < 0)
		c = isatty(STDOUT_FILENO) && !getenv("NO_COLOR");
	return c;
}

#define G (color_on() ? "\033[32m" : "")
#define R (color_on() ? "\033[31m" : "")
#define Y (color_on() ? "\033[33m" : "")
#define C (color_on() ? "\033[36m" : "")
#define N (color_on() ? "\033[0m" : "")

/* ---- 配置读取: /proc/config.gz 或 /boot/config-<release> ---- */
static char *read_config(size_t *len)
{
	char path[512];
	struct utsname u;
	char *buf = NULL;
	size_t cap = 0, n = 0;
	int used_popen = 0;
	FILE *f = NULL;

	if (access("/proc/config.gz", R_OK) == 0) {
		f = popen("gzip -dc /proc/config.gz 2>/dev/null", "r");
		used_popen = 1;
	} else if (uname(&u) == 0) {
		snprintf(path, sizeof(path), "/boot/config-%s", u.release);
		f = fopen(path, "r");
	}
	if (!f)
		return NULL;

	for (;;) {
		char tmp[4096];
		size_t r = fread(tmp, 1, sizeof(tmp), f);

		if (r == 0)
			break;
		if (n + r + 1 > cap) {
			char *nb;

			cap = (n + r + 1) * 2;
			nb = realloc(buf, cap);
			if (!nb) {
				free(buf);
				if (used_popen)
					pclose(f);
				else
					fclose(f);
				return NULL;
			}
			buf = nb;
		}
		memcpy(buf + n, tmp, r);
		n += r;
	}
	if (used_popen)
		pclose(f);
	else
		fclose(f);
	if (buf)
		buf[n] = '\0';
	*len = n;
	return buf;
}

/* 逐行查某 CONFIG_ 项: 2=y, 1=m, 0=n/缺失 */
static int cfg_val(const char *mem, const char *key)
{
	const char *p = mem;
	size_t kl;

	if (!mem)
		return 0;
	kl = strlen(key);
	while (p && *p) {
		const char *e = strchr(p, '\n');
		size_t len = e ? (size_t)(e - p) : strlen(p);

		if (len > kl && !strncmp(p, key, kl) && p[kl] == '=') {
			char v = p[kl + 1];

			return v == 'y' ? 2 : v == 'm' ? 1 : 0;
		}
		p = e ? e + 1 : NULL;
	}
	return 0;
}

static int module_loaded(const char *name)
{
	FILE *f = fopen("/proc/modules", "r");
	char line[512];
	int rc = -1;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char *sp = line;

		while (*sp && *sp != ' ' && *sp != '\t' && *sp != '\n')
			sp++;
		*sp = '\0';
		if (!strcmp(line, name)) {
			rc = 1;
			break;
		}
	}
	if (rc == -1)
		rc = 0;
	fclose(f);
	return rc;
}

/* 尝试创建 AF_RXRPC socket 并 bind 本地 service */
static int test_rxrpc_socket(void)
{
	struct rxrpc_sa sa;
	int s, rc = 0;

	s = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
	if (s < 0) {
		out("%s[-]%s socket(AF_RXRPC): %s\n", R, N, strerror(errno));
		return -1;
	}
	out("%s[+]%s socket(AF_RXRPC, SOCK_DGRAM, PF_INET) 创建成功\n", G, N);

	memset(&sa, 0, sizeof(sa));
	sa.srx_family = AF_RXRPC;
	sa.srx_service = htons(1);
	sa.transport_type = SOCK_DGRAM;
	sa.transport_len = sizeof(sa.transport.sin);
	sa.transport.sin.sin_family = AF_INET;
	sa.transport.sin.sin_port = htons(0);
	sa.transport.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		out("%s[!]%s bind rxrpc service=1: %s (可能缺 CAP_NET_RAW)\n",
		    Y, N, strerror(errno));
		rc = -1;
	} else {
		out("%s[+]%s bind rxrpc service=1 成功\n", G, N);
	}

	close(s);

	/*
	 * server socket 应使用 RXRPC_SECURITY_KEYRING; RXRPC_SECURITY_KEY 是
	 * [clnt] 专用, 对已 bind 的 server socket 设置会 EISCONN。
	 * 这里另建 client socket 探测 KEY 的 sockopt 是否可达
	 * (key 内容格式仍需按内核 rxkad 解析规则调整)。
	 */
	{
		int cs = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
		char key[64] = "rxkad:2:cell:0";

		if (cs >= 0) {
			if (setsockopt(cs, SOL_RXRPC, RXRPC_SECURITY_KEY,
				       key, sizeof(key)) < 0)
				out("%s[!]%s client RXRPC_SECURITY_KEY: %s "
				    "(key 格式需按内核调整)\n",
				    Y, N, strerror(errno));
			else
				out("%s[+]%s client RXRPC_SECURITY_KEY 可达\n",
				    G, N);
			close(cs);
		}
	}
	return rc;
}

/* splice(file -> pipe) 能力测试: 与 ESP 版共用同一原语 */
static int test_splice(void)
{
	char tmpl[] = "/tmp/rxrpc_splice_XXXXXX";
	const char *msg = "DFRG";
	int fd, pfd[2];
	off_t off = 0;
	ssize_t n;

	fd = mkstemp(tmpl);
	if (fd < 0)
		return -1;
	if (write(fd, msg, 4) != 4) {
		close(fd);
		unlink(tmpl);
		return -1;
	}
	if (pipe(pfd) < 0) {
		close(fd);
		unlink(tmpl);
		return -1;
	}
	/* 显式 offset 0: write 之后文件位置在 4, 用 NULL 会读到 EOF */
	n = splice(fd, &off, pfd[1], NULL, 4, 0);
	close(pfd[0]);
	close(pfd[1]);
	close(fd);
	unlink(tmpl);
	return n == 4 ? 0 : -1;
}

int main(void)
{
	struct utsname u;
	char *cfg = NULL;
	size_t cfg_len = 0;
	int af_rxrpc = 0, af_ipv4 = 0, rxkad = 0;
	int m_rxrpc, m_rxkad;
	int ok_rxrpc = 0, ok_splice = 0;
	int score = 0, need = 0;

	setvbuf(stdout, NULL, _IONBF, 0);

	out("%sCVE-2026-43500 (rxrpc/rxkad Dirty Frag) 可达性探测%s\n\n", C, N);
	if (uname(&u) == 0)
		out("[*] 内核: %s %s\n", u.release, u.machine);

	cfg = read_config(&cfg_len);

	/* ---- 1. 配置 ---- */
	out("\n%s[1] 内核配置%s\n", C, N);
	if (!cfg) {
		out("%s[!]%s 读不到内核配置 "
		    "(无 /proc/config.gz 也无 /boot/config-*)\n", Y, N);
	} else {
		af_rxrpc = cfg_val(cfg, "CONFIG_AF_RXRPC");
		af_ipv4 = cfg_val(cfg, "CONFIG_AF_RXRPC_IPV4");
		rxkad = cfg_val(cfg, "CONFIG_RXKAD");

		out("%s CONFIG_AF_RXRPC        %s\n", af_rxrpc ? "[+]" : "[-]",
		    af_rxrpc == 2 ? "y" : af_rxrpc == 1 ? "m" : "n/缺失");
		if (af_ipv4 != 0)
			out("[+] CONFIG_AF_RXRPC_IPV4   %s\n",
			    af_ipv4 == 2 ? "y" : "m");
		else
			out("[*] CONFIG_AF_RXRPC_IPV4   未列出 (5.x 常无此独立项,\n"
			    "    IPv4 支持随 AF_RXRPC 内置; 以 [3] socket/bind 实测为准)\n");
		out("%s CONFIG_RXKAD           %s\n", rxkad ? "[+]" : "[-]",
		    rxkad == 2 ? "y" : rxkad == 1 ? "m" : "n/缺失");

		/* AF_RXRPC_IPV4 在 5.x 可能不存在, 不作硬性要求 */
		score += (af_rxrpc != 0) + (rxkad != 0);
		need += 2;
	}

	/* ---- 2. 模块 ---- */
	out("\n%s[2] 模块加载%s\n", C, N);
	m_rxrpc = module_loaded("rxrpc");
	m_rxkad = module_loaded("rxkad");
	out("%s rxrpc  %s\n", m_rxrpc == 1 ? "[+]" : "[!]",
	    m_rxrpc == 1 ? "已加载" : m_rxrpc == 0 ? "未加载" : "无法判断");
	out("%s rxkad  %s\n", m_rxkad == 1 ? "[+]" : "[!]",
	    m_rxkad == 1 ? "已加载" : m_rxkad == 0 ? "未加载" : "无法判断");

	/* ---- 3. AF_RXRPC socket ---- */
	out("\n%s[3] AF_RXRPC socket%s\n", C, N);
	if (test_rxrpc_socket() == 0) {
		ok_rxrpc = 1;
		score++;
	}
	need++;

	/* socket 创建可能触发 request_module 按需加载 rxrpc, 再查一次 */
	if (ok_rxrpc && module_loaded("rxrpc") == 1)
		out("%s[+]%s rxrpc 已按需自动加载 (由 socket 创建触发)\n",
		    G, N);

	/* ---- 4. splice 原语 ---- */
	out("\n%s[4] splice 原语%s\n", C, N);
	if (test_splice() == 0) {
		out("%s[+]%s splice(file->pipe) 可用\n", G, N);
		ok_splice = 1;
		score++;
	} else {
		out("%s[-]%s splice(file->pipe) 不可用: %s\n", R, N,
		    strerror(errno));
	}
	need++;

	/* ---- 结论 ---- */
	out("\n%s[*] 结论%s\n", C, N);
	out("%s 条件满足 %d/%d 项%s\n", score == need ? G : Y, score, need, N);
	if (!ok_rxrpc) {
		out("%s[-]%s 本机 AF_RXRPC 不可用: 43500 的触发路径不存在, "
		    "无法利用\n", R, N);
	} else if (!ok_splice) {
		out("%s[-]%s splice 不可用: 缺少共享页原语\n", R, N);
	} else {
		out("%s[!]%s 配置层面具备条件, 但完整利用还需要:\n", Y, N);
		out("      rxkad 会话密钥握手 + rxrpc call 状态机 + 合法 DATA 包构造,\n");
		out("      这些强依赖目标内核版本, 本探测不做猜测式实现。\n");
		out("      下一步: 有 rxrpc 服务监听 (UDP 7000-7009) 且能建立 call 时,\n");
		out("      再补 splice 共享页 -> DATA 发送 -> 回读校验 的触发代码。\n");
	}

	out("\n[*] 缓解: 若不需要 AFS/rxrpc, 禁用模块并升级内核:\n");
	out("    printf 'install rxrpc /bin/false\\ninstall rxkad /bin/false\\n' "
	    "> /etc/modprobe.d/norxrpc.conf\n");

	free(cfg);
	(void)cfg_len;
	return (ok_rxrpc && ok_splice) ? 0 : 1;
}
