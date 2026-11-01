/*
 * rootmgr_fd.h —— 用户态怎么拿到 [ksu_driver] 的 fd，以及怎么做 ioctl 通信
 *
 * 两层：
 *
 *   1) 取 fd（只取一次，进程内缓存）
 *          int fd = rootmgr_fd();
 *          if (fd < 0) { perror("rootmgr_fd"); ... }
 *
 *      第一次调用会走 reboot(2) 暗号，模块给当前进程装一个 fd 并把它当成
 *      返回值还回来；之后 g_rootmgr_fd 里就有缓存，不再进内核。
 *
 *   2) 通信（全部走 ioctl，魔术字符 'K'）
 *          rootmgr_ping();                 探活
 *          rootmgr_get_info(&info);        版本 / uid / 是否 root
 *          rootmgr_grant_root();           给调用者自己提权到 root
 *          rootmgr_grant_pid(pid);         给指定 pid 提权（需要 manager）
 *
 * 注意：模块装 fd 时带了 O_CLOEXEC，所以 exec 之后子进程继承不到，
 * 需要在新进程里重新调一次 rootmgr_fd()（缓存变量本身也是每个进程一份）。
 */

#ifndef ROOTMGR_FD_H
#define ROOTMGR_FD_H

#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ROOTMGR_MAGIC1 0xDEADBEEF
#define ROOTMGR_MAGIC2 0xCAFEBABE

/* -------------------------------------------------------------------------
 * ioctl 协议：魔术字符 'K'，和内核 rootmgr.c 保持一致
 * ---------------------------------------------------------------------- */

#define KSU_IOCTL_MAGIC 'K'

#define KSU_NR_PING         0
#define KSU_NR_GRANT_ROOT   1
#define KSU_NR_GET_INFO     2
#define KSU_NR_GET_VERSION  3
#define KSU_NR_GRANT_PID    4
#define KSU_NR_SET_APP_PROFILE 5
#define KSU_NR_GET_APP_PROFILE 6
#define KSU_NR_CLEAR_APP_PROFILE 7

struct ksu_get_info_cmd {
	uint32_t version;      /* 22000 => 2.2.0 */
	uint32_t flags;        /* bit0 已 root，bit1 是 manager */
	uint32_t uid;          /* 调用者 real uid */
	uint32_t euid;         /* 调用者 effective uid */
	int32_t  manager_uid;  /* allow_uid，-1 表示按能力判断 */
	uint32_t reserved;
};

/* 一条程序授权。身份是 exe 的 (ino, dev)，不是路径。 */
struct ksu_app_entry {
	uint64_t ino;
	uint32_t dev;
	int32_t  state;        /* 0 = 未记录，1 = root，2 = 禁止 */
	uint32_t uid;
	uint32_t reserved;
};

#define KSU_POLICY_ASK  0
#define KSU_POLICY_ROOT 1
#define KSU_POLICY_DENY 2

#define KSU_FLAG_ROOT    (1u << 0)
#define KSU_FLAG_MANAGER (1u << 1)

/* 带授权表接口（SET/GET/CLEAR_APP_PROFILE）的最低版本：2.3.0 */
#define KSU_MIN_VERSION 23000

#define KSU_IOCTL_PING        _IOC(_IOC_NONE, KSU_IOCTL_MAGIC, KSU_NR_PING, 0)
#define KSU_IOCTL_GRANT_ROOT  _IOC(_IOC_NONE, KSU_IOCTL_MAGIC, KSU_NR_GRANT_ROOT, 0)
#define KSU_IOCTL_GET_INFO    _IOC(_IOC_READ, KSU_IOCTL_MAGIC, KSU_NR_GET_INFO, \
				   sizeof(struct ksu_get_info_cmd))
#define KSU_IOCTL_GET_VERSION _IOC(_IOC_READ, KSU_IOCTL_MAGIC, KSU_NR_GET_VERSION, \
				   sizeof(uint32_t))
#define KSU_IOCTL_GRANT_PID   _IOC(_IOC_WRITE, KSU_IOCTL_MAGIC, KSU_NR_GRANT_PID, \
				   sizeof(int32_t))
#define KSU_IOCTL_SET_APP_PROFILE _IOC(_IOC_WRITE, KSU_IOCTL_MAGIC, \
				       KSU_NR_SET_APP_PROFILE, \
				       sizeof(struct ksu_app_entry))
#define KSU_IOCTL_GET_APP_PROFILE _IOC(_IOC_READ | _IOC_WRITE, KSU_IOCTL_MAGIC, \
				       KSU_NR_GET_APP_PROFILE, \
				       sizeof(struct ksu_app_entry))
#define KSU_IOCTL_CLEAR_APP_PROFILE _IOC(_IOC_NONE, KSU_IOCTL_MAGIC, \
					 KSU_NR_CLEAR_APP_PROFILE, 0)

/* 进程内的唯一缓存 */
static int g_rootmgr_fd = -1;

static inline int rootmgr_fd(void)
{
	long ret;

	if (g_rootmgr_fd >= 0)
		return g_rootmgr_fd;

	errno = 0;
	ret = syscall(SYS_reboot, (long)ROOTMGR_MAGIC1, (long)ROOTMGR_MAGIC2,
		      0, NULL);
	if (ret < 0) {
		/* 内核原样返回 -EINVAL 说明钩子没接上（模块没装 / 暗号被拦） */
		if (errno == 0)
			errno = ENOENT;
		return -1;
	}

	g_rootmgr_fd = (int)ret;
	return g_rootmgr_fd;
}

static inline void rootmgr_fd_close(void)
{
	if (g_rootmgr_fd >= 0) {
		close(g_rootmgr_fd);
		g_rootmgr_fd = -1;
	}
}

/* 唯一的发命令入口：拿 fd + ioctl */
static inline int rootmgr_call(unsigned long cmd, void *arg)
{
	int fd = rootmgr_fd();

	if (fd < 0)
		return -1;
	return ioctl(fd, cmd, arg);
}

static inline int rootmgr_ping(void)
{
	return rootmgr_call(KSU_IOCTL_PING, NULL);
}

static inline int rootmgr_get_version(uint32_t *out)
{
	return rootmgr_call(KSU_IOCTL_GET_VERSION, out);
}

static inline int rootmgr_get_info(struct ksu_get_info_cmd *out)
{
	return rootmgr_call(KSU_IOCTL_GET_INFO, out);
}

/* 给自己提权：成功后 getuid() 就是 0 */
static inline int rootmgr_grant_root(void)
{
	return rootmgr_call(KSU_IOCTL_GRANT_ROOT, NULL);
}

/* 给别的进程提权：需要 allow_uid 匹配或 CAP_SYS_ADMIN */
static inline int rootmgr_grant_pid(int pid)
{
	int32_t p = pid;

	return rootmgr_call(KSU_IOCTL_GRANT_PID, &p);
}

/* -------------------------------------------------------------------------
 * 程序授权表：身份取 exe 的 (st_ino, st_dev)
 * ---------------------------------------------------------------------- */

/* 把一个路径 / 一个 /proc/<pid>/exe 填成授权条目（state 由调用者设） */
static inline int rootmgr_app_id(const char *path, struct ksu_app_entry *out)
{
	struct stat st;

	memset(out, 0, sizeof(*out));
	if (stat(path, &st) != 0)
		return -1;

	out->ino = (uint64_t)st.st_ino;
	/* 内核用 new_encode_dev()，32 位就够；高位在 64 位 dev_t 里是空的 */
	out->dev = (uint32_t)st.st_dev;
	return 0;
}

/* 写一条授权：state 传 ROOT / DENY 是新增或修改，传 ASK 是删除 */
static inline int rootmgr_set_app(const struct ksu_app_entry *e)
{
	return rootmgr_call(KSU_IOCTL_SET_APP_PROFILE, (void *)e);
}

/* 直接按路径设置某程序的状态 */
static inline int rootmgr_set_state(const char *path, int state)
{
	struct ksu_app_entry e;

	if (rootmgr_app_id(path, &e) != 0)
		return -1;
	e.state = state;
	return rootmgr_set_app(&e);
}

/* 读当前进程自己的授权状态 */
static inline int rootmgr_get_app(struct ksu_app_entry *e)
{
	return rootmgr_call(KSU_IOCTL_GET_APP_PROFILE, e);
}

/* 清空内核里的整张授权表（全量同步前先清） */
static inline int rootmgr_clear_app(void)
{
	return rootmgr_call(KSU_IOCTL_CLEAR_APP_PROFILE, NULL);
}

/* -------------------------------------------------------------------------
 * 打开 / 关闭通道
 * ---------------------------------------------------------------------- */

/*
 * rootmgr_open()：模块在不在。
 *   返回 0 表示通道可用，-1 表示没装上（errno 保留原因）。
 *   内部会顺带确认一次版本号，防止接上的是别的驱动。
 */
static inline int rootmgr_open(uint32_t *version)
{
	uint32_t v = 0;

	if (rootmgr_fd() < 0)
		return -1;
	if (rootmgr_get_version(&v) != 0)
		return -1;
	if (v < KSU_MIN_VERSION) {      /* 老模块没有授权表接口 */
		errno = ENOTSUP;
		return -1;
	}
	if (version)
		*version = v;
	return 0;
}

#endif /* ROOTMGR_FD_H */
