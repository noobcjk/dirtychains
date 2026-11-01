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
#include <sys/ioctl.h>
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

struct ksu_get_info_cmd {
	uint32_t version;      /* 21000 => 2.1.0 */
	uint32_t flags;        /* bit0 已 root，bit1 是 manager */
	uint32_t uid;          /* 调用者 real uid */
	uint32_t euid;         /* 调用者 effective uid */
	int32_t  manager_uid;  /* allow_uid，-1 表示按能力判断 */
	uint32_t reserved;
};

#define KSU_FLAG_ROOT    (1u << 0)
#define KSU_FLAG_MANAGER (1u << 1)

#define KSU_IOCTL_PING        _IOC(_IOC_NONE, KSU_IOCTL_MAGIC, KSU_NR_PING, 0)
#define KSU_IOCTL_GRANT_ROOT  _IOC(_IOC_NONE, KSU_IOCTL_MAGIC, KSU_NR_GRANT_ROOT, 0)
#define KSU_IOCTL_GET_INFO    _IOC(_IOC_READ, KSU_IOCTL_MAGIC, KSU_NR_GET_INFO, \
				   sizeof(struct ksu_get_info_cmd))
#define KSU_IOCTL_GET_VERSION _IOC(_IOC_READ, KSU_IOCTL_MAGIC, KSU_NR_GET_VERSION, \
				   sizeof(uint32_t))
#define KSU_IOCTL_GRANT_PID   _IOC(_IOC_WRITE, KSU_IOCTL_MAGIC, KSU_NR_GRANT_PID, \
				   sizeof(int32_t))

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

#endif /* ROOTMGR_FD_H */
