/*
 * rootmgr_fd.h —— 用户态怎么拿到 [ksu_driver] 的 fd，并且只拿一次
 *
 * 用法：
 *      int fd = rootmgr_fd();
 *      if (fd < 0) { perror("rootmgr_fd"); ... }
 *      ioctl(fd, ...);
 *
 * 第一次调用会走 reboot(2) 暗号，模块给当前进程装一个 fd 并把它当成
 * 返回值还回来；之后 g_rootmgr_fd 里就有缓存，不再进内核。
 *
 * 注意：模块装 fd 时带了 O_CLOEXEC，所以 exec 之后子进程继承不到，
 * 需要在新进程里重新调一次 rootmgr_fd()（缓存变量本身也是每个进程一份）。
 */

#ifndef ROOTMGR_FD_H
#define ROOTMGR_FD_H

#include <errno.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ROOTMGR_MAGIC1 0xDEADBEEF
#define ROOTMGR_MAGIC2 0xCAFEBABE

#define ROOTMGR_IOCTL_MAGIC 'R'
#define ROOTMGR_CMD_PING    _IO(ROOTMGR_IOCTL_MAGIC, 0)
#define ROOTMGR_CMD_VERSION _IOR(ROOTMGR_IOCTL_MAGIC, 1, char[32])

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

static inline int rootmgr_ping(void)
{
	int fd = rootmgr_fd();

	if (fd < 0)
		return -1;
	return ioctl(fd, ROOTMGR_CMD_PING, 0);
}

#endif /* ROOTMGR_FD_H */
