// SPDX-License-Identifier: GPL-2.0
/*
 * rootmgr_fd_demo.c —— 验证 [ksu_driver] 通道
 *
 *   cc -O2 -o rootmgr_fd_demo rootmgr_fd_demo.c
 *   sudo insmod rootmgr.ko
 *   ./rootmgr_fd_demo
 *
 * 期望输出：
 *   fd = 3
 *   /proc/self/fd/3 -> anon_inode:[ksu_driver]
 *   cached fd = 3   (×3，说明没有重复获取)
 *   ping ok
 *   version = 2.0
 */

#include <stdio.h>
#include <string.h>

#include "rootmgr_fd.h"

int main(void)
{
	char link[64], target[256];
	char ver[32] = { 0 };
	ssize_t n;
	int fd, i;

	fd = rootmgr_fd();
	if (fd < 0) {
		perror("rootmgr_fd");
		fprintf(stderr,
			"拿不到 fd：模块没装，或者 kretprobe 没挂上\n");
		return 1;
	}
	printf("fd = %d\n", fd);

	/* 这个 fd 背后的 inode 到底叫什么 */
	snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
	n = readlink(link, target, sizeof(target) - 1);
	if (n > 0) {
		target[n] = '\0';
		printf("%s -> %s\n", link, target);
	}

	/* 再调三次，不应该再进内核 */
	for (i = 0; i < 3; i++)
		printf("cached fd = %d\n", rootmgr_fd());

	if (rootmgr_ping() < 0) {
		perror("ping");
		return 1;
	}
	printf("ping ok\n");

	if (ioctl(fd, ROOTMGR_CMD_VERSION, ver) == 0)
		printf("version = %s\n", ver);

	rootmgr_fd_close();
	return 0;
}
