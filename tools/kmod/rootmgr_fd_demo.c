// SPDX-License-Identifier: GPL-2.0
/*
 * rootmgr_fd_demo.c —— 验证 [ksu_driver] 通道 + ioctl 协议
 *
 *   cc -O2 -o rootmgr_fd_demo rootmgr_fd_demo.c
 *   sudo insmod rootmgr.ko
 *   ./rootmgr_fd_demo
 *
 * 期望输出（root 下）：
 *   == 拿 fd ==
 *   fd = 3
 *   /proc/self/fd/3 -> anon_inode:[ksu_driver]
 *   cached fd = 3        (×3，说明没有重复进内核)
 *
 *   == ioctl 通信（魔术 'K'）==
 *   PING ok
 *   version = 21000 (2.1.0)
 *   info: version=21000 flags=0x3 root=1 manager=1 uid=0 euid=0 allow_uid=-1
 *
 *   == APP PROFILE（按 exe 的 ino/dev 授权）==
 *   app: ino=0x1a2b3c dev=0x801 state=ask(未记录)
 *   GRANT_ROOT 被 deny 拦住：Operation not permitted
 *   ...
 *
 *   == GRANT_ROOT ==
 *   已经是 root，GRANT_ROOT 是空操作
 *
 *   == GRANT_PID ==
 *   child:  before grant uid=65534
 *   parent: grant_pid(12345) ok
 *   child:  after  grant uid=0
 *
 *   == EXEC 自动提权（授权后执行即 root）==
 *   授权 root 后，nobody 执行 /tmp/rootmgr_exec_probe -u => 0
 *   撤销授权后，nobody 再执行一次 => 65534
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "rootmgr_fd.h"

static void section(const char *title)
{
	printf("\n== %s ==\n", title);
}

static void print_info(void)
{
	struct ksu_get_info_cmd info;

	if (rootmgr_get_info(&info) != 0) {
		perror("GET_INFO");
		return;
	}
	printf("info: version=%u flags=%#x root=%d manager=%d uid=%u euid=%u allow_uid=%d\n",
	       info.version, info.flags,
	       !!(info.flags & KSU_FLAG_ROOT),
	       !!(info.flags & KSU_FLAG_MANAGER),
	       info.uid, info.euid, info.manager_uid);
}

static void print_app(void)
{
	struct ksu_app_entry e;

	if (rootmgr_get_app(&e) != 0) {
		perror("GET_APP_PROFILE");
		return;
	}
	printf("app: ino=%#llx dev=%#x state=%s\n",
	       (unsigned long long)e.ino, e.dev,
	       e.state == KSU_POLICY_ROOT ? "root" :
	       e.state == KSU_POLICY_DENY ? "deny" :
	       e.state == KSU_POLICY_ASK  ? "ask(未记录)" : "?");
}

static void test_app_profile(void)
{
	section("APP PROFILE（按 exe 的 ino/dev 授权）");
	print_app();

	/* 1) 显式禁止：连 manager 也提不了，这是硬约束 */
	if (rootmgr_set_state("/proc/self/exe", KSU_POLICY_DENY) != 0) {
		perror("SET deny");
		return;
	}
	print_app();
	if (rootmgr_grant_root() == 0)
		printf("!! 不应该成功：deny 没生效\n");
	else
		printf("GRANT_ROOT 被 deny 拦住：%s\n", strerror(errno));

	/* 2) 改成 root */
	if (rootmgr_set_state("/proc/self/exe", KSU_POLICY_ROOT) != 0)
		perror("SET root");
	else
		print_app();

	/* 3) 删掉记录，回到"未登记" */
	if (rootmgr_set_state("/proc/self/exe", KSU_POLICY_ASK) != 0)
		perror("SET ask");
	else
		print_app();
}

static void test_grant_root(void)
{
	uid_t before = getuid();

	section("GRANT_ROOT");

	if (before == 0 && geteuid() == 0) {
		printf("已经是 root，GRANT_ROOT 是空操作\n");
		return;
	}

	if (rootmgr_grant_root() != 0) {
		printf("被拒：%s\n", strerror(errno));
		printf("提示：allow_uid=-1 时要求 CAP_SYS_ADMIN；"
		       "非 root 场景请用 insmod rootmgr.ko allow_uid=%d\n",
		       (int)before);
		return;
	}

	printf("ok: uid %d -> %d, euid -> %d\n", (int)before, (int)getuid(),
	       (int)geteuid());
	print_info();
}

/* root 下 fork 一个降到 nobody 的子进程，父进程隔空给它提权 */
static void test_grant_pid(void)
{
	int pfd[2];
	pid_t pid;

	section("GRANT_PID");

	if (geteuid() != 0) {
		printf("跳过：需要 root 才能 fork 一个降权子进程\n");
		return;
	}

	if (pipe(pfd) != 0) {
		perror("pipe");
		return;
	}

	pid = fork();
	if (pid == 0) {
		char c;
		int rc;

		close(pfd[1]);
		if (setgid(65534) != 0 || setuid(65534) != 0)
			_exit(2);

		printf("child:  before grant uid=%d euid=%d\n",
		       (int)getuid(), (int)geteuid());
		fflush(stdout);

		rc = read(pfd[0], &c, 1);
		if (rc != 1)
			_exit(3);

		printf("child:  after  grant uid=%d euid=%d\n",
		       (int)getuid(), (int)geteuid());
		_exit(getuid() == 0 ? 0 : 4);
	}

	if (pid < 0) {
		perror("fork");
		close(pfd[0]);
		close(pfd[1]);
		return;
	}

	close(pfd[0]);
	usleep(200000);                 /* 等子进程降权完 */

	if (rootmgr_grant_pid((int)pid) == 0)
		printf("parent: grant_pid(%d) ok\n", (int)pid);
	else
		perror("parent: grant_pid");

	if (write(pfd[1], "x", 1) != 1)
		perror("write");
	close(pfd[1]);

	{
		int status = 0;

		waitpid(pid, &status, 0);
		printf("parent: child exit=%d\n",
		       WIFEXITED(status) ? WEXITSTATUS(status) : -1);
	}
}

/* 把 src 整个拷到 dst（用来给测试造一个"只属于自己"的可执行文件） */
static int copy_file(const char *src, const char *dst)
{
	char buf[65536];
	int in, out;
	ssize_t n;
	int ret = 0;

	in = open(src, O_RDONLY);
	if (in < 0)
		return -1;
	out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
	if (out < 0) {
		close(in);
		return -1;
	}
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		ssize_t off = 0;

		while (off < n) {
			ssize_t w = write(out, buf + off, (size_t)(n - off));

			if (w <= 0) {
				ret = -1;
				goto out;
			}
			off += w;
		}
	}
	if (n < 0)
		ret = -1;
out:
	close(in);
	close(out);
	return ret;
}

/* 以 nobody(65534) 执行 path，参数固定是 -u（id -u 的语义） */
static int run_as_nobody(const char *path)
{
	pid_t pid;
	int status = 0;

	fflush(stdout);
	pid = fork();
	if (pid == 0) {
		if (setgid(65534) != 0 || setuid(65534) != 0)
			_exit(126);
		execl(path, path, "-u", (char *)NULL);
		_exit(127);
	}
	if (pid < 0)
		return -1;

	if (waitpid(pid, &status, 0) != pid)
		return -1;
	if (!WIFEXITED(status))
		return -1;
	return WEXITSTATUS(status);
}

/*
 * exec 钩子：把一份 id 拷到 /tmp 授权为 root，然后让 nobody 去执行它。
 * 授权前 uid 应该是 65534，授权后应该是 0 —— 这一步就是"setuid 位"的
 * 内核版，程序自己什么都不用做。
 */
static void test_exec_auto_root(void)
{
	const char *src = "/usr/bin/id";
	const char *dst = "/tmp/rootmgr_exec_probe";
	struct ksu_get_info_cmd info;
	int rc;

	section("EXEC 自动提权（授权后执行即 root）");

	if (geteuid() != 0) {
		printf("跳过：需要 root 才能 fork 一个降权子进程\n");
		return;
	}

	if (rootmgr_get_info(&info) == 0 && !(info.flags & KSU_FLAG_AUTOEXEC)) {
		printf("exec 钩子没挂上：模块 < 2.4，或者 exec_root=0\n");
		return;
	}

	if (copy_file(src, dst) != 0) {
		printf("跳过：拷不了 %s（%s）\n", src, strerror(errno));
		return;
	}

	if (rootmgr_set_state(dst, KSU_POLICY_ROOT) != 0) {
		perror("SET root");
		unlink(dst);
		return;
	}

	printf("授权 root 后，nobody 执行 %s -u => ", dst);
	rc = run_as_nobody(dst);
	if (rc == 127)
		printf("\n  （exec 失败：%s 可能挂在 noexec 分区）\n", dst);

	if (rootmgr_set_state(dst, KSU_POLICY_ASK) != 0)
		perror("SET ask");

	printf("撤销授权后，nobody 再执行一次 => ");
	run_as_nobody(dst);

	unlink(dst);
}

int main(void)
{
	char link[64], target[256];
	ssize_t n;

	setvbuf(stdout, NULL, _IOLBF, 0);
	uint32_t ver = 0;
	int fd, i;

	section("拿 fd");
	fd = rootmgr_fd();
	if (fd < 0) {
		perror("rootmgr_fd");
		fprintf(stderr, "拿不到 fd：模块没装，或者 kretprobe 没挂上\n");
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

	section("ioctl 通信（魔术 'K'）");
	if (rootmgr_ping() != 0) {
		perror("PING");
		return 1;
	}
	printf("PING ok\n");

	if (rootmgr_get_version(&ver) == 0)
		printf("version = %u (%u.%u.%u)\n", ver,
		       ver / 10000, ver / 100 % 100, ver % 100);

	print_info();

	test_app_profile();
	test_grant_root();
	test_grant_pid();
	test_exec_auto_root();

	rootmgr_fd_close();
	printf("\ndone\n");
	return 0;
}
