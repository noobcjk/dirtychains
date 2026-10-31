#!/usr/bin/env python3
"""
把内核偏移记录写成外部配置表：

    offset/<N>系/<release>/target.h

两种输入：

    python3 tools/mk_offset.py rec.json              # 一条（ovswrap -dump-krec 的输出）
    python3 tools/mk_offset.py --from-c ovswrap.c    # 内嵌表里的 808 条全导出来

target.h 是一组 #define，ovswrap 启动时按 `uname -r` 找到对应目录直接读，
不再需要重新编译。它同时是合法 C 头文件，可以 #include 静态编译。

目录结构（--root 改变根）：

    offset/
      5系/
        5.8.0-59-generic/target.h
      6系/
        6.6.117-45.11.6.tl4.x86_64/target.h
"""

import argparse
import json
import sys
from pathlib import Path

# 与 ovswrap.c 的 struct th_key / print_target 一一对应
FIELDS = [
    ("NF_CONNTRACK_HELPER_ME", "nf_conntrack_helper_me"),
    ("MODULE_KOBJ_KTYPE", "module_kobj_ktype"),
    ("TASK_PID", "task_pid"),
    ("TASK_CRED", "task_cred"),
    ("TASK_PID_LINKS", "task_pid_links"),
    ("CRED_FSUID", "cred_fsuid"),
    ("CRED_FSGID", "cred_fsgid"),
    ("CRED_CAP_PERMITTED", "cred_cap_permitted"),
    ("CRED_CAP_EFFECTIVE", "cred_cap_effective"),
    ("PID_NAMESPACE_IDR", "pid_namespace_idr"),
    ("IDR_IDR_RT", "idr_idr_rt"),
    ("IDR_BASE", "idr_base"),
    ("XARRAY_XA_HEAD", "xarray_xa_head"),
    ("XA_NODE_SHIFT", "xa_node_shift"),
    ("XA_NODE_SLOTS", "xa_node_slots"),
    ("PID_TASKS", "pid_tasks"),
    ("HLIST_HEAD_FIRST", "hlist_head_first"),
    ("DST_ENTRY_REF", "dst_entry_ref"),
    ("METADATA_DST_TUN_INFO", "metadata_dst_tun_info"),
    ("IP_TUNNEL_KEY_IPV4_SRC", "ip_tunnel_key_ipv4_src"),
    ("IP_TUNNEL_KEY_IPV4_DST", "ip_tunnel_key_ipv4_dst"),
    ("IP_TUNNEL_KEY_TOS", "ip_tunnel_key_tos"),
    ("IP_TUNNEL_KEY_TTL", "ip_tunnel_key_ttl"),
    ("IP_TUNNEL_KEY_TP_SRC", "ip_tunnel_key_tp_src"),
    ("IP_TUNNEL_KEY_TP_DST", "ip_tunnel_key_tp_dst"),
    ("OVS_CT_LABELS", "ovs_ct_labels"),
    ("OVS_CT_ACTION_LEN", "ovs_ct_action_len"),
]

DEFAULT_LANES = "tos,ttl,tp_src_0,tp_src_1,tp_dst_0,tp_dst_1," \
                "ipv4_src_0,ipv4_src_1,ipv4_src_2,ipv4_src_3," \
                "ipv4_dst_0,ipv4_dst_1,ipv4_dst_2,ipv4_dst_3"


def fnv1a(text):
    """与 ovswrap.c 的 fnv1a32 一致：用于 KREC_VERSION_HASH。"""
    h = 0x811C9DC5
    for b in text.encode():
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def render(rec, source=""):
    o = rec["offsets"]
    missing = [k for _, k in FIELDS if k not in o]
    if missing:
        raise SystemExit("记录缺少字段：" + ", ".join(missing))
    for k in ("vmlinux_module_ktype", "vmlinux_init_pid_ns"):
        if k not in o:
            raise SystemExit("记录缺少字段：" + k)

    rel = rec["release"]
    ver = rec.get("version", "")
    vhash = int(rec.get("version_hash") or (fnv1a(ver) if ver else 0))
    mach = rec.get("machine", "x86_64")
    lanes = rec.get("read_lanes") or DEFAULT_LANES.split(",")
    lanes = ",".join(lanes) if isinstance(lanes, list) else str(lanes)

    out = []
    out.append("/*")
    out.append(" * target.h - dirtyfrag OVS (CVE-2026-64531) kernel offsets")
    out.append(" *")
    out.append(" * 放这里：offset/<N>系/<release>/target.h")
    out.append(" * 例：    offset/5系/5.8.0-59-generic/target.h")
    out.append(" *")
    out.append(" * 程序启动时按目录名找本机 release，不需要重新编译。")
    out.append(" * 本文件同时也是合法 C 头文件，可以直接 #include 静态编译。")
    out.append(" *")
    out.append(" * 生成: tools/mk_offset.py" + (f"（{source}）" if source else ""))
    out.append(" */")
    out.append("#ifndef DIRTYFRAG_TARGET_H")
    out.append("#define DIRTYFRAG_TARGET_H")
    out.append("")
    out.append("#define KREC_FORMAT        1")
    out.append(f'#define KREC_RELEASE       "{rel}"')
    out.append(f'#define KREC_VERSION       "{ver}"')
    out.append(f'#define KREC_VERSION_HASH  {vhash}UL')
    out.append(f'#define KREC_MACHINE       "{mach}"')
    out.append("")
    out.append("/* 符号偏移：相对 _text，与 KASLR 无关 */")
    out.append(f"#define KREC_VMLINUX_MODULE_KTYPE {int(o['vmlinux_module_ktype'])}UL")
    out.append(f"#define KREC_VMLINUX_INIT_PID_NS  {int(o['vmlinux_init_pid_ns'])}UL")
    out.append("")
    out.append("/* 结构体字段偏移 */")
    for macro, key in FIELDS:
        out.append(f"#define {'KREC_' + macro:<30} {int(o[key])}")
    out.append("")
    out.append("/* 行为参数：从调试信息推不出来，只能实机试 */")
    kind = o.get("dst_entry_ref_kind", "__rcuref")
    out.append(f'#define KREC_REF_KIND      "{kind}"')
    out.append(f"#define KREC_TUNNEL_INFO   {int(rec.get('ovs_key_attr_tunnel_info', 31))}")
    out.append(f'#define KREC_READ_CARRIER  "{rec.get("read_carrier", "timeout")}"')
    out.append(f'#define KREC_WRITE_CARRIER '
               f'"{rec.get("write_carrier", rec.get("read_carrier", "timeout"))}"')
    out.append(f'#define KREC_READ_LANES    "{lanes}"')
    out.append("")
    out.append("#endif /* DIRTYFRAG_TARGET_H */")
    out.append("")
    return "\n".join(out)


def dest_path(root, release):
    major = release.split(".", 1)[0]
    if not major.isdigit():
        raise SystemExit(f"release 解析不出主版本号：{release}")
    return Path(root) / f"{major}系" / release / "target.h"


def write_one(root, rec, force, dry, stats, source="", quiet_conflict=False):
    text = render(rec, source)
    path = dest_path(root, rec["release"])
    if path.exists():
        old = path.read_text(encoding="utf-8")
        if old == text:
            stats["same"] += 1
            return
        if not force:
            if quiet_conflict:      # 批量导出：同 release 不同 build，留最后一条
                stats["update"] += 1
                path.write_text(text, encoding="utf-8")
                return
            stats["conflict"] += 1
            print(f"  冲突: {path} 已存在且内容不同（--force 覆盖）", file=sys.stderr)
            return
        stats["update"] += 1
    else:
        stats["new"] += 1
    if dry:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def load_from_c(path):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import gen_krec_table as g

    src = Path(path).read_text(encoding="utf-8")
    return g.unpack(g.decode_c_blob(src))


def main():
    ap = argparse.ArgumentParser(
        description="把内核偏移记录写成 offset/<N>系/<release>/target.h")
    ap.add_argument("rec", nargs="?", help="rec.json（ovswrap -dump-krec 输出）")
    ap.add_argument("--from-c", metavar="OVSWRAP_C",
                    help="从内嵌表批量导出（传 ovswrap.c）")
    ap.add_argument("--root", default="offset", help="配置表根目录，默认 offset")
    ap.add_argument("--force", action="store_true", help="覆盖已存在且内容不同的表")
    ap.add_argument("--dry-run", action="store_true", help="只统计不写盘")
    args = ap.parse_args()

    stats = {"new": 0, "update": 0, "same": 0, "conflict": 0}

    if args.from_c:
        records = load_from_c(args.from_c)
        # 同 release 有多个 build 时只留最后一条，避免每轮重复覆盖
        last = {}
        for rec in records:
            last[rec["release"]] = rec
        print(f"内嵌表：{len(records)} 条，{len(last)} 个 release")
        for rec in last.values():
            write_one(args.root, rec, args.force, args.dry_run, stats, "内嵌表")
    elif args.rec:
        rec = json.loads(Path(args.rec).read_text(encoding="utf-8"))
        write_one(args.root, rec, args.force, args.dry_run, stats, args.rec)
    else:
        ap.error("需要 rec.json 或 --from-c ovswrap.c")

    print(f"新增 {stats['new']}，覆盖 {stats['update']}，"
          f"未变 {stats['same']}，冲突 {stats['conflict']}"
          + ("（--dry-run，未写盘）" if args.dry_run else ""))
    if stats["conflict"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
