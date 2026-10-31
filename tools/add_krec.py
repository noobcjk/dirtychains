#!/usr/bin/env python3
"""把一条内核记录合并进 ovswrap.c 里的预置表。

用法:
    python3 tools/add_krec.py rec.json ovswrap.c [--dry-run]

rec.json 就是 `ovswrap -dump-krec` 打出来的那种 JSON（单条对象或数组）:

    ovswrap -dump-krec > rec.json
    python3 tools/add_krec.py rec.json ovswrap.c

合并规则:
    * 同 release 且 version 哈希相同  -> 覆盖那一条（改错重来很方便）
    * 同 release 但 build 串不同      -> 追加一条
    * release 没出现过               -> 追加

写回时会重新去重、重新打包，其它记录一条不动（会打印 before/after 条数）。
"""

import json
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])

import gen_krec_table as g


def validate(record, index):
    def need(cond, msg):
        if not cond:
            raise SystemExit(f"第 {index} 条记录有问题: {msg}")

    need(isinstance(record, dict), "不是 JSON 对象")
    need(record.get("release"), "缺 release")
    need(record.get("version", "") is not None, "version 不能是 null")
    off = record.get("offsets")
    need(isinstance(off, dict), "缺 offsets 对象")

    for name in g.LAYOUT_FIELDS:
        need(name in off, f"offsets 缺字段 {name}")
        value = off[name]
        need(isinstance(value, int) and 0 <= value <= 0xFFFF,
             f"offsets.{name}={value!r} 不是 0..65535 的整数")

    for name in g.SYMBOL_FIELDS:
        need(name in off, f"offsets 缺字段 {name}")
        value = off[name]
        need(isinstance(value, int) and 0 <= value <= 0xFFFFFFFF,
             f"offsets.{name}={value!r} 不是 0..2^32-1 的整数")

    kind = off.get("dst_entry_ref_kind")
    need(kind in ("__rcuref", "__refcnt"),
         f"offsets.dst_entry_ref_kind 只能是 __rcuref / __refcnt，给的是 {kind!r}")

    for key in ("read_carrier", "write_carrier"):
        value = record.get(key, "timeout")
        need(value in g.CARRIERS, f"{key}={value!r} 只能是 timeout / labels-only")
        record[key] = value

    lanes = record.get("read_lanes", [])
    need(isinstance(lanes, list), "read_lanes 必须是数组")
    for lane in lanes:
        need(lane in g.LANE_ID, f"未知 lane {lane!r}")
    need(len(lanes) <= 14, "read_lanes 最多 14 条")
    record["read_lanes"] = lanes

    ti = record.get("ovs_key_attr_tunnel_info", 31)
    need(isinstance(ti, int) and 0 < ti < 256, f"ovs_key_attr_tunnel_info={ti!r} 不像 attr id")
    record["ovs_key_attr_tunnel_info"] = ti

    record.setdefault("machine", "x86_64")
    record.setdefault("version", "")


def main() -> None:
    args = [a for a in sys.argv[1:] if a != "--dry-run"]
    dry = "--dry-run" in sys.argv[1:]
    if len(args) != 2:
        raise SystemExit(__doc__)

    rec_path, c_path = args
    incoming = json.load(open(rec_path, encoding="utf-8"))
    if isinstance(incoming, dict):
        incoming = [incoming]
    for i, record in enumerate(incoming):
        validate(record, i)

    src = open(c_path, encoding="utf-8").read()
    records = g.unpack(g.decode_c_blob(src))
    before = len(records)

    index = {}
    for i, record in enumerate(records):
        index[(record["release"], g.version_hash(record))] = i

    replaced = added = 0
    for record in incoming:
        key = (record["release"], g.version_hash(record))
        if key in index:
            records[index[key]] = record
            replaced += 1
        else:
            index[key] = len(records)
            records.append(record)
            added += 1

    blob = g.pack(records)
    print(f"表: {before} -> {len(records)} 条（新增 {added}，覆盖 {replaced}），"
          f"raw={len(blob)}B b85={len(__import__('base64').b85encode(blob))}B")
    for record in incoming:
        print(f"  + {record['release']}  "
              f"{record['read_carrier']}/{record['write_carrier']} "
              f"tunnel_info={record['ovs_key_attr_tunnel_info']} "
              f"lanes={len(record['read_lanes'])}")

    if dry:
        print("--dry-run：没有写文件")
        return

    open(c_path, "w", encoding="utf-8").write(g.replace_block(src, g.emit_c(blob)))
    print(f"已写回 {c_path}；重新 make 让它进入二进制。")


if __name__ == "__main__":
    main()
