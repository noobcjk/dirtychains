#!/usr/bin/env python3
"""把 ovswrap-poc.py 里的 base85+zlib 内核记录表转成 dirtyfrag-gui.c 能直接吃的紧凑二进制块。

用法:
    python3 tools/gen_krec_table.py <ovswrap-poc.py> <dirtyfrag-gui.c>
    python3 tools/gen_krec_table.py --dump <dirtyfrag-gui.c>      # 反解成 JSON 看看表里有什么

做的事情:
  1. 解出原版 _KERNEL_RECORDS_B85 (b85 -> zlib -> JSON, 808 条)。
  2. 去重: offsets / carrier+tunnel+lanes 组合 / release 字符串池。
  3. 打包成固定小端二进制, 再用 base85 编码成 C 字符串字面量。
  4. 重写 dirtyfrag-gui.c 里 BEGIN KREC / END KREC 之间的内容。

二进制格式 (全部小端):
    char  magic[4]      "OKR1"
    u16   n_rec
    u16   n_off
    u16   n_combo
    u16   fmt           当前 1
    u32   pool_len
  offsets[n_off]:  27 x u16 布局偏移, u32 vmlinux_module_ktype,
                   u32 vmlinux_init_pid_ns, u8 ref_kind
  combos[n_combo]: u8 read_carrier, u8 write_carrier, u8 tunnel_info,
                   u8 nlanes, u8 lane_id[nlanes]
  recs[n_rec]:     u32 release_off, u32 version_hash, u16 off_idx,
                   u8 combo_idx, u8 rsvd
  pool:            NUL 结尾的 release 字符串
"""

import ast
import base64
import json
import re
import struct
import sys
import zlib

# 与 dirtyfrag-gui.c 里 struct koffs 的字段顺序严格一致（ref_kind 单独占 1 字节）
LAYOUT_FIELDS = [
    "nf_conntrack_helper_me",
    "module_kobj_ktype",
    "task_pid",
    "task_cred",
    "task_pid_links",
    "cred_fsuid",
    "cred_fsgid",
    "cred_cap_permitted",
    "cred_cap_effective",
    "pid_namespace_idr",
    "idr_idr_rt",
    "idr_base",
    "xarray_xa_head",
    "xa_node_shift",
    "xa_node_slots",
    "pid_tasks",
    "hlist_head_first",
    "dst_entry_ref",
    "metadata_dst_tun_info",
    "ip_tunnel_key_ipv4_src",
    "ip_tunnel_key_ipv4_dst",
    "ip_tunnel_key_tos",
    "ip_tunnel_key_ttl",
    "ip_tunnel_key_tp_src",
    "ip_tunnel_key_tp_dst",
    "ovs_ct_labels",
    "ovs_ct_action_len",
]

SYMBOL_FIELDS = ["vmlinux_module_ktype", "vmlinux_init_pid_ns"]

LANES = [
    "tos",
    "ttl",
    "tp_src_0",
    "tp_src_1",
    "tp_dst_0",
    "tp_dst_1",
    "ipv4_src_0",
    "ipv4_src_1",
    "ipv4_src_2",
    "ipv4_src_3",
    "ipv4_dst_0",
    "ipv4_dst_1",
    "ipv4_dst_2",
    "ipv4_dst_3",
]
LANE_ID = {name: i for i, name in enumerate(LANES)}

CARRIERS = {"timeout": 0, "labels-only": 1}
CARRIER_NAMES = {v: k for k, v in CARRIERS.items()}

MAGIC = b"OKR1"
FMT = 1
HEADER_LEN = 16
OFF_STRIDE = len(LAYOUT_FIELDS) * 2 + 8 + 1     # 63
REC_STRIDE = 12

BLOCK_RE = re.compile(r"/\* BEGIN KREC.*?/\* END KREC \*/\n", re.S)


def fnv1a(text: str) -> int:
    h = 0x811C9DC5
    for byte in text.encode():
        h = ((h ^ byte) * 0x01000193) & 0xFFFFFFFF
    return h


def version_hash(record) -> int:
    if "version_hash" in record:
        return int(record["version_hash"])
    return fnv1a(record.get("version", ""))


# --------------------------------------------------------------------------
# 从 .c 里取出 base85 文本并解码
# --------------------------------------------------------------------------

def extract_b85_text(src: str) -> str:
    m = BLOCK_RE.search(src)
    if not m:
        raise SystemExit("dirtyfrag-gui.c 里没有 BEGIN KREC / END KREC 标记块")
    return "".join(re.findall(r'"([^"]*)"', m.group(0)))


def decode_c_blob(src: str) -> bytes:
    return base64.b85decode(extract_b85_text(src))


# --------------------------------------------------------------------------
# 打包 / 解包
# --------------------------------------------------------------------------

def pack(records) -> bytes:
    offsets_pool = []
    offsets_index = {}
    combo_pool = []
    combo_index = {}
    string_pool = bytearray()
    string_index = {}

    def intern(text):
        if text not in string_index:
            string_index[text] = len(string_pool)
            string_pool.extend(text.encode() + b"\x00")
        return string_index[text]

    recs = []
    for rec in records:
        off = rec["offsets"]
        key = (
            tuple(off[name] for name in LAYOUT_FIELDS),
            off["vmlinux_module_ktype"],
            off["vmlinux_init_pid_ns"],
            off["dst_entry_ref_kind"],
        )
        if key not in offsets_index:
            for name in LAYOUT_FIELDS:
                value = off[name]
                if not 0 <= value <= 0xFFFF:
                    raise SystemExit(f"{rec['release']}: {name}={value} 超出 u16")
            offsets_index[key] = len(offsets_pool)
            offsets_pool.append(key)

        combo_key = (
            rec["read_carrier"],
            rec["write_carrier"],
            rec["ovs_key_attr_tunnel_info"],
            tuple(rec["read_lanes"]),
        )
        if combo_key not in combo_index:
            combo_index[combo_key] = len(combo_pool)
            combo_pool.append(combo_key)

        recs.append(
            (
                intern(rec["release"]),
                version_hash(rec),
                offsets_index[key],
                combo_index[combo_key],
            )
        )

    if len(recs) > 0xFFFF or len(offsets_pool) > 0xFFFF or len(combo_pool) > 0xFFFF:
        raise SystemExit("记录数超出 u16")

    out = bytearray()
    out += MAGIC
    out += struct.pack("<HHHHI", len(recs), len(offsets_pool), len(combo_pool),
                       FMT, len(string_pool))

    for layout, sym_ktype, sym_pidns, ref_kind in offsets_pool:
        out += struct.pack("<27HIIB", *layout, sym_ktype, sym_pidns,
                           0 if ref_kind == "__rcuref" else 1)

    for read_carrier, write_carrier, tunnel_info, lanes in combo_pool:
        if len(lanes) > 14:
            raise SystemExit(f"lane 数量异常: {len(lanes)}")
        out += struct.pack("<BBBB", CARRIERS[read_carrier], CARRIERS[write_carrier],
                           tunnel_info, len(lanes))
        out += bytes(LANE_ID[name] for name in lanes)

    for rel_off, ver_hash, off_idx, combo_idx in recs:
        out += struct.pack("<IIHBB", rel_off, ver_hash, off_idx, combo_idx, 0)

    out += string_pool
    return bytes(out)


def unpack(blob: bytes):
    if len(blob) < HEADER_LEN or blob[:4] != MAGIC:
        raise SystemExit("blob 头损坏")
    n_rec, n_off, n_combo, fmt, pool_len = struct.unpack_from("<HHHHI", blob, 4)
    if fmt != FMT:
        raise SystemExit(f"不认识的格式版本 {fmt}")
    p = HEADER_LEN

    off_tab = blob[p:p + n_off * OFF_STRIDE]
    p += n_off * OFF_STRIDE

    combos = []
    for _ in range(n_combo):
        rc, wc, ti, nlanes = blob[p], blob[p + 1], blob[p + 2], blob[p + 3]
        lanes = [LANES[i] for i in blob[p + 4:p + 4 + nlanes]]
        combos.append((CARRIER_NAMES[rc], CARRIER_NAMES[wc], ti, lanes))
        p += 4 + nlanes

    rec_tab = blob[p:p + n_rec * REC_STRIDE]
    p += n_rec * REC_STRIDE
    pool = blob[p:p + pool_len]

    def cstr(off):
        end = pool.index(b"\x00", off)
        return pool[off:end].decode()

    records = []
    for i in range(n_rec):
        rel_off, ver_hash, off_idx, combo_idx, _ = struct.unpack_from(
            "<IIHBB", rec_tab, i * REC_STRIDE)
        base = off_idx * OFF_STRIDE
        layout = struct.unpack_from("<27H", off_tab, base)
        sym_ktype, sym_pidns = struct.unpack_from("<II", off_tab, base + 54)
        ref_kind = off_tab[base + 62]
        read_carrier, write_carrier, tunnel_info, lanes = combos[combo_idx]

        offsets = {name: int(value) for name, value in zip(LAYOUT_FIELDS, layout)}
        offsets["vmlinux_module_ktype"] = sym_ktype
        offsets["vmlinux_init_pid_ns"] = sym_pidns
        offsets["dst_entry_ref_kind"] = "__rcuref" if ref_kind == 0 else "__refcnt"

        records.append({
            "release": cstr(rel_off),
            "version": "",
            "version_hash": ver_hash,
            "machine": "x86_64",
            "offsets": offsets,
            "read_carrier": read_carrier,
            "write_carrier": write_carrier,
            "read_lanes": lanes,
            "ovs_key_attr_tunnel_info": tunnel_info,
        })
    return records


# --------------------------------------------------------------------------
# 生成 C 代码块
# --------------------------------------------------------------------------

def emit_c(blob: bytes) -> str:
    text = base64.b85encode(blob).decode()
    width = 96
    lines = [text[i:i + width] for i in range(0, len(text), width)]
    body = "\n".join('    "%s"' % line for line in lines)
    return (
        "/* BEGIN KREC: 由 tools/gen_krec_table.py 生成, 不要手改 */\n"
        "#define KREC_B85_LEN %d\n"
        "static const char krec_b85[] =\n%s;\n"
        "/* END KREC */\n" % (len(text), body)
    )


def replace_block(src: str, block: str) -> str:
    if not BLOCK_RE.search(src):
        raise SystemExit("dirtyfrag-gui.c 里没有 KREC 标记块")
    return BLOCK_RE.sub(lambda _: block, src, count=1)


# --------------------------------------------------------------------------
# 入口
# --------------------------------------------------------------------------

def load_records(path: str):
    src = open(path, "rb").read()
    m = re.search(
        rb"# BEGIN EMBEDDED KERNEL RECORDS\n_KERNEL_RECORDS_B85 = \((.*?)\)\n# END",
        src,
        re.S,
    )
    if not m:
        raise SystemExit("源文件里找不到 _KERNEL_RECORDS_B85")
    blob = ast.literal_eval(m.group(1).decode())
    return json.loads(zlib.decompress(base64.b85decode(blob)))


def main() -> None:
    args = sys.argv[1:]
    if args[:1] == ["--dump"] and len(args) == 2:
        src = open(args[1], "r", encoding="utf-8").read()
        records = unpack(decode_c_blob(src))
        json.dump(records, sys.stdout, ensure_ascii=False, indent=1)
        sys.stdout.write("\n")
        sys.stderr.write(f"{len(records)} 条记录\n")
        return

    if len(args) != 2:
        raise SystemExit(__doc__)

    records = load_records(args[0])
    blob = pack(records)
    path = args[1]
    src = open(path, "r", encoding="utf-8").read()
    open(path, "w", encoding="utf-8").write(replace_block(src, emit_c(blob)))
    print(
        f"records={len(records)} raw={len(blob)}B "
        f"b85={len(base64.b85encode(blob))}B -> {path}"
    )


if __name__ == "__main__":
    main()
