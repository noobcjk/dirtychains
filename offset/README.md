# offset/：内核偏移配置表

CVE-2026-64531（OVS CT action 越界）需要 29 个结构体字段偏移、2 个符号偏移和 4 项
行为参数。这些都由内核构建决定，程序启动时按本机 `uname -r` 到这里找表，
**不需要重新编译**。

## 目录规则

```
offset/
├── 5系/5.14.0-611.54.6.el9_7.x86_64/target.h
├── 5系/5.8.0-59-generic/target.h
├── 6系/6.8.0-100-generic/target.h
└── 7系/7.0.0-14-generic/target.h
```

第一层是 `uname -r` 的第一个数字加「系」，第二层原样照抄 `uname -r`，
文件名固定 `target.h`。`target.h` 既是被逐行解析的配置，也是合法 C 头文件
（可以 `#include` 静态编译）。

## 当前内容

**740 个 release**，其中：

| 来源 | 数量 | 说明 |
|---|---|---|
| 记录集重建 | 739 | 由 `krec-808.json` 的 808 条去重生成（同 release 不同 build 只留最后一条） |
| 本机实测 | 1 | `5系/5.8.0-59-generic`，内核模块 `tools/kmod` 在真机上读出 |

分布：5系 164（5.14 有 30、5.15 有 133、5.8 有 1）、6系 489、7系 87。
覆盖 6.1 / 6.6 / 6.8 / 6.11 / 6.12 / 6.13 / 6.14 / 6.15 / 6.16 / 6.17 / 6.18 / 6.19 /
7.0 / 7.1 各发行版构建。**5.4 没有、5.8 只有这一条**，其余老内核走动态推导或 `-krec` 借用。

完整的 808 条原始记录（含被覆盖的 69 条重复）在源码根目录的 `krec-808.json`，
`make offset-sync` 可以据此整批重建本目录。**程序只认这里的表，没有内嵌兜底。**

## 查找顺序

```
-offset <dir>  →  $OVSWRAP_OFFSET_DIR  →  <可执行文件目录>/offset
               →  ./offset  →  /usr/share/dirtyfrag/offset
               →  BTF / pahole / System.map 推导
```

目录里没有本机 release 时逐级回退，最后退回动态推导（需要 BTF 或 System.map）。
所以拷走单个二进制时，记得把 `offset/` 一起带上。

## target.h 里有什么

```c
#define KREC_FORMAT        1
#define KREC_RELEASE       "6.8.0-100-generic"
#define KREC_VERSION       ""
#define KREC_VERSION_HASH  1339404537UL     /* version 为空时用它判 exact */
#define KREC_MACHINE       "x86_64"

#define KREC_VMLINUX_MODULE_KTYPE 23473792UL  /* 相对 _text，与 KASLR 无关 */
#define KREC_VMLINUX_INIT_PID_NS  23473472UL
#define KREC_TASK_PID             2272        /* 结构体字段偏移 */
...
#define KREC_REF_KIND      "__refcnt"         /* 或 __rcuref */
#define KREC_TUNNEL_INFO   31                 /* 29 或 31 */
#define KREC_READ_CARRIER  "timeout"          /* 或 labels-only */
#define KREC_WRITE_CARRIER "timeout"
#define KREC_READ_LANES    "tos,ttl,tp_src_0,..."
```

三类字段的来源不同：

| 类别 | 来源 | 能否自动推导 |
|---|---|---|
| 27 个结构体字段偏移 | 编译器写入的 BTF/DWARF，或 `offsetof()` | 能（pahole / 内核模块） |
| 2 个符号偏移 | `System.map` 或 `/proc/kallsyms` 减 `_text` | 能 |
| `ref_kind` / `tunnel_info` | 内核源码的枚举与成员定义 | 能（看源码或 uapi 头） |
| `read_carrier` / `write_carrier` / `read_lanes` | **实机试出来的** | 不能，只能跑 `-scan` 看 |

## 加一台新机器

**1. 有 BTF / dbgsym**（最省事）：

```bash
./ovswrap -dump-target > /tmp/target.h
mkdir -p "offset/$(uname -r | cut -d. -f1)系/$(uname -r)"
mv /tmp/target.h "offset/$(uname -r | cut -d. -f1)系/$(uname -r)/"
```

**2. 没有 BTF，但有内核头**：用 `tools/kmod` 的模块现测，输出 JSON 再转：

```bash
make kmod && sudo insmod tools/kmod/krec_dump.ko
cat /proc/krec_dump > rec.json && sudo rmmod krec_dump
python3 tools/mk_offset.py rec.json        # 直接写进 offset/
```

**3. 结构体没变，借用邻近版本**（零成本，先试这个）：

```bash
./ovswrap -check -krec 6.8.0-100-generic   # 跑 -scan 看自检过不过
```

**4. 手工补一份**：复制一份同系列的 `target.h`，改 `KREC_RELEASE`，再按实机结果
调整 `READ_LANES` / carrier。丢字段的表现在加载时会被拒绝（少于 20 个键，或缺
`TASK_PID` / `TASK_CRED` / `CRED_FSUID` / 两个符号偏移之一）。

改完存盘即生效，不用 `make`。

## 重新生成

```bash
make offset-sync               # 用 krec-808.json 整批重建 offset/
make offset-add REC=rec.json   # 单条记录 -> offset/
```

`make offset-sync` 只在内容不同时才写盘（显示「未变 740」），加 `--force` 才强制覆盖。

## 校验

740 张 `target.h` 已与 `krec-808.json` 逐条比对：27 个字段偏移、2 个符号偏移、
`ref_kind`、`tunnel_info`、两种 carrier、lane 顺序、版本哈希、release 字符串——
**0 处不符**。
