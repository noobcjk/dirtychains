# DirtyChains —— GTK3 / XFCE 前端（引擎已内嵌，单文件）
#
#   make                编译 dirtychains（前端 + 五链引擎 + OVS 引擎）
#   make poc            另外编一个独立的命令行引擎
#   make ovswrap        用同一个源编出不含 GTK 的 OVS 命令行版
#   make offset-add REC=rec.json 把一条记录写成 offset/<N>系/<release>/target.h
#   make offset-sync     从 krec-808.json 整批重建 offset/ 目录树
#   make kmod            编译 tools/kmod 的偏移提取模块
#   sudo make install   装到 /usr/local/bin，背景图与 offset/ 进 share/dirtychains
#   make clean

CC     ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
PKG    := gtk+-3.0

GTK_CFLAGS := $(shell pkg-config --cflags $(PKG))
GTK_LIBS   := $(shell pkg-config --libs $(PKG))

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
DATADIR ?= $(PREFIX)/share/dirtychains

TARGET     := dirtychains
# 单文件：GTK 前端 + ovswrap 引擎都在这里（偏移表在 offset/，运行时读）
# 源文件名保留 dirtyfrag-gui.c / dirtyfrag_lpe.c：记录实现来路，不随项目名改
SRC        := dirtyfrag-gui.c
ENGINE_SRC := dirtyfrag_lpe.c
ENGINE     := poc
REC        ?= rec.json
BGIMG      := bg.png

GUI_OBJ := dirtychains.o
ENG_OBJ := dirtychains-engine.o

# 引擎里有若干 (void)write 的 unused-result 警告，与功能无关，统一压掉
ENGINE_CFLAGS := $(CFLAGS) -Wno-unused-result

all: $(TARGET)

# 前端侧（含内置 OVS 引擎）：main 保持原名
$(GUI_OBJ): $(SRC)
	$(CC) $(CFLAGS) $(GTK_CFLAGS) -c -o $@ $<

# 五链引擎侧：把 main 改名，免得和 GUI 的 main 撞车
$(ENG_OBJ): $(ENGINE_SRC)
	$(CC) $(ENGINE_CFLAGS) -Dmain=dirtychains_poc_main -c -o $@ $<

$(TARGET): $(GUI_OBJ) $(ENG_OBJ)
	$(CC) -o $@ $(GUI_OBJ) $(ENG_OBJ) $(GTK_LIBS) -lutil

# 独立的命令行版本，可单独拷走使用
poc: $(ENGINE_SRC)
	$(CC) $(ENGINE_CFLAGS) -o $@ $<

# CVE-2026-64531 (net/openvswitch CT action 越界) 命令行版
# 源码就在 dirtyfrag-gui.c 里，用 OVSWRAP_STANDALONE 把 GTK 段裁掉
ovswrap: $(SRC)
	$(CC) $(CFLAGS) -DOVSWRAP_STANDALONE -o $@ $<

# 预置内核表：把原版 base85+zlib 表去重打包后写回源文件
krec:
	python3 tools/gen_krec_table.py $(KREC_PY) $(KREC_SRC)

# 编译偏移提取模块（目标机需要 linux-headers-$(uname -r)）
kmod:
	$(MAKE) -C tools/kmod

# 外部配置表：一条记录写成一个目录（rec.json 由 `ovswrap -dump-krec` 生成）
offset-add:
	python3 tools/mk_offset.py $(REC) --root offset

# 外部配置表：从记录集整批重建（krec-808.json 是历史内嵌表的完整导出）
offset-sync:
	python3 tools/mk_offset.py --from-json krec-808.json --root offset

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	@if [ -f $(ENGINE) ]; then \
		install -m 755 $(ENGINE) $(DESTDIR)$(BINDIR)/$(ENGINE); \
		echo "cli engine -> $(DESTDIR)$(BINDIR)/$(ENGINE) (可选)"; \
	fi
	@if [ -f $(BGIMG) ]; then \
		install -d $(DESTDIR)$(DATADIR); \
		install -m 644 $(BGIMG) $(DESTDIR)$(DATADIR)/$(BGIMG); \
		echo "background -> $(DESTDIR)$(DATADIR)/$(BGIMG)"; \
	else \
		echo "提示: 没有 $(BGIMG)，界面使用纯色底"; \
	fi
	@if [ -d offset ]; then \
		install -d $(DESTDIR)$(DATADIR)/offset; \
		cp -r offset/. $(DESTDIR)$(DATADIR)/offset/; \
		echo "offset tables -> $(DESTDIR)$(DATADIR)/offset"; \
	fi
	@if [ -f tools/kmod/krec_dump.c ]; then \
		install -d $(DESTDIR)$(DATADIR)/tools/kmod; \
		install -m 644 tools/kmod/krec_dump.c tools/kmod/Makefile \
			$(DESTDIR)$(DATADIR)/tools/kmod/; \
		echo "kmod source -> $(DESTDIR)$(DATADIR)/tools/kmod (root 获取偏移表用)"; \
	fi
	@if [ -f tools/kmod/krec_dump.ko ]; then \
		install -m 644 tools/kmod/krec_dump.ko $(DESTDIR)$(DATADIR)/krec_dump.ko; \
		echo "krec_dump.ko -> $(DESTDIR)$(DATADIR)/krec_dump.ko"; \
	fi

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(BINDIR)/$(ENGINE)
	rm -f $(DESTDIR)$(DATADIR)/$(BGIMG)
	rm -rf $(DESTDIR)$(DATADIR)/offset
	rm -rf $(DESTDIR)$(DATADIR)/tools
	rm -f $(DESTDIR)$(DATADIR)/krec_dump.ko

clean:
	rm -f $(TARGET) $(GUI_OBJ) $(ENG_OBJ) $(ENGINE) ovswrap

.PHONY: all install uninstall clean poc ovswrap offset-add offset-sync kmod
