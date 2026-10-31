# DirtyFrag GUI —— GTK3 / XFCE 前端（引擎已内嵌）
#
#   make                编译单文件 dirtyfrag-gui（GUI + 五链引擎）
#   make poc            另外编一个独立的命令行 poc
#   make ovswrap        编译 CVE-2026-64531 (OVS) 独立验证程序
#   make krec           从原版 ovswrap-poc.py 重新生成预置内核表
#   make krec-add REC=rec.json   把一条记录并进表
#   make offset-add REC=rec.json 把一条记录写成 offset/<N>系/<release>/target.h
#   make offset-sync     把内嵌表整表导出成 offset/ 目录树
#   make krec-export     导出内嵌表：krec-808.json + 整表写进 offset/
#   make kmod            编译 tools/kmod 的偏移提取模块
#   sudo make install   装到 /usr/local/bin，背景图进 share/dirtyfrag
#   make clean

CC     ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
PKG    := gtk+-3.0

GTK_CFLAGS := $(shell pkg-config --cflags $(PKG))
GTK_LIBS   := $(shell pkg-config --libs $(PKG))

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
APPDIR  ?= $(PREFIX)/share/applications
DATADIR ?= $(PREFIX)/share/dirtyfrag

TARGET     := dirtyfrag-gui
SRC        := dirtyfrag-gui.c
ENGINE_SRC := dirtyfrag_lpe.c
ENGINE     := poc
OVS_SRC    := ovswrap.c
KREC_PY    ?= ovswrap-poc.py
REC        ?= rec.json
BGIMG      := bg.png

GUI_OBJ := dirtyfrag-gui.o
ENG_OBJ := dirtyfrag-engine.o
OVS_OBJ := ovswrap-engine.o

# 引擎里有若干 (void)write 的 unused-result 警告，与功能无关，统一压掉
ENGINE_CFLAGS := $(CFLAGS) -Wno-unused-result

all: $(TARGET)

# GUI 侧：main 保持原名
$(GUI_OBJ): $(SRC)
	$(CC) $(CFLAGS) $(GTK_CFLAGS) -c -o $@ $<

# 引擎侧：把 main 改名，免得和 GUI 的 main 撞车
$(ENG_OBJ): $(ENGINE_SRC)
	$(CC) $(ENGINE_CFLAGS) -Dmain=dirtyfrag_poc_main -c -o $@ $<

# OVS 引擎：同样把 main 改名，避免和 GUI 的 main 撞车
$(OVS_OBJ): $(OVS_SRC)
	$(CC) $(CFLAGS) -Dmain=ovswrap_main -c -o $@ $<

$(TARGET): $(GUI_OBJ) $(ENG_OBJ) $(OVS_OBJ)
	$(CC) -o $@ $(GUI_OBJ) $(ENG_OBJ) $(OVS_OBJ) $(GTK_LIBS) -lutil

# 独立的命令行版本，可单独拷走使用
poc: $(ENGINE_SRC)
	$(CC) $(ENGINE_CFLAGS) -o $@ $<

# CVE-2026-64531 (net/openvswitch CT action 越界) 独立验证程序
ovswrap: ovswrap.c
	$(CC) $(CFLAGS) -o $@ $<

# 预置内核表：把原版 base85+zlib 表去重打包后写回 ovswrap.c
krec:
	python3 tools/gen_krec_table.py $(KREC_PY) $(OVS_SRC)

# 编译偏移提取模块（目标机需要 linux-headers-$(uname -r)）
kmod:
	$(MAKE) -C tools/kmod

# 把一条记录并进表（rec.json 由 `ovswrap -dump-krec` 生成）
krec-add:
	python3 tools/add_krec.py $(REC) $(OVS_SRC)

# 外部配置表：一条记录写成一个目录
offset-add:
	python3 tools/mk_offset.py $(REC) --root offset

# 外部配置表：内嵌表整表导出（739 个 release 目录）
offset-sync:
	python3 tools/mk_offset.py --from-c $(OVS_SRC) --root offset

# 提取内嵌表：JSON 全集 + 目录树，直接落到 offset/
krec-export:
	python3 tools/gen_krec_table.py --dump $(OVS_SRC) > krec-808.json
	python3 tools/mk_offset.py --from-c $(OVS_SRC) --root offset
	@python3 -c 'import json;print("records:", len(json.load(open("krec-808.json"))))'

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(APPDIR)
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
	install -m 644 dirtyfrag-gui.desktop $(DESTDIR)$(APPDIR)/
	@if [ -d offset ]; then \
		install -d $(DESTDIR)$(DATADIR)/offset; \
		cp -r offset/. $(DESTDIR)$(DATADIR)/offset/; \
		echo "offset tables -> $(DESTDIR)$(DATADIR)/offset"; \
	fi

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(BINDIR)/$(ENGINE)
	rm -f $(DESTDIR)$(APPDIR)/dirtyfrag-gui.desktop
	rm -f $(DESTDIR)$(DATADIR)/$(BGIMG)
	rm -rf $(DESTDIR)$(DATADIR)/offset

clean:
	rm -f $(TARGET) $(GUI_OBJ) $(ENG_OBJ) $(OVS_OBJ)

.PHONY: all install uninstall clean poc ovswrap krec krec-add offset-add offset-sync krec-export kmod
