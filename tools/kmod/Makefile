# SPDX-License-Identifier: GPL-2.0
#
# krec_dump —— 直接打印 CVE-2026-64531 需要的偏移与符号地址
#
#   make                   构建（自动判断 dst_entry 用 __rcuref 还是 __refcnt）
#   sudo insmod krec_dump.ko
#   cat /proc/krec_dump > rec.json
#   sudo rmmod krec_dump
#
# 指定别的内核树：make KDIR=/path/to/linux-headers
# 强制字段选择：  make KCFLAGS=-DKREC_FORCE_REFCNT
#                 make KCFLAGS=-DKREC_FORCE_RCUREF

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# 两个独立模块，同一份 Makefile 里靠 ROOTMGR 切换目标。
# 用 := 而不是 +=，否则命令行传 obj-m= 时会被这里的追加弄成两个模块。
ifdef ROOTMGR
obj-m := rootmgr.o
else
obj-m += krec_dump.o
endif

all:
	@if [ ! -d "$(KDIR)" ]; then \
		echo "找不到内核树 $(KDIR)"; \
		echo "  Ubuntu/Debian: sudo apt install linux-headers-\$$(uname -r)"; \
		echo "  RHEL/CentOS:   sudo dnf install kernel-devel-\$$(uname -r)"; \
		exit 1; \
	fi
	@if $(MAKE) -s -C $(KDIR) M=$(PWD) modules >/dev/null 2>&1; then \
		echo "krec_dump.ko: dst_entry 引用计数字段按内核版本选定"; \
	elif $(MAKE) -s -C $(KDIR) M=$(PWD) modules KCFLAGS=-DKREC_FORCE_REFCNT >/dev/null 2>&1; then \
		echo "krec_dump.ko: dst_entry.__refcnt（版本号不准，已回退）"; \
	elif $(MAKE) -s -C $(KDIR) M=$(PWD) modules KCFLAGS=-DKREC_FORCE_RCUREF >/dev/null 2>&1; then \
		echo "krec_dump.ko: dst_entry.__rcuref（版本号不准，已切换）"; \
	else \
		echo "两种字段都编不过，下面是默认配置的完整报错："; \
		$(MAKE) -C $(KDIR) M=$(PWD) modules; \
	fi

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# 常驻 root 管理器（独立模块，和 krec_dump 互不影响）
#   make rootmgr
#   sudo insmod rootmgr.ko [allow_uid=1000]
rootmgr:
	@if [ ! -d "$(KDIR)" ]; then \
		echo "找不到内核树 $(KDIR)"; \
		echo "  Ubuntu/Debian: sudo apt install linux-headers-\$$(uname -r)"; \
		echo "  RHEL/CentOS:   sudo dnf install kernel-devel-\$$(uname -r)"; \
		exit 1; \
	fi
	$(MAKE) -C $(KDIR) M=$(PWD) ROOTMGR=1 modules

rootmgr-clean:
	$(MAKE) -C $(KDIR) M=$(PWD) ROOTMGR=1 clean

.PHONY: all clean rootmgr rootmgr-clean
