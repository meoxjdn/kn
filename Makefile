# 最终修正版 Makefile - 确保输出文件名与 Actions 匹配
MODULE_NAME := android-wuwa

# 核心逻辑：将 wuwa_stepper.o 链接为 android-wuwa.ko
obj-m += $(MODULE_NAME).o
$(MODULE_NAME)-y := wuwa_stepper.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
