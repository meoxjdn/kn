# 纯净版内核模块 Makefile (专为 GitHub Actions DDK 适配)
obj-m += wuwa_stepper.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all: driver

driver:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
