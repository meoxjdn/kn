obj-m += wuwa_stepper.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all: driver ctrl

driver:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

ctrl: wuwa_ctrl.c
	$(CC) -O2 -Wall wuwa_ctrl.c -o wuwa_ctrl

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f wuwa_ctrl
