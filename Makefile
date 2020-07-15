obj-m := vmx.o

CFLAGS_vmx.o := -std=gnu11 -Wno-declaration-after-statement -mno-ms-bitfields
KERN_SRC := /usr/src/linux-headers-5.3.0-62-generic

.PHONY: run ins msg rm clean

run: ins rm msg

vmx.ko: vmx.c
	make -C $(KERN_SRC) M=$(PWD) modules

ins: vmx.ko
	sudo insmod $<

rm:
	sudo rmmod vmx

msg:
	dmesg -x

clean:
	make -C $(KERN_SRC) M=$(PWD) clean
