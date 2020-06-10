obj-m := vtx.o

KERN_SRC := /usr/src/linux-headers-5.3.0-53-generic

.PHONY: run ins msg rm clean

run: ins rm msg

vtx.ko: vtx.c
	make -C $(KERN_SRC) M=$(PWD) modules

ins: vtx.ko
	sudo insmod $<

rm:
	sudo rmmod vtx

msg:
	dmesg -x | grep vtx

clean:
	make -C $(KERN_SRC) M=$(PWD) clean
