# export ARCH = arm64
# export CROSS_COMPILE = aarch64-none-linux-gnu
obj-m += ex_chrdev.o
KDIR := /usr/src/linux-headers-6.12.107+deb13-amd64
PWD ?= $(shell pwd)
all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
