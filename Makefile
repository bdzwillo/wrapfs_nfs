WRAPFS_VERSION="1.4"

ARCH=$(shell uname -m)

ifeq ($(KERNEL_SOURCE), )
KERNEL_VERSION=$(shell uname -r)
KERNEL_SOURCE=/lib/modules/$(KERNEL_VERSION)/build
endif

EXTRA_CFLAGS += -DWRAPFS_VERSION=\"$(WRAPFS_VERSION)\"
#ccflags-y := -DDEBUG
ccflags-y := -DWRAP_REMOTE_FILE_LOCKS -DWRAPFS_INTERCEPT_INODE_MODIFY

obj-m += wrapfs.o
wrapfs-y := dentry.o file.o inode.o main.o super.o lookup.o mmap.o

all:
	make -C $(KERNEL_SOURCE) M=$(PWD) modules

clean:
	make -C $(KERNEL_SOURCE) M=$(PWD) clean


