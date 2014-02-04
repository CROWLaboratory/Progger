TARGETS = all clean

obj-m:=progger.o
KVERSION = $(shell uname -r)
KDIR:=/lib/modules/$(KVERSION)/build
PWD:= $(shell pwd)

all:
	make -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
