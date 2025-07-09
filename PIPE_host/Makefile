obj-m := alp.o
alp-objs := main.o tools/func.o control/dev_info.o control/hash_map.o alp/alp_header.o hook_out/local_out.o hook_in/local_in.o

EXTRA_CFLAGS += -Wall -DOSA_LINUX -D__KERNEL__ -I$(src)/control -I$(src)/tools -I$(src)/alp -I$(src)/hook_out -I$(src)/hook_in

all:
	make -C /usr/src/linux-headers-$(shell uname -r) M=$(PWD) modules

clean:	
	make -C /usr/src/linux-headers-$(shell uname -r) M=$(PWD) clean