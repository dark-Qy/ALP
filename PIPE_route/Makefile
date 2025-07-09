EXTRA_CFLAGS += -I$(PWD)/include -I$(PWD)/ALH_header -I$(PWD)/alh_L2 -I$(PWD)/alh_L3 -I$(PWD)/hasht -I$(PWD)/port -lcrypto

all:
	if(test ! -d $(PWD)/bin)then mkdir $(PWD)/bin; fi
	gcc *.c */*.c -o ./bin/main $(EXTRA_CFLAGS) $(shell pkg-config --cflags --libs libdpdk)

clean:
	rm $(PWD)/bin/main

send:
	scp -r * bupt@172.16.72.132:/home/bupt/Program/dpdk-test