#include <stdint.h>
#include <rte_ethdev.h>
#include <rte_ip.h>

int alh_l2_rx_handler(struct rte_mbuf *mbuf, unsigned char *key,unsigned char *pre_mac);
int alh_l2_tx_handler(uint16_t rx_port, struct rte_ether_addr *next_hop,struct rte_mbuf *mbuf, long *time_ns);  // time_ns 仅在测试中计算发出数据包之前所产生的时间开销，没有实际意义
int get_next_hop(unsigned char *dst_ip, struct rte_ether_addr *next_hop);