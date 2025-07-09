#include <rte_mbuf.h>
#include <rte_ether.h>

#ifndef __L3_H__
#define __L3_H__

#define OUT
#define IN
#define AID_LEN 8

#endif

int alh_l3_rx_handler(struct rte_mbuf *mbuf, IN unsigned char *key, OUT unsigned char *aid);
int alh_l3_tx_handler(struct rte_mbuf *mbuf, IN unsigned char *pre_mac,OUT struct rte_ether_addr *next_hop);