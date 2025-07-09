#include <rte_byteorder.h>
#include <time.h>

#include "alh_L2.h"
#include "mackey_ht.h"

#define ETHER_TYPE_IPv6 0x86dd

int alh_l2_rx_handler(struct rte_mbuf *mbuf, unsigned char *key,unsigned char *pre_mac) {
    struct rte_ether_hdr *eth_hdr;
    int retval = 0;

    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

    // 首先判断以太头中的EtherType是否为IPv6，ALH只关注IPv6数据包
    if(eth_hdr->ether_type != rte_cpu_to_be_16(ETHER_TYPE_IPv6)) {
        printf("\033[33mWarning\033[0m: Ether type: %04X\n", eth_hdr->ether_type);
        return -2;
    }
    // 保存上一跳的MAC地址
    memcpy(pre_mac,eth_hdr->src_addr.addr_bytes,MAC_LEN);

    return 0;
}

int alh_l2_tx_handler(uint16_t rx_port, struct rte_ether_addr *next_hop,struct rte_mbuf *mbuf, long *time_ns) {
    struct rte_ether_hdr *eth_hdr;
    uint16_t tx_port = rx_port ^ 1;
    uint16_t nb_tx;
    struct timespec ts1, ts2;
    clock_gettime(CLOCK_REALTIME, &ts1);

    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    rte_eth_macaddr_get(tx_port, &eth_hdr->src_addr);
    rte_ether_addr_copy(next_hop, &eth_hdr->dst_addr);

    clock_gettime(CLOCK_REALTIME, &ts2);
    *time_ns = ts2.tv_nsec - ts1.tv_nsec;

    nb_tx = rte_eth_tx_burst(tx_port, 0, &mbuf, 1);

    /* 对于没有成功返回的数据包，需要手动将空间释放，使其回到 mempool */
    if (unlikely(nb_tx < 1)) 
        rte_pktmbuf_free(mbuf);
    else {
        // 打印数据包
        //printf("********\n");
       //rte_pktmbuf_dump(stdout, mbuf, rte_pktmbuf_pkt_len(mbuf));
    }

    return 0;
}

// 根据下一跳的ipv6地址获取下一跳的MAC地址
int get_next_hop(unsigned char *dst_ip, struct rte_ether_addr *next_hop) {
    // 这里需要根据NDP获取下一跳的MAC地址，在测试中直接通过静态匹配
    unsigned char ip_2024[16] = "\x20\x24";
    unsigned char nexthop_2024[6] = "\x00\x0c\x29\x9e\x15\x24";

    unsigned char ip_2025[16] = "\x20\x25";
    unsigned char nexthop_2025[6] = "\x00\x0c\x29\xa6\x12\x28";

    if(memcmp(ip_2024, dst_ip, 8) == 0)
        memcpy(next_hop, nexthop_2024, 6);
    else
        memcpy(next_hop, nexthop_2025, 6);
    
    //memset(next_hop, 0xff, sizeof(struct rte_ether_addr));
    return 0;
}
