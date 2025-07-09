#include <stdint.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <time.h>
#include <signal.h>

#include "port.h"
#include "ALH.h"
#include "mackey_ht.h"
#include "alh_L2.h"
#include "alh_L3.h"

#define BURST_SIZE 32

// process the signal SIGINT
void exit_of_program(int signo) {
    printf("\nExiting...\n");

    mackey_ht_free();
    next_hop_mac_ht_free();
    prev_hop_mac_ht_free();
    rte_eal_cleanup();

    exit(0);
}

static void lcore_main(void) {
    uint16_t port;

    RTE_ETH_FOREACH_DEV(port)
        if (rte_eth_dev_socket_id(port) >= 0 &&
            rte_eth_dev_socket_id(port) != (int)rte_socket_id())
            printf("WARNING, port %u is on remote NUMA node to "
                    "polling thread.\n\tPerformance will "
                    "not be optimal.\n", port);

    printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n", rte_lcore_id());

	/* 设置循环监听网卡，接受到数据包的时候将其打印并原路返回一份 */
    for (;;) {
        RTE_ETH_FOREACH_DEV(port) {
            struct rte_mbuf *bufs[BURST_SIZE];
            const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
            unsigned char key[16], aid[AID_LEN];
            unsigned char src_rid[RID_LEN], dst_rid[RID_LEN];
            unsigned char pre_mac[6];
            int retval;

            if (unlikely(nb_rx == 0)) continue;
            
            for (uint16_t i = 0; i < nb_rx; i++) {
                struct rte_mbuf *m = bufs[i];
                struct rte_ether_addr next_hop;
                struct timespec ts1, ts2, ts3, ts4, ts5, ts6;

                clock_gettime(CLOCK_REALTIME, &ts1);

                retval = alh_l2_rx_handler(m, key,pre_mac);    // 2层接受函数需要根据源mac地址找到映射的对称密钥
                if(retval < 0) {
                    rte_pktmbuf_free(m);
                    continue;
                }
                clock_gettime(CLOCK_REALTIME, &ts2);
                
                retval = alh_l3_rx_handler(m, key, aid);    // 3层接受函数需要根据验证扩展报头（IPC和身份）
                if(retval < 0) {
                    rte_pktmbuf_free(m);
                    continue;
                }
                clock_gettime(CLOCK_REALTIME, &ts3);
                
                // l4_tx_handler(m);    // 4层发送函数需要根据应用层协议进行分流，但是dpdk主要用在网关上，暂时不考虑它的应用层问题
                    
                // 三层发送函数需要根据目的mac地址找到映射的对称密钥，所以需要提前查询下一跳的mac地址
                get_next_hop(rte_pktmbuf_mtod_offset(m, struct rte_ipv6_hdr *, sizeof(struct rte_ether_hdr))->dst_addr, &next_hop);

                alh_l3_tx_handler(m,pre_mac,&next_hop);       // 3层发送函数需要根据目的mac地址找到映射的对称密钥，并添加扩展报头
                clock_gettime(CLOCK_REALTIME, &ts4);
                long time_ns;
                alh_l2_tx_handler(port, &next_hop, m, &time_ns);    // 2层发送函数需要根据目的mac地址找到映射的对称密钥，并添加目的mac地址

                clock_gettime(CLOCK_REALTIME, &ts5);

                printf("alh_l2_rx_handler Nanoseconds: %ld\n", ts2.tv_nsec - ts1.tv_nsec);
                printf("alh_l3_rx_handler Nanoseconds: %ld\n", ts3.tv_nsec - ts2.tv_nsec);
                printf("alh_l3_tx_handler Nanoseconds: %ld\n", ts4.tv_nsec - ts3.tv_nsec);
                printf("alh_l2_tx_handler Nanoseconds: %ld\n", ts5.tv_nsec - ts4.tv_nsec);
                printf("alh_l2_tx_handler Nanoseconds without tx_burst: %ld\n", time_ns);
                printf("Total Nanoseconds: %ld\n", ts5.tv_nsec - ts1.tv_nsec);
                printf("Total Nanoseconds without tx_burst: %ld\n", ts4.tv_nsec - ts1.tv_nsec + time_ns);

            }
        }
    }
}

int main(int argc, char *argv[]) {
    struct rte_mempool *mbuf_pool;
    int retval;
    unsigned dev_count = 0;

    retval = rte_eal_init(argc, argv);      // 初始化 Environment Abstraction Layer (EAL)
    if(retval < 0)
        rte_exit(EXIT_FAILURE, "\033[32m****Error with EAL initialization\033[0m\n");

    argc -= retval;
    argv += retval;

    init_hash_tables();
    // set signal handler for SIGINT
    signal(SIGINT, exit_of_program);

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", 8192, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    dev_count = rte_eth_dev_count_avail();
    printf("Port count: %u\n", dev_count);
    for(int i = 0; i < dev_count; i++) {
        port_init(i, mbuf_pool);
    }
    lcore_main();
    
    rte_eal_cleanup();
    return 0;
}