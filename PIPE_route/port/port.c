#include "port.h"

static const struct rte_eth_conf port_conf_default = {
    .rxmode = { .max_lro_pkt_size = RTE_ETHER_MAX_LEN }
};

int port_init(uint8_t port, struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = 1024, nb_txd = 1024;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    // 配置端口
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0) {
        rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n", retval, port);
    }

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n", port, strerror(-retval));
        return retval;
    }

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    // 设置RX和TX队列
    for(q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, 0, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0) {
            rte_exit(EXIT_FAILURE, "Cannot setup rx queue: err=%d, port=%u\n", retval, port);
        }
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    for (q = 0; q < tx_rings; q++) {
    retval = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }

    // 启动端口
    retval = rte_eth_dev_start(port);
    if (retval < 0) {
        rte_exit(EXIT_FAILURE, "Cannot start port: err=%d, port=%u\n", retval, port);
    }
    // 使网卡工作在混杂模式
    /*
    retval = rte_eth_promiscuous_enable(port);
    if (retval < 0) {
	rte_exit(EXIT_FAILURE, "Cannot set port promiscuous\n");
    }
    */
    struct rte_ether_addr mac_addr;
    char dev_name[RTE_ETH_NAME_MAX_LEN];
    rte_eth_macaddr_get(port, &mac_addr);
    rte_eth_dev_get_name_by_port(port, dev_name);
    // 打印MAC地址
    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&mac_addr));

    printf("%d[%s] Ethernet interface start\n", port, dev_name);
}