#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <openssl/sha.h>

#include "ALH.h"

int add_alh_header(struct rte_mbuf *mbuf) {
    unsigned int data_len = sizeof(LABEL_HEADER);
    LABEL_HEADER *data = NULL;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv6_hdr *ipv6_hdr;
    char *p;

    if (rte_pktmbuf_headroom(mbuf) < data_len) {
        printf("Not enough headroom or tailroom in mbuf\n");
        rte_pktmbuf_free(mbuf);
        return -1;
    }

    p = rte_pktmbuf_prepend(mbuf, data_len);
    memset(data, 0, data_len);

    // 将以太头和IPv6头拷贝到mbuf的头部位置，然后更新各个指针
    eth_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ether_hdr *, sizeof(LABEL_HEADER));
    ipv6_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv6_hdr *, sizeof(LABEL_HEADER) + sizeof(struct rte_ether_hdr));
    memcpy(p, eth_hdr, sizeof(struct rte_ether_hdr));
    memcpy(p + sizeof(struct rte_ether_hdr), ipv6_hdr, sizeof(struct rte_ipv6_hdr));
    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    ipv6_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv6_hdr *, sizeof(struct rte_ether_hdr));

    data = (LABEL_HEADER *)(p + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr));

    return 0;
}

int remove_alh_header(struct rte_mbuf *mbuf) {
    unsigned int label_hdr_len = sizeof(LABEL_HEADER);
    LABEL_HEADER *label_hdr = NULL;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv6_hdr *ipv6_hdr;
    unsigned char *p;

    // 将以太头和IPv6头拷贝到LABEL_HEADER位置处
    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    ipv6_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv6_hdr *, sizeof(struct rte_ether_hdr));
    p = rte_pktmbuf_mtod_offset(mbuf, unsigned char *, sizeof(LABEL_HEADER));

    memcpy(p + sizeof(struct rte_ether_hdr), ipv6_hdr, sizeof(struct rte_ipv6_hdr));
    memcpy(p, eth_hdr, sizeof(struct rte_ether_hdr));

    rte_pktmbuf_adj(mbuf, label_hdr_len);

    return 0;
}