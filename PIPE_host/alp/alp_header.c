#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>

#include "alp_header.h"

OPT_ALP_HEADER *skb_alp_header(struct sk_buff *skb) {
    // 由于逐跳选项头中的选项需要按顺序处理，所以判断第一个选项头是否是地址标签选项头即可
    struct ipv6hdr *ipv6_header;
    struct ipv6_hopopt_hdr *hopopt_header;
    unsigned char *opt_type;

    ipv6_header = ipv6_hdr(skb);
    if(ipv6_header->nexthdr == NEXTHDR_HOP) {
        hopopt_header = (struct ipv6_hopopt_hdr*)(ipv6_header + 1);
        opt_type = (unsigned char*)(hopopt_header + 1);
        if(*opt_type == OPT_ALP)
            return (OPT_ALP_HEADER*)(opt_type);
    }
    return NULL;
}

int add_extended_header(struct sk_buff *skb, char *path, unsigned int hop, const char *rid) {
    struct ipv6hdr ipv6_header;
    struct ipv6_hopopt_hdr *hop_header;
    unsigned int hopopt_len = 0;
    unsigned char *integral_hopopt_hdr = NULL;
    unsigned char *extended_header = NULL;
    OPT_ALP_HEADER *alp_opt_hdr = NULL;
    short payload_len;

    // 复制备份原IPv6基本报头以及可能存在的逐跳选项头，然后将其移除，并扩大 sk_buff 的大小以容纳地址标签选项头
    memcpy(&ipv6_header, skb->data, IPV6_HEADER_LEN);    
    if(ipv6_header.nexthdr == NEXTHDR_HOP) {
        hop_header = (struct ipv6_hopopt_hdr*)(skb->data + IPV6_HEADER_LEN);
        hopopt_len = (hop_header->hdrlen + 1) << 3;
        integral_hopopt_hdr = kmalloc(hopopt_len, GFP_KERNEL);
        memcpy(integral_hopopt_hdr, hop_header, hopopt_len);
    }
    skb_pull(skb, IPV6_HEADER_LEN + hopopt_len);
    pskb_expand_head(skb, 2 + sizeof(OPT_ALP_HEADER) + PATH_LEN(hop), 0, GFP_ATOMIC);

    // 创建地址标签选项头，如果已经存在逐跳选项头，则地址标签选项头前需要补 2 字节的 PadN 选项头。否则，需要补上逐跳选项头
    // todo: 这里填充 2B 是为了满足 HBH 的字节对齐要求，实际上现在的报头设计中，不一定是 2B
    extended_header = skb_push(skb, 2 + sizeof(OPT_ALP_HEADER) + PATH_LEN(hop));
    if(hopopt_len != 0) memset(extended_header, 0x0100, 2);
    else {
        hop_header = (struct ipv6_hopopt_hdr*)extended_header;
        hop_header->nexthdr = ipv6_header.nexthdr;
        hop_header->hdrlen = ((2 + sizeof(OPT_ALP_HEADER) + PATH_LEN(hop)) >> 3) - 1;
    }
    alp_opt_hdr = (OPT_ALP_HEADER*)(extended_header + 2);
    alp_opt_hdr->opt_type = OPT_ALP;
    alp_opt_hdr->opt_datalen = sizeof(OPT_ALP_HEADER) + PATH_LEN(hop) - 2;
    alp_opt_hdr->path_length = PATH_LEN(hop);
    alp_opt_hdr->hop_count = 0;
    memcpy(alp_opt_hdr->IPC, rid, RID_SIZE);    // local_out 借助 IPC 字段将目的 rid 传递到 post_routing
    memcpy(alp_opt_hdr + 1, path, PATH_LEN(hop));
    // 剩余字段应在 post_routing 阶段填充

    // 恢复 IPv6 基本报头以及可能存在的逐跳选项头
    // 恢复时需要修改 IPv6 头部的协议和 payload_len 字段、逐跳选项头的长度字段 
    ipv6_header.nexthdr = NEXTHDR_HOP;
    payload_len = ntohs(ipv6_header.payload_len);
    payload_len += sizeof(OPT_ALP_HEADER) + 2 + PATH_LEN(hop);
    ipv6_header.payload_len = htons(payload_len);
    if(hopopt_len != 0) {
        hop_header = skb_push(skb, hopopt_len);
        memcpy((unsigned char*)hop_header, integral_hopopt_hdr, hopopt_len);
        kfree(integral_hopopt_hdr);
        integral_hopopt_hdr = NULL;
        hop_header->hdrlen += (2 + sizeof(OPT_ALP_HEADER) + PATH_LEN(hop)) >> 3;
    }
    memcpy(skb_push(skb, IPV6_HEADER_LEN), &ipv6_header, sizeof(struct ipv6hdr));
    skb_reset_network_header(skb);
    skb_reset_mac_header(skb);
    
    return 0;
}

int remove_extended_header(struct sk_buff *skb) {
    short payload_len;
    unsigned int buff_len = 0;
    struct ipv6_hopopt_hdr *hop_header = NULL;
    struct ipv6hdr *ipv6_header;
    char *header_buff = NULL;
    OPT_ALP_HEADER *alp_opt_hdr = skb_alp_header(skb);
    
    // 备份基本报头和逐跳选项头，然后将其移除
    buff_len = (unsigned char*)alp_opt_hdr - skb->data;
    header_buff = kmalloc(buff_len, GFP_KERNEL);
    memcpy(header_buff, skb->data, buff_len);
    ipv6_header = (struct ipv6hdr*)header_buff;
    hop_header = (struct ipv6_hopopt_hdr*)(header_buff + buff_len - 2);
    skb_pull(skb, buff_len);


    // 移除 ALP 选项头，并修改
    if((hop_header->hdrlen + 1) << 3 > sizeof(OPT_ALP_HEADER) + PATH_LEN(alp_opt_hdr->hop_count) + 2) {
        // TODO: 处理可能存在的剩余逐跳选项
    }
    else {
        ipv6_header->nexthdr = hop_header->nexthdr;
        skb_pull(skb, sizeof(OPT_ALP_HEADER) + PATH_LEN(alp_opt_hdr->hop_count));
        payload_len = ntohs(ipv6_header->payload_len);
        payload_len -= sizeof(OPT_ALP_HEADER) + 2 + PATH_LEN(alp_opt_hdr->hop_count);
        ipv6_header->payload_len = htons(payload_len);
        buff_len -= 2;  // 逐跳选项头被一并移除

        // Update the sk_buff's control block
        IP6CB(skb)->flags &= (~IP6SKB_HOPBYHOP);
        IP6CB(skb)->nhoff = 6;
    }

    memcpy(skb_push(skb, buff_len), header_buff, buff_len);
    skb_reset_network_header(skb);

    return 0;
}
