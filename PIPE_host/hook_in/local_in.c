#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include "local_in.h"
#include "func.h"
#include "hash_map.h"
#include "alp_header.h"
#include "dev_info.h"

static unsigned int alp_local_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    unsigned char epsilon[16];
    char prev_rid[RID_SIZE];
    unsigned char *src;
    unsigned char *reply_addr = NULL;
    char *session_key;
    unsigned char aid_src[8];
    struct crypto_cipher *tfm;
    unsigned char *path_mark = NULL;
    OPT_ALP_HEADER *alp_opt_hdr = skb_alp_header(skb);

    if(alp_opt_hdr == NULL) {
        return NF_ACCEPT;
    }

    // 根据上一跳 mac 地址获取 rid，然后和 ts 一起进行 mac 得到 epsilon
    memcpy(prev_rid, get_prev_rid_by_mac(eth_hdr(skb)->h_source), RID_SIZE);
    mac(prev_rid, get_rid(), (char *)&alp_opt_hdr->timestamp, 4, get_hop_key_by_rid(prev_rid), epsilon);

    // 将 epsilon 和源 IP 地址的最后 64 位异或得到第一个源 aid
    src = (unsigned char*)&(ipv6_hdr(skb)->saddr);
    xor_data(src + 8, epsilon, src + 8, 8);

    // 将路径信息中的 mark 与 epsilon 异或得到最终的 mark_dst
    path_mark = (unsigned char *)(alp_opt_hdr + 1);
    xor_data(path_mark, epsilon, path_mark, 16);

    // 根据第一个源 aid 获取会话密钥，解密 mark 得到第二个源 aid
    session_key = get_session_key_by_aid(src + 8);
    tfm = crypto_alloc_cipher("aes", 0, 0);
    crypto_cipher_setkey(tfm, session_key, 16);
    crypto_cipher_decrypt_one(tfm, aid_src, path_mark);

    // 比较两个源 aid 是否一致，若不一致则说明数据包不符合方案设计逻辑
    if(memcmp(aid_src, src + 8, 8) != 0) {
        DEBUG_PRINT("[ALP] aid not match\n");
        return NF_DROP;
    }

    // 移除扩展报头
    remove_extended_header(skb);

    // 根据解密出的 aid 还原出真实的源 ip，使终端能够构造回复包
    src = (unsigned char*)&(ipv6_hdr(skb)->saddr);
    reply_addr = get_ip6_by_aid(aid_src);
    if(reply_addr != NULL)
        memcpy(src, reply_addr, 16);

    return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
    .hook = alp_local_in,
    .pf = NFPROTO_IPV6,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP6_PRI_FIRST
};

int local_in_init(void) {
    nf_register_net_hook(&init_net, &nfho);
    return 0;
}

void local_in_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
}