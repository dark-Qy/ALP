#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>

#include "local_out.h"
#include "hash_map.h"
#include "alp_header.h"
#include "dev_info.h"
#include "func.h"

// 将 TCP MSS 减小一定的量，为拓展头提供空间
static unsigned int set_mss(struct sk_buff *skb, size_t len) {
    struct ipv6hdr *iph;
    struct tcphdr *tcph;
    unsigned char *ptr;
    int opt_len;
    u16* mss;

    // 获取 IPv6 数据包头部
    iph = ipv6_hdr(skb);
    if (!iph || iph->nexthdr != IPPROTO_TCP)
        return 0;

    // 获取 TCP 数据包头部，协商 MSS 的过程一定出现在 SYN 包中，因此其他 TCP 包可以直接放行
    tcph = tcp_hdr(skb);
    if (!tcph || !tcph->syn)
        return 0;

    // 获取 TCP 选项部分
    ptr = (unsigned char *)tcph + sizeof(struct tcphdr);
    opt_len = (tcph->doff * 4) - sizeof(struct tcphdr);

    // 遍历 TCP 选项，查找 MSS 选项，TCP option 是 TLV 格式，其中 Type 和 Length 都各占一个字节
    while (opt_len > 0) {
        if (*ptr == TCPOPT_MSS && *(ptr + 1) == TCPOLEN_MSS) {
            if (*ptr == TCPOPT_MSS) {
            //if (*(ptr + 1) >= 4) {
                // 减小 MSS 值
                mss = (u16 *)(ptr + 2);
                *mss = ntohs(*mss);
                if (*mss > len) {
                    *mss -= len;
                }
                *mss = htons(*mss);
            }
            break;
        }
        if (*ptr == TCPOPT_EOL) {
        // if (*ptr <= 1) {
            break;
        }
        opt_len -= *(ptr + 1);
        ptr += *(ptr + 1);
    }

    return 0;
}

static unsigned int alp_local_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    // 根据数据包源 IP 地址查询是否有路径信息
    char path[512];
    char rid[RID_SIZE];
    unsigned int hop = 0;
    OPT_ALP_HEADER *alp_opt_hdr = NULL;
    struct in6_addr dst_ip;
    unsigned char *src;
    struct {
        unsigned char *path_mark;
        unsigned char *path_pi;
    } path_offset;
    char *session_key;
    char *hop_key;
    struct crypto_cipher *tfm;
    unsigned char seed[16];
    unsigned char epsilon[16];
    int ts;
    unsigned char beta[16];
    char next_rid[RID_SIZE];
    char dst_rid[RID_SIZE];
    path_offset.path_mark = NULL;
    path_offset.path_pi = NULL;

    // 如果这个数据包是邻居请求数据||邻居通告就不进行任何处理
    if(ipv6_hdr(skb)->nexthdr == IPPROTO_ICMPV6 && (icmp6_hdr(skb)->icmp6_type == 135 || icmp6_hdr(skb)->icmp6_type == 136)) {
        return NF_ACCEPT;
    }

    // 获取 skb 中的目的 IPv6 地址，并查询路径信息
    dst_ip = ipv6_hdr(skb)->daddr;
    if(-1 == find_path_by_ip6((char *)&dst_ip, path, &hop, dst_rid)) {
        return NF_DROP; // 如果没有路径信息，禁止数据包发出
    }

    // 如果路径信息存在，构造逐跳选项头，并附加必要的信息
    add_extended_header(skb, path, hop, rid);
    set_mss(skb, 2 + sizeof(OPT_ALP_HEADER) + PATH_LEN(hop));   // 设置 tcp 握手过程中协商的 mss 值
    alp_opt_hdr = skb_alp_header(skb);

    // 根据解密路径信息，获取下一跳 MAC
    path_offset.path_mark = (unsigned char *)(alp_opt_hdr + 1);
    if(PATH_LEN(alp_opt_hdr->hop_count) > alp_opt_hdr->path_length) {
        DEBUG_PRINT("Invalid path_offset info\n"); // 路径信息长度不足以计算出下一跳
        return NF_DROP;
    }
    path_offset.path_pi = path_offset.path_mark + PATH_LEN(alp_opt_hdr->hop_count);

    // 获取会话密钥并加密 aid 得到 seed
    session_key = get_session_key_by_ip6((char *)&ipv6_hdr(skb)->daddr);
    tfm = crypto_alloc_cipher("aes", 0, 0);
    crypto_cipher_setkey(tfm, session_key, 16);
    crypto_cipher_encrypt_one(tfm, seed, get_aid());

    // 根据 rid 和秘密值得到 beta
    mac(get_rid(), dst_rid, get_secret(), 8, session_key, beta);

    // 根据 beta 和 P0 异或得到下一跳 rid 以及与下一跳的对称密钥 hop_key
    xor_data(beta, path_offset.path_pi, next_rid, 4);
    hop_key = get_hop_key_by_rid(next_rid);

    // 根据 rid 和时间戳得到 epsilon
    ts = ktime_get();
    mac(get_rid(), next_rid, (char *)&ts, 4, hop_key, epsilon);
    alp_opt_hdr->timestamp = ts;

    // 生成地址标签，将其输出到源地址的后 64 位
    src = (unsigned char*)&(ipv6_hdr(skb)->saddr);
    xor_data(epsilon, get_aid(), src + 8, 8);

    // 修改 path_offset 信息中的 mark 部分
    xor_data(path_offset.path_mark, beta, path_offset.path_mark, 16);
    xor_data(path_offset.path_mark, seed, path_offset.path_mark, 16);
    xor_data(path_offset.path_mark, epsilon, path_offset.path_mark, 16);

    alp_opt_hdr->hop_count++;

    // 在 local_out 和 post_routing 之间，数据包会进行如下操作
    // 1. 在路由表中查询目的 ip 对应的网关 ip
    // 2. 在邻居表中查询网关 ip 对应的 mac 地址和指定设备
    // 3. 将数据包从指定设备发出
    // 但是现在需要的流程是：
    // 1. 解密得到下一跳 rid
    // 2. 根据 rid 要确定下一跳 mac 地址（或者说网关？）和指定的发送设备
    // 不知道这些流程具体应该怎么控制，因此 hooknum 使用 POST_ROUTING 进行处理。如果弄清楚了，应该采用 LOCAL_OUT 进行处理。

    // 根据路由标识设置下一跳 mac 地址，并构造以太头发送
    eth_header(skb, skb->dev, ETH_P_IPV6, get_next_mac_by_rid(next_rid), NULL, 0);

    dev_queue_xmit(skb);

	// 已经在该函数中已经构建了以太头，所以返回 NF_STOLEN 表示内核无需在对其进行处理
	return NF_STOLEN;
}

static struct nf_hook_ops nfho = {
    .hook = alp_local_out,
    .pf = NFPROTO_IPV6,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = NF_IP6_PRI_LAST
};

int local_out_init(void) {
    // todo: 设置虚假的设备信息
    set_aid("aaaaaaaa");
    set_rid("aaaa");
    set_secret("aaaaaaaa");
    nf_register_net_hook(&init_net, &nfho);
    return 0;
}

void local_out_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
}
    
    
    
