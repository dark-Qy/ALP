#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <time.h>
#include <openssl/hmac.h>
#include "alh_L3.h"
#include "ALH.h"
#include "mackey_ht.h"


void print_hex(const char *label, const unsigned char *data, int len);
// 将两个数据异或
void xor_data(const char* in1, const char* in2, char* out, int len) {
    int i;
    for(i = 0; i < len; i++) {
        out[i] = in1[i] ^ in2[i];
    }
}

void MDD5(const unsigned char *buffer, size_t len, unsigned char *mac_out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); // 创建上下文
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_MD_CTX\n");
        return;
    }

    // 初始化 MD5 算法
    if (EVP_DigestInit_ex(ctx, EVP_md5(), NULL) != 1) {
        fprintf(stderr, "EVP_DigestInit_ex failed\n");
        EVP_MD_CTX_free(ctx);
        return;
    }

    // 更新数据
    if (EVP_DigestUpdate(ctx, buffer, len) != 1) {
        fprintf(stderr, "EVP_DigestUpdate failed\n");
        EVP_MD_CTX_free(ctx);
        return;
    

    // 获取最终的哈希值
    unsigned int out_len;
    if (EVP_DigestFinal_ex(ctx, mac_out, &out_len) != 1) {
        fprintf(stderr, "EVP_DigestFinal_ex failed\n");
        EVP_MD_CTX_free(ctx);
        return;
    }

    EVP_MD_CTX_free(ctx); // 释放上下文
}

// 计算MAC值，其中 len 标志了前一个字段使用的是 ts(4B)  还是 secret(8B)
void mac(const char* rid1, const char* rid2, const char* ts_or_secret, const size_t len, const char* key, char* mac_out) {
    struct crypto_shash *tfm;
    struct shash_desc *shash;
    unsigned char buffer[32];

    // 将所有参数拼接在一起进行加密
    memcpy(buffer, rid1, 4);
    memcpy(buffer + 4, rid2, 4);
    memcpy(buffer + 8, ts_or_secret, len);
    memcpy(buffer + 8 + len, key, 16);
    MDD5(buffer,24+len,mac_out);
}



static void get_ipc(IN struct rte_ipv6_hdr *ipv6_hdr,  IN const char *aid, IN const char* eea, IN unsigned int ts, IN unsigned sn, OUT char *ipc) {
    const unsigned int HASH_LEN = 16 + 16 + 8 + EEA_LEN + 4 + 4;
    unsigned char  temp[HASH_LEN];

    memcpy(temp, ipv6_hdr->src_addr, 16);
    memcpy(temp + 16, ipv6_hdr->dst_addr, 16);
    memcpy(temp + 32, aid, AID_LEN);
    memcpy(temp + 40, eea, EEA_LEN);
    memcpy(temp + 40 + EEA_LEN, &ts, 4);
    memcpy(temp + 40 + EEA_LEN + 4, &sn, 4);
    SHA256(temp, HASH_LEN, ipc);
}

int alh_l3_rx_handler(struct rte_mbuf *mbuf, IN unsigned char *key, OUT unsigned char *aid) {
    struct rte_ipv6_hdr *ipv6_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv6_hdr *, sizeof(struct rte_ether_hdr));
    // 获取数据包中的Hop by Hop扩展报头
    // 由于是option字段，所以需要再往数据包头后移动 Next Header(8 bit) + Hdr Len(8 bit) 的长度
    LABEL_HEADER *label_hdr = rte_pktmbuf_mtod_offset(mbuf, LABEL_HEADER *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr)+2);

    // 首先判断接受的数据包中是否有IPv6 Hop by Hop扩展报头
    if (ipv6_hdr->proto != IPPROTO_HOPOPTS) {
        printf("\033[31mError\033[0m: No Hop by Hop header!\n");
        return -1;
    }
    // 然后判断Option字段中的Option Type 是否为 0x33
    if (label_hdr->opt_type != 0x33) {
        printf("\033[31mError\033[0m: No ALH header!\n");
        return -1;
    }

    // 由于不需要进行字段校验，因此接收到直接返回即可
    return 0;
}

int alh_l3_tx_handler(struct rte_mbuf *mbuf, IN unsigned char *pre_mac,OUT struct rte_ether_addr *next_hop) {
    struct rte_ipv6_hdr *ipv6_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv6_hdr *, sizeof(struct rte_ether_hdr));
    LABEL_HEADER *alp_opt_hdr = rte_pktmbuf_mtod_offset(mbuf, LABEL_HEADER *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr)+2);
    // 偏移量
    struct {
        unsigned char *path_mark;
        unsigned char *path_pi;
    } path_offset;
    unsigned char *src;
    path_offset.path_mark = NULL;
    path_offset.path_pi = NULL;
    // 对偏移量进行赋值
    path_offset.path_mark = (unsigned char *)(alp_opt_hdr + 1);
    if(PATH_LEN(alp_opt_hdr->hop_count) > alp_opt_hdr->path_length) {
        printf("\033[31mError\033[0m: Invalid path_offset info!\n");
        return -1;
    }
    path_offset.path_pi = path_offset.path_mark + PATH_LEN(alp_opt_hdr->hop_count);
    alp_opt_hdr->hop_count++;
    
    printf("MARK = %02x%02x%02x%02x\n", path_offset.path_mark[0], path_offset.path_mark[1], path_offset.path_mark[2], path_offset.path_mark[3]);
    printf("Pi = %02x%02x%02x%02x\n", path_offset.path_pi[0], path_offset.path_pi[1], path_offset.path_pi[2], path_offset.path_pi[3]);

    
    // 相关变量值
    unsigned char epsilon_1[16],epsilon_2[16];
    unsigned char beta[16];
    unsigned char dst_rid[RID_LEN],src_rid[RID_LEN];
    unsigned char key[KEY_LEN];
    unsigned char aid[AID_LEN];
    // 自己的rid和秘密值
    unsigned char my_rid[RID_LEN] = "bbbb";
    unsigned char secret[8] = "bbbbbbbb";
    // 从数据包中读取ts,Pn,Markn
    unsigned int ts = alp_opt_hdr->timestamp;
    // 上一跳的rid是通过mac地址利用哈希表获取的，下一跳的rid是通过数据包解析后计算获得的
    prev_hop_mac_ht_find(pre_mac, src_rid);
    print_hex("src_mac", pre_mac, MAC_LEN);

    // 6个步骤进行加密

    // 1.根据自己的路由标识通过哈希表找hop_key，并根据src_rid和my_rid进行md5计算得到epsilon_1和beta
    mackey_ht_find(my_rid, key);
    mac(src_rid,my_rid,(char *)&ts,4,key,epsilon_1);
    mac(src_rid,my_rid,secret,8,key,beta);

    // 2.从数据包中解析获得Pn，通过异或操作得到下一跳的rid
    xor_data(path_offset.path_pi,beta,dst_rid,RID_LEN);

    // 3.根据下一跳的rid和新的ts进行md5计算得到epsilon_2
    struct timespec real_ts;
    clock_gettime(CLOCK_REALTIME, &real_ts);
    ts = (unsigned int)real_ts.tv_nsec;
    mac(my_rid,dst_rid,(char *)&ts,4,key,epsilon_2);
    alp_opt_hdr->timestamp = ts;

    // 4.通过异或操作得到新的Markn,并将Markn重新填充到数据包中
    xor_data(path_offset.path_mark, beta, path_offset.path_mark, 16);
    xor_data(path_offset.path_mark, epsilon_1, path_offset.path_mark, 16);
    xor_data(path_offset.path_mark, epsilon_2, path_offset.path_mark, 16);

    // 5.通过epsilon_1和ipv6地址后64位的IID进行异或操作得到AID
    src = (unsigned char *)(ipv6_hdr->src_addr);
    xor_data(epsilon_1,src + 8,aid,8);
    printf("aid = %c%c%c%c%c%c%c%c\n", aid[0], aid[1], aid[2], aid[3], aid[4], aid[5], aid[6], aid[7]);

    // 6.通过AID和epsilon_2进行异或操作得到新的IID，并将其填充到数据包中
    xor_data(aid,epsilon_2,src + 8,8);

    // 通过下一跳的rid找到下一跳的mac地址
    next_hop_mac_ht_find(dst_rid, (unsigned char*)next_hop);

    return 0;
}

// Helper function to print binary data in hex format
void print_hex(const char *label, const unsigned char *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

