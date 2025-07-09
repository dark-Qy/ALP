#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/crypto.h>

#include "debug_util.h"
#include "alp.h"

#ifndef __HASH_TABLE__
#define __HASH_TABLE__

#define HASHTABLE_SIZE 10

// 以 ip6 映射到路径信息
typedef struct __path_info {
    char ip6[16];
    char *path;
    unsigned int hop;   // 总跳数 hop，暗示了路径信息的长度
    char rid[RID_SIZE]; // 目的终端 id，作为路径信息的一部分

    struct hlist_node hnode;
} PATH_INFO;

#endif

void hashtable_init(void);
void hashtable_exit(void);

int insert_path(IN const char *ip6, IN const char *path, IN unsigned int hop, IN unsigned char *rid); // 插入路径信息
int find_path_by_ip6(IN const char *ip6, OUT char *path, OUT unsigned int *hop, OUT unsigned char *rid); // 根据 IPv6 地址找路径

char *get_session_key_by_ip6(const char *dst);   // 根据目的 IP 找会话密钥
char *get_session_key_by_aid(const char *dst_aid);   // 根据目的 aid 找会话密钥
char *get_ip6_by_aid(const char *aid);   // 根据 aid 找 IPv6 地址
char *get_hop_key_by_rid(const char *rid);   // 根据路由标识找 hop 密钥
char *get_next_mac_by_rid(const char *rid);   // 根据路由标识找下一跳 MAC 地址
char *get_prev_rid_by_mac(const char *mac);   // 根据 MAC 地址找上一跳路由标识