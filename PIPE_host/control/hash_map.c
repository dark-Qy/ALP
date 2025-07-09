#include <linux/jhash.h>

#include "hash_map.h"
#include "func.h"

DEFINE_HASHTABLE(path_info_hashtable, HASHTABLE_SIZE);

static struct {
    char session[16];
    char hop_key[16];
} fake_table;

void hashtable_init(void) {
    char beta0[16], beta1[16];
    char P0[4], P1[4];
    int hop = 2;
    char path[PATH_LEN(hop)];
    memcpy(fake_table.session, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16);
    memcpy(fake_table.hop_key, "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f", 16);
    
    // todo: 插入假的路径信息(T1 - R - T2)
    mac("aaaa", "cccc", "aaaaaaaa", 8, fake_table.session, beta0);
    mac("aaaa", "bbbb", "bbbbbbbb", 8, fake_table.hop_key, beta1);
    xor_data(beta0, "bbbb", P0, 4);
    xor_data(beta1, "cccc", P1, 4);
    xor_data(beta0, beta1, path, 16);
    memcpy(path + 16, P0, 4);
    memcpy(path + 20, P1, 4);
    // 将 ip6 为 2025::2 的路径信息插入到哈希表中
    insert_path("\x20\x25\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02", path, hop, "cccc");
}

void hashtable_exit(void) {
    // todo: 清理哈希表释放资源
}

// 插入路径信息
int insert_path(IN const char *ip6, IN const char *path, IN unsigned int hop, IN unsigned char *rid) {
    PATH_INFO *pinfo = kmalloc(sizeof(PATH_INFO), GFP_KERNEL);
    memcpy(pinfo->ip6, ip6, 16);
    pinfo->path = kmalloc(PATH_LEN(hop), GFP_KERNEL);
    memcpy(pinfo->path, path, PATH_LEN(hop));
    memcpy(pinfo->rid, rid, RID_SIZE);
    pinfo->hop = hop;

    hash_add(path_info_hashtable, &pinfo->hnode, jhash(pinfo->ip6, 16, 0));

    return 0;
}

// 根据 IPv6 地址找路径
int find_path_by_ip6(IN const char *ip6, OUT char *path, OUT unsigned int *hop, OUT unsigned char *rid) {
    PATH_INFO *pinfo = NULL;
    hash_for_each_possible(path_info_hashtable, pinfo, hnode, jhash(ip6, 16, 0)) {
        memcpy(path, pinfo->path, PATH_LEN(pinfo->hop));
        memcpy(rid, pinfo->rid, RID_SIZE);
        *hop = pinfo->hop;
        return 0;
    }
    return -1;
}

// 根据目的 IP 找会话密钥
char *get_session_key_by_ip6(const char *dst) {
    return fake_table.session;
}

// 根据目的 aid 找会话密钥
char *get_session_key_by_aid(const char *dst_aid) {
    return fake_table.session;
}

// 根据 aid 找 IPv6 地址
char *get_ip6_by_aid(const char *aid) {
    // todo: 构建真实的查询表
    if(memcmp(aid, "aaaaaaaa", 8) == 0) {
        return "\x20\x24\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02";
    }
    else if(memcmp(aid, "cccccccc", 8) == 0) {
        return "\x20\x25\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02";
    }
    
    return NULL;
}

// 根据路由标识找 hop 密钥
char *get_hop_key_by_rid(const char *rid) {
    return fake_table.hop_key;
}

// 根据路由标识找下一跳 MAC 地址
char *get_next_mac_by_rid(const char *rid) {
    // todo: 设置下一跳 MAC 地址
    return "\x00\x0c\x29\x7b\xc5\x00";
}

// 根据 MAC 地址找上一跳路由标识
char *get_prev_rid_by_mac(const char *mac) {
    // todo: 设置上一跳路由标识
    return "bbbb";
}