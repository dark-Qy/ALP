#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>

#include "mackey_ht.h"
// 下面为重写的逻辑

struct rte_hash *mackey_ht = NULL;      // 路由标识到密钥的映射
struct rte_hash *next_hop_mac_ht = NULL; // 路由标识到下一跳 MAC 地址的映射
struct rte_hash *prev_hop_mac_ht = NULL; // MAC 地址到上一跳路由标识的映射

// 创建哈希表的函数
struct rte_hash *create_hash_table(const char *name, int key_len) {
    struct rte_hash_parameters params = {0};
    params.name = name;
    params.entries = MAX_ENTRIES;
    params.key_len = key_len;
    params.hash_func = rte_jhash;
    params.hash_func_init_val = 0;
    params.socket_id = rte_socket_id();

    struct rte_hash *ht = rte_hash_create(&params);

    if (ht == NULL) {
        fprintf(stderr, "Failed to create hash table: %s\n", name);
    } else {
        printf("Hash table '%s' created successfully.\n", name);
    }

    return ht;
}



// 插入到路由标识到密钥的哈希表
int mackey_ht_insert(unsigned char *rid, unsigned char *key) {
    unsigned char *ht_rid = rte_malloc(NULL, RID_LEN, 0);
    unsigned char *ht_key = rte_malloc(NULL, KEY_LEN, 0);
    memcpy(ht_rid, rid, RID_LEN);
    memcpy(ht_key, key, KEY_LEN);
    // dpdk对哈希表的add操作可能会修改已有的映射，所以没有必要额外实现update
    return rte_hash_add_key_data(mackey_ht, ht_rid, ht_key);
}

// 测试插入路由标识到密钥
static void test_fake_hop_key_insert() {
    unsigned char rid1[RID_LEN] = {0x61, 0x61, 0x61, 0x61};
    unsigned char rid2[RID_LEN] = {0x62, 0x62, 0x62, 0x62};
    unsigned char fake_key[KEY_LEN] = "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";

    mackey_ht_insert(rid1, fake_key);
    mackey_ht_insert(rid2, fake_key);
}

// 插入到下一跳路由标识到下一跳 MAC 地址的哈希表
int next_hop_mac_ht_insert(unsigned char *rid, unsigned char *mac) {
    unsigned char *ht_rid = rte_malloc(NULL, RID_LEN, 0);
    unsigned char *ht_mac = rte_malloc(NULL, MAC_LEN, 0);
    memcpy(ht_rid, rid, RID_LEN);
    memcpy(ht_mac, mac, MAC_LEN);
    // dpdk对哈希表的add操作可能会修改已有的映射，所以没有必要额外实现update
    return rte_hash_add_key_data(next_hop_mac_ht, ht_rid, ht_mac);
}

// 测试插入下一跳路由标识到下一跳 MAC 地址
static void test_fake_next_mac_insert() {
    unsigned char rid1[RID_LEN] = {0x61, 0x61, 0x61, 0x61};
    unsigned char rid2[RID_LEN] = {0x63, 0x63, 0x63, 0x63};
    unsigned char mac1[MAC_LEN] = {0x00, 0x0c, 0x29, 0x9e, 0x15, 0x24};
    unsigned char mac2[MAC_LEN] = {0x00, 0x0c, 0x29, 0xa6, 0x12, 0x28};

    next_hop_mac_ht_insert(rid1, mac1);
    next_hop_mac_ht_insert(rid2, mac2);
}

// 插入到 上一跳MAC 地址到上一跳路由标识的哈希表
int prev_hop_mac_ht_insert(unsigned char *mac, unsigned char *rid) {
    unsigned char *ht_rid = rte_malloc(NULL, RID_LEN, 0);
    unsigned char *ht_mac = rte_malloc(NULL, MAC_LEN, 0);
    memcpy(ht_rid, rid, RID_LEN);
    memcpy(ht_mac, mac, MAC_LEN);
    // dpdk对哈希表的add操作可能会修改已有的映射，所以没有必要额外实现update
    return rte_hash_add_key_data(prev_hop_mac_ht, ht_mac, ht_rid);
}

// 测试插入 上一跳MAC 地址到上一跳路由标识
static void test_fake_prev_rid_insert() {
    unsigned char rid1[RID_LEN] = {0x61, 0x61, 0x61, 0x61};
    unsigned char rid2[RID_LEN] = {0x63, 0x63, 0x63, 0x63};
    unsigned char mac1[MAC_LEN] = {0x00, 0x0c, 0x29, 0x9e, 0x15, 0x24};
    unsigned char mac2[MAC_LEN] = {0x00, 0x0c, 0x29, 0xa6, 0x12, 0x28};

    prev_hop_mac_ht_insert(mac1, rid1);
    prev_hop_mac_ht_insert(mac2, rid2);
}

// 初始化三个哈希表
void init_hash_tables() {
    mackey_ht = create_hash_table("hop_key_by_rid_ht", RID_LEN);
    if (mackey_ht == NULL) {
        rte_exit(EXIT_FAILURE, "Failed to create mackey_ht.\n");
    }

    next_hop_mac_ht = create_hash_table("next_mac_by_rid_ht", RID_LEN);
    if (next_hop_mac_ht == NULL) {
        rte_exit(EXIT_FAILURE, "Failed to create next_hop_mac_ht.\n");
    }

    prev_hop_mac_ht = create_hash_table("prev_rid_by_mac_ht", MAC_LEN);
    if (prev_hop_mac_ht == NULL) {
        rte_exit(EXIT_FAILURE, "Failed to create prev_hop_mac_ht.\n");
    }

    // 测试插入数据
    test_fake_hop_key_insert();
    test_fake_next_mac_insert();
    test_fake_prev_rid_insert();
}


// 根据路由标识查找密钥
int mackey_ht_find(unsigned char *rid, unsigned char *key) {
    unsigned char *ht_key = NULL;

    // 查找哈希表
    rte_hash_lookup_data(mackey_ht, rid, (void **)&ht_key);
    if (ht_key == NULL) {
        // 查找失败
        return -1;
    }
    // 复制找到的密钥
    memcpy(key, ht_key, KEY_LEN);
    return 0;
}

// 根据路由标识查找下一跳 MAC 地址
int next_hop_mac_ht_find(unsigned char *rid, unsigned char *mac) {
    unsigned char *ht_mac = NULL;

    // 查找哈希表
    rte_hash_lookup_data(next_hop_mac_ht, rid, (void **)&ht_mac);
    if (ht_mac == NULL) {
        // 查找失败
        return -1;
    }
    // 复制找到的 MAC 地址
    memcpy(mac, ht_mac, MAC_LEN);
    return 0;
}

// 根据 MAC 地址查找上一跳路由标识
int prev_hop_mac_ht_find(unsigned char *mac, unsigned char *rid) {
    unsigned char *ht_rid = NULL;

    // 查找哈希表
    rte_hash_lookup_data(prev_hop_mac_ht, mac, (void **)&ht_rid);
    if (ht_rid == NULL) {
        // 查找失败
        return -1;
    }
    // 复制找到的路由标识
    memcpy(rid, ht_rid, RID_LEN);
    return 0;
}

// 释放路由标识查找密钥哈希表
void mackey_ht_free() {
    unsigned char *ht_key = NULL, *ht_rid = NULL;
    uint32_t next = 0;
    rte_hash_iterate(mackey_ht, (const void**)&ht_rid, (void**)&ht_key, &next);
    while(next != MAX_ENTRIES) {
        rte_free(ht_key);
        rte_hash_iterate(mackey_ht, (const void**)&ht_rid, (void**)&ht_key, &next); 
    }
    rte_hash_free(mackey_ht);
}

// 释放路由标识查找下一跳 MAC 地址哈希表
void next_hop_mac_ht_free() {
    unsigned char *ht_mac = NULL, *ht_rid = NULL;
    uint32_t next = 0;
    rte_hash_iterate(next_hop_mac_ht, (const void**)&ht_rid, (void**)&ht_mac, &next);
    while(next != MAX_ENTRIES) {
        rte_free(ht_mac);
        rte_hash_iterate(next_hop_mac_ht, (const void**)&ht_rid, (void**)&ht_mac, &next); 
    }
    rte_hash_free(next_hop_mac_ht);
}

// 释放 MAC 地址查找上一跳路由标识哈希表
void prev_hop_mac_ht_free() {
    unsigned char *ht_rid = NULL, *ht_mac = NULL;
    uint32_t next = 0;
    rte_hash_iterate(prev_hop_mac_ht, (const void**)&ht_mac, (void**)&ht_rid, &next);
    while(next != MAX_ENTRIES) {
        rte_free(ht_rid);
        // rte_free(ht_mac);    // 不知道为什么需要把这个注释掉，不然会产生一个错误，不过不影响程序的正常运行
        rte_hash_iterate(prev_hop_mac_ht, (const void**)&ht_mac, (void**)&ht_rid, &next); 
    }
    rte_hash_free(prev_hop_mac_ht);
}

