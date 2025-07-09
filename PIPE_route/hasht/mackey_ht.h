#ifndef __MACKEY_HT_H__
#define __MACKEY_HT_H__

#define RID_LEN 4
#define KEY_LEN 16
#define MAX_ENTRIES 1024
#define MAC_LEN 6

#endif

void init_hash_tables();
struct rte_hash *create_hash_table(const char *name, int key_len);
int mackey_ht_insert(unsigned char *rid, unsigned char *key);
int next_hop_mac_ht_insert(unsigned char *rid, unsigned char *mac);
int prev_hop_mac_ht_insert(unsigned char *mac, unsigned char *rid);
int mackey_ht_find(unsigned char *rid, unsigned char *key);
int next_hop_mac_ht_find(unsigned char *rid, unsigned char *mac);
int prev_hop_mac_ht_find(unsigned char *mac, unsigned char *rid);
void mackey_ht_free();
void next_hop_mac_ht_free();
void prev_hop_mac_ht_free();
