#include <linux/string.h>

#include "dev_info.h"

static struct {
    char aid[8];
    char rid[4];
    char secret[8];
} dev_info;

// 获取设备自身 aid(8B)
const char *get_aid(void) {
    return dev_info.aid;
}

// 获取设备自身 rid(4B)
const char *get_rid(void){
    return dev_info.rid;
}

// 获取设备自身 secret(8B)  
const char *get_secret(void) {
    return dev_info.secret;
}

// 设置设备自身 aid(8B)
void set_aid(const char *aid) {
    memcpy(dev_info.aid, aid, 8);
}

// 设置设备自身 rid(4B)
void set_rid(const char *rid) {
    memcpy(dev_info.rid, rid, 4);
}

// 设置设备自身 secret(8B)
void set_secret(const char *secret) {
    memcpy(dev_info.secret, secret, 8);
}