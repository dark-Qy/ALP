#include <crypto/hash.h>
#include <linux/string.h>
#include "func.h"

// 将两个数据异或
void xor_data(const char* in1, const char* in2, char* out, int len) {
    int i;
    for(i = 0; i < len; i++) {
        out[i] = in1[i] ^ in2[i];
    }
}

// 计算MAC值，其中 len 标志了前一个字段使用的是 ts(4B)  还是 secret(8B)
void mac(const char* rid1, const char* rid2, const char* ts_or_secret, const size_t len, const char* key, char* mac_out) {
    struct crypto_shash *tfm;
    struct shash_desc *shash;
    unsigned char buffer[32];

    // 初始化加密上下文
    tfm = crypto_alloc_shash("md5", 0, 0);
    shash = kzalloc(sizeof(*shash) + crypto_shash_descsize(tfm), GFP_KERNEL);
    shash->tfm = tfm;

    // 将所有参数拼接在一起进行加密
    memcpy(buffer, rid1, 4);
    memcpy(buffer + 4, rid2, 4);
    memcpy(buffer + 8, ts_or_secret, len);
    memcpy(buffer + 8 + len, key, 16);
    crypto_shash_digest(shash, buffer, 24 + len, mac_out);

    crypto_free_shash(tfm);
    kfree(shash);
}