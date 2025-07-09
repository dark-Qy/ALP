void xor_data(const char* in1, const char* in2, char* out, int len);    // 将两个数据异或

// 计算MAC值，其中 len 标志了前一个字段使用的是 ts(4B)  还是 secret(8B)
void mac(const char* rid1, const char* rid2, const char* ts_or_secret, const size_t len, const char* key, char* mac_out);