const char *get_aid(void);  // 获取设备自身 aid(8B)
const char *get_rid(void);  // 获取设备自身 rid(4B)
const char *get_secret(void);  // 获取设备自身 secret(8B)

void set_aid(const char *aid);
void set_rid(const char *rid);
void set_secret(const char *secret);