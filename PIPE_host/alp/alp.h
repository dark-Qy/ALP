#include <linux/types.h>

#ifndef OPT_ALP
#define OPT_ALP 0X33
#define ETH_ADDRESS_LEN 6
#define IPV6_ADDRESS_LEN 16
#define IPV6_HEADER_LEN 40

#define MARK_LEN 16
#define RID_SIZE 4
#define P_LEN RID_SIZE     // Pi的长度，与 RID_SIZ 相同
#define PATH_LEN(hop) (MARK_LEN + P_LEN * hop)

enum EEA_TYPE {
    EEA_SM4 = 1,
    EEA_AES128,
    EEA_AES256,
    EEA_DES,
    EEA_3DES
};

enum IPC_TYPE {
    IPC_SHA256 = 1,
    IPC_SHA384,
    IPC_SHA512,
    IPC_MD5
};

// 自定义地址标签选项头结构体
typedef struct __alp_header {
    __u8 opt_type;
    __u8 opt_datalen;
    __u8 eea_type;  // eea_type 和 ipc_type 暂时不需要关注，随便赋值即可
    __u8 ipc_type;
    __u8 path_length;   // Mark+Pi 的总长度
    __u8 hop_count;     // 当前已经计算过的跳数
    __u32 timestamp;
    __u32 sequence;
    __u8 IPC[8];
    // 结构体后跟变长的路径信息（Mark+Pi)
} __attribute__((packed)) OPT_ALP_HEADER;
#endif