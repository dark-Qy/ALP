#include <stdint.h>
#include <rte_mbuf.h>

#ifndef IPPROTO_LABEL
#define IPPROTO_LABEL 146
#define EEA_LEN 8
#define IPC_LEN 8
#define MAC_LEN 6
#define MARK_LEN 16
#define RID_LEN 4
#define P_LEN RID_LEN
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

// 自定义扩展报头结构
#pragma pack(1)
typedef struct __label_header {
    uint8_t opt_type;
    uint8_t opt_datalen;
    uint8_t eea_type;
    uint8_t ipc_type;
    uint8_t path_length; //Mark+Pi的总长度
    uint8_t hop_count; // 当前已经计算过的跳数
    uint32_t timestamp;
    uint32_t sequence;
    uint8_t IPC[IPC_LEN];
    // 本 demo 中使用 aes 加密、sha256 作哈希，故 eea 长为 64位，IPC 长为 256 位
} LABEL_HEADER;
#pragma pack()

#endif

int add_alh_header(struct rte_mbuf *mbuf);
int remove_alh_header(struct rte_mbuf *mbuf);
