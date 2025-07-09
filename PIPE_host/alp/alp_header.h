#include <linux/skbuff.h>

#include "alp.h"

OPT_ALP_HEADER *skb_alp_header(struct sk_buff *skb);
int add_extended_header(struct sk_buff *skb, char *path, unsigned int hop, const char *rid);
int remove_extended_header(struct sk_buff *skb);