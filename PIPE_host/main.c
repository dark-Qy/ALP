#include <linux/module.h>
#include <linux/kernel.h>

#include "debug_util.h"
#include "local_out.h"
#include "local_in.h"
#include "hash_map.h"

static int __init alp_init(void) {
    int ret = 0;
    ret |= local_out_init();
    hashtable_init();
    local_in_init();

    if(ret == 0)
        DEBUG_PRINT("Address Label with Path Verification module loaded.\n");
    else
        DEBUG_PRINT("Address Label with Path Verification module load failed.\n");
    
    return 0;
}

static void __exit alp_exit(void) {
    local_out_exit();
    local_in_exit();
    hashtable_exit();

    pr_info("Address Label with Path Verification module unloaded.\n");
}

module_init(alp_init);
module_exit(alp_exit);
MODULE_LICENSE("GPL");