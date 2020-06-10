#include <linux/module.h> /* MODULE_LICENSE, MODULE_DESCRIPTION, module_init, module_exit */
#include <linux/printk.h> /* pr_info */
#include <stdint.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("vtx");

static int __init vtx_init(void) {
    pr_info("vtx: init\n");

    return 0;
}

static void __exit vtx_exit(void) { pr_info("vtx: exit\n"); }

module_init(vtx_init);
module_exit(vtx_exit);
