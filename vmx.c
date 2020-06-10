#include <linux/module.h> /* MODULE_LICENSE, MODULE_DESCRIPTION, module_init, module_exit */
#include <linux/printk.h> /* pr_info */
#include <linux/types.h>  /* uint32_t */

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("vmx");

static int __init vmx_init(void) {
    pr_info("vmx: init\n");

    uint32_t ecx;
    asm volatile ("cpuid" : "=c" (ecx) : "a" (0x01) : "ebx", "edx");
    if ((ecx & 0x20) == 0) {
        pr_info("vmx: vmx is not supported\n");
        return 0;
    }
    pr_info("vmx: vmx is supported\n");

    return 0;
}

static void __exit vmx_exit(void) { pr_info("vmx: exit\n"); }

module_init(vmx_init);
module_exit(vmx_exit);
