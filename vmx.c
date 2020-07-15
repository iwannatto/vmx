#include <asm/io.h>
#include <linux/module.h> /* MODULE_LICENSE, MODULE_DESCRIPTION, module_init, module_exit */
#include <linux/printk.h> /* pr_info */
#include <linux/slab.h>   /* kmalloc */
#include <linux/types.h>  /* uint32_t */

#include <linux/vmalloc.h>

#define UINT64_MAX 18446744073709551615UL

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("vmx");

// read model specific register
static inline uint64_t rdmsr_(uint32_t index) {
    uint32_t eax, edx;
    asm volatile("rdmsr" : "=a"(eax), "=d"(edx) : "c"(index));
    return ((uint64_t)edx << 32) | eax;
}

static inline void wrmsr_(uint32_t index, uint64_t value) {
    uint32_t eax, edx;
    eax = value & 0xffffffff;
    edx = value >> 32;
    asm volatile("wrmsr" : : "c"(index), "a"(eax), "d"(edx));
}

static inline uint32_t vmread(uint32_t index) {
    uint32_t value;
    asm volatile("vmread %%rax, %%rdx" : "=d"(value) : "a"(index) : "cc");
    return value;
}

static inline void vmwrite(uint32_t index, uint64_t value) {
    asm volatile("vmwrite %%rdx, %%rax"
                 :
                 : "a"(index), "d"(value)
                 : "cc", "memory");
}

static inline uint64_t rdtsc_(void) {
    uint32_t eax, edx;
    asm volatile("rdtsc" : "=a"(eax), "=d"(edx));
    return (uint64_t)edx << 32 | (uint64_t)eax;
}

static inline uint64_t vmcall(uint64_t arg) {
    uint64_t ret;
    asm volatile("vmcall"
                 : "=a"(ret)
                 : "c"(arg)
                 : "memory", "rdx", "r8", "r9", "r10", "r11");
    return ret;
}

static int env[28];
static int index;
static uint64_t tsc_exit[10], tsc_entry[10];

void print_results(void) {
    uint64_t exit_min = UINT64_MAX, entry_min = UINT64_MAX, exit_max = 0,
             entry_max = 0;
    uint64_t exit_avg = 0, entry_avg = 0;

    int i;
    for (i = 0; i < 10; i++) {
        pr_info("VM exit[%d]: %5lld, VM entry[%d]: %5lld\r\n", i, tsc_exit[i],
                i, tsc_entry[i]);
        if (tsc_exit[i] < exit_min) exit_min = tsc_exit[i];
        if (tsc_exit[i] > exit_max) exit_max = tsc_exit[i];
        exit_avg += tsc_exit[i];
        if (tsc_entry[i] < entry_min) entry_min = tsc_entry[i];
        if (tsc_entry[i] > entry_max) entry_max = tsc_entry[i];
        entry_avg += tsc_entry[i];
    }
    pr_info("VM exit : min = %5lld, max = %5lld, avg = %5lld\r\n", exit_min,
            exit_max, exit_avg / 10);
    pr_info("VM entry: min = %5lld, max = %5lld, avg = %5lld\r\n", entry_min,
            entry_max, entry_avg / 10);
}

void print_exitreason(uint64_t reason) {
    uint64_t q = vmread(0x6400);
    uint64_t rip = vmread(0x681E);
    uint64_t rsp = vmread(0x681C);
    pr_info("Unexpected VM exit: reason=%llx, qualification=%llx\r\n", reason,
            q);
    pr_info("rip: %08llx, rsp: %08llx\r\n", rip, rsp);
    int i;
    for (i = 0; i < 16; i++, rip++)
        pr_info("%02x ", *(uint8_t *)rip);
    pr_info("\r\n");
    for (i = 0; i < 16; i++, rsp += 8)
        pr_info("%016llx: %016llx\r\n", rsp, *(uint64_t *)rsp);
    pr_info("\r\n");
}

uint64_t host_entry(uint64_t arg) {
    tsc_exit[index] = rdtsc_() - arg;
    uint64_t reason = vmread(0x4402);
    if (reason == 18) {
        if (arg > 0) {
            uint64_t rip = vmread(0x681E); // Guest RIP
            uint64_t len = vmread(0x440C); // VM-exit instruction length
            vmwrite(0x681E, rip + len);
            return rdtsc_();
        }
        print_results();
    } else
        print_exitreason(reason);

    __builtin_longjmp(env, 1);
}

void __host_entry(void);
void _host_entry(void) {
    asm volatile("__host_entry:\n\t"
                 "call host_entry\n\t"
                 "vmresume\n\t"
                 "loop: jmp loop\n\t");
}

void guest_entry(void) {
    // warm up
    int i;
    for (i = 0; i < 10; i++)
        vmcall(1);
    // benchmark
    for (index = 0; index < 10; index++) {
        uint64_t tsc;
        tsc = vmcall(rdtsc_());
        tsc = rdtsc_() - tsc;
        tsc_entry[index] = tsc;
    }
    vmcall(0);
    while (1)
        ;
}

struct registers {
    uint16_t cs, ds, es, fs, gs, ss, tr, ldt;
    uint32_t rflags;
    uint64_t cr0, cr3, cr4;
    uint64_t ia32_efer, ia32_feature_control;
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) gdt, idt;
    // attribute "packed" requires -mno-ms-bitfields
};

void save_registers(struct registers *regs) {
    asm volatile("mov %%cr0, %0" : "=r"(regs->cr0));
    asm volatile("mov %%cr3, %0" : "=r"(regs->cr3));
    asm volatile("mov %%cr4, %0" : "=r"(regs->cr4));
    regs->ia32_efer = rdmsr_(0xC0000080);
    asm volatile("pushf; pop %%rax" : "=a"(regs->rflags));
    asm volatile("mov %%cs, %0" : "=m"(regs->cs));
}

void print_registers(struct registers *regs) {
    pr_info("CR0: %016llx, CR3: %016llx, CR4: %016llx\n", regs->cr0, regs->cr3,
            regs->cr4);
    pr_info("RFLAGS: %016x\n", regs->rflags);
    pr_info("CS: %04x\n", regs->cs);
    pr_info("IA32_EFER: %016llx\n", regs->ia32_efer);
    pr_info("IA32_FEATURE_CONTROL: %016llx\n", rdmsr_(0x3a));
}

// char vmxon_region[4096] __attribute__((aligned(4096)));
// char vmcs[4096] __attribute__((aligned(4096)));
// char host_stack[4096] __attribute__((aligned(4096)));
// char guest_stack[4096] __attribute__((aligned(4096)));
// char tss[4096] __attribute__((aligned(4096)));

char *get_physically_4096_aligned_virtual_address(void) {
    void *vaddr = kmalloc(4096 * 2, GFP_KERNEL);
    phys_addr_t paddr = virt_to_phys(vaddr);
    if ((paddr % 4096) == 0) {
        return vaddr;
    } else {
        phys_addr_t diff = 4096 - (paddr % 4096);
        return vaddr + diff;
    }
}

static int __init vmx_init(void) {
    pr_info("vmx: init");

    char *vmxon_region = get_physically_4096_aligned_virtual_address();
    char *vmcs = get_physically_4096_aligned_virtual_address();
    char *host_stack = get_physically_4096_aligned_virtual_address();
    char *guest_stack = get_physically_4096_aligned_virtual_address();
    char *tss = get_physically_4096_aligned_virtual_address();

    uint32_t error;
    struct registers regs;

    pr_info("Starting VMXbench ...\r\n");

    // check the presence of VMX support
    uint32_t ecx;
    asm volatile("cpuid" : "=c"(ecx) : "a"(1) : "ebx", "edx");
    if ((ecx & 0x20) == 0) // CPUID.1:ECX.VMX[bit 5] != 1
        goto error_vmx_not_supported;
    pr_info("VMX is supported\r\n");

    // enable VMX
    pr_info("Enable VMX\r\n");
    asm volatile("mov %%cr4, %0" : "=r"(regs.cr4));
    regs.cr4 |= 0x2000; // CR4.VME[bit 13] = 1
    asm volatile("mov %0, %%cr4" ::"r"(regs.cr4));

    // enable VMX operation
    pr_info("Enable VMX operation\r\n");
    regs.ia32_feature_control = rdmsr_(0x3a);
    if ((regs.ia32_feature_control & 0x1) == 0) {
        regs.ia32_feature_control |= 0x5; // firmware should set this
        wrmsr_(0x3a, regs.ia32_feature_control);
    } else if ((regs.ia32_feature_control & 0x4) == 0)
        goto error_vmx_disabled;

    // apply fixed bits to CR0 & CR4
    uint64_t apply_fixed_bits(uint64_t reg, uint32_t fixed0, uint32_t fixed1) {
        reg |= rdmsr_(fixed0);
        reg &= rdmsr_(fixed1);
        return reg;
    }
    asm volatile("mov %%cr0, %0" : "=r"(regs.cr0));
    regs.cr0 = apply_fixed_bits(regs.cr0, 0x486, 0x487);
    asm volatile("mov %0, %%cr0" ::"r"(regs.cr0));
    asm volatile("mov %%cr4, %0" : "=r"(regs.cr4));
    regs.cr4 = apply_fixed_bits(regs.cr4, 0x488, 0x489);
    asm volatile("mov %0, %%cr4" ::"r"(regs.cr4));

    phys_addr_t pptr;
    uint32_t *vptr;

    // enter VMX operation
    pr_info("Enter VMX operation\r\n");
    uint8_t vmxon_error;
    uint32_t revision_id = rdmsr_(0x480);
    pptr = virt_to_phys(vmxon_region);
    vptr = (uint32_t *)vmxon_region;

    vptr[0] = revision_id;
    pr_info("vptr: %p", vptr);
    pr_info("valid: %d", __virt_addr_valid((unsigned long)vptr));
    pr_info("pptr: %llx", pptr);
    asm volatile("vmxon %1" : "=@ccbe"(vmxon_error) : "m"(pptr));
    uint8_t is_cf_set;
    uint8_t is_zf_set;
    asm volatile("setc %0" : "=r"(is_cf_set));
    asm volatile("sete %0" : "=r"(is_zf_set));
    if (is_cf_set) {
        pr_info("CF is set");
    } else {
        pr_info("CF is not set");
    }
    if (is_zf_set) {
        pr_info("ZF is set");
    } else {
        pr_info("ZF is not set");
    }
    if (vmxon_error) goto error_vmxon;

    // // initialize VMCS
    pr_info("Initialize VMCS\r\n");
    pptr = virt_to_phys(vmcs);
    vptr = (uint32_t *)vmcs;
    int i = 0;
    for (i = 0; i < 4096 / sizeof(uint32_t); ++i) {
        vptr[i] = 0;
    }
    vptr[0] = revision_id;
    pr_info("vptr: %p", vptr);
    pr_info("pptr: %llx", pptr);
    asm volatile("vmclear %1" : "=@ccbe"(error) : "m"(pptr));
    asm volatile("setc %0" : "=r"(is_cf_set));
    asm volatile("sete %0" : "=r"(is_zf_set));
    if (is_cf_set) {
        pr_info("CF is set");
    } else {
        pr_info("CF is not set");
    }
    if (is_zf_set) {
        pr_info("ZF is set");
    } else {
        pr_info("ZF is not set");
    }
    if (error) goto error_vmclear;
    asm volatile("vmptrld %1" : "=@ccbe"(error) : "m"(pptr));
    if (error) goto error_vmptrld;

    // initialize control fields
    uint32_t apply_allowed_settings(uint32_t value, uint64_t msr_index) {
        uint64_t msr_value = rdmsr_(msr_index);
        value |= (msr_value & 0xffffffff);
        value &= (msr_value >> 32);
        return value;
    }
    uint32_t pinbased_ctls = apply_allowed_settings(0x1e, 0x481);
    vmwrite(0x4000, pinbased_ctls); // Pin-based VM-execution controls
    uint32_t procbased_ctls = apply_allowed_settings(0x0401e9f2, 0x482);
    vmwrite(0x4002,
            procbased_ctls); // Primary processor-based VM-execution controls
    vmwrite(0x4004, 0x0);    // Exception bitmap
    uint32_t exit_ctls = apply_allowed_settings(0x336fff, 0x483);
    vmwrite(0x400c, exit_ctls); // VM-exit controls
    uint32_t entry_ctls = apply_allowed_settings(0x93ff, 0x484);
    vmwrite(0x4012, entry_ctls); // VM-entry controls

    void vmwrite_gh(uint32_t guest_id, uint32_t host_id, uint64_t value) {
        vmwrite(guest_id, value);
        vmwrite(host_id, value);
    }

    // // 16-Bit Guest and Host State Fields
    asm volatile("mov %%es, %0" : "=m"(regs.es));
    asm volatile("mov %%cs, %0" : "=m"(regs.cs));
    asm volatile("mov %%ss, %0" : "=m"(regs.ss));
    asm volatile("mov %%ds, %0" : "=m"(regs.ds));
    asm volatile("mov %%fs, %0" : "=m"(regs.fs));
    asm volatile("mov %%gs, %0" : "=m"(regs.gs));
    asm volatile("sldt %0" : "=m"(regs.ldt));
    asm volatile("str %0" : "=m"(regs.tr));
    vmwrite_gh(0x0800, 0x0c00, regs.es); // ES selector
    vmwrite_gh(0x0802, 0x0c02, regs.cs); // CS selector
    vmwrite_gh(0x0804, 0x0c04, regs.ss); // SS selector
    vmwrite_gh(0x0806, 0x0c06, regs.ds); // DS selector
    vmwrite_gh(0x0808, 0x0c08, regs.fs); // FS selector
    vmwrite_gh(0x080a, 0x0c0a, regs.gs); // GS selector
    vmwrite(0x080c, regs.ldt);           // Guest LDTR selector
    vmwrite_gh(0x080e, 0x0c0c, regs.tr); // TR selector
    vmwrite(0x0c0c, 0x08);               // dummy TR selector for real hardware

    // // 64-Bit Guest and Host State Fields
    vmwrite(0x2800, ~0ULL); // VMCS link pointer
    // vmwrite(0x2802, 0);  // Guest IA32_DEBUGCTL
    regs.ia32_efer = rdmsr_(0xC0000080);
    vmwrite_gh(0x2806, 0x2c02, regs.ia32_efer); // IA32_EFER

    // 32-Bit Guest and Host State Fields
    asm volatile("sgdt %0" : "=m"(regs.gdt));
    asm volatile("sidt %0" : "=m"(regs.idt));
    uint32_t get_seg_limit(uint32_t selector) {
        uint32_t limit;
        asm volatile("lsl %1, %0" : "=r"(limit) : "r"(selector));
        return limit;
    }
    vmwrite(0x4800, get_seg_limit(regs.es));  // Guest ES limit
    vmwrite(0x4802, get_seg_limit(regs.cs));  // Guest CS limit
    vmwrite(0x4804, get_seg_limit(regs.ss));  // Guest SS limit
    vmwrite(0x4806, get_seg_limit(regs.ds));  // Guest DS limit
    vmwrite(0x4808, get_seg_limit(regs.fs));  // Guest FS limit
    vmwrite(0x480a, get_seg_limit(regs.gs));  // Guest GS limit
    vmwrite(0x480c, get_seg_limit(regs.ldt)); // Guest LDTR limit
    uint32_t tr_limit = get_seg_limit(regs.tr);
    if (tr_limit == 0) tr_limit = 0x0000ffff;
    vmwrite(0x480e, tr_limit);       // Guest TR limit
    vmwrite(0x4810, regs.gdt.limit); // Guest GDTR limit
    vmwrite(0x4812, regs.idt.limit); // Guest IDTR limit
    uint32_t get_seg_access_rights(uint32_t selector) {
        uint32_t access_rights;
        asm volatile("lar %1, %0" : "=r"(access_rights) : "r"(selector));
        return access_rights >> 8;
    }
    vmwrite(0x4814, get_seg_access_rights(regs.es)); // Guest ES access rights
    vmwrite(0x4816, get_seg_access_rights(regs.cs)); // Guest CS access rights
    vmwrite(0x4818, get_seg_access_rights(regs.ss)); // Guest SS access rights
    vmwrite(0x481a,
            get_seg_access_rights(regs.ds)); // Guest DS access rights
    vmwrite(0x481c, get_seg_access_rights(regs.fs));
    // Guest FS access rights
    vmwrite(0x481e,
            get_seg_access_rights(regs.gs)); // Guest GS access rights
    uint32_t ldtr_access_rights = get_seg_access_rights(regs.ldt);
    if (ldtr_access_rights == 0) ldtr_access_rights = 0x18082;
    vmwrite(0x4820, ldtr_access_rights); // Guest LDTR access rights
    uint32_t tr_access_rights = get_seg_access_rights(regs.tr);
    if (tr_access_rights == 0) tr_access_rights = 0x0808b;
    vmwrite(0x4822, tr_access_rights); // Guest TR access rights

    // // Natual-Width Control Fields
    asm volatile("mov %%cr3, %0" : "=r"(regs.cr3));
    vmwrite_gh(0x6800, 0x6c00, regs.cr0);
    vmwrite_gh(0x6802, 0x6c02, regs.cr3);
    vmwrite_gh(0x6804, 0x6c04, regs.cr4);

    uint64_t get_seg_base(uint32_t selector) { return 0; }
    vmwrite(0x6806, get_seg_base(regs.es));       // es base
    vmwrite(0x6808, get_seg_base(regs.cs));       // cs base
    vmwrite(0x680a, get_seg_base(regs.ss));       // ss base
    vmwrite(0x680c, get_seg_base(regs.ds));       // ds base
    vmwrite(0x680e, get_seg_base(regs.fs));       // fs base
    vmwrite(0x6810, get_seg_base(regs.gs));       // gs base
    vmwrite(0x6812, get_seg_base(regs.ldt));      // LDTR base
    vmwrite(0x6814, (uint64_t)virt_to_phys(tss)); // TR base

    vmwrite_gh(0x6816, 0x6C0C, regs.gdt.base); // GDTR base
    vmwrite_gh(0x6818, 0x6C0E, regs.idt.base); // IDT base

    vmwrite(0x6C14, (uint64_t)virt_to_phys(
                        &host_stack[sizeof(host_stack)])); // HOST_RSP
    vmwrite(0x6C16, (uint64_t)virt_to_phys(__host_entry)); // Host RIP
    vmwrite(0x681C, (uint64_t)virt_to_phys(
                        &guest_stack[sizeof(guest_stack)])); // GUEST_RSP
    vmwrite(0x681E, (uint64_t)virt_to_phys(guest_entry));    // Guest RIP
    asm volatile("pushf; pop %%rax" : "=a"(regs.rflags));
    regs.rflags &= ~0x200ULL; // clear interrupt enable flag
    vmwrite(0x6820, regs.rflags);

    if (!__builtin_setjmp(env)) {
        pr_info("Launch a VM\r\n");
        asm volatile("cli");
        asm volatile("vmlaunch" ::: "memory");
        goto error_vmx;
    } else {
        goto disable_vmx;
    }

error_vmx:
    pr_info("VMLAUNCH failed: ");
    pr_info("Error Number is %d\r\n", vmread(0x4400));
    goto disable_vmx;

error_vmptrld:
    pr_info("VMPTRLD failed.\r\n");
    goto disable_vmx;

error_vmclear:
    pr_info("VMCLEAR failed.\r\n");
    goto disable_vmx;

error_vmxon:
    pr_info("VMXON failed.\r\n");
    goto disable_vmx;

disable_vmx:
    asm volatile("vmxoff");
    asm volatile("mov %%cr4, %0" : "=r"(regs.cr4));
    regs.cr4 &= ~0x2000; // CR4.VME[bit 13] = 0
    asm volatile("mov %0, %%cr4" ::"r"(regs.cr4));
    goto exit;

error_vmx_disabled:
    pr_info("VMX is disabled by the firmware\r\n");
    goto exit;

error_vmx_not_supported:
    pr_info("VMX is not supported in this processor\r\n");
    goto exit;

exit:
    pr_info("Press any key to go back to the UEFI menu\r\n");

    pr_info("vmx: init end");

    return 0;
}

static void __exit vmx_exit(void) { pr_info("vmx: exit\n"); }

module_init(vmx_init);
module_exit(vmx_exit);
