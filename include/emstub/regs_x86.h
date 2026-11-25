#ifndef EMSTUB_REGS_X86_H
#define EMSTUB_REGS_X86_H

#include "proto.h"

typedef enum em_regblock {
    EM_RB_X86_CORE = 0,
    EM_RB_X86_SEG  = 1,
    EM_RB_X86_CTRL = 2,
    EM_RB_X86_SYS  = 3,
    EM_RB_X86_FPU  = 4,
    EM_RB_X86_VMX  = 5,
    EM_RB_X86_GUEST = 6,
} em_regblock;

#define EM_RB_BIT(block_id)  (1u << (block_id))
#define EM_RB_STOPPED_SET    (EM_RB_BIT(EM_RB_X86_CORE) | EM_RB_BIT(EM_RB_X86_SEG) | \
                              EM_RB_BIT(EM_RB_X86_CTRL))

typedef struct em_rb_hdr {
    uint16_t id;
    uint16_t reserved;
    uint32_t size;
} em_rb_hdr;
EM_STATIC_ASSERT(sizeof(em_rb_hdr) == 8, "em_rb_hdr layout");

typedef struct em_x86_core {
    uint64_t rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip;
    uint64_t rflags;
} em_x86_core;
EM_STATIC_ASSERT(sizeof(em_x86_core) == 144, "em_x86_core layout");

#define EM_X86_GPR(core, reg_index)  (((uint64_t *)&(core))[reg_index])

typedef struct em_x86_seg {
    uint64_t base;
    uint32_t limit;
    uint16_t selector;
    uint16_t attr;
} em_x86_seg;
EM_STATIC_ASSERT(sizeof(em_x86_seg) == 16, "em_x86_seg layout");

#define EM_SEG_TYPE(attr)  ((attr) & 0xFu)
#define EM_SEG_S(attr)     (((attr) >> 4) & 1u)
#define EM_SEG_DPL(attr)   (((attr) >> 5) & 3u)
#define EM_SEG_P(attr)     (((attr) >> 7) & 1u)
#define EM_SEG_AVL(attr)   (((attr) >> 12) & 1u)
#define EM_SEG_L(attr)     (((attr) >> 13) & 1u)
#define EM_SEG_DB(attr)    (((attr) >> 14) & 1u)
#define EM_SEG_G(attr)     (((attr) >> 15) & 1u)

typedef struct em_x86_segs {
    em_x86_seg cs, ss, ds, es, fs, gs, ldtr, tr;
    em_x86_seg gdtr, idtr;
} em_x86_segs;
EM_STATIC_ASSERT(sizeof(em_x86_segs) == 160, "em_x86_segs layout");

typedef struct em_x86_ctrl {
    uint64_t cr0, cr2, cr3, cr4, cr8;
    uint64_t efer, xcr0;
    uint64_t dr0, dr1, dr2, dr3, dr6, dr7;
} em_x86_ctrl;
EM_STATIC_ASSERT(sizeof(em_x86_ctrl) == 104, "em_x86_ctrl layout");

typedef struct em_x86_sys {
    uint64_t sysenter_cs, sysenter_esp, sysenter_eip;
    uint64_t star, lstar, cstar, fmask, kernel_gs_base;
    uint64_t pat, apic_base, tsc, tsc_aux, smbase;
} em_x86_sys;
EM_STATIC_ASSERT(sizeof(em_x86_sys) == 104, "em_x86_sys layout");

typedef struct em_x86_fpu {
    uint16_t fcw, fsw;
    uint8_t  ftw, reserved0;
    uint16_t fop;
    uint64_t fpu_ip, fpu_dp;
    uint32_t mxcsr, mxcsr_mask;
    uint8_t  st[8][16];
    uint8_t  xmm[16][16];
    uint8_t  reserved1[96];
} em_x86_fpu;
EM_STATIC_ASSERT(sizeof(em_x86_fpu) == 512, "em_x86_fpu layout");

/* VMX state of a cpu. valid says which groups the stub could fill (EM_VMX_V_*); the
 * others read as zero. The guest and host fields are the current VMCS's. */
typedef struct em_x86_vmx {
    uint32_t valid;
    uint32_t flags;                 /* EM_VMX_F_* */
    uint64_t vmxon_pa;
    uint64_t vmcs_pa;               /* current VMCS, ~0 = none */

    uint64_t eptp;
    uint16_t vpid;
    uint16_t reserved0[3];
    uint64_t proc_ctls, proc_ctls2, exit_ctls, entry_ctls;

    uint64_t guest_cr0, guest_cr3, guest_cr4, guest_efer, guest_pat;
    uint64_t guest_pdpte[4];        /* PAE guest with EPT: loaded from the VMCS, not memory */

    uint64_t host_cr0, host_cr3, host_cr4, host_efer;
    uint64_t host_rip, host_rsp;

    uint32_t exit_reason;           /* last VM exit */
    uint32_t reserved1;
    uint64_t exit_qualification;
    uint64_t guest_linear_addr;
    uint64_t guest_physical_addr;
} em_x86_vmx;
EM_STATIC_ASSERT(sizeof(em_x86_vmx) == 224, "em_x86_vmx layout");

#define EM_VMX_V_STATE       (1u << 0)   /* flags, vmxon_pa, vmcs_pa */
#define EM_VMX_V_CTLS        (1u << 1)   /* eptp, vpid, the execution / exit / entry controls */
#define EM_VMX_V_GUEST       (1u << 2)   /* guest_cr0 ... guest_pdpte */
#define EM_VMX_V_HOST        (1u << 3)   /* host_* */
#define EM_VMX_V_EXIT        (1u << 4)   /* exit_reason ... guest_physical_addr */

#define EM_VMX_F_ON          (1u << 0)   /* VMXON executed */
#define EM_VMX_F_NON_ROOT    (1u << 1)   /* stopped in the guest */
#define EM_VMX_F_VMCS        (1u << 2)   /* a current VMCS is loaded */
#define EM_VMX_F_EPT         (1u << 3)   /* EPT enabled in the current VMCS */
#define EM_VMX_F_VPID        (1u << 4)
#define EM_VMX_F_UG          (1u << 5)   /* unrestricted guest */

/* Controls the debugger looks at. */
#define EM_VMX_PROC2_EPT     (1ull << 1)
#define EM_VMX_PROC2_VPID    (1ull << 5)
#define EM_VMX_PROC2_UG      (1ull << 7)
#define EM_VMX_PROC2_MBEC    (1ull << 22)  /* mode-based execute control for EPT */
#define EM_VMX_EXIT_HOST_64  (1ull << 9)   /* host address-space size */
#define EM_VMX_ENTRY_IA32E   (1ull << 9)   /* IA-32e mode guest */

/* Registers of the current VMCS's guest. In non-root mode they are the cpu's own; in root
 * mode rip / rsp / rflags and the segments come from the VMCS guest-state area and the
 * GPRs from wherever the hypervisor saved them on the VM exit. */
typedef struct em_x86_guest {
    uint32_t    valid;              /* EM_GUEST_V_* */
    uint32_t    reserved;
    em_x86_core core;
    em_x86_segs seg;
} em_x86_guest;
EM_STATIC_ASSERT(sizeof(em_x86_guest) == 312, "em_x86_guest layout");

#define EM_GUEST_V_GPRS      (1u << 0)   /* rax ... r15 except rsp */
#define EM_GUEST_V_RIP       (1u << 1)   /* rip, rsp, rflags */
#define EM_GUEST_V_SEGS      (1u << 2)

#define EM_X86_RB_MAX 512u

static inline uint32_t em_x86_rb_size(uint32_t id)
{
    switch (id) {
        case EM_RB_X86_CORE:
            return (uint32_t)sizeof(em_x86_core);
        case EM_RB_X86_SEG:
            return (uint32_t)sizeof(em_x86_segs);
        case EM_RB_X86_CTRL:
            return (uint32_t)sizeof(em_x86_ctrl);
        case EM_RB_X86_SYS:
            return (uint32_t)sizeof(em_x86_sys);
        case EM_RB_X86_FPU:
            return (uint32_t)sizeof(em_x86_fpu);
        case EM_RB_X86_VMX:
            return (uint32_t)sizeof(em_x86_vmx);
        case EM_RB_X86_GUEST:
            return (uint32_t)sizeof(em_x86_guest);
    }
    return 0;
}

typedef struct em_x86_regs {
    em_x86_core core;
    em_x86_segs seg;
    em_x86_ctrl ctrl;
    em_x86_sys  sys;
    em_x86_fpu  fpu;
    em_x86_vmx  vmx;
    em_x86_guest guest;
    uint32_t    valid;
    uint32_t    reserved;
} em_x86_regs;

#endif
