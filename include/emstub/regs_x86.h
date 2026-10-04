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

typedef struct em_x86_vmx {
    uint64_t    host_cr0, host_cr3, host_cr4, host_rsp, host_rip, host_ept;
    uint64_t    guest_cr0, guest_cr3, guest_cr4, guest_rsp, guest_rip, guest_efer;
    em_x86_core host_saved;
    em_x86_core guest_saved;
    uint8_t     vmx_enabled, vmx_in_guest, reserved[6];
} em_x86_vmx;
EM_STATIC_ASSERT(sizeof(em_x86_vmx) == 392, "em_x86_vmx layout");

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
    uint32_t    valid;
    uint32_t    reserved;
} em_x86_regs;

#endif
