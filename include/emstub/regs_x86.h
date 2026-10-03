/* x86 register blocks for the emstub protocol. Freestanding, valid C11 and C++11.
 *
 * On the wire every block is em_rb_hdr followed by `size` bytes of block data.
 * Blocks only grow at the end: a reader copies min(size, sizeof(local struct)) and
 * zero-fills the rest, so older stubs keep working with newer debuggers and vice versa.
 */
#ifndef EMSTUB_REGS_X86_H
#define EMSTUB_REGS_X86_H

#include "proto.h"

typedef enum em_regblock {
    EM_RB_X86_CORE = 0,       /* GPRs, rip, rflags          (in every STOPPED) */
    EM_RB_X86_SEG  = 1,       /* segments + GDTR/IDTR       (in every STOPPED) */
    EM_RB_X86_CTRL = 2,       /* CRs, EFER, XCR0, DRs       (in every STOPPED) */
    EM_RB_X86_SYS  = 3,       /* system MSRs                (on demand) */
    EM_RB_X86_FPU  = 4,       /* FXSAVE image               (on demand) */
    EM_RB_X86_VMX  = 5,       /* hypervisor state, Svmm     (on demand, optional) */
} em_regblock;

#define EM_RB_BIT(id)        (1u << (id))
#define EM_RB_STOPPED_SET    (EM_RB_BIT(EM_RB_X86_CORE) | EM_RB_BIT(EM_RB_X86_SEG) | \
                              EM_RB_BIT(EM_RB_X86_CTRL))

typedef struct em_rb_hdr {
    uint16_t id;              /* em_regblock */
    uint16_t reserved;
    uint32_t size;            /* bytes of block data that follow */
} em_rb_hdr;
EM_STATIC_ASSERT(sizeof(em_rb_hdr) == 8, "em_rb_hdr layout");

typedef struct em_x86_core {
    uint64_t rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi;   /* encoding order */
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip;
    uint64_t rflags;
} em_x86_core;
EM_STATIC_ASSERT(sizeof(em_x86_core) == 144, "em_x86_core layout");

/* GPR by encoding number (0 = rax ... 15 = r15): EM_X86_GPR(core, 3) is core.rbx. */
#define EM_X86_GPR(core, n)  (((uint64_t *)&(core))[n])

typedef struct em_x86_seg {
    uint64_t base;
    uint32_t limit;
    uint16_t selector;
    uint16_t attr;            /* VMX access-rights layout, bits 0..15 */
} em_x86_seg;
EM_STATIC_ASSERT(sizeof(em_x86_seg) == 16, "em_x86_seg layout");

#define EM_SEG_TYPE(a)  ((a) & 0xFu)
#define EM_SEG_S(a)     (((a) >> 4) & 1u)
#define EM_SEG_DPL(a)   (((a) >> 5) & 3u)
#define EM_SEG_P(a)     (((a) >> 7) & 1u)
#define EM_SEG_AVL(a)   (((a) >> 12) & 1u)
#define EM_SEG_L(a)     (((a) >> 13) & 1u)   /* 64-bit code segment */
#define EM_SEG_DB(a)    (((a) >> 14) & 1u)
#define EM_SEG_G(a)     (((a) >> 15) & 1u)

typedef struct em_x86_segs {
    em_x86_seg cs, ss, ds, es, fs, gs, ldtr, tr;
    em_x86_seg gdtr, idtr;    /* selector and attr unused */
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
} em_x86_sys;                 /* any other MSR: READ_MSR / WRITE_MSR */
EM_STATIC_ASSERT(sizeof(em_x86_sys) == 104, "em_x86_sys layout");

typedef struct em_x86_fpu {   /* FXSAVE image */
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

typedef struct em_x86_vmx {   /* Svmm: state of the hypervisor running inside the guest */
    uint64_t    host_cr0, host_cr3, host_cr4, host_rsp, host_rip, host_ept;
    uint64_t    guest_cr0, guest_cr3, guest_cr4, guest_rsp, guest_rip, guest_efer;
    em_x86_core host_saved;
    em_x86_core guest_saved;
    uint8_t     vmx_enabled, vmx_in_guest, reserved[6];
} em_x86_vmx;
EM_STATIC_ASSERT(sizeof(em_x86_vmx) == 392, "em_x86_vmx layout");

#define EM_X86_RB_MAX 512u   /* largest block (FPU) */

/* Size of a block as this header version defines it; 0 for unknown ids. */
static inline uint32_t em_x86_rb_size(uint32_t id)
{
    switch (id) {
    case EM_RB_X86_CORE: return (uint32_t)sizeof(em_x86_core);
    case EM_RB_X86_SEG:  return (uint32_t)sizeof(em_x86_segs);
    case EM_RB_X86_CTRL: return (uint32_t)sizeof(em_x86_ctrl);
    case EM_RB_X86_SYS:  return (uint32_t)sizeof(em_x86_sys);
    case EM_RB_X86_FPU:  return (uint32_t)sizeof(em_x86_fpu);
    case EM_RB_X86_VMX:  return (uint32_t)sizeof(em_x86_vmx);
    }
    return 0;
}

/* Full register state of one cpu as kept by the debugger. Not sent as a whole:
 * only its blocks go over the wire. */
typedef struct em_x86_regs {
    em_x86_core core;
    em_x86_segs seg;
    em_x86_ctrl ctrl;
    em_x86_sys  sys;
    em_x86_fpu  fpu;
    em_x86_vmx  vmx;
    uint32_t    valid;        /* EM_RB_BIT(n) set = block n is filled in */
    uint32_t    reserved;
} em_x86_regs;

#endif
