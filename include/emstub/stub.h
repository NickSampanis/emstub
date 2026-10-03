/* emstub core: the target-side debug stub.
 *
 * The core knows nothing about its host. The embedder (Bochs, QEMU, Svmm, an OS kernel)
 * supplies an ops table for transport and target access, and calls three functions:
 *
 *   1. em_stub_init()     once at startup.
 *   2. em_stub_reset()    whenever a debugger connects on the transport.
 *   3. While the target runs, call em_stub_poll() regularly (every N instructions, per
 *      translation block, or from a timer). It never blocks. If it returns EM_RUN_STOP,
 *      stop the cpus and call em_stub_stopped(..., EM_STOP_PAUSE, ...).
 *   4. Whenever the target stops (breakpoint, step done, exception, pause), call
 *      em_stub_stopped(). It talks to the debugger until told to resume, then returns:
 *        EM_RESUME_CONTINUE  run freely; keep calling em_stub_poll()
 *        EM_RESUME_STEP      execute exactly one instruction on resume.cpu, then call
 *                            em_stub_stopped(..., EM_STOP_STEP, ...)
 *        EM_RESUME_DETACH    the debugger is gone: run freely, drop stub breakpoints
 *
 * Threading: the core is not thread-safe. em_stub_poll() and em_stub_stopped() are the
 * only readers of the transport, and they must never run at the same time. Call both
 * from the same thread (the executor loop), or hold one lock around every em_stub_* call.
 * Partial packets are kept in struct em_stub between calls, so a request that starts
 * arriving during em_stub_poll() and finishes during em_stub_stopped() is not lost.
 *
 * The core never allocates: every buffer lives in struct em_stub, which the embedder
 * owns (static storage is fine). It needs only stdint.h and stddef.h.
 *
 * Old SvmmDebugStub mapping:
 *   SvmmDbgInit                 -> em_stub_init + em_stub_reset
 *   SvmmDbgLoop                 -> em_stub_stopped
 *   SvmmDbgCheckAsyncBreakpoint -> em_stub_poll
 */
#ifndef EMSTUB_STUB_H
#define EMSTUB_STUB_H

#include <stddef.h>
#include <stdint.h>

#include "proto.h"
#include "regs_x86.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Largest payload the stub accepts or sends. Override at compile time to trade memory
 * for fewer round-trips; struct em_stub holds two buffers of this size. */
#ifndef EM_STUB_MAX_PAYLOAD
#define EM_STUB_MAX_PAYLOAD 4096u
#endif

typedef struct em_stub_ops {
    /* --- transport (required) ------------------------------------------------------- */

    /* Send all len bytes. Return 0, or < 0 if the connection is gone. TCP embedders
     * should set TCP_NODELAY: every reply is one small send. */
    int32_t   (*send)(void *user, const void *buf, uint32_t len);

    /* Receive up to len bytes. block != 0: wait for at least one byte. block == 0: return
     * 0 at once if nothing is available. Return bytes read, or < 0 if the connection is gone. */
    int32_t   (*recv)(void *user, void *buf, uint32_t len, int block);

    /* --- target access (required) --------------------------------------------------- */

    /* Physical memory. Return bytes actually transferred (short = unmapped / MMIO refused). */
    uint32_t  (*read_phys)(void *user, uint64_t pa, void *buf, uint32_t len);
    uint32_t  (*write_phys)(void *user, uint64_t pa, const void *buf, uint32_t len);

    /* Register block `block` (em_regblock) of `cpu`. get_regs fills buf with the block as
     * defined in regs_x86.h and returns its size, or -em_status on error. set_regs always
     * receives a full-size block. Only blocks listed in em_stub_info.regblocks are asked for. */
    int32_t   (*get_regs)(void *user, uint16_t cpu, uint32_t block, void *buf, uint32_t cap);
    em_status (*set_regs)(void *user, uint16_t cpu, uint32_t block, const void *buf, uint32_t size);

    /* --- optional: NULL = not supported ---------------------------------------------- */

    /* Linear (virtual) memory through the cpu's own MMU / TLB. When NULL, the core
     * translates page by page (translate below, or its built-in x86 page walker) and uses
     * read_phys / write_phys. */
    uint32_t  (*read_virt)(void *user, uint16_t cpu, uint64_t va, void *buf, uint32_t len);
    uint32_t  (*write_virt)(void *user, uint16_t cpu, uint64_t va, const void *buf, uint32_t len);

    /* Linear -> physical. When NULL, the core walks the x86 page tables itself using
     * read_phys and the CTRL register block. flags: EM_XLATE_*. */
    em_status (*translate)(void *user, uint16_t cpu, uint64_t va, uint64_t *pa, uint32_t *flags);

    /* Breakpoints managed by the target (no 0xCC in guest memory). Both or neither.
     * When the target hits one, call em_stub_stopped(..., EM_STOP_BREAKPOINT or
     * EM_STOP_WATCH, id, accessed address). */
    em_status (*bp_set)(void *user, const em_bp_req *req, uint32_t *id);
    em_status (*bp_clear)(void *user, uint32_t id);

    em_status (*read_msr)(void *user, uint16_t cpu, uint32_t index, uint64_t *value);
    em_status (*write_msr)(void *user, uint16_t cpu, uint32_t index, uint64_t value);

    em_status (*snap_save)(void *user, const char *name);
    em_status (*snap_load)(void *user, const char *name);

    /* Free-form command for target-specific features. cmd is not NUL terminated.
     * Write at most cap bytes of text to out and return the count. */
    uint32_t  (*monitor)(void *user, const char *cmd, uint32_t cmd_len, char *out, uint32_t cap);
} em_stub_ops;

typedef struct em_stub_info {
    const char *target;       /* shown by the debugger: "bochs 2.8", "qemu 9.1", "svmm" */
    uint16_t    cpu_count;
    uint32_t    regblocks;    /* EM_RB_BIT(...) of the blocks get_regs / set_regs handle;
                                 must include CORE */
    uint64_t    features;     /* EM_FEAT_* */
} em_stub_info;

typedef enum em_run {
    EM_RUN_CONTINUE = 0,
    EM_RUN_STOP     = 1,      /* debugger asked for a pause */
} em_run;

typedef enum em_resume_action {
    EM_RESUME_CONTINUE = 0,
    EM_RESUME_STEP     = 1,
    EM_RESUME_DETACH   = 2,
} em_resume_action;

typedef struct em_resume {
    em_resume_action action;
    uint16_t         cpu;     /* cpu to step for EM_RESUME_STEP */
} em_resume;

/* Embedder-owned state. Treat the fields as private. */
typedef struct em_stub {
    const em_stub_ops *ops;
    void              *user;
    em_stub_info       info;
    uint64_t           commands[2];   /* implemented command ids, sent in HELLO */

    uint32_t           peer_max;      /* debugger's max payload, from HELLO */
    uint8_t            connected;     /* 0 until em_stub_reset, and after a transport error */
    uint8_t            running;
    uint8_t            pause_req;
    uint8_t            in_handler;

    uint8_t            resume_set;    /* a CONTINUE / STEP arrived */
    em_resume          resume;

    uint32_t           rx_have;       /* bytes of the current packet received so far */
    uint32_t           tx_len;        /* reply payload length built by a handler */
    uint8_t            rx[sizeof(em_hdr) + EM_STUB_MAX_PAYLOAD];
    uint8_t            tx[sizeof(em_hdr) + EM_STUB_MAX_PAYLOAD];
    uint8_t            scratch[EM_X86_RB_MAX];
} em_stub;

void      em_stub_init(em_stub *s, const em_stub_ops *ops, void *user, const em_stub_info *info);

/* A debugger connected on the transport. running: whether the target is currently running. */
void      em_stub_reset(em_stub *s, int running);

int       em_stub_connected(const em_stub *s);

/* While running: serve pending requests without blocking. */
em_run    em_stub_poll(em_stub *s);

/* The target stopped on `cpu`. bp_id / addr as described for em_stopped in proto.h. */
em_resume em_stub_stopped(em_stub *s, uint16_t cpu, em_stop_reason reason, uint32_t bp_id,
                          uint64_t addr);

/* Send log text to the debugger as an OUTPUT event. Not from inside an ops callback.
 * Returns 0, or -1 if not connected / called from a callback. Long text is truncated. */
int       em_stub_output(em_stub *s, const char *text, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
