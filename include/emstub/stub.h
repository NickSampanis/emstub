#ifndef EMSTUB_STUB_H
#define EMSTUB_STUB_H

#include <stddef.h>
#include <stdint.h>

#include "proto.h"
#include "regs_x86.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef EM_STUB_MAX_PAYLOAD
#define EM_STUB_MAX_PAYLOAD 4096u
#endif

typedef struct em_stub_ops {
    int32_t   (*send)(void *user, const void *buf, uint32_t len);
    int32_t   (*recv)(void *user, void *buf, uint32_t len, int block);

    uint32_t  (*read_phys)(void *user, uint16_t cpu, uint64_t pa, void *buf, uint32_t len);
    uint32_t  (*write_phys)(void *user, uint16_t cpu, uint64_t pa, const void *buf, uint32_t len);

    int32_t   (*get_regs)(void *user, uint16_t cpu, uint32_t block, void *buf, uint32_t cap);
    em_status (*set_regs)(void *user, uint16_t cpu, uint32_t block, const void *buf, uint32_t size);

    uint32_t  (*read_virt)(void *user, uint16_t cpu, uint64_t va, void *buf, uint32_t len);
    uint32_t  (*write_virt)(void *user, uint16_t cpu, uint64_t va, const void *buf, uint32_t len);

    em_status (*translate)(void *user, uint16_t cpu, uint64_t va, uint64_t *pa, uint32_t *flags);

    em_status (*bp_set)(void *user, const em_bp_req *req);
    em_status (*bp_clear)(void *user, const em_bp_req *req);

    em_status (*read_msr)(void *user, uint16_t cpu, uint32_t index, uint64_t *value);
    em_status (*write_msr)(void *user, uint16_t cpu, uint32_t index, uint64_t value);

    em_status (*snap_save)(void *user, const char *name);
    em_status (*snap_load)(void *user, const char *name);

    uint32_t  (*monitor)(void *user, const char *cmd, uint32_t cmd_len, char *out, uint32_t cap);
} em_stub_ops;

typedef struct em_stub_info {
    const char *target;
    uint16_t    cpu_count;
    uint32_t    regblocks;
    uint64_t    features;
} em_stub_info;

typedef enum em_run {
    EM_RUN_CONTINUE = 0,
    EM_RUN_STOP     = 1,
} em_run;

typedef enum em_resume_action {
    EM_RESUME_CONTINUE = 0,
    EM_RESUME_STEP     = 1,
    EM_RESUME_DETACH   = 2,
} em_resume_action;

typedef struct em_resume {
    em_resume_action action;
    uint16_t         cpu;
} em_resume;

typedef struct em_stub {
    const em_stub_ops *ops;
    void              *user;
    em_stub_info       info;
    uint64_t           commands[2];

    uint32_t           peer_max;
    uint8_t            connected;
    uint8_t            running;
    uint8_t            pause_req;
    uint8_t            in_handler;

    uint8_t            resume_set;
    em_resume          resume;

    uint32_t           rx_have;
    uint32_t           tx_len;
    uint8_t            rx[sizeof(em_hdr) + EM_STUB_MAX_PAYLOAD];
    uint8_t            tx[sizeof(em_hdr) + EM_STUB_MAX_PAYLOAD];
    uint8_t            scratch[EM_X86_RB_MAX];
} em_stub;

void      em_stub_init(em_stub *stub, const em_stub_ops *ops, void *user, const em_stub_info *info);
void      em_stub_reset(em_stub *stub, int running);
int       em_stub_connected(const em_stub *stub);
em_run    em_stub_poll(em_stub *stub);
em_resume em_stub_stopped(em_stub *stub, uint16_t cpu, em_stop_reason reason, uint32_t bp_id,
                          uint64_t addr);
int       em_stub_output(em_stub *stub, const char *text, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
