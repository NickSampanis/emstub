/* emstub wire protocol. Freestanding: needs only stdint.h. Valid C11 and C++11 (Bochs is C++).
 *
 * Rules:
 *  - Little-endian. Every struct is naturally aligned with explicit padding, so no #pragma pack.
 *  - A packet is em_hdr followed by hdr.len bytes of payload.
 *  - The debugger sends REQ. The stub answers each one with exactly one REPLY carrying the same seq.
 *  - The stub may send an EVENT (seq 0) whenever it is not in the middle of a reply.
 *  - A payload is never larger than the max_payload agreed in HELLO; dbgeng splits big reads.
 *  - Adding a command or event: add a row to EM_COMMANDS / EM_EVENTS below. Additions never
 *    change EM_PROTO_VERSION; the stub advertises what it implements in em_hello_rep.commands.
 */
#ifndef EMSTUB_PROTO_H
#define EMSTUB_PROTO_H

#include <stdint.h>

#if defined(__cplusplus)
#define EM_STATIC_ASSERT(c, m) static_assert(c, m)
#else
#define EM_STATIC_ASSERT(c, m) _Static_assert(c, m)
#endif

#define EM_MAGIC          0x42444D45u   /* "EMDB" */
#define EM_PROTO_VERSION  1u
#define EM_MIN_PAYLOAD    4096u         /* every stub accepts at least this */

typedef enum em_kind {
    EM_KIND_REQ   = 0,
    EM_KIND_REPLY = 1,
    EM_KIND_EVENT = 2,
} em_kind;

typedef enum em_status {
    EM_OK = 0,
    EM_E_UNSUPPORTED,     /* command or block not implemented by this stub */
    EM_E_BADARG,
    EM_E_FAULT,           /* unmapped / unreadable memory */
    EM_E_PARTIAL,         /* reply holds less data than requested */
    EM_E_RUNNING,         /* needs a stopped target */
} em_status;

typedef struct em_hdr {
    uint32_t magic;
    uint16_t type;        /* em_cmd or em_event */
    uint8_t  kind;        /* em_kind */
    uint8_t  status;      /* em_status, replies only */
    uint32_t seq;         /* request seq, echoed by the reply; 0 for events */
    uint32_t len;         /* payload bytes that follow */
    uint32_t crc;         /* CRC-32 of the payload, 0 when len == 0 */
} em_hdr;
EM_STATIC_ASSERT(sizeof(em_hdr) == 20, "em_hdr layout");

/* --- payloads ------------------------------------------------------------ */

typedef struct em_empty {
    uint32_t reserved;    /* C has no empty structs; always 0 */
} em_empty;
EM_STATIC_ASSERT(sizeof(em_empty) == 4, "em_empty layout");

typedef struct em_hello_req {
    uint32_t version;         /* debugger's EM_PROTO_VERSION */
    uint32_t max_payload;     /* largest payload the debugger accepts */
} em_hello_req;
EM_STATIC_ASSERT(sizeof(em_hello_req) == 8, "em_hello_req layout");

typedef struct em_hello_rep {
    uint32_t version;         /* stub's EM_PROTO_VERSION */
    uint32_t max_payload;     /* largest payload the stub accepts */
    uint64_t commands[2];     /* bit n set = command id n implemented */
    uint64_t features;        /* EM_FEAT_* */
    uint32_t regblocks;       /* bit n set = register block n available (em_regblock) */
    uint16_t arch;            /* EM_ARCH_* */
    uint16_t cpu_count;
    char     target[32];      /* "bochs 2.8", "qemu 9.1", "svmm"; NUL padded */
} em_hello_rep;
EM_STATIC_ASSERT(sizeof(em_hello_rep) == 72, "em_hello_rep layout");

#define EM_ARCH_X86          1u

#define EM_FEAT_JIT          (1ull << 0)   /* JIT translation queries */
#define EM_FEAT_HW_WATCH     (1ull << 1)   /* BP_SET supports read/write watchpoints */
#define EM_FEAT_PHYS_BP      (1ull << 2)   /* BP_SET supports physical addresses */

enum {
    EM_SPACE_VIRT = 0,        /* translated with the given cpu's page tables */
    EM_SPACE_PHYS = 1,
};

enum {
    EM_BP_EXEC   = 0,
    EM_BP_WRITE  = 1,
    EM_BP_READ   = 2,
    EM_BP_ACCESS = 3,
};

#define EM_CPU_ALL 0xFFFFu

typedef struct em_mem_req {
    uint64_t addr;
    uint32_t len;             /* <= negotiated max_payload */
    uint16_t cpu;
    uint8_t  space;           /* EM_SPACE_* */
    uint8_t  reserved;
} em_mem_req;
EM_STATIC_ASSERT(sizeof(em_mem_req) == 16, "em_mem_req layout");

typedef struct em_regs_req {
    uint16_t cpu;
    uint16_t reserved;
    uint32_t blocks;          /* bit n = em_regblock n */
} em_regs_req;
EM_STATIC_ASSERT(sizeof(em_regs_req) == 8, "em_regs_req layout");

typedef struct em_xlate_req {
    uint64_t vaddr;
    uint16_t cpu;
    uint16_t reserved[3];
} em_xlate_req;
EM_STATIC_ASSERT(sizeof(em_xlate_req) == 16, "em_xlate_req layout");

typedef struct em_xlate_rep {
    uint64_t paddr;
    uint32_t flags;           /* EM_XLATE_* */
    uint32_t reserved;
} em_xlate_rep;
EM_STATIC_ASSERT(sizeof(em_xlate_rep) == 16, "em_xlate_rep layout");

#define EM_XLATE_WRITABLE    (1u << 0)
#define EM_XLATE_USER        (1u << 1)
#define EM_XLATE_NX          (1u << 2)
#define EM_XLATE_LARGE       (1u << 3)    /* 2 MB / 4 MB page */
#define EM_XLATE_HUGE        (1u << 4)    /* 1 GB page */

typedef struct em_step_req {
    uint16_t cpu;             /* executes exactly one instruction on this cpu */
    uint16_t reserved[3];
} em_step_req;
EM_STATIC_ASSERT(sizeof(em_step_req) == 8, "em_step_req layout");

typedef struct em_bp_req {
    uint64_t addr;
    uint32_t len;             /* 1 for EM_BP_EXEC */
    uint8_t  type;            /* EM_BP_* */
    uint8_t  space;           /* EM_SPACE_* */
    uint16_t cpu;             /* EM_CPU_ALL for every cpu */
} em_bp_req;
EM_STATIC_ASSERT(sizeof(em_bp_req) == 16, "em_bp_req layout");

typedef struct em_bp_rep {
    uint32_t id;
    uint32_t reserved;
} em_bp_rep;
EM_STATIC_ASSERT(sizeof(em_bp_rep) == 8, "em_bp_rep layout");

typedef struct em_bp_id {
    uint32_t id;
    uint32_t reserved;
} em_bp_id;
EM_STATIC_ASSERT(sizeof(em_bp_id) == 8, "em_bp_id layout");

typedef struct em_msr {
    uint32_t index;
    uint16_t cpu;
    uint16_t reserved;
    uint64_t value;
} em_msr;
EM_STATIC_ASSERT(sizeof(em_msr) == 16, "em_msr layout");

typedef struct em_name_req {
    char name[64];            /* NUL padded */
} em_name_req;
EM_STATIC_ASSERT(sizeof(em_name_req) == 64, "em_name_req layout");

typedef enum em_stop_reason {
    EM_STOP_ATTACH,           /* first stop after connecting */
    EM_STOP_PAUSE,
    EM_STOP_STEP,
    EM_STOP_BREAKPOINT,       /* bp_id valid */
    EM_STOP_WATCH,            /* bp_id valid, addr = accessed address */
    EM_STOP_EXCEPTION,        /* addr = vector | (error code << 32) */
    EM_STOP_RESET,
} em_stop_reason;

typedef struct em_stopped {
    uint16_t cpu;
    uint8_t  reason;          /* em_stop_reason */
    uint8_t  reserved;
    uint32_t bp_id;
    uint64_t addr;
} em_stopped;                 /* followed by register blocks: at least CORE, SEG, CTRL */
EM_STATIC_ASSERT(sizeof(em_stopped) == 16, "em_stopped layout");

/* --- command and event tables ----------------------------------------------
 *
 * X(name, id, request, reply, flags)   request / reply: fixed part of the payload
 * X(name, id, payload, flags)          for events
 */
#define EM_F_REQ_TAIL  (1u << 0)      /* variable data follows the fixed request */
#define EM_F_REP_TAIL  (1u << 1)      /* variable data follows the fixed reply / event */
#define EM_F_RUNNING   (1u << 2)      /* allowed while the target runs */

#define EM_COMMANDS(X)                                                                           \
    X(HELLO,      0x01, em_hello_req,    em_hello_rep,  EM_F_RUNNING)                            \
    X(GET_REGS,   0x02, em_regs_req,     em_empty,      EM_F_REP_TAIL)                           \
    X(SET_REGS,   0x03, em_regs_req,     em_empty,      EM_F_REQ_TAIL)                           \
    X(READ_MEM,   0x04, em_mem_req,      em_empty,      EM_F_REP_TAIL | EM_F_RUNNING)            \
    X(WRITE_MEM,  0x05, em_mem_req,      em_empty,      EM_F_REQ_TAIL | EM_F_RUNNING)            \
    X(TRANSLATE,  0x06, em_xlate_req,    em_xlate_rep,  0)                                       \
    X(CONTINUE,   0x07, em_empty,        em_empty,      0)                                       \
    X(STEP,       0x08, em_step_req,     em_empty,      0)                                       \
    X(PAUSE,      0x09, em_empty,        em_empty,      EM_F_RUNNING)                            \
    X(BP_SET,     0x0A, em_bp_req,       em_bp_rep,     EM_F_RUNNING)                            \
    X(BP_CLEAR,   0x0B, em_bp_id,        em_empty,      EM_F_RUNNING)                            \
    X(READ_MSR,   0x0C, em_msr,          em_msr,        0)                                       \
    X(WRITE_MSR,  0x0D, em_msr,          em_empty,      0)                                       \
    X(SNAP_SAVE,  0x0E, em_name_req,     em_empty,      0)                                       \
    X(SNAP_LOAD,  0x0F, em_name_req,     em_empty,      0)                                       \
    X(MONITOR,    0x10, em_empty,        em_empty,      EM_F_REQ_TAIL | EM_F_REP_TAIL)

/* Stub -> debugger, unsolicited. Ids have bit 7 set. */
#define EM_EVENTS(X)                                                                             \
    X(STOPPED,    0x81, em_stopped,      EM_F_REP_TAIL)   /* + register blocks */                \
    X(OUTPUT,     0x82, em_empty,        EM_F_REP_TAIL)   /* + text: emulator / guest log */

typedef enum em_cmd {
#define EM_X(name, id, req, rep, flags) EM_CMD_##name = id,
    EM_COMMANDS(EM_X)
#undef EM_X
} em_cmd;

typedef enum em_event {
#define EM_X(name, id, payload, flags) EM_EV_##name = id,
    EM_EVENTS(EM_X)
#undef EM_X
} em_event;

#define EM_CMD_ID_LIMIT 128u          /* command ids must fit em_hello_rep.commands */

static inline const char *em_type_name(uint16_t type)
{
    switch (type) {
#define EM_X(name, id, ...) case id: return #name;
    EM_COMMANDS(EM_X)
    EM_EVENTS(EM_X)
#undef EM_X
    }
    return "?";
}

/* Size of the fixed request part; 0 for unknown types. */
static inline uint32_t em_req_size(uint16_t type)
{
    switch (type) {
#define EM_X(name, id, req, rep, flags) case id: return (uint32_t)sizeof(req);
    EM_COMMANDS(EM_X)
#undef EM_X
    }
    return 0;
}

/* Size of the fixed reply (or event) part; 0 for unknown types. */
static inline uint32_t em_rep_size(uint16_t type)
{
    switch (type) {
#define EM_X(name, id, req, rep, flags) case id: return (uint32_t)sizeof(rep);
    EM_COMMANDS(EM_X)
#undef EM_X
#define EM_X(name, id, payload, flags) case id: return (uint32_t)sizeof(payload);
    EM_EVENTS(EM_X)
#undef EM_X
    }
    return 0;
}

static inline uint32_t em_type_flags(uint16_t type)
{
    switch (type) {
#define EM_X(name, id, req, rep, flags) case id: return (flags);
    EM_COMMANDS(EM_X)
#undef EM_X
#define EM_X(name, id, payload, flags) case id: return (flags);
    EM_EVENTS(EM_X)
#undef EM_X
    }
    return 0;
}

/* CRC-32 (IEEE 802.3, reflected), bitwise so it needs no table in a kernel stub.
 * Chain calls by passing the previous result as crc; start with 0. */
static inline uint32_t em_crc32(uint32_t crc, const void *data, uint32_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t       i;
    int            bit;

    crc = ~crc;
    for (i = 0; i < len; i++) {
        crc ^= p[i];
        for (bit = 0; bit < 8; bit++)
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

#endif
