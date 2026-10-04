#ifndef EMSTUB_PROTO_H
#define EMSTUB_PROTO_H

#include <stdint.h>

#if defined(__cplusplus)
#define EM_STATIC_ASSERT(condition, message) static_assert(condition, message)
#else
#define EM_STATIC_ASSERT(condition, message) _Static_assert(condition, message)
#endif

#define EM_MAGIC          0x42444D45u
#define EM_PROTO_VERSION  1u
#define EM_MIN_PAYLOAD    4096u

typedef enum em_kind {
    EM_KIND_REQ   = 0,
    EM_KIND_REPLY = 1,
    EM_KIND_EVENT = 2,
} em_kind;

typedef enum em_status {
    EM_OK = 0,
    EM_E_UNSUPPORTED,
    EM_E_BADARG,
    EM_E_FAULT,
    EM_E_PARTIAL,
    EM_E_RUNNING,
} em_status;

typedef struct em_hdr {
    uint32_t magic;
    uint16_t type;
    uint8_t  kind;
    uint8_t  status;
    uint32_t seq;
    uint32_t len;
    uint32_t crc;
} em_hdr;
EM_STATIC_ASSERT(sizeof(em_hdr) == 20, "em_hdr layout");

typedef struct em_empty {
    uint32_t reserved;
} em_empty;
EM_STATIC_ASSERT(sizeof(em_empty) == 4, "em_empty layout");

typedef struct em_hello_req {
    uint32_t version;
    uint32_t max_payload;
} em_hello_req;
EM_STATIC_ASSERT(sizeof(em_hello_req) == 8, "em_hello_req layout");

typedef struct em_hello_rep {
    uint32_t version;
    uint32_t max_payload;
    uint64_t commands[2];
    uint64_t features;
    uint32_t regblocks;
    uint16_t arch;
    uint16_t cpu_count;
    char     target[32];
} em_hello_rep;
EM_STATIC_ASSERT(sizeof(em_hello_rep) == 72, "em_hello_rep layout");

#define EM_ARCH_X86          1u

#define EM_FEAT_JIT          (1ull << 0)
#define EM_FEAT_HW_WATCH     (1ull << 1)
#define EM_FEAT_PHYS_BP      (1ull << 2)

enum {
    EM_SPACE_VIRT = 0,
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
    uint32_t len;
    uint16_t cpu;
    uint8_t  space;
    uint8_t  reserved;
} em_mem_req;
EM_STATIC_ASSERT(sizeof(em_mem_req) == 16, "em_mem_req layout");

typedef struct em_regs_req {
    uint16_t cpu;
    uint16_t reserved;
    uint32_t blocks;
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
    uint32_t flags;
    uint32_t reserved;
} em_xlate_rep;
EM_STATIC_ASSERT(sizeof(em_xlate_rep) == 16, "em_xlate_rep layout");

#define EM_XLATE_WRITABLE    (1u << 0)
#define EM_XLATE_USER        (1u << 1)
#define EM_XLATE_NX          (1u << 2)
#define EM_XLATE_LARGE       (1u << 3)
#define EM_XLATE_HUGE        (1u << 4)

typedef struct em_step_req {
    uint16_t cpu;
    uint16_t reserved[3];
} em_step_req;
EM_STATIC_ASSERT(sizeof(em_step_req) == 8, "em_step_req layout");

typedef struct em_bp_req {
    uint64_t addr;
    uint32_t len;
    uint8_t  type;
    uint8_t  space;
    uint16_t cpu;
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
    char name[64];
} em_name_req;
EM_STATIC_ASSERT(sizeof(em_name_req) == 64, "em_name_req layout");

typedef enum em_stop_reason {
    EM_STOP_ATTACH,
    EM_STOP_PAUSE,
    EM_STOP_STEP,
    EM_STOP_BREAKPOINT,
    EM_STOP_WATCH,
    EM_STOP_EXCEPTION,
    EM_STOP_RESET,
} em_stop_reason;

typedef struct em_stopped {
    uint16_t cpu;
    uint8_t  reason;
    uint8_t  reserved;
    uint32_t bp_id;
    uint64_t addr;
} em_stopped;
EM_STATIC_ASSERT(sizeof(em_stopped) == 16, "em_stopped layout");

#define EM_F_REQ_TAIL  (1u << 0)
#define EM_F_REP_TAIL  (1u << 1)
#define EM_F_RUNNING   (1u << 2)

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

#define EM_EVENTS(X)                                                                             \
    X(STOPPED,    0x81, em_stopped,      EM_F_REP_TAIL)                                          \
    X(OUTPUT,     0x82, em_empty,        EM_F_REP_TAIL)

typedef enum em_cmd {
#define EM_X(name, id, request_type, reply_type, flags) EM_CMD_##name = id,
    EM_COMMANDS(EM_X)
#undef EM_X
} em_cmd;

typedef enum em_event {
#define EM_X(name, id, payload_type, flags) EM_EV_##name = id,
    EM_EVENTS(EM_X)
#undef EM_X
} em_event;

#define EM_CMD_ID_LIMIT 128u

static inline const char *em_type_name(uint16_t type)
{
    switch (type) {
#define EM_X(name, id, ...) \
        case id:            \
            return #name;
        EM_COMMANDS(EM_X)
        EM_EVENTS(EM_X)
#undef EM_X
    }
    return "?";
}

static inline uint32_t em_req_size(uint16_t type)
{
    switch (type) {
#define EM_X(name, id, request_type, reply_type, flags) \
        case id:                                        \
            return (uint32_t)sizeof(request_type);
        EM_COMMANDS(EM_X)
#undef EM_X
    }
    return 0;
}

static inline uint32_t em_rep_size(uint16_t type)
{
    switch (type) {
#define EM_X(name, id, request_type, reply_type, flags) \
        case id:                                        \
            return (uint32_t)sizeof(reply_type);
        EM_COMMANDS(EM_X)
#undef EM_X
#define EM_X(name, id, payload_type, flags) \
        case id:                            \
            return (uint32_t)sizeof(payload_type);
        EM_EVENTS(EM_X)
#undef EM_X
    }
    return 0;
}

static inline uint32_t em_type_flags(uint16_t type)
{
    switch (type) {
#define EM_X(name, id, request_type, reply_type, flags) \
        case id:                                        \
            return (flags);
        EM_COMMANDS(EM_X)
#undef EM_X
#define EM_X(name, id, payload_type, flags) \
        case id:                            \
            return (flags);
        EM_EVENTS(EM_X)
#undef EM_X
    }
    return 0;
}

static inline uint32_t em_crc32(uint32_t crc, const void *data, uint32_t len)
{
    const uint8_t        *bytes;
    uint32_t             byte_index;
    int                  bit_index;

    bytes = (const uint8_t *)data;
    crc = ~crc;
    for (byte_index = 0; byte_index < len; byte_index++) {
        crc ^= bytes[byte_index];
        for (bit_index = 0; bit_index < 8; bit_index++)
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

#endif
