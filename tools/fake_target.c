/* Fake x86-64 target: a TCP server that runs the emstub core over a tiny interpreted
 * machine. Use it to develop and test dbgeng and the GUI without Bochs or QEMU.
 *
 *   fake_target [port] [--cpus N] [--qemu-skip] [--no-run-set] [--no-bp-filter]
 *               [--no-held-access] [--halted N]   (default 4242, 127.0.0.1 only, 1 cpu)
 *
 * --halted N starts cpu N halted, like an AP waiting for INIT-SIPI; cpu 0 wakes it
 * HALT_WAKE_MS after it first runs. Stepping a halted cpu also runs the last continue's
 * cpus, held ones staying stopped, until it wakes and executes one instruction (what
 * QEMU's em-dbg bridge does).
 *
 * With --cpus N (up to 8) every cpu runs the program below on its own stack, sharing
 * memory. Exec breakpoints can be limited to one cpu (em_bp_req.cpu), and a CONTINUE can
 * run only some of the cpus (EM_FEAT_RUN_SET); the cpus left out answer register requests
 * meanwhile (EM_FEAT_HELD_ACCESS). --no-run-set, --no-bp-filter and --no-held-access turn
 * those off, to test a debugger against stubs without them.
 *
 * The machine: 1 MB of RAM, long-mode page tables mapping 0x400000-0x40FFFF, and this
 * program at 0x401000, looping forever:
 *
 *   start:    call main ; jmp start
 *   main:     return checksum(data, 4)          data = { 1, 2, 3, 4 } at 0x402000
 *   checksum: sum = (sum << 1) ^ buf[i] for each byte
 *
 * Only these instructions are understood (dispatch is by address, not by decoding),
 * plus int3: a 0xCC byte written over an instruction traps like on real hardware
 * (EM_STOP_EXCEPTION, addr = 3, rip after the 0xCC). Exec breakpoints set with BP_SET
 * are supported too. Executes about 1000 instructions per millisecond while running.
 */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "emstub/stub.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef SOCKET sock_t;
static void sleep_ms(unsigned ms) { Sleep(ms); }
static uint64_t now_ms(void) { return GetTickCount64(); }
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
typedef int sock_t;
#define INVALID_SOCKET (-1)
#define closesocket close
static void sleep_ms(unsigned ms)
{
    struct timespec ts;

    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static uint64_t now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}
#endif

/* --- machine ------------------------------------------------------------------------- */

#define RAM_SIZE     (1u << 20)
#define VA_BASE      0x400000ull     /* mapped 64 KB window */
#define VA_SIZE      0x10000ull
#define PA_BASE      0x10000ull      /* VA_BASE maps here */
#define ENTRY        0x401040ull
#define STACK_TOP    0x40FF00ull
#define DATA_ADDR    0x402000ull
#define FLAG_ZF      (1ull << 6)
#define MAX_BPS      16
#define MAX_SNAPS    32
#define MAX_CPUS     8
#define CPU_STACK    0x1000ull       /* each cpu's stack is this far below the previous one */
#define CPU_STAGGER  5               /* cpu n starts n * CPU_STAGGER instructions ahead */
#define HALT_WAKE_MS 2000u           /* cpu 0 wakes the --halted cpu this long after it first runs */

typedef struct fake_cpu {
    em_x86_core core;
    em_x86_segs segs;
    em_x86_ctrl ctrl;
    int         skip_bp;             /* instructions left that must not re-hit a breakpoint */
    int         pending;             /* stopped in the same round as the reported cpu */
    int         halted;              /* --halted: waits for cpu 0 to wake it */
    int         runs;                /* in the last continue's run set (em-dbg's emdbg_runs) */
    em_stop_reason pending_reason;
    uint32_t    pending_bp;
    uint64_t    pending_addr;
} fake_cpu;

static uint8_t     ram[RAM_SIZE];
static fake_cpu    cpus[MAX_CPUS];
static uint16_t    cpu_count = 1;        /* --cpus N */
static uint64_t    bps[MAX_BPS];          /* 0 = free slot; id = index + 1 */
static uint16_t    bp_cpus[MAX_BPS];      /* EM_CPU_ALL, or the only cpu the breakpoint stops */
static uint64_t    executed;
static int         qemu_skip;            /* --qemu-skip: the skip also hides the next instruction's breakpoint */
static int         run_sets = 1;         /* --no-run-set: do not offer EM_FEAT_RUN_SET */
static int         bp_filter = 1;        /* --no-bp-filter: breakpoints stop every cpu */
static int         held_access = 1;      /* --no-held-access: do not offer EM_FEAT_HELD_ACCESS */
static int         halted_cpu = -1;      /* --halted N */
static uint64_t    wake_at;              /* when cpu 0 wakes halted_cpu; 0 = cpu 0 has not run */

/* Snapshots live outside the machine, so they survive reset_machine() and reconnects. */
typedef struct snapshot {
    char        name[EM_SNAP_NAME_MAX + 1];
    uint32_t    id;
    uint64_t    saved_at;
    uint64_t    executed;
    uint8_t    *ram;
    fake_cpu    cpus[MAX_CPUS];
} snapshot;

static snapshot    snaps[MAX_SNAPS];
static uint32_t    snap_count;
static uint32_t    snap_next_id;

static const uint8_t program[] = {
    /* 0x401000 checksum */
    0x31, 0xC0,                                /* xor eax, eax                    */
    0x85, 0xF6,                                /* test esi, esi                   */
    0x74, 0x11,                                /* je 0x401017                     */
    0x31, 0xC9,                                /* xor ecx, ecx                    */
    0x0F, 0xB6, 0x14, 0x0F,                    /* movzx edx, byte ptr [rdi+rcx]   */
    0x01, 0xC0,                                /* add eax, eax                    */
    0x31, 0xD0,                                /* xor eax, edx                    */
    0x48, 0xFF, 0xC1,                          /* inc rcx                         */
    0x39, 0xCE,                                /* cmp esi, ecx                    */
    0x75, 0xF1,                                /* jne 0x401008                    */
    0xC3,                                      /* ret                             */
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    /* 0x401020 main */
    0x48, 0x83, 0xEC, 0x28,                    /* sub rsp, 0x28                   */
    0x48, 0x8D, 0x3D, 0xD5, 0x0F, 0x00, 0x00,  /* lea rdi, [rip+0xFD5]            */
    0xBE, 0x04, 0x00, 0x00, 0x00,              /* mov esi, 4                      */
    0xE8, 0xCB, 0xFF, 0xFF, 0xFF,              /* call 0x401000                   */
    0x48, 0x83, 0xC4, 0x28,                    /* add rsp, 0x28                   */
    0xC3,                                      /* ret                             */
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    /* 0x401040 start */
    0xE8, 0xDB, 0xFF, 0xFF, 0xFF,              /* call 0x401020                   */
    0xEB, 0xF9,                                /* jmp 0x401040                    */
};

static uint8_t *va_ptr(uint64_t va, uint32_t len)
{
    if (va < VA_BASE || va + len > VA_BASE + VA_SIZE)
        return NULL;
    return ram + PA_BASE + (va - VA_BASE);
}

static uint64_t read64(uint64_t va)
{
    uint8_t *p = va_ptr(va, 8);
    uint64_t v = 0;

    if (p)
        memcpy(&v, p, 8);
    return v;
}

static void write64(uint64_t va, uint64_t v)
{
    uint8_t *p = va_ptr(va, 8);

    if (p)
        memcpy(p, &v, 8);
}

static void put_pte(uint64_t pa, uint64_t value)
{
    memcpy(ram + pa, &value, 8);
}

static int exec_one(fake_cpu *cpu);

static void reset_cpu(fake_cpu *cpu, uint64_t stack_top)
{
    cpu->core.rip = ENTRY;
    cpu->core.rsp = stack_top;
    cpu->core.rflags = 0x202;

    cpu->segs.cs.selector = 0x10;
    cpu->segs.cs.attr = 0x209B;               /* code, present, L = 1 */
    cpu->segs.ss.selector = cpu->segs.ds.selector = cpu->segs.es.selector = 0x18;
    cpu->segs.ss.attr = cpu->segs.ds.attr = cpu->segs.es.attr = 0xC093;
    cpu->segs.cs.limit = cpu->segs.ss.limit = cpu->segs.ds.limit = cpu->segs.es.limit = 0xFFFFFFFF;
    cpu->segs.gdtr.base = 0x5000;
    cpu->segs.gdtr.limit = 0x2F;

    cpu->ctrl.cr0 = 0x80000011;               /* PG | ET | PE */
    cpu->ctrl.cr3 = 0x1000;
    cpu->ctrl.cr4 = 0x20;                     /* PAE */
    cpu->ctrl.efer = 0x500;                   /* LME | LMA */
    cpu->ctrl.dr6 = 0xFFFF0FF0;
    cpu->ctrl.dr7 = 0x400;
}

/* Every cpu runs the same program on its own stack; cpu n is started n * CPU_STAGGER
 * instructions ahead so they are not all at the same place. */
static void reset_machine(void)
{
    uint64_t i;
    uint64_t step;

    memset(ram, 0, sizeof ram);
    /* PML4 0x1000 -> PDPT 0x2000 -> PD 0x3000 -> PT 0x4000; PD[2] covers 0x400000. */
    put_pte(0x1000, 0x2000 | 3);
    put_pte(0x2000, 0x3000 | 3);
    put_pte(0x3000 + 2 * 8, 0x4000 | 3);
    for (i = 0; i < VA_SIZE / 0x1000; i++)
        put_pte(0x4000 + i * 8, (PA_BASE + i * 0x1000) | 3);
    memcpy(va_ptr(0x401000, sizeof program), program, sizeof program);
    memcpy(va_ptr(DATA_ADDR, 4), "\x01\x02\x03\x04", 4);

    memset(cpus, 0, sizeof cpus);
    for (i = 0; i < cpu_count; i++) {
        reset_cpu(&cpus[i], STACK_TOP - i * CPU_STACK);
        cpus[i].runs = 1;
    }

    memset(bps, 0, sizeof bps);
    executed = 0;
    for (i = 1; i < cpu_count; i++)
        for (step = 0; step < i * CPU_STAGGER; step++)
            exec_one(&cpus[i]);
    wake_at = 0;
    if (halted_cpu >= 0 && halted_cpu < cpu_count)
        cpus[halted_cpu].halted = 1;
}

static void set_zf(fake_cpu *cpu, int zf)
{
    cpu->core.rflags = zf ? (cpu->core.rflags | FLAG_ZF) : (cpu->core.rflags & ~FLAG_ZF);
}

/* Execute the instruction at the cpu's rip. Returns -1, or an exception vector. */
static int exec_one(fake_cpu *cpu)
{
    uint64_t pc = cpu->core.rip;
    uint8_t *code = va_ptr(pc, 1);
    uint32_t eax = (uint32_t)cpu->core.rax;
    uint8_t *data;

    if (!code)
        return 14;                            /* #PF: outside the mapped window */
    if (*code == 0xCC) {
        cpu->core.rip = pc + 1;                    /* int3 traps after the instruction */
        return 3;
    }

    switch (pc) {
    case 0x401000: cpu->core.rax = 0; cpu->core.rip = 0x401002; break;
    case 0x401002: set_zf(cpu, (uint32_t)cpu->core.rsi == 0); cpu->core.rip = 0x401004; break;
    case 0x401004: cpu->core.rip = (cpu->core.rflags & FLAG_ZF) ? 0x401017 : 0x401006; break;
    case 0x401006: cpu->core.rcx = 0; cpu->core.rip = 0x401008; break;
    case 0x401008:
        data = va_ptr(cpu->core.rdi + cpu->core.rcx, 1);
        cpu->core.rdx = data ? *data : 0;
        cpu->core.rip = 0x40100C;
        break;
    case 0x40100C: cpu->core.rax = (uint32_t)(eax + eax); cpu->core.rip = 0x40100E; break;
    case 0x40100E: cpu->core.rax = eax ^ (uint32_t)cpu->core.rdx; cpu->core.rip = 0x401010; break;
    case 0x401010: cpu->core.rcx++; cpu->core.rip = 0x401013; break;
    case 0x401013: set_zf(cpu, (uint32_t)cpu->core.rsi == (uint32_t)cpu->core.rcx); cpu->core.rip = 0x401015; break;
    case 0x401015: cpu->core.rip = (cpu->core.rflags & FLAG_ZF) ? 0x401017 : 0x401008; break;
    case 0x401017:
    case 0x401039:
        cpu->core.rip = read64(cpu->core.rsp);
        cpu->core.rsp += 8;
        break;
    case 0x401020: cpu->core.rsp -= 0x28; cpu->core.rip = 0x401024; break;
    case 0x401024: cpu->core.rdi = DATA_ADDR; cpu->core.rip = 0x40102B; break;
    case 0x40102B: cpu->core.rsi = 4; cpu->core.rip = 0x401030; break;
    case 0x401030:
        cpu->core.rsp -= 8;
        write64(cpu->core.rsp, 0x401035);
        cpu->core.rip = 0x401000;
        break;
    case 0x401035: cpu->core.rsp += 0x28; cpu->core.rip = 0x401039; break;
    case 0x401040:
        cpu->core.rsp -= 8;
        write64(cpu->core.rsp, 0x401045);
        cpu->core.rip = 0x401020;
        break;
    case 0x401045: cpu->core.rip = 0x401040; break;
    default:
        return 6;                             /* #UD: not an instruction we know */
    }
    executed++;
    return -1;
}

static uint32_t bp_at(uint64_t va, uint16_t cpu)
{
    uint32_t i;

    for (i = 0; i < MAX_BPS; i++)
        if (bps[i] == va && (!bp_filter || bp_cpus[i] == EM_CPU_ALL || bp_cpus[i] == cpu))
            return i + 1;
    return 0;
}

/* --- stub ops ------------------------------------------------------------------------ */

static int32_t op_send(void *user, const void *buf, uint32_t len)
{
    sock_t      s = *(sock_t *)user;
    const char *p = (const char *)buf;
    int         n;

    while (len) {
        n = (int)send(s, p, (int)len, 0);
        if (n <= 0)
            return -1;
        p += n;
        len -= (uint32_t)n;
    }
    return 0;
}

static int32_t op_recv(void *user, void *buf, uint32_t len, int block)
{
    sock_t         s = *(sock_t *)user;
    fd_set         rd;
    struct timeval tv;
    int            n;

    if (!block) {
        FD_ZERO(&rd);
        FD_SET(s, &rd);
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        if (select((int)s + 1, &rd, NULL, NULL, &tv) <= 0)
            return 0;
    }
    n = (int)recv(s, (char *)buf, (int)len, 0);
    return n > 0 ? n : -1;
}

static uint32_t op_read_phys(void *user, uint16_t cpu, uint64_t pa, void *buf, uint32_t len)
{
    (void)user;
    if (pa >= RAM_SIZE)
        return 0;
    if (len > RAM_SIZE - pa)
        len = (uint32_t)(RAM_SIZE - pa);
    memcpy(buf, ram + pa, len);
    return len;
}

static uint32_t op_write_phys(void *user, uint16_t cpu, uint64_t pa, const void *buf, uint32_t len)
{
    (void)user;
    if (pa >= RAM_SIZE)
        return 0;
    if (len > RAM_SIZE - pa)
        len = (uint32_t)(RAM_SIZE - pa);
    memcpy(ram + pa, buf, len);
    return len;
}

static void *block(uint16_t cpu, uint32_t id, uint32_t *size)
{
    if (cpu >= cpu_count)
        return NULL;
    switch (id) {
    case EM_RB_X86_CORE: *size = sizeof cpus[cpu].core; return &cpus[cpu].core;
    case EM_RB_X86_SEG:  *size = sizeof cpus[cpu].segs; return &cpus[cpu].segs;
    case EM_RB_X86_CTRL: *size = sizeof cpus[cpu].ctrl; return &cpus[cpu].ctrl;
    }
    return NULL;
}

static int32_t op_get_regs(void *user, uint16_t cpu, uint32_t id, void *buf, uint32_t cap)
{
    uint32_t size;
    void    *src = block(cpu, id, &size);

    (void)user;
    if (!src)
        return -EM_E_UNSUPPORTED;
    if (cap < size)
        return -EM_E_BADARG;
    memcpy(buf, src, size);
    return (int32_t)size;
}

static em_status op_set_regs(void *user, uint16_t cpu, uint32_t id, const void *buf, uint32_t size)
{
    uint32_t local;
    void    *dst = block(cpu, id, &local);

    (void)user;
    if (!dst || size != local)
        return EM_E_UNSUPPORTED;
    memcpy(dst, buf, size);
    return EM_OK;
}

static em_status op_bp_set(void *user, const em_bp_req *req)
{
    uint32_t i;

    (void)user;
    if (req->type != EM_BP_EXEC || req->space != EM_SPACE_VIRT)
        return EM_E_UNSUPPORTED;
    for (i = 0; i < MAX_BPS; i++) {
        if (!bps[i]) {
            bps[i] = req->addr;
            bp_cpus[i] = req->cpu;
            return EM_OK;
        }
    }
    return EM_E_BADARG;
}

static em_status op_bp_clear(void *user, const em_bp_req *req)
{
    uint32_t i;

    (void)user;

   if (req->type != EM_BP_EXEC || req->space != EM_SPACE_VIRT)
        return EM_E_UNSUPPORTED;
    for (i = 0; i < MAX_BPS; i++) {
        if (bps[i] == req->addr && bp_cpus[i] == req->cpu) {
            bps[i] = 0;
            return EM_OK;
        }
    }
    return EM_OK;
}
static uint32_t op_monitor(void *user, const char *cmd, uint32_t cmd_len, char *out, uint32_t cap)
{
    uint16_t cpu;
    int      n;

    (void)user;
    if (cmd_len == 4 && !memcmp(cmd, "info", 4)) {
        n = snprintf(out, cap, "fake target: %llu instructions executed\n",
                     (unsigned long long)executed);
        for (cpu = 0; cpu < cpu_count && n >= 0 && (uint32_t)n < cap; cpu++)
            n += snprintf(out + n, cap - (uint32_t)n, "  cpu %u: rip=%016llX\n", cpu,
                          (unsigned long long)cpus[cpu].core.rip);
    } else if (cmd_len == 5 && !memcmp(cmd, "reset", 5)) {
        reset_machine();
        n = snprintf(out, cap, "machine reset\n");
    } else
        n = snprintf(out, cap, "monitor commands: info, reset\n");
    return n < 0 ? 0 : ((uint32_t)n < cap ? (uint32_t)n : cap);
}

static snapshot *snap_by_name(const char *name)
{
    uint32_t index;

    for (index = 0; index < snap_count; index++)
        if (!strcmp(snaps[index].name, name))
            return &snaps[index];
    return NULL;
}

static snapshot *snap_by_id(const char *id)
{
    char     text[16];
    uint32_t index;

    for (index = 0; index < snap_count; index++) {
        snprintf(text, sizeof text, "%u", snaps[index].id);
        if (!strcmp(text, id))
            return &snaps[index];
    }
    return NULL;
}

static snapshot *snap_by_entry(const char *id, const char *name)
{
    snapshot *snap;

    snap = snap_by_id(id);
    if (!snap || strcmp(snap->name, name))
        return NULL;
    return snap;
}

static void snap_describe(const snapshot *snap, em_snap_entry *info)
{
    snprintf(info->id, sizeof info->id, "%u", snap->id);
    snprintf(info->name, sizeof info->name, "%s", snap->name);
    info->saved_at = snap->saved_at;
}

/* With an id, that snapshot is updated in place (renamed too when the name differs); an unknown
   id is an error. Without one, a name that already exists is updated, otherwise a new snapshot is
   made. An update keeps the snapshot's id. */
static em_status op_snap_save(void *user, const char *id, const char *name,
                              em_snap_entry *save_entry)
{
    snapshot *snap;
    snapshot *named;
    char      auto_name[32];
    uint32_t  number;

    (void)user;
    if (id[0]) {
        snap = snap_by_id(id);
        if (!snap)
            return EM_E_BADARG;
        if (name[0]) {
            named = snap_by_name(name);
            if (named && named != snap)
                return EM_E_BADARG;
            snprintf(snap->name, sizeof snap->name, "%s", name);
        }
        name = snap->name;
    }
    if (!name[0]) {
        number = snap_next_id;
        do {
            number++;
            snprintf(auto_name, sizeof auto_name, "snap-%u", number);
        } while (snap_by_name(auto_name));
        name = auto_name;
    }
    snap = snap_by_name(name);
    if (!snap) {
        if (snap_count == MAX_SNAPS)
            return EM_E_BADARG;
        snap = &snaps[snap_count];
        memset(snap, 0, sizeof *snap);
        snap->ram = malloc(RAM_SIZE);
        if (!snap->ram)
            return EM_E_FAULT;
        snprintf(snap->name, sizeof snap->name, "%s", name);
        snap->id = ++snap_next_id;
        snap_count++;
    }
    snap->saved_at = (uint64_t)time(NULL);
    snap->executed = executed;
    memcpy(snap->ram, ram, RAM_SIZE);
    memcpy(snap->cpus, cpus, sizeof cpus);
    snap_describe(snap, save_entry);
    return EM_OK;
}

static em_status op_snap_load(void *user, const char *id, const char *name)
{
    snapshot *snap;
    uint32_t  index;

    (void)user;
    snap = snap_by_entry(id, name);
    if (!snap)
        return EM_E_BADARG;
    memcpy(ram, snap->ram, RAM_SIZE);
    memcpy(cpus, snap->cpus, sizeof cpus);
    for (index = 0; index < MAX_CPUS; index++)
        cpus[index].pending = 0;
    executed = snap->executed;
    return EM_OK;
}

static em_status op_snap_list(void *user, em_snap_emit emit, void *ctx)
{
    em_snap_entry snap_entry;
    em_status     status;
    uint32_t      index;

    (void)user;
    status = EM_OK;
    for (index = 0; index < snap_count && status == EM_OK; index++) {
        memset(&snap_entry, 0, sizeof snap_entry);
        snap_describe(&snaps[index], &snap_entry);
        status = emit(ctx, &snap_entry);
    }
    return status;
}

static em_status op_snap_delete(void *user, const char *id, const char *name)
{
    snapshot *snap;

    (void)user;
    snap = snap_by_entry(id, name);
    if (!snap)
        return EM_E_BADARG;
    free(snap->ram);
    memmove(snap, snap + 1, (size_t)(&snaps[snap_count] - (snap + 1)) * sizeof *snap);
    snap_count--;
    return EM_OK;
}

static const em_stub_ops ops = {
    op_send, op_recv,
    op_read_phys, op_write_phys,
    op_get_regs, op_set_regs,
    NULL, NULL,                   /* read_virt / write_virt: use the core's page walker */
    NULL,                         /* translate: same */
    op_bp_set, op_bp_clear,
    NULL, NULL,                   /* msr */
    op_snap_save, op_snap_load, op_snap_list, op_snap_delete,
    op_monitor,
};

/* --- session ------------------------------------------------------------------------- */

/* One instruction of a cpu, unless it is at a breakpoint. Returns 1 if the cpu stopped. */
static int run_one(fake_cpu *cpu, uint16_t index, em_stop_reason *reason, uint32_t *bp_id,
                   uint64_t *addr)
{
    int vec;

    if (!cpu->skip_bp && (*bp_id = bp_at(cpu->core.rip, index)) != 0) {
        *reason = EM_STOP_BREAKPOINT;
        *addr = 0;
        return 1;
    }
    if (cpu->skip_bp)
        cpu->skip_bp--;
    vec = exec_one(cpu);
    if (vec < 0)
        return 0;
    *reason = EM_STOP_EXCEPTION;
    *bp_id = 0;
    *addr = (uint64_t)vec;
    return 1;
}

/* A resumed cpu that stopped in the same round as the reported one: its stop is reported
 * now, before anything runs. Returns 1 if there was one. */
static int take_pending(em_stub *s, uint16_t *stop_cpu, em_stop_reason *reason, uint32_t *bp_id,
                        uint64_t *addr)
{
    uint16_t index;

    for (index = 0; index < cpu_count; index++) {
        if (!cpus[index].pending || !em_stub_cpu_runs(s, index))
            continue;
        cpus[index].pending = 0;
        *stop_cpu = index;
        *reason = cpus[index].pending_reason;
        *bp_id = cpus[index].pending_bp;
        *addr = cpus[index].pending_addr;
        return 1;
    }
    return 0;
}

static uint16_t first_running(em_stub *s)
{
    uint16_t index;

    for (index = 0; index < cpu_count; index++)
        if (em_stub_cpu_runs(s, index))
            return index;
    return 0;
}

/* Run the machine for one debugger connection. Starts stopped (EM_STOP_ATTACH).
 * All-stop: a continue runs the cpus the debugger named (all of them by default), one
 * instruction each in turn, until one of them stops; a step runs only the requested cpu.
 * The round in which a cpu stops is finished, like cores running in parallel: a second
 * cpu that stops in it keeps its stop pending for a later resume. */
static void run_session(em_stub *s)
{
    em_resume      r;
    em_stop_reason reason = EM_STOP_ATTACH;
    em_stop_reason other_reason;
    fake_cpu      *cpu;
    uint64_t       addr = 0;
    uint64_t       other_addr;
    uint32_t       bp_id = 0;
    uint32_t       other_bp;
    uint16_t       stop_cpu = 0;
    uint16_t       index;
    int            stepping = -1;        /* halted cpu whose step runs every cpu */
    int            stopped = 1;
    int            vec, i;

    for (;;) {
        if (stopped) {
            r = em_stub_stopped(s, stop_cpu, reason, bp_id, addr);
            if (r.action == EM_RESUME_DETACH)
                return;
            stopped = 0;
            stepping = -1;
            bp_id = 0;
            addr = 0;
            if (take_pending(s, &stop_cpu, &reason, &bp_id, &addr)) {
                stopped = 1;
                continue;
            }
            if (r.action == EM_RESUME_STEP) {
                stop_cpu = r.cpu < cpu_count ? r.cpu : 0;
                if (cpus[stop_cpu].halted) {
                    stepping = stop_cpu;       /* em-dbg: the run set runs with it */
                } else {
                    vec = exec_one(&cpus[stop_cpu]);
                    stopped = 1;
                    reason = vec < 0 ? EM_STOP_STEP : EM_STOP_EXCEPTION;
                    addr = vec < 0 ? 0 : (uint64_t)vec;
                    continue;
                }
            } else {
                for (index = 0; index < cpu_count; index++) {
                    cpus[index].runs = em_stub_cpu_runs(s, index);
                    if (cpus[index].runs)
                        cpus[index].skip_bp = qemu_skip ? 2 : 1;   /* resuming from a breakpoint must not re-hit it */
                }
            }
        }

        for (i = 0; i < 1000 && !stopped; i++) {
            for (index = 0; index < cpu_count; index++) {
                if (stepping >= 0 ? (int)index != stepping && !cpus[index].runs
                                  : !em_stub_cpu_runs(s, index))
                    continue;
                cpu = &cpus[index];
                if (cpu->halted)
                    continue;
                if (index == 0 && halted_cpu >= 0 && cpus[halted_cpu].halted) {
                    if (!wake_at)
                        wake_at = now_ms() + HALT_WAKE_MS;
                    else if (now_ms() >= wake_at)
                        cpus[halted_cpu].halted = 0;
                }
                if (!stopped && (int)index == stepping) {
                    vec = exec_one(cpu);
                    stopped = 1;
                    stop_cpu = index;
                    reason = vec < 0 ? EM_STOP_STEP : EM_STOP_EXCEPTION;
                    bp_id = 0;
                    addr = vec < 0 ? 0 : (uint64_t)vec;
                } else if (!stopped) {
                    if (run_one(cpu, index, &reason, &bp_id, &addr)) {
                        stopped = 1;
                        stop_cpu = index;
                    }
                } else if ((int)index != stepping &&
                           run_one(cpu, index, &other_reason, &other_bp, &other_addr)) {
                    cpu->pending = 1;
                    cpu->pending_reason = other_reason;
                    cpu->pending_bp = other_bp;
                    cpu->pending_addr = other_addr;
                }
            }
        }
        if (stopped)
            continue;
        if (em_stub_poll(s) == EM_RUN_STOP) {
            stopped = 1;
            stop_cpu = first_running(s);
            reason = EM_STOP_PAUSE;
            continue;
        }
        if (!em_stub_connected(s))
            return;
        sleep_ms(1);
    }
}

int main(int argc, char **argv)
{
    static em_stub     stub;
    em_stub_info       info;
    struct sockaddr_in sa;
    sock_t             server, client;
    unsigned           port = 4242u;
    int                one = 1;
    int                arg;
#ifdef _WIN32
    WSADATA            wsa;
#endif

    for (arg = 1; arg < argc; arg++) {
        if (!strcmp(argv[arg], "--qemu-skip"))
            qemu_skip = 1;
        else if (!strcmp(argv[arg], "--cpus") && arg + 1 < argc)
            cpu_count = (uint16_t)atoi(argv[++arg]);
        else if (!strcmp(argv[arg], "--no-run-set"))
            run_sets = 0;
        else if (!strcmp(argv[arg], "--no-bp-filter"))
            bp_filter = 0;
        else if (!strcmp(argv[arg], "--no-held-access"))
            held_access = 0;
        else if (!strcmp(argv[arg], "--halted") && arg + 1 < argc)
            halted_cpu = atoi(argv[++arg]);
        else
            port = (unsigned)atoi(argv[arg]);
    }
    if (cpu_count < 1 || cpu_count > MAX_CPUS) {
        fprintf(stderr, "fake_target: --cpus must be 1 to %u\n", MAX_CPUS);
        return 1;
    }
#ifdef _WIN32
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return 1;
#endif

    server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server == INVALID_SOCKET)
        return 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((unsigned short)port);
    if (bind(server, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(server, 1) != 0) {
        fprintf(stderr, "fake_target: cannot listen on 127.0.0.1:%u\n", port);
        return 1;
    }

    memset(&info, 0, sizeof info);
    info.target = "fake x86-64";
    info.cpu_count = cpu_count;
    info.regblocks = EM_RB_BIT(EM_RB_X86_CORE) | EM_RB_BIT(EM_RB_X86_SEG) |
                     EM_RB_BIT(EM_RB_X86_CTRL);
    info.features = (run_sets ? EM_FEAT_RUN_SET : 0) | (held_access ? EM_FEAT_HELD_ACCESS : 0);

    printf("fake_target listening on 127.0.0.1:%u (%u cpu%s)\n", port, cpu_count,
           cpu_count == 1 ? "" : "s");
    fflush(stdout);
    for (;;) {
        client = accept(server, NULL, NULL);
        if (client == INVALID_SOCKET)
            continue;
        setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
        printf("debugger connected\n");
        fflush(stdout);

        reset_machine();
        em_stub_init(&stub, &ops, &client, &info);
        em_stub_reset(&stub, 0);
        run_session(&stub);

        closesocket(client);
        printf("debugger disconnected\n");
        fflush(stdout);
    }
}
