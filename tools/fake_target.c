/* Fake x86-64 target: a TCP server that runs the emstub core over a tiny interpreted
 * machine. Use it to develop and test dbgeng and the GUI without Bochs or QEMU.
 *
 *   fake_target [port]          (default 4242, listens on 127.0.0.1 only)
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

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef SOCKET sock_t;
static void sleep_ms(unsigned ms) { Sleep(ms); }
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

static uint8_t     ram[RAM_SIZE];
static em_x86_core core;
static em_x86_segs segs;
static em_x86_ctrl ctrl;
static uint64_t    bps[MAX_BPS];          /* 0 = free slot; id = index + 1 */
static uint64_t    executed;

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

static void reset_machine(void)
{
    uint64_t i;

    memset(ram, 0, sizeof ram);
    /* PML4 0x1000 -> PDPT 0x2000 -> PD 0x3000 -> PT 0x4000; PD[2] covers 0x400000. */
    put_pte(0x1000, 0x2000 | 3);
    put_pte(0x2000, 0x3000 | 3);
    put_pte(0x3000 + 2 * 8, 0x4000 | 3);
    for (i = 0; i < VA_SIZE / 0x1000; i++)
        put_pte(0x4000 + i * 8, (PA_BASE + i * 0x1000) | 3);
    memcpy(va_ptr(0x401000, sizeof program), program, sizeof program);
    memcpy(va_ptr(DATA_ADDR, 4), "\x01\x02\x03\x04", 4);

    memset(&core, 0, sizeof core);
    core.rip = ENTRY;
    core.rsp = STACK_TOP;
    core.rflags = 0x202;

    memset(&segs, 0, sizeof segs);
    segs.cs.selector = 0x10;
    segs.cs.attr = 0x209B;                    /* code, present, L = 1 */
    segs.ss.selector = segs.ds.selector = segs.es.selector = 0x18;
    segs.ss.attr = segs.ds.attr = segs.es.attr = 0xC093;
    segs.cs.limit = segs.ss.limit = segs.ds.limit = segs.es.limit = 0xFFFFFFFF;
    segs.gdtr.base = 0x5000;
    segs.gdtr.limit = 0x2F;

    memset(&ctrl, 0, sizeof ctrl);
    ctrl.cr0 = 0x80000011;                    /* PG | ET | PE */
    ctrl.cr3 = 0x1000;
    ctrl.cr4 = 0x20;                          /* PAE */
    ctrl.efer = 0x500;                        /* LME | LMA */
    ctrl.dr6 = 0xFFFF0FF0;
    ctrl.dr7 = 0x400;

    memset(bps, 0, sizeof bps);
    executed = 0;
}

static void set_zf(int zf)
{
    core.rflags = zf ? (core.rflags | FLAG_ZF) : (core.rflags & ~FLAG_ZF);
}

/* Execute the instruction at rip. Returns -1, or an exception vector. */
static int exec_one(void)
{
    uint64_t pc = core.rip;
    uint8_t *code = va_ptr(pc, 1);
    uint32_t eax = (uint32_t)core.rax;
    uint8_t *data;

    if (!code)
        return 14;                            /* #PF: outside the mapped window */
    if (*code == 0xCC) {
        core.rip = pc + 1;                    /* int3 traps after the instruction */
        return 3;
    }

    switch (pc) {
    case 0x401000: core.rax = 0; core.rip = 0x401002; break;
    case 0x401002: set_zf((uint32_t)core.rsi == 0); core.rip = 0x401004; break;
    case 0x401004: core.rip = (core.rflags & FLAG_ZF) ? 0x401017 : 0x401006; break;
    case 0x401006: core.rcx = 0; core.rip = 0x401008; break;
    case 0x401008:
        data = va_ptr(core.rdi + core.rcx, 1);
        core.rdx = data ? *data : 0;
        core.rip = 0x40100C;
        break;
    case 0x40100C: core.rax = (uint32_t)(eax + eax); core.rip = 0x40100E; break;
    case 0x40100E: core.rax = eax ^ (uint32_t)core.rdx; core.rip = 0x401010; break;
    case 0x401010: core.rcx++; core.rip = 0x401013; break;
    case 0x401013: set_zf((uint32_t)core.rsi == (uint32_t)core.rcx); core.rip = 0x401015; break;
    case 0x401015: core.rip = (core.rflags & FLAG_ZF) ? 0x401017 : 0x401008; break;
    case 0x401017:
    case 0x401039:
        core.rip = read64(core.rsp);
        core.rsp += 8;
        break;
    case 0x401020: core.rsp -= 0x28; core.rip = 0x401024; break;
    case 0x401024: core.rdi = DATA_ADDR; core.rip = 0x40102B; break;
    case 0x40102B: core.rsi = 4; core.rip = 0x401030; break;
    case 0x401030:
        core.rsp -= 8;
        write64(core.rsp, 0x401035);
        core.rip = 0x401000;
        break;
    case 0x401035: core.rsp += 0x28; core.rip = 0x401039; break;
    case 0x401040:
        core.rsp -= 8;
        write64(core.rsp, 0x401045);
        core.rip = 0x401020;
        break;
    case 0x401045: core.rip = 0x401040; break;
    default:
        return 6;                             /* #UD: not an instruction we know */
    }
    executed++;
    return -1;
}

static uint32_t bp_at(uint64_t va)
{
    uint32_t i;

    for (i = 0; i < MAX_BPS; i++)
        if (bps[i] == va)
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

static uint32_t op_read_phys(void *user, uint64_t pa, void *buf, uint32_t len)
{
    (void)user;
    if (pa >= RAM_SIZE)
        return 0;
    if (len > RAM_SIZE - pa)
        len = (uint32_t)(RAM_SIZE - pa);
    memcpy(buf, ram + pa, len);
    return len;
}

static uint32_t op_write_phys(void *user, uint64_t pa, const void *buf, uint32_t len)
{
    (void)user;
    if (pa >= RAM_SIZE)
        return 0;
    if (len > RAM_SIZE - pa)
        len = (uint32_t)(RAM_SIZE - pa);
    memcpy(ram + pa, buf, len);
    return len;
}

static void *block(uint32_t id, uint32_t *size)
{
    switch (id) {
    case EM_RB_X86_CORE: *size = sizeof core; return &core;
    case EM_RB_X86_SEG:  *size = sizeof segs; return &segs;
    case EM_RB_X86_CTRL: *size = sizeof ctrl; return &ctrl;
    }
    return NULL;
}

static int32_t op_get_regs(void *user, uint16_t cpu, uint32_t id, void *buf, uint32_t cap)
{
    uint32_t size;
    void    *src = block(id, &size);

    (void)user;
    (void)cpu;
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
    void    *dst = block(id, &local);

    (void)user;
    (void)cpu;
    if (!dst || size != local)
        return EM_E_UNSUPPORTED;
    memcpy(dst, buf, size);
    return EM_OK;
}

static em_status op_bp_set(void *user, const em_bp_req *req, uint32_t *id)
{
    uint32_t i;

    (void)user;
    if (req->type != EM_BP_EXEC || req->space != EM_SPACE_VIRT || req->addr == 0)
        return EM_E_UNSUPPORTED;
    for (i = 0; i < MAX_BPS; i++) {
        if (!bps[i]) {
            bps[i] = req->addr;
            *id = i + 1;
            return EM_OK;
        }
    }
    return EM_E_BADARG;
}

static em_status op_bp_clear(void *user, uint32_t id)
{
    (void)user;
    if (id == 0 || id > MAX_BPS || !bps[id - 1])
        return EM_E_BADARG;
    bps[id - 1] = 0;
    return EM_OK;
}

static uint32_t op_monitor(void *user, const char *cmd, uint32_t cmd_len, char *out, uint32_t cap)
{
    int n;

    (void)user;
    if (cmd_len == 4 && !memcmp(cmd, "info", 4))
        n = snprintf(out, cap, "fake target: %llu instructions executed, rip=%016llX\n",
                     (unsigned long long)executed, (unsigned long long)core.rip);
    else if (cmd_len == 5 && !memcmp(cmd, "reset", 5)) {
        reset_machine();
        n = snprintf(out, cap, "machine reset\n");
    } else
        n = snprintf(out, cap, "monitor commands: info, reset\n");
    return n < 0 ? 0 : ((uint32_t)n < cap ? (uint32_t)n : cap);
}

static const em_stub_ops ops = {
    op_send, op_recv,
    op_read_phys, op_write_phys,
    op_get_regs, op_set_regs,
    NULL, NULL,                   /* read_virt / write_virt: use the core's page walker */
    NULL,                         /* translate: same */
    op_bp_set, op_bp_clear,
    NULL, NULL,                   /* msr */
    NULL, NULL,                   /* snapshots */
    op_monitor,
};

/* --- session ------------------------------------------------------------------------- */

/* Run the machine for one debugger connection. Starts stopped (EM_STOP_ATTACH). */
static void run_session(em_stub *s)
{
    em_resume      r;
    em_stop_reason reason = EM_STOP_ATTACH;
    uint64_t       addr = 0;
    uint32_t       bp_id = 0;
    int            stopped = 1;
    int            skip_bp = 0;
    int            vec, i;

    for (;;) {
        if (stopped) {
            r = em_stub_stopped(s, 0, reason, bp_id, addr);
            if (r.action == EM_RESUME_DETACH)
                return;
            stopped = 0;
            skip_bp = 1;                      /* resuming from a breakpoint must not re-hit it */
            bp_id = 0;
            addr = 0;
            if (r.action == EM_RESUME_STEP) {
                vec = exec_one();
                stopped = 1;
                reason = vec < 0 ? EM_STOP_STEP : EM_STOP_EXCEPTION;
                addr = vec < 0 ? 0 : (uint64_t)vec;
                continue;
            }
        }

        for (i = 0; i < 1000 && !stopped; i++) {
            if (!skip_bp && (bp_id = bp_at(core.rip)) != 0) {
                stopped = 1;
                reason = EM_STOP_BREAKPOINT;
                break;
            }
            skip_bp = 0;
            vec = exec_one();
            if (vec >= 0) {
                stopped = 1;
                reason = EM_STOP_EXCEPTION;
                addr = (uint64_t)vec;
            }
        }
        if (stopped)
            continue;
        if (em_stub_poll(s) == EM_RUN_STOP) {
            stopped = 1;
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
    unsigned           port = argc > 1 ? (unsigned)atoi(argv[1]) : 4242u;
    int                one = 1;
#ifdef _WIN32
    WSADATA            wsa;

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
    info.cpu_count = 1;
    info.regblocks = EM_RB_BIT(EM_RB_X86_CORE) | EM_RB_BIT(EM_RB_X86_SEG) |
                     EM_RB_BIT(EM_RB_X86_CTRL);

    printf("fake_target listening on 127.0.0.1:%u\n", port);
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
