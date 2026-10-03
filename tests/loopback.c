/* Loopback test for emstub core: fake x86 target + in-memory transport. */
#include "emstub/stub.h"

#include <stdio.h>
#include <string.h>

static uint8_t     mem[0x10000];
static em_x86_core core;
static em_x86_ctrl ctrl;

static uint8_t  to_stub[1 << 16];
static uint32_t to_stub_len, to_stub_pos;
static uint8_t  from_stub[1 << 16];
static uint32_t from_stub_len, from_stub_pos;
static uint32_t seq;
static int      failures;

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); failures++; } } while (0)

static int32_t t_send(void *u, const void *b, uint32_t n) { (void)u; memcpy(from_stub + from_stub_len, b, n); from_stub_len += n; return 0; }
static int deferred_continue;    /* CONTINUEs the "debugger" sends once the stub waits */
static void request(uint16_t type, const void *p, uint32_t n, const void *tail, uint32_t tn);

static int32_t t_recv(void *u, void *b, uint32_t n, int block)
{
    static const em_empty empty = { 0 };
    uint32_t avail = to_stub_len - to_stub_pos;

    (void)u;
    if (!avail && block && deferred_continue) {
        deferred_continue--;
        request(EM_CMD_CONTINUE, &empty, sizeof empty, 0, 0);
        avail = to_stub_len - to_stub_pos;
    }
    if (!avail)
        return block ? -1 : 0;     /* blocking on an empty queue = test bug: disconnect */
    if (n > avail) n = avail;
    if (n > 7) n = 7;              /* deliver in small pieces to exercise reassembly */
    memcpy(b, to_stub + to_stub_pos, n);
    to_stub_pos += n;
    return (int32_t)n;
}
static uint32_t t_rphys(void *u, uint64_t pa, void *b, uint32_t n) { (void)u; if (pa + n > sizeof mem) return 0; memcpy(b, mem + pa, n); return n; }
static uint32_t t_wphys(void *u, uint64_t pa, const void *b, uint32_t n) { (void)u; if (pa + n > sizeof mem) return 0; memcpy(mem + pa, b, n); return n; }
static int32_t t_get(void *u, uint16_t cpu, uint32_t blk, void *b, uint32_t cap)
{
    (void)u; (void)cpu;
    if (blk == EM_RB_X86_CORE && cap >= sizeof core) { memcpy(b, &core, sizeof core); return sizeof core; }
    if (blk == EM_RB_X86_CTRL && cap >= sizeof ctrl) { memcpy(b, &ctrl, sizeof ctrl); return sizeof ctrl; }
    return -EM_E_UNSUPPORTED;
}
static em_status t_set(void *u, uint16_t cpu, uint32_t blk, const void *b, uint32_t n)
{
    (void)u; (void)cpu;
    if (blk == EM_RB_X86_CORE && n == sizeof core) { memcpy(&core, b, n); return EM_OK; }
    return EM_E_UNSUPPORTED;
}

static void put64(uint64_t pa, uint64_t v) { memcpy(mem + pa, &v, 8); }

static void request(uint16_t type, const void *p, uint32_t n, const void *tail, uint32_t tn)
{
    em_hdr h;

    h.magic = EM_MAGIC; h.type = type; h.kind = EM_KIND_REQ; h.status = 0; h.seq = ++seq; h.len = n + tn;
    memcpy(to_stub + to_stub_len + sizeof h, p, n);
    if (tn) memcpy(to_stub + to_stub_len + sizeof h + n, tail, tn);
    h.crc = h.len ? em_crc32(0, to_stub + to_stub_len + sizeof h, h.len) : 0;
    memcpy(to_stub + to_stub_len, &h, sizeof h);
    to_stub_len += sizeof h + h.len;
}

/* Next packet from the stub; payload copied to out. */
static em_hdr next(void *out)
{
    em_hdr h;

    memset(&h, 0, sizeof h);
    if (from_stub_pos + sizeof h > from_stub_len) { printf("FAIL: no packet\n"); failures++; return h; }
    memcpy(&h, from_stub + from_stub_pos, sizeof h);
    if (out) memcpy(out, from_stub + from_stub_pos + sizeof h, h.len);
    CHECK(h.magic == EM_MAGIC);
    CHECK(h.crc == (h.len ? em_crc32(0, from_stub + from_stub_pos + sizeof h, h.len) : 0));
    from_stub_pos += sizeof h + h.len;
    return h;
}

int main(void)
{
    static const em_stub_ops ops = { t_send, t_recv, t_rphys, t_wphys, t_get, t_set, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    static em_stub s;
    em_stub_info   info = { "test", 1, EM_RB_BIT(EM_RB_X86_CORE) | EM_RB_BIT(EM_RB_X86_CTRL), 0 };
    em_hello_req   hello = { EM_PROTO_VERSION, 8192 };
    em_hello_rep   hrep;
    em_mem_req     mr;
    em_xlate_req   xr;
    em_xlate_rep   xp;
    em_regs_req    rr;
    em_step_req    step;
    uint32_t       full_len;
    em_empty       empty = { 0 };
    em_stopped     ev;
    em_resume      r;
    em_hdr         h;
    uint8_t        buf[4096];
    uint8_t        setblk[sizeof(em_rb_hdr) + 8];
    em_rb_hdr      rb;
    uint64_t       newrax = 0x1122334455667788ull;
    int            steps;

    /* Long-mode page tables: va 0x10000 -> pa 0x8000 (4K), va 0x200000 -> pa 0 (2M page). */
    put64(0x1000, 0x2000 | 3);          /* PML4[0] */
    put64(0x2000, 0x3000 | 3);          /* PDPT[0] */
    put64(0x3000, 0x4000 | 3);          /* PD[0] -> PT */
    put64(0x3008, 0x0 | 0x83);          /* PD[1]: 2 MB page at 0 */
    put64(0x4000 + 0x10 * 8, 0x8000 | 3);
    memcpy(mem + 0x8000, "HELLO-FROM-8000!", 16);
    memcpy(mem + 0x100, "LRG!", 4);
    ctrl.cr0 = 0x80000011; ctrl.cr3 = 0x1000; ctrl.cr4 = 0x20; ctrl.efer = 0x500;
    core.rip = 0x10000; core.rax = 1; core.rbx = 2;

    em_stub_init(&s, &ops, NULL, &info);
    em_stub_reset(&s, 0);

    request(EM_CMD_HELLO, &hello, sizeof hello, 0, 0);
    mr.addr = 0x10000; mr.len = 16; mr.cpu = 0; mr.space = EM_SPACE_VIRT; mr.reserved = 0;
    request(EM_CMD_READ_MEM, &mr, sizeof mr, 0, 0);
    mr.addr = 0x200100; mr.len = 4;
    request(EM_CMD_READ_MEM, &mr, sizeof mr, 0, 0);
    mr.addr = 0x400000;
    request(EM_CMD_READ_MEM, &mr, sizeof mr, 0, 0);
    memset(&xr, 0, sizeof xr); xr.vaddr = 0x10ABC;
    request(EM_CMD_TRANSLATE, &xr, sizeof xr, 0, 0);
    rb.id = EM_RB_X86_CORE; rb.reserved = 0; rb.size = 8;          /* short block: only rax */
    memcpy(setblk, &rb, sizeof rb); memcpy(setblk + sizeof rb, &newrax, 8);
    rr.cpu = 0; rr.reserved = 0; rr.blocks = 0;
    request(EM_CMD_SET_REGS, &rr, sizeof rr, setblk, sizeof setblk);
    request(EM_CMD_SNAP_SAVE, buf, 64, 0, 0);                      /* unsupported */
    memset(&step, 0, sizeof step);
    request(EM_CMD_STEP, &step, sizeof step, 0, 0);

    r = em_stub_stopped(&s, 0, EM_STOP_ATTACH, 0, 0);
    CHECK(r.action == EM_RESUME_STEP);

    h = next(buf); memcpy(&ev, buf, sizeof ev);
    CHECK(h.kind == EM_KIND_EVENT && h.type == EM_EV_STOPPED && ev.reason == EM_STOP_ATTACH);
    CHECK(h.len == sizeof ev + 2 * sizeof(em_rb_hdr) + sizeof(em_x86_core) + sizeof(em_x86_ctrl));
    h = next(&hrep);
    CHECK(h.type == EM_CMD_HELLO && h.status == EM_OK && h.seq == 1);
    CHECK(hrep.max_payload == EM_STUB_MAX_PAYLOAD && !strcmp(hrep.target, "test"));
    CHECK(hrep.commands[0] & (1ull << EM_CMD_TRANSLATE));
    CHECK(!(hrep.commands[0] & (1ull << EM_CMD_BP_SET)));
    h = next(buf);
    CHECK(h.status == EM_OK && h.len == 16 && !memcmp(buf, "HELLO-FROM-8000!", 16));
    h = next(buf);
    CHECK(h.status == EM_OK && h.len == 4 && !memcmp(buf, "LRG!", 4));
    h = next(buf);
    CHECK(h.status == EM_E_FAULT && h.len == 0);
    h = next(&xp);
    CHECK(h.status == EM_OK && xp.paddr == 0x8ABC && (xp.flags & EM_XLATE_WRITABLE));
    h = next(NULL);
    CHECK(h.type == EM_CMD_SET_REGS && h.status == EM_OK);
    CHECK(core.rax == newrax && core.rbx == 2 && core.rip == 0x10000);   /* short block kept the rest */
    h = next(NULL);
    CHECK(h.type == EM_CMD_SNAP_SAVE && h.status == EM_E_UNSUPPORTED);
    h = next(NULL);
    CHECK(h.type == EM_CMD_STEP && h.status == EM_OK);

    /* Embedder executes one instruction and reports the step. */
    deferred_continue++;
    core.rip++;
    steps = 1;
    r = em_stub_stopped(&s, 0, EM_STOP_STEP, 0, 0);
    CHECK(steps == 1 && r.action == EM_RESUME_CONTINUE);
    h = next(buf); memcpy(&ev, buf, sizeof ev);
    CHECK(h.type == EM_EV_STOPPED && ev.reason == EM_STOP_STEP);
    h = next(NULL);
    CHECK(h.type == EM_CMD_CONTINUE && h.status == EM_OK);

    /* Running: memory works, GET_REGS is refused, PAUSE stops. */
    mr.addr = 0x10000; mr.len = 5; mr.space = EM_SPACE_VIRT;
    request(EM_CMD_READ_MEM, &mr, sizeof mr, 0, 0);
    rr.blocks = EM_RB_BIT(EM_RB_X86_CORE);
    request(EM_CMD_GET_REGS, &rr, sizeof rr, 0, 0);
    request(EM_CMD_PAUSE, &empty, sizeof empty, 0, 0);
    CHECK(em_stub_poll(&s) == EM_RUN_STOP);
    CHECK(em_stub_poll(&s) == EM_RUN_CONTINUE);
    h = next(buf);
    CHECK(h.status == EM_OK && !memcmp(buf, "HELLO", 5));
    h = next(NULL);
    CHECK(h.type == EM_CMD_GET_REGS && h.status == EM_E_RUNNING);
    h = next(NULL);
    CHECK(h.type == EM_CMD_PAUSE && h.status == EM_OK);
    CHECK(em_stub_output(&s, "log", 3) == 0);
    h = next(buf);
    CHECK(h.kind == EM_KIND_EVENT && h.type == EM_EV_OUTPUT && h.len == 3);

    deferred_continue++;
    r = em_stub_stopped(&s, 0, EM_STOP_PAUSE, 0, 0);
    CHECK(r.action == EM_RESUME_CONTINUE);
    h = next(buf); memcpy(&ev, buf, sizeof ev);
    CHECK(ev.reason == EM_STOP_PAUSE);
    next(NULL);

    /* A request split across poll() and stopped(): the first 10 bytes arrive while
     * running, the rest after the stop. It must be served as one GET_REGS. */
    rr.blocks = EM_RB_BIT(EM_RB_X86_CORE);
    full_len = to_stub_len;
    request(EM_CMD_GET_REGS, &rr, sizeof rr, 0, 0);
    to_stub_len = full_len + 10;              /* only part of it is "on the wire" yet */
    full_len += sizeof(em_hdr) + sizeof rr;
    CHECK(em_stub_poll(&s) == EM_RUN_CONTINUE);
    CHECK(from_stub_pos == from_stub_len);    /* nothing answered yet */
    to_stub_len = full_len;                   /* the rest arrives */
    deferred_continue++;
    r = em_stub_stopped(&s, 0, EM_STOP_PAUSE, 0, 0);
    CHECK(r.action == EM_RESUME_CONTINUE);
    next(NULL);                               /* STOPPED */
    h = next(buf);
    CHECK(h.type == EM_CMD_GET_REGS && h.status == EM_OK &&
          h.len == sizeof(em_rb_hdr) + sizeof(em_x86_core));
    CHECK(!memcmp(buf + sizeof(em_rb_hdr), &core, sizeof core));
    h = next(NULL);
    CHECK(h.type == EM_CMD_CONTINUE);

    /* Corrupted packet drops the connection; stopped() then detaches. */
    request(EM_CMD_HELLO, &hello, sizeof hello, 0, 0);
    to_stub[to_stub_len - 1] ^= 0xFF;
    em_stub_poll(&s);
    CHECK(!em_stub_connected(&s));
    CHECK(em_stub_stopped(&s, 0, EM_STOP_PAUSE, 0, 0).action == EM_RESUME_DETACH);

    printf("%s (%d failures)\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures != 0;
}
