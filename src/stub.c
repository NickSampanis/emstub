/* emstub core. See include/emstub/stub.h for how an embedder drives it. */
#include "emstub/stub.h"

EM_STATIC_ASSERT(EM_STUB_MAX_PAYLOAD >= EM_MIN_PAYLOAD, "EM_STUB_MAX_PAYLOAD too small");
EM_STATIC_ASSERT(EM_STUB_MAX_PAYLOAD >= sizeof(em_stopped) + 3 * sizeof(em_rb_hdr) +
                 sizeof(em_x86_core) + sizeof(em_x86_segs) + sizeof(em_x86_ctrl),
                 "STOPPED event must fit in one payload");

#define TX_PAYLOAD(s)  ((s)->tx + sizeof(em_hdr))
#define RX_PAYLOAD(s)  ((s)->rx + sizeof(em_hdr))

/* --- freestanding helpers ------------------------------------------------------------ */

static void em_memcpy(void *dst, const void *src, uint32_t n)
{
    uint8_t       *d = (uint8_t *)dst;
    const uint8_t *p = (const uint8_t *)src;

    while (n--)
        *d++ = *p++;
}

static void em_memset(void *dst, uint8_t c, uint32_t n)
{
    uint8_t *d = (uint8_t *)dst;

    while (n--)
        *d++ = c;
}

static uint32_t em_min(uint32_t a, uint32_t b)
{
    return a < b ? a : b;
}

/* --- framing ------------------------------------------------------------------------- */

static void drop_connection(em_stub *s)
{
    s->connected = 0;
    s->rx_have = 0;
}

/* Room for a reply / event payload: our buffer, limited by what the debugger accepts. */
static uint32_t tx_cap(const em_stub *s)
{
    return em_min(EM_STUB_MAX_PAYLOAD, s->peer_max);
}

/* Send TX_PAYLOAD(s)[0..len) with a header in front. */
static int send_packet(em_stub *s, uint16_t type, em_kind kind, em_status status, uint32_t seq,
                       uint32_t len)
{
    em_hdr h;

    h.magic  = EM_MAGIC;
    h.type   = type;
    h.kind   = (uint8_t)kind;
    h.status = (uint8_t)status;
    h.seq    = seq;
    h.len    = len;
    h.crc    = len ? em_crc32(0, TX_PAYLOAD(s), len) : 0;
    em_memcpy(s->tx, &h, sizeof h);

    if (s->ops->send(s->user, s->tx, (uint32_t)sizeof h + len) < 0) {
        drop_connection(s);
        return -1;
    }
    return 0;
}

/* Accumulate one request in s->rx. Returns 1 when a complete, valid request is there,
 * 0 when more bytes are needed (non-blocking only), -1 when the connection was dropped. */
static int recv_packet(em_stub *s, int block)
{
    em_hdr   h;
    uint32_t need;
    int32_t  n;

    for (;;) {
        need = (uint32_t)sizeof h;
        if (s->rx_have >= sizeof h) {
            em_memcpy(&h, s->rx, sizeof h);
            if (h.magic != EM_MAGIC || h.kind != EM_KIND_REQ || h.len > EM_STUB_MAX_PAYLOAD) {
                drop_connection(s);   /* no way to resync a byte stream */
                return -1;
            }
            need += h.len;
            if (s->rx_have == need) {
                s->rx_have = 0;
                if (h.len && em_crc32(0, RX_PAYLOAD(s), h.len) != h.crc) {
                    drop_connection(s);
                    return -1;
                }
                return 1;
            }
        }

        n = s->ops->recv(s->user, s->rx + s->rx_have, need - s->rx_have, block);
        if (n < 0) {
            drop_connection(s);
            return -1;
        }
        if (n == 0 && !block)
            return 0;
        s->rx_have += (uint32_t)n;
    }
}

/* --- x86 page walker (used when the embedder has no translate / read_virt) ----------- */

#define X86_CR0_PG    (1ull << 31)
#define X86_CR4_PSE   (1ull << 4)
#define X86_CR4_PAE   (1ull << 5)
#define X86_EFER_LMA  (1ull << 10)
#define X86_PTE_P     (1ull << 0)
#define X86_PTE_RW    (1ull << 1)
#define X86_PTE_US    (1ull << 2)
#define X86_PTE_PS    (1ull << 7)
#define X86_PTE_NX    (1ull << 63)

/* 4-level long mode, 3-level PAE and 2-level legacy paging, with large pages.
 * 5-level paging (LA57) is not handled yet. */
static em_status walk_x86(em_stub *s, uint16_t cpu, uint64_t va, uint64_t *pa, uint32_t *flags)
{
    static const uint8_t long_shift[] = { 39, 30, 21, 12 };
    static const uint8_t long_bits[]  = { 9, 9, 9, 9 };
    static const uint8_t pae_shift[]  = { 30, 21, 12 };
    static const uint8_t pae_bits[]   = { 2, 9, 9 };
    static const uint8_t leg_shift[]  = { 22, 12 };
    static const uint8_t leg_bits[]   = { 10, 10 };
    const uint8_t *shift;
    const uint8_t *bits;
    em_x86_ctrl    ctrl;
    uint64_t       table, entry, mask, idx, page;
    uint32_t       esize, entry32, f;
    int            levels, i, large;

    if (s->ops->get_regs(s->user, cpu, EM_RB_X86_CTRL, &ctrl, sizeof ctrl) != (int32_t)sizeof ctrl)
        return EM_E_UNSUPPORTED;

    f = EM_XLATE_WRITABLE | EM_XLATE_USER;
    if (!(ctrl.cr0 & X86_CR0_PG)) {
        *pa = va;
        *flags = f;
        return EM_OK;
    }

    if (ctrl.efer & X86_EFER_LMA) {
        shift = long_shift;
        bits = long_bits;
        levels = 4;
        esize = 8;
        mask = 0x000FFFFFFFFFF000ull;
        table = ctrl.cr3 & mask;
    } else if (ctrl.cr4 & X86_CR4_PAE) {
        shift = pae_shift;
        bits = pae_bits;
        levels = 3;
        esize = 8;
        mask = 0x000FFFFFFFFFF000ull;
        table = ctrl.cr3 & 0xFFFFFFE0ull;
        va &= 0xFFFFFFFFull;
    } else {
        shift = leg_shift;
        bits = leg_bits;
        levels = 2;
        esize = 4;
        mask = 0xFFFFF000ull;
        table = ctrl.cr3 & mask;
        va &= 0xFFFFFFFFull;
    }

    for (i = 0; i < levels; i++) {
        idx = (va >> shift[i]) & ((1ull << bits[i]) - 1);
        entry = 0;
        if (esize == 8) {
            if (s->ops->read_phys(s->user, table + idx * 8, &entry, 8) != 8)
                return EM_E_FAULT;
        } else {
            entry32 = 0;
            if (s->ops->read_phys(s->user, table + idx * 4, &entry32, 4) != 4)
                return EM_E_FAULT;
            entry = entry32;
        }
        if (!(entry & X86_PTE_P))
            return EM_E_FAULT;

        /* PAE PDPT entries have no RW/US/NX bits. */
        if (!(levels == 3 && i == 0)) {
            if (!(entry & X86_PTE_RW))
                f &= ~EM_XLATE_WRITABLE;
            if (!(entry & X86_PTE_US))
                f &= ~EM_XLATE_USER;
            if (esize == 8 && (entry & X86_PTE_NX))
                f |= EM_XLATE_NX;
        }

        large = i < levels - 1 && (entry & X86_PTE_PS) &&
                ((levels == 4 && i >= 1) || (levels == 3 && i == 1) ||
                 (levels == 2 && (ctrl.cr4 & X86_CR4_PSE)));
        if (large) {
            page = 1ull << shift[i];
            *pa = (entry & mask & ~(page - 1)) + (va & (page - 1));
            *flags = f | (shift[i] == 30 ? EM_XLATE_HUGE : EM_XLATE_LARGE);
            return EM_OK;
        }
        table = entry & mask;
    }

    *pa = table + (va & 0xFFFu);
    *flags = f;
    return EM_OK;
}

static em_status translate(em_stub *s, uint16_t cpu, uint64_t va, uint64_t *pa, uint32_t *flags)
{
    if (s->ops->translate)
        return s->ops->translate(s->user, cpu, va, pa, flags);
    if (s->info.regblocks & EM_RB_BIT(EM_RB_X86_CTRL))
        return walk_x86(s, cpu, va, pa, flags);
    return EM_E_UNSUPPORTED;
}

/* --- memory -------------------------------------------------------------------------- */

static uint32_t page_chunk(uint64_t addr, uint32_t left)
{
    uint32_t chunk = 0x1000u - (uint32_t)(addr & 0xFFFu);

    return em_min(chunk, left);
}

static uint32_t mem_read(em_stub *s, uint16_t cpu, uint8_t space, uint64_t addr, uint8_t *buf,
                         uint32_t len)
{
    uint64_t pa;
    uint32_t done = 0;
    uint32_t chunk, n, flags;

    if (space == EM_SPACE_PHYS)
        return s->ops->read_phys(s->user, addr, buf, len);
    if (s->ops->read_virt)
        return s->ops->read_virt(s->user, cpu, addr, buf, len);

    while (done < len) {
        chunk = page_chunk(addr + done, len - done);
        if (translate(s, cpu, addr + done, &pa, &flags) != EM_OK)
            break;
        n = s->ops->read_phys(s->user, pa, buf + done, chunk);
        done += n;
        if (n != chunk)
            break;
    }
    return done;
}

static uint32_t mem_write(em_stub *s, uint16_t cpu, uint8_t space, uint64_t addr, const uint8_t *buf,
                          uint32_t len)
{
    uint64_t pa;
    uint32_t done = 0;
    uint32_t chunk, n, flags;

    if (space == EM_SPACE_PHYS)
        return s->ops->write_phys(s->user, addr, buf, len);
    if (s->ops->write_virt)
        return s->ops->write_virt(s->user, cpu, addr, buf, len);

    while (done < len) {
        chunk = page_chunk(addr + done, len - done);
        if (translate(s, cpu, addr + done, &pa, &flags) != EM_OK)
            break;
        n = s->ops->write_phys(s->user, pa, buf + done, chunk);
        done += n;
        if (n != chunk)
            break;
    }
    return done;
}

/* --- register blocks ----------------------------------------------------------------- */

/* Append em_rb_hdr + data for every block in `blocks` to out[*pos..cap). */
static em_status append_blocks(em_stub *s, uint16_t cpu, uint32_t blocks, uint8_t *out,
                               uint32_t cap, uint32_t *pos)
{
    em_rb_hdr rb;
    uint32_t  id;
    int32_t   n;

    for (id = 0; id < 32; id++) {
        if (!(blocks & EM_RB_BIT(id)))
            continue;
        if (*pos + sizeof rb > cap)
            return EM_E_BADARG;
        n = s->ops->get_regs(s->user, cpu, id, out + *pos + sizeof rb,
                             cap - *pos - (uint32_t)sizeof rb);
        if (n < 0)
            return (em_status)-n;
        rb.id = (uint16_t)id;
        rb.reserved = 0;
        rb.size = (uint32_t)n;
        em_memcpy(out + *pos, &rb, sizeof rb);
        *pos += (uint32_t)sizeof rb + (uint32_t)n;
    }
    return EM_OK;
}

/* Hand one incoming block to set_regs at its full local size. A shorter block (from an
 * older debugger) is laid over the current values so unknown fields keep their contents;
 * a longer one (from a newer debugger) is cut to what this stub knows. */
static em_status set_block(em_stub *s, uint16_t cpu, uint32_t id, const uint8_t *data, uint32_t size)
{
    uint32_t local = em_x86_rb_size(id);
    int32_t  n;

    if (!local || !(s->info.regblocks & EM_RB_BIT(id)))
        return EM_E_UNSUPPORTED;
    if (size < local) {
        n = s->ops->get_regs(s->user, cpu, id, s->scratch, local);
        if (n < 0)
            return (em_status)-n;
    }
    em_memcpy(s->scratch, data, em_min(size, local));
    return s->ops->set_regs(s->user, cpu, id, s->scratch, local);
}

/* --- command handlers ---------------------------------------------------------------
 * Each gets the request payload (fixed part + tail), already checked for minimum size,
 * writes its reply payload to TX_PAYLOAD(s), sets s->tx_len and returns the status.
 * Payloads are copied into locals: the rx buffer gives no alignment guarantees. */

typedef em_status (*em_handler)(em_stub *s, const uint8_t *req, uint32_t len);

#define EM_X(name, id, rq, rp, fl) static em_status h_##name(em_stub *, const uint8_t *, uint32_t);
EM_COMMANDS(EM_X)
#undef EM_X

static em_handler handler_for(uint16_t type)
{
    switch (type) {
#define EM_X(name, id, rq, rp, fl) case id: return h_##name;
    EM_COMMANDS(EM_X)
#undef EM_X
    }
    return NULL;
}

static int cpu_ok(const em_stub *s, uint16_t cpu)
{
    return cpu < s->info.cpu_count;
}

static void reply(em_stub *s, const void *data, uint32_t len)
{
    em_memcpy(TX_PAYLOAD(s), data, len);
    s->tx_len = len;
}

static em_status h_HELLO(em_stub *s, const uint8_t *req, uint32_t len)
{
    em_hello_req q;
    em_hello_rep r;
    uint32_t     i;

    (void)len;
    em_memcpy(&q, req, sizeof q);
    s->peer_max = q.max_payload < EM_MIN_PAYLOAD ? EM_MIN_PAYLOAD : q.max_payload;

    em_memset(&r, 0, sizeof r);
    r.version     = EM_PROTO_VERSION;
    r.max_payload = EM_STUB_MAX_PAYLOAD;
    r.commands[0] = s->commands[0];
    r.commands[1] = s->commands[1];
    r.features    = s->info.features;
    r.regblocks   = s->info.regblocks;
    r.arch        = EM_ARCH_X86;
    r.cpu_count   = s->info.cpu_count;
    for (i = 0; s->info.target && s->info.target[i] && i < sizeof r.target - 1; i++)
        r.target[i] = s->info.target[i];
    reply(s, &r, sizeof r);
    return EM_OK;
}

static em_status h_GET_REGS(em_stub *s, const uint8_t *req, uint32_t len)
{
    em_regs_req q;
    uint32_t    pos = 0;
    em_status   st;

    (void)len;
    em_memcpy(&q, req, sizeof q);
    if (!cpu_ok(s, q.cpu))
        return EM_E_BADARG;
    st = append_blocks(s, q.cpu, q.blocks & s->info.regblocks, TX_PAYLOAD(s), tx_cap(s), &pos);
    s->tx_len = pos;
    return st;
}

static em_status h_SET_REGS(em_stub *s, const uint8_t *req, uint32_t len)
{
    em_regs_req q;
    em_rb_hdr   rb;
    uint32_t    pos;
    em_status   st;

    em_memcpy(&q, req, sizeof q);
    if (!cpu_ok(s, q.cpu))
        return EM_E_BADARG;
    for (pos = sizeof q; pos + sizeof rb <= len; pos += rb.size) {
        em_memcpy(&rb, req + pos, sizeof rb);
        pos += (uint32_t)sizeof rb;
        if (rb.size > len - pos)
            return EM_E_BADARG;
        st = set_block(s, q.cpu, rb.id, req + pos, rb.size);
        if (st != EM_OK)
            return st;
    }
    return EM_OK;
}

static em_status h_READ_MEM(em_stub *s, const uint8_t *req, uint32_t len)
{
    em_mem_req q;
    uint32_t   n;

    (void)len;
    em_memcpy(&q, req, sizeof q);
    if (q.space > EM_SPACE_PHYS || !cpu_ok(s, q.cpu) || q.len > tx_cap(s))
        return EM_E_BADARG;
    n = mem_read(s, q.cpu, q.space, q.addr, TX_PAYLOAD(s), q.len);
    s->tx_len = n;
    return n == q.len ? EM_OK : n ? EM_E_PARTIAL : EM_E_FAULT;
}

static em_status h_WRITE_MEM(em_stub *s, const uint8_t *req, uint32_t len)
{
    em_mem_req q;
    uint32_t   n;

    em_memcpy(&q, req, sizeof q);
    if (q.space > EM_SPACE_PHYS || !cpu_ok(s, q.cpu) || q.len != len - sizeof q)
        return EM_E_BADARG;
    n = mem_write(s, q.cpu, q.space, q.addr, req + sizeof q, q.len);
    return n == q.len ? EM_OK : n ? EM_E_PARTIAL : EM_E_FAULT;
}

static em_status h_TRANSLATE(em_stub *s, const uint8_t *req, uint32_t len)
{
    em_xlate_req q;
    em_xlate_rep r;
    em_status    st;

    (void)len;
    em_memcpy(&q, req, sizeof q);
    if (!cpu_ok(s, q.cpu))
        return EM_E_BADARG;
    em_memset(&r, 0, sizeof r);
    st = translate(s, q.cpu, q.vaddr, &r.paddr, &r.flags);
    if (st == EM_OK)
        reply(s, &r, sizeof r);
    return st;
}

static void set_resume(em_stub *s, em_resume_action action, uint16_t cpu)
{
    s->resume.action = action;
    s->resume.cpu = cpu;
    s->resume_set = 1;
}

static em_status h_CONTINUE(em_stub *s, const uint8_t *req, uint32_t len)
{
    (void)req;
    (void)len;
    set_resume(s, EM_RESUME_CONTINUE, 0);
    return EM_OK;
}

static em_status h_STEP(em_stub *s, const uint8_t *req, uint32_t len)
{
    em_step_req q;

    (void)len;
    em_memcpy(&q, req, sizeof q);
    if (!cpu_ok(s, q.cpu))
        return EM_E_BADARG;
    set_resume(s, EM_RESUME_STEP, q.cpu);
    return EM_OK;
}

static em_status h_PAUSE(em_stub *s, const uint8_t *req, uint32_t len)
{
    (void)req;
    (void)len;
    if (s->running)
        s->pause_req = 1;
    return EM_OK;
}

static em_status h_BP_SET(em_stub *s, const uint8_t *req, uint32_t len)
{
    em_bp_req q;
    em_bp_rep r;
    em_status st;

    (void)len;
    em_memcpy(&q, req, sizeof q);
    em_memset(&r, 0, sizeof r);
    st = s->ops->bp_set(s->user, &q, &r.id);
    if (st == EM_OK)
        reply(s, &r, sizeof r);
    return st;
}

static em_status h_BP_CLEAR(em_stub *s, const uint8_t *req, uint32_t len)
{
    em_bp_id q;

    (void)len;
    em_memcpy(&q, req, sizeof q);
    return s->ops->bp_clear(s->user, q.id);
}

static em_status h_READ_MSR(em_stub *s, const uint8_t *req, uint32_t len)
{
    em_msr    q;
    em_status st;

    (void)len;
    em_memcpy(&q, req, sizeof q);
    if (!cpu_ok(s, q.cpu))
        return EM_E_BADARG;
    st = s->ops->read_msr(s->user, q.cpu, q.index, &q.value);
    if (st == EM_OK)
        reply(s, &q, sizeof q);
    return st;
}

static em_status h_WRITE_MSR(em_stub *s, const uint8_t *req, uint32_t len)
{
    em_msr q;

    (void)len;
    em_memcpy(&q, req, sizeof q);
    if (!cpu_ok(s, q.cpu))
        return EM_E_BADARG;
    return s->ops->write_msr(s->user, q.cpu, q.index, q.value);
}

static em_status h_SNAP_SAVE(em_stub *s, const uint8_t *req, uint32_t len)
{
    em_name_req q;

    (void)len;
    em_memcpy(&q, req, sizeof q);
    q.name[sizeof q.name - 1] = '\0';
    return s->ops->snap_save(s->user, q.name);
}

static em_status h_SNAP_LOAD(em_stub *s, const uint8_t *req, uint32_t len)
{
    em_name_req q;

    (void)len;
    em_memcpy(&q, req, sizeof q);
    q.name[sizeof q.name - 1] = '\0';
    return s->ops->snap_load(s->user, q.name);
}

static em_status h_MONITOR(em_stub *s, const uint8_t *req, uint32_t len)
{
    const char *cmd = (const char *)req + sizeof(em_empty);
    uint32_t    cmd_len = len - (uint32_t)sizeof(em_empty);

    s->tx_len = s->ops->monitor(s->user, cmd, cmd_len, (char *)TX_PAYLOAD(s), tx_cap(s));
    return EM_OK;
}

/* --- dispatch ------------------------------------------------------------------------ */

static void set_command(em_stub *s, uint16_t id)
{
    s->commands[id / 64] |= 1ull << (id % 64);
}

static int command_supported(const em_stub *s, uint16_t id)
{
    return id < EM_CMD_ID_LIMIT && (s->commands[id / 64] & (1ull << (id % 64)));
}

static void compute_commands(em_stub *s)
{
    const em_stub_ops *o = s->ops;

    s->commands[0] = 0;
    s->commands[1] = 0;
    set_command(s, EM_CMD_HELLO);
    set_command(s, EM_CMD_GET_REGS);
    set_command(s, EM_CMD_SET_REGS);
    set_command(s, EM_CMD_READ_MEM);
    set_command(s, EM_CMD_WRITE_MEM);
    set_command(s, EM_CMD_CONTINUE);
    set_command(s, EM_CMD_STEP);
    set_command(s, EM_CMD_PAUSE);
    if (o->translate || (s->info.regblocks & EM_RB_BIT(EM_RB_X86_CTRL)))
        set_command(s, EM_CMD_TRANSLATE);
    if (o->bp_set && o->bp_clear) {
        set_command(s, EM_CMD_BP_SET);
        set_command(s, EM_CMD_BP_CLEAR);
    }
    if (o->read_msr)
        set_command(s, EM_CMD_READ_MSR);
    if (o->write_msr)
        set_command(s, EM_CMD_WRITE_MSR);
    if (o->snap_save)
        set_command(s, EM_CMD_SNAP_SAVE);
    if (o->snap_load)
        set_command(s, EM_CMD_SNAP_LOAD);
    if (o->monitor)
        set_command(s, EM_CMD_MONITOR);
}

/* Run the request in s->rx and send its reply. */
static void handle_packet(em_stub *s)
{
    em_hdr     h;
    em_handler fn;
    em_status  st;
    uint32_t   flags, fixed;

    em_memcpy(&h, s->rx, sizeof h);
    fn    = handler_for(h.type);
    flags = em_type_flags(h.type);
    fixed = em_req_size(h.type);
    s->tx_len = 0;

    if (!fn || !command_supported(s, h.type))
        st = EM_E_UNSUPPORTED;
    else if (h.len < fixed || (!(flags & EM_F_REQ_TAIL) && h.len != fixed))
        st = EM_E_BADARG;
    else if (s->running && !(flags & EM_F_RUNNING))
        st = EM_E_RUNNING;
    else {
        s->in_handler = 1;
        st = fn(s, RX_PAYLOAD(s), h.len);
        s->in_handler = 0;
    }

    /* A failed reply may be shorter than the fixed reply size; the debugger checks
     * status before reading the payload. */
    send_packet(s, h.type, EM_KIND_REPLY, st, h.seq, s->tx_len);
}

/* Serve every request that is already waiting, without blocking. */
static void service(em_stub *s)
{
    while (s->connected && recv_packet(s, 0) > 0)
        handle_packet(s);
}

static void send_stopped(em_stub *s, uint16_t cpu, em_stop_reason reason, uint32_t bp_id,
                         uint64_t addr)
{
    em_stopped ev;
    uint32_t   pos;

    ev.cpu      = cpu;
    ev.reason   = (uint8_t)reason;
    ev.reserved = 0;
    ev.bp_id    = bp_id;
    ev.addr     = addr;
    em_memcpy(TX_PAYLOAD(s), &ev, sizeof ev);
    pos = (uint32_t)sizeof ev;

    if (append_blocks(s, cpu, EM_RB_STOPPED_SET & s->info.regblocks, TX_PAYLOAD(s), tx_cap(s),
                      &pos) != EM_OK)
        pos = (uint32_t)sizeof ev;   /* registers unavailable: the debugger asks with GET_REGS */
    send_packet(s, EM_EV_STOPPED, EM_KIND_EVENT, EM_OK, 0, pos);
}

/* --- public API ---------------------------------------------------------------------- */

void em_stub_init(em_stub *s, const em_stub_ops *ops, void *user, const em_stub_info *info)
{
    em_memset(s, 0, sizeof *s);
    s->ops      = ops;
    s->user     = user;
    s->info     = *info;
    s->peer_max = EM_MIN_PAYLOAD;
    compute_commands(s);
}

void em_stub_reset(em_stub *s, int running)
{
    s->connected    = 1;
    s->running      = (uint8_t)(running != 0);
    s->pause_req    = 0;
    s->in_handler   = 0;
    s->resume_set   = 0;
    s->rx_have      = 0;
    s->peer_max     = EM_MIN_PAYLOAD;
}

int em_stub_connected(const em_stub *s)
{
    return s->connected;
}

em_run em_stub_poll(em_stub *s)
{
    if (!s->connected)
        return EM_RUN_CONTINUE;
    service(s);
    if (s->pause_req) {
        s->pause_req = 0;
        return EM_RUN_STOP;
    }
    return EM_RUN_CONTINUE;
}

em_resume em_stub_stopped(em_stub *s, uint16_t cpu, em_stop_reason reason, uint32_t bp_id,
                          uint64_t addr)
{
    em_resume detach;

    detach.action = EM_RESUME_DETACH;
    detach.cpu = cpu;
    if (!s->connected)
        return detach;

    s->running    = 0;
    s->pause_req  = 0;
    s->resume_set = 0;

    send_stopped(s, cpu, reason, bp_id, addr);
    while (s->connected && !s->resume_set) {
        if (recv_packet(s, 1) > 0)
            handle_packet(s);
    }
    if (!s->connected)
        return detach;

    s->running = 1;
    return s->resume;
}

int em_stub_output(em_stub *s, const char *text, uint32_t len)
{
    if (!s->connected || s->in_handler)
        return -1;
    len = em_min(len, tx_cap(s));
    em_memcpy(TX_PAYLOAD(s), text, len);
    return send_packet(s, EM_EV_OUTPUT, EM_KIND_EVENT, EM_OK, 0, len);
}
