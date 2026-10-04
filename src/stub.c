#include "emstub/stub.h"

EM_STATIC_ASSERT(EM_STUB_MAX_PAYLOAD >= EM_MIN_PAYLOAD, "EM_STUB_MAX_PAYLOAD too small");
EM_STATIC_ASSERT(EM_STUB_MAX_PAYLOAD >= sizeof(em_stopped) + 3 * sizeof(em_rb_hdr) +
                 sizeof(em_x86_core) + sizeof(em_x86_segs) + sizeof(em_x86_ctrl),
                 "STOPPED event must fit in one payload");

#define TX_PAYLOAD(stub)  ((stub)->tx + sizeof(em_hdr))
#define RX_PAYLOAD(stub)  ((stub)->rx + sizeof(em_hdr))

static void em_memcpy(void *dst, const void *src, uint32_t count)
{
    uint8_t              *dst_bytes;
    const uint8_t        *src_bytes;

    dst_bytes = (uint8_t *)dst;
    src_bytes = (const uint8_t *)src;
    while (count--)
        *dst_bytes++ = *src_bytes++;
}

static void em_memset(void *dst, uint8_t value, uint32_t count)
{
    uint8_t              *dst_bytes;

    dst_bytes = (uint8_t *)dst;
    while (count--)
        *dst_bytes++ = value;
}

static uint32_t em_min(uint32_t first, uint32_t second)
{
    return first < second ? first : second;
}

static void drop_connection(em_stub *stub)
{
    stub->connected = 0;
    stub->rx_have = 0;
}

static uint32_t tx_cap(const em_stub *stub)
{
    return em_min(EM_STUB_MAX_PAYLOAD, stub->peer_max);
}

static int send_packet(em_stub *stub, uint16_t type, em_kind kind, em_status status, uint32_t seq,
                       uint32_t len)
{
    em_hdr               header;

    header.magic  = EM_MAGIC;
    header.type   = type;
    header.kind   = (uint8_t)kind;
    header.status = (uint8_t)status;
    header.seq    = seq;
    header.len    = len;
    header.crc    = len ? em_crc32(0, TX_PAYLOAD(stub), len) : 0;
    em_memcpy(stub->tx, &header, sizeof header);

    if (stub->ops->send(stub->user, stub->tx, (uint32_t)sizeof header + len) < 0) {
        drop_connection(stub);
        return -1;
    }
    return 0;
}

static int recv_packet(em_stub *stub, int block)
{
    em_hdr               header;
    uint32_t             needed;
    int32_t              received;

    for (;;) {
        needed = (uint32_t)sizeof header;
        if (stub->rx_have >= sizeof header) {
            em_memcpy(&header, stub->rx, sizeof header);
            if (header.magic != EM_MAGIC || header.kind != EM_KIND_REQ ||
                header.len > EM_STUB_MAX_PAYLOAD) {
                drop_connection(stub);
                return -1;
            }
            needed += header.len;
            if (stub->rx_have == needed) {
                stub->rx_have = 0;
                if (header.len && em_crc32(0, RX_PAYLOAD(stub), header.len) != header.crc) {
                    drop_connection(stub);
                    return -1;
                }
                return 1;
            }
        }

        received = stub->ops->recv(stub->user, stub->rx + stub->rx_have, needed - stub->rx_have,
                                   block);
        if (received < 0) {
            drop_connection(stub);
            return -1;
        }
        if (received == 0 && !block)
            return 0;
        stub->rx_have += (uint32_t)received;
    }
}

#define X86_CR0_PG    (1ull << 31)
#define X86_CR4_PSE   (1ull << 4)
#define X86_CR4_PAE   (1ull << 5)
#define X86_EFER_LMA  (1ull << 10)
#define X86_PTE_P     (1ull << 0)
#define X86_PTE_RW    (1ull << 1)
#define X86_PTE_US    (1ull << 2)
#define X86_PTE_PS    (1ull << 7)
#define X86_PTE_NX    (1ull << 63)

static em_status walk_x86(em_stub *stub, uint16_t cpu, uint64_t va, uint64_t *pa, uint32_t *flags)
{
    static const uint8_t long_shift[]   = { 39, 30, 21, 12 };
    static const uint8_t long_bits[]    = { 9, 9, 9, 9 };
    static const uint8_t pae_shift[]    = { 30, 21, 12 };
    static const uint8_t pae_bits[]     = { 2, 9, 9 };
    static const uint8_t legacy_shift[] = { 22, 12 };
    static const uint8_t legacy_bits[]  = { 10, 10 };
    const uint8_t        *level_shift;
    const uint8_t        *level_bits;
    em_x86_ctrl          ctrl_regs;
    uint64_t             table;
    uint64_t             entry;
    uint64_t             addr_mask;
    uint64_t             table_index;
    uint64_t             page_size;
    uint32_t             entry_size;
    uint32_t             entry32;
    uint32_t             xlate_flags;
    int                  level_count;
    int                  level;
    int                  is_large;

    if (stub->ops->get_regs(stub->user, cpu, EM_RB_X86_CTRL, &ctrl_regs, sizeof ctrl_regs) !=
        (int32_t)sizeof ctrl_regs)
        return EM_E_UNSUPPORTED;

    xlate_flags = EM_XLATE_WRITABLE | EM_XLATE_USER;
    if (!(ctrl_regs.cr0 & X86_CR0_PG)) {
        *pa = va;
        *flags = xlate_flags;
        return EM_OK;
    }

    if (ctrl_regs.efer & X86_EFER_LMA) {
        level_shift = long_shift;
        level_bits = long_bits;
        level_count = 4;
        entry_size = 8;
        addr_mask = 0x000FFFFFFFFFF000ull;
        table = ctrl_regs.cr3 & addr_mask;
    } else if (ctrl_regs.cr4 & X86_CR4_PAE) {
        level_shift = pae_shift;
        level_bits = pae_bits;
        level_count = 3;
        entry_size = 8;
        addr_mask = 0x000FFFFFFFFFF000ull;
        table = ctrl_regs.cr3 & 0xFFFFFFE0ull;
        va &= 0xFFFFFFFFull;
    } else {
        level_shift = legacy_shift;
        level_bits = legacy_bits;
        level_count = 2;
        entry_size = 4;
        addr_mask = 0xFFFFF000ull;
        table = ctrl_regs.cr3 & addr_mask;
        va &= 0xFFFFFFFFull;
    }

    for (level = 0; level < level_count; level++) {
        table_index = (va >> level_shift[level]) & ((1ull << level_bits[level]) - 1);
        entry = 0;
        if (entry_size == 8) {
            if (stub->ops->read_phys(stub->user, cpu, table + table_index * 8, &entry, 8) != 8)
                return EM_E_FAULT;
        } else {
            entry32 = 0;
            if (stub->ops->read_phys(stub->user, cpu, table + table_index * 4, &entry32, 4) != 4)
                return EM_E_FAULT;
            entry = entry32;
        }
        if (!(entry & X86_PTE_P))
            return EM_E_FAULT;

        if (!(level_count == 3 && level == 0)) {
            if (!(entry & X86_PTE_RW))
                xlate_flags &= ~EM_XLATE_WRITABLE;
            if (!(entry & X86_PTE_US))
                xlate_flags &= ~EM_XLATE_USER;
            if (entry_size == 8 && (entry & X86_PTE_NX))
                xlate_flags |= EM_XLATE_NX;
        }

        is_large = level < level_count - 1 && (entry & X86_PTE_PS) &&
                   ((level_count == 4 && level >= 1) || (level_count == 3 && level == 1) ||
                    (level_count == 2 && (ctrl_regs.cr4 & X86_CR4_PSE)));
        if (is_large) {
            page_size = 1ull << level_shift[level];
            *pa = (entry & addr_mask & ~(page_size - 1)) + (va & (page_size - 1));
            *flags = xlate_flags | (level_shift[level] == 30 ? EM_XLATE_HUGE : EM_XLATE_LARGE);
            return EM_OK;
        }
        table = entry & addr_mask;
    }

    *pa = table + (va & 0xFFFu);
    *flags = xlate_flags;
    return EM_OK;
}

static em_status translate(em_stub *stub, uint16_t cpu, uint64_t va, uint64_t *pa, uint32_t *flags)
{
    if (stub->ops->translate)
        return stub->ops->translate(stub->user, cpu, va, pa, flags);
    if (stub->info.regblocks & EM_RB_BIT(EM_RB_X86_CTRL))
        return walk_x86(stub, cpu, va, pa, flags);
    return EM_E_UNSUPPORTED;
}

static uint32_t page_chunk(uint64_t addr, uint32_t remaining)
{
    uint32_t             chunk;

    chunk = 0x1000u - (uint32_t)(addr & 0xFFFu);
    return em_min(chunk, remaining);
}

static uint32_t mem_read(em_stub *stub, uint16_t cpu, uint8_t space, uint64_t addr, uint8_t *buf,
                         uint32_t len)
{
    uint64_t             phys_addr;
    uint32_t             bytes_done;
    uint32_t             chunk;
    uint32_t             bytes_read;
    uint32_t             xlate_flags;

    if (space == EM_SPACE_PHYS)
        return stub->ops->read_phys(stub->user, cpu, addr, buf, len);
    if (stub->ops->read_virt)
        return stub->ops->read_virt(stub->user, cpu, addr, buf, len);

    bytes_done = 0;
    while (bytes_done < len) {
        chunk = page_chunk(addr + bytes_done, len - bytes_done);
        if (translate(stub, cpu, addr + bytes_done, &phys_addr, &xlate_flags) != EM_OK)
            break;
        bytes_read = stub->ops->read_phys(stub->user, cpu, phys_addr, buf + bytes_done, chunk);
        bytes_done += bytes_read;
        if (bytes_read != chunk)
            break;
    }
    return bytes_done;
}

static uint32_t mem_write(em_stub *stub, uint16_t cpu, uint8_t space, uint64_t addr,
                          const uint8_t *buf, uint32_t len)
{
    uint64_t             phys_addr;
    uint32_t             bytes_done;
    uint32_t             chunk;
    uint32_t             bytes_written;
    uint32_t             xlate_flags;

    if (space == EM_SPACE_PHYS)
        return stub->ops->write_phys(stub->user, cpu, addr, buf, len);
    if (stub->ops->write_virt)
        return stub->ops->write_virt(stub->user, cpu, addr, buf, len);

    bytes_done = 0;
    while (bytes_done < len) {
        chunk = page_chunk(addr + bytes_done, len - bytes_done);
        if (translate(stub, cpu, addr + bytes_done, &phys_addr, &xlate_flags) != EM_OK)
            break;
        bytes_written = stub->ops->write_phys(stub->user, cpu, phys_addr, buf + bytes_done, chunk);
        bytes_done += bytes_written;
        if (bytes_written != chunk)
            break;
    }
    return bytes_done;
}

static em_status append_blocks(em_stub *stub, uint16_t cpu, uint32_t blocks, uint8_t *out,
                               uint32_t cap, uint32_t *pos)
{
    em_rb_hdr            block_hdr;
    uint32_t             block_id;
    int32_t              block_size;

    for (block_id = 0; block_id < 32; block_id++) {
        if (!(blocks & EM_RB_BIT(block_id)))
            continue;
        if (*pos + sizeof block_hdr > cap)
            return EM_E_BADARG;
        block_size = stub->ops->get_regs(stub->user, cpu, block_id, out + *pos + sizeof block_hdr,
                                         cap - *pos - (uint32_t)sizeof block_hdr);
        if (block_size < 0)
            return (em_status)-block_size;
        block_hdr.id = (uint16_t)block_id;
        block_hdr.reserved = 0;
        block_hdr.size = (uint32_t)block_size;
        em_memcpy(out + *pos, &block_hdr, sizeof block_hdr);
        *pos += (uint32_t)sizeof block_hdr + (uint32_t)block_size;
    }
    return EM_OK;
}

static em_status set_block(em_stub *stub, uint16_t cpu, uint32_t block_id, const uint8_t *data,
                           uint32_t size)
{
    uint32_t             local_size;
    int32_t              result;

    local_size = em_x86_rb_size(block_id);
    if (!local_size || !(stub->info.regblocks & EM_RB_BIT(block_id)))
        return EM_E_UNSUPPORTED;
    if (size < local_size) {
        result = stub->ops->get_regs(stub->user, cpu, block_id, stub->scratch, local_size);
        if (result < 0)
            return (em_status)-result;
    }
    em_memcpy(stub->scratch, data, em_min(size, local_size));
    return stub->ops->set_regs(stub->user, cpu, block_id, stub->scratch, local_size);
}

typedef em_status (*em_handler)(em_stub *stub, const uint8_t *req, uint32_t len);

#define EM_X(name, id, request_type, reply_type, flags) \
    static em_status h_##name(em_stub *, const uint8_t *, uint32_t);
EM_COMMANDS(EM_X)
#undef EM_X

static em_handler handler_for(uint16_t type)
{
    switch (type) {
#define EM_X(name, id, request_type, reply_type, flags) \
        case id:                                        \
            return h_##name;
        EM_COMMANDS(EM_X)
#undef EM_X
    }
    return NULL;
}

static int cpu_ok(const em_stub *stub, uint16_t cpu)
{
    return cpu < stub->info.cpu_count;
}

static void reply(em_stub *stub, const void *data, uint32_t len)
{
    em_memcpy(TX_PAYLOAD(stub), data, len);
    stub->tx_len = len;
}

static em_status h_HELLO(em_stub *stub, const uint8_t *req, uint32_t len)
{
    em_hello_req         hello_req;
    em_hello_rep         hello_rep;
    uint32_t             char_index;

    (void)len;
    em_memcpy(&hello_req, req, sizeof hello_req);
    stub->peer_max = hello_req.max_payload < EM_MIN_PAYLOAD ? EM_MIN_PAYLOAD : hello_req.max_payload;

    em_memset(&hello_rep, 0, sizeof hello_rep);
    hello_rep.version     = EM_PROTO_VERSION;
    hello_rep.max_payload = EM_STUB_MAX_PAYLOAD;
    hello_rep.commands[0] = stub->commands[0];
    hello_rep.commands[1] = stub->commands[1];
    hello_rep.features    = stub->info.features;
    hello_rep.regblocks   = stub->info.regblocks;
    hello_rep.arch        = EM_ARCH_X86;
    hello_rep.cpu_count   = stub->info.cpu_count;
    for (char_index = 0; stub->info.target && stub->info.target[char_index] &&
         char_index < sizeof hello_rep.target - 1; char_index++)
        hello_rep.target[char_index] = stub->info.target[char_index];
    reply(stub, &hello_rep, sizeof hello_rep);
    return EM_OK;
}

static em_status h_GET_REGS(em_stub *stub, const uint8_t *req, uint32_t len)
{
    em_regs_req          regs_req;
    uint32_t             payload_pos;
    em_status            status;

    (void)len;
    em_memcpy(&regs_req, req, sizeof regs_req);
    if (!cpu_ok(stub, regs_req.cpu))
        return EM_E_BADARG;
    payload_pos = 0;
    status = append_blocks(stub, regs_req.cpu, regs_req.blocks & stub->info.regblocks,
                           TX_PAYLOAD(stub), tx_cap(stub), &payload_pos);
    stub->tx_len = payload_pos;
    return status;
}

static em_status h_SET_REGS(em_stub *stub, const uint8_t *req, uint32_t len)
{
    em_regs_req          regs_req;
    em_rb_hdr            block_hdr;
    uint32_t             payload_pos;
    em_status            status;

    em_memcpy(&regs_req, req, sizeof regs_req);
    if (!cpu_ok(stub, regs_req.cpu))
        return EM_E_BADARG;
    for (payload_pos = sizeof regs_req; payload_pos + sizeof block_hdr <= len;
         payload_pos += block_hdr.size) {
        em_memcpy(&block_hdr, req + payload_pos, sizeof block_hdr);
        payload_pos += (uint32_t)sizeof block_hdr;
        if (block_hdr.size > len - payload_pos)
            return EM_E_BADARG;
        status = set_block(stub, regs_req.cpu, block_hdr.id, req + payload_pos, block_hdr.size);
        if (status != EM_OK)
            return status;
    }
    return EM_OK;
}

static em_status h_READ_MEM(em_stub *stub, const uint8_t *req, uint32_t len)
{
    em_mem_req           mem_req;
    uint32_t             bytes_read;

    (void)len;
    em_memcpy(&mem_req, req, sizeof mem_req);
    if (mem_req.space > EM_SPACE_PHYS || !cpu_ok(stub, mem_req.cpu) || mem_req.len > tx_cap(stub))
        return EM_E_BADARG;
    bytes_read = mem_read(stub, mem_req.cpu, mem_req.space, mem_req.addr, TX_PAYLOAD(stub),
                          mem_req.len);
    stub->tx_len = bytes_read;
    return bytes_read == mem_req.len ? EM_OK : bytes_read ? EM_E_PARTIAL : EM_E_FAULT;
}

static em_status h_WRITE_MEM(em_stub *stub, const uint8_t *req, uint32_t len)
{
    em_mem_req           mem_req;
    uint32_t             bytes_written;

    em_memcpy(&mem_req, req, sizeof mem_req);
    if (mem_req.space > EM_SPACE_PHYS || !cpu_ok(stub, mem_req.cpu) ||
        mem_req.len != len - sizeof mem_req)
        return EM_E_BADARG;
    bytes_written = mem_write(stub, mem_req.cpu, mem_req.space, mem_req.addr,
                              req + sizeof mem_req, mem_req.len);
    return bytes_written == mem_req.len ? EM_OK : bytes_written ? EM_E_PARTIAL : EM_E_FAULT;
}

static em_status h_TRANSLATE(em_stub *stub, const uint8_t *req, uint32_t len)
{
    em_xlate_req         xlate_req;
    em_xlate_rep         xlate_rep;
    em_status            status;

    (void)len;
    em_memcpy(&xlate_req, req, sizeof xlate_req);
    if (!cpu_ok(stub, xlate_req.cpu))
        return EM_E_BADARG;
    em_memset(&xlate_rep, 0, sizeof xlate_rep);
    status = translate(stub, xlate_req.cpu, xlate_req.vaddr, &xlate_rep.paddr, &xlate_rep.flags);
    if (status == EM_OK)
        reply(stub, &xlate_rep, sizeof xlate_rep);
    return status;
}

static void set_resume(em_stub *stub, em_resume_action action, uint16_t cpu)
{
    stub->resume.action = action;
    stub->resume.cpu = cpu;
    stub->resume_set = 1;
}

static em_status h_CONTINUE(em_stub *stub, const uint8_t *req, uint32_t len)
{
    (void)req;
    (void)len;
    set_resume(stub, EM_RESUME_CONTINUE, 0);
    return EM_OK;
}

static em_status h_STEP(em_stub *stub, const uint8_t *req, uint32_t len)
{
    em_step_req          step_req;

    (void)len;
    em_memcpy(&step_req, req, sizeof step_req);
    if (!cpu_ok(stub, step_req.cpu))
        return EM_E_BADARG;
    set_resume(stub, EM_RESUME_STEP, step_req.cpu);
    return EM_OK;
}

static em_status h_PAUSE(em_stub *stub, const uint8_t *req, uint32_t len)
{
    (void)req;
    (void)len;
    if (stub->running)
        stub->pause_req = 1;
    return EM_OK;
}

static em_status h_BP_SET(em_stub *stub, const uint8_t *req, uint32_t len)
{
    em_bp_req            bp_req;
    em_bp_rep            bp_rep;
    em_status            status;

    (void)len;
    em_memcpy(&bp_req, req, sizeof bp_req);
    em_memset(&bp_rep, 0, sizeof bp_rep);
    status = stub->ops->bp_set(stub->user, &bp_req);
    if (status == EM_OK)
        reply(stub, &bp_rep, sizeof bp_rep);
    return status;
}

static em_status h_BP_CLEAR(em_stub *stub, const uint8_t *req, uint32_t len)
{
    em_bp_req            bp_req;

    (void)len;
    em_memcpy(&bp_req, req, sizeof bp_req);
    return stub->ops->bp_clear(stub->user, &bp_req);
}

static em_status h_READ_MSR(em_stub *stub, const uint8_t *req, uint32_t len)
{
    em_msr               msr;
    em_status            status;

    (void)len;
    em_memcpy(&msr, req, sizeof msr);
    if (!cpu_ok(stub, msr.cpu))
        return EM_E_BADARG;
    status = stub->ops->read_msr(stub->user, msr.cpu, msr.index, &msr.value);
    if (status == EM_OK)
        reply(stub, &msr, sizeof msr);
    return status;
}

static em_status h_WRITE_MSR(em_stub *stub, const uint8_t *req, uint32_t len)
{
    em_msr               msr;

    (void)len;
    em_memcpy(&msr, req, sizeof msr);
    if (!cpu_ok(stub, msr.cpu))
        return EM_E_BADARG;
    return stub->ops->write_msr(stub->user, msr.cpu, msr.index, msr.value);
}

static em_status h_SNAP_SAVE(em_stub *stub, const uint8_t *req, uint32_t len)
{
    em_name_req          name_req;

    (void)len;
    em_memcpy(&name_req, req, sizeof name_req);
    name_req.name[sizeof name_req.name - 1] = '\0';
    return stub->ops->snap_save(stub->user, name_req.name);
}

static em_status h_SNAP_LOAD(em_stub *stub, const uint8_t *req, uint32_t len)
{
    em_name_req          name_req;

    (void)len;
    em_memcpy(&name_req, req, sizeof name_req);
    name_req.name[sizeof name_req.name - 1] = '\0';
    return stub->ops->snap_load(stub->user, name_req.name);
}

static em_status h_MONITOR(em_stub *stub, const uint8_t *req, uint32_t len)
{
    const char           *command;
    uint32_t             command_len;

    command = (const char *)req + sizeof(em_empty);
    command_len = len - (uint32_t)sizeof(em_empty);
    stub->tx_len = stub->ops->monitor(stub->user, command, command_len, (char *)TX_PAYLOAD(stub),
                                      tx_cap(stub));
    return EM_OK;
}

static void set_command(em_stub *stub, uint16_t command_id)
{
    stub->commands[command_id / 64] |= 1ull << (command_id % 64);
}

static int command_supported(const em_stub *stub, uint16_t command_id)
{
    return command_id < EM_CMD_ID_LIMIT &&
           (stub->commands[command_id / 64] & (1ull << (command_id % 64)));
}

static void compute_commands(em_stub *stub)
{
    const em_stub_ops    *ops;

    ops = stub->ops;
    stub->commands[0] = 0;
    stub->commands[1] = 0;
    set_command(stub, EM_CMD_HELLO);
    set_command(stub, EM_CMD_GET_REGS);
    set_command(stub, EM_CMD_SET_REGS);
    set_command(stub, EM_CMD_READ_MEM);
    set_command(stub, EM_CMD_WRITE_MEM);
    set_command(stub, EM_CMD_CONTINUE);
    set_command(stub, EM_CMD_STEP);
    set_command(stub, EM_CMD_PAUSE);
    if (ops->translate || (stub->info.regblocks & EM_RB_BIT(EM_RB_X86_CTRL)))
        set_command(stub, EM_CMD_TRANSLATE);
    if (ops->bp_set && ops->bp_clear) {
        set_command(stub, EM_CMD_BP_SET);
        set_command(stub, EM_CMD_BP_CLEAR);
    }
    if (ops->read_msr)
        set_command(stub, EM_CMD_READ_MSR);
    if (ops->write_msr)
        set_command(stub, EM_CMD_WRITE_MSR);
    if (ops->snap_save)
        set_command(stub, EM_CMD_SNAP_SAVE);
    if (ops->snap_load)
        set_command(stub, EM_CMD_SNAP_LOAD);
    if (ops->monitor)
        set_command(stub, EM_CMD_MONITOR);
}

static void handle_packet(em_stub *stub)
{
    em_hdr               header;
    em_handler           handler;
    em_status            status;
    uint32_t             type_flags;
    uint32_t             fixed_size;

    em_memcpy(&header, stub->rx, sizeof header);
    handler    = handler_for(header.type);
    type_flags = em_type_flags(header.type);
    fixed_size = em_req_size(header.type);
    stub->tx_len = 0;

    if (!handler || !command_supported(stub, header.type))
        status = EM_E_UNSUPPORTED;
    else if (header.len < fixed_size || (!(type_flags & EM_F_REQ_TAIL) && header.len != fixed_size))
        status = EM_E_BADARG;
    else if (stub->running && !(type_flags & EM_F_RUNNING))
        status = EM_E_RUNNING;
    else {
        stub->in_handler = 1;
        status = handler(stub, RX_PAYLOAD(stub), header.len);
        stub->in_handler = 0;
    }

    send_packet(stub, header.type, EM_KIND_REPLY, status, header.seq, stub->tx_len);
}

static void service(em_stub *stub)
{
    while (stub->connected && recv_packet(stub, 0) > 0)
        handle_packet(stub);
}

static void send_stopped(em_stub *stub, uint16_t cpu, em_stop_reason reason, uint32_t bp_id,
                         uint64_t addr)
{
    em_stopped           stopped_event;
    uint32_t             payload_pos;

    stopped_event.cpu      = cpu;
    stopped_event.reason   = (uint8_t)reason;
    stopped_event.reserved = 0;
    stopped_event.bp_id    = bp_id;
    stopped_event.addr     = addr;
    em_memcpy(TX_PAYLOAD(stub), &stopped_event, sizeof stopped_event);
    payload_pos = (uint32_t)sizeof stopped_event;

    if (append_blocks(stub, cpu, EM_RB_STOPPED_SET & stub->info.regblocks, TX_PAYLOAD(stub),
                      tx_cap(stub), &payload_pos) != EM_OK)
        payload_pos = (uint32_t)sizeof stopped_event;
    send_packet(stub, EM_EV_STOPPED, EM_KIND_EVENT, EM_OK, 0, payload_pos);
}

void em_stub_init(em_stub *stub, const em_stub_ops *ops, void *user, const em_stub_info *info)
{
    em_memset(stub, 0, sizeof *stub);
    stub->ops      = ops;
    stub->user     = user;
    stub->info     = *info;
    stub->peer_max = EM_MIN_PAYLOAD;
    compute_commands(stub);
}

void em_stub_reset(em_stub *stub, int running)
{
    stub->connected    = 1;
    stub->running      = (uint8_t)(running != 0);
    stub->pause_req    = 0;
    stub->in_handler   = 0;
    stub->resume_set   = 0;
    stub->rx_have      = 0;
    stub->peer_max     = EM_MIN_PAYLOAD;
}

int em_stub_connected(const em_stub *stub)
{
    return stub->connected;
}

em_run em_stub_poll(em_stub *stub)
{
    if (!stub->connected)
        return EM_RUN_CONTINUE;
    service(stub);
    if (stub->pause_req) {
        stub->pause_req = 0;
        return EM_RUN_STOP;
    }
    return EM_RUN_CONTINUE;
}

em_resume em_stub_stopped(em_stub *stub, uint16_t cpu, em_stop_reason reason, uint32_t bp_id,
                          uint64_t addr)
{
    em_resume            detach_resume;

    detach_resume.action = EM_RESUME_DETACH;
    detach_resume.cpu = cpu;
    if (!stub->connected)
        return detach_resume;

    stub->running    = 0;
    stub->pause_req  = 0;
    stub->resume_set = 0;

    send_stopped(stub, cpu, reason, bp_id, addr);
    while (stub->connected && !stub->resume_set) {
        if (recv_packet(stub, 1) > 0)
            handle_packet(stub);
    }
    if (!stub->connected)
        return detach_resume;

    stub->running = 1;
    return stub->resume;
}

int em_stub_output(em_stub *stub, const char *text, uint32_t len)
{
    if (!stub->connected || stub->in_handler)
        return -1;
    len = em_min(len, tx_cap(stub));
    em_memcpy(TX_PAYLOAD(stub), text, len);
    return send_packet(stub, EM_EV_OUTPUT, EM_KIND_EVENT, EM_OK, 0, len);
}
