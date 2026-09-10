"""
emutest.py -- verification harness (NOT part of the shipped compiler).

Loads the compiled program's .text/.rdata/.idata/.data bytes straight
into a Unicorn CPU emulator and runs it, with small Python stubs
standing in for GetStdHandle/ReadFile/WriteFile/FlushFileBuffers/
ExitProcess. This lets us check that the *instructions themselves* do
what the FALSE program says, completely independent of whether the
sandbox's Wine install can successfully run a real Windows process.
"""
import struct
import sys
from unicorn import *
from unicorn.x86_const import *

from falsec import FalseCompiler
from runtime import Runtime, IMPORTS
from pe_writer import IMAGE_BASE

PAGE = 0x1000
STACK_BASE = 0x00007FF000000000
STACK_SIZE = 1 << 20
STUB_BASE = 0x0000150000000000


def _align_up(n, a):
    return (n + a - 1) // a * a


def run_false_program(source_bytes, stdin_bytes=b"", max_instructions=0, trace=False):
    rt = Runtime()
    compiler = FalseCompiler(rt, source_bytes)
    compiler.compile_program()
    rt.asm.resolve_local_fixups()
    rt.text.buf = rt.asm.buf
    rt.pe.add_text_fixups("text", rt.asm)
    rt._build_pdata_xdata()
    rt.pe.set_entry("text", rt.start_label.offset)

    # Reuse the real PE layout algorithm so addresses match production exactly.
    order = [n for n in ("text", "rdata", "pdata", "xdata", "idata", "data") if n in rt.pe.regions]
    layout = {}
    rva = 0x1000
    for name in order:
        r = rt.pe.regions[name]
        virt_size = len(r.buf) + r.extra_virtual
        layout[name] = rva
        rva += _align_up(max(virt_size, 1), PAGE)

    for patch_region, patch_off, kind, target_region, target_key, instr_end_off in rt.pe.fixups:
        tgt = IMAGE_BASE + layout[target_region] + rt.pe.regions[target_region].symtab[target_key]
        buf = rt.pe.regions[patch_region].buf
        if kind == "riprel":
            instr_end_va = IMAGE_BASE + layout[patch_region] + instr_end_off
            struct.pack_into("<i", buf, patch_off, tgt - instr_end_va)
        else:
            struct.pack_into("<I", buf, patch_off, tgt & 0xFFFFFFFF)

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    for name in order:
        r = rt.pe.regions[name]
        base = IMAGE_BASE + layout[name]
        size = _align_up(max(len(r.buf) + r.extra_virtual, 1), PAGE)
        uc.mem_map(base, size)
        if r.buf:
            uc.mem_write(base, bytes(r.buf))

    uc.mem_map(STACK_BASE, STACK_SIZE)
    uc.reg_write(UC_X86_REG_RSP, STACK_BASE + STACK_SIZE - 0x1000)

    uc.mem_map(STUB_BASE, PAGE)
    uc.mem_write(STUB_BASE, b"\xc3" * 0x100)

    iat = rt.pe.regions["idata"]
    func_order = [f for funcs in IMPORTS.values() for f in funcs]
    stub_addr = {}
    for i, fn in enumerate(func_order):
        slot_off = iat.symtab[("iat", fn)]
        addr = STUB_BASE + i * 16
        stub_addr[fn] = addr
        struct.pack_into("<Q", iat.buf, slot_off, addr)
    # re-write patched idata into emulator memory (IAT slots changed above)
    uc.mem_write(IMAGE_BASE + layout["idata"], bytes(iat.buf))

    output = bytearray()
    stdin_pos = [0]
    exit_code = [None]
    messagebox_calls = []
    handles = {-11 & 0xFFFFFFFFFFFFFFFF: 1, -10 & 0xFFFFFFFFFFFFFFFF: 2}

    def do_ret(uc):
        rsp = uc.reg_read(UC_X86_REG_RSP)
        ret_addr = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret_addr)

    def hook_code(uc, address, size, user_data):
        if address == stub_addr["GetStdHandle"]:
            n = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFFFFFFFFFF
            uc.reg_write(UC_X86_REG_RAX, handles.get(n, 0))
            do_ret(uc)
        elif address == stub_addr["WriteFile"]:
            ptr = uc.reg_read(UC_X86_REG_RDX)
            n = uc.reg_read(UC_X86_REG_R8) & 0xFFFFFFFF
            data = uc.mem_read(ptr, n)
            output.extend(data)
            lp_written = uc.reg_read(UC_X86_REG_R9)
            if lp_written:
                uc.mem_write(lp_written, struct.pack("<I", n))
            uc.reg_write(UC_X86_REG_RAX, 1)
            do_ret(uc)
        elif address == stub_addr["ReadFile"]:
            ptr = uc.reg_read(UC_X86_REG_RDX)
            maxlen = uc.reg_read(UC_X86_REG_R8) & 0xFFFFFFFF
            chunk = stdin_bytes[stdin_pos[0]: stdin_pos[0] + maxlen]
            stdin_pos[0] += len(chunk)
            uc.mem_write(ptr, chunk)
            lp_read = uc.reg_read(UC_X86_REG_R9)
            if lp_read:
                uc.mem_write(lp_read, struct.pack("<I", len(chunk)))
            uc.reg_write(UC_X86_REG_RAX, 1)
            do_ret(uc)
        elif address == stub_addr["FlushFileBuffers"]:
            uc.reg_write(UC_X86_REG_RAX, 1)
            do_ret(uc)
        elif "MessageBoxW" in stub_addr and address == stub_addr["MessageBoxW"]:
            text_ptr = uc.reg_read(UC_X86_REG_RDX)
            caption_ptr = uc.reg_read(UC_X86_REG_R8)

            def read_wstr(ptr):
                if ptr == 0:
                    return ""
                raw = bytearray()
                off = 0
                while True:
                    ch = uc.mem_read(ptr + off, 2)
                    if ch == b"\x00\x00":
                        break
                    raw += ch
                    off += 2
                return raw.decode("utf-16-le")

            messagebox_calls.append((read_wstr(caption_ptr), read_wstr(text_ptr)))
            uc.reg_write(UC_X86_REG_RAX, 1)  # IDOK
            do_ret(uc)
        elif address == stub_addr["ExitProcess"]:
            exit_code[0] = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
            uc.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook_code, begin=STUB_BASE, end=STUB_BASE + 0x100)

    if trace:
        def trace_hook(uc, address, size, user_data):
            print(f"  0x{address:x}")
        uc.hook_add(UC_HOOK_CODE, trace_hook,
                    begin=IMAGE_BASE, end=IMAGE_BASE + 0x10000000)

    start = IMAGE_BASE + layout["text"] + rt.start_label.offset
    try:
        uc.emu_start(start, 0, count=max_instructions)
    except UcError as e:
        rip = uc.reg_read(UC_X86_REG_RIP)
        print(f"EMULATION ERROR at rip=0x{rip:x}: {e}", file=sys.stderr)
        raise
    return bytes(output), exit_code[0], messagebox_calls


if __name__ == "__main__":
    path = sys.argv[1]
    stdin_data = sys.stdin.buffer.read() if not sys.stdin.isatty() else b""
    with open(path, "rb") as f:
        src = f.read()
    out, code, msgboxes = run_false_program(src, stdin_bytes=stdin_data)
    sys.stdout.buffer.write(out)
    for caption, text in msgboxes:
        print(f"\n[MessageBoxW  caption={caption!r}  text={text!r}]", file=sys.stderr)
    print(f"\n[exit code: {code}]", file=sys.stderr)
