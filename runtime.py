"""
runtime.py -- builds the fixed runtime that every compiled FALSE
program links against: the kernel32 import table, the data layout
(variables, I/O buffers, the FALSE evaluation stack), the x64
exception/unwind tables (.pdata/.xdata -- required by the Windows x64
ABI for every non-leaf function; without them the OS's stack-walking
code has nothing to look up and the process can crash during teardown)
and a handful of small subroutines (write_buffer/write_char/print_int/
read_char/flush_io) implemented directly in hand-encoded x86-64.

Register convention used throughout the generated code (this is the
x86-64 analogue of the register conventions the original 68k FALSE
compiler documented for its inline-assembly feature -- see the
"Inline assembly" section of falsec.py's docstring):

    R15  = FALSE evaluation-stack pointer (grows upward; the current
           top-of-stack value lives at [R15-8]). Preserved across any
           call, including Win32 calls, by the Windows x64 ABI.
    RSP  = ordinary native stack (used for CALL/RET and as scratch by
           the runtime subroutines below).
    RCX/RDX/R8/R9 = argument registers for both our own internal
           subroutine convention and, of course, real Win32 calls.

Internal (non-Win32) call convention used between compiler-generated
code and the runtime subroutines below:
    write_buffer(RCX=ptr, RDX=len)      -> (nothing)
    write_char(RCX=byte)                -> (nothing)
    print_int(RCX=signed 64-bit value)  -> (nothing)
    read_char()                         -> RAX = 0..255, or -1 on EOF
    flush_io()                          -> (nothing)
Every runtime subroutine self-aligns the stack on entry, so callers
never need to worry about 16-byte alignment before calling them.
"""

import struct
from asm_x64 import (
    Assembler, ExternRef, Label,
    RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R15,
)
from pe_writer import PEImage, CHAR_TEXT, CHAR_RDATA, CHAR_RWDATA

IMPORTS = {
    "KERNEL32.dll": ["ExitProcess", "GetStdHandle", "WriteFile", "ReadFile", "FlushFileBuffers"],
    "USER32.dll": ["MessageBoxW"],
}

INPUT_BUF_SIZE = 8192
FALSE_STACK_SIZE = 1 << 20       # 1 MiB of FALSE data-stack, zero-filled

STD_OUTPUT_HANDLE = -11
STD_INPUT_HANDLE = -10


def _unwind_info_trivial():
    """UNWIND_INFO for a leaf-ish function that never moves RSP outside
    the implicit CALL/RET push/pop (this covers _start, the compiled
    FALSE program body and every compiled [...] block: none of them
    build a stack frame, they only ever CALL and RET)."""
    return bytes([0x01, 0x00, 0x00, 0x00])  # version=1,flags=0,prolog=0,codes=0


def _unwind_info_rbp_frame():
    """UNWIND_INFO for the `push rbp; mov rbp,rsp` prologue used by the
    runtime's own helper subroutines (which realign/adjust RSP after
    establishing RBP as a fixed frame pointer, exactly what
    UWOP_SET_FPREG describes)."""
    header = bytes([0x01, 0x04, 0x02, 0x05])   # prolog=4 bytes, 2 codes, frame reg=RBP(5)
    code_setfpreg = bytes([0x04, 0x03])        # offset 4: UWOP_SET_FPREG
    code_pushrbp = bytes([0x01, 0x50])         # offset 1: UWOP_PUSH_NONVOL reg=5(RBP)
    return header + code_setfpreg + code_pushrbp


class Runtime:
    def __init__(self):
        self.pe = PEImage()
        self.text = self.pe.region("text", CHAR_TEXT)
        self.rdata = self.pe.region("rdata", CHAR_RDATA)
        self.pdata = self.pe.region("pdata", CHAR_RDATA)
        self.xdata = self.pe.region("xdata", CHAR_RDATA)
        self.idata = self.pe.region("idata", CHAR_RWDATA)
        self.data = self.pe.region("data", CHAR_RWDATA)

        self.asm = Assembler()
        self._string_id = 0
        self.func_ranges = []   # (start_label, end_label, has_rbp_frame)

        self._build_data_layout()
        self._build_imports()
        self._build_runtime_code()

    def add_function_range(self, start_label, end_label, has_rbp_frame=False):
        """Register [start_label, end_label) as one function for the
        x64 exception directory (.pdata/.xdata). Every callable region
        of code -- the runtime helpers, the compiled FALSE program
        body, and every compiled [...] block -- must be registered so
        the OS can unwind through it."""
        self.func_ranges.append((start_label, end_label, has_rbp_frame))

    # ------------------------------------------------------------------
    # data section: 26 global variables, I/O scratch, then a large
    # zero-filled tail (input buffer + the FALSE stack) that costs no
    # file space.
    # ------------------------------------------------------------------
    def _build_data_layout(self):
        d = self.data
        d.add(b"\x00" * (26 * 8), key="vars")     # a..z, 8 bytes each
        for i in range(26):
            d.symtab[("var", chr(ord("a") + i))] = d.symtab["vars"] + i * 8
        d.add(b"\x00" * 8, key="hStdOut")
        d.add(b"\x00" * 8, key="hStdIn")
        d.add(b"\x00" * 8, key="bytes_written")
        d.add(b"\x00" * 8, key="bytes_read")
        d.add(b"\x00" * 8, key="in_buf_pos")
        d.add(b"\x00" * 8, key="in_buf_len")
        d.add(b"\x00" * 8, key="char_out_buf")
        d.add(b"\x00" * 32, key="int_str_buf")
        d.align(16)
        d.mark("in_buf")
        # in_buf and the FALSE stack are virtual-only: no file bytes.
        d.extra_virtual = INPUT_BUF_SIZE + 16
        d.symtab["false_stack"] = len(d.buf) + INPUT_BUF_SIZE + 16

    def var_ref(self, letter):
        """ExternRef for the storage cell of global variable a..z."""
        assert "a" <= letter <= "z"
        idx = ord(letter) - ord("a")
        # each variable gets its own key so PEImage fixups can target it
        key = ("var", letter)
        if key not in self.data.symtab:
            self.data.symtab[key] = self.data.symtab["vars"] + idx * 8
        return ExternRef("data", key)

    def add_string(self, raw_bytes):
        """Store a string literal in .rdata; return (ExternRef, length)."""
        key = ("str", self._string_id)
        self._string_id += 1
        self.rdata.add(raw_bytes, key=key)
        return ExternRef("rdata", key), len(raw_bytes)

    # ------------------------------------------------------------------
    # import table (one descriptor per DLL in IMPORTS, generalized so
    # additional DLLs -- e.g. user32.dll for MessageBoxW -- are just
    # another entry in the IMPORTS dict at the top of this file)
    # ------------------------------------------------------------------
    def _build_imports(self):
        idata = self.idata
        for dll, funcs in IMPORTS.items():
            for f in funcs:
                idata.align(2)
                idata.add(struct.pack("<H", 0) + f.encode("ascii") + b"\x00", key=("hn", f))
                if len(idata.buf) % 2:
                    idata.buf.append(0)

        dllname_off = {}
        for dll in IMPORTS:
            dllname_off[dll] = idata.here()
            idata.add(dll.encode("ascii") + b"\x00")

        ilt_start = {}
        ilt_off = {}
        for dll, funcs in IMPORTS.items():
            idata.align(8)
            ilt_start[dll] = idata.here()
            for f in funcs:
                ilt_off[f] = idata.here()
                idata.add(b"\x00" * 8)
            idata.add(b"\x00" * 8)  # ILT terminator for this DLL

        idata.align(8)
        idata.mark("iat")
        iat_off = {}
        for dll, funcs in IMPORTS.items():
            for f in funcs:
                iat_off[f] = idata.here()
                idata.add(b"\x00" * 8, key=("iat", f))
            idata.add(b"\x00" * 8)  # IAT terminator for this DLL
        idata.mark("iat_end")

        idata.align(8)
        idata.mark("import_dir")
        desc_off = {}
        for dll in IMPORTS:
            desc_off[dll] = idata.here()
            idata.add(b"\x00" * 20)
        idata.add(b"\x00" * 20)  # null descriptor terminator
        idata.mark("import_dir_end")

        for dll, funcs in IMPORTS.items():
            d = desc_off[dll]
            self.pe.add_absrva_fixup("idata", d + 0, "idata", ("ilt_start", dll))
            self.pe.add_absrva_fixup("idata", d + 12, "idata", ("dllname", dll))
            self.pe.add_absrva_fixup("idata", d + 16, "idata", ("iat_start", dll))
            idata.symtab[("ilt_start", dll)] = ilt_start[dll]
            idata.symtab[("dllname", dll)] = dllname_off[dll]
            idata.symtab[("iat_start", dll)] = iat_off[funcs[0]]
            for f in funcs:
                self.pe.add_absrva_fixup("idata", ilt_off[f], "idata", ("hn", f))
                self.pe.add_absrva_fixup("idata", iat_off[f], "idata", ("hn", f))

    def iat(self, func_name):
        return ExternRef("idata", ("iat", func_name))

    # ------------------------------------------------------------------
    # runtime subroutines
    # ------------------------------------------------------------------
    def _build_runtime_code(self):
        a = self.asm

        self.start_label = a.new_label("_start")
        self.write_buffer_label = a.new_label("write_buffer")
        self.write_char_label = a.new_label("write_char")
        self.print_int_label = a.new_label("print_int")
        self.read_char_label = a.new_label("read_char")
        self.flush_io_label = a.new_label("flush_io")
        self.main_label = a.new_label("false_main")  # bound by the FALSE compiler

        # ---------------- _start -----------------------------------------
        a.bind(self.start_label)
        a.mov_reg_imm64(RCX, STD_OUTPUT_HANDLE & 0xFFFFFFFFFFFFFFFF)
        a.call_rip(self.iat("GetStdHandle"))
        a.mov_rip_reg(ExternRef("data", "hStdOut"), RAX)
        a.mov_reg_imm64(RCX, STD_INPUT_HANDLE & 0xFFFFFFFFFFFFFFFF)
        a.call_rip(self.iat("GetStdHandle"))
        a.mov_rip_reg(ExternRef("data", "hStdIn"), RAX)
        a.lea_rip(R15, ExternRef("data", "false_stack"))
        a.call_label(self.main_label)
        a.mov_reg_imm64(RCX, 0)
        a.call_rip(self.iat("ExitProcess"))
        start_end = a.new_label("_start_end")
        a.bind(start_end)
        self.add_function_range(self.start_label, start_end, has_rbp_frame=False)

        # ---------------- write_buffer(RCX=ptr, RDX=len) -------------------
        a.bind(self.write_buffer_label)
        a.push_reg(RBP)
        a.mov_reg_reg(RBP, RSP)
        a.mov_reg_reg(R10, RCX)
        a.mov_reg_reg(R11, RDX)
        a.and_reg_imm32(RSP, -16)
        a.sub_reg_imm32(RSP, 48)
        a.mov_reg_rip(RCX, ExternRef("data", "hStdOut"))
        a.mov_reg_reg(RDX, R10)
        a.mov_reg_reg(R8, R11)
        a.lea_rip(R9, ExternRef("data", "bytes_written"))
        a.mov_mem_imm32(RSP, 32, 0)
        a.call_rip(self.iat("WriteFile"))
        a.mov_reg_reg(RSP, RBP)
        a.pop_reg(RBP)
        a.ret()
        wb_end = a.new_label("write_buffer_end")
        a.bind(wb_end)
        self.add_function_range(self.write_buffer_label, wb_end, has_rbp_frame=True)

        # ---------------- write_char(RCX=byte) ------------------------------
        a.bind(self.write_char_label)
        a.push_reg(RBP)
        a.mov_reg_reg(RBP, RSP)
        a.and_reg_imm32(RSP, -16)
        a.lea_rip(R10, ExternRef("data", "char_out_buf"))
        a.mov_mem8_reg(R10, 0, RCX)
        a.mov_reg_reg(RCX, R10)
        a.mov_reg_imm64(RDX, 1)
        a.call_label(self.write_buffer_label)
        a.mov_reg_reg(RSP, RBP)
        a.pop_reg(RBP)
        a.ret()
        wc_end = a.new_label("write_char_end")
        a.bind(wc_end)
        self.add_function_range(self.write_char_label, wc_end, has_rbp_frame=True)

        # ---------------- print_int(RCX=value) ------------------------------
        a.bind(self.print_int_label)
        a.push_reg(RBP)
        a.mov_reg_reg(RBP, RSP)
        a.and_reg_imm32(RSP, -16)
        a.mov_reg_reg(RAX, RCX)
        a.mov_reg_imm64(R10, 0)          # sign flag
        neg_skip = a.new_label("pi_pos")
        a.test_reg_reg(RAX, RAX)
        a.jge(neg_skip)
        a.neg_reg(RAX)
        a.mov_reg_imm64(R10, 1)
        a.bind(neg_skip)
        a.lea_rip(RDI, ExternRef("data", "int_str_buf"))
        a.add_reg_imm32(RDI, 31)
        a.mov_reg_imm64(RBX, 10)
        a.mov_reg_imm64(R11, 0)          # digit count
        digit_loop = a.new_label("pi_loop")
        a.bind(digit_loop)
        a.cqo()
        a.idiv_reg(RBX)
        a.add_reg_imm32(RDX, 0x30)
        a.dec_reg(RDI)
        a.mov_mem8_reg(RDI, 0, RDX)
        a.add_reg_imm32(R11, 1)
        a.test_reg_reg(RAX, RAX)
        a.jnz(digit_loop)
        no_sign = a.new_label("pi_nosign")
        a.test_reg_reg(R10, R10)
        a.jz(no_sign)
        a.mov_reg_imm64(R9, 0x2D)        # '-'
        a.dec_reg(RDI)
        a.mov_mem8_reg(RDI, 0, R9)
        a.add_reg_imm32(R11, 1)
        a.bind(no_sign)
        a.mov_reg_reg(RCX, RDI)
        a.mov_reg_reg(RDX, R11)
        a.call_label(self.write_buffer_label)
        a.mov_reg_reg(RSP, RBP)
        a.pop_reg(RBP)
        a.ret()
        pi_end = a.new_label("print_int_end")
        a.bind(pi_end)
        self.add_function_range(self.print_int_label, pi_end, has_rbp_frame=True)

        # ---------------- read_char() -> RAX ---------------------------------
        a.bind(self.read_char_label)
        a.push_reg(RBP)
        a.mov_reg_reg(RBP, RSP)
        a.mov_reg_rip(R10, ExternRef("data", "in_buf_pos"))
        a.mov_reg_rip(R11, ExternRef("data", "in_buf_len"))
        have_data = a.new_label("rc_have")
        a.cmp_reg_reg(R10, R11)
        a.jl(have_data)
        a.and_reg_imm32(RSP, -16)
        a.sub_reg_imm32(RSP, 48)
        a.mov_reg_rip(RCX, ExternRef("data", "hStdIn"))
        a.lea_rip(RDX, ExternRef("data", "in_buf"))
        a.mov_reg_imm64(R8, INPUT_BUF_SIZE)
        a.lea_rip(R9, ExternRef("data", "bytes_read"))
        a.mov_mem_imm32(RSP, 32, 0)
        a.call_rip(self.iat("ReadFile"))
        a.mov_reg_rip(R10, ExternRef("data", "bytes_read"))
        do_eof = a.new_label("rc_eof")
        a.test_reg_reg(R10, R10)
        a.jz(do_eof)
        a.mov_rip_reg(ExternRef("data", "in_buf_len"), R10)
        a.mov_reg_imm64(R10, 0)
        a.mov_rip_reg(ExternRef("data", "in_buf_pos"), R10)
        a.jmp(have_data)
        a.bind(do_eof)
        a.mov_reg_imm64(RAX, 0xFFFFFFFFFFFFFFFF)
        a.mov_reg_reg(RSP, RBP)
        a.pop_reg(RBP)
        a.ret()
        a.bind(have_data)
        a.mov_reg_rip(R10, ExternRef("data", "in_buf_pos"))
        a.lea_rip(RDX, ExternRef("data", "in_buf"))
        a.add_reg_reg(RDX, R10)
        a.mov_reg_mem8(RAX, RDX, 0)
        a.add_reg_imm32(R10, 1)
        a.mov_rip_reg(ExternRef("data", "in_buf_pos"), R10)
        a.mov_reg_reg(RSP, RBP)
        a.pop_reg(RBP)
        a.ret()
        rc_end = a.new_label("read_char_end")
        a.bind(rc_end)
        self.add_function_range(self.read_char_label, rc_end, has_rbp_frame=True)

        # ---------------- flush_io() -------------------------------------------
        a.bind(self.flush_io_label)
        a.push_reg(RBP)
        a.mov_reg_reg(RBP, RSP)
        a.and_reg_imm32(RSP, -16)
        a.sub_reg_imm32(RSP, 32)
        a.mov_reg_rip(RCX, ExternRef("data", "hStdOut"))
        a.call_rip(self.iat("FlushFileBuffers"))
        a.mov_reg_reg(RSP, RBP)
        a.pop_reg(RBP)
        a.ret()
        flush_end = a.new_label("flush_io_end")
        a.bind(flush_end)
        self.add_function_range(self.flush_io_label, flush_end, has_rbp_frame=True)

    # ------------------------------------------------------------------
    def _build_pdata_xdata(self):
        """Populate .pdata (RUNTIME_FUNCTION[]) / .xdata (UNWIND_INFO
        blobs) from everything registered via add_function_range(), and
        wire the fixed unwind-info blob(s) up to it. Must run after all
        codegen (including the FALSE program body) is finished, so every
        label has a final offset, and *before* pe.build() so the Exception
        Table data directory can be filled in."""
        trivial_key = self.xdata.add(_unwind_info_trivial(), key="uw_trivial")
        frame_key = self.xdata.add(_unwind_info_rbp_frame(), key="uw_rbpframe")

        # RUNTIME_FUNCTION entries must be sorted by BeginAddress (RVA).
        ranges = sorted(self.func_ranges, key=lambda r: r[0].offset)
        for start_label, end_label, has_frame in ranges:
            entry_off = self.pdata.here()
            self.pdata.add(b"\x00" * 12)
            self.pe.add_absrva_fixup("pdata", entry_off + 0, "text", ("label", id(start_label)))
            self.pe.add_absrva_fixup("pdata", entry_off + 4, "text", ("label", id(end_label)))
            self.pe.add_absrva_fixup("pdata", entry_off + 8, "xdata",
                                      "uw_rbpframe" if has_frame else "uw_trivial")
            # register the label offsets as text-region symtab entries so
            # the absrva fixups above can look them up like any other symbol
            self.text.symtab[("label", id(start_label))] = start_label.offset
            self.text.symtab[("label", id(end_label))] = end_label.offset

    # ------------------------------------------------------------------
    def finalize(self):
        """Call once the FALSE program body has been compiled (and
        self.main_label bound) to resolve fixups and build the .exe bytes."""
        self.asm.resolve_local_fixups()
        self.text.buf = self.asm.buf
        self.pe.add_text_fixups("text", self.asm)
        self._build_pdata_xdata()
        self.pe.set_entry("text", self.start_label.offset)
        return self.pe.build()
