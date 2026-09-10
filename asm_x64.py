"""
asm_x64.py -- a very small, self-contained x86-64 machine code encoder.

This is NOT a general purpose assembler. It implements only the handful
of instruction forms that the FALSE compiler needs, hand-encoded byte
by byte. It also provides label/fixup bookkeeping so the compiler can
emit forward and backward jumps (needed for [...] blocks, "?" and "#")
and cross-section references (needed for string literals, the variable
table and the import address table).

Register numbers (both GP and encoding index) follow the standard
x86-64 numbering:
    0=RAX 1=RCX 2=RDX 3=RBX 4=RSP 5=RBP 6=RSI 7=RDI
    8=R8  9=R9 10=R10 11=R11 12=R12 13=R13 14=R14 15=R15
"""

import struct

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)

REG_NAMES = {
    RAX: "rax", RCX: "rcx", RDX: "rdx", RBX: "rbx",
    RSP: "rsp", RBP: "rbp", RSI: "rsi", RDI: "rdi",
    R8: "r8", R9: "r9", R10: "r10", R11: "r11",
    R12: "r12", R13: "r13", R14: "r14", R15: "r15",
}


class Label:
    """A symbolic position inside a code (or data) buffer."""
    __slots__ = ("name", "resolved", "offset")

    def __init__(self, name):
        self.name = name
        self.resolved = False
        self.offset = None

    def __repr__(self):
        return f"<Label {self.name} @{self.offset}>"


class ExternRef:
    """
    A reference that can only be resolved once the final layout of the
    PE image (section RVAs) is known -- e.g. `lea reg, [rip+var_table]`
    or `call [rip+IAT_WriteFile]`. `kind` is one of:
        'data'   -> offset into the data blob (rw section)
        'rdata'  -> offset into the rdata blob (strings, ro)
        'iat'    -> index into the import address table
        'text'   -> offset into the text (code) blob itself
    """
    __slots__ = ("kind", "key")

    def __init__(self, kind, key):
        self.kind = kind
        self.key = key


class Assembler:
    """
    Accumulates machine code into `self.buf`. Local (intra-buffer) jumps
    use `Label`; forward references are patched automatically once the
    label is bound with `bind()` -- if the label isn't bound yet when a
    jump to it is emitted, the fixup is queued and resolved by
    `resolve_local_fixups()`, which callers invoke once every label used
    has been bound (the FALSE compiler does this once per top level
    program, since blocks are fully nested).

    Cross-section references are queued in `self.extern_fixups` and are
    resolved later by the PE writer once it has decided final section
    RVAs (see pe_writer.py: `patch_extern_fixups`).
    """

    def __init__(self):
        self.buf = bytearray()
        self._local_fixups = []       # (patch_off, label, instr_end_off)
        self.extern_fixups = []       # (patch_off, ExternRef, instr_end_off)

    # ---- low level helpers -------------------------------------------------

    def _emit(self, data):
        self.buf += data

    def pos(self):
        return len(self.buf)

    def new_label(self, name="L"):
        return Label(f"{name}{id(object()) & 0xffffff:06x}")

    def bind(self, label):
        assert not label.resolved, f"label {label.name} already bound"
        label.offset = len(self.buf)
        label.resolved = True

    def resolve_local_fixups(self):
        for patch_off, label, instr_end_off in self._local_fixups:
            assert label.resolved, f"unresolved label {label.name}"
            rel = label.offset - instr_end_off
            struct.pack_into("<i", self.buf, patch_off, rel)
        self._local_fixups.clear()

    # ---- REX / ModRM / SIB --------------------------------------------------

    @staticmethod
    def _rex(w, r, x, b, force=False):
        val = 0x40 | (w << 3) | (r << 2) | (x << 1) | b
        if val != 0x40 or force:
            return bytes([val])
        return b""

    def _modrm_reg_reg(self, w, op_reg, rm_reg, opcode_bytes, reg_is_dest=True,
                        force_rex=False):
        """Encode `OPCODE reg, rm` (register-direct addressing only)."""
        r = (op_reg >> 3) & 1
        b = (rm_reg >> 3) & 1
        self._emit(self._rex(w, r, 0, b, force=force_rex))
        self._emit(bytes(opcode_bytes))
        modrm = 0xC0 | ((op_reg & 7) << 3) | (rm_reg & 7)
        self._emit(bytes([modrm]))

    def _modrm_mem(self, base_reg, disp, extra_reg_field=0):
        """
        Build ModRM(+SIB)(+disp) bytes for [base_reg + disp].
        extra_reg_field is placed in the reg/opcode-extension field.
        Returns the bytes; caller is responsible for the REX prefix.
        """
        out = bytearray()
        breg = base_reg & 7
        reg_field = extra_reg_field & 7
        need_sib = (breg == RSP & 7)  # RSP/R12 always need a SIB byte
        if disp == 0 and breg != (RBP & 7):
            mod = 0b00
        elif -128 <= disp <= 127:
            mod = 0b01
        else:
            mod = 0b10
        modrm = (mod << 6) | (reg_field << 3) | (0b100 if need_sib else breg)
        out.append(modrm)
        if need_sib:
            out.append(0x24)  # scale=1, index=none(100), base=RSP/R12(100)
        if mod == 0b01:
            out += struct.pack("<b", disp)
        elif mod == 0b10:
            out += struct.pack("<i", disp)
        return bytes(out)

    # ---- data movement -------------------------------------------------------

    def mov_reg_imm64(self, reg, imm):
        """mov r64, imm64 (REX.W + B8+r + imm64) -- always 10 bytes."""
        imm &= 0xFFFFFFFFFFFFFFFF
        self._emit(self._rex(1, 0, 0, (reg >> 3) & 1, force=True))
        self._emit(bytes([0xB8 | (reg & 7)]))
        self._emit(struct.pack("<Q", imm))

    def mov_reg_reg(self, dst, src):
        """mov dst, src (64-bit)."""
        if dst == src:
            return
        self._modrm_reg_reg(1, src, dst, [0x89])  # mov r/m64, r64

    def mov_reg_mem(self, dst, base, disp):
        """mov dst, [base+disp]"""
        r = (dst >> 3) & 1
        b = (base >> 3) & 1
        self._emit(self._rex(1, r, 0, b, force=True))
        self._emit(bytes([0x8B]))
        self._emit(self._modrm_mem(base, disp, dst))

    def mov_mem_reg(self, base, disp, src):
        """mov [base+disp], src"""
        r = (src >> 3) & 1
        b = (base >> 3) & 1
        self._emit(self._rex(1, r, 0, b, force=True))
        self._emit(bytes([0x89]))
        self._emit(self._modrm_mem(base, disp, src))

    def mov_reg_mem8(self, dst, base, disp):
        """movzx dst(32), byte [base+disp]"""
        r = (dst >> 3) & 1
        b = (base >> 3) & 1
        self._emit(self._rex(0, r, 0, b))
        self._emit(bytes([0x0F, 0xB6]))
        self._emit(self._modrm_mem(base, disp, dst))

    def mov_mem8_reg(self, base, disp, src):
        """mov byte [base+disp], src(low 8 bits)"""
        r = (src >> 3) & 1
        b = (base >> 3) & 1
        pfx = self._rex(0, r, 0, b, force=(src >= RSP and src <= RDI))
        self._emit(pfx)
        self._emit(bytes([0x88]))
        self._emit(self._modrm_mem(base, disp, src))

    # RIP-relative addressing: used for referencing our own data/rdata/iat
    def _lea_or_mov_rip(self, opcode_bytes, reg, extern_ref, w=1):
        r = (reg >> 3) & 1
        self._emit(self._rex(w, r, 0, 0, force=True))
        self._emit(bytes(opcode_bytes))
        modrm = 0b00_000_101 | ((reg & 7) << 3)
        self._emit(bytes([modrm]))
        patch_off = len(self.buf)
        self._emit(b"\x00\x00\x00\x00")
        instr_end = len(self.buf)
        self.extern_fixups.append((patch_off, extern_ref, instr_end))

    def lea_rip(self, reg, extern_ref):
        """lea reg, [rip+extern]  (address-of)"""
        self._lea_or_mov_rip([0x8D], reg, extern_ref)

    def mov_reg_rip(self, reg, extern_ref):
        """mov reg, [rip+extern]  (load qword)"""
        self._lea_or_mov_rip([0x8B], reg, extern_ref)

    def mov_rip_reg(self, extern_ref, reg):
        """mov [rip+extern], reg  (store qword)"""
        self._lea_or_mov_rip([0x89], reg, extern_ref)

    def mov_mem_imm32(self, base, disp, imm):
        """mov qword [base+disp], imm32 (sign-extended)"""
        self._emit(self._rex(1, 0, 0, (base >> 3) & 1, force=True))
        self._emit(bytes([0xC7]))
        self._emit(self._modrm_mem(base, disp, 0))
        self._emit(struct.pack("<i", imm))

    def call_rip(self, extern_ref):
        """call [rip+extern]  (indirect call through e.g. an IAT slot)"""
        self._emit(bytes([0xFF]))
        modrm = 0b00_010_101  # /2 = call, mod00 rm101 = rip-relative
        self._emit(bytes([modrm]))
        patch_off = len(self.buf)
        self._emit(b"\x00\x00\x00\x00")
        instr_end = len(self.buf)
        self.extern_fixups.append((patch_off, extern_ref, instr_end))

    # ---- arithmetic / logic ---------------------------------------------------

    def _binop_reg_reg(self, opcode, dst, src):
        self._modrm_reg_reg(1, src, dst, [opcode])

    def add_reg_reg(self, dst, src):
        self._binop_reg_reg(0x01, dst, src)   # add r/m64, r64

    def sub_reg_reg(self, dst, src):
        self._binop_reg_reg(0x29, dst, src)   # sub r/m64, r64

    def and_reg_reg(self, dst, src):
        self._binop_reg_reg(0x21, dst, src)

    def or_reg_reg(self, dst, src):
        self._binop_reg_reg(0x09, dst, src)

    def xor_reg_reg(self, dst, src):
        self._binop_reg_reg(0x31, dst, src)

    def cmp_reg_reg(self, a, b):
        self._binop_reg_reg(0x39, a, b)       # cmp r/m64(a), r64(b)

    def test_reg_reg(self, a, b):
        self._binop_reg_reg(0x85, a, b)

    def add_reg_imm32(self, reg, imm):
        self._emit(self._rex(1, 0, 0, (reg >> 3) & 1, force=True))
        self._emit(bytes([0x81]))
        self._emit(bytes([0xC0 | (reg & 7)]))
        self._emit(struct.pack("<i", imm))

    def sub_reg_imm32(self, reg, imm):
        self._emit(self._rex(1, 0, 0, (reg >> 3) & 1, force=True))
        self._emit(bytes([0x81]))
        self._emit(bytes([0xE8 | (reg & 7)]))
        self._emit(struct.pack("<i", imm))

    def and_reg_imm32(self, reg, imm):
        self._emit(self._rex(1, 0, 0, (reg >> 3) & 1, force=True))
        self._emit(bytes([0x81]))
        self._emit(bytes([0xE0 | (reg & 7)]))
        self._emit(struct.pack("<i", imm))

    def imul_reg_reg(self, dst, src):
        """imul dst, src  (dst *= src), 0F AF /r"""
        r = (dst >> 3) & 1
        b = (src >> 3) & 1
        self._emit(self._rex(1, r, 0, b, force=True))
        self._emit(bytes([0x0F, 0xAF]))
        self._emit(bytes([0xC0 | ((dst & 7) << 3) | (src & 7)]))

    def idiv_reg(self, reg):
        """idiv r/m64  (rdx:rax / reg -> quotient rax, remainder rdx). F7 /7"""
        self._emit(self._rex(1, 0, 0, (reg >> 3) & 1, force=True))
        self._emit(bytes([0xF7]))
        self._emit(bytes([0xF8 | (reg & 7)]))

    def neg_reg(self, reg):
        self._emit(self._rex(1, 0, 0, (reg >> 3) & 1, force=True))
        self._emit(bytes([0xF7]))
        self._emit(bytes([0xD8 | (reg & 7)]))

    def not_reg(self, reg):
        self._emit(self._rex(1, 0, 0, (reg >> 3) & 1, force=True))
        self._emit(bytes([0xF7]))
        self._emit(bytes([0xD0 | (reg & 7)]))

    def cqo(self):
        self._emit(bytes([0x48, 0x99]))

    def shl_reg_imm8(self, reg, imm):
        self._emit(self._rex(1, 0, 0, (reg >> 3) & 1, force=True))
        self._emit(bytes([0xC1]))
        self._emit(bytes([0xE0 | (reg & 7)]))
        self._emit(bytes([imm & 0xFF]))

    def inc_reg(self, reg):
        self._emit(self._rex(1, 0, 0, (reg >> 3) & 1, force=True))
        self._emit(bytes([0xFF]))
        self._emit(bytes([0xC0 | (reg & 7)]))

    def dec_reg(self, reg):
        self._emit(self._rex(1, 0, 0, (reg >> 3) & 1, force=True))
        self._emit(bytes([0xFF]))
        self._emit(bytes([0xC8 | (reg & 7)]))

    # ---- byte-sized set/compare helpers ---------------------------------------

    def sete_al(self):
        self._emit(bytes([0x0F, 0x94, 0xC0]))

    def setne_al(self):
        self._emit(bytes([0x0F, 0x95, 0xC0]))

    def setg_al(self):
        self._emit(bytes([0x0F, 0x9F, 0xC0]))

    def setl_al(self):
        self._emit(bytes([0x0F, 0x9C, 0xC0]))

    def movzx_eax_al(self):
        self._emit(bytes([0x0F, 0xB6, 0xC0]))

    # ---- stack -------------------------------------------------------------

    def push_reg(self, reg):
        b = (reg >> 3) & 1
        if b:
            self._emit(bytes([0x41]))
        self._emit(bytes([0x50 | (reg & 7)]))

    def pop_reg(self, reg):
        b = (reg >> 3) & 1
        if b:
            self._emit(bytes([0x41]))
        self._emit(bytes([0x58 | (reg & 7)]))

    # ---- control flow --------------------------------------------------------

    def _jcc(self, tttn, label):
        self._emit(bytes([0x0F, 0x80 | tttn]))
        patch_off = len(self.buf)
        self._emit(b"\x00\x00\x00\x00")
        instr_end = len(self.buf)
        if label.resolved:
            struct.pack_into("<i", self.buf, patch_off, label.offset - instr_end)
        else:
            self._local_fixups.append((patch_off, label, instr_end))

    def jmp(self, label):
        self._emit(bytes([0xE9]))
        patch_off = len(self.buf)
        self._emit(b"\x00\x00\x00\x00")
        instr_end = len(self.buf)
        if label.resolved:
            struct.pack_into("<i", self.buf, patch_off, label.offset - instr_end)
        else:
            self._local_fixups.append((patch_off, label, instr_end))

    def jz(self, label):
        self._jcc(0x4, label)

    def jnz(self, label):
        self._jcc(0x5, label)

    def jl(self, label):
        self._jcc(0xC, label)

    def jge(self, label):
        self._jcc(0xD, label)

    def jle(self, label):
        self._jcc(0xE, label)

    def jg(self, label):
        self._jcc(0xF, label)

    def lea_label(self, reg, label):
        """lea reg, [rip+label]  (address-of a same-buffer label; used to
        push a compiled [...] block's entry point as a FALSE function
        value)."""
        r = (reg >> 3) & 1
        self._emit(self._rex(1, r, 0, 0, force=True))
        self._emit(bytes([0x8D]))
        modrm = 0b00_000_101 | ((reg & 7) << 3)
        self._emit(bytes([modrm]))
        patch_off = len(self.buf)
        self._emit(b"\x00\x00\x00\x00")
        instr_end = len(self.buf)
        if label.resolved:
            struct.pack_into("<i", self.buf, patch_off, label.offset - instr_end)
        else:
            self._local_fixups.append((patch_off, label, instr_end))

    def call_label(self, label):
        """Direct near call (E8 rel32) to a label in this same buffer."""
        self._emit(bytes([0xE8]))
        patch_off = len(self.buf)
        self._emit(b"\x00\x00\x00\x00")
        instr_end = len(self.buf)
        if label.resolved:
            struct.pack_into("<i", self.buf, patch_off, label.offset - instr_end)
        else:
            self._local_fixups.append((patch_off, label, instr_end))

    def call_reg(self, reg):
        b = (reg >> 3) & 1
        self._emit(self._rex(0, 0, 0, b))
        self._emit(bytes([0xFF]))
        self._emit(bytes([0xD0 | (reg & 7)]))

    def ret(self):
        self._emit(bytes([0xC3]))

    # ---- raw bytes (used by the FALSE `NNN\`` inline-assembly feature) -------

    def raw_word_le(self, value):
        """Splice a raw 16-bit little-endian word directly into the stream."""
        self._emit(struct.pack("<H", value & 0xFFFF))

    def raw_bytes(self, data):
        self._emit(bytes(data))
