#!/usr/bin/env python3
"""
falsec.py -- a native x86-64 compiler for the FALSE programming language
(Wouter van Oortmerssen, 1993), targeting 64-bit Windows.

    https://strlen.com/files/lang/false/false.txt

Unlike the original 1 KB 68k compiler (which produced an Amiga
executable through a small runtime library) this compiler emits
x86-64 machine code directly, byte by byte (see asm_x64.py), and
writes it straight into a hand-built PE32+ (.exe) image (see
pe_writer.py) -- no assembler, linker or Windows SDK is required to
use it.

--------------------------------------------------------------------
Language summary (see the manual above for the full story)
--------------------------------------------------------------------
    integer            push value                      1  100
    'c                 push ord(c)                      'A
    a..z               push the *address* of variable   a
    :                  (n,addr - )   store               1a:
    ;                  (addr - n)    fetch                a;
    [ ... ]            push the address of a compiled function
    !                  (fn - )       call it              f;!
    ?                  (bool,fn - )  call fn if bool
    #                  (condfn,bodyfn - )  while loop
    + - * / _          arithmetic (_ is unary minus)
    = >                comparison, result is 0 or -1 (all bits set)
    & | ~              bitwise/boolean and/or/not
    $ % \\ @ ø(pick)    dup / drop / swap / rot / pick
    . ,                print number / print character
    " ... "            print a string literal
    ^                  read one character (-1 = EOF)
    ß (flush)          flush stdout
    NNN`               *inline assembly* -- see below

--------------------------------------------------------------------
Inline assembly, ported to x86-64
--------------------------------------------------------------------
The manual's "FALSE wizards corner" describes the *only* extension
mechanism the original language ever had:

    syntax:      <integer>`
    any integer value 0..65535 followed by a backquote causes that
    16-bit value to be put directly into the code [stream]. A series
    of backquoted values may allow you a primitive form of inline
    assembly.

This compiler keeps that mechanism completely unchanged: a run of
digits immediately followed by a backtick is *not* compiled as a
FALSE stack push -- its 16-bit little-endian representation is
spliced verbatim into the machine-code stream at exactly the point
it occurs, in between whatever ordinary FALSE operators surround it.
Chaining several such "NNN-backtick" tokens back to back lets you hand-assemble
arbitrary x86-64 byte sequences directly into the compiled program,
exactly as chaining 68k opcode words did in 1993 -- only the
instruction set (and therefore the bytes you'd write) has changed.

Register conventions for inline assembly (the x86-64 analogue of the
manual's "A6=dosbase, A5=eval stack, A4=variables, D6=stdout,
D5=stdin" table):

    R15   FALSE evaluation stack pointer. Grows upward; top-of-stack
          is the qword at [R15-8]. Push: `mov [r15],reg` then
          `add r15,8`. Pop: `sub r15,8` then `mov reg,[r15]`.
          Preserved across calls by the Windows x64 ABI.
    RSP   ordinary native stack (return addresses, locals).
    RIP-relative addressing reaches every compiler-managed symbol
          (variables, string literals, the Win32 IAT, the runtime
          helpers) without needing to know the load address, because
          the image has a fixed, non-relocated base -- run this
          compiler with --map to print the absolute addresses of
          every symbol for a given program, for use when
          hand-encoding `mov reg,imm64` / rip-relative disp32 values.
    call [rip+<disp>]   is how compiled code reaches WriteFile,
          ReadFile, GetStdHandle, FlushFileBuffers, ExitProcess.
    call <near rel32>   reaches the compiler's own runtime helpers:
          write_buffer(rcx=ptr,rdx=len), write_char(rcx=byte),
          print_int(rcx=value), read_char()->rax, flush_io().
          --map prints their addresses too.

As in the original, this feature does no validation whatsoever: it
is genuinely possible to corrupt the surrounding code and crash the
compiled program, exactly as the manual warns ("the compiler may
even crash if you don't balance your [ and ]").

--------------------------------------------------------------------
Fidelity notes / deliberate deviations
--------------------------------------------------------------------
* Integers are full 64-bit (the original 1k parser topped out at
  320000 purely because of its tiny source buffer; that limit was
  never part of the language).
* "pick" and "flush" are two characters the manual could only render
  as the mangled placeholder "\xef\xbf\xbd" -- on the original Amiga
  keyboard they were Alt-O and Alt-S. This compiler accepts both the
  common Latin-1 encodings (0xF8 'ø' for pick, 0xDF 'ß' for flush)
  and their UTF-8 encodings, so files written in either convention
  work unmodified.
* The one compile-time error the manual documents ("it found a
  symbol in the source which isn't part of the language") is
  preserved: an unrecognised character aborts compilation and the
  process exits with status 10, exactly as the original did.
"""

import argparse
import sys

from asm_x64 import (
    Assembler, ExternRef,
    RAX, RBX, RCX, RDX, RSI, RDI, RSP, RBP, R15,
)
from runtime import Runtime, IMPORTS
from pe_writer import IMAGE_BASE


class FalseSyntaxError(Exception):
    """The one error class the original compiler documented: an
    unrecognised symbol, or a structurally broken [ ] / " " / { }."""


PICK_BYTES = (0xF8,)        # Latin-1 'ø'
FLUSH_BYTES = (0xDF,)       # Latin-1 'ß'
PICK_UTF8 = (0xC3, 0xB8)    # 'ø'
FLUSH_UTF8 = (0xC3, 0x9F)   # 'ß'


class FalseCompiler:
    def __init__(self, rt: Runtime, source: bytes, verbose=False):
        self.rt = rt
        self.asm = rt.asm
        self.src = source
        self.n = len(source)
        self.pos = 0
        self.verbose = verbose

    # ---- tiny byte-stream reader -------------------------------------------

    def _peek(self, ahead=0):
        p = self.pos + ahead
        return self.src[p] if p < self.n else -1

    def _next(self):
        c = self._peek()
        if c != -1:
            self.pos += 1
        return c

    def _where(self):
        line = self.src.count(b"\n", 0, self.pos) + 1
        col = self.pos - (self.src.rfind(b"\n", 0, self.pos))
        return f"line {line}, col {col}"

    def _err(self, msg):
        raise FalseSyntaxError(f"{msg} at {self._where()} (offset {self.pos})")

    # ---- FALSE data-stack push/pop helpers ---------------------------------

    def fpush(self, reg):
        a = self.asm
        a.mov_mem_reg(R15, 0, reg)
        a.add_reg_imm32(R15, 8)

    def fpop(self, reg):
        a = self.asm
        a.sub_reg_imm32(R15, 8)
        a.mov_reg_mem(reg, R15, 0)

    # ---- entry point --------------------------------------------------------

    def compile_program(self):
        a = self.asm
        a.bind(self.rt.main_label)
        self.compile_block(top_level=True)
        a.ret()
        main_end = a.new_label("false_main_end")
        a.bind(main_end)
        self.rt.add_function_range(self.rt.main_label, main_end, has_rbp_frame=False)

    # ---- block compilation ---------------------------------------------------

    def compile_block(self, top_level=False):
        """Compile tokens up to (and consuming) a matching ']', or to EOF
        if top_level."""
        while True:
            c = self._peek()
            if c == -1:
                if top_level:
                    return
                self._err("unterminated '[' (missing ']')")
            if c == ord("]"):
                if top_level:
                    self._err("unmatched ']'")
                self.pos += 1
                return
            self.compile_one()

    # ---- one token -------------------------------------------------------------

    def compile_one(self):
        a = self.asm
        rt = self.rt
        c = self._next()

        # whitespace
        if c in (0x20, 0x09, 0x0D, 0x0A):
            return

        # comments: {...}, not nested
        if c == ord("{"):
            while True:
                d = self._next()
                if d == -1:
                    self._err("unterminated '{' comment")
                if d == ord("}"):
                    return

        # string literal
        if c == ord('"'):
            start = self.pos
            while True:
                d = self._next()
                if d == -1:
                    self._err('unterminated string literal')
                if d == ord('"'):
                    break
            raw = bytes(self.src[start:self.pos - 1])
            ref, length = rt.add_string(raw)
            a.lea_rip(RCX, ref)
            a.mov_reg_imm64(RDX, length)
            a.call_label(rt.write_buffer_label)
            return

        # lambda / code block
        if c == ord("["):
            end_label = a.new_label("blk_end")
            start_label = a.new_label("blk_start")
            a.jmp(end_label)
            a.bind(start_label)
            self.compile_block()
            a.ret()
            a.bind(end_label)
            rt.add_function_range(start_label, end_label, has_rbp_frame=False)
            a.lea_label(RAX, start_label)
            self.fpush(RAX)
            return

        # number literal, or NNN` inline-assembly word
        if 0x30 <= c <= 0x39:
            digits = chr(c)
            while 0x30 <= self._peek() <= 0x39:
                digits += chr(self._next())
            value = int(digits)
            if self._peek() == ord("`"):
                self.pos += 1
                a.raw_word_le(value & 0xFFFF)
            else:
                a.mov_reg_imm64(RAX, value)
                self.fpush(RAX)
            return

        # character literal
        if c == ord("'"):
            ch = self._next()
            if ch == -1:
                self._err("'  at end of input (missing character)")
            a.mov_reg_imm64(RAX, ch)
            self.fpush(RAX)
            return

        # variables a..z
        if ord("a") <= c <= ord("z"):
            ref = rt.var_ref(chr(c))
            a.lea_rip(RAX, ref)
            self.fpush(RAX)
            return

        # ---- operators ---------------------------------------------------------
        if c == ord(":"):          # (n,addr - )   store
            self.fpop(RAX)         # addr
            self.fpop(RBX)         # value
            a.mov_mem_reg(RAX, 0, RBX)
            return
        if c == ord(";"):          # (addr - n)    fetch
            self.fpop(RAX)
            a.mov_reg_mem(RBX, RAX, 0)
            self.fpush(RBX)
            return
        if c == ord("!"):          # (fn - )       apply
            self.fpop(RAX)
            a.call_reg(RAX)
            return

        if c == ord("+"):
            self.fpop(RBX); self.fpop(RAX); a.add_reg_reg(RAX, RBX); self.fpush(RAX); return
        if c == ord("-"):
            self.fpop(RBX); self.fpop(RAX); a.sub_reg_reg(RAX, RBX); self.fpush(RAX); return
        if c == ord("*"):
            self.fpop(RBX); self.fpop(RAX); a.imul_reg_reg(RAX, RBX); self.fpush(RAX); return
        if c == ord("/"):
            self.fpop(RBX); self.fpop(RAX); a.cqo(); a.idiv_reg(RBX); self.fpush(RAX); return
        if c == ord("_"):
            self.fpop(RAX); a.neg_reg(RAX); self.fpush(RAX); return

        if c == ord("="):
            self.fpop(RBX); self.fpop(RAX)
            a.cmp_reg_reg(RAX, RBX); a.sete_al(); a.movzx_eax_al(); a.neg_reg(RAX)
            self.fpush(RAX); return
        if c == ord(">"):
            self.fpop(RBX); self.fpop(RAX)
            a.cmp_reg_reg(RAX, RBX); a.setg_al(); a.movzx_eax_al(); a.neg_reg(RAX)
            self.fpush(RAX); return

        if c == ord("&"):
            self.fpop(RBX); self.fpop(RAX); a.and_reg_reg(RAX, RBX); self.fpush(RAX); return
        if c == ord("|"):
            self.fpop(RBX); self.fpop(RAX); a.or_reg_reg(RAX, RBX); self.fpush(RAX); return
        if c == ord("~"):
            self.fpop(RAX); a.not_reg(RAX); self.fpush(RAX); return

        if c == ord("$"):          # dup
            a.mov_reg_mem(RAX, R15, -8); self.fpush(RAX); return
        if c == ord("%"):          # drop
            a.sub_reg_imm32(R15, 8); return
        if c == ord("\\"):         # swap
            a.mov_reg_mem(RAX, R15, -8)
            a.mov_reg_mem(RBX, R15, -16)
            a.mov_mem_reg(R15, -8, RBX)
            a.mov_mem_reg(R15, -16, RAX)
            return
        if c == ord("@"):          # rot: (n,n1,n2 - n1,n2,n)
            a.mov_reg_mem(RAX, R15, -24)  # n
            a.mov_reg_mem(RBX, R15, -16)  # n1
            a.mov_reg_mem(RCX, R15, -8)   # n2
            a.mov_mem_reg(R15, -24, RBX)
            a.mov_mem_reg(R15, -16, RCX)
            a.mov_mem_reg(R15, -8, RAX)
            return
        if c in PICK_BYTES or (c == PICK_UTF8[0] and self._peek() == PICK_UTF8[1]):
            if c == PICK_UTF8[0]:
                self.pos += 1
            self.fpop(RCX)
            a.mov_reg_reg(RAX, RCX)
            a.shl_reg_imm8(RAX, 3)
            a.mov_reg_reg(RDX, R15)
            a.sub_reg_imm32(RDX, 8)
            a.sub_reg_reg(RDX, RAX)
            a.mov_reg_mem(RAX, RDX, 0)
            self.fpush(RAX)
            return

        if c == ord("?"):          # (bool,fn - )
            self.fpop(RAX)         # fn
            self.fpop(RBX)         # bool
            skip = a.new_label("if_skip")
            a.test_reg_reg(RBX, RBX)
            a.jz(skip)
            a.call_reg(RAX)
            a.bind(skip)
            return
        if c == ord("#"):          # (condfn,bodyfn - )
            self.fpop(RAX)         # bodyfn
            self.fpop(RBX)         # condfn
            a.push_reg(RBX)
            a.push_reg(RAX)
            loop_start = a.new_label("while_top")
            loop_end = a.new_label("while_end")
            a.bind(loop_start)
            a.mov_reg_mem(RCX, RSP, 8)   # condfn
            a.call_reg(RCX)
            self.fpop(RAX)
            a.test_reg_reg(RAX, RAX)
            a.jz(loop_end)
            a.mov_reg_mem(RCX, RSP, 0)   # bodyfn
            a.call_reg(RCX)
            a.jmp(loop_start)
            a.bind(loop_end)
            a.add_reg_imm32(RSP, 16)
            return

        if c == ord("."):          # print number
            self.fpop(RCX)
            a.call_label(rt.print_int_label)
            return
        if c == ord(","):          # print character
            self.fpop(RCX)
            a.call_label(rt.write_char_label)
            return
        if c == ord("^"):          # read character
            a.call_label(rt.read_char_label)
            self.fpush(RAX)
            return
        if c in FLUSH_BYTES or (c == FLUSH_UTF8[0] and self._peek() == FLUSH_UTF8[1]):
            if c == FLUSH_UTF8[0]:
                self.pos += 1
            a.call_label(rt.flush_io_label)
            return

        self._err(f"found a symbol which isn't part of the language: {chr(c)!r} (0x{c:02x})")

    # ---- diagnostics ------------------------------------------------------------

    def print_map(self, file=sys.stderr):
        pe = self.rt.pe
        layout = pe.last_layout

        def va(region, key):
            return IMAGE_BASE + layout[region]["rva"] + pe.regions[region].symtab[key]

        print("symbol table (absolute addresses, for inline-assembly authors)", file=file)
        print(f"  image base        0x{IMAGE_BASE:016x}", file=file)
        print(f"  false_stack base  0x{va('data', 'false_stack'):016x}", file=file)
        for letter in "abcdefghijklmnopqrstuvwxyz":
            print(f"  var {letter}            0x{va('data', ('var', letter)):016x}", file=file)
        for name, label in (
            ("write_buffer", self.rt.write_buffer_label),
            ("write_char", self.rt.write_char_label),
            ("print_int", self.rt.print_int_label),
            ("read_char", self.rt.read_char_label),
            ("flush_io", self.rt.flush_io_label),
        ):
            print(f"  {name:<16}0x{IMAGE_BASE + layout['text']['rva'] + label.offset:016x}", file=file)
        for fn in (name for funcs in IMPORTS.values() for name in funcs):
            print(f"  IAT {fn:<18}0x{va('idata', ('iat', fn)):016x}", file=file)


def compile_file(src_path, out_path, verbose=False, dump_map=False):
    with open(src_path, "rb") as f:
        source = f.read()

    rt = Runtime()
    compiler = FalseCompiler(rt, source, verbose=verbose)
    compiler.compile_program()
    exe_bytes = rt.finalize()

    with open(out_path, "wb") as f:
        f.write(exe_bytes)

    if dump_map:
        compiler.print_map()

    if verbose:
        print(f"wrote {out_path} ({len(exe_bytes)} bytes)", file=sys.stderr)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="falsec.py",
        description="Compile a FALSE (.f) source file straight to a native "
                     "64-bit Windows executable (.exe), no linker required.",
    )
    ap.add_argument("source", help="FALSE source file, e.g. helloworld.f")
    ap.add_argument("-o", "--output", help="output .exe path (default: source with .exe extension)")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--map", dest="dump_map", action="store_true",
                     help="print the absolute address of every runtime symbol "
                          "and variable (for hand-writing NNN` inline assembly)")
    args = ap.parse_args(argv)

    out_path = args.output
    if not out_path:
        if args.source.lower().endswith(".f"):
            out_path = args.source[:-2] + ".exe"
        else:
            out_path = args.source + ".exe"

    try:
        compile_file(args.source, out_path, verbose=args.verbose, dump_map=args.dump_map)
    except FalseSyntaxError as e:
        print(f"falsec: compile error: {e}", file=sys.stderr)
        sys.exit(10)
    except OSError as e:
        print(f"falsec: {e}", file=sys.stderr)
        sys.exit(10)

    sys.exit(0)


if __name__ == "__main__":
    main()
