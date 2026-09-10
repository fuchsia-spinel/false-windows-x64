# falsec — a native x86-64 FALSE compiler for Windows

---

**Fuchsia's note:**

This exists because I wanted to mess with FALSE on Windows with inline assembly support (none of the existing interpreters seem to have this feature) without having to write the compiler myself. It's in Python because I figured Claude would be able to write it in Python fairly quickly and accurately, especially compared to a lot of other languages.

---

A compiler for Wouter van Oortmerssen's **FALSE** language
(<https://strlen.com/files/lang/false/false.txt>) that compiles
straight to a 64-bit Windows executable. There is no assembler,
linker, or Windows SDK involved anywhere in the pipeline: this Python
program hand-encodes x86-64 machine code, byte by byte, and writes it
directly into a PE32+ (`.exe`) image it also builds from scratch.

```
python3 falsec.py program.f          # -> program.exe
python3 falsec.py program.f -o out.exe -v --map
```

## Layout

| file          | purpose                                                          |
|---------------|-------------------------------------------------------------------|
| `asm_x64.py`  | tiny hand-rolled x86-64 instruction encoder (only what FALSE needs) |
| `pe_writer.py`| minimal PE32+ image builder (sections, imports, `.pdata`/`.xdata`) |
| `runtime.py`  | the fixed runtime every program links against: Win32 imports, data layout, `write_buffer`/`write_char`/`print_int`/`read_char`/`flush_io` |
| `falsec.py`   | the FALSE lexer + single-pass code generator + CLI |
| `emutest.py`  | a [Unicorn](https://www.unicorn-engine.org/)-based test harness that runs a compiled program's actual machine code directly, with Python stand-ins for GetStdHandle/ReadFile/WriteFile/ExitProcess — useful for checking a program's behavior without a Windows machine |
| `examples/`   | sample `.f` programs |

## How it works, briefly

FALSE is compiled the way its own 1993 compiler compiled it: one
linear pass over the source, dispatching on each character as it's
read, recursing into `[...]` blocks. There's no AST. Each FALSE
operator emits a short, fixed instruction sequence:

* The **FALSE data stack** is a plain array in memory; **R15** always
  points one-past its top (`[R15-8]` is top-of-stack). Push is
  `mov [r15],reg` / `add r15,8`; pop is `sub r15,8` / `mov reg,[r15]`.
  R15 is a callee-saved register under the Windows x64 ABI, so it
  survives calls into Win32 functions untouched.
* A `[...]` block compiles to a jump-over-it followed by its body and
  a `ret`; the block's address (computed with a RIP-relative `lea`) is
  what gets pushed as its "function value". `!` is just an indirect
  `call`; `?` and `#` are a conditional call and a call/call/jump loop
  around two such addresses.
* Variables `a`-`z` are 8-byte cells in a fixed data table; the letter
  token pushes that cell's *address*, and `:`/`;` do the store/fetch.
* Every function (the runtime helpers, the program's top level, and
  every `[...]` block) gets an entry in `.pdata`/`.xdata` — the x64
  exception/unwind tables — because the Windows x64 ABI requires it
  for every non-leaf function, not just ones that actually throw.
* The image loads at a fixed, non-ASLR base (`0x140000000`) and every
  cross-section reference is RIP-relative, so no `.reloc` section is
  needed at all.

See the module docstring at the top of `falsec.py` for the full
language reference and the inline-assembly section below.

## Inline assembly

The original FALSE manual describes exactly one extension mechanism:

> syntax: `<integer>`\``
> any integer value 0..65535 followed by a backquote causes that
> 16-bit value to be put directly into the code. A series of
> backquoted values may allow you a primitive form of inline assembly.

This compiler keeps that mechanism **completely unchanged**. A run of
digits immediately followed by a backtick is not compiled as a stack
push — its 16-bit little-endian value is spliced verbatim into the
machine-code stream at that exact point, interleaved with whatever
ordinary FALSE operators surround it. Chaining several `NNN`` tokens
lets you hand-assemble arbitrary x86-64 bytes directly into the
program, exactly as chaining 68k opcode words did in 1993 — only the
instruction set (and so the bytes you'd write) is different now.

Register/ABI conventions for anyone hand-encoding bytes this way (the
x86-64 analogue of the manual's "A6=dosbase, A5=eval stack, ..."
table):

* **R15** — the FALSE stack pointer (see above). Preserved across any
  call.
* **RSP** — the ordinary native stack.
* RIP-relative addressing reaches every symbol the compiler manages
  (variables, string literals, the Win32 IAT, the runtime helpers)
  without needing to know the load address, because the image is
  never rebased. Run `falsec.py prog.f --map` to print the absolute
  address of every symbol for that specific compiled program.
* `call [rip+disp]` is how compiled code reaches `WriteFile`,
  `ReadFile`, `GetStdHandle`, `FlushFileBuffers`, `ExitProcess`.
* `call rel32` reaches the runtime's own helpers:
  `write_buffer(rcx=ptr,rdx=len)`, `write_char(rcx=byte)`,
  `print_int(rcx=value)`, `read_char()->rax`, `flush_io()`. `--map`
  prints their addresses too.

As in the original, this does zero validation: you can absolutely
corrupt the surrounding code and crash the compiled program if you
don't balance things correctly. That's the deal.

Worked example — hand-encoding `add qword [r15-8], 5` (opcode bytes
`49 81 47 F8 05 00 00 00`) to bump the current stack top by 5 from
inside a FALSE program:

```
10 33097`63559`5`0` .        {prints 15}
```

### Calling a real Win32 function: MessageBoxW

The runtime only puts `KERNEL32.dll` in the import table by default,
but `IMPORTS` in `runtime.py` is just a `{dll: [functions]}` dict —
add an entry and `rt.iat("YourFunction")` works from inline assembly
exactly like the built-in calls do. `examples/messagebox.f` does this
for `USER32.dll!MessageBoxW`; `runtime.py` already lists it.

The interesting part is that a hand-typed `.f` file has no way to ask
the compiler to allocate rdata for you — `"..."` strings and their
bookkeeping only exist because the *compiler* calls into that
machinery when it sees a quote character; raw `NNN`` bytes can't
trigger it. So the two wide-character strings MessageBoxW needs live
*inline in the code stream*, right after a short jump that hops over
them — the classic hand-assembly trick — and are reached with
ordinary RIP-relative `lea`, computed from a fixed, local offset that
never depends on anything outside the block itself. The only address
that genuinely depends on the rest of the program is the IAT slot for
`MessageBoxW` itself, reached with `call [rip+disp32]` same as any
other Win32 call.

In practice nobody hand-computes 172 backtick tokens with a
calculator: the example was produced by writing the call once using
this project's own `Assembler` class (`push rbp` / `and rsp,-16` /
`lea` to a local label / `call` through the IAT / ...), letting it
resolve every displacement the normal way, then splitting the
resulting bytes into 16-bit words. That's a legitimate way to use the
feature — assemble with any tool you like, then paste the bytes in as
`NNN`` tokens — and it's exactly what real inline-assembly authors did
with the 68k version in 1993 too.

## Fidelity notes / deliberate deviations from the 1993 compiler

* Integers are full 64-bit. The original compiler's 320000 ceiling was
  a limitation of its tiny source buffer, not part of the language.
* "pick" and "flush" are two characters the manual could only render
  as a mangled placeholder — on the original Amiga keyboard they were
  Alt-O and Alt-S. This compiler accepts both common encodings people
  use for them today: Latin-1 (`0xF8` 'ø' for pick, `0xDF` 'ß' for
  flush) and their UTF-8 encodings, so source written either way just
  works.
* The one compile-time error the manual documents — "it found a
  symbol in the source which isn't part of the language" — is
  preserved verbatim, including the original's exit status: an
  unrecognised character aborts compilation and the process exits
  with status 10.

## Testing

Every operator (arithmetic, comparisons, bitwise ops, all five stack
shuffles including `pick`, variables, `[...]`/`!`/`?`/`#`, string/char
printing, `^` read, `ß` flush, and the `NNN`` inline-assembly splice)
was verified by running the actual compiled machine code in a Unicorn
CPU emulation (`emutest.py`) with Python stand-ins for the five Win32
calls the runtime uses — this checks the generated code's logic
directly, independent of any particular Windows/Wine install. All of
the example programs produce the expected output under emulation.

Separately, the produced `.exe` files were checked structurally with
`pefile` (valid headers, non-overlapping sections, correctly resolved
imports) and their instruction encoding was spot-checked against
`objdump` disassembly.

I was not able to get a fully clean run under this sandbox's Wine
install: very short-lived processes — including a trivial reference
"hello world" built with real `mingw-w64` and even *unmodified* mingw
output that I patched by a single byte — reproducibly fault deep
inside Wine's own `ntdll` during process teardown, strictly *after*
the program has already produced correct output and called
`ExitProcess` correctly (confirmed via `WINEDEBUG=+seh` register
dumps showing only Wine-internal state, none of the process's own).
That points at a Wine-specific edge case in this headless container
rather than at the generated executables, but I haven't been able to
confirm the programs run cleanly on real Windows, so treat that as
outstanding verification if it matters for your use case.
