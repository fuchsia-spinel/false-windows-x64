"""
pe_writer.py -- builds a minimal, self-contained PE32+ (.exe) image for
64-bit Windows directly from raw bytes, with no external linker.

Design notes
------------
* No ASLR / no relocation table: the image is loaded at a fixed
  preferred ImageBase (0x140000000, the normal default for 64-bit
  EXEs) and every cross-section reference the compiler emits is
  RIP-relative, so no .reloc section is required. This keeps the
  writer small at the cost of relying on that base address being
  free (true for the overwhelming majority of processes).
* Four sections: .text (code), .rdata (string literals), .idata
  (import directory/IAT for kernel32.dll -- kept read+write, which
  is where the loader patches in resolved addresses), .data
  (variables table, I/O scratch buffers, the FALSE evaluation
  stack). .data's FALSE-stack region is virtual-only (zero-filled
  by the loader) so it doesn't bloat the file.
"""

import struct

IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
IMAGE_FILE_RELOCS_STRIPPED = 0x0001

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

CHAR_TEXT = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
CHAR_RDATA = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
CHAR_RWDATA = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE

IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020

SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200
IMAGE_BASE = 0x0000000140000000


def _align(value, align):
    return (value + align - 1) // align * align


def _pad(b, align):
    while len(b) % align:
        b.append(0)


class Region:
    """One section's content blob plus a symbol table of local offsets."""

    def __init__(self, name, characteristics, extra_virtual=0):
        self.name = name
        self.characteristics = characteristics
        self.buf = bytearray()
        self.symtab = {}
        self.extra_virtual = extra_virtual  # zero-filled tail (not in file)

    def here(self):
        return len(self.buf)

    def add(self, data, key=None):
        off = len(self.buf)
        self.buf += data
        if key is not None:
            self.symtab[key] = off
        return off

    def mark(self, key):
        self.symtab[key] = len(self.buf)

    def align(self, n=8):
        while len(self.buf) % n:
            self.buf.append(0)


class PEImage:
    def __init__(self):
        self.regions = {}
        self.fixups = []  # (patch_region, patch_off, kind, target_region, target_key, instr_end_off)
        self.entry = None  # (region_name, local_offset)

    def region(self, name, characteristics, extra_virtual=0):
        r = Region(name, characteristics, extra_virtual)
        self.regions[name] = r
        return r

    def add_text_fixups(self, text_region_name, asm):
        """Import an Assembler's extern_fixups (all RIP-relative)."""
        for patch_off, extref, instr_end_off in asm.extern_fixups:
            self.fixups.append(
                (text_region_name, patch_off, "riprel", extref.kind, extref.key, instr_end_off)
            )

    def add_riprel_fixup(self, patch_region, patch_off, target_region, target_key, instr_end_off):
        self.fixups.append((patch_region, patch_off, "riprel", target_region, target_key, instr_end_off))

    def add_absrva_fixup(self, patch_region, patch_off, target_region, target_key):
        self.fixups.append((patch_region, patch_off, "absrva", target_region, target_key, None))

    def set_entry(self, region_name, local_offset):
        self.entry = (region_name, local_offset)

    # ------------------------------------------------------------------

    def build(self):
        order = [n for n in ("text", "rdata", "pdata", "xdata", "idata", "data") if n in self.regions]
        section_headers_size = 40 * len(order)
        header_size = 0x40 + 4 + 20 + 240 + section_headers_size
        size_of_headers = _align(header_size, FILE_ALIGNMENT)

        # ---- lay out sections (RVA + file offset) -----------------------
        layout = {}
        rva = SECTION_ALIGNMENT
        file_off = size_of_headers
        for name in order:
            r = self.regions[name]
            raw_size = _align(len(r.buf), FILE_ALIGNMENT)
            virt_size = len(r.buf) + r.extra_virtual
            layout[name] = dict(rva=rva, raw_size=raw_size, virt_size=virt_size,
                                 file_off=file_off if raw_size else 0)
            rva += _align(max(virt_size, 1), SECTION_ALIGNMENT)
            file_off += raw_size
        size_of_image = _align(rva, SECTION_ALIGNMENT)
        self.last_layout = layout  # exposed for --map style introspection

        # ---- resolve fixups ----------------------------------------------
        for patch_region, patch_off, kind, target_region, target_key, instr_end_off in self.fixups:
            tgt = layout[target_region]["rva"] + self.regions[target_region].symtab[target_key]
            buf = self.regions[patch_region].buf
            if kind == "riprel":
                instr_end_rva = layout[patch_region]["rva"] + instr_end_off
                val = tgt - instr_end_rva
                struct.pack_into("<i", buf, patch_off, val)
            elif kind == "absrva":
                struct.pack_into("<I", buf, patch_off, tgt & 0xFFFFFFFF)
            else:
                raise ValueError(kind)

        # ---- assemble the file --------------------------------------------
        out = bytearray()

        # DOS header (64 bytes): just e_magic + e_lfanew, rest zero.
        dos = bytearray(0x40)
        dos[0:2] = b"MZ"
        struct.pack_into("<I", dos, 0x3C, 0x40)
        out += dos

        out += b"PE\x00\x00"

        n_sections = len(order)
        coff = struct.pack(
            "<HHIIIHH",
            IMAGE_FILE_MACHINE_AMD64,
            n_sections,
            0,  # TimeDateStamp
            0,  # PointerToSymbolTable
            0,  # NumberOfSymbols
            240,  # SizeOfOptionalHeader
            IMAGE_FILE_RELOCS_STRIPPED | IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE,
        )
        out += coff

        entry_rva = layout[self.entry[0]]["rva"] + self.entry[1]
        text_rva = layout.get("text", {}).get("rva", 0)
        text_raw = len(self.regions["text"].buf) if "text" in self.regions else 0
        size_of_init_data = sum(layout[n]["raw_size"] for n in order if n != "text")

        data_dirs = [(0, 0)] * 16
        if "pdata" in self.regions:
            data_dirs[3] = (layout["pdata"]["rva"], len(self.regions["pdata"].buf))
        if "idata" in self.regions:
            idata = self.regions["idata"]
            idd_rva = layout["idata"]["rva"] + idata.symtab["import_dir"]
            idd_size = idata.symtab["import_dir_end"] - idata.symtab["import_dir"]
            data_dirs[1] = (idd_rva, idd_size)
            iat_rva = layout["idata"]["rva"] + idata.symtab["iat"]
            iat_size = idata.symtab["iat_end"] - idata.symtab["iat"]
            data_dirs[12] = (iat_rva, iat_size)

        opt = bytearray()
        opt += struct.pack("<H", 0x20B)          # Magic (PE32+)
        opt += struct.pack("<BB", 1, 0)           # Linker version
        opt += struct.pack("<I", text_raw)        # SizeOfCode
        opt += struct.pack("<I", size_of_init_data)
        opt += struct.pack("<I", 0)               # SizeOfUninitializedData
        opt += struct.pack("<I", entry_rva)
        opt += struct.pack("<I", text_rva)        # BaseOfCode
        opt += struct.pack("<Q", IMAGE_BASE)
        opt += struct.pack("<I", SECTION_ALIGNMENT)
        opt += struct.pack("<I", FILE_ALIGNMENT)
        opt += struct.pack("<HH", 6, 0)           # OS version
        opt += struct.pack("<HH", 0, 0)           # Image version
        opt += struct.pack("<HH", 6, 0)           # Subsystem version
        opt += struct.pack("<I", 0)               # Win32VersionValue
        opt += struct.pack("<I", size_of_image)
        opt += struct.pack("<I", size_of_headers)
        opt += struct.pack("<I", 0)               # CheckSum
        opt += struct.pack("<H", IMAGE_SUBSYSTEM_WINDOWS_CUI)
        opt += struct.pack("<H", IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        opt += struct.pack("<Q", 0x100000)        # SizeOfStackReserve
        opt += struct.pack("<Q", 0x1000)          # SizeOfStackCommit
        opt += struct.pack("<Q", 0x100000)        # SizeOfHeapReserve
        opt += struct.pack("<Q", 0x1000)          # SizeOfHeapCommit
        opt += struct.pack("<I", 0)               # LoaderFlags
        opt += struct.pack("<I", 16)              # NumberOfRvaAndSizes
        for drva, dsize in data_dirs:
            opt += struct.pack("<II", drva, dsize)
        assert len(opt) == 240, len(opt)
        out += opt

        for name in order:
            r = self.regions[name]
            lay = layout[name]
            nm = name.encode()
            if name == "text":
                nm = b".text"
            elif name == "rdata":
                nm = b".rdata"
            elif name == "pdata":
                nm = b".pdata"
            elif name == "xdata":
                nm = b".xdata"
            elif name == "idata":
                nm = b".idata"
            elif name == "data":
                nm = b".data"
            nm = nm[:8] + b"\x00" * (8 - len(nm[:8]))
            hdr = nm
            hdr += struct.pack("<I", lay["virt_size"])
            hdr += struct.pack("<I", lay["rva"])
            hdr += struct.pack("<I", lay["raw_size"])
            hdr += struct.pack("<I", lay["file_off"])
            hdr += struct.pack("<IIHH", 0, 0, 0, 0)
            hdr += struct.pack("<I", r.characteristics)
            assert len(hdr) == 40
            out += hdr

        _pad(out, FILE_ALIGNMENT)
        assert len(out) == size_of_headers

        for name in order:
            r = self.regions[name]
            lay = layout[name]
            body = bytearray(r.buf)
            _pad(body, FILE_ALIGNMENT)
            assert lay["file_off"] == len(out) or len(r.buf) == 0
            out += body

        return bytes(out)
