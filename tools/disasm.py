"""Carbon phase 2 — offline disassembly of key functions from the exe ON DISK.

Usage: python disasm.py [rva_hex] [length] ...
Default set: TLS_Slot_get, LuaVM_Load, ScriptContextResume, Luau_Execute.
Reads bytes from the file image (runtime page protection does not apply).
"""
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE = r"C:\Users\sargs\AppData\Local\Roblox\Versions\version-cec3ad5889b447cf\RobloxPlayerBeta.exe"

TARGETS = [
    ("TLS_Slot_get", 0x6BB0, 0x120),
    ("LuaVM_Load", 0x4188AF0, 0x300),
    ("ScriptContextResume", 0x423C6F0, 0x300),
    ("Luau_Execute", 0x25CB0D0, 0x100),
]


def load_pe(path):
    with open(path, "rb") as f:
        data = f.read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    image_base = struct.unpack_from("<Q", data, opt + 24)[0] if magic == 0x20B else None
    sect = opt + opt_size
    sections = []
    for i in range(nsec):
        s = data[sect + i * 40: sect + (i + 1) * 40]
        name = s[:8].rstrip(b"\0").decode(errors="replace")
        vsize, va, rsize, raw = struct.unpack_from("<IIII", s, 8)
        sections.append((name, va, vsize, raw, rsize))
    return data, image_base, sections


def rva_to_off(sections, rva):
    for name, va, vsize, raw, rsize in sections:
        if va <= rva < va + max(vsize, rsize):
            return raw + (rva - va), name
    return None, None


def disasm(name, rva, length, data, sections, image_base):
    off, sect = rva_to_off(sections, rva)
    print(f"\n=== {name}  RVA 0x{rva:x}  file+0x{'%x' % (off or 0)} [{sect}]  "
          f"vaddr 0x{image_base + rva:x}  ({length} bytes requested) ===")
    if off is None:
        print("  <RVA not in any section>")
        return
    blob = data[off: off + length]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    count = 0
    for insn in md.disasm(blob, image_base + rva):
        bytes_hex = insn.bytes.hex()
        print(f"  0x{insn.address:x}:  {bytes_hex:<30} {insn.mnemonic} {insn.op_str}")
        count += 1
        # stop at a few natural boundaries: we print a lot, caller can crop
        if count >= 160:
            print("  ... (cropped)")
            break


def main():
    if len(sys.argv) > 3 and sys.argv[1] == "--bin":
        # --bin file vaddr_hex : disassemble a raw dump whose first byte is at vaddr
        path = sys.argv[2]
        vaddr = int(sys.argv[3], 16)
        blob = open(path, "rb").read()
        print(f"=== dump {path}  {len(blob)} bytes @ 0x{vaddr:x} ===")
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for insn in md.disasm(blob, vaddr):
            print(f"  0x{insn.address:x}:  {insn.bytes.hex():<30} {insn.mnemonic} {insn.op_str}")
        return
    data, base, sections = load_pe(EXE)
    print(f"image base from PE: 0x{base:x}")
    if len(sys.argv) > 1:
        pairs = sys.argv[1:]
        for i in range(0, len(pairs), 2):
            rva = int(pairs[i], 16)
            ln = int(pairs[i + 1], 16) if i + 1 < len(pairs) else 0x200
            disasm(f"rva_{pairs[i]}", rva, ln, data, sections, base)
    else:
        for name, rva, ln in TARGETS:
            disasm(name, rva, ln, data, sections, base)


if __name__ == "__main__":
    main()
