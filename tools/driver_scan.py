"""Carbon - read a kernel driver's dispatch surface before ever loading it.

Why this exists: RING0.md lists `gdrv3.sys` (Gigabyte, installed, stopped) as the one remaining
"no WDK, no reboot" route to a physical-memory primitive, and notes that a high-bit immediate sweep
did NOT turn up the gdrv family's classic IOCTL codes. That is not a verdict - it only means those
specific constants are absent. Deciding "is this driver a memory primitive" needs three things read
off the file, and this tool prints exactly those:

  1. what it IMPORTS. A driver that never touches physical memory cannot be one: look for
     `MmMapIoSpace`/`MmMapIoSpaceEx`, `ZwMapViewOfSection`, `ZwOpenSection`, `MmGetPhysicalMemoryRanges`,
     `MmMapLockedPagesSpecifyCache`, and the `\\Device\\PhysicalMemory` string.
  2. where its IRP_MJ_DEVICE_CONTROL handler lives. x64 `DRIVER_OBJECT.MajorFunction` starts at +0x70
     and each entry is 8 bytes, so IRP_MJ_DEVICE_CONTROL (0x0E) is a store to `[reg+0xE0]` and
     IRP_MJ_CREATE (0x00) a store to `[reg+0x70]`.
  3. what codes its handlers COMPARE against. Every `cmp/mov <reg>, imm32` with the high bit set is a
     candidate IOCTL code; they are printed with their RVA so the dispatch can be read, not guessed.

Everything here is a static read of a file on disk. Nothing is loaded, installed, started or called.
Usage: python tools/driver_scan.py C:\\Windows\\System32\\drivers\\gdrv3.sys
"""
import argparse
import struct
import sys

# a driver's own strings are not guaranteed ASCII; printing one must not kill the scan
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

MEM_IMPORTS = (
    "MmMapIoSpace", "MmUnmapIoSpace", "MmGetPhysicalMemoryRanges", "MmMapLockedPages",
    "MmMapLockedPagesSpecifyCache", "ZwMapViewOfSection", "ZwOpenSection", "ZwUnmapViewOfSection",
    "MmCopyMemory", "MmGetVirtualForPhysical", "MmAllocateContiguousMemory",
    "ObReferenceObjectByHandle", "ZwAllocateVirtualMemory", "MmIsAddressValid",
)


def load_pe(path):
    with open(path, "rb") as f:
        data = f.read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    nsec, optsz = struct.unpack_from("<HH", data, coff + 2)[0], struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != 0x20B:
        sys.exit(f"not a PE32+ image (magic 0x{magic:x}) - kernel drivers on x64 are PE32+")
    image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    entry = struct.unpack_from("<I", data, opt + 16)[0]
    # data directories start 0x70 into the optional header; #0 export, #1 import
    dir_import_rva, dir_import_size = struct.unpack_from("<II", data, opt + 0x78)
    sections = []
    sect = opt + optsz
    for i in range(nsec):
        s = data[sect + i * 40: sect + (i + 1) * 40]
        name = s[:8].rstrip(b"\0").decode(errors="replace")
        vsize, va, rsize, raw = struct.unpack_from("<IIII", s, 8)
        chars = struct.unpack_from("<I", s, 36)[0]
        sections.append(dict(name=name, va=va, vsize=vsize, rsize=rsize, raw=raw, chars=chars))
    return data, image_base, entry, sections, (dir_import_rva, dir_import_size)


def rva_to_off(sections, rva):
    for s in sections:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["rsize"]):
            return s["raw"] + (rva - s["va"])
    return None


def exec_sections(sections):
    return [s for s in sections if s["chars"] & 0x20000000]


def imports(data, sections, ddir):
    """Return (names, iat_map): module->[names], and {rva_of_iat_slot: 'module!name'}."""
    out, iat = {}, {}
    dir_rva, dir_size = ddir
    if not dir_size:
        return out, iat
    off = rva_to_off(sections, dir_rva)
    if off is None:
        return out, iat
    k = 0
    while True:
        desc = data[off + k * 20: off + (k + 1) * 20]
        if len(desc) < 20 or desc == b"\0" * 20:
            break
        oft, _, _, name_rva, first_thunk = struct.unpack_from("<IIIII", desc)
        noff = rva_to_off(sections, name_rva)
        dll = data[noff:data.find(b"\0", noff)].decode("ascii", "replace") if noff is not None else "?"
        names = []
        walk = oft or first_thunk
        t = rva_to_off(sections, walk)
        slot = 0
        while t is not None:
            ent = struct.unpack_from("<Q", data, t + slot * 8)[0]
            if ent == 0:
                break
            if not (ent & 0x8000000000000000):     # by name
                hoff = rva_to_off(sections, ent)
                if hoff is None:
                    break
                nm = data[hoff + 2:data.find(b"\0", hoff + 2)].decode("ascii", "replace")
                names.append(nm)
                iat[first_thunk + slot * 8] = f"{dll}!{nm}"
            else:
                names.append(f"ordinal#{ent & 0xffff}")
            slot += 1
        out[dll] = names
        k += 1
    return out, iat


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("driver")
    ap.add_argument("--window", default="0x4000", help="bytes of .text to decode (hex)")
    args = ap.parse_args()

    data, image_base, entry, sections, ddir = load_pe(args.driver)
    print(f"image {args.driver}")
    print(f"  image base 0x{image_base:x}, entry rva 0x{entry:x}, {len(sections)} sections")
    for s in sections:
        kind = " EXEC" if s["chars"] & 0x20000000 else ""
        print(f"  {s['name']:<9} va 0x{s['va']:<8x} vsize 0x{s['vsize']:<8x} raw 0x{s['rsize']:<8x}{kind}")

    imps, iat = imports(data, sections, ddir)
    print("\nimports:")
    for dll, names in sorted(imps.items()):
        print(f"  {dll}: {len(names)} entries")
    hits = sorted({n for names in imps.values() for n in names if n in MEM_IMPORTS})
    print(f"  memory-primitive imports: {hits if hits else 'NONE - no physical/virtual memory API at all'}")

    for needle in (b"\\Device\\PhysicalMemory", b"\\Device\\", b"\\DosDevices\\", b"\\??\\"):
        idx = data.find(needle)
        if idx >= 0:
            end = data.find(b"\0", idx)
            print(f"  device string at file+0x{idx:x}: {data[idx:end].decode('ascii', 'replace')!r}")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for s in exec_sections(sections):
        blob = data[s["raw"]: s["raw"] + s["rsize"]]
        if not blob:
            continue
        majors, codes = [], []
        for ins in md.disasm(blob, image_base + s["va"]):
            rva = ins.address - image_base
            for op in ins.operands:
                if op.type == X86_OP_MEM and 0x70 <= op.mem.disp <= 0x150 and op.mem.base:
                    slot = (op.mem.disp - 0x70) // 8
                    if (op.mem.disp - 0x70) % 8 == 0:
                        majors.append((rva, ins.mnemonic, ins.op_str, slot, op.mem.disp))
                if op.type == X86_OP_IMM and ins.mnemonic in ("cmp", "mov", "test", "and", "xor"):
                    v = op.imm & 0xFFFFFFFF
                    if 0x80000000 <= v <= 0xFFFFFFFF and ins.mnemonic in ("cmp", "mov"):
                        codes.append((rva, ins.mnemonic, ins.op_str))
                if ins.mnemonic == "call" and op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    tgt = ins.address + ins.size + op.mem.disp - image_base
                    if tgt in iat:
                        if iat[tgt] in [f"{d}!{n}" for d in imps for n in imps[d]] and \
                                any(x in iat[tgt] for x in MEM_IMPORTS):
                            print(f"  [EXEC] 0x{rva:x}  call {iat[tgt]}")
        if majors:
            print(f"\n  --- writes into a DRIVER_OBJECT MajorFunction slot [{s['name']}] ---")
            for rva, mn, ops, slot, disp in majors[:40]:
                print(f"    0x{rva:x}  {mn} {ops}    ; slot {slot}  (IRP_MJ_{slot:02x}), [reg+0x{disp:x}]")
        else:
            print(f"\n  --- no write into a MajorFunction slot found in [{s['name']}] ---")
        print(f"\n  --- high-bit immediates (candidate IOCTL codes) in [{s['name']}] ---")
        for rva, mn, ops in codes[:60]:
            print(f"    0x{rva:x}  {mn} {ops}")
        print(f"    ({len(codes)} total, {len(majors)} slot writes)")
        break


if __name__ == "__main__":
    main()
