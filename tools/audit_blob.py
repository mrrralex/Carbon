#!/usr/bin/env python3
"""Carbon — precise self-containment audit of the injector's payload section.

Why not a byte scan
-------------------
The injector ships a cheap scan for `E8`/`E9` bytes whose rel32 lands outside the section, and it
reports candidates — but those bytes also occur *inside instruction operands*, so the scan cannot
decide. On the first build it reported one candidate while a real disassembly of the same section
found zero out-of-blob transfers. Reporting a false positive is survivable; the dangerous direction
is a false negative, so the check that actually gates injection is:

  1. this audit (a decoder walks the section and every call/jmp/rip-relative operand is resolved), and
  2. the injector's synthetic self-test, which *executes* every path of the payload in a fake image
     laid out at the real offsets — a stray call would fault there.

What the sweep must satisfy
---------------------------
The linear sweep from the payload entry must end EXACTLY at the end of the section. That invariant is
what makes the audit trustworthy: if any instruction were mis-decoded the stream would desync and the
final address would no longer match the section size. It is reported, not assumed.

Usage:
    python tools/audit_blob.py [path/to/injector.exe]
"""
import os
import sys

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import xref_pe as X   # noqa: E402  (shares the PE loader with the other tools)

DEFAULT_EXE = r"C:\Users\sargs\source\repos\Carbon\inject\bin\Release\injector.exe"
SECTION = ".cpl"


def main() -> int:
    exe = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_EXE
    pe = X.load_pe(exe)
    if pe is None:
        print(f"{exe} is not a PE")
        return 1
    data, base, sections = pe
    sec = next((s for s in sections if s["name"] == SECTION), None)
    if sec is None:
        print(f"no {SECTION} section in {exe} - the payload was not compiled into it")
        return 1

    off, size = sec["raw"], sec["vsize"]
    blob = data[off:off + size]
    lo, hi = base + sec["va"], base + sec["va"] + size
    print(f"{os.path.basename(exe)}: {SECTION} va=0x{sec['va']:x} file+0x{off:x} size={size} (0x{size:x})")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    insns = list(md.disasm(blob, lo))
    if not insns:
        print("  FAIL: nothing decoded")
        return 1
    end = insns[-1].address + insns[-1].size
    sweep_ok = (end == hi)
    print(f"  sweep      : {len(insns)} instructions, ends at +0x{end - lo:x} "
          f"({'exact' if sweep_ok else 'DESYNCED - audit not trustworthy'})")

    bad_calls, bad_branches, foreign = [], [], []
    for ins in insns:
        if ins.mnemonic in ("call", "jmp"):
            for op in ins.operands:
                if op.type == X86_OP_IMM and not (lo <= op.imm < hi):
                    (bad_calls if ins.mnemonic == "call" else bad_branches).append((ins, op.imm))
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = ins.address + ins.size + op.mem.disp
                if not (lo <= t < hi):
                    foreign.append((ins, t))

    for ins, t in bad_calls:
        print(f"  OUT-OF-BLOB call   @ +0x{ins.address - lo:x} -> 0x{t:x}")
    for ins, t in bad_branches:
        print(f"  OUT-OF-BLOB branch @ +0x{ins.address - lo:x} -> 0x{t:x}")
    for ins, t in foreign:
        print(f"  FOREIGN rip ref    @ +0x{ins.address - lo:x} {ins.mnemonic} {ins.op_str} -> 0x{t:x}")

    print(f"  result     : {len(bad_calls)} out-of-blob call(s), {len(bad_branches)} branch(es), "
          f"{len(foreign)} foreign rip-relative reference(s)")
    ok = sweep_ok and not bad_calls and not bad_branches and not foreign
    print("  verdict    : " + ("self-contained" if ok else "NOT self-contained - do not inject"))
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
