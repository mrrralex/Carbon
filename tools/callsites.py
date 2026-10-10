"""Carbon phase 2 — wide call-site windows on the DECRYPTED image.

Why this exists
---------------
`xref_pe.py` reports 16 bytes of raw hex before each `call rel32` hit. That is enough to
see a `call`, but not enough to read the argument setup: it starts mid-instruction as
often as not (the first byte of a window is frequently the tail of a longer `mov`), and
it shows exactly the registers loaded in the last ~4 instructions — no more.

The LuaVM_Load contract question — which register carries the payload, which the chunk
name, what the two gate globals gate — is decided entirely by those few instructions,
so 16 bytes of hex is the wrong instrument. This tool prints a *decoded* window instead,
and refuses to print a window it cannot prove is in sync.

Method
------
For each call site at RVA `t` (the `E8` byte):
  1. candidate start points `s` run from `t - back` up to `t - 4`;
  2. a sweep from `s` is ACCEPTED only if the last two decoded instructions land as
     `... at t-? ; 0xE8 <rel32> at t` with the rel32 resolving to the target — i.e. the
     decoder walks *into* the call on the instruction boundary, not past it;
  3. the first accepted `s` wins (the longest run of instructions that reaches the call
     without a desync) and its full listing is printed.
So every printed window ends on the call, and any desync earlier in the window would have
been rejected rather than printed. `--check` still shows the ones that failed, because a
window that cannot be decoded cleanly is itself information (thunk tail, jump table, int3
padding).

Raw hex of the last `--hex` bytes is printed alongside, so a claim can be re-derived by
hand from the bytes even if a mnemonic is arguable.

Usage
-----
    python tools/callsites.py luavm_load
    python tools/callsites.py 0x4188af0 --back 0x140 --fwd 0x20
    python tools/callsites.py scriptctx_resume --limit 6 --check
"""
from __future__ import annotations

import argparse
import os
import sys

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

import xref_pe as X

try:  # single source of truth for the image path (refscan.py owns it)
    from refscan import IMAGE as DEFAULT_IMAGE
except Exception:  # pragma: no cover
    DEFAULT_IMAGE = ""

MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = False
SEC_EXECUTE = 0x20000000


def text_region(data, image_base, sections):
    """The executable .text-like region only (call sites cannot live elsewhere)."""
    out = []
    for name, vaddr, blob, is_exec in X.regions_pe(data, image_base, sections):
        if is_exec:
            out.append((name, vaddr, blob))
    return out


def find_calls(data, image_base, sections, target_rva):
    calls = []
    target_abs = image_base + target_rva
    for name, vaddr, blob in text_region(data, image_base, sections):
        i = 0
        n = len(blob)
        while i < n - 4:
            if blob[i] == 0xE8:
                import struct
                rel = struct.unpack_from("<i", blob, i + 1)[0]
                if vaddr + i + 5 + rel == target_abs:
                    calls.append((vaddr + i - image_base, name))
            i += 1
    return calls


def window(data, sections, image_base, site_rva, back, fwd, target_abs):
    """(start_rva, insns, sync_ok) for a decodable window ending exactly on the call."""
    off = X.rva_to_fileoff(sections, site_rva - back)
    if off is None:
        return None, [], False
    blob = data[off: off + back + 5 + fwd]
    scale = image_base + site_rva - back
    site_va = image_base + site_rva
    for s in range(0, max(1, back - 3)):
        # sweep exactly as far as the end of the call (that is the whole point: does the
        # decoder land ON the call, or walk past it?)
        insns = list(MD.disasm(blob[s:back - s + 5], scale + s))
        if len(insns) < 2:
            continue
        last, prev = insns[-1], insns[-2]
        if last.address == site_va and last.mnemonic == "call" \
                and prev.address + prev.size == site_va:
            return (site_rva - back + s), insns, True
    # no clean sync: report what the sweep from the requested start yields (up to the call)
    insns = list(MD.disasm(blob[:back + 5], scale))
    return (site_rva - back), insns, False


def main() -> int:
    ap = argparse.ArgumentParser(description="wide decoded windows around call sites (decrypted image)")
    ap.add_argument("target", nargs="?", help="target RVA (0x...) or a known name from xref_pe.TARGETS")
    ap.add_argument("--image", default=DEFAULT_IMAGE)
    ap.add_argument("--back", default="0xa0", help="how far before the call to start (hex, default 0xa0)")
    ap.add_argument("--fwd", default="0x20", help="how far after the call to keep (hex)")
    ap.add_argument("--at", default=None, metavar="RVA",
                    help="ignore call-site discovery: just decode a window starting at this RVA")
    ap.add_argument("--len", default="0x60", help="window length for --at (hex)")
    ap.add_argument("--limit", type=int, default=0, help="print at most N sites (0 = all)")
    ap.add_argument("--check", action="store_true", help="also list sites whose window failed sync")
    ap.add_argument("--hex", default="24", help="how many bytes of raw hex before the call to print")
    args = ap.parse_args()

    image = args.image
    if not os.path.exists(image):
        raise SystemExit(f"image not found: {image}\n  pass --image <path to *_decrypted.exe>")
    back, fwd, nhex = int(args.back, 16), int(args.fwd, 16), int(args.hex, 16)

    pe = X.load_pe(image)
    if pe is None:
        raise SystemExit(f"{image} is not a PE")
    data, image_base, sections = pe
    print(f"image {os.path.basename(image)}: {len(data)} bytes, base 0x{image_base:x}")
    if args.at is not None:
        at = int(args.at, 16)
        length = int(args.len, 16)
        off = X.rva_to_fileoff(sections, at)
        if off is None:
            raise SystemExit(f"RVA 0x{at:x} not file-backed")
        blob = data[off:off + length]
        print(f"window 0x{at:x}..0x{at + length:x} ({length} bytes)")
        for ins in MD.disasm(blob, image_base + at):
            print(f"     0x{ins.address - image_base:06x}:  {ins.bytes.hex():<24} {ins.mnemonic} {ins.op_str}")
        return 0
    if not args.target:
        raise SystemExit("need a target RVA/name, or --at <rva>")
    target_rva = X.parse_target(args.target)
    target_abs = image_base + target_rva
    calls = find_calls(data, image_base, sections, target_rva)
    print(f"target {args.target} rva 0x{target_rva:x}: {len(calls)} call site(s)\n")

    printed = 0
    unsynced = []
    for site_rva, secname in calls:
        if args.limit and printed >= args.limit:
            break
        start_rva, insns, ok = window(data, sections, image_base, site_rva, back, fwd, target_abs)
        off = X.rva_to_fileoff(sections, site_rva - nhex)
        raw = data[off: off + nhex + 5] if off is not None else b""
        print(f"--- CALL @ rva 0x{site_rva:x} [{secname}]  window 0x{start_rva:x}..0x{site_rva + fwd:x}"
              f"  {'SYNC OK' if ok else 'SYNC FAIL'}")
        print(f"    raw[:-{nhex}] {raw.hex(' ')}")
        if not ok:
            unsynced.append(site_rva)
            if not args.check:
                print("    (window rejected - not decoded; --check to see a best-effort listing)\n")
                continue
        for ins in insns:
            mark = ">>>" if ins.address == target_abs - target_rva + site_rva else "   "
            tag = ""
            if ins.address == image_base + site_rva:
                tag = f"   <- call 0x{target_rva:x}"
            print(f"  {mark} 0x{ins.address - image_base:06x}:  {ins.bytes.hex():<24} {ins.mnemonic} {ins.op_str}{tag}")
        printed += 1
        print()
    if unsynced and not args.check:
        print(f"{len(unsynced)} site(s) skipped for failed sync: "
              + ", ".join(f"0x{s:x}" for s in unsynced))
    return 0


if __name__ == "__main__":
    sys.exit(main())
