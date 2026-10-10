# Carbon -- read a minidump and say *where* it died, in module+offset, not in bare hex.
#
# Why: crashpad uploads the client's minidump and deletes the local copy, so the dumps we get to keep
# are the ones we write ourselves (tools/dump_client.ps1, tools/dbgwatch.py --dump) and the ones
# crashpad failed to upload (AppData\Local\Roblox\logs\crashes\reports\*.dmp). All of them are the same
# format, and the interesting content is always the same three streams:
#
#   ExceptionStream  - if the dump was taken at a fault: code, faulting address, faulting thread and
#                      that thread's CONTEXT (RIP/RSP), which is the answer to "where did it die"
#   ThreadListStream - every thread's CONTEXT, plus its stack's location in the dump
#   ModuleListStream - the mapping that turns an address into name+offset
#
# Stack scanning matters because a fault is often not on the thread that started it: MiniDumpNormal
# carries the memory of each thread's stack, so the return addresses still on it (any 8-byte word that
# lands inside a module's image) are the call path that led there.
#
#   python tools/dmp_read.py <file.dmp> [--stacks] [--all-threads] [--modules]
#
# A caveat worth knowing when reading its output: in the dumps WE write, the ExceptionStream's
# ExceptionAddress field can come back as 0 and its parameter array can belong to some other record,
# because dbghelp builds that record itself. The exception CODE and the CONTEXT (RIP/RSP/RBP) in that
# stream are correct, and the live watcher log prints the address and parameters straight from the
# debug event, so take the address from there and the RIP from here.

import argparse
import os
import struct
import sys
from datetime import datetime, timezone

THREAD_LIST = 3
MODULE_LIST = 4
MEMORY_LIST = 5
EXCEPTION_STREAM = 6
SYSTEM_INFO = 7
MEMORY64_LIST = 9

EXC_NAMES = {
    0xC0000005: "ACCESS_VIOLATION", 0xC000001D: "ILLEGAL_INSTRUCTION",
    0xC0000094: "INTEGER_DIVIDE_BY_ZERO", 0xC0000096: "PRIVILEGED_INSTRUCTION",
    0xC00000FD: "STACK_OVERFLOW", 0xC0000374: "HEAP_CORRUPTION",
    0xC0000409: "STACK_BUFFER_OVERRUN/__fastfail", 0xC0000602: "FAIL_FAST_EXCEPTION",
    0x80000003: "BREAKPOINT", 0x80000001: "GUARD_PAGE",
}
AV_ACCESS = {0: "READ", 1: "WRITE", 8: "EXECUTE"}

IMAGE_SCAN_LIMIT = 0x20000000  # an address this far past a module base is treated as that module's


class Dump:
    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        magic, self.version, nstreams, dirrva, checksum, self.timestamp, self.flags = \
            struct.unpack_from("<4sIIIIII", self.data, 0)
        if magic != b"MDMP":
            raise ValueError("not a minidump (magic %r)" % magic)
        self.streams = {}
        for i in range(nstreams):
            stype, size, rva = struct.unpack_from("<III", self.data, dirrva + 12 * i)
            self.streams.setdefault(stype, []).append((rva, size))

    def u32(self, off):
        return struct.unpack_from("<I", self.data, off)[0]

    def u64(self, off):
        return struct.unpack_from("<Q", self.data, off)[0]

    def modules(self):
        out = []
        for rva, _size in self.streams.get(MODULE_LIST, []):
            n = self.u32(rva)
            for i in range(n):
                base = rva + 4 + 108 * i
                img_base = self.u64(base)
                img_size = self.u32(base + 8)
                name_rva = self.u32(base + 20)
                nlen = self.u32(name_rva)
                name = self.data[name_rva + 4:name_rva + 4 + nlen].decode("utf-16-le", "replace")
                out.append((img_base, img_size, os.path.basename(name)))
        return out

    def threads(self):
        out = []
        for rva, _size in self.streams.get(THREAD_LIST, []):
            n = self.u32(rva)
            for i in range(n):
                t = rva + 4 + 48 * i
                tid = self.u32(t)
                stack_start = self.u64(t + 16)
                stack_size = self.u32(t + 24)
                stack_rva = self.u32(t + 28)
                ctx_size = self.u32(t + 40)
                ctx_rva = self.u32(t + 44)
                ctx = self.data[ctx_rva:ctx_rva + ctx_size] if ctx_rva else b""
                out.append({"tid": tid, "stack": (stack_start, stack_size, stack_rva),
                            "ctx": ctx})
        return out

    def exception(self):
        """(thread_id, code, address, nparams, params, context_bytes) or None."""
        for rva, size in self.streams.get(EXCEPTION_STREAM, []):
            tid = self.u32(rva)
            code = self.u32(rva + 8)
            addr = self.u64(rva + 16)
            nparams = self.u32(rva + 24)
            params = [self.u64(rva + 32 + 8 * i) for i in range(min(nparams, 15))]
            ctx_size = self.u32(rva + 160)
            ctx_rva = self.u32(rva + 164)
            ctx = self.data[ctx_rva:ctx_rva + ctx_size] if ctx_rva else b""
            return tid, code, addr, nparams, params, ctx
        return None

    def stack_bytes(self, thread):
        _start, size, rva = thread["stack"]
        return self.data[rva:rva + size] if rva and size else b""

    def any_memory(self):
        """start -> bytes, from whichever memory stream the dump was written with."""
        out = {}
        for rva, _size in self.streams.get(MEMORY64_LIST, []):
            nranges = self.u64(rva)
            base_rva = self.u64(rva + 8)
            off = base_rva
            for i in range(nranges):
                start = self.u64(rva + 16 + 16 * i)
                size = self.u64(rva + 24 + 16 * i)
                out[start] = self.data[off:off + size]
                off += size
        for rva, _size in self.streams.get(MEMORY_LIST, []):
            n = self.u32(rva)
            for i in range(n):
                e = rva + 4 + 16 * i
                start = self.u64(e)
                size = self.u32(e + 8)
                mrva = self.u32(e + 12)
                out[start] = self.data[mrva:mrva + size]
        return out


def rip_of(chunk, rsp_off=152, rbp_off=160, rip_off=248):
    if len(chunk) >= rip_off + 8:
        return (struct.unpack_from("<Q", chunk, rip_off)[0],
                struct.unpack_from("<Q", chunk, rsp_off)[0],
                struct.unpack_from("<Q", chunk, rbp_off)[0])
    return None, None, None


def describe(addr, mods):
    for base, size, name in mods:
        if base <= addr < base + size:
            return "%s+0x%x" % (name, addr - base)
    for base, size, name in mods:
        if base <= addr < base + IMAGE_SCAN_LIMIT:
            return "%s+0x%x (size unknown)" % (name, addr - base)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("--stacks", action="store_true", help="scan each thread's stack for return addresses")
    ap.add_argument("--all-threads", action="store_true", help="list every thread, not just interesting ones")
    ap.add_argument("--modules", action="store_true", help="list the module map")
    args = ap.parse_args()

    d = Dump(args.dump)
    mods = d.modules()
    threads = d.threads()

    print("dump    : %s (%d bytes)" % (args.dump, len(d.data)))
    print("written : %s   flags 0x%x   %d streams" % (
        datetime.fromtimestamp(d.timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ UTC"),
        d.flags, sum(len(v) for v in d.streams.values())))
    print("modules : %d   threads: %d" % (len(mods), len(threads)))
    main = [m for m in mods if m[2].lower().startswith(("robloxplayerbeta", "faultchild", "injector"))]
    for base, size, name in main:
        print("image   : %-28s base 0x%016x size 0x%x" % (name, base, size))

    exc = d.exception()
    if exc:
        tid, code, addr, nparams, params, ctx = exc
        label = EXC_NAMES.get(code, "?")
        print("\nEXCEPTION in thread %d : 0x%08x (%s)" % (tid, code, label))
        print("  address : %s" % (describe(addr, mods) or "0x%016x (no module)" % addr))
        if code == 0xC0000005 and nparams >= 2:
            print("  access  : %s at 0x%x" % (AV_ACCESS.get(params[0], "?%d" % params[0]), params[1]))
        elif params:
            print("  params  : %s" % " ".join("0x%x" % p for p in params))
        rip, rsp, rbp = rip_of(ctx)
        if rip is not None:
            print("  register: rip %s" % (describe(rip, mods) or "0x%016x" % rip))
            print("            rsp 0x%016x  rbp 0x%016x" % (rsp, rbp))
        # the faulting thread's own stack, even when its registers are elsewhere by dump time
        for t in threads:
            if t["tid"] == tid:
                scan(t, mods, d, "  faulting thread stack")
    else:
        print("\nno ExceptionStream: this dump was taken outside a fault (deliberate dump, or the\n"
              "exception was already handled), so only the thread states are meaningful.")

    hot = []
    for t in threads:
        rip, rsp, rbp = rip_of(t["ctx"])
        if rip is None:
            continue
        where = describe(rip, mods)
        t["where"] = where
        t["rip"] = rip
        t["rsp"] = rsp
        # a thread parked in a module that is not ntdll/kernel32 is doing real work; those are the
        # ones worth naming. ntdll waits are the 100 sleeping threads of any client.
        interesting = where and not where.lower().startswith(("ntdll", "win32u", "kernel32"))
        if interesting or args.all_threads:
            hot.append(t)
    print("\nthreads with a rip outside ntdll/kernel32: %d of %d" % (len(hot), len(threads)))
    for t in sorted(hot, key=lambda t: t["tid"]):
        print("  tid %-6d rip %-46s rsp 0x%016x" % (t["tid"], t.get("where") or "0x%016x" % t["rip"], t["rsp"]))
        if args.stacks:
            scan(t, mods, d, "    ")

    if args.modules:
        print("\nmodules (%d):" % len(mods))
        for base, size, name in sorted(mods, key=lambda m: m[0]):
            print("  0x%016x  %10d  %s" % (base, size, name))


def scan(thread, mods, dump, indent):
    """Every 8-byte word on the stack that lands inside an image is a return address; naming them in
    order (outermost first) is the call path that led to this thread's state."""
    blob = dump.stack_bytes(thread)
    if not blob:
        print("%s  (no stack bytes in this dump)" % indent)
        return
    start = thread["stack"][0]
    hits = []
    for off in range(0, len(blob) - 8, 8):
        v = struct.unpack_from("<Q", blob, off)[0]
        # Strictly inside an image. The looser test (anything within 0x10000000 of a base) is right
        # for naming a fault address, where the module map may be incomplete, but on a stack it turns
        # every heap pointer that happens to follow a module base into a fake return address: the
        # first version of this listed 41 "return addresses" for a program with a 4-frame stack.
        where = None
        for base, size, name in mods:
            if base < v < base + size:
                where = "%s+0x%x" % (name, v - base)
                break
        if where and not where.startswith(("ntdll", "win32u")):
            hits.append((start + off, where))
    if not hits:
        print("%s  (no return addresses into a non-ntdll image on this stack)" % indent)
        return
    print("%s  stack: %d candidate return addresses, innermost first:" % (indent, len(hits)))
    for addr, where in hits[:40]:
        print("%s    0x%016x  %s" % (indent, addr, where))
    if len(hits) > 40:
        print("%s    ... %d more" % (indent, len(hits) - 40))


if __name__ == "__main__":
    sys.exit(main())
