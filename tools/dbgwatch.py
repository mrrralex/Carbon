# Carbon -- watch a Roblox client from outside and record *how* it dies.
#
# Why this exists: the payload's own black box (a VEH in the target) recorded nothing, and by the
# time anyone looks, crashpad has uploaded the client's minidump and deleted the local copy. Nothing
# is left to read. A debugger attached to the client sees the fault *first*, with the exact code, the
# faulting address and its owning module+RVA, the thread's registers, every DLL loaded after attach,
# and finally the process exit code -- and it writes its own minidump at the moment of the fault, with
# the real exception pointers, which is a dump the client cannot upload away.
#
#   python tools/dbgwatch.py --pid 12716              # attach now, watch for 120 s
#   python tools/dbgwatch.py --wait-for-client        # attach as soon as a client appears
#   python tools/dbgwatch.py --pid 12716 --seconds 300 --dump
#
# The target's exit code -- 0xc0000005 (access violation), 0xc0000409 (fail fast), 0xc0000374 (heap
# corruption) or 0 (TerminateProcess / clean exit) -- is reported in the log and is the one fact that
# survives even when no exception was ever raised. This tool's own exit code is only about the tool:
# 0 = watched to the end, 2 = no such process, 3 = attach refused.
#
# NOTE: a process whose debugger exits is killed by Windows. The `finally` below detaches
# (DebugActiveProcessStop) so that never happens by accident, and --seconds is bounded by default.

import argparse
import ctypes
import ctypes.wintypes as wt
import os
import struct
import sys
import time
from datetime import datetime

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
MAX_MODULE_NAME32 = 255

THREAD_GET_CONTEXT = 0x0008
THREAD_QUERY_INFORMATION = 0x0040

CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x1
CONTEXT_INTEGER = CONTEXT_AMD64 | 0x2
CONTEXT_FULL_FLAGS = CONTEXT_CONTROL | CONTEXT_INTEGER

# Offsets inside the amd64 CONTEXT (winnt.h). Verified against the struct definition, not guessed:
# P1Home..P6Home (6*8) then ContextFlags at 48, and Rip after R15 at 248.
CTX_FLAGS_OFF = 48
CTX_RAX_OFF = 120
CTX_RCX_OFF = 128
CTX_RDX_OFF = 136
CTX_RSP_OFF = 152
CTX_RBP_OFF = 160
CTX_RIP_OFF = 248
CTX_SIZE = 1232

# The debug-event union starts after code/pid/tid + 4 bytes of padding. EXCEPTION_RECORD is 152
# bytes on x64, so dwFirstChance sits at 16+152.
EVT_UNION_OFF = 16
EXC_REC_SIZE = 152
EXC_CODE_OFF = 0
EXC_ADDR_OFF = 16
EXC_NPARAMS_OFF = 24
EXC_INFO_OFF = 32
EXC_FIRST_CHANCE_OFF = EVT_UNION_OFF + EXC_REC_SIZE


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wt.DWORD),
        ("hModule", wt.HMODULE),
        ("szModule", ctypes.c_char * (MAX_MODULE_NAME32 + 1)),
        ("szExePath", ctypes.c_char * wt.MAX_PATH),
    ]


# dbghelp.h declares this packed to 4, and the difference is not cosmetic: with the default 8-byte
# alignment it is 24 bytes instead of 16, dbghelp reads the ThreadId/pointer/flag fields from the
# wrong offsets, and MiniDumpWriteDump fails with 0x800703E6 ERROR_NOACCESS and writes a 0-byte file.
# Measured both ways (tools/_dumpprobe.py, since deleted): pack4 + ClientPointers=FALSE is the
# combination that produces a dump carrying an ExceptionStream, and its context RIP is the fault.
class MINIDUMP_EXCEPTION_INFORMATION(ctypes.Structure):
    _pack_ = 4
    _fields_ = [("ThreadId", wt.DWORD), ("ExceptionPointers", ctypes.c_void_p),
                ("ClientPointers", wt.BOOL)]


class EXCEPTION_POINTERS(ctypes.Structure):
    _fields_ = [("ExceptionRecord", ctypes.c_void_p), ("ContextRecord", ctypes.c_void_p)]


k32.DebugActiveProcess.argtypes = [wt.DWORD]
k32.DebugActiveProcess.restype = wt.BOOL
k32.DebugActiveProcessStop.argtypes = [wt.DWORD]
k32.DebugActiveProcessStop.restype = wt.BOOL
k32.WaitForDebugEvent.argtypes = [ctypes.c_void_p, wt.DWORD]
k32.WaitForDebugEvent.restype = wt.BOOL
k32.ContinueDebugEvent.argtypes = [wt.DWORD, wt.DWORD, wt.DWORD]
k32.ContinueDebugEvent.restype = wt.BOOL
k32.CloseHandle.argtypes = [wt.HANDLE]
k32.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.OpenThread.restype = wt.HANDLE
k32.GetThreadContext.argtypes = [wt.HANDLE, ctypes.c_void_p]
k32.GetThreadContext.restype = wt.BOOL

FIRST_CHANCE_EXC = {
    0x80000003: "breakpoint (initial debugger breakpoint or a real bp)",
    0xE06D7363: "C++ exception throw",
    0x406D1388: "SetThreadName",
    0x40010006: "OutputDebugString",
}
FATAL_EXC = {
    0xC0000005: "ACCESS_VIOLATION",
    0xC000001D: "ILLEGAL_INSTRUCTION",
    0xC0000094: "INTEGER_DIVIDE_BY_ZERO",
    0xC0000096: "PRIVILEGED_INSTRUCTION",
    0xC00000FD: "STACK_OVERFLOW",
    0xC0000374: "HEAP_CORRUPTION",
    0xC0000409: "STACK_BUFFER_OVERRUN / __fastfail",
    0xC0000602: "FAIL_FAST_EXCEPTION",
    0xC0000135: "DLL_NOT_FOUND",
    0xC0000142: "DLL_INIT_FAILED",
    0x80000001: "GUARD_PAGE",
    0x80000004: "SINGLE_STEP",
}


def client_pids():
    out = []
    for name in ("RobloxPlayerBeta.exe",):
        h = k32.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
        if h == -1:
            continue
        import ctypes.wintypes as _w

        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [("dwSize", _w.DWORD), ("cntUsage", _w.DWORD), ("th32ProcessID", _w.DWORD),
                        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)), ("th32ModuleID", _w.DWORD),
                        ("cntThreads", _w.DWORD), ("th32ParentProcessID", _w.DWORD),
                        ("pcPriClassBase", ctypes.c_long), ("dwFlags", _w.DWORD),
                        ("szExeFile", ctypes.c_char * _w.MAX_PATH)]

        pe = PROCESSENTRY32()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
        k32.Process32First.argtypes = [wt.HANDLE, ctypes.c_void_p]
        k32.Process32Next.argtypes = [wt.HANDLE, ctypes.c_void_p]
        if k32.Process32First(h, ctypes.byref(pe)):
            while True:
                if pe.szExeFile.decode(errors="replace").lower() == name.lower():
                    out.append(pe.th32ProcessID)
                if not k32.Process32Next(h, ctypes.byref(pe)):
                    break
        k32.CloseHandle(h)
    return out


def snapshot_modules(pid):
    """[(base, size, name)] -- the mapping used to turn a fault address into module!rva."""
    mods = []
    h = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if h == -1:
        return mods
    me = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(MODULEENTRY32)
    k32.Module32First.argtypes = [wt.HANDLE, ctypes.c_void_p]
    k32.Module32Next.argtypes = [wt.HANDLE, ctypes.c_void_p]
    if k32.Module32First(h, ctypes.byref(me)):
        while True:
            base = ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value or 0
            mods.append((base, me.modBaseSize, me.szModule.decode(errors="replace")))
            if not k32.Module32Next(h, ctypes.byref(me)):
                break
    k32.CloseHandle(h)
    return mods


IMAGE_SCAN_LIMIT = 0x10000000


def describe(addr, mods):
    for base, size, name in mods:
        if base and base <= addr < base + size:
            return "%s+0x%x (base 0x%x)" % (name, addr - base, base)
    # A module loaded after our snapshot that we have no entry for: never report "outside every
    # module" for an address that is really just newly mapped, because that reads like a wild
    # pointer when it may be the DLL the crash actually happened in.
    for base, size, name in mods:
        if base and base < addr < base + IMAGE_SCAN_LIMIT:
            return "%s+0x%x (size unknown)" % (name, addr - base)
    return "outside every known module"


def thread_regs(tid):
    h = k32.OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, False, tid)
    if not h:
        return None
    try:
        buf = ctypes.create_string_buffer(CTX_SIZE)
        struct.pack_into("<I", buf, CTX_FLAGS_OFF, CONTEXT_FULL_FLAGS)
        if not k32.GetThreadContext(h, buf):
            return None
        g = lambda off: struct.unpack_from("<Q", buf, off)[0]
        return {"rip": g(CTX_RIP_OFF), "rsp": g(CTX_RSP_OFF), "rbp": g(CTX_RBP_OFF),
                "rax": g(CTX_RAX_OFF), "rcx": g(CTX_RCX_OFF), "rdx": g(CTX_RDX_OFF)}
    finally:
        k32.CloseHandle(h)


def write_dump(pid, tid, exc_rec_bytes, ctx_bytes, path):
    """A minidump carrying the live exception, so tools/dmp_read.py can name the faulting RIP later.

    Two things here were found the hard way and must not be "simplified" back:
      * MINIDUMP_EXCEPTION_INFORMATION is packed to 4 (see the class), or dbghelp errors out with
        ERROR_NOACCESS and writes nothing at all.
      * ClientPointers stays FALSE. That reads like the opposite of what a debugger wants, but it is
        the combination that works: TRUE fails the call for any packing.
    """
    dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)
    dbghelp.MiniDumpWriteDump.argtypes = [wt.HANDLE, wt.DWORD, wt.HANDLE, wt.DWORD,
                                          ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    dbghelp.MiniDumpWriteDump.restype = wt.BOOL
    k32.OpenProcess.restype = wt.HANDLE
    k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    PROCESS_ALL = 0x1F0FFF
    h = k32.OpenProcess(PROCESS_ALL, False, pid)
    if not h:
        return "OpenProcess failed: %d" % ctypes.get_last_error()
    try:
        rec = ctypes.create_string_buffer(exc_rec_bytes, EXC_REC_SIZE)
        # The exception record's own `ExceptionRecord` link still points into the *target*, and with
        # ClientPointers=TRUE dbghelp follows it in OUR address space -- which is how it produced
        # 0x800703E6 ERROR_NOACCESS instead of a dump. A synthesized record has no chain, so the link
        # is cleared.
        struct.pack_into("<Q", rec, 8, 0)
        ctx = ctypes.create_string_buffer(ctx_bytes, CTX_SIZE)
        ep = EXCEPTION_POINTERS(ctypes.cast(rec, ctypes.c_void_p),
                                ctypes.cast(ctx, ctypes.c_void_p))
        mei = MINIDUMP_EXCEPTION_INFORMATION(tid, ctypes.cast(ctypes.byref(ep), ctypes.c_void_p), False)
        MiniDumpNormal, MiniDumpWithThreadInfo = 0x0, 0x1000
        import msvcrt
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_BINARY | os.O_TRUNC)
        try:
            # the CRT fd is not necessarily the Win32 handle dbghelp wants; get the real one
            fh = wt.HANDLE(msvcrt.get_osfhandle(fd))
            ok = dbghelp.MiniDumpWriteDump(h, pid, fh, MiniDumpNormal | MiniDumpWithThreadInfo,
                                           ctypes.byref(mei), None, None)
            if not ok:
                return "MiniDumpWriteDump failed: %d" % ctypes.get_last_error()
        finally:
            os.close(fd)
        return None
    finally:
        k32.CloseHandle(h)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--wait-for-client", action="store_true")
    ap.add_argument("--seconds", type=float, default=120.0)
    ap.add_argument("--dump", action="store_true", default=True)
    ap.add_argument("--no-dump", dest="dump", action="store_false")
    ap.add_argument("--outdir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "out"))
    ap.add_argument("--plain", action="store_true", help="no timestamps (for diffing)")
    ap.add_argument("--force", action="store_true",
                    help="attach to any pid, not just a Roblox client (used to test this tool)")
    args = ap.parse_args()

    def say(msg):
        line = msg if args.plain else "%s %s" % (datetime.now().strftime("%H:%M:%S.%f")[:-3], msg)
        print(line, flush=True)

    pid = args.pid
    if not pid and args.wait_for_client:
        say("waiting for a RobloxPlayerBeta process...")
        deadline = time.time() + args.seconds
        while time.time() < deadline:
            found = client_pids()
            if found:
                pid = found[0]
                break
            time.sleep(0.25)
        if not pid:
            say("no client appeared within %.0fs" % args.seconds)
            return 2
    if not pid:
        found = client_pids()
        if not found:
            say("no RobloxPlayerBeta process is running; pass --wait-for-client to wait for one")
            return 2
        pid = found[0]
    if pid not in client_pids() and not args.force:
        say("pid %d is not a RobloxPlayerBeta process" % pid)
        return 2

    os.makedirs(args.outdir, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    logpath = os.path.join(args.outdir, "dbgwatch_%d_%s.txt" % (pid, stamp))
    logf = open(logpath, "w", buffering=1)

    def emit(msg):
        say(msg)
        logf.write(msg + "\n")
        logf.flush()

    emit("=== dbgwatch pid %d, --seconds %.0f, first-chance exceptions are logged, not stopped ==="
         % (pid, args.seconds))
    mods = snapshot_modules(pid)
    emit("%d modules already loaded; the ones that matter:" % len(mods))
    for base, size, name in sorted(mods, key=lambda m: m[1], reverse=True)[:6]:
        emit("    %-28s base 0x%016x size 0x%x" % (name, base, size))

    if not k32.DebugActiveProcess(pid):
        err = ctypes.get_last_error()
        emit("DebugActiveProcess FAILED: win32 error %d (%s)"
             % (err, "access denied -- protected process" if err == 5 else "?"))
        logf.close()
        return 3
    emit("attached (DebugActiveProcess ok)")

    evt = ctypes.create_string_buffer(512)
    dirty = set()
    dumps = 0
    initial_bp_pending = True
    seen = {}       # (code, addr, tid) -> count, so a fault the target keeps re-taking cannot flood
    dumped = set()  # (code, addr, tid) already dumped at first chance
    deadline = time.time() + args.seconds
    exit_code = None
    wanted = set()
    try:
        while time.time() < deadline:
            if not k32.WaitForDebugEvent(evt, 250):
                if k32.GetLastError() not in (121, 258):  # ERROR_SEM_TIMEOUT, WAIT_TIMEOUT
                    emit("WaitForDebugEvent failed: %d" % ctypes.get_last_error())
                    break
                continue
            code, dpid, tid = struct.unpack_from("<III", evt, 0)
            status = DBG_CONTINUE
            if code == EXCEPTION_DEBUG_EVENT:
                if dirty:
                    mods = snapshot_modules(pid)
                    dirty.clear()
                ecode = struct.unpack_from("<I", evt, EXC_REC_SIZE * 0 + EXC_CODE_OFF + EVT_UNION_OFF)[0]
                eaddr = struct.unpack_from("<Q", evt, EVT_UNION_OFF + EXC_ADDR_OFF)[0]
                nparams = struct.unpack_from("<I", evt, EVT_UNION_OFF + EXC_NPARAMS_OFF)[0]
                first = struct.unpack_from("<I", evt, EXC_FIRST_CHANCE_OFF)[0]
                params = [struct.unpack_from("<Q", evt, EVT_UNION_OFF + EXC_INFO_OFF + 8 * i)[0]
                          for i in range(min(nparams, 4))]
                label = FATAL_EXC.get(ecode) or FIRST_CHANCE_EXC.get(ecode) or "?"
                regs = thread_regs(tid)
                emit("EXC  code 0x%08x (%s) addr 0x%016x  %s" % (ecode, label, eaddr, describe(eaddr, mods)))
                if params:
                    emit("     params %s" % " ".join("0x%x" % p for p in params))
                if regs:
                    emit("     tid %d rip 0x%016x rip@%s" % (tid, regs["rip"], describe(regs["rip"], mods)))
                    emit("     rsp 0x%016x rbp 0x%016x rax 0x%016x rcx 0x%016x rdx 0x%016x"
                         % (regs["rsp"], regs["rbp"], regs["rax"], regs["rcx"], regs["rdx"]))
                key = (ecode, eaddr, tid)
                seen[key] = seen.get(key, 0) + 1
                emit("     %s chance%s" % ("first" if first else "SECOND (nobody handled it)",
                                          "  [repeat #%d]" % seen[key] if seen[key] > 1 else ""))
                # Continue semantics are the whole ballgame here. DBG_CONTINUE means "handled: resume
                # the thread where it faulted" -- which for a real fault re-executes the faulting
                # instruction and reports it again, forever. That is not a hypothetical: it is what
                # the first version of this tool did, and it turned one access violation into
                # thousands of first-chance events and never a second chance. The correct contract is
                # NOT_HANDLED for every fault (so the target's own handlers get their chance, and the
                # OS re-reports it to us as second chance when nobody does), and DBG_CONTINUE only for
                # the synthetic initial breakpoint, which is the debugger's own and must be stepped over.
                status = DBG_EXCEPTION_NOT_HANDLED
                if ecode == 0x80000003 and first and initial_bp_pending:
                    emit("     initial breakpoint: continuing it, this is not a fault")
                    initial_bp_pending = False
                    status = DBG_CONTINUE
                want_dump = args.dump and dumps < 3 and (
                    not first or (ecode in FATAL_EXC and key not in dumped))
                if want_dump:
                    dpath = os.path.join(args.outdir, "fault_%d_%s_%d.dmp" % (pid, stamp, dumps))
                    rec = evt.raw[EVT_UNION_OFF:EVT_UNION_OFF + EXC_REC_SIZE]
                    h = k32.OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, False, tid)
                    ctx = None
                    if h:
                        buf = ctypes.create_string_buffer(CTX_SIZE)
                        struct.pack_into("<I", buf, CTX_FLAGS_OFF, CONTEXT_FULL_FLAGS)
                        if k32.GetThreadContext(h, buf):
                            ctx = buf.raw
                        k32.CloseHandle(h)
                    if ctx:
                        err = write_dump(pid, tid, rec, ctx, dpath)
                        emit("     dump: %s" % (dpath if not err else "FAILED " + err))
                        if not err:
                            dumps += 1
                            dumped.add(key)
            elif code == LOAD_DLL_DEBUG_EVENT:
                hfile = struct.unpack_from("<Q", evt, EVT_UNION_OFF)[0]
                base = struct.unpack_from("<Q", evt, EVT_UNION_OFF + 8)[0]
                if hfile:
                    k32.CloseHandle(wt.HANDLE(hfile))  # or the image stays locked for the whole run
                if base:
                    wanted.add(base)
                    # Mark the mapping stale; re-snapshot lazily. Replacing the entry with a
                    # placeholder was the original bug: ntoskrnl-sized system DLLs re-load at a base
                    # we already knew, the placeholder (0x1000) then shadowed the real size, and the
                    # fault address came out "outside every known module" -- a false wild pointer.
                    dirty.add(base)
                emit("LOAD dll at 0x%016x" % base)
            elif code == EXIT_PROCESS_DEBUG_EVENT:
                exit_code = struct.unpack_from("<I", evt, EVT_UNION_OFF)[0]
                emit("EXIT process, exit code 0x%08x (%s)"
                     % (exit_code, FATAL_EXC.get(exit_code, "not an exception code")))
                k32.ContinueDebugEvent(dpid, tid, status)
                break
            elif code in (CREATE_PROCESS_DEBUG_EVENT,):
                hfile = struct.unpack_from("<Q", evt, EVT_UNION_OFF)[0]
                if hfile:
                    k32.CloseHandle(wt.HANDLE(hfile))
            if not k32.ContinueDebugEvent(dpid, tid, status):
                emit("ContinueDebugEvent failed: %d" % ctypes.get_last_error())
                break
    finally:
        # A process is killed when its debugger goes away, so always let go of it explicitly.
        if k32.DebugActiveProcessStop(pid):
            emit("detached (DebugActiveProcessStop ok)")
        else:
            emit("detach failed: %d" % ctypes.get_last_error())
        emit("=== dbgwatch done, log: %s ===" % logpath)
        logf.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
