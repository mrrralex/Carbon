# Carbon -- self-test for tools/dbgwatch.py, so the watcher is proven *without* a Roblox client.
#
# It spawns a child that raises an unhandled 0xC0000005 (the same code the client dies with), attaches
# the watcher to it, and checks that the watcher saw: the code, the module the fault address belongs to,
# the thread registers, a second-chance report, a minidump it wrote itself, and the exit code.
#
#   python tools/dbgwatch_selftest.py
#
# A green self-test means every part of the watcher that does not depend on Roblox works: attach,
# debug-event decode, thread contexts, RVA mapping, dump writing, and exit-code capture.

import ctypes
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WATCH = os.path.join(HERE, "dbgwatch.py")

# The victim is native on purpose. A Python child cannot prove this tool: CPython turns an access
# violation inside a ctypes call into a catchable OSError, so the fault never reaches second chance
# and no dump is ever written. tools/faultchild.exe (built by tools/build_faultchild.cmd) writes to
# an unmapped address in its own code, which is the same shape as the client's death.
VICTIM = os.path.join(HERE, "out", "faultchild.exe")

CHECKS = [
    ("saw the exception code", lambda t: re.search(r"EXC  code 0xc0000005 \(ACCESS_VIOLATION\)", t, re.I)),
    ("named the faulting module, not 'outside'", lambda t: re.search(r"rip 0x[0-9a-f]{16} rip@faultchild\.exe\+0x", t, re.I)),
    ("named the fault address's module", lambda t: re.search(r"addr 0x[0-9a-f]{16}  faultchild\.exe\+0x", t, re.I)),
    ("reported registers", lambda t: re.search(r"rsp 0x[0-9a-f]{16} rbp", t, re.I)),
    ("reported a second-chance fault", lambda t: "SECOND (nobody handled it)" in t),
    ("wrote its own minidump", lambda t: re.search(r"dump: .*fault_", t)),
    ("captured the exit code", lambda t: re.search(r"EXIT process, exit code 0xc0000005", t, re.I)),
    ("detached cleanly", lambda t: "detached (DebugActiveProcessStop ok)" in t),
]


def main():
    outdir = os.path.join(ROOT, "tools", "out")
    os.makedirs(outdir, exist_ok=True)
    if not os.path.exists(VICTIM):
        print("self-test: %s is missing -- run tools\\build_faultchild.cmd first" % VICTIM)
        return 2
    child = subprocess.Popen([VICTIM, "--delay", "3000", "--kind", "av-write"])
    print("self-test: child pid %d" % child.pid)
    time.sleep(0.5)
    r = subprocess.run([sys.executable, WATCH, "--pid", str(child.pid), "--seconds", "30",
                        "--force", "--plain", "--outdir", outdir],
                       capture_output=True, text=True, cwd=ROOT)
    child.wait(timeout=10)
    text = r.stdout + r.stderr
    print(text, end="")
    if r.returncode != 0:
        print("self-test: FAIL -- watcher returned %d" % r.returncode)
        return 1
    bad = 0
    for name, fn in CHECKS:
        ok = bool(fn(text))
        print("  %-38s %s" % (name + ":", "ok" if ok else "FAIL"))
        bad += 0 if ok else 1
    print("self-test: %s" % ("PASSED" if not bad else "FAILED (%d)" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
