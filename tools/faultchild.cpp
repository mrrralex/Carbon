/* Carbon -- a throwaway native process that dies the way the client dies.
 *
 * tools/dbgwatch.py has to be trusted before it is pointed at a live Roblox client, and a Python
 * child cannot prove it: CPython converts an access violation inside a ctypes call into a catchable
 * OSError, so the fault never reaches second chance and no dump is written. This child is native, so
 * an unhandled fault really is unhandled -- first chance, second chance, exit code, minidump.
 *
 *   faultchild [--delay ms] [--kind av-write|av-read|failfast|heap|spin|soft]
 *
 * Build (see tools/build_faultchild.cmd): cl /O2 /MD faultchild.cpp /Fo... /Fe tools\out\faultchild.exe
 */

#include <windows.h>
#include <cstdio>
#include <cstring>

static volatile long* g_pad;

int main(int argc, char** argv)
{
    DWORD delay = 8000;
    const char* kind = "av-write";
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--delay") && i + 1 < argc) delay = (DWORD)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--kind") && i + 1 < argc) kind = argv[++i];
    }
    printf("faultchild pid %lu, kind %s, faulting in %lums\n", GetCurrentProcessId(), kind,
           (unsigned long)delay);
    fflush(stdout);
    Sleep(delay);

    if (!strcmp(kind, "soft")) {
        /* A HANDLED access violation every 400 ms, forever - the exception pattern a game client runs
           at all times (guard pages, probe reads, C++ throws). It is what turns a *dangling* VEH
           registration into a hard crash: a vectored handler is consulted before SEH, so if the
           registered handler's code was unmapped, the fault becomes unhandled and the process dies
           with an access violation inside a region that no longer exists. */
        printf("soft: taking a handled access violation every 400 ms, forever\n");
        fflush(stdout);
        for (;;) {
            __try { *(volatile int*)0x0 = 1; }
            __except (EXCEPTION_EXECUTE_HANDLER) { }
            Sleep(400);
        }
    } else if (!strcmp(kind, "spin")) {
        /* A thread that is RUNNING ITS OWN CODE, which is what --stand-in needs: the injector only
           redirects a thread whose RIP is inside the target's main image (redirecting a parked one
           dispatches nothing), and a sleeping process has none. This also keeps the RIP here for the
           whole window, so the redirect lands in .text of a process we can sacrifice. */
        volatile unsigned long long x = 0;
        printf("spinning in faultchild.exe's own .text - safe to aim a redirect at\n");
        fflush(stdout);
        for (unsigned long long i = 0; i < 0xFFFFFFFFULL * 8; ++i) x = x + i;
        printf("spin finished without being redirected (x=%llu)\n", (unsigned long long)x);
    } else if (!strcmp(kind, "failfast")) {
        /* what a __fastfail / stack-cookie trip looks like from outside: 0xC0000409 */
        __fastfail(7);
    } else if (!strcmp(kind, "heap")) {
        /* what a corrupted heap looks like: 0xC0000374, raised by ntdll on the next heap call */
        void* p = HeapAlloc(GetProcessHeap(), 0, 64);
        memset(p, 0x41, 4096);          /* overflow the block */
        HeapFree(GetProcessHeap(), 0, p);
    } else if (!strcmp(kind, "av-read")) {
        volatile long* p = (volatile long*)0xDEADBEEF0000ULL;
        printf("%ld\n", *p);
    } else {
        /* the plain case: a write to an unmapped address, inside this module's own code */
        g_pad = (volatile long*)0x00000000DEAD0000ULL;
        *g_pad = 1;
    }
    printf("faultchild: reached the end WITHOUT faulting (kind %s did nothing)\n", kind);
    return 0;
}
