// Carbon — phase 1 probe.
// READ-ONLY by design: resolves and validates the state-acquisition chain from
// ANALYSIS.md section 3 and logs everything. Calls ZERO engine functions and
// writes ZERO game memory. See the roadmap: nothing executes until phase 2/5
// has confirmed signatures in a disassembler.

#include <Windows.h>
#include <cstdio>
#include <cstdint>
#include <string>

#include "offsets.h"

namespace {
    FILE* g_log = nullptr;

    void logf(const char* fmt, ...) {
        if (!g_log) return;
        va_list ap; va_start(ap, fmt);
        vfprintf(g_log, fmt, ap);
        va_end(ap);
        fflush(g_log);
    }

    // ---- safe-read helpers: never deref what isn't committed -----------------
    bool readable(const void* p, size_t n) {
        if (!p || ((uintptr_t)p & 7) != 0) return false;
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
        if (mbi.State != MEM_COMMIT) return false;
        if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
        uintptr_t end = (uintptr_t)p + n;
        uintptr_t region_end = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (end > region_end) { // would cross into the next region: check it too
            MEMORY_BASIC_INFORMATION mbi2{};
            if (VirtualQuery((void*)end, &mbi2, sizeof(mbi2)) != sizeof(mbi2)) return false;
            if (mbi2.State != MEM_COMMIT || mbi2.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
        }
        return true;
    }

    uint64_t read_q(uint64_t addr) {
        if (!readable((const void*)addr, 8)) return 0;
        return *(const uint64_t*)addr;
    }

    // MSVC x64 std::string best-effort (SSO: inline buf when capacity <= 15)
    std::string read_msvc_string(uint64_t addr) {
        if (!readable((const void*)addr, 32)) return "<unreadable>";
        const uint8_t* b = (const uint8_t*)addr;
        uint64_t size = *(const uint64_t*)(b + 16);
        uint64_t cap  = *(const uint64_t*)(b + 24);
        if (cap > 0x100000) return "<not-a-string>";
        const char* data = (cap <= 15) ? (const char*)b : *(const char**)b;
        if (!readable(data, size ? size : 1)) return "<unreadable-ptr>";
        return std::string(data, (size_t)size);
    }

    bool looks_like_ptr(uint64_t p) {
        return p && (p & 7) == 0 && p > 0x10000 && p < 0x00007FFFFFFFFFFF;
    }

    // ---- the chain -----------------------------------------------------------
    void probe() {
        char modpath[MAX_PATH]{};
        GetModuleFileNameA(nullptr, modpath, MAX_PATH);
        uint64_t base = (uint64_t)GetModuleHandle(nullptr);
        logf("exe          : %s\n", modpath);
        logf("exe base     : 0x%llx\n", base);

        // build identity: refuse if the code bytes at known RVAs don't match what we
        // expect for cec3ad58 (cheap version gate; phase 1 has no VERSION resource).
        {
            uint8_t expected_prologue[] = { 0x48, 0x89, 0x5C }; // placeholder-class check
            (void)expected_prologue;
            logf("version gate : SKIPPED (phase 1 — add byte-signature check in phase 2)\n");
        }

        // pTaskScheduler
        uint64_t sched_slot = base + RBX::pTaskScheduler;
        if (!readable((void*)sched_slot, 8)) { logf("FAIL: pTaskScheduler slot not readable\n"); return; }
        uint64_t sched = read_q(sched_slot);
        logf("pTaskScheduler@+0x8b79128 -> 0x%llx %s\n", sched, looks_like_ptr(sched) ? "" : "<BAD>");
        if (!looks_like_ptr(sched)) return;

        // job vector
        uint64_t begin = read_q(sched + RBX::TaskScheduler::JobsStart);
        uint64_t end   = read_q(sched + RBX::TaskScheduler::JobsEnd);
        logf("jobs begin=0x%llx end=0x%llx\n", begin, end);
        if (!looks_like_ptr(begin) || !looks_like_ptr(end) || end <= begin || ((end - begin) % 8) != 0) {
            logf("FAIL: job vector sanity\n"); return;
        }
        uint64_t count = (end - begin) / 8;
        if (count == 0 || count > 4096) { logf("FAIL: job count %llu out of band\n", count); return; }
        logf("job count    : %llu\n", count);

        // iterate jobs, find ScriptContext candidates
        int found = 0;
        for (uint64_t i = 0; i < count; ++i) {
            uint64_t job = read_q(begin + i * 8);
            if (!looks_like_ptr(job)) continue;
            std::string name = read_msvc_string(job + RBX::TaskSchedulerJob::JobName);
            uint64_t sc = read_q(job + RBX::TaskScheduler::ScriptContext);
            if (!looks_like_ptr(sc)) continue;
            uint64_t L = read_q(sc + RBX::SC2LS);
            logf("job[%2llu] %-28s sc=0x%llx L=0x%llx%s\n",
                 i, name.c_str(), sc, L, looks_like_ptr(L) ? "" : " <L-BAD>");
            if (looks_like_ptr(L)) {
                ++found;
                // dump the first qwords of the lua_State head for later analysis
                logf("  L head:");
                for (int q = 0; q < 4; ++q) logf(" %016llx", read_q(L + q * 8));
                logf("\n");
            }
        }
        logf("plausible (SC, lua_State) pairs: %d\n", found);

        // EnableLoadModule current value (read-only!)
        uint64_t flag_addr = base + RBX::EnableLoadModule;
        if (readable((void*)flag_addr, 4))
            logf("EnableLoadModule current: %u (0x%llx)\n", *(const uint32_t*)flag_addr, flag_addr);
        else
            logf("EnableLoadModule slot not readable\n");

        logf("PROBE DONE — no engine function was called, no memory was written.\n");
    }

    DWORD WINAPI worker(LPVOID) {
        char logpath[MAX_PATH]{};
        GetTempPathA(MAX_PATH, logpath);
        strcat_s(logpath, "carbon_probe.log");
        fopen_s(&g_log, logpath, "w");
        if (!g_log) return 0;
        logf("=== Carbon phase-1 probe (read-only) ===\n");
        probe();
        fclose(g_log); g_log = nullptr;
        return 0;
    }
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        HANDLE t = CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
