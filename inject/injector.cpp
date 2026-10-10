// Carbon — the injector. Places the read-only payload from payload.cpp into Roblox and reports
// what it found. Design choices, and why:
//
//   * NOTHING happens without --inject. The default run audits the artifact and runs the payload
//     in our own process first.
//   * The audit is mandatory: the payload is extracted from its own section and every relative
//     call/jump in it must land inside the blob. A stray call to memcpy/__chkstk would mean the
//     copied bytes are not self-contained, and that is exactly the kind of thing that kills a
//     client. Out-of-range call -> refuse to inject.
//   * The self-test is mandatory too: the SAME copied bytes that would go into Roblox are first
//     executed in our own process against a context that is guaranteed to fail (no image / no
//     scheduler). If they misbehave, they misbehave here, not inside the game.
//   * Delivery is APC-only (QueueUserAPC). No CreateRemoteThread, no LoadLibrary, no module is
//     added to the target, no thread's context is modified: the payload runs at a point where the
//     thread was already going to return to user mode. That is the least invasive way to get code
//     to run inside a protected process, and the safest to test.
//   * If no APC ever dispatches we deliberately DO NOT free the target allocations - a queued APC
//     still points at them, and freeing would turn our harmless leftover into a crash later.
//
// Read-only guarantee: the payload reads target memory and writes only its own context block,
// which we allocated. No Roblox bytes are modified anywhere in this program.
#include <Windows.h>
#include <TlHelp32.h>
#include <algorithm>
#include <cstddef>          /* offsetof, for the single hijack_tid field written per redirect */
#include <cstdio>
#include <cstdarg>
#include <cwchar>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "payload.h"

/* the menu UI (gui.cpp) - compiled into this same binary so it drives the real pipeline */
extern "C" int cc_ui_run();

/* the engine's compile half (luau_bridge.cpp): source -> Luau bytecode, in THIS process */
extern "C" int cc_compile_source(const char* source, size_t len, void** out_data, size_t* out_size,
                                  char* err, size_t err_cap);
extern "C" void cc_compile_free(void* p);
extern "C" unsigned cc_bytecode_version(const void* data, size_t n);
extern "C" unsigned cc_bytecode_type_version(const void* data, size_t n);
extern "C" int cc_bytecode_acceptable(unsigned version, unsigned type_version);

#define TARGET_EXE     L"RobloxPlayerBeta.exe"
#define TARGET_VERSION "version-cec3ad5889b447cf"

static FILE* g_log = nullptr;

/* Set by the menu UI (gui.cpp) so the same lines that go to stdout/inject_log.txt also land in
   its console tab. The pipeline does not change behaviour because a UI is watching. */
static void (*g_sink)(const char*) = nullptr;

/* --stand-in. The delivery mechanism is not Roblox-specific: suspend ONE thread, point its RIP at a
   stub that calls the payload and restores the thread through NtContinue. The only way to separate
   "our redirect killed the client" from "the client reacted to a redirect" is to aim the identical
   redirect at a process nobody depends on. The payload refuses there - it validates the scheduler
   before it dereferences anything (self-test case 1 proves that: our own image -> BAD_SCHEDULER) -
   so the run exercises the suspend/redirect/restore path and nothing else. Never used by the UI. */
static bool g_stand_in = false;

static void logf_(const char* fmt, ...)
{
    char buf[2048];
    va_list ap = nullptr;
    va_start(ap, fmt);
    int n = _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    fputs(buf, stdout);
    if (g_log) { fputs(buf, g_log); fflush(g_log); }
    if (g_sink) g_sink(buf);
}

/* ------------------------------------------------------------------ artifact ---------- */

static uint8_t* find_section(const char* name, size_t* size_out)
{
    uint8_t* base = (uint8_t*)GetModuleHandleW(nullptr);
    auto dos = (IMAGE_DOS_HEADER*)base;
    auto nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (memcmp(sec[i].Name, name, strlen(name)) == 0) {
            *size_out = sec[i].Misc.VirtualSize;
            return base + sec[i].VirtualAddress;
        }
    }
    return nullptr;
}

// A byte scan for E8/E9 cannot prove anything: those bytes occur inside instruction operands,
// so it produces false positives (this build: 1 candidate, and a real disassembly of the same
// section says 0 real out-of-blob transfers). It is kept as a *hint* only - the gate is the
// self-test below, whose synthetic case executes every path in the payload. The precise,
// decoder-backed audit lives in tools/audit_blob.py and is run as part of the workflow.
static void audit_blob(const uint8_t* blob, size_t size, int* candidates_out)
{
    int candidates = 0;
    uint64_t lo = (uint64_t)blob, hi = lo + size;
    for (size_t i = 0; i + 5 <= size; ++i) {
        uint8_t op = blob[i];
        if (op != 0xE8 && op != 0xE9) continue;
        int32_t rel;
        memcpy(&rel, blob + i + 1, 4);
        uint64_t target = (uint64_t)(blob + i) + 5 + (int64_t)rel;
        if (target < lo || target >= hi) ++candidates;
    }
    *candidates_out = candidates;
}

/* The linker can resolve a function symbol to a `jmp rel32` THUNK in .text rather than to the body
   it actually holds in .cpl (an ILT entry). Verified live, this build does exactly that:
   `0x1400029cd: jmp 0x140116000`, with the real payload at 0x140116000. Only .cpl is copied into the
   target, so the entry we need is the thunk's TARGET - a thunk itself is never part of the blob.
   Following at most a few hops is enough, and the caller still enforces "the result must be inside
   .cpl", so a wrong answer cannot reach a client. */
static uint64_t resolve_entry_thunk(uint64_t addr, const uint8_t* lo, const uint8_t* hi)
{
    for (int hops = 0; hops < 4; ++hops) {
        if (addr >= (uint64_t)lo && addr < (uint64_t)hi) return addr;   /* already the body */
        const uint8_t* p = (const uint8_t*)addr;
        if (p[0] == 0xE9) {                                            /* jmp rel32 */
            int32_t rel = 0; memcpy(&rel, p + 1, 4);
            uint64_t next = (uint64_t)(p + 5 + (int64_t)rel);
            if (next == addr) break;
            addr = next; continue;
        }
        if (p[0] == 0xEB) {                                            /* jmp rel8 */
            int8_t rel = 0; memcpy(&rel, p + 1, 1);
            uint64_t next = (uint64_t)(p + 2 + (int64_t)rel);
            if (next == addr) break;
            addr = next; continue;
        }
        break;   /* not a thunk: indirect or something else - report it as-is and fail the check */
    }
    return addr;
}

/* copy the payload into a fresh RX buffer exactly the way it will be in the target */
static void* materialise(const uint8_t* blob, size_t size)
{
    void* p = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) return nullptr;
    memcpy(p, blob, size);
    DWORD old = 0;
    if (!VirtualProtect(p, size, PAGE_EXECUTE_READ, &old)) { VirtualFree(p, 0, MEM_RELEASE); return nullptr; }
    return p;
}

/* ------------------------------------------------------------------ redirect gate ------ */

/* Where a thread redirect is allowed to land, decided at the moment of the write.
   Measured, 2026-10-10, two Attach presses: each redirected a thread the caller had JUST sampled
   inside the image (rip 0x7ff610f1e65a, 0x7ff610f4a6d9), and each actually wrote the context when
   that same thread's rip was in ntdll instead (0x7ffbb0841544, 0x7ffbb0844a14 - between the
   target's ntdll base and NtContinue's own address, i.e. a kernel transition). Immediately after
   each write no thread in the client used any CPU in a 60 ms window, and the two runs ended in an
   access-violation death (the injector itself recorded exit 0xC0000005) and in a hang that Windows
   had to close. So the write, not the delivery, is what broke those clients.
   Why the caller's test cannot be trusted: it is made on a sample taken BEFORE the suspend, and a
   thread parked in a wait is back inside a syscall within those milliseconds - the sample says
   in-image while the write lands in ntdll. The test is therefore applied again inside hijack_one,
   on the context that is really there, and it is deliberately strict: the client's own image, or
   nothing. A thread running anywhere else is not a delivery opportunity, it is a client we are
   about to break. */
static bool redirectable_ip(uint64_t rip, uint64_t image, uint32_t image_size)
{
    if (!rip || !image || !image_size) return false;
    return rip >= image && rip < image + (uint64_t)image_size;
}

/* ------------------------------------------------------------------ selftest ---------- */

static int selftest(const uint8_t* blob, size_t size)
{
    logf_("--- self-test: the exact bytes that would be injected, executed here first ---\n");
    void* copy = materialise(blob, size);
    if (!copy) { logf_("  FAIL: could not materialise a copy\n"); return -1; }
    auto fn = (void(*)(cc_ctx*))copy;
    int failures = 0;

    {   /* case 1: valid context, but this process has no Roblox image layout */
        cc_ctx ctx{};
        memset(&ctx, 0, sizeof(ctx));
        ctx.marker = CC_MARK;
        ctx.abi = (uint32_t)sizeof(cc_ctx);
        ctx.self_va = (uint64_t)&ctx;
        ctx.vq = (uint64_t)&VirtualQuery;
        ctx.roblox_base = (uint64_t)GetModuleHandleW(nullptr);
        fn(&ctx);
        int ok = (ctx.done == CC_DONE) && (ctx.status == CC_BAD_SCHEDULER);
        logf_("  case 1 (our own image, expect BAD_SCHEDULER) : done=%s status=%u %s\n",
              ctx.done == CC_DONE ? "yes" : "NO", ctx.status, ok ? "ok" : "UNEXPECTED");
        if (!ok) ++failures;
    }
    {   /* case 2: no image at all */
        cc_ctx ctx{};
        memset(&ctx, 0, sizeof(ctx));
        ctx.marker = CC_MARK;
        ctx.abi = (uint32_t)sizeof(cc_ctx);
        ctx.self_va = (uint64_t)&ctx;
        ctx.vq = (uint64_t)&VirtualQuery;
        ctx.roblox_base = 0;
        fn(&ctx);
        int ok = (ctx.done == CC_DONE) && (ctx.status == CC_BAD_IMAGE);
        logf_("  case 2 (null image, expect BAD_IMAGE)       : done=%s status=%u %s\n",
              ctx.done == CC_DONE ? "yes" : "NO", ctx.status, ok ? "ok" : "UNEXPECTED");
        if (!ok) ++failures;
    }
    {   /* case 3: wrong marker -> must refuse and must NOT claim done */
        cc_ctx ctx{};
        memset(&ctx, 0, sizeof(ctx));
        ctx.abi = (uint32_t)sizeof(cc_ctx);
        ctx.self_va = (uint64_t)&ctx;
        ctx.vq = (uint64_t)&VirtualQuery;
        fn(&ctx);
        int ok = (ctx.done != CC_DONE);
        logf_("  case 3 (bad marker, expect refusal)         : done=%s %s\n",
              ctx.done == CC_DONE ? "yes" : "no", ok ? "ok" : "UNEXPECTED");
        if (!ok) ++failures;
    }
    {   /* case 4: already-done payload is a no-op (two APCs can dispatch) */
        cc_ctx ctx{};
        memset(&ctx, 0, sizeof(ctx));
        ctx.marker = CC_MARK;
        ctx.abi = (uint32_t)sizeof(cc_ctx);
        ctx.self_va = (uint64_t)&ctx;
        ctx.vq = (uint64_t)&VirtualQuery;
        ctx.done = CC_DONE;
        ctx.status = 1234;
        fn(&ctx);
        int ok = (ctx.status == 1234);
        logf_("  case 4 (second dispatch is a no-op)         : status=%u %s\n",
              ctx.status, ok ? "ok" : "UNEXPECTED");
        if (!ok) ++failures;
    }
    {   /* case 5: SYNTHETIC TARGET. A fake image laid out at the real offsets, so every branch
           of the payload runs - chain, all three state offsets, both routes, the flag reads and
           the success path. This is what makes the self-test a gate rather than a smoke test:
           a stray call to an address outside the blob would fault here, on this path. */
        /* The reservation must span the HIGHEST rva the payload will touch, and the highest is
           not pTaskScheduler - FakeDataModel sits ~0x5C000 bytes further up. Deriving the size
           from the constant that wins, instead of from the one we happened to look at, is the
           fix for the out-of-bounds write this test caught on its first full run. */
        const uint64_t kTopRva = CC_RVA_FAKE_DATAMODEL > CC_RVA_P_TASKSCHEDULER
                               ? CC_RVA_FAKE_DATAMODEL : CC_RVA_P_TASKSCHEDULER;
        const uint64_t kSize = kTopRva + 0x2000;
        uint8_t* img = (uint8_t*)VirtualAlloc(nullptr, kSize,
                                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!img) {
            logf_("  case 5 (synthetic target)                   : could not reserve %llu MB - skipped\n",
                  (unsigned long long)(kSize >> 20));
        } else {
            uint64_t B = (uint64_t)img;
            /* Bounds-checked writers. Every fake write goes through chk(), so a wrong size, a
               wrong offset constant or a new field added to the payload turns into a reported
               failure here rather than an access violation with no explanation. */
            int oob = 0;
            auto chk = [&](uint64_t at, uint64_t n) -> bool {
                if (at >= B && at + n <= B + kSize) return true;
                oob = 1;
                logf_("  case 5: OOB write at 0x%llx (%s the synthetic image, +0x%llx past size)\n",
                      at, at >= B ? "inside" : "below",
                      (unsigned long long)(at >= B ? at - (B + kSize) : B - at));
                return false;
            };
            auto put64 = [&](uint64_t at, uint64_t v) { if (chk(at, 8)) memcpy((void*)at, &v, 8); };
            auto put32 = [&](uint64_t at, uint32_t v) { if (chk(at, 4)) memcpy((void*)at, &v, 4); };
            auto put16 = [&](uint64_t at, uint16_t v) { if (chk(at, 2)) memcpy((void*)at, &v, 2); };
            auto put8  = [&](uint64_t at, uint8_t  v) { if (chk(at, 1)) memcpy((void*)at, &v, 1); };

            logf_("  case 5: synthetic image at 0x%llx (%llu MB committed, top rva 0x%llx)\n",
                  B, (unsigned long long)(kSize >> 20), (unsigned long long)kTopRva);
            /* Three distinct objects, because the live chain has three indirections:
               sched+0xC8 -> vector storage -> [0] = job object -> +0x1C0 = ScriptContext.
               The first version of this fixture collapsed the vector cell and the job into one
               address, so *(begin) read back as zero and the loop found no job at all. */
            const uint64_t S   = B + 0x1000;    /* fake TaskScheduler         */
            const uint64_t VEC = B + 0x2000;    /* fake jobs vector storage   */
            const uint64_t J   = B + 0x3000;    /* fake job object            */
            const uint64_t C   = B + 0x4000;    /* fake ScriptContext         */
            const uint64_t L   = B + 0x5000;    /* fake lua_State             */
            const uint64_t GS  = B + 0x6000;    /* fake global_State          */
            const uint64_t FAKE = B + 0x7000;   /* fake FakeDataModel         */
            const uint64_t REAL = B + 0x8000;   /* fake RealDataModel         */

            put16(B, 0x5A4D);                                        /* MZ */
            put64(B + CC_RVA_P_TASKSCHEDULER, S);
            put64(B + CC_RVA_FAKE_DATAMODEL, FAKE);
            put64(FAKE + CC_OFF_REAL_DATAMODEL, REAL);               /* DataModel */
            put64(REAL + CC_OFF_DATAMODEL_SC, C);                    /* same SC -> routes agree */
            put64(S + CC_OFF_JOBS_BEGIN, VEC);
            put64(S + CC_OFF_JOBS_END, VEC + 8);
            put64(VEC, J);                                           /* vector[0] = job */
            put64(J + CC_OFF_JOB_SCRIPTCTX, C);
            put64(C + CC_OFF_SC_LUASTATE_A, L);
            put32(C + CC_OFF_SC_RESUME_DEPTH, 1);
            put8(L + CC_OFF_L_TT, 8);
            put8(L + CC_OFF_L_MARKED, 0);
            put64(L + CC_OFF_L_GLOBAL_STATE, GS);
            put8(B + CC_RVA_ENABLE_LOAD_MODULE, 1);
            put8(B + CC_RVA_GATE_A, 0);
            put8(B + CC_RVA_GATE_B, 1);

            cc_ctx ctx{};
            memset(&ctx, 0, sizeof(ctx));
            ctx.marker = CC_MARK;
            ctx.abi = (uint32_t)sizeof(cc_ctx);
            ctx.self_va = (uint64_t)&ctx;
            ctx.vq = (uint64_t)&VirtualQuery;
            ctx.roblox_base = B;
            fn(&ctx);

            bool ok = !oob
                   && ctx.done == CC_DONE && ctx.status == CC_OK
                   && ctx.sched == S && ctx.lua_state == L
                   && ctx.job_begin == VEC && ctx.job_count == 1
                   && ctx.job_first == J        /* proves the vector-cell indirection */
                   && ctx.jobs_seen == 1
                   && ctx.lua_state_off == CC_OFF_SC_LUASTATE_A
                   && ctx.sc_from_job == C && ctx.sc_from_dm == C && ctx.sc_routes_agree == 1
                   && ctx.resume_depth == 1 && ctx.jobs_with_state == 1
                   && ctx.flags[0] == 1 && ctx.flags[1] == 0 && ctx.flags[2] == 1
                   && ctx.reads_gated == 0;
            logf_("  case 5 (synthetic target, full coverage)    : status=%u sched=%s job=%s offset=0x%x "
                  "L=%s routes=%s flags=%llu/%llu/%llu gated=%u oob=%d %s\n",
                  ctx.status, ctx.sched == S ? "ok" : "BAD", ctx.job_first == J ? "ok" : "BAD",
                  ctx.lua_state_off, ctx.lua_state == L ? "ok" : "BAD",
                  ctx.sc_routes_agree ? "agree" : "DIFFER",
                  ctx.flags[0], ctx.flags[1], ctx.flags[2], ctx.reads_gated, oob, ok ? "ok" : "UNEXPECTED");
            if (!ok) ++failures;

            /* cases 5b/5c/5d: the exec path's three refusals, on the same synthetic image. Each
               one must be refused BEFORE any call into the target - a half-armed exec that calls
               something anyway is the failure this code exists to prevent, and "it typechecked"
               does not cover it. Order matters and is checked in order: addresses, then state,
               then the loader's own version gate. */
            {
                uint8_t bc_ok[8]  = { 9, 3, 0, 0, 0, 0, 0, 0 };   /* inside the loader's window */
                uint8_t bc_bad[8] = { 2, 3, 0, 0, 0, 0, 0, 0 };   /* version 2: the gate says no  */
                const char* nm = "@selftest";
                cc_exec_scratch scratch{};
                cc_ctx e{};
                auto run_case = [&](const char* tag, const char* what, uint64_t loader_va, uint64_t bytecode,
                                    uint64_t bc_size, uint32_t expect, bool clear_state,
                                    uint32_t mode = 1, int want_arg1 = -1) {
                    if (clear_state) put64(C + CC_OFF_SC_LUASTATE_A, 0);
                    memset(&e, 0, sizeof(e));
                    e.marker = CC_MARK;
                    e.abi = (uint32_t)sizeof(cc_ctx);
                    e.self_va = (uint64_t)&e;
                    e.vq = (uint64_t)&VirtualQuery;
                    e.roblox_base = B;
                    e.image_size = kSize;
                    e.exec_scratch = (uint64_t)&scratch;
                    e.bytecode = bytecode;
                    e.bytecode_size = bc_size;
                    e.chunkname = (uint64_t)nm;
                    e.loader_va = loader_va;
                    e.resume_va = B + 0x2000;
                    e.exec_mode = mode;
                    fn(&e);
                    int cok = e.done == CC_DONE && e.exec_status == expect;
                    if (want_arg1 >= 0 && (int)e.arg1_ok != want_arg1) cok = 0;
                    logf_("  case %-5s (%-32s): audit=%u exec=%u expect=%u arg1=%s %s\n",
                          tag, what, e.status, e.exec_status, expect,
                          mode == 3 ? (e.arg1_ok ? "ok" : "BAD") : "-", cok ? "ok" : "UNEXPECTED");
                    if (!cok) ++failures;
                    if (clear_state) put64(C + CC_OFF_SC_LUASTATE_A, L);
                };
                run_case("5b", "exec address outside the image", B + kSize + 0x10000,
                         (uint64_t)bc_ok, sizeof(bc_ok), CC_EXEC_BAD_ARGS, false);
                run_case("5c", "exec bytecode the gate rejects", B + 0x2000,
                         (uint64_t)bc_bad, sizeof(bc_bad), CC_EXEC_BAD_ARGS, false);
                run_case("5d", "exec with no validated state", B + 0x2000,
                         (uint64_t)bc_ok, sizeof(bc_ok), CC_EXEC_NO_STATE, true);
                /* 5e/5f: ARG1 itself, which is what faulted a live client on 2026-10-10. The
                   synthetic state can be given both the shape the loader dereferences AND the
                   shape that crashed it, so the refusal and the acceptance are both pinned here
                   instead of only in the client. */
                const uint64_t CONT = B + 0x9000;    /* a fake hash container */
                put64(L + 0x18, 0);                  /* 0 size, NULL buckets - the fault's shape */
                run_case("5e", "exec whose ARG1 cannot be dereferenced", B + 0x2000,
                         (uint64_t)bc_ok, sizeof(bc_ok), CC_EXEC_NO_ARG1, false, 1, 0);
                put64(CONT + 0x18, (uint64_t)4);     /* a plausible capacity (int32 at +0x18) */
                put64(CONT + 0x20, B + 0x9100);      /* a readable bucket array at +0x20      */
                put64(L + 0x18, CONT);
                run_case("5f", "dry run, ARG1 shaped the way the loader reads it", B + 0x2000,
                         (uint64_t)bc_ok, sizeof(bc_ok), CC_EXEC_DRY, false, 3, 1);

                /* 5g: the container's ARG2, checked without calling anything. A 14-byte script is
                   exactly the size that made the entry read the pointer's bytes as text (capacity
                   below 16 selects MSVC's inline form), which is what `execute at 0x0` was. */
                {
                    static const char small_src[] = "print(\"hello\")";   /* 14 bytes, as typed */
                    memset(&e, 0, sizeof(e));
                    e.marker = CC_MARK;
                    e.abi = (uint32_t)sizeof(cc_ctx);
                    e.self_va = (uint64_t)&e;
                    e.vq = (uint64_t)&VirtualQuery;
                    e.roblox_base = B;
                    e.image_size = kSize;
                    e.exec_scratch = (uint64_t)&scratch;
                    e.bytecode = (uint64_t)bc_ok;
                    e.bytecode_size = sizeof(bc_ok);
                    e.chunkname = (uint64_t)nm;
                    e.loader_va = B + 0x2000;
                    e.resume_va = B + 0x2000;
                    e.container_va = B + 0x2000;
                    e.container_payload = (uint64_t)small_src;
                    e.container_size = 14;
                    e.exec_mode = 6;
                    fn(&e);
                    bool okg = e.done == CC_DONE && e.exec_status == CC_EXEC_DRY
                            && scratch.str_data == (uint64_t)small_src
                            && scratch.str_size == 14 && scratch.str_cap >= 16;
                    logf_("  case 5g    (container ARG2 std::string, no call) : exec=%u expect=%u "
                          "data=%s size=%llu cap=%llu %s\n",
                          e.exec_status, (unsigned)CC_EXEC_DRY,
                          scratch.str_data == (uint64_t)small_src ? "ok" : "BAD",
                          (unsigned long long)scratch.str_size,
                          (unsigned long long)scratch.str_cap, okg ? "ok" : "UNEXPECTED");
                    if (!okg) ++failures;
                }
            }
            VirtualFree(img, 0, MEM_RELEASE);
        }
    }

    {   /* case 6: the black box. The recorder is driven directly, on the exact copied bytes that
           would be injected, with a synthetic exception - so what it records is checked HERE instead
           of being trusted inside a client we cannot read after it dies. Registered through the same
           AddVectoredExceptionHandler the payload calls, and unregistered immediately: a handler left
           registered in our own process would observe unrelated faults for the rest of the run (a C++
           throw is an SEH exception too). */
        uint64_t veh_sym = (uint64_t)&cc_veh;
        uint64_t veh_addr = resolve_entry_thunk(veh_sym, blob, blob + size);
        bool in_blob = veh_addr >= (uint64_t)blob && veh_addr < (uint64_t)blob + size;
        auto veh = (int(*)(cc_exc_ptrs*, cc_ctx*))((uint8_t*)copy + (veh_addr - (uint64_t)blob));
        cc_blackbox bb{};
        cc_ctx c{};
        memset(&c, 0, sizeof(c));
        c.marker = CC_MARK;
        c.abi = (uint32_t)sizeof(cc_ctx);
        c.self_va = (uint64_t)&c;
        /* The recovery walks the faulting stack and gates every read with VirtualQuery, so a
           recorder without vq can only ever answer "the stack was not readable" - which is what
           case 6b reported (walked=0) until this line existed. */
        c.vq = (uint64_t)&VirtualQuery;
        c.blackbox = (uint64_t)&bb;
        c.exec_stage = CC_STAGE_BEFORE_LOAD;
        c.bb_hold_loops = 0;              /* unit check, not a run: no spin here */
        c.add_veh = (uint64_t)&AddVectoredExceptionHandler;
        c.veh_handler = (uint64_t)veh;
        cc_addveh_fn add = (cc_addveh_fn)c.add_veh;
        c.veh_handle = add(1, (void*)c.veh_handler);
        c.veh_installed = c.veh_handle ? 1u : 0u;

        cc_exc_rec rec{};
        rec.code = 0xC0000005u;
        rec.address = 0x1122334455667788ull;
        rec.params = 2;
        rec.info[0] = 1;                  /* write */
        rec.info[1] = 0xDEADBEEF0000ull;
        alignas(16) uint8_t fake[0x500] = { 0 };
        uint64_t want_rsp = 0x22AA33BB44CC55DDull, want_rax = 0x99EE8877AA55CC11ull;
        memcpy(fake + CC_CTX_RSP, &want_rsp, 8);
        memcpy(fake + CC_CTX_RAX, &want_rax, 8);
        cc_exc_ptrs p{};
        p.record = &rec;
        p.context = fake;
        int rv = veh(&p, &c);

        /* The recorder no longer answers -1 here. -1 is EXCEPTION_CONTINUE_EXECUTION, so a fault
           the handler could not fix was retried at the same instruction forever - the client
           going "not responding" instead of dying, which is what Execute produced. An unfixable
           fault must be handed on: 0. */
        bool ok = in_blob && c.veh_installed == 1 && rv == 0
               && bb.magic == CC_BB_MAGIC && bb.code == rec.code && bb.address == rec.address
               && bb.fault_va == rec.info[1] && bb.access == 1
               && bb.stage == CC_STAGE_BEFORE_LOAD && bb.rsp == want_rsp && bb.rax == want_rax
               && bb.handler_rc == 0 && bb.recovered == 0;
        logf_("  case 6 (black box records, hands the fault on): in_cpl=%s installed=%u rv=%d magic=%s "
              "rip=%s va=%s regs=%s handed_on=%s %s\n",
              in_blob ? "yes" : "NO", c.veh_installed, rv,
              bb.magic == CC_BB_MAGIC ? "ok" : "BAD",
              bb.address == rec.address ? "ok" : "BAD",
              bb.fault_va == rec.info[1] ? "ok" : "BAD",
              (bb.rsp == want_rsp && bb.rax == want_rax) ? "ok" : "BAD",
              bb.recovered == 0 ? "ok" : "BAD",
              ok ? "ok" : "UNEXPECTED");
        if (!ok) ++failures;

        /* case 6b: the RECOVERY. Same handler and the same kind of fault, but now the fault happened
           inside a call this payload made and the faulting stack carries a return address into the
           payload - the exact situation that used to be an infinite retry. What must happen:
           rip/rsp/rax are pointed back into the payload, the handler says CONTINUE_EXECUTION, and
           the record says recovered. Checked on a real synthetic stack, not by inspection. */
        {
            alignas(16) uint8_t payloadfake[0x80] = { 0 };
            const uint64_t pflo = (uint64_t)payloadfake;
            const uint64_t pfhi = (uint64_t)payloadfake + sizeof(payloadfake);
            uint64_t fake_stack[16];
            memset(fake_stack, 0, sizeof(fake_stack));
            const uint64_t ret_into_payload = pflo + 0x20;
            fake_stack[2] = ret_into_payload;      /* the payload's own return address */

            cc_blackbox bb2{};
            cc_ctx c2{};
            c2 = c;                                 /* same recorder, armed */
            /* The recorder now decides ownership by thread, so the fixture has to say which thread
               it is. Case 6 above leaves hijack_tid 0, which is why it must keep being handed on. */
            c2.get_tid = (uint64_t)&GetCurrentThreadId;
            c2.hijack_tid = GetCurrentThreadId();
            c2.blackbox = (uint64_t)&bb2;
            c2.payload_lo = pflo;
            c2.payload_hi = pfhi;
            c2.roblox_base = pflo;                  /* the "client image" for this case */
            c2.image_size = sizeof(payloadfake);
            c2.exec_stage = CC_STAGE_BEFORE_LOAD;
            c2.fault_recovered = 0;

            cc_exc_rec rec2 = rec;
            rec2.address = pflo + 4;                /* inside the image, so a call can own it */
            rec2.info[1] = 0xDEAD0000ull;
            alignas(16) uint8_t ctx2[0x500] = { 0 };
            uint64_t rsp2 = (uint64_t)&fake_stack[0];
            memcpy(ctx2 + CC_CTX_RSP, &rsp2, 8);
            cc_exc_ptrs p2{};
            p2.record = &rec2;
            p2.context = ctx2;
            int rv2 = veh(&p2, &c2);

            uint64_t got_rsp = 0, got_rip = 0, got_rax = 0;
            memcpy(&got_rsp, ctx2 + CC_CTX_RSP, 8);
            memcpy(&got_rip, ctx2 + CC_CTX_RIP, 8);
            memcpy(&got_rax, ctx2 + CC_CTX_RAX, 8);
            bool ok2 = rv2 == -1 && bb2.recovered == 1 && bb2.handler_rc == 0xFFFFFFFFu
                    && bb2.resume_rip == ret_into_payload
                    && got_rip == ret_into_payload && got_rsp == (uint64_t)&fake_stack[3]
                    && got_rax == 1 && c2.fault_recovered == 1 && bb2.fault_rva == 4
                    && bb2.magic == CC_BB_MAGIC;
            logf_("  case 6b (a faulted CALL is recovered)       : rv=%d rip=%s rsp=%s rax=%s "
                  "resumed=%s client_kept=%s %s\n",
                  rv2, got_rip == ret_into_payload ? "ok" : "BAD",
                  got_rsp == (uint64_t)&fake_stack[3] ? "ok" : "BAD",
                  got_rax == 1 ? "ok" : "BAD",
                  bb2.recovered == 1 ? "ok" : "BAD",
                  c2.fault_recovered == 1 ? "ok" : "BAD",
                  ok2 ? "ok" : "UNEXPECTED");
            static const char* why[] = { "not our fault", "no payload range supplied",
                                        "the walk left the committed stack",
                                        "walked the stack, no return address into the payload",
                                        "recovered" };
            logf_("       diagnostic                 : stage_seen=%u fault_rva=%llu magic=%s why=%u (%s) "
                  "walked=%llu rsp=0x%llx ret=0x%llx\n",
                  bb2.stage, bb2.fault_rva, bb2.magic == CC_BB_MAGIC ? "ok" : "BAD",
                  bb2.recover_why, bb2.recover_why < 5 ? why[bb2.recover_why] : "?",
                  bb2.walked, bb2.fault_rsp, ret_into_payload);
            if (!ok2) ++failures;
        }

        /* case 6c: the fault that actually killed a client on 2026-10-10. A call through a null
           pointer faults at rip 0 - outside the image - so the v6 rule ("the rip must be inside
           the image") called it the client's and handed it on. It is OUR call, on OUR thread, and
           it must be recovered: that is the difference between a report and a dead client. */
        {
            alignas(16) uint8_t payloadfake[0x80] = { 0 };
            const uint64_t pflo = (uint64_t)payloadfake;
            uint64_t fake_stack[16];
            memset(fake_stack, 0, sizeof(fake_stack));
            const uint64_t ret_into_payload = pflo + 0x30;
            fake_stack[1] = ret_into_payload;

            cc_blackbox bb3{};
            cc_ctx c3 = c;
            c3.get_tid = (uint64_t)&GetCurrentThreadId;
            c3.hijack_tid = GetCurrentThreadId();
            c3.blackbox = (uint64_t)&bb3;
            c3.payload_lo = pflo;
            c3.payload_hi = pflo + sizeof(payloadfake);
            c3.roblox_base = 0;
            c3.image_size = 0;
            c3.exec_stage = CC_STAGE_BEFORE_CONTAINER;
            c3.fault_recovered = 0;

            cc_exc_rec rec3 = rec;
            rec3.address = 0;               /* `execute at 0x0` - outside every image */
            rec3.info[0] = 8;
            rec3.info[1] = 0;
            alignas(16) uint8_t ctx3[0x500] = { 0 };
            uint64_t rsp3 = (uint64_t)&fake_stack[0];
            memcpy(ctx3 + CC_CTX_RSP, &rsp3, 8);
            cc_exc_ptrs p3{};
            p3.record = &rec3;
            p3.context = ctx3;
            int rv3 = veh(&p3, &c3);
            uint64_t got_rip3 = 0, got_rax3 = 0;
            memcpy(&got_rip3, ctx3 + CC_CTX_RIP, 8);
            memcpy(&got_rax3, ctx3 + CC_CTX_RAX, 8);
            bool ok3 = rv3 == -1 && bb3.recovered == 1 && bb3.ours == 1 && bb3.fault_rva == 0
                    && got_rip3 == ret_into_payload && got_rax3 == 1
                    && bb3.recover_why == CC_REC_DONE && c3.fault_recovered == 1;
            logf_("  case 6c (a null-call fault on OUR thread)   : rv=%d ours=%s rip=%s rax=%s "
                  "fault_rva=%llu why=%u %s\n",
                  rv3, bb3.ours == 1 ? "ok" : "BAD",
                  got_rip3 == ret_into_payload ? "ok" : "BAD",
                  got_rax3 == 1 ? "ok" : "BAD", bb3.fault_rva,
                  bb3.recover_why, ok3 ? "ok" : "UNEXPECTED");
            if (!ok3) ++failures;
        }
        if (c.veh_handle) RemoveVectoredExceptionHandler((void*)c.veh_handle);
    }

    {   /* case 7: where a redirect may land, pinned on the numbers from the crashed session. Both
           Attach presses on 2026-10-10 sampled a thread INSIDE the image and wrote the context when
           that same thread was in ntdll; both clients went from running to frozen within one sample
           (then: exit 0xC0000005, and a hang Windows had to close). The rows below are those exact
           values, so the gate that refuses them cannot be removed without this failing. */
        const uint64_t ib = 0x7ff60b3c0000ull;      /* image base, that session's log */
        const uint32_t isz = 0x9127000u;            /* image size, the same line      */
        struct { uint64_t rip; bool want; const char* note; } c7[] = {
            { 0x7ff610f1e65aull, true,  "sampled in-image (thread 4232, run 1)" },
            { 0x7ff610f4a6d9ull, true,  "sampled in-image (thread 7968, run 2)" },
            { 0x7ffbb0841544ull, false, "written in ntdll - that client died (run 1)" },
            { 0x7ffbb0844a14ull, false, "written in ntdll - that client hung (run 2)" },
            { ib,                true,  "the image's first byte" },
            { ib + isz - 1,      true,  "the image's last byte" },
            { ib + isz,          false, "one byte past the image" },
            { 0,                 false, "no rip at all" },
        };
        bool ok7 = true;
        for (const auto& t7 : c7) if (redirectable_ip(t7.rip, ib, isz) != t7.want) ok7 = false;
        logf_("  case 7 (redirect landing site, 8 measured)  : %s\n", ok7 ? "ok" : "UNEXPECTED");
        if (!ok7) {
            for (const auto& t7 : c7)
                logf_("       %-46s 0x%llx -> %s (want %s)\n", t7.note, t7.rip,
                      redirectable_ip(t7.rip, ib, isz) ? "accept" : "refuse",
                      t7.want ? "accept" : "refuse");
            ++failures;
        }
    }

    VirtualFree(copy, 0, MEM_RELEASE);
    logf_("  self-test: %s\n", failures ? "FAILED - will not inject" : "PASSED");
    return failures ? -1 : 0;
}

/* ------------------------------------------------------------------ target ------------ */

static DWORD find_pid(const wchar_t* exe)
{
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exe) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static uint64_t module_base(DWORD pid, const wchar_t* name)
{
    uint64_t base = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W me{ sizeof(me) };
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, name) == 0) { base = (uint64_t)me.modBaseAddr; break; }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

static bool rpm(HANDLE proc, uint64_t addr, void* buf, size_t n)
{
    SIZE_T got = 0;
    return ReadProcessMemory(proc, (LPCVOID)addr, buf, n, &got) && got == n;
}

/* Names for the payload's exec stages. A run that dies inside a call leaves no report, so these
   strings are what turns "the client crashed" into "the client crashed in that call". */
static const char* stage_name(uint32_t s)
{
    switch (s) {
        case CC_STAGE_BEFORE_LOAD:   return "about to call the bytecode loader (0x25ffdd0)";
        case CC_STAGE_AFTER_LOAD:    return "the loader returned";
        case CC_STAGE_BEFORE_RESUME: return "about to call the resume entry (0x418fef0)";
        case CC_STAGE_AFTER_RESUME:  return "the resume returned";
        case CC_STAGE_BEFORE_CONTAINER: return "about to call the container, LuaVM_Load (0x4188af0)";
        case CC_STAGE_AFTER_CONTAINER:  return "the container returned";
        default:                     return "-";
    }
}

/* One place that names an exec mode, used by both the plan line and the report. The earlier version
   had the ternary in two places and one of them described mode 3 as "load, then resume" - a plan
   line that misdescribes what is about to happen is worse than no plan line. */
static const char* exec_mode_name(uint32_t m)
{
    switch (m) {
        case 0:  return "audit only (nothing is called)";
        case 1:  return "load only (the resume is not called)";
        case 3:  return "dry run (guards + struct, no call)";
        case 2:  return "load, then resume (direct loader call)";
        case 4:  return "container + resume (LuaVM_Load, the client's own entry)";
        case 5:  return "container only (LuaVM_Load, no resume)";
        case 6:  return "container dry run (the std::string is built, nothing is called)";
        default: return "?";
    }
}

/* The VM entry points this project has read out of the client (SIGNATURES.md 2/4/9.1/9.2). A thread
   whose RIP is inside one of these is executing the client's own VM, which means the *per-thread* VM
   state that a foreign thread lacks is set up on it already. That matters: measured 2026-10-09, the
   loader call from an arbitrary in-image thread faulted the client with 0xC0000005 while the payload
   had reached nothing beyond that call (SIGNATURES.md 9.6). So candidates are ordered by this, not
   by how busy they are. */
static const char* vm_function_of(uint64_t rip, uint64_t base)
{
    if (!base || rip < base) return nullptr;
    const uint64_t rva = rip - base;
    static const struct { const char* name; uint64_t rva, size; } table[] = {
        { "LuaVM_Load",          0x4188AF0, 0x2000 },
        { "resume wrapper",      0x418FEF0, 0x60   },
        { "ScriptContextResume", 0x423C6F0, 0x400  },
        { "Luau_Execute",        0x25CB0D0, 0x400  },
        { "bytecode loader",     0x25FFDD0, 0x3000 },
    };
    for (const auto& f : table)
        if (rva >= f.rva && rva < f.rva + f.size) return f.name;
    return nullptr;
}

/* The facts that decide whether the exec path may run at all, printed the moment the payload reports
   reaching a stage. Reason: a run that dies inside a call never writes its final report, and then
   "which ScriptContext offset produced the state, and was there one at all" is the first thing
   anyone asks afterwards. */
static void log_state_facts(const cc_ctx& p)
{
    logf_("                   state          : L 0x%llx via SC+0x%x, resume depth %u, %u of %u job(s) had one\n",
          p.lua_state, p.lua_state_off, p.resume_depth, p.jobs_with_state, p.jobs_seen);
    logf_("                   recorder       : %s\n",
          p.veh_installed ? "armed in the target (a fault will be recorded)"
                          : "NOT armed - a fault will tell us nothing");
}

/* Why no call happened, for the run where that is the answer. */
static const char* exec_not_called_why(uint32_t s)
{
    switch (s) {
        case CC_EXEC_DRY:      return "the mode asked for a dry run - all guards ran, nothing was called";
        case CC_EXEC_OFF:      return "this run asked for no execution";
        case CC_EXEC_BAD_ARGS: return "an address or size from the caller was unusable, so the call was refused";
        case CC_EXEC_NO_STATE: return "no validated lua_State - join an experience so the client has a live state";
        case CC_EXEC_NO_ARG1:  return "the loader's OWN first dereference of ARG1 has nothing usable at "
                                      "[L+0x18] (see arg1 below) - refused instead of faulting";
        case CC_EXEC_FAULTED:  return "the call faulted; the recorder recovered the payload (see fault below)";
        default:               return "?";
    }
}

/* The recorder's output, read WHILE the handler is still holding the faulting thread. That window is
   the whole point of the spin in cc_veh: a fatal fault ends the process microseconds after it is
   recorded, and ReadProcessMemory on an exited process fails, so a poll that only checks afterwards
   is a poll that always misses. Called from every wait loop, prints once. */
static bool poll_blackbox(HANDLE proc, uint64_t va, uint64_t base, uint64_t image_size, bool* said)
{
    if (!va || (*said)) return false;
    cc_blackbox bb{};
    if (!rpm(proc, va, &bb, sizeof(bb)) || bb.magic != CC_BB_MAGIC) return false;
    *said = true;
    logf_("\n=== black box - the actual fault, read out of the target while it was held ===\n");
    logf_("  exception      : 0x%08x%s\n", bb.code,
          bb.code == 0xC0000005u ? "  (access violation)" : bb.code == 0xC00000FDu ? "  (stack overflow)" : "");
    if (base && bb.address >= base && bb.address < base + image_size)
        logf_("  faulting rip   : 0x%llx  inside the client image, rva 0x%llx\n",
              bb.address, bb.address - base);
    else
        logf_("  faulting rip   : 0x%llx  (outside the client image)\n", bb.address);
    logf_("  stage          : %u - %s\n", bb.stage, stage_name(bb.stage));
    logf_("  access         : %s 0x%llx\n",
          bb.access == 1 ? "write to" : bb.access == 8 ? "execute at" : "read from", bb.fault_va);
    logf_("  faulting regs  : rsp 0x%llx rax 0x%llx rcx 0x%llx rdx 0x%llx r8 0x%llx r9 0x%llx\n",
          bb.rsp, bb.rax, bb.rcx, bb.rdx, bb.r8, bb.r9);
    /* What the handler DID, printed next to the fault itself. In v6 the two outcomes mean very
       different things: recovered = the client is still alive and the payload reported a failure;
       passed on = the client's own handler now owns it. Printing only the -1 that v6 fixed is how
       a hang came to look like a record. */
    static const char* rwhy[] = { "not one of our calls", "no payload range was supplied",
                                  "the walk left the committed stack",
                                  "walked the stack, no return address into the payload",
                                  "recovered" };
    logf_("  faulting thread: tid %u; the payload was delivered on tid %u -> %s\n",
          bb.fault_tid, bb.expected_tid,
          bb.ours ? "OUR thread, so this fault is ours to fix"
                  : "NOT our thread - the client's own fault, handed on deliberately");
    logf_("  recorder       : %s (returned %d, why %u: %s, walked %llu, faulting rsp 0x%llx)\n",
          bb.recovered ? "RECOVERED - control was moved back into the payload, the client is unaffected"
                       : "passed on to the client's own handler (EXCEPTION_CONTINUE_SEARCH)",
          (int)bb.handler_rc, bb.recover_why, bb.recover_why < 5 ? rwhy[bb.recover_why] : "?",
          bb.walked, bb.fault_rsp);
    if (bb.recovered)
        logf_("  resumed at     : 0x%llx (this payload), rva of the fault 0x%llx\n",
              bb.resume_rip, bb.fault_rva);
    return true;
}

static void report(const cc_ctx& c)
{
    static const char* st[] = { "OK", "BAD_CTX", "BAD_IMAGE", "BAD_SCHEDULER", "BAD_JOB_VECTOR", "NO_LUA_STATE" };
    logf_("\n=== payload result (from inside the target) ===\n");
    logf_("  status              : %u (%s)\n", c.status,
          c.status <= 5 ? st[c.status] : "?");
    logf_("  image base          : 0x%llx  (size 0x%llx)\n", c.roblox_base, c.image_size);
    logf_("  TaskScheduler       : 0x%llx\n", c.sched);
    logf_("  jobs                : %llu at 0x%llx (first job 0x%llx)\n",
          c.job_count, c.job_begin, c.job_first);
    logf_("  jobs seen / w/ state: %u / %u\n", c.jobs_seen, c.jobs_with_state);
    logf_("  ScriptContext (job) : 0x%llx\n", c.sc_from_job);
    logf_("  DataModel           : 0x%llx\n", c.datamodel);
    logf_("  ScriptContext (DM)  : 0x%llx   routes agree: %s\n", c.sc_from_dm,
          c.sc_routes_agree ? "YES" : "no");
    logf_("  lua_State           : 0x%llx   (via SC+0x%x)\n", c.lua_state, c.lua_state_off);
    logf_("  resume depth        : %u   (ScriptContextResume bails at >= 3)\n", c.resume_depth);
    logf_("  offsets tried       : %u candidates, %u rejected by the readability gate\n",
          c.lua_state_offsets_tried, c.reads_gated);
    logf_("  first tt probes     :");
    for (uint32_t i = 0; i < c.tt_count && i < 8; ++i) logf_(" 0x%llx", c.tt_seen[i]);
    logf_("\n");
    logf_("  EnableLoadModule    : %llu   (0x%llx)\n", c.flags[0], CC_RVA_ENABLE_LOAD_MODULE);
    logf_("  gate A (LuaVM_Load) : %llu   (0x%llx, RbsConfigAliasResolution)\n", c.flags[1], CC_RVA_GATE_A);
    logf_("  gate B (LuaVM_Load) : %llu   (0x%llx, RemoveBytecodeCopyOnLoad)\n", c.flags[2], CC_RVA_GATE_B);

    if (c.exec_mode || c.exec_status) {
        static const char* es[] = { "OFF", "LOADED", "RESUMED", "BAD_ARGS", "NO_STATE", "LOAD_FAILED",
                                   "DRY (guards ok, nothing called)", "NO_ARG1 (refused before the call)",
                                   "FAULTED (recovered by the recorder)" };
        const uint32_t es_n = (uint32_t)(sizeof(es) / sizeof(es[0]));
        logf_("  --- exec (v3) ---\n");
        logf_("  exec mode           : %u (%s)\n", c.exec_mode, exec_mode_name(c.exec_mode));
        logf_("  exec stage          : %u - %s\n", c.exec_stage, stage_name(c.exec_stage));
        logf_("  exec status         : %u (%s)\n", c.exec_status,
              c.exec_status < es_n ? es[c.exec_status] : "?");
        /* Whether a call HAPPENED is a fact about the run, not about the mode. A dry run never
           calls anything, and a refused exec has no numbers to show - so printing "rax=0,
           args.result=0 -> the loader accepted the chunk" for those reads as a success this code
           never observed. Only a run that actually reached the call gets the verdict line. */
        /* The ARG1 evidence, on every exec run. This is what turns "it refused" into a number the
           next run can act on - `arg1 size 0` and `buckets 0` is precisely the state that faulted
           the client on 2026-10-10, and the loader cannot be called through it. */
        if (c.arg1_ok || c.exec_status == CC_EXEC_NO_ARG1)
            logf_("  arg1 ([L+0x18])     : 0x%llx -> size %llu, buckets 0x%llx  (%s)\n",
                  c.arg1_field, c.arg1_size, c.arg1_buckets,
                  c.arg1_ok ? "usable - the loader's own dereference is satisfied"
                            : "NOT usable - this is the crash Execute used to cause");
        if (c.fault_recovered)
            logf_("  fault recovered     : yes, at rva 0x%llx - the client survived the call\n", c.fault_rva);
        if (c.exec_status == CC_EXEC_LOADED || c.exec_status == CC_EXEC_RESUMED ||
            c.exec_status == CC_EXEC_LOAD_FAILED) {
            logf_("  loader              : rax=%u, args.result=%u  -> %s\n", c.loader_rc, c.loader_result,
                  (c.loader_rc == 0 && c.loader_result == 0) ? "the loader accepted the chunk"
                                                             : "the loader REJECTED the chunk");
            if (c.exec_mode >= 2)
                logf_("  resume              : rax=%u, result[0]=%u  (%s)\n", c.resume_rc, c.resume_result,
                      c.exec_status == CC_EXEC_RESUMED ? "the resume returned" : "NOT reached");
        } else {
            logf_("  loader              : NOT called (%s)\n", exec_not_called_why(c.exec_status));
        }
    }
}

/* ------------------------------------------------------------------ inject ------------ */

/* ------------------------------------------------------- stub + hijack delivery ------------
   Why this exists: the APC route needs a thread to enter an ALERTABLE wait, and measurement says
   that on this client it does not happen. Live run (2026-10-08, home screen): an APC queued on
   every one of 146 threads, 60 s of watching, ZERO dispatches. A delivery mechanism that depends
   on another process's cooperation is not a mechanism.

   So the payload is delivered the way the header always reserved room for (reserved_ntcontinue):
   suspend ONE thread, point its RIP at a stub we write into the target, and let the stub call the
   payload and then restore the thread's exact context through NtContinue. Watch what that stub
   does and does not do:
     * it does NOT need the thread to cooperate, and it does NOT create a thread;
     * it is position-independent (absolute immediates only), so it runs at any address;
     * it ends in NtContinue with the context we saved BEFORE touching RIP, so the thread resumes
       with its registers, stack and flags exactly as they were - the 8 bytes `call rax` pushes are
       below the stack pointer the thread was using and are discarded by the restore.
   The remaining risk is stated rather than hidden: a thread suspended inside a kernel transition
   resumes through a syscall return path, which is the classic failure mode of this technique. */

static bool build_stub(uint8_t* out, size_t* len, uint64_t ctx, uint64_t payload,
                       uint64_t p_saved_ctx, uint64_t nt_continue)
{
    size_t i = 0;
    auto movabs = [&](uint8_t low_reg, uint64_t imm) {
        out[i++] = 0x48; out[i++] = (uint8_t)(0xB8 + low_reg);
        memcpy(out + i, &imm, 8); i += 8;
    };
    movabs(1, ctx);            /* mov rcx, ctx        */
    movabs(0, payload);        /* mov rax, payload    */
    out[i++] = 0xFF; out[i++] = 0xD0;                    /* call rax */
    movabs(1, p_saved_ctx);    /* mov rcx, &CONTEXT   */
    out[i++] = 0x31; out[i++] = 0xD2;                    /* xor edx, edx (TestAlert=FALSE) */
    movabs(0, nt_continue);    /* mov rax, NtContinue */
    out[i++] = 0xFF; out[i++] = 0xE0;                    /* jmp rax - never returns */
    *len = i;
    return i <= 64;
}

/* Which thread to hijack MATTERS, and not in a subtle way. A thread blocked in a kernel wait does
   not pick up a changed RIP - the kernel resumes it from its own trap frame - so redirecting one
   looks like success and dispatches nothing. Measured here: thread 6392 redirected, client healthy,
   payload never ran. A thread that is actually RUNNING is in user mode, so SuspendThread + SetThread
   Context lands squarely. So: sample per-thread CPU twice and take the busiest. */
struct busy_tid { DWORD tid; unsigned long long delta; };

static int pick_busy_threads(DWORD pid, busy_tid* out, int maxn)
{
    struct samp { DWORD tid; unsigned long long t; };
    std::vector<samp> a, b;
    auto sample = [&](std::vector<samp>& into) {
        into.clear();
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return;
        THREADENTRY32 te{ sizeof(te) };
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != pid) continue;
                HANDLE th = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (!th) continue;
                FILETIME c{}, e{}, k{}, u{};
                if (GetThreadTimes(th, &c, &e, &k, &u)) {
                    unsigned long long t = ((unsigned long long)k.dwHighDateTime << 32 | k.dwLowDateTime)
                                         + ((unsigned long long)u.dwHighDateTime << 32 | u.dwLowDateTime);
                    into.push_back({ te.th32ThreadID, t });
                }
                CloseHandle(th);
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    };
    sample(a);
    Sleep(60);
    sample(b);
    std::vector<busy_tid> v;
    for (const auto& x : b)
        for (const auto& y : a)
            if (x.tid == y.tid && x.t > y.t) { v.push_back({ x.tid, x.t - y.t }); break; }
    for (size_t i = 0; i < v.size(); ++i)          /* simple selection sort, tiny n */
        for (size_t j = i + 1; j < v.size(); ++j)
            if (v[j].delta > v[i].delta) { busy_tid t = v[i]; v[i] = v[j]; v[j] = t; }
    int n = (int)(std::min)((size_t)maxn, v.size());   /* windows.h defines min() as a macro */
    for (int i = 0; i < n; ++i) out[i] = v[i];
    return n;
}

/* Move ONE thread's RIP to the stub. Returns true only if the context was saved, RIP was moved and
   the thread was resumed - the caller then polls the payload's own context for the result, exactly
   as it does on the APC path. Deliberately does not poll here: one wait loop, one place to look. */
/* Where a thread was, WITHOUT touching it. This matters more than it looks: a thread parked in a
   kernel wait resumes from the kernel's own trap frame, so a redirect can report success and
   dispatch nothing - and the reverse mistake (dropping a redirect into a thread that is midway
   through VM work) is worse. So read first, decide, and only then redirect. */
static uint64_t thread_rip(DWORD tid)
{
    HANDLE th = OpenThread(THREAD_GET_CONTEXT, FALSE, tid);
    if (!th) return 0;
    CONTEXT c{};
    c.ContextFlags = CONTEXT_CONTROL;
    uint64_t rip = GetThreadContext(th, &c) ? (uint64_t)c.Rip : 0;
    CloseHandle(th);
    return rip;
}

/* Move ONE thread's RIP to the stub. Returns true only if the context was saved, RIP was moved and
   the thread was resumed - the caller then polls the payload's own context for the result, exactly
   as it does on the APC path. Returns false WITHOUT writing anything when the thread is not in the
   image at this instant (redirectable_ip): that write is the one measured to kill this client. */
static bool hijack_one(HANDLE proc, DWORD tid, uint64_t stub_va, uint64_t saved_va,
                       uint64_t image, uint32_t image_size)
{
    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                           FALSE, tid);
    if (!th) return false;
    if (SuspendThread(th) == (DWORD)-1) { CloseHandle(th); return false; }

    CONTEXT c{};
    c.ContextFlags = CONTEXT_FULL;
    bool ok = GetThreadContext(th, &c) != 0;
    if (ok && !redirectable_ip((uint64_t)c.Rip, image, image_size)) {
        /* Nothing is written here - not even the saved copy. The thread is resumed with the exact
           context it was suspended with: untouched is the only safe state to hand back a thread
           whose rip we do not understand. */
        logf_("  hijack         : thread %-6lu REFUSED - stopped at rip 0x%llx, outside the client\n"
              "                   image (the target's ntdll / another module: a kernel transition).\n"
              "                   The caller's earlier sample of this thread said in-image, so this\n"
              "                   is where the write would have landed. Resumed untouched.\n",
              tid, (uint64_t)c.Rip);
        ResumeThread(th);
        CloseHandle(th);
        return false;
    }
    /* save the WHOLE context BEFORE moving RIP: the thread's future depends on that write landing */
    if (ok) ok = WriteProcessMemory(proc, (LPVOID)saved_va, &c, sizeof(c), nullptr) != 0;
    if (ok) {
        c.Rip = stub_va;
        ok = SetThreadContext(th, &c) != 0;
    }
    ResumeThread(th);
    CloseHandle(th);
    return ok;
}

/* The main image of ANY process, for --stand-in. Toolhelp lists the main image first. */
static uint64_t main_module_base(DWORD pid, uint32_t* size_out)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    uint64_t base = 0;
    if (Module32FirstW(snap, &me)) {
        base = (uint64_t)me.modBaseAddr;
        if (size_out) *size_out = me.modBaseSize;
    }
    CloseHandle(snap);
    return base;
}

static int inject(DWORD pid, int timeout_ms, int watch_ms, int max_threads, bool use_hijack,
                  const char* exec_source = nullptr, int exec_mode = 2)
{
    HANDLE proc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
                              PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!proc) { logf_("FAIL: OpenProcess(pid %lu) err=%lu\n", pid, GetLastError()); return -1; }

    wchar_t path[MAX_PATH]{}; DWORD plen = MAX_PATH;
    if (!QueryFullProcessImageNameW(proc, 0, path, &plen)) path[0] = 0;
    uint64_t base = module_base(pid, TARGET_EXE);
    if (!base && g_stand_in) base = main_module_base(pid, nullptr);   /* --stand-in: any process */
    uint64_t k32  = module_base(pid, L"kernel32.dll");

    logf_("\n--- target ---\n");
    logf_("  pid            : %lu\n", pid);
    logf_("  image          : %ls\n", path);
    logf_("  base / kernel32: 0x%llx / 0x%llx\n", base, k32);

    if (!base || !k32) { logf_("FAIL: could not read the target module list\n"); CloseHandle(proc); return -1; }

    bool build_ok = wcsstr(path, L"version-cec3ad5889b447cf") != nullptr;
    if (!build_ok && g_stand_in)
        logf_("  stand-in       : NOT the client build. This run tests the delivery mechanism and its\n"
              "                   restore, nothing else - the payload will refuse (it validates the\n"
              "                   scheduler before it dereferences anything).\n");
    if (!build_ok && !g_stand_in) {
        logf_("REFUSING: this is not %ls. Every offset in this payload is build-specific, and the\n"
              "          whole point of the build gate is that guessing here crashes the client.\n",
              TARGET_VERSION);
        CloseHandle(proc);
        return -1;
    }

    uint32_t e_lfanew = 0, image_size = 0;
    if (!rpm(proc, base + 0x3C, &e_lfanew, 4) || !rpm(proc, base + e_lfanew + 0x50, &image_size, 4)) {
        logf_("FAIL: cannot read the target PE headers\n"); CloseHandle(proc); return -1;
    }
    logf_("  image size     : 0x%x\n", image_size);

    size_t blob_size = 0;
    uint8_t* blob = find_section(".cpl", &blob_size);
    if (!blob || blob_size == 0 || blob_size > 0x8000) {
        logf_("FAIL: .cpl section not found or implausible (%p, %llu bytes)\n", blob, (unsigned long long)blob_size);
        CloseHandle(proc); return -1;
    }
    uint64_t fn_sym = (uint64_t)&cc_payload;
    uint64_t fn_addr = resolve_entry_thunk(fn_sym, blob, blob + blob_size);
    if (fn_addr != fn_sym)
        logf_("  entry          : symbol is a thunk - followed it\n");
    if (fn_addr < (uint64_t)blob || fn_addr >= (uint64_t)blob + blob_size) {
        /* Report the numbers. A check that fails without saying what it compared is a check that
           costs a session to debug - this one already did, once. */
        uint8_t* own = (uint8_t*)GetModuleHandleW(nullptr);
        logf_("FAIL: cc_payload is not inside .cpl - the section is not what we think it is\n");
        logf_("  .cpl      : rva 0x%llx, size 0x%llx\n",
              (unsigned long long)(blob - own), (unsigned long long)blob_size);
        logf_("  cc_payload: symbol rva 0x%llx, resolved rva 0x%llx -> %+lld bytes from the section start\n",
              (unsigned long long)(fn_sym - (uint64_t)own), (unsigned long long)(fn_addr - (uint64_t)own),
              (long long)(fn_addr - (uint64_t)blob));
        auto dos = (IMAGE_DOS_HEADER*)own;
        auto nt = (IMAGE_NT_HEADERS*)(own + dos->e_lfanew);
        auto sec = IMAGE_FIRST_SECTION(nt);
        logf_("  our sections (%u):\n", nt->FileHeader.NumberOfSections);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
            logf_("    %-8.8s rva 0x%-6llx vsize 0x%-6llx chars 0x%x\n", sec[i].Name,
                  (unsigned long long)sec[i].VirtualAddress, (unsigned long long)sec[i].Misc.VirtualSize,
                  sec[i].Characteristics);
        CloseHandle(proc); return -1;
    }
    logf_("  payload        : %llu bytes at .cpl, entry 0x%llx (+0x%llx into the section)\n",
          (unsigned long long)blob_size, fn_addr, fn_addr - (uint64_t)blob);

    /* --- place the blob --- */
    void* remote_blob = VirtualAllocEx(proc, nullptr, blob_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_blob) { logf_("FAIL: VirtualAllocEx(blob) err=%lu\n", GetLastError()); CloseHandle(proc); return -1; }
    if (!WriteProcessMemory(proc, remote_blob, blob, blob_size, nullptr)) {
        logf_("FAIL: WriteProcessMemory(blob) err=%lu\n", GetLastError());
        VirtualFreeEx(proc, remote_blob, 0, MEM_RELEASE); CloseHandle(proc); return -1;
    }
    DWORD old = 0;
    if (!VirtualProtectEx(proc, remote_blob, blob_size, PAGE_EXECUTE_READ, &old)) {
        logf_("FAIL: VirtualProtectEx(RX) err=%lu\n", GetLastError());
        VirtualFreeEx(proc, remote_blob, 0, MEM_RELEASE); CloseHandle(proc); return -1;
    }
    uint64_t entry = (uint64_t)remote_blob + (fn_addr - (uint64_t)blob);

    void* remote_ctx = VirtualAllocEx(proc, nullptr, sizeof(cc_ctx), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_ctx) { logf_("FAIL: VirtualAllocEx(ctx)\n"); VirtualFreeEx(proc, remote_blob, 0, MEM_RELEASE); CloseHandle(proc); return -1; }

    cc_ctx ctx{};
    memset(&ctx, 0, sizeof(ctx));
    ctx.marker = CC_MARK;
    ctx.abi = (uint32_t)sizeof(cc_ctx);
    ctx.self_va = (uint64_t)remote_ctx;
    ctx.vq = k32 + ((uint64_t)&VirtualQuery - (uint64_t)GetModuleHandleW(L"kernel32.dll"));
    ctx.roblox_base = base;
    ctx.kernel32_base = k32;
    ctx.image_size = image_size;
    /* The payload's own range in the target. The recorder needs it to recognise its own return
       address on a faulting stack (that is how a faulted call gets recovered instead of killing
       the client), and "roughly right" is not good enough for that: it must be the exact range
       the .cpl section was copied to. */
    ctx.payload_lo = (uint64_t)remote_blob;
    ctx.payload_hi = blob_size ? (uint64_t)remote_blob + blob_size : 0;

    /* --- optional: the exec block (v3). The source is compiled HERE, in our process, and only the
       result crosses. One block in the target holds all three things the loader needs to be
       pointed at: the scratch struct the payload fills, the chunk name, and the bytecode. They
       go in ONE allocation so a single address describes the whole arrangement and no field is
       ever computed by two programs differently. */
    void* remote_exec = nullptr;
    if (exec_source) {
        void* code = nullptr; size_t code_size = 0; char err[512] = { 0 };
        int crc = cc_compile_source(exec_source, strlen(exec_source), &code, &code_size, err, sizeof(err));
        if (crc != 0) {
            logf_("FAIL: the editor's Luau did not compile (code %d): %s\n", crc, err[0] ? err : "unknown");
            logf_("      nothing was placed in the target - a syntax error never reaches the client.\n");
            VirtualFreeEx(proc, remote_ctx, 0, MEM_RELEASE);
            VirtualFreeEx(proc, remote_blob, 0, MEM_RELEASE);
            CloseHandle(proc);
            return -3;
        }
        unsigned v = cc_bytecode_version(code, code_size), tv = cc_bytecode_type_version(code, code_size);
        logf_("  compile        : %llu byte(s) of source -> %llu byte(s) of bytecode, version %u / type %u (%s)\n",
              (unsigned long long)strlen(exec_source), (unsigned long long)code_size, v, tv,
              cc_bytecode_acceptable(v, tv) ? "inside the loader's window" : "OUTSIDE THE LOADER'S WINDOW");
        if (!cc_bytecode_acceptable(v, tv)) {
            logf_("FAIL: refusing to hand the loader a version its own gate rejects.\n");
            cc_compile_free(code);
            VirtualFreeEx(proc, remote_ctx, 0, MEM_RELEASE);
            VirtualFreeEx(proc, remote_blob, 0, MEM_RELEASE);
            CloseHandle(proc);
            return -3;
        }
        const char* chunkname = "@CarbonEditor";
        /* Layout, in one allocation so one address describes the whole arrangement:
             [0]                  the scratch struct the payload fills (and the std::string it
                                  builds for the container path lives in there too)
             [name_off]           the chunk name, NUL-terminated
             [code_off]           the compiled bytecode
             [src_off]            the SOURCE text, for the container modes (4/5)
           The source is placed for the container because LuaVM_Load's ARG2 is a std::string it
           PARSES (`call 0x4188770` right after its size test at +0x10), so the client's own entry
           wants the payload, and mode 5 exists to ask whether it also accepts raw bytecode. */
        uint64_t name_off = (uint64_t)sizeof(cc_exec_scratch);
        uint64_t code_off = (name_off + strlen(chunkname) + 1 + 7) & ~(uint64_t)7;
        size_t src_size = strlen(exec_source) + 1;
        uint64_t src_off = (code_off + code_size + 7) & ~(uint64_t)7;
        size_t total = (size_t)(src_off + src_size);
        if (total > (8u << 20)) {
            logf_("FAIL: exec block would be %llu bytes - refusing\n", (unsigned long long)total);
            cc_compile_free(code);
            VirtualFreeEx(proc, remote_ctx, 0, MEM_RELEASE);
            VirtualFreeEx(proc, remote_blob, 0, MEM_RELEASE);
            CloseHandle(proc);
            return -3;
        }
        std::vector<uint8_t> blk(total, 0);
        memcpy(blk.data() + name_off, chunkname, strlen(chunkname) + 1);
        memcpy(blk.data() + code_off, code, code_size);
        memcpy(blk.data() + src_off, exec_source, src_size);
        cc_compile_free(code);
        remote_exec = VirtualAllocEx(proc, nullptr, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remote_exec || !WriteProcessMemory(proc, remote_exec, blk.data(), total, nullptr)) {
            logf_("FAIL: could not place the exec block (err=%lu)\n", GetLastError());
            if (remote_exec) VirtualFreeEx(proc, remote_exec, 0, MEM_RELEASE);
            VirtualFreeEx(proc, remote_ctx, 0, MEM_RELEASE);
            VirtualFreeEx(proc, remote_blob, 0, MEM_RELEASE);
            CloseHandle(proc);
            return -3;
        }
        ctx.exec_scratch = (uint64_t)remote_exec;
        ctx.chunkname = (uint64_t)remote_exec + name_off;
        ctx.bytecode = (uint64_t)remote_exec + code_off;
        ctx.bytecode_size = code_size;
        ctx.loader_va = base + CC_RVA_LOADER;
        ctx.resume_va = base + CC_RVA_RESUME_WRAPPER;
        ctx.container_va = base + CC_RVA_CONTAINER;
        /* What the container is handed as its std::string: the source for mode 4 (its parser's
           obvious input), the compiled bytecode for mode 5 (the question that mode exists to ask). */
        if (exec_mode == 5) {
            ctx.container_payload = (uint64_t)remote_exec + code_off;
            ctx.container_size = code_size;
        } else {
            ctx.container_payload = (uint64_t)remote_exec + src_off;
            ctx.container_size = src_size - 1;      /* the NUL is not part of the string */
        }
        ctx.exec_mode = (uint32_t)exec_mode;
        logf_("  exec block     : %llu byte(s) at 0x%llx - scratch, name \"%s\", bytecode, source\n",
              (unsigned long long)total, (uint64_t)remote_exec, chunkname);
        if (exec_mode >= 4)
            logf_("  container arg2 : %s, %llu byte(s) at 0x%llx (capacity forced to %llu: below 16\n"
                  "                   MSVC stores the string inline and the entry would read our\n"
                  "                   pointer's bytes as text)\n",
                  exec_mode == 5 ? "raw bytecode" : "the source text",
                  (unsigned long long)ctx.container_size, ctx.container_payload,
                  (unsigned long long)(ctx.container_size < 16 ? 16 : ctx.container_size));
        logf_("  exec plan      : %s\n", exec_mode_name((uint32_t)exec_mode));
        logf_("  exec targets   : loader 0x%llx (rva 0x%llx), container 0x%llx (rva 0x%llx), "
             "resume 0x%llx (rva 0x%llx)\n",
             base + CC_RVA_LOADER, (unsigned long long)CC_RVA_LOADER,
             base + CC_RVA_CONTAINER, (unsigned long long)CC_RVA_CONTAINER,
             base + CC_RVA_RESUME_WRAPPER, (unsigned long long)CC_RVA_RESUME_WRAPPER);
    } else {
        ctx.exec_mode = 0;          /* the read-only audit: exactly the bytes audited before */
    }

    /* --- the black box (v4). Three more target allocations: the record itself, and a 15-byte
       trampoline that supplies the cc_ctx pointer the handler cannot otherwise know (a payload has
       no data section across the process boundary - only .cpl is copied). The handler address is
       resolved out of the SAME blob, so the recorder the target runs is the exact bytes the
       self-test just executed here. */
    uint64_t veh_addr = 0;
    {
        uint64_t veh_sym = (uint64_t)&cc_veh;
        veh_addr = resolve_entry_thunk(veh_sym, blob, blob + blob_size);
    }
    void* remote_bb = nullptr;
    void* remote_tramp = nullptr;
    if (veh_addr < (uint64_t)blob || veh_addr >= (uint64_t)blob + blob_size) {
        logf_("  recorder       : cc_veh is not inside .cpl (%+lld bytes from the section start) -\n"
              "                   no recorder this run\n", (long long)(veh_addr - (uint64_t)blob));
    } else {
        remote_bb = VirtualAllocEx(proc, nullptr, sizeof(cc_blackbox), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        remote_tramp = VirtualAllocEx(proc, nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        uint64_t handler_va = entry + (veh_addr - (uint64_t)blob);
        if (remote_bb && remote_tramp) {
            uint8_t tr[32] = { 0 };
            size_t ti = 0;
            tr[ti++] = 0x48; tr[ti++] = 0xBA;                       /* mov rdx, <ctx> */
            memcpy(tr + ti, &remote_ctx, 8); ti += 8;
            tr[ti++] = 0x48; tr[ti++] = 0xB8;                       /* mov rax, <handler> */
            memcpy(tr + ti, &handler_va, 8); ti += 8;
            tr[ti++] = 0xFF; tr[ti++] = 0xE0;                       /* jmp rax */
            DWORD op = 0;
            bool ok = WriteProcessMemory(proc, remote_tramp, tr, ti, nullptr) != 0;
            ok = ok && VirtualProtectEx(proc, remote_tramp, 64, PAGE_EXECUTE_READ, &op) != 0;
            if (!ok) {
                logf_("  recorder       : could not arm the trampoline (err=%lu) - no recorder this run\n",
                      GetLastError());
                VirtualFreeEx(proc, remote_bb, 0, MEM_RELEASE); remote_bb = nullptr;
                VirtualFreeEx(proc, remote_tramp, 0, MEM_RELEASE); remote_tramp = nullptr;
            } else {
                ctx.add_veh = k32 + ((uint64_t)&AddVectoredExceptionHandler -
                                     (uint64_t)GetModuleHandleW(L"kernel32.dll"));
                /* and the way back out: without it the payload cannot disarm the recorder, and a
                   registered handler whose code we are about to unmap is the client's death */
                ctx.remove_veh = k32 + ((uint64_t)&RemoveVectoredExceptionHandler -
                                        (uint64_t)GetModuleHandleW(L"kernel32.dll"));
                /* The recorder's new test for "is this fault ours": the thread id. See payload.h v7 -
                   the address test let a null-pointer fault from our own call kill the client. */
                ctx.get_tid = k32 + ((uint64_t)&GetCurrentThreadId -
                                     (uint64_t)GetModuleHandleW(L"kernel32.dll"));
                ctx.veh_handler = (uint64_t)remote_tramp;
                ctx.blackbox = (uint64_t)remote_bb;
                ctx.bb_hold_loops = 250000000u;    /* ~0.5 s of spin: >> the 20 ms poll */
                logf_("  recorder       : armed - handler 0x%llx (rva 0x%llx), trampoline 0x%llx, record 0x%llx\n",
                      handler_va, veh_addr, (uint64_t)remote_tramp, (uint64_t)remote_bb);
            }
        } else {
            logf_("  recorder       : could not allocate the record/trampoline (err=%lu)\n", GetLastError());
            if (remote_bb) { VirtualFreeEx(proc, remote_bb, 0, MEM_RELEASE); remote_bb = nullptr; }
            if (remote_tramp) { VirtualFreeEx(proc, remote_tramp, 0, MEM_RELEASE); remote_tramp = nullptr; }
        }
    }

    if (!WriteProcessMemory(proc, remote_ctx, &ctx, sizeof(ctx), nullptr)) {
        logf_("FAIL: WriteProcessMemory(ctx)\n");
        VirtualFreeEx(proc, remote_ctx, 0, MEM_RELEASE);
        VirtualFreeEx(proc, remote_blob, 0, MEM_RELEASE);
        CloseHandle(proc);
        return -1;
    }

    logf_("  placed         : payload @0x%llx (RX), ctx @0x%llx (RW) - both freed on the way out\n",
          (uint64_t)remote_blob, (uint64_t)remote_ctx);

    /* --- deliver: one APC per thread, no thread is touched or created --- */
    int queued = 0, threads_seen = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te{ sizeof(te) };
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != pid) continue;
                ++threads_seen;
                if (queued >= max_threads) continue;
                HANDLE th = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (!th) continue;
                if (QueueUserAPC((PAPCFUNC)entry, th, (ULONG_PTR)remote_ctx)) ++queued;
                CloseHandle(th);
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }
    logf_("  delivery       : %d APC(s) queued across %d thread(s) - no CreateRemoteThread, no module\n",
          queued, threads_seen);

    /* --- optional: hijack delivery, for when no thread ever reaches an alertable wait --- */
    if (use_hijack) {
        uint64_t tn = module_base(pid, L"ntdll.dll");
        uint64_t on = (uint64_t)GetModuleHandleW(L"ntdll.dll");
        if (!tn || !on) { logf_("FAIL: cannot locate ntdll in the target\n"); }
        else {
            /* Which restore primitive to use is NOT a constant of the platform: measured live on this
               client, the target's NtContinue starts `e9 81 f5 e8` - an inline jmp, i.e. a HOOK -
               while ours starts `4c 8b d1 b8`. Jumping into that hook would hand the client's own
               anti-cheat the thread the payload is running on. So each candidate is checked against
               our own copy of the same image (identical RVA, since both processes map the same
               ntdll), and the first CLEAN one that takes (context, arg) is used. The log names the
               hooked ones, because that list is itself worth knowing. */
            /* both take (CONTEXT*, arg) and both "restore this context and continue" - RtlUnwindEx is
               deliberately NOT here: it unwinds, which is a different operation wearing a similar
               name, and calling it on a live thread is not a restore. */
            const char* cands[] = { "NtContinue", "RtlRestoreContext" };
            uint64_t ntcont = 0;
            for (const char* fname : cands) {
                uint64_t ours = (uint64_t)GetProcAddress((HMODULE)on, fname);
                if (!ours) { logf_("  restore        : %-18s not exported here\n", fname); continue; }
                uint8_t mine[16] = { 0 }, theirs[16] = { 0 };
                memcpy(mine, (const void*)ours, sizeof(mine));
                uint64_t at = tn + (ours - on);
                bool read_ok = rpm(proc, at, theirs, sizeof(theirs));
                bool clean = read_ok && memcmp(mine, theirs, sizeof(mine)) == 0;
                logf_("  restore        : %-18s target 0x%llx  %s   (ours %02x %02x %02x %02x / theirs %02x %02x %02x %02x)\n",
                      fname, at, !read_ok ? "UNREADABLE" : (clean ? "clean" : "HOOKED"),
                      mine[0], mine[1], mine[2], mine[3], theirs[0], theirs[1], theirs[2], theirs[3]);
                if (clean && !ntcont) ntcont = at;
            }
            bool pro_ok = ntcont != 0;
            void* remote_stub = VirtualAllocEx(proc, nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            void* remote_save = VirtualAllocEx(proc, nullptr, sizeof(CONTEXT) + 64, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!pro_ok || !remote_stub || !remote_save) {
                logf_("FAIL: hijack setup (ntcont prologue %s, stub %p, save %p)\n",
                      pro_ok ? "ok" : "unrecognised", remote_stub, remote_save);
            } else {
                uint8_t stub[64] = { 0 };
                size_t stub_len = 0;
                build_stub(stub, &stub_len, (uint64_t)remote_ctx, entry,
                           (uint64_t)remote_save, ntcont);
                bool ok = WriteProcessMemory(proc, remote_stub, stub, stub_len, nullptr) != 0;
                DWORD oldp = 0;
                ok = ok && VirtualProtectEx(proc, remote_stub, 64, PAGE_EXECUTE_READ, &oldp) != 0;
                if (!ok) {
                    logf_("FAIL: could not write/arm the stub\n");
                } else {
                    logf_("  hijack         : stub 0x%llx (%llu bytes), saved context 0x%llx, NtContinue 0x%llx\n",
                          (uint64_t)remote_stub, (unsigned long long)stub_len,
                          (uint64_t)remote_save, ntcont);
                    /* prefer a thread that is not the process's first (main/UI) one */
                    DWORD tids[8] = { 0 };
                    int n = 0;
                    HANDLE snap2 = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                    if (snap2 != INVALID_HANDLE_VALUE) {
                        THREADENTRY32 te{ sizeof(te) };
                        if (Thread32First(snap2, &te)) {
                            do {
                                if (te.th32OwnerProcessID != pid) continue;
                                if (n < 8) tids[n++] = te.th32ThreadID;
                            } while (Thread32Next(snap2, &te));
                        }
                        CloseHandle(snap2);
                    }
                    (void)tids;
                    /* ROUNDS. One redirect is a sample, not a delivery: if the thread happens to be
                       inside a kernel transition (entered from a syscall stub of the client's own),
                       the kernel restores RIP from its trap frame and the redirect is simply
                       swallowed - measured live, with the client alive and nothing dispatched.
                       Neither our log nor the thread can tell us that in advance, so the honest
                       response is to try again on a fresh sample instead of calling one attempt a
                       verdict. */
                    bool got_stage = false;
                    bool bb_said = false;
                    int busy_before = -1;       /* did this target have running threads when we started? */
                    for (int round = 0; round < 4; ++round) {
                    busy_tid busy[8]{};
                    int nb = pick_busy_threads(pid, busy, 8);
                    if (nb == 0) {
                        /* Zero CPU across EVERY thread in a 60 ms window has two readings, and they
                           are not the same fact. A client that was running threads and then has none
                           has FROZEN - measured 2026-10-10, in both crashed runs the whole target
                           went quiet within one sample of a redirect, ending in an access-violation
                           death and in a hang Windows had to close. A client that had none to begin
                           with is merely idle between frames, which is the case the old single
                           message described. Saying "frozen" for both would be a claim this run has
                           not earned, so the earlier sample decides which one is reported. */
                        DWORD ec0 = 0;
                        bool gone = GetExitCodeProcess(proc, &ec0) && ec0 != STILL_ACTIVE;
                        if (gone)
                            logf_("FAIL: the target exited (code 0x%lx) - there is no thread left to\n"
                                  "      redirect, and nothing else is attempted.\n", ec0);
                        else if (busy_before > 0)
                            logf_("FAIL: the target had %d thread(s) consuming CPU and now has none - that\n"
                                  "      is a FROZEN client, not a shortage of candidates (the shape of\n"
                                  "      both 2026-10-10 failures). Stopping the redirect path here.\n",
                                  busy_before);
                        else
                            logf_("  hijack         : no thread in the target is running anything this\n"
                                  "                   instant, so there is nothing to redirect. Load an\n"
                                  "                   experience so the client is running script jobs, then\n"
                                  "                   attach again.\n");
                        break;
                    }
                    if (busy_before <= 0) busy_before = nb;
                    int parked = 0;
                    /* Read every candidate's RIP BEFORE touching any of them, then order them: a
                       thread inside a VM entry point has the client's per-thread VM state, a plain
                       in-image thread does not. */
                    uint64_t rip0[8] = { 0 };
                    bool in_image[8] = { false };
                    const char* vmname[8] = { nullptr };
                    for (int i = 0; i < nb; ++i) {
                        rip0[i] = thread_rip(busy[i].tid);
                        in_image[i] = rip0[i] >= base && rip0[i] < base + image_size;
                        vmname[i] = in_image[i] ? vm_function_of(rip0[i], base) : nullptr;
                    }
                    for (int pass = 0; pass < 2; ++pass)   /* pass 0: VM threads, pass 1: the rest */
                    for (int i = 0; i < nb; ++i) {
                        if ((vmname[i] != nullptr) != (pass == 0)) continue;
                        logf_("  hijack         : thread %-6lu busy +%-8llu rip 0x%llx  %s\n",
                              busy[i].tid, busy[i].delta, rip0[i],
                              vmname[i] ? vmname[i]
                              : in_image[i] ? "inside the client image - running game/VM code"
                              : (rip0[i] >= tn && rip0[i] < tn + 0x200000) ? "inside ntdll - a wait" : "elsewhere");
                        if (!in_image[i]) {
                            /* Skip it rather than "try" it. Measured: redirecting a parked thread
                               reports success and dispatches nothing, and what happens to that
                               thread's VM state afterwards is not something to gamble a client on. */
                            ++parked;
                            continue;
                        }
                        /* Stamp the tid the payload must recognise as its own, IMMEDIATELY before
                           the redirect. Not earlier: an APC queued by an earlier round can dispatch
                           at any moment, and a payload that read a stale tid would classify its own
                           fault as the client's. This single 4-byte write is what makes a null-call
                           fault recoverable instead of fatal. */
                        {
                            uint32_t tid32 = busy[i].tid;
                            WriteProcessMemory(proc,
                                               (void*)((uint64_t)remote_ctx +
                                                       offsetof(cc_ctx, hijack_tid)),
                                               &tid32, sizeof(tid32), nullptr);
                        }
                        if (!hijack_one(proc, busy[i].tid, (uint64_t)remote_stub, (uint64_t)remote_save,
                                        base, image_size)) {
                            logf_("                   could not take that one\n");
                            continue;
                        }
                        uint64_t rip = 0, rsp = 0;
                        rpm(proc, (uint64_t)remote_save + 0xF8, &rip, 8);
                        rpm(proc, (uint64_t)remote_save + 0x98, &rsp, 8);
                        logf_("                   redirected from rip 0x%llx rsp 0x%llx - the payload will report\n", rip, rsp);
                        /* give it a moment to run and report before trying another, watching the
                           stage marker so a run that dies in a call still says which call */
                        DWORD last_stage = 0;
                        bool said_state = false;
                        DWORD t0 = GetTickCount();
                        while (GetTickCount() - t0 < 1200) {
                            cc_ctx probe{};
                            if (rpm(proc, (uint64_t)remote_ctx, &probe, sizeof(probe))) {
                                if (probe.done == CC_DONE) { logf_("                   dispatched\n"); break; }
                                if (probe.exec_stage != last_stage) {
                                    last_stage = probe.exec_stage;
                                    got_stage = true;
                                    logf_("                   stage %lu - %s\n", probe.exec_stage, stage_name(probe.exec_stage));
                                    /* the payload only reaches a stage after validating a state,
                                       so these facts are true of this run and are worth having
                                       even if the client dies on the next instruction */
                                    if (probe.exec_stage && !said_state) { said_state = true; log_state_facts(probe); }
                                }
                            }
                            /* the fault we are looking for happens ON this thread, inside this
                               window - so the recorder is checked here, not only after it */
                            poll_blackbox(proc, (uint64_t)remote_bb, base, image_size, &bb_said);
                            Sleep(20);
                        }
                        {   /* stop as soon as one thread reports */
                            cc_ctx probe{};
                            if (rpm(proc, (uint64_t)remote_ctx, &probe, sizeof(probe)) &&
                                probe.done == CC_DONE) break;
                        }
                    }
                    if (parked && nb == parked)
                        logf_("  hijack         : every candidate was parked in a wait - refusing to redirect any of\n"
                              "                   them. Load a game so the client is running script jobs, then re-run.\n");
                    {   /* did any redirect take? if not, take a fresh sample of threads and go again */
                        cc_ctx probe{};
                        bool dispatched = rpm(proc, (uint64_t)remote_ctx, &probe, sizeof(probe)) &&
                                          probe.done == CC_DONE;
                        if (dispatched) break;
                        logf_("  hijack         : round %d delivered nothing (redirects swallowed by a kernel\n"
                              "                   transition are invisible) - resampling threads\n", round + 1);
                    }
                    }   /* rounds */
                }
            }
        }
    }
    if (!queued && !use_hijack) {
        logf_("  NOTE: nothing was queued; the target allocations are left mapped on purpose so any\n"
              "        later dispatch cannot point at freed memory.\n");
        CloseHandle(proc);
        return -1;
    }

    /* --- wait for the payload to report --- */
    logf_("  waiting up to %d ms for a dispatch (an APC runs when its thread next enters an\n"
          "  alertable wait; game threads do that constantly)\n", timeout_ms);
    cc_ctx out{};
    bool got = false;
    bool bb_said = false;
    DWORD last_stage = 0;
    bool said_state = false;
    DWORD start = GetTickCount();
    while (GetTickCount() - start < (DWORD)timeout_ms) {
        poll_blackbox(proc, (uint64_t)remote_bb, base, image_size, &bb_said);
        Sleep(10);
        cc_ctx probe{};
        if (rpm(proc, (uint64_t)remote_ctx, &probe, sizeof(probe)) && probe.done == CC_DONE) {
            out = probe; got = true; break;
        }
        if (probe.exec_stage != last_stage) {
            last_stage = probe.exec_stage;
            logf_("  stage          : %lu - %s\n", probe.exec_stage, stage_name(probe.exec_stage));
            /* A run that dies inside a call never reports; these facts are the ones worth having
               afterwards, so they are logged the moment the payload says it got that far. */
            if (probe.exec_stage && !said_state) { said_state = true; log_state_facts(probe); }
        }
        DWORD ec = 0;
        if (GetExitCodeProcess(proc, &ec) && ec != STILL_ACTIVE) {
            logf_("  the target exited while we waited (code %lu)\n", ec);
            break;
        }
    }

    if (!got && watch_ms > 0) {
        logf_("  not dispatched yet; watching another %d ms (the APCs stay queued)\n", watch_ms);
        DWORD w = GetTickCount();
        while (GetTickCount() - w < (DWORD)watch_ms) {
            Sleep(20);
            cc_ctx probe{};
            if (rpm(proc, (uint64_t)remote_ctx, &probe, sizeof(probe)) && probe.done == CC_DONE) {
                out = probe; got = true; break;
            }
            DWORD ec = 0;
            if (GetExitCodeProcess(proc, &ec) && ec != STILL_ACTIVE) {
                logf_("  the target exited while we watched (code %lu)\n", ec);
                break;
            }
        }
    }

    int rc = 0;
    if (got) {
        report(out);
        logf_("  self_va check  : %s\n", out.self_va == (uint64_t)remote_ctx ? "ok" : "MISMATCH");
        if (remote_bb && !bb_said)
            logf_("  black box      : armed, nothing faulted this run%s\n",
                  out.veh_installed ? "" : " - but the payload did NOT install it in the target");
        /* A payload that reported success does NOT prove the client survived: measured once
           (SIGNATURES.md 9.4), the client died AFTER a run that had already reported. Watch for a
           couple of seconds and say which happened, so no later run has to infer it from a pid
           that no longer opens. */
        if (exec_source) {
            DWORD ec = 0;
            bool gone = false;
            for (int i = 0; i < 100; ++i) {
                Sleep(20);
                if (GetExitCodeProcess(proc, &ec) && ec != STILL_ACTIVE) { gone = true; break; }
            }
            if (gone) logf_("  client after run : EXITED (code 0x%lx) within 2 s of the report\n", ec);
            else      logf_("  client after run : alive 2 s after the report\n");
        }
        if (out.exec_status == CC_EXEC_RESUMED)
            logf_("  what to check  : the chunk's own print(...) in %%LOCALAPPDATA%%\\Roblox\\logs\\\n"
                  "                   <version>_Player_*_last.log - that is the chunk running, not a\n"
                  "                   return value of ours\n");
    } else {
        if (!bb_said && remote_bb)
            logf_("  black box      : armed, but no fault was ever recorded. Either the death was not\n"
                  "                   a first-chance exception on a thread we redirected, or the\n"
                  "                   recorder was never installed (see the 'recorder:' line above).\n");
        logf_("\n  no dispatch within the window: the APC(s) are still queued.\n"
              "  This is not a failure of the payload - it means no thread reached an alertable wait\n"
              "  while we were watching. Leaving both allocations mapped (a queued APC must keep a\n"
              "  valid target); re-run with --watch <ms> or run it while a game is actually loaded.\n");
        rc = 2;
        CloseHandle(proc);
        return rc;      /* deliberately no VirtualFreeEx here */
    }

    /* Freeing is only safe once nothing in the target can still reach into these pages. The one
       thing that can is the recorder: a VEH registration whose handler is the trampoline, which
       jumps into the blob. The payload disarms it in cc_finish and says so (veh_removed); if it did
       not - a run that died on the way out, or a payload too old to know about the field - the pages
       stay mapped on purpose, exactly like the queued-APC case above, and the run says why. */
    bool recorder_still_registered = false;
    {
        cc_ctx final_ctx{};
        if (rpm(proc, (uint64_t)remote_ctx, &final_ctx, sizeof(final_ctx)) &&
            final_ctx.veh_installed && !final_ctx.veh_removed)
            recorder_still_registered = true;
        if (final_ctx.veh_installed || final_ctx.veh_removed)
            logf_("  recorder       : %s (handle 0x%llx)\n",
                  final_ctx.veh_removed ? "disarmed in the target before the payload returned"
                                        : "STILL REGISTERED in the target",
                  (unsigned long long)final_ctx.veh_handle);
    }
    if (recorder_still_registered) {
        logf_("  allocations    : NOT freed. The recorder is still registered in the target (handler\n"
              "                   -> trampoline 0x%llx -> the blob at 0x%llx). Freeing now would leave\n"
              "                   the client's next handled exception jumping into unmapped memory.\n",
              (unsigned long long)remote_tramp, (unsigned long long)remote_blob);
        CloseHandle(proc);
        return rc;
    }
    VirtualFreeEx(proc, remote_ctx, 0, MEM_RELEASE);
    VirtualFreeEx(proc, remote_blob, 0, MEM_RELEASE);
    if (remote_bb) VirtualFreeEx(proc, remote_bb, 0, MEM_RELEASE);
    if (remote_tramp) VirtualFreeEx(proc, remote_tramp, 0, MEM_RELEASE);
    if (remote_exec) VirtualFreeEx(proc, remote_exec, 0, MEM_RELEASE);
    logf_("  allocations    : freed%s%s%s\n", remote_exec ? " (payload, ctx, exec block" : " (payload, ctx",
          remote_bb ? ", record, trampoline" : "", ")");
    CloseHandle(proc);
    return rc;
}

/* ------------------------------------------------------------------ ui bridge -------- */
/* The menu UI drives this exact pipeline - it does not get its own copy of it. Anything the UI
   can do, the CLI can do, and the reverse: same gate, same placement, same delivery. */

extern "C" void ccui_set_sink(void (*fn)(const char*)) { g_sink = fn; }

/* Compile for the UI/CLI and describe the result in one line. The acceptance test is the CLIENT's
   own rule (cc_bytecode_acceptable), not a version number hard-coded here: if the loader's window
   ever moves, this says so instead of quietly shipping bytecode it would reject. */
extern "C" int ccui_compile(const char* source, size_t len, char* summary, size_t cap)
{
    void* data = nullptr;
    size_t size = 0;
    char err[512] = { 0 };
    int rc = cc_compile_source(source, len, &data, &size, err, sizeof(err));
    if (rc != 0) {
        if (summary && cap) _snprintf_s(summary, cap, _TRUNCATE, "compile FAILED: %s", err[0] ? err : "unknown");
        return 1;
    }
    unsigned v = cc_bytecode_version(data, size);
    unsigned tv = cc_bytecode_type_version(data, size);
    if (summary && cap) {
        _snprintf_s(summary, cap, _TRUNCATE,
                    "compiled %llu byte(s): version %u, type version %u -> %s",
                    (unsigned long long)size, v, tv,
                    cc_bytecode_acceptable(v, tv) ? "acceptable to the client loader"
                                                  : "OUT OF THE LOADER'S WINDOW");
    }
    cc_compile_free(data);
    return 0;
}

static int run_compile(const char* source)
{
    void* data = nullptr;
    size_t size = 0;
    char err[512] = { 0 };
    int rc = cc_compile_source(source, strlen(source), &data, &size, err, sizeof(err));
    if (rc != 0) {
        printf("compile FAILED (code %d): %s\n", rc, err[0] ? err : "unknown");
        return 3;
    }
    unsigned v = cc_bytecode_version(data, size);
    unsigned tv = cc_bytecode_type_version(data, size);
    printf("source   : %llu byte(s)\n", (unsigned long long)strlen(source));
    printf("bytecode : %llu byte(s)\n", (unsigned long long)size);
    printf("versions : %u / %u  (%s)\n", v, tv,
           cc_bytecode_acceptable(v, tv) ? "inside the loader's accepted window"
                                        : "OUTSIDE the loader's accepted window");
    printf("header   :");
    for (size_t i = 0; i < 12 && i < size; ++i) printf(" %02x", ((unsigned char*)data)[i]);
    printf("\n");
    cc_compile_free(data);
    return 0;
}

extern "C" int ccui_selftest(void)
{
    size_t blob_size = 0;
    uint8_t* blob = find_section(".cpl", &blob_size);
    if (!blob || !blob_size) return 1;
    return selftest(blob, blob_size) == 0 ? 0 : 2;
}

extern "C" unsigned long ccui_find_roblox(void) { return (unsigned long)find_pid(TARGET_EXE); }

/* 0 = the running client is the build every offset here is locked to, 1 = it is not, 2 = unknown.
   A version mismatch is not a warning we can shrug at: the RVAs point into a different program. */
extern "C" int ccui_version_ok(unsigned long pid)
{
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!proc) return 2;
    wchar_t path[MAX_PATH * 2]{};
    DWORD n = (DWORD)(sizeof(path) / sizeof(path[0]));
    int rc = 2;
    if (QueryFullProcessImageNameW(proc, 0, path, &n)) rc = wcsstr(path, L"version-cec3ad5889b447cf") ? 0 : 1;
    CloseHandle(proc);
    return rc;
}

/* The UI's Attach. `use_redirect` is the delivery choice the picker in gui.cpp maps to: 0 = APC
   only, 1 = steal a thread's RIP. The UI used to hard-code 0, which made its one button unable to
   reach the delivery that actually dispatches on this client (SIGNATURES.md 9.4: 146 APCs across
   all threads over 60 s, zero dispatches). */
extern "C" int ccui_attach(unsigned long pid, int timeout_ms, int watch_ms, int threads,
                           int use_redirect)
{
    return inject((DWORD)pid, timeout_ms, watch_ms, threads, use_redirect != 0);
}

/* The UI's Execute. It is the CLI's --exec, not a second implementation: same compile, same gate,
   same placement, same delivery. `mode` 1 loads the chunk, 2 loads and resumes it. */
extern "C" int ccui_exec(unsigned long pid, const char* source, int mode, int* exec_status_out)
{
    if (exec_status_out) *exec_status_out = -1;
    return inject((DWORD)pid, 6000, 0, 12, true, source, mode);
}

/* ------------------------------------------------------------------ main -------------- */

int main(int argc, char** argv)
{
    bool do_inject = false, do_audit = false, do_ui = false, do_hijack = false;
    const char* exec_source = nullptr;
    int exec_mode = 2;
    DWORD pid = 0;
    int timeout_ms = 5000, watch_ms = 0, max_threads = 12;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--ui"))          do_ui = true;
        else if (!strcmp(argv[i], "--compile") && i + 1 < argc) return run_compile(argv[++i]);
        else if (!strcmp(argv[i], "--exec") && i + 1 < argc) { exec_source = argv[++i]; do_inject = true; }
        else if (!strcmp(argv[i], "--load-only")) exec_mode = 1;
        else if (!strcmp(argv[i], "--dry-exec")) exec_mode = 3;
        else if (!strcmp(argv[i], "--inject"))      do_inject = true;
        else if (!strcmp(argv[i], "--audit"))  do_audit = true;
        else if (!strcmp(argv[i], "--hijack")) do_hijack = true;
        else if (!strcmp(argv[i], "--stand-in")) g_stand_in = true;   /* delivery test, any process */
        else if (!strcmp(argv[i], "--pid") && i + 1 < argc) pid = (DWORD)strtoul(argv[++i], nullptr, 0);
        else if (!strcmp(argv[i], "--timeout") && i + 1 < argc) timeout_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--watch") && i + 1 < argc) watch_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--threads") && i + 1 < argc) max_threads = atoi(argv[++i]);
        else { printf("usage: injector [--ui] [--inject] [--hijack] [--audit] [--compile \"<luau source>\"]\n"
                      "                 [--exec \"<luau source>\" [--load-only | --dry-exec]] [--pid N]\n"
                      "                 [--timeout ms] [--watch ms] [--threads N] [--stand-in]\n"
                      "  --stand-in with --hijack: aim the same redirect at any process (not the\n"
                      "             client) to test the suspend/stub/NtContinue restore on its own.\n"
                      "  --exec     compile here, place the payload, load the chunk in the client,\n"
                      "             then resume it (--load-only stops after the load; --dry-exec\n"
                      "             builds the loader's arguments and calls nothing).\n");
               return 1; }
    }

    /* No arguments at all means this exe was double-clicked, and the only thing a click can
       sensibly mean is "open the UI". Every CLI mode still requires its explicit flag, so a
       script's arguments keep their exact meaning, and an argument we do not recognise still gets
       the usage text instead of a window. */
    if (argc == 1) do_ui = true;

    /* unbuffered: if the payload ever faults the process dies instantly, and buffered output
       would take the evidence with it */
    setvbuf(stdout, nullptr, _IONBF, 0);

    /* next to the exe, not in whatever directory we inherited: a log nobody can find is not a log.
       Opened BEFORE the UI branch on purpose: a --ui run used to leave no file at all, so the one
       run that kills a client - the kind this project most needs to read afterwards - was the one
       with no record outside a console tab that nobody can reopen later. */
    char logpath[MAX_PATH]{};
    GetModuleFileNameA(nullptr, logpath, MAX_PATH);
    char* dot = strrchr(logpath, '.');
    if (dot) *dot = 0;
    strncat_s(logpath, "_log.txt", _TRUNCATE);
    fopen_s(&g_log, logpath, "w");

    if (do_ui) {
        /* The window IS the interface in this mode. A console-subsystem exe started by a click
           always gets a console window, so it is hidden and released rather than left sitting
           behind the UI; every line that would have gone to stdout is already in the log file
           opened above (and, once the window exists, in its console tab). */
        if (HWND con = GetConsoleWindow()) ShowWindow(con, SW_HIDE);
        FreeConsole();
        return cc_ui_run();
    }

    printf("Carbon injector - in-process read-only probe\n");
    if (g_log) printf("log: %s\n", logpath);

    size_t blob_size = 0;
    uint8_t* blob = find_section(".cpl", &blob_size);
    if (!blob) { printf("FAIL: no .cpl section in this binary - the payload was not compiled in\n"); return 1; }
    printf("payload section .cpl: %llu bytes\n", (unsigned long long)blob_size);

    int candidates = 0;
    audit_blob(blob, blob_size, &candidates);
    printf("audit: %d E8/E9 byte(s) whose rel32 leaves the section (heuristic only: those\n"
           "       bytes also occur inside operands). Precise check: python tools/audit_blob.py\n",
           candidates);

    if (selftest(blob, blob_size) != 0) return 2;
    if (do_audit && !do_inject) return 0;

    if (!do_inject) {
        printf("\nnothing else was done (pass --inject to place the payload in the client, or --ui for\n"
               "the menu interface).\n"
               "safety: --inject only ever queues an APC, never writes Roblox memory, and frees\n"
               "        everything it allocated as soon as the payload reports back.\n");
        return 0;
    }

    if (exec_source) {
        /* Say it before doing it. Measured on this build: delivery is the weak link, not the
           payload - a redirect that lands in a kernel transition makes the client die LATE, after
           the run that armed it has already reported. The operator of this tool is the one taking
           that risk, so the tool states it instead of implying safety. */
        printf("\nWARNING: --exec calls into the running client (bytecode loader%s). Delivery here is a\n"
               "         thread redirect, and a redirect that is swallowed can kill the client AFTER\n"
               "         this run ends. Save your work in the client first.\n",
               exec_mode >= 2 ? " + resume" : exec_mode == 1 ? " only" : " dry run - nothing is called");
    }

    if (!pid) {
        pid = find_pid(TARGET_EXE);
        if (!pid) { printf("FAIL: %ls is not running\n", TARGET_EXE); return 4; }
    }
    int rc = inject(pid, timeout_ms, watch_ms, max_threads, do_hijack, exec_source, exec_mode);
    if (g_log) fclose(g_log);
    return rc;
}
