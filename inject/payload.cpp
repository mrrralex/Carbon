// Carbon — the payload that runs INSIDE Roblox (v1: strictly read-only).
//
// Design rules, all of them load-bearing:
//   1. It lives alone in its own section (".cpl") and is copied into the target verbatim, so it
//      must not reference anything outside itself: no CRT, no imports, no globals, no strings,
//      no tables. Everything it needs arrives through cc_ctx.
//   2. It dereferences nothing before the target's own VirtualQuery says the page is committed,
//      readable and big enough for the whole access. Pointers that fail are counted, not
//      followed - one bad read inside Roblox is a dead client.
//   3. It only READS target memory and only WRITES its own cc_ctx block (which the injector
//      allocated). Nothing is written into Roblox, no function is called in the process, no
//      thread state is touched. That is what makes this safe to run on a live client.
//   4. It is idempotent: if two APCs dispatch, the second sees done == CC_DONE and returns.
//
// v3 adds an EXEC path, and it makes a different promise on purpose. The audit still only reads;
// but when the caller asks for execution, the payload calls the client's own bytecode loader and
// then the client's own resume entry, with a chunk the caller compiled. That is a write into the
// VM and it is the point of the exercise - so the two paths are separated by exec_mode, stated in
// the report, and never mixed: exec_mode == 0 runs exactly the bytes that were audited before.
#include "payload.h"

#pragma code_seg(".cpl")
#pragma optimize("", off)
#pragma runtime_checks("", off)

#define CC_NOCRT __declspec(noinline) static

CC_NOCRT uint64_t cc_copy(void* dst, const void* src, uint64_t n)
{
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    for (uint64_t i = 0; i < n; ++i) d[i] = s[i];
    return n;
}

CC_NOCRT void cc_zero(void* dst, uint64_t n)
{
    unsigned char* d = (unsigned char*)dst;
    for (uint64_t i = 0; i < n; ++i) d[i] = 0;
}

#define CC_OFFSETOF(type, field) \
    ((uint64_t)((const unsigned char*)&((const type*)0x1000)->field - (const unsigned char*)0x1000))

/* Committed + readable + the whole range inside the queried region. */
CC_NOCRT int cc_readable(cc_ctx* ctx, uint64_t addr, uint64_t n)
{
    if (!addr || !ctx->vq) return 0;
    cc_mbi mbi{};
    cc_vq_fn vq = (cc_vq_fn)ctx->vq;
    if (!vq((const void*)addr, &mbi, (uint64_t)sizeof(mbi))) return 0;
    if (mbi.State != 0x1000u) return 0;                 /* MEM_COMMIT */
    const uint32_t p = mbi.Protect;
    if (p == 0 || (p & (0x01u | 0x100u)) != 0) return 0; /* PAGE_NOACCESS | PAGE_GUARD */
    if (addr + n > mbi.BaseAddress + mbi.RegionSize) return 0;
    return 1;
}

CC_NOCRT int cc_read(cc_ctx* ctx, uint64_t addr, void* out, uint64_t n)
{
    if (!cc_readable(ctx, addr, n)) { ctx->reads_gated++; return 0; }
    cc_copy(out, (const void*)addr, n);
    return 1;
}

CC_NOCRT uint64_t cc_q(cc_ctx* ctx, uint64_t addr, int* ok)
{
    uint64_t v = 0;
    int r = cc_read(ctx, addr, &v, 8);
    if (ok) *ok = r;
    return r ? v : 0;
}

CC_NOCRT int cc_looks(uint64_t p)
{
    return p && (p & 7) == 0 && p > 0x10000 && p < 0x00007FFFFFFFFFFFULL;
}

CC_NOCRT void cc_finish(cc_ctx* ctx, uint32_t status)
{
    /* Disarm the recorder FIRST, on every exit path, before the injector can see done. The recorder
       is a vectored handler in the client whose code chain is trampoline -> this blob; the injector
       frees this blob as soon as it sees done. A registration left behind therefore converts the
       client's next HANDLED exception into a fatal one, which is exactly what "the payload reported
       OK and the client died a second later" was. Not a small leak: a time bomb. */
    if (ctx->veh_installed && ctx->veh_handle && ctx->remove_veh) {
        cc_removeveh_fn rm = (cc_removeveh_fn)ctx->remove_veh;
        if (rm((void*)ctx->veh_handle)) ctx->veh_removed = 1;
        ctx->veh_installed = 0;
    }
    ctx->status = status;
    ctx->done = CC_DONE;     /* written last: everything above is visible before the injector sees it */
}

CC_NOCRT int cc_validate_lua_state(cc_ctx* ctx, uint64_t L)
{
    if (!cc_looks(L)) return 0;
    uint8_t hdr[4];
    if (!cc_read(ctx, L + CC_OFF_L_TT, hdr, 4)) return 0;
    /* Luau CommonHeader: +8 lu_byte tt (8 = LUA_TTHREAD), +9 marked, +10 status */
    if (hdr[0] != 8) return 0;
    if (hdr[1] >= 0x80) return 0;
    uint64_t gs = 0;
    if (!cc_read(ctx, L + CC_OFF_L_GLOBAL_STATE, &gs, 8)) return 0;
    if (!cc_looks(gs)) return 0;
    return 1;
}

/* ---------------------------------------------------------------- exec (v3) ----------------
   Two calls, both into the client's own code, in this order:

     0x25ffdd0  the bytecode loader. Reads the struct built below and pushes the main closure onto
                the state's stack. Verified argument contract (tools/pin_exec.py): +0x30 name,
                +0x38 data, +0x40 size, +0x48 mode, +0x4c its own result dword, +0x18 address-only.
                It reports success as rax == 0 AND args.result == 0.

     0x418fef0  the resume wrapper - the client's own "resume this ScriptContext" helper, one call
                above ScriptContextResume (0x423c6f0). Calling the WRAPPER is deliberate: it adds
                the +0x8f0 adjustment (0x418ff05) and applies the depth guard (0x418ff00) itself,
                so two constants and one guard stop being our business. r8 is forwarded into the
                callee and [0x423c771] loads [r8] with an explicit zero branch, so we pass the
                address of a zeroed slot rather than NULL - the same shape the client's own call
                site at 0x3f966a4 uses (there: lea r8,[rsp+0xb0], r9d=1).

   Stated rather than hidden: the resume runs on whatever thread delivered the payload, and the
   client's scheduler may be running a script job on another thread at the same moment. The depth
   counter we read was 1, under the guard's limit of 3, so the guard is not what stops this. */

CC_NOCRT int cc_addr_in_image(cc_ctx* ctx, uint64_t addr, uint64_t need)
{
    if (!ctx->roblox_base || !ctx->image_size) return 0;
    if (addr < ctx->roblox_base) return 0;
    if (addr + need < addr) return 0;                       /* overflow */
    return addr + need <= ctx->roblox_base + ctx->image_size;
}

/* The loader's own acceptance rule, applied HERE first: version byte 3..14 or 100, and for
   version >= 4 a type version byte 1..3 (SIGNATURES.md 8.2 read out of the loader). Rejecting
   here means the loader's version-mismatch path - which formats a message and calls into an error
   routine on OUR thread - is unreachable through this code. */
CC_NOCRT int cc_bytecode_gate(cc_ctx* ctx, uint64_t data, uint64_t size)
{
    if (size < 2) return 0;
    uint8_t hdr[2];
    if (!cc_read(ctx, data, hdr, 2)) return 0;
    unsigned v = hdr[0], tv = hdr[1];
    if (!((v >= 3 && v <= 14) || v == 100)) return 0;
    if (v >= 4 && !(tv >= 1 && tv <= 3)) return 0;
    return 1;
}

/* ---------------------------------------------------------------- ARG1, preflighted --------
   Why this exists, with the measurement it came from (SIGNATURES.md 9.9/9.10). Execute pressed the
   loader directly and the client faulted at loader+0x350:

       0x260010b  mov r14, [r15 + 0x18]      ; r15 = ARG1 for the whole body (written once, at entry)
       0x260010f  movsxd rcx, [r14 + 0x18]   ; a SIZE, used as a mask
       0x2600113  dec rcx
       0x2600119  and rcx, rax               ; rax = a hash computed by the byte loop above
       0x260011c  mov rax, [r14 + 0x20]      ; the bucket array
       0x2600120  mov rcx, [rax + rcx*8]     ; FAULT: read from 0x9c085930

The arithmetic is exact: `0x13810b26 * 8 = 0x9c085930`, the address the recorder reported, and that
index is the hash itself - which only happens when `[r14+0x18]` is 0, so the mask became -1, and
`[r14+0x20]` was null. An empty container, reached from `[ARG1+0x18]`.

So ARG1 is what failed, not the argument struct: the four fields the loader reads out of the struct
(mode +0x48, size +0x40, data +0x38, name +0x30) are built exactly as the client builds them. What
was never checked is the object the loader indexes FIRST, and a tag byte cannot see it. This function
applies the loader's own test before the call, and reports what it found either way, so a refusal
says `[L+0x18] -> size 334175024` instead of costing a client.

MEASURED LIVE, READ-ONLY (tools/state_probe.py, 2026-10-10): the accepted state on a live client
(SC+0xf78, tag 8) has `[L+0x18] = 0x2991806aef0` whose `+0x18` is 334175024 - not a size - so this
gate refuses it. That is the honest result and it is the point: the previous code called anyway. */
CC_NOCRT int cc_arg1_preflight(cc_ctx* ctx, uint64_t L)
{
    ctx->arg1_ok = 0;
    uint64_t field = 0;
    /* +0x18 is not a guess: the loader loads exactly this, and so does LuaVM_Load itself
       (`mov rcx, [rbx+0x18]` at 0x4188bf0). */
    if (!cc_read(ctx, L + 0x18, &field, 8)) return 0;
    ctx->arg1_field = field;
    if (!cc_looks(field)) return 0;
    /* int32 at +0x18, used as `capacity - 1` and ANDed with a 32-bit hash: a plausible size is
       required, and 0 is exactly the value that turned the mask into -1 in the fault above. */
    int32_t size32 = 0;
    if (!cc_read(ctx, field + 0x18, &size32, 4)) return 0;
    if (size32 < 1 || size32 > (1 << 20)) return 0;
    ctx->arg1_size = (uint64_t)(uint32_t)size32;
    uint64_t buckets = 0;
    if (!cc_read(ctx, field + 0x20, &buckets, 8)) return 0;
    ctx->arg1_buckets = buckets;
    if (!cc_looks(buckets) || !cc_readable(ctx, buckets, 8)) return 0;
    ctx->arg1_ok = 1;
    return 1;
}

CC_NOCRT void cc_exec(cc_ctx* ctx)
{
    int container = ctx->exec_mode >= 4;
    if (!ctx->exec_mode) { ctx->exec_status = CC_EXEC_OFF; return; }
    if (!ctx->exec_scratch || !ctx->chunkname || !ctx->sc_from_job) {
        ctx->exec_status = CC_EXEC_BAD_ARGS; return;
    }
    /* Mode 4/5 call the container; everything else calls the loader and needs the bytecode. */
    if (container) {
        if (!ctx->container_va || !ctx->container_payload || !ctx->container_size) {
            ctx->exec_status = CC_EXEC_BAD_ARGS; return;
        }
        if (!cc_addr_in_image(ctx, ctx->container_va, 0x20)) {
            ctx->exec_status = CC_EXEC_BAD_ARGS; return;
        }
        if (!cc_readable(ctx, ctx->container_payload, ctx->container_size)) {
            ctx->exec_status = CC_EXEC_BAD_ARGS; return;
        }
    } else {
        if (!ctx->bytecode || !ctx->bytecode_size || !ctx->loader_va || !ctx->resume_va) {
            ctx->exec_status = CC_EXEC_BAD_ARGS; return;
        }
        if (!cc_addr_in_image(ctx, ctx->loader_va, 0x20) || !cc_addr_in_image(ctx, ctx->resume_va, 0x20)) {
            ctx->exec_status = CC_EXEC_BAD_ARGS; return;   /* a wrong address here is a dead client */
        }
        if (!cc_readable(ctx, ctx->bytecode, ctx->bytecode_size)) {
            ctx->exec_status = CC_EXEC_BAD_ARGS; return;
        }
    }
    if (!cc_readable(ctx, ctx->exec_scratch, (uint64_t)sizeof(cc_exec_scratch)) ||
        !cc_readable(ctx, ctx->chunkname, 2)) {
        ctx->exec_status = CC_EXEC_BAD_ARGS; return;
    }
    if (!ctx->lua_state || !cc_validate_lua_state(ctx, ctx->lua_state)) {
        ctx->exec_status = CC_EXEC_NO_STATE; return;
    }
    cc_arg1_preflight(ctx, ctx->lua_state);

    if (!container && !cc_bytecode_gate(ctx, ctx->bytecode, ctx->bytecode_size)) {
        ctx->exec_status = CC_EXEC_BAD_ARGS; return;
    }

    cc_exec_scratch* s = (cc_exec_scratch*)ctx->exec_scratch;
    cc_zero(s, (uint64_t)sizeof(*s));
    s->args.name = ctx->chunkname;
    s->args.data = ctx->bytecode;
    s->args.size = ctx->bytecode_size;
    s->args.mode = 0;                 /* 0 at every call site we read */
    s->args.result = 1;               /* pessimistic: the loader has to clear it */
    s->thread_ref = 0;                /* the resume reads [r8]; 0 is the branch it handles */
    (void)CC_OFFSETOF(cc_load_args, addr_self);   /* +0x18 is address-only; nothing to fill in */

    /* mode 3 stops HERE: every guard above ran, the argument struct is built and readable, and
       nothing was called. That separates "our exec scaffolding is wrong" from "the loader call is
       wrong" in one run instead of after a crash with no witness. */
    if (ctx->exec_mode == 3) { ctx->exec_status = CC_EXEC_DRY; return; }

    if (container) {
        /* The client's own entry, with the client's own convention (see CC_RVA_CONTAINER). ARG2 is
           the std::string the injector pointed at; the entry tests its size at +0x10 and then
           parses it. NOTE, stated rather than hidden: that parse (0x4188770) is the payload parser,
           so what it accepts is a property of the payload - which is why the injector can send the
           SOURCE (mode 4's default) or raw bytecode (mode 5) and why the fault recovery below
           matters for both. */
        s->str_data = ctx->container_payload;
        s->str_size = ctx->container_size;
        /* MSVC's std::string stores the characters INLINE in the 16-byte union when the capacity is
           below 16, and behind the pointer at +0x00 only when it is 16 or more. This entry does the
           SSO test the other way round (`cmp [rsp+0x120], 0x10; cmovae r15, [rsp+0x108]`), so a
           capacity under 16 makes it read the POINTER'S BYTES as the script text - garbage in, and
           on 2026-10-10 a fault out: `execute at 0x0`. Setting the capacity to the size of the
           payload picks inline for a short string, which is the wrong branch for a payload that
           lives elsewhere; forcing 16 or more picks the pointer form that matches where our bytes
           actually are. */
        s->str_cap  = ctx->container_size < 16 ? 16 : ctx->container_size;
        if (ctx->exec_mode == 6) { ctx->exec_status = CC_EXEC_DRY; return; }   /* the string, un-called */
        ctx->exec_stage = CC_STAGE_BEFORE_CONTAINER;
        cc_container_fn run = (cc_container_fn)ctx->container_va;
        uint64_t crc = run((void*)ctx->lua_state, &s->str_data, (void*)ctx->chunkname, 0);
        ctx->exec_stage = CC_STAGE_AFTER_CONTAINER;
        ctx->container_rc = (uint32_t)crc;
        ctx->loader_rc = (uint32_t)crc;      /* "what the entry returned", same field */
        /* A recovered fault resumes HERE, with rax set to 1 by the handler. Reporting it as
           LOAD_FAILED would hide the difference between "the entry said no" and "the entry
           faulted and we got control back", which is the whole point of the recovery. */
        if (ctx->fault_recovered) { ctx->exec_status = CC_EXEC_FAULTED; return; }
        if (crc != 0) { ctx->exec_status = CC_EXEC_LOAD_FAILED; return; }
        ctx->exec_status = CC_EXEC_LOADED;
        if (ctx->exec_mode == 5) return;
    } else {
        /* The loader's first dereference of ARG1, applied here rather than discovered by the
           client's crash handler. Refusing is the whole point: on 2026-10-10 this exact call cost
           a client, and the recorder named the instruction that did it. */
        if (!ctx->arg1_ok) { ctx->exec_status = CC_EXEC_NO_ARG1; return; }
        ctx->exec_stage = CC_STAGE_BEFORE_LOAD;
        cc_load_fn load = (cc_load_fn)ctx->loader_va;
        uint64_t rc = load((void*)ctx->lua_state, s);
        ctx->exec_stage = CC_STAGE_AFTER_LOAD;
        ctx->loader_rc = (uint32_t)rc;
        ctx->loader_result = s->args.result;
        if (ctx->fault_recovered) { ctx->exec_status = CC_EXEC_FAULTED; return; }
        if (rc != 0 || s->args.result != 0) { ctx->exec_status = CC_EXEC_LOAD_FAILED; return; }
        ctx->exec_status = CC_EXEC_LOADED;
        if (ctx->exec_mode < 2) return;   /* "load only" stops here, on purpose */
    }

    /* Both paths resume through the client's own wrapper, so the address is checked once, here,
       rather than only on the loader path where it used to be. */
    if (!ctx->resume_va || !cc_addr_in_image(ctx, ctx->resume_va, 0x20)) {
        ctx->exec_status = CC_EXEC_LOADED;   /* loaded, but there is nowhere safe to resume */
        return;
    }
    ctx->exec_stage = CC_STAGE_BEFORE_RESUME;
    cc_resume_fn resume = (cc_resume_fn)ctx->resume_va;
    uint64_t r = resume((void*)ctx->sc_from_job, s->result20, &s->thread_ref, 1, 0, 0);
    ctx->exec_stage = CC_STAGE_AFTER_RESUME;
    ctx->resume_rc = (uint32_t)r;
    uint32_t res0 = 0;
    cc_copy(&res0, s->result20, 4);
    ctx->resume_result = res0;
    ctx->exec_status = CC_EXEC_RESUMED;
}

/* ---------------------------------------------------------------- black box (v4/v6) ------
   Reached through the injector's trampoline with (EXCEPTION_POINTERS*, cc_ctx*). Two jobs now, and
   the distinction between them is the whole reason this function was rewritten:

     * a fault that came out of a call WE made (exec_stage says we are inside one of the calls, and
       the faulting rip is inside the client image) is RECOVERED: the innermost return address
       belonging to this payload is looked up on the faulting stack, the context is pointed at it,
       rax is set to a failure code, and the payload carries on exactly as if that call had
       returned an error. The client never sees the exception, and Execute reports a failure.

     * anything else - the client's own guard-page probes, C++ throws, a fault on another thread -
       is recorded and passed on with EXCEPTION_CONTINUE_SEARCH (0).

   Until v6 this returned -1 and called it "EXCEPTION_CONTINUE_SEARCH". -1 is
   EXCEPTION_CONTINUE_EXECUTION, so every fault this handler could not fix was retried at the same
   instruction, forever: that is the client appearing to hang ("not responding") instead of
   crashing, and it is the symptom Execute produced. There is no correct -1 without fixing the
   context first, which is exactly what the recovery path below does. */
extern "C" int cc_veh(cc_exc_ptrs* p, cc_ctx* ctx)
{
    int rc = 0;                     /* EXCEPTION_CONTINUE_SEARCH: observe, do not swallow */
    if (ctx && p && p->record) {
        cc_blackbox* bb = (cc_blackbox*)ctx->blackbox;
        if (bb) {
            cc_zero(bb, (uint64_t)sizeof(*bb));
            bb->code     = p->record->code;
            bb->address  = p->record->address;
            bb->access   = (uint32_t)p->record->info[0];
            bb->fault_va = p->record->info[1];
            bb->stage    = ctx->exec_stage;
            if (ctx->roblox_base && p->record->address >= ctx->roblox_base &&
                p->record->address < ctx->roblox_base + ctx->image_size)
                bb->fault_rva = p->record->address - ctx->roblox_base;
            const uint8_t* c = (const uint8_t*)p->context;
            /* the recovery below REWRITES this context, which is the only write this payload makes
               into a context it did not allocate - hence two views of the same pointer */
            uint8_t* cw = (uint8_t*)p->context;
            if (c) {
                cc_copy(&bb->rsp, c + CC_CTX_RSP, 8);
                cc_copy(&bb->rax, c + CC_CTX_RAX, 8);
                cc_copy(&bb->rcx, c + CC_CTX_RCX, 8);
                cc_copy(&bb->rdx, c + CC_CTX_RDX, 8);
                cc_copy(&bb->r8,  c + CC_CTX_R8,  8);
                cc_copy(&bb->r9,  c + CC_CTX_R9,  8);
            }

            /* ---- recovery, for a fault on OUR thread, inside a call this payload made ----
               Note what is NOT tested: the faulting address. Measured 2026-10-10, the container
               call faulted with `execute at 0x0` - rip 0, outside the image - and a rule keyed on
               "the rip must be inside the image" therefore handed our own fatal fault to the client,
               which died. A call through a null pointer is exactly the kind of fault a wrong
               container/state pair produces, so the identity of the THREAD is the test. */
            const int in_a_call = ctx->exec_stage == CC_STAGE_BEFORE_LOAD ||
                                  ctx->exec_stage == CC_STAGE_BEFORE_RESUME ||
                                  ctx->exec_stage == CC_STAGE_BEFORE_CONTAINER;
            uint32_t my_tid = 0;
            if (ctx->get_tid) my_tid = ((uint32_t(*)(void))ctx->get_tid)();
            const int ours = ctx->get_tid && ctx->hijack_tid && my_tid == ctx->hijack_tid;
            bb->fault_tid = my_tid;
            bb->expected_tid = ctx->hijack_tid;
            bb->ours = ours ? 1u : 0u;
            bb->recover_why = CC_REC_NOT_OUR_FAULT;
            if (!in_a_call || !ours) {
                /* the client's own fault, or a fault on another of its threads: not ours to fix */
                bb->recover_why = CC_REC_NOT_OUR_FAULT;
            } else if (!ctx->payload_lo || ctx->payload_hi <= ctx->payload_lo) {
                bb->recover_why = CC_REC_NO_PAYLOAD;
            } else if (c) {
                uint64_t rsp = 0;
                cc_copy(&rsp, c + CC_CTX_RSP, 8);
                bb->fault_rsp = rsp;
                /* Walk UP the faulting stack for the first slot that holds an address inside this
                   payload. That value is the return address of the call that faulted (nothing else
                   on the stack points into a small private mapping), so pointing rip at it and rsp
                   just above it returns the thread straight to the instruction AFTER that call -
                   the frame is abandoned exactly as an exception unwind would abandon it. Reading
                   is gated per slot: a fault inside the handler would be fatal. */
                uint64_t slot = 0, ret = 0;
                bb->recover_why = CC_REC_NOT_FOUND;
                for (uint64_t k = 0; k < 0x400; k += 8) {
                    uint64_t a = rsp + k;
                    if (!cc_readable(ctx, a, 8)) {           /* left the committed stack */
                        bb->recover_why = CC_REC_STACK_ENDED;
                        break;
                    }
                    bb->walked = k + 8;
                    uint64_t v = 0;
                    cc_copy(&v, (const void*)a, 8);
                    if (v >= ctx->payload_lo && v < ctx->payload_hi) {
                        slot = a; ret = v; bb->recover_why = CC_REC_DONE; break;
                    }
                }
                if (slot) {
                    uint64_t nrsp = slot + 8;
                    uint64_t failed = 1;                  /* rax out of the recovered call */
                    cc_copy(cw + CC_CTX_RSP, &nrsp, 8);
                    cc_copy(cw + CC_CTX_RIP, &ret, 8);
                    cc_copy(cw + CC_CTX_RAX, &failed, 8);
                    rc = -1;                              /* EXCEPTION_CONTINUE_EXECUTION, context now fixed */
                    ctx->fault_recovered = 1;
                    ctx->fault_rva = bb->fault_rva;
                    bb->recovered = 1;
                    bb->resume_rip = ret;
                    bb->recover_why = CC_REC_DONE;
                }
            }
            bb->handler_rc = (uint32_t)(int32_t)rc;
            bb->magic = CC_BB_MAGIC;      /* last: the injector's reader keys on this */
        }
    }
    /* Hold this thread. A fatal fault otherwise ends the process microseconds after the write, and
       the injector polls every 20 ms - the record would be written and never read. A counted spin,
       not a sleep: the payload has no imports and no CRT. */
    if (ctx && ctx->bb_hold_loops) {
        volatile uint64_t acc = 0;
        for (uint32_t i = 0; i < ctx->bb_hold_loops; ++i) acc += i;
        (void)acc;
    }
    return rc;
}

extern "C" void cc_payload(cc_ctx* ctx)
{
    if (!ctx) return;
    /* refuse to run against a context that is not ours */
    if (ctx->marker != CC_MARK || ctx->self_va != (uint64_t)ctx || (uint32_t)ctx->abi != (uint32_t)sizeof(cc_ctx)) {
        if (ctx->marker == CC_MARK) { ctx->status = CC_BAD_CTX; ctx->done = CC_DONE; }
        return;
    }
    if (ctx->done == CC_DONE) return;      /* second dispatch of the same APC */

    /* ---- 0. the recorder, before anything below can fault -------------------------
       Installed first on purpose: the stages that matter are the calls, and a recorder armed after
       the call of interest is a recorder that can miss it. */
    if (ctx->add_veh && ctx->veh_handler) {
        cc_addveh_fn add = (cc_addveh_fn)ctx->add_veh;
        ctx->veh_handle = add(1, (void*)ctx->veh_handler);
        ctx->veh_installed = ctx->veh_handle ? 1u : 0u;
    }

    /* ---- 1. the image ------------------------------------------------------------ */
    uint64_t base = ctx->roblox_base;
    uint16_t mz = 0;
    if (!cc_read(ctx, base, &mz, 2) || mz != 0x5A4D) { cc_finish(ctx, CC_BAD_IMAGE); return; }

    /* ---- 2. TaskScheduler (independent sanity gates, same as probe.exe) ---------- */
    int ok = 0;
    uint64_t slot = base + CC_RVA_P_TASKSCHEDULER;
    uint64_t sched = cc_q(ctx, slot, &ok);
    if (!ok || !cc_looks(sched)) { cc_finish(ctx, CC_BAD_SCHEDULER); return; }
    ctx->sched = sched;

    uint64_t begin = cc_q(ctx, sched + CC_OFF_JOBS_BEGIN, &ok);
    if (!ok) { cc_finish(ctx, CC_BAD_JOB_VECTOR); return; }
    uint64_t end = cc_q(ctx, sched + CC_OFF_JOBS_END, &ok);
    if (!ok || !cc_looks(begin) || !cc_looks(end) || end <= begin || ((end - begin) % 8) != 0) {
        cc_finish(ctx, CC_BAD_JOB_VECTOR); return;
    }
    uint64_t count = (end - begin) / 8;
    if (count == 0 || count > 4096) { cc_finish(ctx, CC_BAD_JOB_VECTOR); return; }
    ctx->job_begin = begin;
    ctx->job_count = count;

    /* ---- 3. jobs -> ScriptContext -> lua_State ---------------------------------- */
    const uint64_t tries[3] = { CC_OFF_SC_LUASTATE_A, CC_OFF_SC_LUASTATE_B, CC_OFF_SC_LUASTATE_ACH };

    for (uint64_t i = 0; i < count; ++i) {
        uint64_t job = cc_q(ctx, begin + i * 8, &ok);
        if (!ok || !cc_looks(job)) continue;
        ctx->jobs_seen++;
        if (!ctx->job_first) ctx->job_first = job;

        uint64_t sc = cc_q(ctx, job + CC_OFF_JOB_SCRIPTCTX, &ok);
        if (!ok || !cc_looks(sc)) continue;
        if (!ctx->sc_from_job) ctx->sc_from_job = sc;

        for (int t = 0; t < 3; ++t) {
            ctx->lua_state_offsets_tried++;
            uint64_t L = cc_q(ctx, sc + tries[t], &ok);
            if (!ok || !cc_looks(L)) continue;
            if (ctx->tt_count < 8) {
                const uint8_t* raw = (const uint8_t*)&L;   /* keep the raw address in the trace */
                (void)raw;
                ctx->tt_seen[ctx->tt_count++] = L;
            }
            if (!cc_validate_lua_state(ctx, L)) continue;
            /* stability: the slot must still hold the same pointer a moment later */
            uint64_t again = cc_q(ctx, sc + tries[t], &ok);
            if (!ok || again != L) continue;

            if (!ctx->lua_state) {
                ctx->lua_state = L;
                ctx->lua_state_off = (uint32_t)tries[t];
            }
            ctx->jobs_with_state++;
            if (!ctx->resume_depth) {
                uint32_t d = 0;
                if (cc_read(ctx, sc + CC_OFF_SC_RESUME_DEPTH, &d, 4)) ctx->resume_depth = d;
            }
            break;   /* one state per job is enough */
        }
    }

    /* ---- 4. cross-check: FakeDataModel -> RealDataModel -> +0x440 --------------- */
    uint64_t fake = cc_q(ctx, base + CC_RVA_FAKE_DATAMODEL, &ok);
    if (ok && cc_looks(fake)) {
        uint64_t real = cc_q(ctx, fake + CC_OFF_REAL_DATAMODEL, &ok);
        if (ok && cc_looks(real)) {
            ctx->datamodel = real;
            uint64_t sc2 = cc_q(ctx, real + CC_OFF_DATAMODEL_SC, &ok);
            if (ok && cc_looks(sc2)) {
                ctx->sc_from_dm = sc2;
                if (ctx->sc_from_job && sc2 == ctx->sc_from_job) ctx->sc_routes_agree = 1;
            }
        }
    }

    /* ---- 5. the three flags, read-only (their values are unknown to us so far) --- */
    const uint64_t flag_rvas[3] = { CC_RVA_ENABLE_LOAD_MODULE, CC_RVA_GATE_A, CC_RVA_GATE_B };
    for (int f = 0; f < 3; ++f) {
        uint8_t b = 0;
        if (cc_read(ctx, base + flag_rvas[f], &b, 1)) ctx->flags[f] = b;
    }

    /* ---- 6. exec, if the caller asked for it (v3, container mode v6) -------------- */
    cc_exec(ctx);

    if (!ctx->sched)          cc_finish(ctx, CC_BAD_SCHEDULER);
    else if (!ctx->lua_state) cc_finish(ctx, CC_NO_LUA_STATE);
    else                      cc_finish(ctx, CC_OK);
}

#pragma optimize("", on)
#pragma code_seg()
