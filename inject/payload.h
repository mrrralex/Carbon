// Carbon — in-process probe payload: shared contract between payload.cpp (runs inside the
// target) and injector.cpp (places it there).
//
// Rules for this header:
//   * dependency-free. The payload half is compiled with no CRT and no imports, and is copied
//     verbatim out of its own section, so anything it referenced outside itself would be a call
//     into a foreign address. Plain integers and arrays only.
//   * raw RVAs, not prebased addresses. src/offsets.h pre-adds *this* process's module base
//     (REBASE_RBX) because it is written for an in-process DLL; a payload that is copied into
//     another process must never inherit that. Every number below is the value from the Achilles
//     dump (SIGNATURES.md) with the rebase removed.
#pragma once
#include <cstdint>

#define CC_MARK   0x314B5243u   /* 'CRK1' */
#define CC_DONE   0x454E4F44u   /* 'DONE' */

enum cc_status : uint32_t {
    CC_OK              = 0,
    CC_BAD_CTX         = 1,   /* marker/self address mismatch - refuse to run */
    CC_BAD_IMAGE       = 2,   /* target base not readable or not an MZ */
    CC_BAD_SCHEDULER   = 3,
    CC_BAD_JOB_VECTOR  = 4,
    CC_NO_LUA_STATE    = 5,   /* chain resolved, but no candidate state validated */
};

/* How far the exec path got. Reported by the payload, not inferred by the injector: the only
   place that knows whether the loader accepted the chunk is the code that called it. */
enum cc_exec_status : uint32_t {
    CC_EXEC_OFF         = 0,  /* audit only - this run asked for no execution */
    CC_EXEC_LOADED      = 1,  /* the loader returned success; the chunk is on L's stack */
    CC_EXEC_RESUMED     = 2,  /* ... and the resume entry was called */
    CC_EXEC_BAD_ARGS    = 3,  /* exec requested but an address/size from the caller is unusable */
    CC_EXEC_NO_STATE    = 4,  /* no validated lua_State, so there is nothing to load into */
    CC_EXEC_LOAD_FAILED = 5,  /* the loader itself reported failure (see loader_rc/loader_result) */
    CC_EXEC_DRY         = 6,  /* mode 3: every guard ran and the struct was built; nothing called */
    CC_EXEC_NO_ARG1     = 7,  /* ARG1 failed the loader's OWN first dereference - refused, not called */
    CC_EXEC_FAULTED     = 8,  /* a call faulted and the recorder recovered the payload (see fault_rva) */
};

/* The same readings the loader makes of its argument struct, in its own order. Every offset here
   was read out of the loader's code (tools/pin_exec.py), not assumed:

     0x25ffdfb  mov ebx, [rdx+0x48]      <- mode, 32-bit
     0x25ffdfe  mov r14, [rdx+0x40]      <- SIZE (the error path does sub r14d, ecx)
     0x25ffe07  mov rsi, [rdx+0x38]      <- bytecode data, read as [rsi], [rsi+1]
     0x25ffe0f  mov rdi, [rdx+0x30]      <- chunk name, walked byte by byte to its NUL
     0x25ffe13  lea rax, [rdx+0x18]      <- the ADDRESS only; the bytes there are never read
     0x260ae25  mov [r12+0x4c], r13d     <- OUTPUT: 0 on the success exit, 1 on the error exits

   So +0x4c is the loader's own verdict and +0x18 is not an input at all. That is why the struct
   below is written field by field with the pads spelled out: a stray value in a pad is harmless,
   but a value in the wrong named field is not.

   VERIFIED FROM THE CALLER SIDE TOO (2026-10-09). The four LuaVM_Load sites that materialise the
   loader (0x4188c8e, 0x41893ed, 0x4189c36, 0x418a3b6) build this struct at [rsp+0x70] and zero the
   whole +0x10..+0x2f range - `movdqa [rsp+0x70], xmm0` plus `mov qword [rsp+0x80/0x88/0x90/0x98], 0`
   - so +0x10, +0x18, +0x20 and +0x28 are literally zero at every real call, which is exactly how
   this payload builds them. The same stores name the fields from the caller's side as well:
        +0x30 = LuaVM_Load's ARG3, a NUL-terminated chunk name
        +0x38 = the SSO-aware data pointer of ARG2's std::string (cmovae on capacity >= 0x10)
        +0x40 = that string's size, i.e. [ARG2+0x10]
        +0x48 = ARG4, the mode word
   Consequence: the argument struct is NOT why the loader call faults - it matches the client's own
   four call sites field for field and pad for pad. See SIGNATURES.md 9.6 for what the loader call
   does instead. */
typedef struct cc_load_args {
    uint64_t pad00[3];      /* +0x00 .. +0x17                                  */
    uint64_t addr_self;     /* +0x18 : only its address matters (lea rdx+0x18) */
    uint64_t pad20[2];      /* +0x20 .. +0x2f                                  */
    uint64_t name;          /* +0x30 : chunk name, NUL-terminated              */
    uint64_t data;          /* +0x38 : bytecode                                */
    uint64_t size;          /* +0x40 : byte length                             */
    uint32_t mode;          /* +0x48 : 0 at every caller we read               */
    uint32_t result;        /* +0x4c : OUTPUT - 0 means the chunk was loaded    */
} cc_load_args;

/* Everything the exec path needs, in ONE block the injector allocates inside the target. The
   payload fills it; nothing here has to be pre-computed outside, which keeps the contract in
   one place instead of split across two processes. */
typedef struct cc_exec_scratch {
    cc_load_args args;
    uint64_t thread_ref;    /* arg3 of the resume is a POINTER; [0x423c771] loads [r13] and
                               tolerates 0, so a zeroed slot is passed rather than a null */
    uint8_t  result20[24];  /* the 20-byte result struct the resume writes                 */
    uint64_t pad;
    /* v6: the container path's ARG2. LuaVM_Load takes a `const std::string*`, and MSVC's x64
       std::string is { union{char* ptr; char buf[16];} @+0x00; size_t size @+0x10;
       size_t capacity @+0x18 } - the client's own call site at 0x4249f62 reads exactly +0x10 for
       the size (`mov rdi,[rdx+0x10]`) and LuaVM_Load itself tests [+0x10] != 0 at its entry
       (`cmp qword ptr [rdx+0x10], 0`). Payloads over 15 bytes MUST use the pointer form, which is
       what the capacity field selects. */
    uint64_t str_data;      /* +0x00 of the std::string: the payload bytes                   */
    uint64_t str_pad;       /* +0x08                                                         */
    uint64_t str_size;      /* +0x10                                                         */
    uint64_t str_cap;       /* +0x18                                                         */
} cc_exec_scratch;

/* Where the exec path had got to. This exists because a crash inside a call cannot be reported
   afterwards: the process that would have reported it is gone. So the stage is written to the
   caller's own memory BEFORE each call, and the injector watches it while waiting - a live run
   that dies then still says which call it died in, which is the difference between "the loader
   is unsafe" and "we do not know". */
enum cc_exec_stage : uint32_t {
    CC_STAGE_NONE            = 0,
    CC_STAGE_BEFORE_LOAD     = 1,
    CC_STAGE_AFTER_LOAD      = 2,
    CC_STAGE_BEFORE_RESUME   = 3,
    CC_STAGE_AFTER_RESUME    = 4,
    CC_STAGE_BEFORE_CONTAINER = 5,
    CC_STAGE_AFTER_CONTAINER  = 6,
};

/* ARG1 is a lua_State on every reading of it: LuaVM_Load's entry does `mov rbx, rcx` and the four
   call sites pass `rcx = rbx` straight into the loader, so the loader's ARG1 is LuaVM_Load's ARG1 -
   the object LuaVM_Load links into a list at [ARG1+0x18]+0x58 and feeds to the stack check
   0x2587960(L, n) (SIGNATURES.md 6.1). The tag the payload validates is at +8, not +0, because
   Luau's CommonHeader is `GCObject* next; lu_byte tt; lu_byte marked`. */

/* Calls the resume entry as `(sc, out20, *thread_ref, ret, 0, 0)` on the arguments above. */
typedef uint64_t (*cc_resume_fn)(void* sc, void* out20, void* thread_ref,
                                 uint64_t ret, uint64_t zero5, uint64_t zero6);
/* The loader as it is actually called: (lua_State*, cc_load_args*). */
typedef uint64_t (*cc_load_fn)(void* L, void* args);
/* The container as the client itself calls it (two call sites read, both identical in shape). */
typedef uint64_t (*cc_container_fn)(void* L, void* str, void* name, uint64_t mode);

enum cc_off : uint64_t {
    /* globals (data slots in RobloxPlayerBeta.exe) */
    CC_RVA_P_TASKSCHEDULER = 0x8B79128,
    CC_RVA_FAKE_DATAMODEL  = 0x8BCFD50,
    CC_RVA_ENABLE_LOAD_MODULE = 0x869DBC8,   /* u64 flag-table entry */
    CC_RVA_GATE_A          = 0x869E078,      /* "RbsConfigAliasResolution" - LuaVM_Load entry */
    CC_RVA_GATE_B          = 0x869D5B8,      /* "RemoveBytecodeCopyOnLoad" - LuaVM_Load inside */

    /* TaskScheduler / jobs */
    CC_OFF_JOBS_BEGIN      = 0xC8,
    CC_OFF_JOBS_END        = 0xD0,
    CC_OFF_JOB_NAME        = 0x18,           /* MSVC std::string */
    CC_OFF_JOB_SCRIPTCTX   = 0x1C0,          /* field on the job (verified live, ANALYSIS.md 7) */

    /* DataModel route (independent cross-check) */
    CC_OFF_REAL_DATAMODEL  = 0x1F8,
    CC_OFF_DATAMODEL_SC    = 0x440,

    /* ScriptContext -> lua_State candidates */
    CC_OFF_SC_LUASTATE_A   = 0xF78,          /* the live one */
    CC_OFF_SC_LUASTATE_B   = 0xDD0,
    CC_OFF_SC_LUASTATE_ACH = 0x3B8,          /* Achilles header value - known wrong on this build */
    CC_OFF_SC_RESUME_DEPTH = 0x13D8,         /* guard counter ScriptContextResume checks (< 3) */

    /* lua_State (Luau CommonHeader) */
    CC_OFF_L_TT            = 0x8,            /* lu_byte tt; 8 == LUA_TTHREAD */
    CC_OFF_L_MARKED        = 0x9,
    CC_OFF_L_GLOBAL_STATE  = 0x10,

    /* v3 exec - the three functions the exec path calls, and where the guard lives. */
    CC_RVA_LOADER          = 0x25FFDD0,      /* bytecode + arg struct -> closure on L's stack   */

    /* v6 exec - the CONTAINER. `LuaVM_Load` is the entry the client itself uses to load a chunk,
       and its contract is read out of the client's own call sites, not inferred:

           0x4243302  add rdx, 0x18        ; ARG2 = [obj+8]+0x18, an interior std::string*
           0x4243306  xor r9d, r9d         ; ARG4 = mode 0
           0x4243309  mov r8, r15          ; ARG3 = the chunk name
           0x424330c  mov rcx, rsi         ; ARG1 = the lua_State
           0x424330f  call 0x4188af0

       and eight such call sites exist in the image, so this is the calling convention the client
       uses rather than one we guessed. Its entry (live-verified byte for byte against
       probe/bin/Release/dumps/luavm_load_rva4188000.bin and the decrypted image) is
       `push rbx/rsi/rdi/r12/r13/r14/r15; sub rsp,0x140; ... mov r12d,r9d; mov r14,r8; mov rbx,rcx`
       - four arguments, in that order. */
    CC_RVA_CONTAINER       = 0x4188AF0,      /* LuaVM_Load(L, const std::string*, name, mode)   */
    CC_RVA_RESUME_WRAPPER  = 0x418FEF0,      /* (sc, out20, thread_ref, ret, 0, 0) -> resumes  */
    CC_RVA_SCRIPTCTX_RESUME= 0x423C6F0,      /* ... what the wrapper calls; documented, unused */
    CC_RVA_GUARDED_CALL    = 0x259B440,      /* CFG `call [guard]`: forwards (rcx, rdx) and
                                                DISCARDS the result - it is not a try/except,
                                                so the loader is called directly instead        */

    CC_VQ_CHUNK            = 0x1000,         /* region window we insist a pointer sits inside */
};

/* ---- the black box: making a crash say WHERE ------------------------------------------------
   A fault inside a call ends the process before any polling loop can read anything else, and this
   client's crashpad UPLOADS its dump and deletes the local copy (SIGNATURES.md 9.6a: only
   settings.dat is left), so the faulting RIP is unrecoverable afterwards. Three exec runs died at
   `stage 1` without one word about which instruction faulted.

   So the payload registers a vectored exception handler for the thread it runs on and, from inside
   that handler, records the exception into a block the injector allocated - then HOLDS the process
   for a counted spin so the injector's 20 ms poll can read the record before the client's own
   handler runs. `bb_hold_loops` is a caller-provided field so the self-test can set it to 0 and the
   live path can set about a second's worth.

   The handler is reached through a 15-byte trampoline the INJECTOR writes, because the handler
   needs the cc_ctx address and a payload has no globals to stash it in (its data would live in a
   section that is not copied - only `.cpl` is):
        mov rdx, <ctx_va>          ; 2nd argument
        mov rax, <handler_va>
        jmp rax                    ; (EXCEPTION_POINTERS*, cc_ctx*)
   Same calling shape as the real handler, so the trampoline needs no stack frame of its own. */
#define CC_BB_MAGIC 0x42425243u   /* 'CRBB' - written LAST, the reader keys on it */

typedef struct cc_blackbox {
    uint32_t magic;         /* CC_BB_MAGIC once every field below is written         */
    uint32_t code;          /* ExceptionCode                                        */
    uint64_t address;       /* ExceptionAddress - the instruction that faulted      */
    uint64_t fault_va;      /* ExceptionInformation[1] for an access violation      */
    uint32_t access;        /* ExceptionInformation[0]: 0 read, 1 write, 8 execute  */
    uint32_t stage;         /* exec_stage at the moment of the fault                */
    uint64_t rsp;           /* the faulting CONTEXT, for following the stack by hand */
    uint64_t rax, rcx, rdx, r8, r9;
    /* v6: what the handler DID about it, and the identity of the interrupted call. Until v6 the
       handler returned -1 on every fault, believing that to be EXCEPTION_CONTINUE_SEARCH; -1 is
       EXCEPTION_CONTINUE_EXECUTION, so an unfixable fault at the SAME instruction was retried
       forever, which is the client going "not responding" rather than crashing. These fields are
       what a run says afterwards: "recovered into the payload at 0x..." or "passed on to the
       client's own handler". */
    uint32_t recovered;     /* 1 = control was moved back into the payload           */
    uint32_t handler_rc;    /* the value cc_veh returned: 0 search, -1 continue       */
    uint32_t recover_why;   /* cc_recover_why: which step of the recovery decided    */
    uint32_t ours;          /* 1 = the faulting thread is the payload's own thread   */
    uint32_t fault_tid;     /* GetCurrentThreadId() as seen from the handler          */
    uint32_t expected_tid;  /* ctx->hijack_tid, so the two can be compared on paper  */
    uint64_t fault_rva;     /* address - roblox_base, or 0 when outside the image    */
    uint64_t resume_rip;    /* the payload return address the rip was set to         */
    uint64_t fault_rsp;     /* the stack the walk started from                       */
    uint64_t walked;        /* how many slots the walk read before it stopped         */
} cc_blackbox;

/* Why the recovery did or did not happen. A recovery that silently does nothing is worthless in a
   live run: the whole point is that the next Run says which of these it was. */
enum cc_recover_why : uint32_t {
    CC_REC_NOT_OUR_FAULT = 0,   /* no call in flight, or the faulting thread is not ours */
    CC_REC_NO_PAYLOAD    = 1,   /* the payload's own range was not supplied, so no frame can be named */
    CC_REC_STACK_ENDED   = 2,   /* the walk left the committed stack before finding a return address */
    CC_REC_NOT_FOUND     = 3,   /* the stack was walked to the limit with no address into the payload */
    CC_REC_DONE          = 4,   /* recovered: rip/rsp/rax were rewritten and the payload carries on */
};

/* EXCEPTION_RECORD / EXCEPTION_POINTERS, spelled out - the payload has no Windows headers, and the
   fields that matter are only the first four plus the parameter block. */
typedef struct cc_exc_rec {
    uint32_t code;          /* +0x00 ExceptionCode            */
    uint32_t flags;         /* +0x04                           */
    uint64_t record;        /* +0x08 nested EXCEPTION_RECORD*  */
    uint64_t address;       /* +0x10 ExceptionAddress          */
    uint32_t params;        /* +0x18 NumberParameters          */
    uint32_t _pad;          /* +0x1c                           */
    uint64_t info[15];      /* +0x20 ExceptionInformation      */
} cc_exc_rec;
typedef struct cc_exc_ptrs { cc_exc_rec* record; void* context; } cc_exc_ptrs;

/* x64 CONTEXT offsets that the black box reads. The injector already relies on the same two numbers
   when it saves a thread (Rsp +0x98, Rip +0xF8), so these are not new guesses. */
enum cc_ctx_off : uint64_t {
    CC_CTX_RAX = 0x78, CC_CTX_RCX = 0x80, CC_CTX_RDX = 0x88, CC_CTX_RSP = 0x98,
    CC_CTX_R8 = 0xB8, CC_CTX_R9 = 0xC0, CC_CTX_RIP = 0xF8,
};

typedef uint64_t (*cc_addveh_fn)(uint64_t first, void* handler);
typedef uint64_t (*cc_removeveh_fn)(void* handle);

/* MEMORY_BASIC_INFORMATION, x64 - spelled out so the payload needs no Windows headers. */
typedef struct cc_mbi {
    uint64_t BaseAddress;
    uint64_t AllocationBase;
    uint32_t AllocationProtect;
    uint32_t _pad0;
    uint64_t RegionSize;
    uint32_t State;
    uint32_t Protect;
    uint32_t Type;
    uint32_t _pad1;
} cc_mbi;

typedef uint64_t (*cc_vq_fn)(const void* addr, cc_mbi* out, uint64_t len);

typedef struct cc_ctx {
    /* function pointers, resolved for the TARGET process by the injector */
    uint64_t vq;                 /* VirtualQuery                                       */
    uint64_t reserved_set_event; /* v2: completion signal                              */
    uint64_t reserved_ntcontinue;/* v2: thread-hijack restore path                     */

    /* facts about the target, filled in before the payload is queued */
    uint64_t self_va;            /* address of THIS struct inside the target           */
    uint64_t roblox_base;
    uint64_t kernel32_base;
    uint64_t image_size;
    uint32_t marker;             /* CC_MARK                                             */
    uint32_t abi;                /* sizeof(cc_ctx) - catches a header/ABI mismatch      */

    /* black box (v4). add_veh = kernel32!AddVectoredExceptionHandler, veh_handler = the trampoline
       above, blackbox = a cc_blackbox. Zero = no recorder, which is what every self-test case
       except the black-box case uses. */
    uint64_t add_veh;
    uint64_t veh_handler;
    uint64_t blackbox;
    uint32_t bb_hold_loops;      /* spin inside the handler so the poll can read the record */
    uint32_t veh_installed;      /* OUTPUT: 1 once the handler is registered               */
    uint64_t veh_handle;         /* OUTPUT: what AddVectoredExceptionHandler returned      */

    /* exec inputs (v3). All zero = the read-only audit, which is what the self-test covers. */
    uint64_t exec_scratch;       /* target address of a cc_exec_scratch                 */
    uint64_t bytecode;           /* target address of the compiled chunk                */
    uint64_t bytecode_size;
    uint64_t chunkname;          /* target address of a NUL-terminated name             */
    uint64_t loader_va;          /* target base + CC_RVA_LOADER                         */
    uint64_t resume_va;          /* target base + CC_RVA_RESUME_WRAPPER                 */
    /* v6 inputs: the container entry, the payload the container takes (source or bytecode, the
       injector decides and points at it), and the payload's own address range in the target - the
       range is how the recorder recognises ITS OWN return address on the faulting stack and gets
       control back, so it has to be exact. */
    uint64_t container_va;       /* target base + CC_RVA_CONTAINER                      */
    uint64_t container_payload;  /* the bytes handed to the container as a std::string*  */
    uint64_t container_size;
    uint64_t payload_lo;         /* the copied .cpl range inside the target               */
    uint64_t payload_hi;

    uint32_t exec_mode;          /* 0 audit, 1 load only, 2 load + resume,
                                    4 container + resume, 5 container only               */
    uint32_t exec_reserved;

    /* v6: what the loader's OWN first dereference of ARG1 found, recorded on every exec run so the
       report can say why a call was refused instead of leaving a fault to be decoded by hand. */
    uint64_t arg1_field;         /* [L+0x18]: the object the loader indexes             */
    uint64_t arg1_size;          /* (int32)[that+0x18]: the mask the loader computes    */
    uint64_t arg1_buckets;       /* [that+0x20]: the array the loader indexes into      */
    uint32_t arg1_ok;            /* 1 when all three are usable                         */
    uint32_t fault_recovered;    /* 1 when the recorder recovered a faulted call        */
    uint64_t fault_rva;          /* where the recovered fault was, 0 when none          */

    /* exec outputs (v3) */
    uint32_t exec_status;        /* cc_exec_status                                      */
    uint32_t loader_rc;          /* rax out of the loader                               */
    uint32_t loader_result;      /* args.result: the loader's own 0-on-success          */
    uint32_t resume_rc;          /* rax out of the resume entry                         */
    uint32_t resume_result;      /* first dword of the 20-byte result the resume filled */
    uint32_t container_rc;       /* rax out of LuaVM_Load                               */
    uint32_t exec_stage;         /* cc_exec_stage - written BEFORE each call, so a crash localises */

    /* outputs */
    volatile uint32_t done;      /* CC_DONE once every field below is written          */
    uint32_t status;             /* cc_status                                          */

    uint64_t sched;
    uint64_t job_begin;
    uint64_t job_count;
    uint64_t job_first;
    uint64_t sc_from_job;        /* ScriptContext via job+0x1c0                        */
    uint64_t lua_state;          /* validated lua_State                                */
    uint32_t lua_state_off;      /* which ScriptContext offset produced it             */
    uint32_t lua_state_offsets_tried;

    uint64_t sc_from_dm;         /* ScriptContext via FakeDataModel -> DataModel+0x440 */
    uint64_t datamodel;
    uint32_t sc_routes_agree;    /* sc_from_job == sc_from_dm                          */
    uint32_t resume_depth;

    uint64_t flags[4];           /* EnableLoadModule, gate A, gate B (low byte each)    */
    uint32_t jobs_seen;
    uint32_t jobs_with_state;
    uint32_t reads_gated;        /* pointers rejected by the readability gate          */
    uint32_t tt_count;
    uint64_t tt_seen[8];         /* packed (address<<8) | tt for the first few looked at */

    /* v5: the recorder has to be REMOVED before the payload returns. Leaving it registered is not a
       leak, it is a time bomb: its handler is the trampoline, the trampoline jumps into this blob, and
       the injector frees this blob the moment it sees done - so the client's next first-chance
       exception (a game client takes them constantly: guard pages, probe reads, C++ throws) transfers
       control into unmapped memory and turns a handled fault into a fatal one. Measured against a
       stand-in that takes a handled access violation every 400 ms: it dies seconds after a run, while
       a stand-in that spins in its own code survives. remove_veh = the target's
       kernel32!RemoveVectoredExceptionHandler, resolved by the injector like add_veh; veh_removed is
       OUTPUT, 1 once the disarm went through, and the injector will not unmap anything while it is 0. */
    uint64_t remove_veh;
    uint32_t veh_removed;

    /* ---- v7: identifying the payload's OWN thread, which is how a fault gets recovered --------
       Measured 2026-10-10, second live Execute: the container call faulted at `execute at 0x0` -
       a call through a null pointer, which is what a mismatch between the container and the state
       looks like from the outside. That fault has rip = 0, i.e. OUTSIDE the client image, so the
       v6 recovery rule ("the rip must be inside the image") classified our own fatal fault as the
       client's business and let it kill the process. Address is the wrong test; ownership is the
       right one, and the only thread that can be running this payload is the one the injector
       redirected. The injector therefore writes the tid into `hijack_tid` immediately before each
       redirect (never earlier: an APC dispatched by an earlier delivery would read a stale tid),
       and `get_tid` is the target's kernel32!GetCurrentThreadId, resolved the same way as vq. */
    uint64_t get_tid;            /* kernel32!GetCurrentThreadId in the target               */
    uint32_t hijack_tid;         /* the thread the injector just redirected (input)         */
    uint32_t _tid_pad;
} cc_ctx;

#ifdef __cplusplus
extern "C" {
#endif
/* lives in the ".cpl" section of the injector binary, copied out verbatim */
void cc_payload(cc_ctx* ctx);
/* the recorder, reached through the injector's trampoline: (EXCEPTION_POINTERS*, cc_ctx*) */
int  cc_veh(cc_exc_ptrs* p, cc_ctx* ctx);
#ifdef __cplusplus
}
#endif
