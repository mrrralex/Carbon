// Carbon - the compile half of the execute engine, running in OUR process.
//
// Design decision worth stating: the user's source is compiled HERE, not inside the target. Reasons:
//   * the compiler is ~7 MB of code that would otherwise have to be mapped into a process we are
//     trying not to disturb, and it would have to be self-contained the way the payload is;
//   * compiling in our process means a syntax error is caught by us, with no target involvement;
//   * the client's loader validates a version RANGE (3..14, SIGNATURES.md §8.2), so bytecode from
//     these objects is acceptable by the target's own rule, not by our assumption.
// Only the RESULT - a few hundred bytes - crosses into the target.
//
// The compiler itself: prebuilt Luau objects on this machine (third_party/luau-obj). MSVC mangles
// type NAMES rather than layouts, so the entry resolves against objects built from headers we do not
// have - but the structs below must still be at least as large as the real ones, and zero-filled, so
// every field lands on its "off/none" value. That is a legal, unoptimised compile. It is deliberately
// NOT a guess at the real field layout.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace Luau {

struct CompileOptions { unsigned char opaque[512]; };
struct ParseOptions   { unsigned char opaque[512]; };
class BytecodeEncoder;   // class, not struct: PEAU vs PEAV in the mangled name

std::string compile(const std::string& source, const CompileOptions& options,
                    const ParseOptions& parseOptions, BytecodeEncoder* encoder);

}  // namespace Luau

extern "C" {

/* Returns 0 on success and hands back a malloc'd copy of the bytecode.
   Negative on failure, with the compiler's own message copied into `err`.
   The error contract is NOT an exception and NOT an empty string: Luau returns a string whose
   FIRST BYTE IS 0 followed by the message. Treating that as bytecode would hand the loader a
   "version 0" chunk, which is exactly the path that ends in "bytecode corrupted". */
int cc_compile_source(const char* source, size_t len, void** out_data, size_t* out_size,
                      char* err, size_t err_cap)
{
    if (out_data) *out_data = nullptr;
    if (out_size) *out_size = 0;
    if (!source || !out_data || !out_size) return -1;

    Luau::CompileOptions co;
    Luau::ParseOptions po;
    memset(&co, 0, sizeof(co));
    memset(&po, 0, sizeof(po));

    std::string src(source, len);
    std::string bc;
    try {
        bc = Luau::compile(src, co, po, nullptr);
    } catch (...) {
        if (err && err_cap) _snprintf_s(err, err_cap, _TRUNCATE, "compiler threw an exception");
        return -2;
    }

    if (bc.empty()) {
        if (err && err_cap) _snprintf_s(err, err_cap, _TRUNCATE, "compiler returned nothing");
        return -3;
    }
    if ((unsigned char)bc[0] == 0) {
        if (err && err_cap) _snprintf_s(err, err_cap, _TRUNCATE, "%s", bc.c_str() + 1);
        return -4;                                    /* syntax/compile error, message included */
    }

    void* mem = malloc(bc.size());
    if (!mem) return -5;
    memcpy(mem, bc.data(), bc.size());
    *out_data = mem;
    *out_size = bc.size();
    return 0;
}

void cc_compile_free(void* p) { free(p); }

/* bytecode[0] = LBC version, bytecode[1] = type version. Exposed so callers report the target's own
   acceptance rule rather than a hard-coded number. */
unsigned cc_bytecode_version(const void* data, size_t n)
{
    return (data && n) ? (unsigned)((const unsigned char*)data)[0] : 0u;
}

unsigned cc_bytecode_type_version(const void* data, size_t n)
{
    return (data && n > 1) ? (unsigned)((const unsigned char*)data)[1] : 0u;
}

/* the same rule the client's loader enforces (SIGNATURES.md §8.2), so a bad compile cannot be
   silently shipped into a target: version 3..14 or 100, and type version 1..3 for version >= 4 */
int cc_bytecode_acceptable(unsigned version, unsigned type_version)
{
    int v_ok = (version >= 3 && version <= 14) || version == 100;
    if (!v_ok) return 0;
    if (version >= 4) return type_version >= 1 && type_version <= 3;
    return 1;
}

}  // extern "C"
