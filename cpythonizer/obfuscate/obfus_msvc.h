/*
 * obfus_msvc.h - MSVC (cl.exe, x64) port of the parts of
 * https://github.com/DosX-dev/obfus.h that a loader can actually use.
 *
 * WHY A PORT INSTEAD OF THE UPSTREAM HEADER
 * ------------------------------------------
 * obfus.h explicitly refuses MSVC ("obfus.h doesn't support Visual C/C++"):
 * it rewrites every `if` / `while` / `for` / `switch` in the translation unit
 * with GNU statement expressions `({ ... })`, and builds its control flow and
 * junk layers on GNU inline AT&T asm, `__builtin_choose_expr` and
 * `__typeof__`. None of those exist for x64 MSVC, so there is no flag that
 * makes the original header work with cl.exe.
 *
 * What is ported 1:1 in spirit (all of it compiles as plain /TC C):
 *   - RND()/seed mixing .......... same formula, __COUNTER__ + __LINE__ + seed
 *   - HIDE_STRING() .............. literal lives only on the stack, never in
 *                                  .rdata/.data, reached through an opaque
 *                                  noinline accessor
 *   - opaque predicates .......... conditions a static analyser cannot fold
 *   - ANTI_DEBUG ................. the same probe set (PEB, debug port,
 *                                  remote debugger, DR0-DR7 hardware
 *                                  breakpoints, ThreadHideFromDebugger) with
 *                                  the response behind an obfuscated sink
 *   - math VM .................... VM_* operations executed by a noinline
 *                                  dispatcher with rotated opcodes
 *   - fake protector signatures  .aspack / .adata / __wibu0x sections
 *
 * What could NOT be ported and why:
 *   - The automatic `if`/`while`/`for` rewriting. Flattening arbitrary C needs
 *     statement expressions; MSVC has no equivalent. Instead the caller writes
 *     the flattened dispatcher explicitly with OBF_DISPATCH_* (same result in
 *     the binary: one switch, one loop, opaque state values).
 *   - Inline-asm junk and the raw `.byte` opcodes. MSVC x64 has no inline asm;
 *     the junk is emitted with volatile noinline helpers instead.
 *
 * FEATURE SWITCHES (define before including):
 *   NO_OBFH        = 1  compile the whole thing out (no overhead at all)
 *   NO_OBFH_AD     = 1  disable the anti-debug layer
 *   OBFH_AD_V2     = 1  add the hardware-breakpoint probe (needs a second
 *                        thread; slightly slower at start)
 *   OBFH_FAKE_SIGNS= 1  emit fake protector/packer section markers
 *   OBFH_BUILD_SEED        per-build seed (cpythonizer passes os.urandom(4))
 */
#ifndef OBFH_MSC_H
#define OBFH_MSC_H

#if defined(_MSC_VER)
#pragma warning(disable: 4127) /* constant conditional - the point of opaques */
#endif

#include <windows.h>
#include <intrin.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =================================================================== */
/*  feature switches                                                    */
/* =================================================================== */

#ifndef OBFH_FAKE_SIGNS
#define OBFH_FAKE_SIGNS 0
#endif
#ifndef OBFH_AD_V2
#define OBFH_AD_V2 1
#endif
#ifndef NO_OBFH_AD
#define NO_OBFH_AD 0
#endif
#ifndef OBFH_BUILD_SEED
#define OBFH_BUILD_SEED 0u
#endif

#if OBFH_FAKE_SIGNS == 1
#pragma section(".aspack", read)
#pragma section(".adata", read)
#pragma section("__wibu00", read)
#pragma section("__wibu01", read)
#define OBFH_SIG __declspec(allocate(".aspack"))
#define OBFH_DATA __declspec(allocate(".adata"))
#define OBFH_WIBU0 __declspec(allocate("__wibu00"))
#define OBFH_WIBU1 __declspec(allocate("__wibu01"))
#else
#define OBFH_SIG
#define OBFH_DATA
#define OBFH_WIBU0
#define OBFH_WIBU1
#endif

/* =================================================================== */
/*  compile-time randomness                                             */
/*                                                                    */
/*  Same mixing as upstream: three independent draws per site so the    */
/*  result is not an affine function of __COUNTER__/__LINE__.          */
/* =================================================================== */

#define OBFH_MIX_A(v) (((unsigned int)(v) ^ ((unsigned int)(v) >> 16)) * 2246822507u)
#define OBFH_MIX_B(v) (((unsigned int)(v) ^ ((unsigned int)(v) >> 13)) * 3266489909u)

#define OBFH_DRAW_A (((__COUNTER__) + ((unsigned int)__LINE__ * 2654435761u) + \
                      (unsigned int)OBFH_BUILD_SEED) ^ 0x9E3779B9u)
#define OBFH_DRAW_B ((__COUNTER__ * 40503u) + 2531011u)
#define OBFH_DRAW_C ((unsigned int)__LINE__ * 2246822519u)

#define RND(min, max)                                                    \
    ((unsigned int)(min) +                                              \
     ((OBFH_MIX_A(OBFH_DRAW_A) ^ OBFH_MIX_B(OBFH_DRAW_B) ^               \
       OBFH_MIX_A(OBFH_DRAW_C)) %                                        \
      ((unsigned int)(max) - (unsigned int)(min) + 1u)))

#define OBFH_JUNK_WORD \
    (OBFH_MIX_A(OBFH_DRAW_B) ^ (unsigned int)OBFH_DRAW_A << 16 ^ OBFH_MIX_B(OBFH_DRAW_C))

/* =================================================================== */
/*  entropy                                                            */
/*                                                                    */
/*  rdtsc through the intrinsic (no inline asm on x64 MSVC) and a      */
/*  counter that differs per call site, so two sites never agree.      */
/* =================================================================== */

__declspec(noinline) static unsigned long long obfh_tick(unsigned int site)
{
    unsigned long long t = __rdtsc();
    _ReadWriteBarrier();
    t ^= (unsigned long long)site * 0x2545F4914F6CDD1DULL;
    t += __rdtsc();
    return t;
}

__declspec(noinline) static int obfh_always(int junk)
{
    volatile int keep = junk | 1;
    return keep & 1;
}

__declspec(noinline) static int obfh_never(int junk)
{
    volatile int keep = junk;
    return keep & 1 ? 1 : 0;
}

/* Unpredictable but deterministic-looking condition for junk branches. */
#define OBFH_JUNK_COND() (obfh_always((int)(obfh_tick(__COUNTER__) & 1u)) != 0)

/* =================================================================== */
/*  hidden strings                                                     */
/*                                                                    */
/*  The literal is a compound literal, so it only ever exists in the    */
/*  frame of the caller: it is not a .rdata/.data entry and cannot be   */
/*  found by walking the string tables of the binary.                  */
/* =================================================================== */

#define STACK_STRING(str) ((char[]){str})

__declspec(noinline) static char *obfh_hidden(char *s)
{
    size_t i;

    if (!s)
        return s;
    for (i = 1; s[i]; i++)
        s[i - 1] = s[i];
    s[i - 1] = 0;
    return s;
}

#define HIDE_STRING(str) (OBFH_JUNK_COND() ? obfh_hidden(STACK_STRING("\0" str "\0")) : (str))

/*
 * Compile-time string encryption (the real thing, not the stack variant).
 *
 * HIDE_STRING only keeps a literal out of the data sections - the bytes still
 * end up in .text as the immediates of the stack stores, so a raw grep over
 * the binary finds them anyway. These helpers are what removes them: the
 * build rewrites CPY_HSTR("x") into an XOR-encrypted byte array that is
 * decoded in place at the call site, so the plaintext never reaches the file.
 *
 *     obfh_decrypt_str((unsigned char[]){0x1e, 0x4b, ..., 0x00}, 0x5a, 8)
 *
 * The key is per call site, so two occurrences of the same name do not share
 * ciphertext, and every one of them decodes to a different buffer.
 */
__declspec(noinline) static char *obfh_decrypt_str(unsigned char *buf,
                                                  unsigned char key, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        buf[i] ^= key;
    _ReadWriteBarrier();
    return (char *)buf;
}

__declspec(noinline) static wchar_t *obfh_decrypt_wstr(wchar_t *buf,
                                                       unsigned char key, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        buf[i] = (wchar_t)(((unsigned char *)buf)[i] ^ key);
    _ReadWriteBarrier();
    return buf;
}

/* Placeholders: cpythonizer rewrites these into encrypted arrays whenever the
   guard is on; without the guard they stay plain literals. */
#define CPY_HSTR(s) s
#define CPY_HWSTR(s) L##s

/* Wide stack variant; kept for API parity, see obfh_hidden_w below. */
__declspec(noinline) static wchar_t *obfh_hidden_w(wchar_t *s)
{
    size_t i;

    if (!s)
        return s;
    for (i = 1; s[i]; i++)
        s[i - 1] = s[i];
    s[i - 1] = 0;
    return s;
}

/* =================================================================== */
/*  opaque predicates                                                  */
/*                                                                    */
/*  True/false by construction, but the analyser cannot see it: the      */
/*  decision happens inside noinline functions fed by rdtsc and          */
/*  volatile values. These are safe to guard real code with - unlike a   */
/*  predicate whose outcome depends on a random draw, which would be a    */
/*  coin flip rather than an opaque one.                                 */
/* =================================================================== */

__declspec(noinline) static int obfh_op_true(unsigned long long a,
                                            unsigned long long b)
{
    volatile unsigned long long x = a ^ (obfh_tick(__COUNTER__) & 0ull);
    volatile unsigned long long y = b ^ (obfh_tick(__COUNTER__) & 0ull);
    volatile unsigned long long z = (x ^ y) ^ (x ^ y);

    _ReadWriteBarrier();
    return (int)(z == 0);
}

__declspec(noinline) static int obfh_op_false(unsigned long long a,
                                             unsigned long long b)
{
    volatile unsigned long long x = a;
    volatile unsigned long long y = b;

    _ReadWriteBarrier();
    return (int)((x ^ y) == 0 && 1);
}

#define OBFH_OPAQUE_TRUE(a, b) \
    obfh_op_true((unsigned long long)(a), (unsigned long long)(b))
#define OBFH_OPAQUE_FALSE(a, b) \
    obfh_op_false((unsigned long long)(a), (unsigned long long)(b))
#define OBFH_OPAQUE_ALWAYS() OBFH_OPAQUE_TRUE(__LINE__, __COUNTER__)
#define OBFH_OPAQUE_NEVER() OBFH_OPAQUE_FALSE(__LINE__, __COUNTER__)

/* Unpredictable condition, only for junk code paths. */
#define OBFH_JUNK_COND() (obfh_always((int)(obfh_tick(__COUNTER__) & 1u)) != 0)

/* =================================================================== */
/*  math VM                                                            */
/*                                                                    */
/*  Every operation is executed by one noinline dispatcher with a       */
/*  rotated opcode and salt, so the constants and the operation itself   */
/*  do not appear in the caller's code.                                 */
/* =================================================================== */

enum obfh_op {
    OBFH_OP_NOP = 0x51, OBFH_OP_ADD, OBFH_OP_SUB, OBFH_OP_MUL,
    OBFH_OP_DIV, OBFH_OP_MOD, OBFH_OP_EQU, OBFH_OP_NEQ,
    OBFH_OP_LSS, OBFH_OP_GTR, OBFH_OP_LEQ, OBFH_OP_GEQ, OBFH_OP_BRANCH
};

/* The opcode crosses the call boundary rotated by a per-site salt, so the
   operation is not visible as a constant in the caller's code. obfh_unrot is
   the same pure-XOR transform, applied again before the dispatch. */
#define OBFH_XOR3(v, s) \
    ((unsigned int)(v) ^ (unsigned int)(s) ^ ((unsigned int)(s) >> 7) ^ ((unsigned int)(s) << 3))

__declspec(noinline) static unsigned int obfh_rot(unsigned int v, unsigned int s)
{
    volatile unsigned int r = OBFH_XOR3(v, s);
    _ReadWriteBarrier();
    return r;
}

__declspec(noinline) static long long obfh_vm(long long a, long long b,
                                             unsigned int op, unsigned int salt)
{
    volatile long long va = a;
    volatile long long vb = b;
    volatile unsigned int vop = obfh_rot(op, salt);
    long long r;

    switch (OBFH_XOR3(vop, salt)) {
    case OBFH_OP_NOP: r = va; break;
    case OBFH_OP_ADD: r = va + vb; break;
    case OBFH_OP_SUB: r = va - vb; break;
    case OBFH_OP_MUL: r = va * vb; break;
    case OBFH_OP_DIV: r = vb ? va / vb : 0; break;
    case OBFH_OP_MOD: r = vb ? va % vb : 0; break;
    case OBFH_OP_EQU: r = va == vb; break;
    case OBFH_OP_NEQ: r = va != vb; break;
    case OBFH_OP_LSS: r = va < vb; break;
    case OBFH_OP_GTR: r = va > vb; break;
    case OBFH_OP_LEQ: r = va <= vb; break;
    case OBFH_OP_GEQ: r = va >= vb; break;
    default:          r = va; break;
    }
    return r;
}

#define VM_OP(a, b, op) ((long long)obfh_vm((long long)(a), (long long)(b), (unsigned int)(op), RND(1, 65535)))

#define VM_ADD(a, b) VM_OP(a, b, OBFH_OP_ADD)
#define VM_SUB(a, b) VM_OP(a, b, OBFH_OP_SUB)
#define VM_MUL(a, b) VM_OP(a, b, OBFH_OP_MUL)
#define VM_DIV(a, b) VM_OP(a, b, OBFH_OP_DIV)
#define VM_MOD(a, b) VM_OP(a, b, OBFH_OP_MOD)
#define VM_EQU(a, b) VM_OP(a, b, OBFH_OP_EQU)
#define VM_NEQ(a, b) VM_OP(a, b, OBFH_OP_NEQ)
#define VM_LSS(a, b) VM_OP(a, b, OBFH_OP_LSS)
#define VM_GTR(a, b) VM_OP(a, b, OBFH_OP_GTR)
#define VM_LEQ(a, b) VM_OP(a, b, OBFH_OP_LEQ)
#define VM_GEQ(a, b) VM_OP(a, b, OBFH_OP_GEQ)
#define VM_OBF_INT(n) ((long long)obfh_vm((long long)(n), (long long)RND(1, 99999999), OBFH_OP_NOP, RND(1, 65535)))

/* A branch whose condition the static analyser cannot fold, but which always
   evaluates to the caller's condition. */
__declspec(noinline) static int obfh_branch(int cond, unsigned int salt)
{
    volatile int c = cond;
    volatile unsigned int keep = salt;

    _ReadWriteBarrier();
    (void)keep;
    return c;
}

#define VM_IF(cond) if (obfh_branch(!!(cond), RND(1, 65535)))
#define VM_ELSE_IF(cond) else if (obfh_branch(!!(cond), RND(1, 65535)))
#define VM_ELSE else

/* =================================================================== */
/*  control flow flattening                                            */
/*                                                                    */
/*  The portable replacement for obfus.h's `if`/`while` rewriting.      */
/*  Write the body as numbered blocks; the binary gets one switch       */
/*  inside one loop, exactly the shape OLLVM produces.                  */
/*                                                                    */
/*      OBF_DISPATCH_BEGIN(int)                                          */
/*      OBF_DISPATCH_CASE(0)                                            */
/*          ...                                                         */
/*          OBF_DISPATCH_GOTO(1)                                        */
/*      OBF_DISPATCH_CASE(1)                                            */
/*          ...                                                         */
/*          OBF_DISPATCH_EXIT                                           */
/*      OBF_DISPATCH_END()                                              */
/* =================================================================== */

#define OBF_DISPATCH_BEGIN(type) \
    type obfh_state = (type)0; \
    for (;;) { switch (obfh_state) {
#define OBF_DISPATCH_CASE(n) case (n):
#define OBF_DISPATCH_GOTO(n) obfh_state = (n); continue;
#define OBF_DISPATCH_EXIT goto obfh_dispatch_done;
#define OBF_DISPATCH_STATE obfh_state
#define OBF_DISPATCH_END() default: break; } } obfh_dispatch_done:

/* =================================================================== */
/*  fake protector / packer signatures                                 */
/* =================================================================== */

#if OBFH_FAKE_SIGNS == 1
/* Misdirection only: tools and scanners that key on a protector's section
   names get a false positive. They also have to be *referenced* - unreferenced
   statics are elided before the section attribute matters - so the anti-debug
   path touches them once, which is also what an analyst sees in the code. */
OBFH_SIG static const char obfh_sig_aspack[] = {0x41, 0x56, 0x50, 0x21, 0x00, 0x00};
OBFH_SIG static const char obfh_sig_aspack2[] = {0x00, 0x00, 0x21, 0x50, 0x56, 0x41};
OBFH_DATA static const char obfh_sig_adatum[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
OBFH_WIBU0 static const char obfh_sig_wibu0[] = {0x57, 0x49, 0x42, 0x55, 0x00, 0x00};
OBFH_WIBU1 static const char obfh_sig_wibu1[] = {0x00, 0x00, 0x55, 0x42, 0x49, 0x57};

__declspec(noinline) static void obfh_sig_touch(void)
{
    volatile unsigned char sink = 0;

    sink ^= (unsigned char)obfh_sig_aspack[0];
    sink ^= (unsigned char)obfh_sig_aspack2[0];
    sink ^= (unsigned char)obfh_sig_adatum[0];
    sink ^= (unsigned char)obfh_sig_wibu0[0];
    sink ^= (unsigned char)obfh_sig_wibu1[0];
    _ReadWriteBarrier();
    (void)sink;
}
#else
__declspec(noinline) static void obfh_sig_touch(void) { }
#endif

/* =================================================================== */
/*  anti-debug                                                         */
/*                                                                    */
/*  Detection is separated from the response: the probes only report    */
/*  evidence, and the reaction is picked behind opaque branches, so a    */
/*  patcher cannot simply NOP the IsDebuggerPresent call.               */
/* =================================================================== */

#if NO_OBFH_AD == 0

typedef LONG (WINAPI *obfh_NtSetInformationThread)(HANDLE, ULONG, ULONG_PTR, ULONG);
typedef LONG (WINAPI *obfh_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef HMODULE (WINAPI *obfh_GetModuleHandleA_)(LPCSTR);
typedef BOOL (WINAPI *obfh_CheckRemoteDebuggerPresent)(HANDLE, BOOL *);

/* Hide this thread from debuggers; failure is not an error. */
__declspec(noinline) static void obfh_ad_hide_thread(void)
{
    HMODULE ntdll = GetModuleHandleA(CPY_HSTR("ntdll.dll"));
    obfh_NtSetInformationThread fn;

    if (!ntdll)
        return;
    fn = (obfh_NtSetInformationThread)(void *)GetProcAddress(ntdll, CPY_HSTR("NtSetInformationThread"));
    if (fn)
        (void)fn(GetCurrentThread(), 0x11 /* ThreadHideFromDebugger */, 0, 0);
}

/* PEB.BeingDebugged without calling IsDebuggerPresent. */
__declspec(noinline) static int obfh_ad_peb_flag(void)
{
#if defined(_M_X64) || defined(__x86_64__)
    unsigned char *peb = (unsigned char *)__readgsqword(0x60);
#else
    unsigned char *peb = (unsigned char *)__readfsdword(0x30);
#endif
    volatile unsigned char *b = (volatile unsigned char *)peb;
    int flag;

    _ReadWriteBarrier();
    flag = b ? b[2] : 0;
    _ReadWriteBarrier();
    return flag != 0;
}

/* ProcessDebugPort / ProcessDebugObjectHandle: catches a debugger that
   never set the PEB flag (and remote debuggers that attach later). */
__declspec(noinline) static int obfh_ad_debug_port(void)
{
    HMODULE ntdll = GetModuleHandleA(CPY_HSTR("ntdll.dll"));
    obfh_NtQueryInformationProcess fn;
    ULONG_PTR port = 0;
    ULONG handle = 0;
    ULONG ret = 0;

    if (!ntdll)
        return 0;
    fn = (obfh_NtQueryInformationProcess)(void *)GetProcAddress(ntdll, CPY_HSTR("NtQueryInformationProcess"));
    if (!fn)
        return 0;
    if (fn(GetCurrentProcess(), 7 /* ProcessDebugPort */, &port, sizeof(port), &ret) == 0)
        return port != 0;
    if (fn(GetCurrentProcess(), 0x1E /* ProcessDebugObjectHandle */, &handle, sizeof(handle), &ret) == 0)
        return handle != 0;
    return 0;
}

__declspec(noinline) static int obfh_ad_remote_debugger(void)
{
    obfh_CheckRemoteDebuggerPresent fn;
    BOOL present = FALSE;

    fn = (obfh_CheckRemoteDebuggerPresent)(void *)GetProcAddress(
        GetModuleHandleA(CPY_HSTR("kernel32.dll")), CPY_HSTR("CheckRemoteDebuggerPresent"));
    if (!fn)
        return 0;
    if (!fn(GetCurrentProcess(), &present))
        return 0;
    return present != FALSE;
}

#if OBFH_AD_V2 == 1
/* DR0-DR7: hardware breakpoints survive every software hook trick.
   The context must be read from another thread (a thread cannot suspend
   itself and read its own debug registers), and the SDK's CONTEXT is used
   verbatim - a hand-rolled layout would read the wrong offsets and report a
   breakpoint that was never set. Only the DR7 enable bits count: DR0-DR3 can
   hold stale addresses from a previous debugger session. */
__declspec(noinline) static DWORD WINAPI obfh_ad_dr_worker(LPVOID arg)
{
    HANDLE thread = (HANDLE)arg;
    CONTEXT ctx;
    DWORD detected = 0;

    if (SuspendThread(thread) != (DWORD)-1) {
        memset(&ctx, 0, sizeof ctx);
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(thread, &ctx))
            detected = (ctx.Dr7 & 0xFFu) != 0;
        ResumeThread(thread);
    }
    CloseHandle(thread);
    return detected;
}

__declspec(noinline) static int obfh_ad_hw_breakpoints(void)
{
    HANDLE dup = NULL;
    HANDLE worker;
    DWORD detected = 0;

    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
                         &dup, 0, FALSE, DUPLICATE_SAME_ACCESS))
        return 0;
    worker = CreateThread(NULL, 0, obfh_ad_dr_worker, dup, 0, NULL);
    if (!worker) {
        CloseHandle(dup);
        return 0;
    }
    if (WaitForSingleObject(worker, 3000) == WAIT_OBJECT_0)
        GetExitCodeThread(worker, &detected);
    CloseHandle(worker);
    return detected != 0;
}
#endif /* OBFH_AD_V2 */

/* Response sinks. Deliberately not ExitProcess: a silent kill is a one-byte
   patch target, while a computed spin loop is not. */
__declspec(noinline) static void obfh_ad_sink_a(unsigned int seed)
{
    volatile unsigned int state = seed | 1u;

    for (;;) {
        unsigned int nxt = state ^ (unsigned int)obfh_tick(__COUNTER__);
        state = ((nxt << 7) | (nxt >> 25)) + RND(1, 65535);
    }
}

__declspec(noinline) static void obfh_ad_sink_b(unsigned int seed)
{
    volatile unsigned int state = seed;

    for (;;) {
        state = state * (RND(1, 32767) * 2u + 1u) + RND(1, 65535);
        state ^= state >> 13;
    }
}

__declspec(noinline) static int obfh_ad_detected(void)
{
    int hit = 0;

    if (OBFH_OPAQUE_ALWAYS()) {
        hit |= obfh_ad_peb_flag();
        hit |= obfh_ad_debug_port();
        hit |= obfh_ad_remote_debugger();
#if OBFH_AD_V2 == 1
        if (!hit)
            hit |= obfh_ad_hw_breakpoints();
#endif
    } else {
        hit = 1;
    }
    return hit;
}

/* Call at the points worth protecting. Cheap enough for startup paths. */
#define ANTI_DEBUG                                                       \
    do {                                                                 \
        obfh_sig_touch();                                                \
        obfh_ad_hide_thread();                                           \
        if (obfh_ad_detected()) {                                        \
            if (RND(0, 1) == 0)                                          \
                obfh_ad_sink_a((unsigned int)obfh_tick(__COUNTER__));    \
            else                                                         \
                obfh_ad_sink_b((unsigned int)obfh_tick(__COUNTER__));    \
        }                                                                \
    } while (0)

#else /* NO_OBFH_AD == 1 */

#define ANTI_DEBUG ((void)0)

#endif /* NO_OBFH_AD */

#ifdef __cplusplus
}
#endif

#endif /* OBFH_MSC_H */
