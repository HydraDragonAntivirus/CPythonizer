/*
 * resolve.h - import-table hiding for the CPythonizer loader.
 *
 * The stub resolves every Win32 entry point it uses at run time, so its import
 * table only ever shows what the static CRT itself pulls in. No CreateProcessW,
 * no VirtualAlloc, no BCryptDecrypt: nothing that describes what the loader
 * does. What remains is the CRT's own list (heap, TLS, stdio, ...), which no
 * amount of work on this file can remove - only dropping the CRT would.
 *
 * Bootstrap, with no new imports:
 *   1. PEB->ImageBaseAddress gives our own image base (one stable PEB offset).
 *   2. Our own import directory is parsed to find GetModuleHandleW and
 *      LoadLibraryExW in the IAT. The CRT already imports both, so the import
 *      table does not grow by a single entry.
 *   3. bcrypt.dll is loaded, then every entry point is found by walking each
 *      module's export directory and matching a keyed hash of
 *      "<module>!<function>". No function name exists anywhere in the binary:
 *      not in .rdata, not in the hash table (which the build stores encrypted).
 *
 * The hash key is a per-build constant, so the usual "hash every export and
 * look for a match" table attack needs that key too. An attacker who hooks
 * GetProcAddress or VirtualAlloc inside the running process can still recover
 * the mapping; that is inherent to in-process resolution, not a defect here.
 */
#ifndef OBFH_RESOLVE_H
#define OBFH_RESOLVE_H

#include <windows.h>
#include <intrin.h>
#include "literals.h"

#define OBFH_HASH_SEED 0x811C9DC5u
#define OBFH_EXPORT_SCAN_LIMIT 0x8000u
#define OBFH_API_MAX 128u

/* ------------------------------------------------------------------ */
/*  keyed hash - mirrored byte for byte by the Python side              */
/* ------------------------------------------------------------------ */

__declspec(noinline) static unsigned obfh_hash_init(unsigned key)
{
    return key ? key : OBFH_HASH_SEED;
}

__declspec(noinline) static unsigned obfh_hash_step(unsigned h, unsigned char c)
{
    h = ((h ^ (unsigned int)c) * 0x01000193u) + 0x3D9Fu;
    h ^= h >> 7;
    return h;
}

__declspec(noinline) static unsigned obfh_hash_name(const char *name, unsigned key)
{
    unsigned h = obfh_hash_init(key);

    while (*name) {
        h = obfh_hash_step(h, (unsigned char)*name++);
        if (!h)
            h = 1u;  /* 0 means "not found" */
    }
    return h ? h : 1u;
}

/*
 * Hash of "<module>!<name>". The resolver walks the exports of a known module,
 * so it only needs the qualified form; this narrow variant is here for callers
 * that hold an ASCII module name (and for verifying the Python mirror).
 */
__declspec(noinline) static unsigned obfh_hash_qualified(const char *module,
                                                         unsigned module_hash,
                                                         const char *name)
{
    unsigned h = module_hash;

    h = obfh_hash_step(h, '!');
    while (*name)
        h = obfh_hash_step(h, (unsigned char)*name++);
    return h ? h : 1u;
}

/* ------------------------------------------------------------------ */
/*  image helpers                                                      */
/* ------------------------------------------------------------------ */

__declspec(noinline) static void *obfh_peb(void)
{
#if defined(_M_X64)
    return (void *)__readgsqword(0x60);
#else
    return (void *)__readfsdword(0x30);
#endif
}

__declspec(noinline) static void *obfh_self_base(void)
{
    unsigned char *peb = (unsigned char *)obfh_peb();

    return peb ? *(void **)(peb + 0x10) : NULL;  /* PEB->ImageBaseAddress */
}

__declspec(noinline) static int obfh_streq_ci(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = *a++;
        char cb = *b++;

        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb)
            return 0;
    }
    return *a == *b;
}

/* ------------------------------------------------------------------ */
/*  our own import table                                               */
/* ------------------------------------------------------------------ */

__declspec(noinline) static unsigned char *obfh_rva(void *base, unsigned rva)
{
    return (unsigned char *)base + rva;
}

/*
 * Fetch one of our own imports by name. Only the two bootstrap entries the CRT
 * already pulls in are looked up this way; everything else goes through the
 * export walk.
 */
__declspec(noinline) static void *obfh_own_import(const char *want)
{
    void *base = obfh_self_base();
    unsigned char *d = (unsigned char *)base;
    unsigned nt_off, imp_rva, imp_size, i;

    if (!base || *(unsigned short *)d != 0x5A4D)
        return NULL;
    nt_off = *(unsigned *)(d + 0x3C);
    if (nt_off + 0x40 > 0x10000)
        return NULL;
    if (*(unsigned *)(d + nt_off) != 0x00004550)
        return NULL;
    if (*(unsigned short *)(d + nt_off + 0x18) != 0x020B)
        return NULL;

    imp_rva = *(unsigned *)(d + nt_off + 0x18 + 0x70 + 1 * 8);
    imp_size = *(unsigned *)(d + nt_off + 0x18 + 0x70 + 1 * 8 + 4);
    if (!imp_rva || !imp_size || imp_size > 0x8000)
        return NULL;

    for (i = 0; i + 20 <= imp_size; i += 20) {
        unsigned char *desc = obfh_rva(base, imp_rva) + i;
        unsigned oft = *(unsigned *)(desc + 0);
        unsigned name_rva = *(unsigned *)(desc + 12);
        unsigned ft = *(unsigned *)(desc + 16);
        unsigned char *thunk;
        unsigned char *iat;

        if (!name_rva || !ft)
            continue;
        if (!obfh_streq_ci((const char *)obfh_rva(base, name_rva),
                           CPY_HSTR("kernel32.dll")))
            continue;

        thunk = obfh_rva(base, oft ? oft : ft);
        iat = obfh_rva(base, ft);
        for (;; thunk += 8, iat += 8) {
            unsigned long long v = *(unsigned long long *)thunk;

            if (!v)
                break;
            if (!(v & (1ull << 63)) &&
                obfh_streq_ci((const char *)obfh_rva(base, (unsigned)v + 2), want))
                return *(void **)iat;
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  export directory walk                                             */
/* ------------------------------------------------------------------ */

typedef struct obfh_exports {
    unsigned char *names;     /* array of RVA */
    unsigned char *ords;      /* array of WORD indexes */
    unsigned char *funcs;     /* array of RVA */
    unsigned count;
} obfh_exports;

__declspec(noinline) static int obfh_exports_open(void *base, obfh_exports *out)
{
    unsigned char *d = (unsigned char *)base;
    unsigned nt_off, edir_rva, edir_size;
    unsigned char *edir;

    if (!base || *(unsigned short *)d != 0x5A4D)
        return 0;
    nt_off = *(unsigned *)(d + 0x3C);
    if (*(unsigned *)(d + nt_off) != 0x00004550)
        return 0;
    if (*(unsigned short *)(d + nt_off + 0x18) != 0x020B)
        return 0;
    edir_rva = *(unsigned *)(d + nt_off + 0x18 + 0x70);
    edir_size = *(unsigned *)(d + nt_off + 0x18 + 0x70 + 4);
    if (!edir_rva || !edir_size || edir_size > 0x10000)
        return 0;

    edir = obfh_rva(base, edir_rva);
    out->count = *(unsigned *)(edir + 24);
    if (!out->count || out->count > OBFH_EXPORT_SCAN_LIMIT)
        return 0;
    out->funcs = obfh_rva(base, *(unsigned *)(edir + 28));
    out->names = obfh_rva(base, *(unsigned *)(edir + 32));
    out->ords = obfh_rva(base, *(unsigned *)(edir + 36));
    return 1;
}

__declspec(noinline) static void *obfh_export_addr(void *base,
                                                   const obfh_exports *ex,
                                                   unsigned index)
{
    unsigned ord = *(unsigned short *)(ex->ords + index * 2);
    unsigned rva;

    if (ord >= ex->count)
        return NULL;
    rva = *(unsigned *)(ex->funcs + ord * 4);
    if (!rva)
        return NULL;
    return obfh_rva(base, rva);
}

/* ------------------------------------------------------------------ */
/*  the resolver itself                                                */
/* ------------------------------------------------------------------ */

typedef void *(WINAPI *obfh_get_module_fn)(LPCWSTR);
typedef void *(WINAPI *obfh_load_module_fn)(LPCWSTR, void *, unsigned long);

/*
 * Forced bootstrap entries. The linker drops an import nobody references, so
 * these two are referenced here on purpose: they are the only Win32 names this
 * file leaves in the import table besides the CRT's own, and every program
 * imports them anyway. Everything else is resolved by hash.
 */
static HMODULE(WINAPI *volatile obfh_boot_module)(LPCWSTR) = GetModuleHandleW;
static HMODULE(WINAPI *volatile obfh_boot_load)(LPCWSTR, void *, DWORD) = LoadLibraryExW;

/* Hash an ASCII-only wide string byte by byte, so no conversion is needed. */
__declspec(noinline) static unsigned obfh_hash_wide(const wchar_t *w, unsigned key)
{
    unsigned h = obfh_hash_init(key);

    for (; *w; w++)
        h = obfh_hash_step(h, (unsigned char)(*w & 0xFF));
    return h;
}

__declspec(noinline) static unsigned obfh_hash_qualified_wide(const wchar_t *module,
                                                             unsigned module_hash,
                                                             const char *name)
{
    unsigned h = module_hash;

    h = obfh_hash_step(h, '!');
    while (*name)
        h = obfh_hash_step(h, (unsigned char)*name++);
    return h ? h : 1u;
}

/*
 * Resolve every slot of a build-generated table of module-qualified name
 * hashes. Returns 0 if anything is missing - a half-resolved loader would fail
 * in a way that is very hard to diagnose later, so the caller aborts.
 *
 *   table        encrypted "<module>!<function>" hashes, one per slot
 *   slots        out: function pointers (also used as scratch while decrypting)
 *   modules      wide module names, already decrypted by the caller
 */
/*
 * Forced bootstrap entries live just above, in this file.
 */
__declspec(noinline) static int obfh_resolve_table(const unsigned *table,
                                                  void **slots, unsigned count,
                                                  unsigned table_key,
                                                  unsigned hash_key,
                                                  const wchar_t *const *modules,
                                                  unsigned module_count)
{
    unsigned want[OBFH_API_MAX];
    obfh_get_module_fn get_module;
    obfh_load_module_fn load_module;
    unsigned i, m, left = count;

    if (count > OBFH_API_MAX)
        return 0;
    for (i = 0; i < count; i++) {
        want[i] = table[i] ^ table_key;
        slots[i] = NULL;
    }

    /* Prefer the IAT slot (it exists because the symbols above are referenced);
       fall back to the direct pointer if the import was optimised away. */
    get_module = (obfh_get_module_fn)obfh_own_import(CPY_HSTR("GetModuleHandleW"));
    if (!get_module)
        get_module = (obfh_get_module_fn)obfh_boot_module;
    load_module = (obfh_load_module_fn)obfh_own_import(CPY_HSTR("LoadLibraryExW"));
    if (!load_module)
        load_module = (obfh_load_module_fn)obfh_boot_load;
    if (!get_module)
        return 0;

    for (m = 0; m < module_count && left; m++) {
        obfh_exports ex;
        void *base = get_module(modules[m]);
        unsigned module_hash;
        unsigned n;

        if (!base && load_module)
            base = load_module(modules[m], NULL, 0x800 /* SYSTEM32 */);
        if (!base || !obfh_exports_open(base, &ex))
            continue;

        module_hash = obfh_hash_wide(modules[m], hash_key);
        for (n = 0; n < ex.count && left; n++) {
            const char *name = (const char *)obfh_rva(base, *(unsigned *)(ex.names + n * 4));
            unsigned h = obfh_hash_qualified_wide(modules[m], module_hash, name);

            for (i = 0; i < count; i++) {
                if (slots[i] || want[i] != h)
                    continue;
                slots[i] = obfh_export_addr(base, &ex, n);
                if (slots[i])
                    left--;
                break;
            }
        }
    }
    return left == 0;
}

#endif /* OBFH_RESOLVE_H */
