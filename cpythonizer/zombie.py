"""Zombie loader: the program is never written to disk.

Layout of the shipped EXE (one binary, two roles, decided by its trailer):

    [ stub ][ runtime blob ][ program blob ][ 56 byte trailer ]

The trailer is ``CPYZMB1\\0`` + ``u64 stored1`` + ``u64 orig1`` + ``u32 mode1``
+ ``u32 crc1`` + ``u64 stored2`` + ``u64 orig2`` + ``u32 mode2`` + ``u32 crc2``.

Role 1 - the shipped EXE (magic ``CPYZMB1``):

  1. decrypt + unpack the runtime blob into ``%TEMP%\\<app>-<8 random hex>\\``
     (python314.dll, the .pyd extension modules, python314.zip,
     vcruntime/libcrypto, ...). These MUST be real files: the Windows loader
     and CPython itself resolve them by path.
  2. write the ZOMBIE into that folder - our own stub bytes + the untouched
     program blob + a ``CPYZMB2`` trailer, named after the original program.
     The dropped EXE holds zero instructions of the real program, so a
     disassembler, a strings scan or a copy of that file yields nothing.
  3. run the zombie, wait for it, delete the folder, forward the exit code.

Role 2 - the zombie, now running from ``%TEMP%`` (magic ``CPYZMB2``):

  1. decrypt the program PE,
  2. map it in memory (headers, sections, relocations, imports, section
     protections, ``.pdata`` registration for x64 unwinding),
  3. anti-dump: zero **only** ``SizeOfImage``,
  4. call its ``wmainCRTStartup``.

Both roles are the same stub bytes, so the zombie is produced by copying this
file's own prefix - there is no second payload to embed anywhere.

Why the program may be mapped but the DLLs may not: a manually mapped module
is invisible to the loader, so everything that expects a real on-disk module
(the import graph, extension module loads, ``sys.prefix`` discovery, TLS,
CRT bookkeeping) breaks. Doing that to *every* DLL kills the program. The EXE
is the one image nothing else loads, so it can live purely in RAM - and once
its DLLs sit next to the zombie in ``%TEMP%``, the mapped program boots just
like the ordinary staged build.
"""
from __future__ import annotations

import os
import shutil
import string
import uuid
import zipfile
import zlib
from pathlib import Path

from .cython_vs import SLN_TEMPLATE, build_sln

MAGIC_OUTER = b"CPYZMB1\0"
MAGIC_ZOMBIE = b"CPYZMB2\0"
# magic(8) + stored(8) + orig(8) + mode(4) + crc(4), per blob
TAIL_OUTER = 56
TAIL_ZOMBIE = 32

MODE_RAW = 0
MODE_LZMA2 = 1

COPY_CHUNK = 1 << 20
SKIP_SUFFIXES = (".pdb", ".exp", ".lib", ".ilk")

# Debug switches, read by the stub at runtime:
#   CPYTHONIZER_ONEFILE_VERBOSE=1     print what the loader does to stderr
#   CPYTHONIZER_ONEFILE_KEEP=1        leave the temp folder behind (or pass
#                                     --cpythonizer-keep to the exe)
#   CPYTHONIZER_ONEFILE_NOANTIDUMP=1  keep SizeOfImage intact

STUB_C = string.Template(r"""/*
 * CPythonizer zombie loader - generated, do not edit.
 *
 * One binary, two roles, picked by the appended trailer:
 *
 *   CPYZMB1  [ stub ][ runtime blob ][ program blob ][ 56 byte trailer ]
 *            Drops the runtime into %TEMP%\<app>-<random>\, writes a ZOMBIE
 *            copy of itself there (stub + program blob, no program code),
 *            runs it and cleans up afterwards.
 *
 *   CPYZMB2  [ stub ][ program blob ][ 32 byte trailer ]
 *            Decrypts the program PE, maps it in RAM and runs it. Only
 *            SizeOfImage is blanked for the anti-dump: the DOS/NT headers,
 *            the section table and .pdata stay intact because the CRT, the
 *            x64 unwinder and CPython all read them.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#ifndef XZ_USE_CRC32
#define XZ_USE_CRC32
#endif
#include "xz.h"

#define MAGIC_OUTER   "CPYZMB1"
#define MAGIC_ZOMBIE  "CPYZMB2"
#define TAIL_OUTER    56
#define TAIL_ZOMBIE   32

#define MODE_RAW      0u
#define MODE_LZMA2    1u

#define COPY_BUF      0x4000
#define MAX_ATTEMPTS  32
#define MAX_IMAGE     (768u * 1024u * 1024u)

/* Injected by the build. */
#define CHILD_NAME        L"$CHILD_NAME"   /* zombie name inside the folder */
#define TEMP_PREFIX       L"$TEMP_PREFIX"  /* random folder name prefix    */
#define ANTIDUMP          $ANTIDUMP         /* 1 = blank SizeOfImage        */
#define PAYLOAD_ENCRYPTED $PAYLOAD_ENCRYPTED

/* Per-build random AES-256-CBC material, masked, one set per blob. */
static const unsigned char K1_MASK[32]   = { $K1_MASK };
static const unsigned char K1_MASKED[32] = { $K1_MASKED };
static const unsigned char K1_IV[16]     = { $K1_IV };
static const unsigned char K2_MASK[32]   = { $K2_MASK };
static const unsigned char K2_MASKED[32] = { $K2_MASKED };
static const unsigned char K2_IV[16]     = { $K2_IV };

static volatile DWORD g_child = 0;
static unsigned char *g_image;      /* mapped program, for the crash locator */
static int g_verbose = -1;
static int g_antidump = -1;

/* ------------------------------------------------------------------ */
/*  logging                                                            */
/* ------------------------------------------------------------------ */

static int env_flag(const wchar_t *name)
{
    wchar_t v[8];

    v[0] = L'\0';
    return GetEnvironmentVariableW(name, v, 8) > 0 && v[0] != L'0';
}

static int verbose(void)
{
    if (g_verbose < 0)
        g_verbose = env_flag(L"CPYTHONIZER_ONEFILE_VERBOSE");
    return g_verbose;
}

static int antidump(void)
{
    if (g_antidump < 0)
        g_antidump = env_flag(L"CPYTHONIZER_ONEFILE_NOANTIDUMP") ? 0 : ANTIDUMP;
    return g_antidump;
}

static void sayf(const wchar_t *fmt, ...)
{
    va_list ap;

    if (!verbose())
        return;
    fwprintf(stderr, L"[cpythonizer] ");
    va_start(ap, fmt);
    vfwprintf(stderr, fmt, ap);
    va_end(ap);
    fputws(L"\n", stderr);
    fflush(stderr);
}

static void fail(const wchar_t *msg)
{
    fwprintf(stderr, L"[cpythonizer] zombie: %s\n", msg);
    fflush(stderr);
}

/* ------------------------------------------------------------------ */
/*  little helpers                                                     */
/* ------------------------------------------------------------------ */

static unsigned rd16(const unsigned char *p)
{
    return (unsigned)p[0] | ((unsigned)p[1] << 8);
}

static unsigned rd32(const unsigned char *p)
{
    return (unsigned)p[0] | ((unsigned)p[1] << 8) |
           ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
}

static ULONGLONG rd64(const unsigned char *p)
{
    ULONGLONG v = 0;
    int i;

    for (i = 7; i >= 0; i--)
        v = (v << 8) | (ULONGLONG)p[i];
    return v;
}

static int read_at(HANDLE f, ULONGLONG off, void *buf, DWORD len)
{
    LARGE_INTEGER li;
    DWORD total = 0;
    unsigned char *p = (unsigned char *)buf;

    li.QuadPart = (LONGLONG)off;
    if (!SetFilePointerEx(f, li, NULL, FILE_BEGIN))
        return 0;
    while (total < len) {
        DWORD got = 0, want = len - total;
        if (!ReadFile(f, p + total, want, &got, NULL) || got == 0)
            return 0;
        total += got;
    }
    return 1;
}

static int copy_range(HANDLE src, ULONGLONG off, ULONGLONG len, HANDLE dst)
{
    unsigned char chunk[COPY_BUF];

    while (len > 0) {
        DWORD want = (DWORD)(len > COPY_BUF ? COPY_BUF : len);
        DWORD put = 0;

        if (!read_at(src, off, chunk, want))
            return 0;
        if (!WriteFile(dst, chunk, want, &put, NULL) || put != want)
            return 0;
        off += want;
        len -= want;
    }
    return 1;
}

static void wc_append(wchar_t *buf, size_t cap, size_t *len, const wchar_t *s)
{
    while (*s && *len + 1 < cap)
        buf[(*len)++] = *s++;
    buf[*len] = L'\0';
}

static int dir_of(const wchar_t *path, wchar_t *out, size_t cap)
{
    const wchar_t *slash = wcsrchr(path, L'\\');
    size_t n;

    if (!slash)
        return 0;
    n = (size_t)(slash - path);
    if (n + 1 > cap)
        return 0;
    memcpy(out, path, n * sizeof(wchar_t));
    out[n] = L'\0';
    return 1;
}

/* Create every directory in the path; existing ones are fine. */
static void ensure_dirs(const wchar_t *path)
{
    wchar_t buf[1024];
    size_t i;

    if (_snwprintf_s(buf, 1024, _TRUNCATE, L"%s", path) < 0)
        return;
    for (i = 3; buf[i] != L'\0'; i++) {
        if (buf[i] == L'\\' || buf[i] == '/') {
            wchar_t sep = buf[i];
            buf[i] = L'\0';
            CreateDirectoryW(buf, NULL);
            buf[i] = sep;
        }
    }
    CreateDirectoryW(buf, NULL);
}

/* Recursive delete; read-only payload files are reset first. */
static void remove_tree(const wchar_t *dir)
{
    WIN32_FIND_DATAW fd;
    wchar_t pattern[1024], child[1024];
    HANDLE h;

    if (_snwprintf_s(pattern, 1024, _TRUNCATE, L"%s\\*", dir) < 0)
        return;
    h = FindFirstFileW(pattern, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L".."))
                continue;
            if (_snwprintf_s(child, 1024, _TRUNCATE, L"%s\\%s", dir,
                             fd.cFileName) < 0)
                continue;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                remove_tree(child);
            else {
                SetFileAttributesW(child, FILE_ATTRIBUTE_NORMAL);
                DeleteFileW(child);
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    SetFileAttributesW(dir, FILE_ATTRIBUTE_NORMAL);
    RemoveDirectoryW(dir);
}

/* The child may need a moment to unmap its DLLs, so retry a little. */
static void cleanup(const wchar_t *dir)
{
    int i;

    for (i = 0; i < 40; i++) {
        remove_tree(dir);
        if (GetFileAttributesW(dir) == INVALID_FILE_ATTRIBUTES)
            return;
        Sleep(25);
    }
}

/* %TEMP%\<prefix>-<8 random hex>, retried until a free name shows up. */
static int make_temp_dir(const wchar_t *prefix, wchar_t *out, size_t cap)
{
    static const wchar_t hex[] = L"0123456789ABCDEF";
    wchar_t base[MAX_PATH], dir[1024], name[32];
    int attempt;

    if (GetTempPathW(MAX_PATH, base) == 0)
        return 0;
    for (attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        unsigned char rnd[4];
        wchar_t *p = name;
        int i;

        if (BCryptGenRandom(NULL, rnd, sizeof(rnd),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
            return 0;
        for (i = 0; i < 4; i++) {
            *p++ = hex[(rnd[i] >> 4) & 0xF];
            *p++ = hex[rnd[i] & 0xF];
        }
        *p = L'\0';
        if (_snwprintf_s(dir, 1024, _TRUNCATE, L"%s%s-%s", base, prefix,
                         name) < 0)
            return 0;
        if (CreateDirectoryW(dir, NULL)) {
            if (_snwprintf_s(out, cap, _TRUNCATE, L"%s", dir) < 0)
                return 0;
            return 1;
        }
        if (GetLastError() != ERROR_ALREADY_EXISTS)
            return 0;
    }
    return 0;
}

static int keep_temp(int argc, wchar_t **argv)
{
    int i;

    if (env_flag(L"CPYTHONIZER_ONEFILE_KEEP"))
        return 1;
    for (i = 1; i < argc; i++)
        if (!wcscmp(argv[i], L"--cpythonizer-keep"))
            return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  blob: decrypt -> decompress -> crc                                  */
/* ------------------------------------------------------------------ */

static int decrypt_payload(const unsigned char *cipher, DWORD cipher_len,
                           const unsigned char *mask,
                           const unsigned char *masked,
                           const unsigned char *iv,
                           unsigned char **out_plain, DWORD *out_plain_len)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD res = 0;
    unsigned char iv_copy[16];
    unsigned char key[32];
    unsigned char *plain;
    int i;

    for (i = 0; i < 32; i++)
        key[i] = (unsigned char)(mask[i] ^ masked[i]);
    memcpy(iv_copy, iv, 16);

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) {
        SecureZeroMemory(key, sizeof(key));
        return 0;
    }
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                          sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        SecureZeroMemory(key, sizeof(key));
        return 0;
    }
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, 32, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        SecureZeroMemory(key, sizeof(key));
        return 0;
    }
    SecureZeroMemory(key, sizeof(key));

    plain = (unsigned char *)malloc(cipher_len);
    if (!plain) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }
    if (BCryptDecrypt(hKey, (PUCHAR)cipher, cipher_len, NULL, iv_copy, 16,
                      plain, cipher_len, &res, 0) != 0) {
        free(plain);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (res > 0) {  /* PKCS#7 unpad */
        unsigned char pad = plain[res - 1];
        if (pad > 0 && pad <= 16 && (DWORD)pad <= res)
            res -= pad;
    }
    *out_plain = plain;
    *out_plain_len = res;
    return 1;
}

static int decompress_lzma2_mem(const unsigned char *in_buf, size_t in_size,
                                unsigned char *out_buf, size_t out_size)
{
    enum xz_ret ret;
    struct xz_dec *s;
    struct xz_buf b;

    xz_crc32_init();
    s = xz_dec_init(XZ_DYNALLOC, 256U << 20);
    if (!s)
        return 0;

    b.out = out_buf;
    b.out_pos = 0;
    b.out_size = out_size;
    b.in = in_buf;
    b.in_pos = 0;
    b.in_size = in_size;

    do {
        ret = xz_dec_run(s, &b);
    } while (ret == XZ_OK);

    xz_dec_end(s);
    return (ret == XZ_STREAM_END && b.out_pos == out_size);
}

/*
 * Read one appended blob, decrypt it, decompress it if needed and check the
 * CRC32 of the result. Returns a malloc'd buffer the caller must free.
 */
static unsigned char *load_blob(HANDLE f, ULONGLONG off, ULONGLONG stored,
                                ULONGLONG orig, unsigned mode, unsigned crc,
                                const unsigned char *mask,
                                const unsigned char *masked,
                                const unsigned char *iv,
                                size_t *out_len)
{
    unsigned char *cipher = NULL, *plain = NULL, *body = NULL;
    DWORD plain_len = 0;

    xz_crc32_init();
    if (stored == 0 || stored > 0xFFFFFFFFULL)
        return NULL;
    if (orig == 0 || orig > 0xFFFFFFFFULL)
        return NULL;
    if (mode != MODE_RAW && mode != MODE_LZMA2)
        return NULL;
    if (mode == MODE_LZMA2 && orig < stored)
        return NULL;

    cipher = (unsigned char *)malloc((size_t)stored);
    if (!cipher)
        return NULL;
    if (!read_at(f, off, cipher, (DWORD)stored)) {
        free(cipher);
        return NULL;
    }

#if PAYLOAD_ENCRYPTED
    if (!decrypt_payload(cipher, (DWORD)stored, mask, masked, iv,
                         &plain, &plain_len)) {
        free(cipher);
        return NULL;
    }
    free(cipher);
    cipher = NULL;
#else
    plain = cipher;
    plain_len = (DWORD)stored;
#endif

    if (mode == MODE_LZMA2) {
        body = (unsigned char *)malloc((size_t)orig);
        if (!body || !decompress_lzma2_mem(plain, plain_len, body,
                                           (size_t)orig)) {
            free(plain);
            free(body);
            return NULL;
        }
        free(plain);
        plain_len = (DWORD)orig;
    } else {
        body = plain;
        if (plain_len != orig) {
            free(body);
            return NULL;
        }
    }

    if (xz_crc32(body, (size_t)plain_len, 0) != crc) {
        sayf(L"blob CRC32 mismatch (want %08x)", crc);
        free(body);
        return NULL;
    }
    *out_len = (size_t)plain_len;
    return body;
}

/* ------------------------------------------------------------------ */
/*  runtime drop: stored ZIP straight into the temp folder              */
/* ------------------------------------------------------------------ */

static int extract_payload(const unsigned char *mem, size_t size,
                           const wchar_t *dest)
{
    size_t pos = 0;
    int files = 0;

    while (pos + 30 <= size) {
        const unsigned char *hdr = mem + pos;
        unsigned method, csize, usize, nlen, elen;
        size_t data;
        wchar_t name[512], target[1024], parent[1024];
        HANDLE out;
        int n_w, k;

        if (hdr[0] != 'P' || hdr[1] != 'K' || hdr[2] != 3 || hdr[3] != 4)
            break;
        method = rd16(hdr + 8);
        csize = rd32(hdr + 18);
        usize = rd32(hdr + 22);
        nlen = rd16(hdr + 26);
        elen = rd16(hdr + 28);
        data = pos + 30 + nlen + elen;
        if (method != 0 || csize != usize || nlen == 0 || nlen >= 512 ||
            data + csize > size) {
            fail(L"corrupt runtime blob");
            return 0;
        }

        n_w = MultiByteToWideChar(CP_UTF8, 0, (const char *)(mem + pos + 30),
                                  (int)nlen, name, 511);
        if (n_w <= 0) {
            fail(L"bad entry name in runtime blob");
            return 0;
        }
        name[n_w] = L'\0';
        for (k = 0; k < n_w; k++)
            if (name[k] == L'/')
                name[k] = L'\\';
        if (wcsstr(name, L"..") != NULL) {
            fail(L"unsafe path in runtime blob");
            return 0;
        }
        if (_snwprintf_s(target, 1024, _TRUNCATE, L"%s\\%s", dest, name) < 0) {
            fail(L"path too long");
            return 0;
        }

        if (name[n_w - 1] == L'\\') {
            ensure_dirs(target);
        } else {
            size_t cut = wcslen(target);

            while (cut > 0 && target[cut - 1] != L'\\')
                cut--;
            if (cut > 0) {
                _snwprintf_s(parent, 1024, _TRUNCATE, L"%s", target);
                parent[cut - 1] = L'\0';
                ensure_dirs(parent);
            }
            out = CreateFileW(target, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
            if (out == INVALID_HANDLE_VALUE) {
                fail(L"cannot create dropped file");
                return 0;
            }
            if (csize > 0) {
                DWORD put = 0;
                if (!WriteFile(out, mem + data, (DWORD)csize, &put, NULL) ||
                    put != (DWORD)csize) {
                    CloseHandle(out);
                    fail(L"cannot write dropped file");
                    return 0;
                }
            }
            CloseHandle(out);
            files++;
        }
        pos = data + csize;
    }
    if (files == 0) {
        fail(L"no files unpacked from the runtime blob");
        return 0;
    }
    sayf(L"runtime dropped: %d file(s)", files);
    return files;
}

/* ------------------------------------------------------------------ */
/*  in-memory PE loader                                                */
/* ------------------------------------------------------------------ */

static DWORD section_prot(DWORD chars)
{
    int x = (chars & 0x20000000u) != 0;
    int w = (chars & 0x80000000u) != 0;
    int r = (chars & 0x40000000u) != 0;

    if (x) {
        if (w) return PAGE_EXECUTE_READWRITE;
        if (r) return PAGE_EXECUTE_READ;
        return PAGE_EXECUTE;
    }
    if (w) return PAGE_READWRITE;
    if (r) return PAGE_READONLY;
    return PAGE_NOACCESS;
}

/*
 * The dropped runtime sits next to the zombie, so absolute paths beat the
 * search order: a hijacked python314.dll earlier on PATH cannot win.
 */
static HMODULE load_payload_dll(const unsigned char *name8,
                                const wchar_t *self_dir)
{
    wchar_t wname[MAX_PATH], full[MAX_PATH];
    HMODULE h;

    if (MultiByteToWideChar(CP_UTF8, 0, (const char *)name8, -1, wname,
                            MAX_PATH) <= 0)
        return NULL;
    if (_snwprintf_s(full, MAX_PATH, _TRUNCATE, L"%s\\%s", self_dir,
                     wname) >= 0 &&
        GetFileAttributesW(full) != INVALID_FILE_ATTRIBUTES) {
        h = LoadLibraryExW(full, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (h)
            return h;
    }
    sayf(L"not in the dropped runtime, using the search path: %ls", wname);
    return LoadLibraryW(wname);
}

static int resolve_imports(unsigned char *base, const wchar_t *self_dir,
                           unsigned import_rva)
{
    unsigned char *d;

    if (!import_rva)
        return 1;
    d = base + import_rva;
    while (rd32(d + 12)) {
        const unsigned char *name = base + rd32(d + 12);
        unsigned oft = rd32(d);
        unsigned ft = rd32(d + 16);
        unsigned stamp = rd32(d + 4);
        HMODULE mod;
        ULONGLONG *thunk, *iat;

        if (!ft)
            return 0;
        if (!oft && stamp != 0) {
            /* Pre-bound IAT: the names are gone, entries already hold
             * addresses, so there is nothing to resolve. */
            sayf(L"pre-bound imports, skipped: %S", (const char *)name);
            d += 20;
            continue;
        }
        mod = load_payload_dll(name, self_dir);
        if (!mod) {
            sayf(L"LoadLibrary failed: %S", (const char *)name);
            return 0;
        }
        thunk = (ULONGLONG *)(base + (oft ? oft : ft));
        iat = (ULONGLONG *)(base + ft);
        {
            ULONGLONG *scan = thunk;
            unsigned count = 0;

            while (*scan++)
                count++;
            sayf(L"imports: %S (%u)", (const char *)name, count);
        }
        while (*thunk) {
            ULONGLONG v = *thunk;
            FARPROC fn;

            if (v & 0x8000000000000000ULL)
                fn = GetProcAddress(mod, (LPCSTR)(ULONG_PTR)(v & 0xFFFF));
            else
                fn = GetProcAddress(mod, (const char *)(base + (unsigned)v + 2));
            if (!fn) {
                sayf(L"GetProcAddress failed in %S", (const char *)name);
                return 0;
            }
            *iat++ = (ULONGLONG)fn;
            thunk++;
        }
        d += 20;
    }
    return 1;
}

static void apply_relocs(unsigned char *base, ULONGLONG delta,
                         unsigned reloc_rva, unsigned reloc_size)
{
    unsigned char *blk, *end;

    if (!reloc_rva || !reloc_size || !delta)
        return;
    blk = base + reloc_rva;
    end = blk + reloc_size;
    while (blk + 8 <= end) {
        unsigned page = rd32(blk);
        unsigned size = rd32(blk + 4);
        unsigned i, n;

        if (size < 8)
            break;
        n = (size - 8) / 2;
        for (i = 0; i < n; i++) {
            unsigned e = rd16(blk + 8 + i * 2);
            unsigned kind = e >> 12;
            unsigned off = e & 0xFFF;

            if (kind == 10) {  /* IMAGE_REL_BASED_DIR64 */
                ULONGLONG *p = (ULONGLONG *)(base + page + off);
                *p += delta;
            } else if (kind == 3) {  /* IMAGE_REL_BASED_HIGHLOW */
                DWORD *p = (DWORD *)(base + page + off);
                *p += (DWORD)delta;
            }
        }
        blk += size;
    }
}

/*
 * The loader never saw this image, so nothing registered its .pdata: any
 * SEH / C++ exception / stack walk crossing it would die with "function
 * unwind info not found". RUNTIME_FUNCTION holds RVAs, so when the image
 * could not be placed at its preferred base the entries are rebased first.
 *
 * ntdll refuses (and on some builds access-violates inside) tables it does
 * not like, so the call is guarded: losing the dynamic unwind table only
 * costs C++ exception propagation across this image, never the program.
 */
static int register_unwind(unsigned char *base, ULONGLONG delta,
                           unsigned sectab, unsigned nsec)
{
    unsigned char *pdata = NULL;
    unsigned pdata_len = 0;
    HMODULE ntdll;
    FARPROC fn;
    ULONG entry = 0;
    NTSTATUS st;
    unsigned i;

    for (i = 0; i < nsec; i++) {
        unsigned char *s = base + sectab + i * 40;
        if (memcmp(s, ".pdata", 6) == 0) {
            pdata = base + rd32(s + 12);
            pdata_len = rd32(s + 8);
            break;
        }
    }
    if (!pdata || pdata_len < 12)
        return 0;
    pdata_len = (pdata_len / 12) * 12;

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return 0;
    fn = GetProcAddress(ntdll, "RtlAddFunctionTable");
    if (!fn)
        return 0;

    if (delta) {
        ULONG n = pdata_len / 12, k;

        for (k = 0; k < n; k++) {
            DWORD *e = (DWORD *)(pdata + k * 12);
            e[0] = (DWORD)(e[0] + delta);
            e[1] = (DWORD)(e[1] + delta);
            e[2] = (DWORD)(e[2] + delta);
        }
        sayf(L"rebased %lu unwind entries (delta 0x%llx)",
             (unsigned long)n, (unsigned long long)delta);
    }

    __try {
        st = ((NTSTATUS (WINAPI *)(PVOID, ULONG, PULONG))(void *)fn)(pdata,
                                                                    pdata_len,
                                                                    &entry);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        sayf(L"warning: RtlAddFunctionTable faulted (0x%08lx); C++ exceptions "
             L"will not unwind through the program image",
             (DWORD)GetExceptionCode());
        return 0;
    }
    if (st < 0) {
        sayf(L"warning: RtlAddFunctionTable returned 0x%08lx", (DWORD)st);
        return 0;
    }
    return 1;
}

static int protect_sections(unsigned char *base, unsigned sectab,
                            unsigned nsec, unsigned size_of_image)
{
    unsigned i;

    for (i = 0; i < nsec; i++) {
        unsigned char *s = base + sectab + i * 40;
        DWORD vsize = rd32(s + 8);
        DWORD old = 0;

        if (vsize == 0)
            continue;
        if (!VirtualProtect(base + rd32(s + 12), vsize,
                            section_prot(rd32(s + 36)), &old)) {
            sayf(L"VirtualProtect failed: %lu", GetLastError());
            return 0;
        }
    }
    FlushInstructionCache(GetCurrentProcess(), base, size_of_image);
    return 1;
}

/* Maps the program PE in RAM and jumps into it. Returns its exit code. */
static int run_program(const unsigned char *pe, size_t pe_len,
                       int argc, wchar_t **argv)
{
    typedef int (WINAPI *entry_t)(int, wchar_t **);
    unsigned nt_off, opt, nsec, sectab, ep_rva, size_of_image,
             size_of_headers, import_rva, reloc_rva, reloc_size, tls_rva;
    ULONGLONG image_base, delta;
    unsigned char *base;
    entry_t entry;
    int rc;

    if (pe_len < 0x100 || rd16(pe) != 0x5A4D) {
        fail(L"program blob is not a PE");
        return 1;
    }
    nt_off = rd32(pe + 0x3C);
    if (nt_off < 0x40 || nt_off + 24 + 112 > pe_len ||
        rd32(pe + nt_off) != 0x4550 || rd16(pe + nt_off + 24) != 0x020B) {
        fail(L"program blob is not a 64-bit PE");
        return 1;
    }
    opt = nt_off + 24;
    ep_rva = rd32(pe + opt + 16);
    image_base = rd64(pe + opt + 24);
    size_of_image = rd32(pe + opt + 56);
    size_of_headers = rd32(pe + opt + 60);
    nsec = rd16(pe + nt_off + 6);
    sectab = nt_off + 24 + rd16(pe + nt_off + 20);
    import_rva = rd32(pe + opt + 112 + 1 * 8);
    reloc_rva = rd32(pe + opt + 112 + 5 * 8);
    reloc_size = rd32(pe + opt + 112 + 5 * 8 + 4);
    tls_rva = rd32(pe + opt + 112 + 9 * 8);

    if (!ep_rva || size_of_image < 0x1000 || size_of_image > MAX_IMAGE ||
        size_of_headers > pe_len || size_of_headers > size_of_image) {
        fail(L"program blob has a bogus image size");
        return 1;
    }
    if (sectab + nsec * 40 > pe_len || nsec == 0 || nsec > 96) {
        fail(L"program blob has a bogus section table");
        return 1;
    }
    if (tls_rva)
        sayf(L"warning: program uses static TLS, callbacks are not run");

    /* Prefer the preferred base: fewer relocations, cleaner .pdata. */
    base = (unsigned char *)VirtualAlloc((LPVOID)(ULONGLONG)image_base,
                                         size_of_image,
                                         MEM_RESERVE | MEM_COMMIT,
                                         PAGE_READWRITE);
    if (!base)
        base = (unsigned char *)VirtualAlloc(NULL, size_of_image,
                                             MEM_RESERVE | MEM_COMMIT,
                                             PAGE_READWRITE);
    if (!base) {
        fail(L"cannot allocate the program image");
        return 1;
    }
    g_image = base;

    memcpy(base, pe, size_of_headers);
    {
        unsigned i;

        for (i = 0; i < nsec; i++) {
            const unsigned char *s = pe + sectab + i * 40;
            unsigned raw = rd32(s + 16);
            unsigned rva = rd32(s + 12);

            if (raw == 0)
                continue;
            if (rva + raw > size_of_image || rd32(s + 20) + raw > pe_len) {
                fail(L"program blob has a bogus section");
                return 1;
            }
            memcpy(base + rva, pe + rd32(s + 20), raw);
        }
    }

    delta = (ULONGLONG)base - image_base;
    sayf(L"base 0x%p, image base 0x%llx, delta 0x%llx, %u section(s), "
         L"size 0x%x", (void *)base, (unsigned long long)image_base,
         (unsigned long long)delta, nsec, size_of_image);
    apply_relocs(base, delta, reloc_rva, reloc_size);

    {
        wchar_t self[MAX_PATH], self_dir[MAX_PATH];

        self_dir[0] = L'\0';
        if (GetModuleFileNameW(NULL, self, MAX_PATH) &&
            dir_of(self, self_dir, MAX_PATH)) {
            SetDllDirectoryW(self_dir);
        }
        if (!resolve_imports(base, self_dir, import_rva)) {
            fail(L"cannot resolve the program imports");
            return 1;
        }
    }

    if (!register_unwind(base, delta, sectab, nsec))
        sayf(L"warning: no unwind table registered for the program image");
    sayf(L"imports + unwind done");

    if (!protect_sections(base, sectab, nsec, size_of_image))
        sayf(L"warning: not every section could be protected");
    sayf(L"sections protected");

    /*
     * Anti-dump: SizeOfImage is what every memory dumper and
     * GetModuleInformation use to size an image, so blanking just this
     * field is enough to leave them with nothing. Nothing else is touched -
     * the DOS/NT headers, the section table and .pdata must stay valid for
     * the CRT, the x64 unwinder and CPython's own module bookkeeping.
     */
    if (antidump()) {
        *(DWORD *)(base + opt + 56) = 0;
        sayf(L"anti-dump: SizeOfImage -> 0 (headers and .pdata intact)");
    }

    sayf(L"program mapped at 0x%p (delta 0x%llx), EP rva 0x%x",
         (void *)base, (unsigned long long)delta, ep_rva);

    entry = (entry_t)(void *)(base + ep_rva);
    rc = entry(argc, argv);
    return rc;
}

/* ------------------------------------------------------------------ */
/*  roles                                                              */
/* ------------------------------------------------------------------ */

static BOOL WINAPI on_ctrl(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT) {
        if (g_child != 0)
            GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, g_child);
        return TRUE;
    }
    return FALSE;
}

/* Verbose-only crash locator: says which image the fault happened in. */
static LONG WINAPI on_exception(PEXCEPTION_POINTERS ep)
{
    BYTE *rip = (BYTE *)ep->ContextRecord->Rip;
    HMODULE mod = NULL;
    wchar_t path[MAX_PATH];
    int in_image = g_image && rip >= g_image && rip < g_image + MAX_IMAGE;

    path[0] = L'\0';
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)rip, &mod))
        GetModuleFileNameW(mod, path, MAX_PATH);
    sayf(L"exception 0x%08lx rip 0x%p in %s +0x%x%s",
         (DWORD)ep->ExceptionRecord->ExceptionCode, (void *)rip,
         path[0] ? path : L"?",
         mod ? (DWORD)(rip - (BYTE *)mod) : 0,
         in_image ? " (inside the program image)" : "");
    return EXCEPTION_CONTINUE_SEARCH;
}

/* CPYZMB1: drop the runtime, spawn the zombie, wait, clean up. */
static int role_droper(const wchar_t *self, int argc, wchar_t **argv)
{
    wchar_t tmpdir[1024], zombie[1024], cmdline[4096];
    unsigned char tail[TAIL_OUTER];
    unsigned char *runtime = NULL;
    ULONGLONG size, stored1, orig1, stored2, orig2, stub_size;
    unsigned mode1, mode2, crc1, crc2;
    size_t runtime_len = 0, cmd_len;
    LARGE_INTEGER zero;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    HANDLE f, out;
    DWORD code = 1;
    int i;

    f = CreateFileW(self, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        fail(L"cannot open own executable");
        return 1;
    }
    if (!GetFileSizeEx(f, (LARGE_INTEGER *)&size) || size < TAIL_OUTER ||
        !read_at(f, size - TAIL_OUTER, tail, TAIL_OUTER)) {
        fail(L"cannot read the zombie trailer");
        CloseHandle(f);
        return 1;
    }

    stored1 = rd64(tail + 8);
    orig1 = rd64(tail + 16);
    mode1 = rd32(tail + 24);
    crc1 = rd32(tail + 28);
    stored2 = rd64(tail + 32);
    orig2 = rd64(tail + 40);
    mode2 = rd32(tail + 48);
    crc2 = rd32(tail + 52);

    if (stored1 == 0 || stored2 == 0 || stored1 > size ||
        stored1 + stored2 + TAIL_OUTER > size || orig1 == 0 || orig2 == 0) {
        fail(L"corrupt zombie trailer");
        CloseHandle(f);
        return 1;
    }
    stub_size = size - TAIL_OUTER - stored1 - stored2;
    if (stub_size < 0x400) {
        fail(L"stub looks truncated");
        CloseHandle(f);
        return 1;
    }

    sayf(L"stub %llu bytes, runtime blob %llu (mode %u), program blob %llu "
         L"(mode %u)",
         (unsigned long long)stub_size, (unsigned long long)stored1, mode1,
         (unsigned long long)stored2, mode2);

    runtime = load_blob(f, stub_size, stored1, orig1, mode1, crc1,
                        K1_MASK, K1_MASKED, K1_IV, &runtime_len);
    if (!runtime) {
        fail(L"cannot unpack the runtime blob");
        CloseHandle(f);
        return 1;
    }

    if (!make_temp_dir(TEMP_PREFIX, tmpdir, 1024)) {
        fail(L"cannot create a temp folder");
        free(runtime);
        CloseHandle(f);
        return 1;
    }
    sayf(L"temp folder: %s", tmpdir);
    if (!extract_payload(runtime, runtime_len, tmpdir)) {
        cleanup(tmpdir);
        free(runtime);
        CloseHandle(f);
        return 1;
    }
    free(runtime);

    /*
     * The zombie: our own stub bytes, then the program blob byte for byte
     * (still encrypted), then its own trailer. The dropped file holds the
     * loader and nothing else - no program header, no code, no import
     * table, nothing to disassemble.
     */
    if (_snwprintf_s(zombie, 1024, _TRUNCATE, L"%s\\%s", tmpdir,
                     CHILD_NAME) < 0) {
        fail(L"temp path too long");
        cleanup(tmpdir);
        CloseHandle(f);
        return 1;
    }
    out = CreateFileW(zombie, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                      FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE) {
        fail(L"cannot write the zombie");
        cleanup(tmpdir);
        CloseHandle(f);
        return 1;
    }
    zero.QuadPart = 0;
    SetFilePointerEx(out, zero, NULL, FILE_BEGIN);
    if (!copy_range(f, 0, stub_size, out) ||
        !copy_range(f, stub_size + stored1, stored2, out)) {
        fail(L"cannot copy the stub and the program blob into the zombie");
        CloseHandle(out);
        CloseHandle(f);
        cleanup(tmpdir);
        return 1;
    }
    {
        unsigned char ztail[TAIL_ZOMBIE];
        DWORD put = 0;

        memcpy(ztail, MAGIC_ZOMBIE, 8);
        memcpy(ztail + 8, tail + 32, TAIL_ZOMBIE - 8);
        if (!WriteFile(out, ztail, TAIL_ZOMBIE, &put, NULL) ||
            put != TAIL_ZOMBIE) {
            fail(L"cannot finish the zombie");
            CloseHandle(out);
            CloseHandle(f);
            cleanup(tmpdir);
            return 1;
        }
    }
    CloseHandle(out);
    CloseHandle(f);
    sayf(L"zombie written: %s", zombie);

    /* argv[0] is the shipped EXE, so the program never sees the temp path. */
    if (_snwprintf_s(cmdline, 4096, _TRUNCATE, L"\"%s\"", self) < 0) {
        fail(L"command line too long");
        cleanup(tmpdir);
        return 1;
    }
    cmd_len = wcslen(cmdline);
    for (i = 1; i < argc; i++) {
        wc_append(cmdline, 4096, &cmd_len, L" ");
        wc_append(cmdline, 4096, &cmd_len, argv[i]);
    }

    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    memset(&pi, 0, sizeof pi);
    if (!CreateProcessW(zombie, cmdline, NULL, NULL, FALSE,
                        CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si, &pi)) {
        fail(L"cannot start the zombie");
        cleanup(tmpdir);
        return 1;
    }
    g_child = pi.dwProcessId;
    SetConsoleCtrlHandler(on_ctrl, TRUE);
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (keep_temp(argc, argv))
        sayf(L"temp folder kept (--cpythonizer-keep)");
    else
        cleanup(tmpdir);
    return (int)code;
}

/* CPYZMB2: we are the zombie in %TEMP% - map and run the program. */
static int role_zombie(const wchar_t *self, int argc, wchar_t **argv)
{
    unsigned char tail[TAIL_ZOMBIE];
    unsigned char *program = NULL;
    ULONGLONG size, stored2, orig2, blob_off;
    unsigned mode2, crc2;
    size_t program_len = 0;
    HANDLE f;
    int rc;

    f = CreateFileW(self, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        fail(L"cannot open the zombie");
        return 1;
    }
    if (!GetFileSizeEx(f, (LARGE_INTEGER *)&size) || size < TAIL_ZOMBIE ||
        !read_at(f, size - TAIL_ZOMBIE, tail, TAIL_ZOMBIE)) {
        fail(L"cannot read the zombie trailer");
        CloseHandle(f);
        return 1;
    }
    stored2 = rd64(tail + 8);
    orig2 = rd64(tail + 16);
    mode2 = rd32(tail + 24);
    crc2 = rd32(tail + 28);
    if (stored2 == 0 || stored2 + TAIL_ZOMBIE > size) {
        fail(L"corrupt zombie trailer");
        CloseHandle(f);
        return 1;
    }
    blob_off = size - TAIL_ZOMBIE - stored2;

    SetEnvironmentVariableW(L"CPYTHONIZER_TEMP", self);
    SetEnvironmentVariableW(L"_MEIPASS", self);

    program = load_blob(f, blob_off, stored2, orig2, mode2, crc2,
                        K2_MASK, K2_MASKED, K2_IV, &program_len);
    CloseHandle(f);
    if (!program) {
        fail(L"cannot unpack the program blob");
        return 1;
    }
    sayf(L"program blob ready: %lu bytes", (unsigned long)program_len);
    if (verbose())
        AddVectoredExceptionHandler(1,
                                    (PVECTORED_EXCEPTION_HANDLER)on_exception);

    /*
     * argv[0] stays whatever the droper forwarded, i.e. the shipped EXE:
     * sys.argv[0] and sys.executable keep pointing at the distributed file
     * while CPython finds python314.zip relative to the process image, which
     * is this zombie inside %TEMP%.
     */
    rc = run_program(program, program_len, argc, argv);
    free(program);
    return rc;
}

/* ------------------------------------------------------------------ */

int wmain(int argc, wchar_t **argv)
{
    wchar_t self[MAX_PATH];
    unsigned char tail[TAIL_OUTER];
    ULONGLONG size;
    HANDLE f;

    if (GetModuleFileNameW(NULL, self, MAX_PATH) == 0) {
        fail(L"cannot resolve own path");
        return 1;
    }
    f = CreateFileW(self, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        fail(L"cannot open own executable");
        return 1;
    }
    if (!GetFileSizeEx(f, (LARGE_INTEGER *)&size) || size < TAIL_OUTER ||
        !read_at(f, size - TAIL_OUTER, tail, TAIL_OUTER)) {
        fail(L"cannot read own trailer");
        CloseHandle(f);
        return 1;
    }

    if (memcmp(tail, MAGIC_OUTER, 8) == 0) {
        CloseHandle(f);
        return role_droper(self, argc, argv);
    }
    if (size >= TAIL_ZOMBIE &&
        memcmp(tail + (TAIL_OUTER - TAIL_ZOMBIE), MAGIC_ZOMBIE, 8) == 0) {
        CloseHandle(f);
        return role_zombie(self, argc, argv);
    }
    CloseHandle(f);
    fail(L"not a cpythonizer zombie executable");
    return 1;
}
""")


def _bytes_list(data: bytes | None) -> str:
    return ", ".join(f"0x{b:02x}" for b in data) if data else "0"


def _new_keys() -> tuple[bytes, bytes, bytes, bytes]:
    """Per-build random AES-256 key, key mask, masked key and IV."""
    key = os.urandom(32)
    mask = os.urandom(32)
    return key, mask, bytes(k ^ m for k, m in zip(key, mask)), os.urandom(16)


def write_stub_c(work: Path, app_name: str, k1: tuple, k2: tuple,
                 encrypt: bool, antidump: bool) -> Path:
    """Emit the zombie stub source with its per-build key material."""
    src = STUB_C.substitute(
        CHILD_NAME=f"{app_name}.exe",
        TEMP_PREFIX=app_name,
        ANTIDUMP="1" if antidump else "0",
        PAYLOAD_ENCRYPTED="1" if encrypt else "0",
        K1_MASK=_bytes_list(k1[1]),
        K1_MASKED=_bytes_list(k1[2]),
        K1_IV=_bytes_list(k1[3]),
        K2_MASK=_bytes_list(k2[1]),
        K2_MASKED=_bytes_list(k2[2]),
        K2_IV=_bytes_list(k2[3]),
    )
    path = work / f"{app_name}_zombie.c"
    path.write_text(src, encoding="utf-8")
    return path


def build_stub(work: Path, app_name: str, out_dir: Path, release, msbuild: Path,
               c_file: Path, rc_file: Path | None = None,
               release_mode: bool = False, noconsole: bool = False,
               keep_pdb: bool = False) -> tuple[Path, Path | None]:
    """Compile the stub. Returns (stub_exe, stub_pdb | None)."""
    from .onefile import STUB_VCXPROJ_TEMPLATE

    guid = str(uuid.uuid4()).upper()
    name = f"{app_name}_zombie_stub"
    resource_item = f'    <ResourceCompile Include="{rc_file.name}" />' if rc_file else ""
    subsystem = "Windows" if noconsole else "Console"
    generate_debug = "true" if (keep_pdb or not release_mode) else "false"
    debug_format = "ProgramDatabase" if (keep_pdb or not release_mode) else "None"
    xz_dir = (Path(__file__).parent / "xz").resolve()
    proj = STUB_VCXPROJ_TEMPLATE.format(
        GUID="{" + guid + "}",
        NAME=name,
        PROJECT_VERSION=release.project_version,
        TOOLSET=release.toolset,
        OUTDIR=str(out_dir),
        INTDIR=str(work / "obj_zombie"),
        CFILE=str(c_file),
        XZ_DIR=str(xz_dir),
        RESOURCE_ITEM=resource_item,
        SUBSYSTEM=subsystem,
        DEF_SUBSYSTEM="_WINDOWS" if noconsole else "_CONSOLE",
        GENERATE_DEBUG=generate_debug,
        DEBUG_FORMAT=debug_format,
    )
    (work / f"{name}.vcxproj").write_text(proj, encoding="utf-8")
    proj_block = f'Project("{{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}}") = "{name}", "{name}.vcxproj", "{{{{{guid}}}}}"\nEndProject'
    config_block = f'\t\t{{{{{guid}}}}}.Release|x64.ActiveCfg = Release|x64\n\t\t{{{{{guid}}}}}.Release|x64.Build.0 = Release|x64'
    sln = work / f"{name}.sln"
    sln.write_text(
        SLN_TEMPLATE.format(
            SLN_MAJOR=release.major,
            PROJECTS=proj_block,
            CONFIGS=config_block,
        ),
        encoding="utf-8",
    )
    print(f"[cpythonizer] Building zombie stub ({release.label}, {subsystem}): {c_file}")
    build_sln(msbuild, sln)
    exe = out_dir / f"{name}.exe"
    if not exe.is_file():
        raise RuntimeError(f"Zombie stub build finished but EXE missing: {exe}")
    pdb = out_dir / f"{name}.pdb"
    emit_debug = keep_pdb or not release_mode
    return exe, pdb if pdb.is_file() and emit_debug else None


def _compress(data: bytes, compress: str, lzma_preset: int,
              lzma_extreme: bool) -> tuple[bytes, int, int]:
    """Returns (stored_bytes, original_size, mode)."""
    if compress != "lzma2":
        return data, len(data), MODE_RAW
    import lzma

    flags = lzma.PRESET_EXTREME if lzma_extreme else 0
    packed = lzma.compress(
        data,
        preset=lzma_preset | flags,
        format=lzma.FORMAT_XZ,
        check=lzma.CHECK_CRC32,
    )
    return packed, len(data), MODE_LZMA2


def _runtime_files(stage: Path, app_name: str):
    """Every staged file the program needs - never the program itself."""
    program = stage / f"{app_name}.exe"
    for src in sorted(stage.rglob("*")):
        if not src.is_file() or src == program:
            continue
        if src.suffix.lower() in SKIP_SUFFIXES:
            continue
        yield src


def make_runtime_blob(stage: Path, app_name: str, out: Path, key: bytes,
                      iv: bytes, compress: str = "none", lzma_preset: int = 9,
                      lzma_extreme: bool = True,
                      encrypt: bool = True) -> tuple[int, int, int, int, int]:
    """Zip the runtime - the DLLs, the .pyd modules, python314.zip.

    These stay real files on disk because the loader and CPython resolve them
    by path; only the program EXE is kept out of the payload.

    Returns (files, stored_size, original_size, mode, crc32).
    """
    from .onefile import aes_encrypt

    raw_zip = out.with_name(out.name + ".raw.zip")
    raw_zip.parent.mkdir(parents=True, exist_ok=True)
    raw_zip.unlink(missing_ok=True)
    files = 0
    with zipfile.ZipFile(raw_zip, "w", zipfile.ZIP_STORED, allowZip64=True) as zf:
        for src in _runtime_files(stage, app_name):
            zf.write(src, src.relative_to(stage).as_posix())
            files += 1
    if files == 0:
        raise RuntimeError(f"No runtime files staged next to {stage / f'{app_name}.exe'}")

    raw_bytes = raw_zip.read_bytes()
    raw_zip.unlink(missing_ok=True)

    stored, uncomp, mode = _compress(raw_bytes, compress, lzma_preset, lzma_extreme)
    crc = zlib.crc32(raw_bytes) & 0xFFFFFFFF
    out.write_bytes(aes_encrypt(key, iv, stored) if encrypt else stored)
    return files, out.stat().st_size, uncomp, mode, crc


def make_program_blob(program: Path, out: Path, key: bytes, iv: bytes,
                      compress: str = "none", lzma_preset: int = 9,
                      lzma_extreme: bool = True,
                      encrypt: bool = True) -> tuple[int, int, int, int]:
    """Encrypt/compress the program PE. Returns (stored, orig, mode, crc)."""
    from .onefile import aes_encrypt

    raw = program.read_bytes()
    stored, uncomp, mode = _compress(raw, compress, lzma_preset, lzma_extreme)
    crc = zlib.crc32(raw) & 0xFFFFFFFF
    out.write_bytes(aes_encrypt(key, iv, stored) if encrypt else stored)
    return out.stat().st_size, uncomp, mode, crc


def pack(stub_exe: Path, runtime_blob: Path, program_blob: Path, out: Path,
         runtime_orig: int, runtime_mode: int, runtime_crc: int,
         program_orig: int, program_mode: int, program_crc: int) -> Path:
    """stub + runtime blob + program blob + trailer -> the zombie EXE."""
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    with open(tmp, "wb") as dst:
        for part in (stub_exe, runtime_blob, program_blob):
            with open(part, "rb") as src:
                shutil.copyfileobj(src, dst, COPY_CHUNK)
        dst.write(MAGIC_OUTER)
        dst.write(runtime_blob.stat().st_size.to_bytes(8, "little"))
        dst.write(runtime_orig.to_bytes(8, "little"))
        dst.write(runtime_mode.to_bytes(4, "little"))
        dst.write(runtime_crc.to_bytes(4, "little"))
        dst.write(program_blob.stat().st_size.to_bytes(8, "little"))
        dst.write(program_orig.to_bytes(8, "little"))
        dst.write(program_mode.to_bytes(4, "little"))
        dst.write(program_crc.to_bytes(4, "little"))
    tmp.replace(out)
    return out


def verify(exe: Path) -> bool:
    """Sanity check: the trailer must describe both blobs inside this file."""
    try:
        size = exe.stat().st_size
        with open(exe, "rb") as fh:
            fh.seek(size - TAIL_OUTER)
            tail = fh.read(TAIL_OUTER)
    except OSError:
        return False
    if len(tail) != TAIL_OUTER or tail[:8] != MAGIC_OUTER:
        return False
    stored1 = int.from_bytes(tail[8:16], "little")
    orig1 = int.from_bytes(tail[16:24], "little")
    stored2 = int.from_bytes(tail[32:40], "little")
    orig2 = int.from_bytes(tail[40:48], "little")
    if not (stored1 and orig1 and stored2 and orig2):
        return False
    return stored1 + stored2 + TAIL_OUTER <= size


def assemble(stage: Path, app_name: str, work: Path, msbuild: Path, release,
             out_exe: Path, icon: Path | None = None,
             release_mode: bool = False, noconsole: bool = False,
             keep_pdb: bool = False, compress: str = "none",
             lzma_preset: int = 9, lzma_extreme: bool = True,
             encrypt: bool = True, antidump: bool = True) -> Path:
    """Fold the runtime into %TEMP% and keep the program in memory only."""
    program = stage / f"{app_name}.exe"
    if not program.is_file():
        raise FileNotFoundError(f"Staged program missing: {program}")

    stub_dir = work / "zombie"
    if stub_dir.exists():
        shutil.rmtree(stub_dir, ignore_errors=True)
    stub_dir.mkdir(parents=True, exist_ok=True)

    stub_rc = None
    if icon is not None and Path(icon).is_file():
        stub_rc = work / f"{app_name}_zombie_stub.rc"
        stub_rc.write_text(f'1 ICON "{Path(icon).name}"\n', encoding="utf-8")

    k1 = _new_keys() if encrypt else (b"", b"", b"", b"")
    k2 = _new_keys() if encrypt else (b"", b"", b"", b"", b"")
    c_file = write_stub_c(
        work, app_name, k1, k2, encrypt=encrypt, antidump=antidump,
    )
    stub_exe, stub_pdb = build_stub(
        work, app_name, stub_dir, release, msbuild, c_file,
        rc_file=stub_rc, release_mode=release_mode, noconsole=noconsole,
        keep_pdb=keep_pdb,
    )

    runtime_blob = work / ("runtime.enc" if encrypt else "runtime.bin")
    program_blob = work / ("program.enc" if encrypt else "program.bin")

    r_files, r_stored, r_orig, r_mode, r_crc = make_runtime_blob(
        stage, app_name, runtime_blob, key=k1[0], iv=k1[3], compress=compress,
        lzma_preset=lzma_preset, lzma_extreme=lzma_extreme, encrypt=encrypt,
    )
    p_stored, p_orig, p_mode, p_crc = make_program_blob(
        program, program_blob, key=k2[0], iv=k2[3], compress=compress,
        lzma_preset=lzma_preset, lzma_extreme=lzma_extreme, encrypt=encrypt,
    )

    exe = pack(stub_exe, runtime_blob, program_blob, out_exe,
               runtime_orig=r_orig, runtime_mode=r_mode, runtime_crc=r_crc,
               program_orig=p_orig, program_mode=p_mode, program_crc=p_crc)
    if not verify(exe):
        raise RuntimeError(f"Packed zombie EXE failed its trailer check: {exe}")
    if stub_pdb is not None and (keep_pdb or not release_mode):
        shutil.copy2(stub_pdb, out_exe.with_name(f"{app_name}-zombie.pdb"))

    print(f"[cpythonizer] ZOMBIE DONE ({release.label}"
          f"{', AES-256' if encrypt else ''}"
          f"{', LZMA2' if compress == 'lzma2' else ''}"
          f"{', anti-dump' if antidump else ''}):\n"
          f"  EXE: {exe} ({exe.stat().st_size // (1 << 20)} MB, runs alone)\n"
          f"  runtime blob {r_stored // (1 << 10)} KB / {r_files} file(s) -> "
          f"%TEMP%\\<app>-<random>\\ on start\n"
          f"  program {p_orig // (1 << 10)} KB is NEVER written to disk; the "
          f"dropped {app_name}.exe is an empty shell\n"
          f"  argv[0] / sys.executable = the shipped EXE; anti-dump = "
          f"{'SizeOfImage only' if antidump else 'off'}")
    return exe
