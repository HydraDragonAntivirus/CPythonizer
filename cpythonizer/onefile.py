"""Onefile mode: ship the Cython --embed build as a single self-extracting EXE.

Layout of the produced EXE:

    [ stub.exe bytes ][ payload ZIP ][ 16 byte trailer ]

The trailer is ``b"CPYONE1\\0"`` + a little-endian uint64 payload size, so the
stub can find its own payload without a resource section.

The stub (stub.c below) has no Python dependency at all. At startup it

  1. creates a randomly named folder under %TEMP% (``Hello-3F2A91C4``),
  2. unpacks the payload into it (stored/uncompressed entries, so no
     decompressor is needed in the stub),
  3. runs the real program from there under its ORIGINAL name, forwarding
     the original command line, so Task Manager / Process Explorer show
     ``Hello.exe`` and never the temp path,
  4. deletes the folder again once the program has exited, and propagates its
     exit code.

The program itself is the ordinary Cython --embed + MSVC build, so nothing
about the produced binary changes apart from its location.
"""
from __future__ import annotations

import shutil
import string
import uuid
import zipfile
from pathlib import Path

from .cython_vs import SLN_TEMPLATE, build_sln

MAGIC_RAW = b"CPYONE1\0"
MAGIC_LZMA = b"CPYLZM2\0"
TRAILER_SIZE = 24
COPY_CHUNK = 1 << 20

# Debug switches, read by the stub at runtime:
#   CPYTHONIZER_ONEFILE_VERBOSE=1  print the temp folder to stderr
#   CPYTHONIZER_ONEFILE_KEEP=1     leave the temp folder behind (or pass
#                                  --cpythonizer-keep to the onefile exe)

STUB_C = string.Template(r"""/*
 * CPythonizer onefile stub - generated, do not edit.
 *
 * Dependency-free launcher around a Cython --embed + MSVC build. The payload
 * (the program, python314.dll, python314.zip and the extension modules) is
 * appended to this EXE as an AES-256 encrypted stored or LZMA2-compressed ZIP;
 * at startup it is decrypted in memory, decompressed, unpacked into a random
 * folder under %TEMP% and executed from there.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#ifndef XZ_USE_CRC32
#define XZ_USE_CRC32
#endif
#include "xz.h"

#define PAYLOAD_MAGIC_RAW  "CPYONE1"
#define PAYLOAD_MAGIC_LZMA "CPYLZM2"
#define TRAILER_SIZE       24
#define MAX_ATTEMPTS       32

/* Injected by the build. */
#define CHILD_NAME   L"$CHILD_NAME"     /* program inside the payload   */
#define TEMP_PREFIX  L"$TEMP_PREFIX"    /* random folder name prefix   */

/* Per-build random encryption keys (AES-256-CBC) with key masking */
static const unsigned char ENC_KEY_MASK[32]   = { $KEY_MASK };
static const unsigned char ENC_KEY_MASKED[32] = { $KEY_MASKED };
static const unsigned char ENC_IV[16]         = { $ENC_IV };

static volatile DWORD g_child = 0;
static int g_verbose = -1;

static int verbose(void)
{
    if (g_verbose < 0) {
        wchar_t v[8];
        v[0] = L'\0';
        g_verbose = (GetEnvironmentVariableW(L"CPYTHONIZER_ONEFILE_VERBOSE",
                                             v, 8) > 0 && v[0] != L'0');
    }
    return g_verbose;
}

static void say(const wchar_t *msg)
{
    if (verbose()) {
        fwprintf(stderr, L"[cpythonizer] %s\n", msg);
        fflush(stderr);
    }
}

static void fail(const wchar_t *msg)
{
    fwprintf(stderr, L"[cpythonizer] onefile: %s\n", msg);
    fflush(stderr);
}

static unsigned rd16(const unsigned char *p)
{
    return (unsigned)p[0] | ((unsigned)p[1] << 8);
}

static unsigned rd32(const unsigned char *p)
{
    return (unsigned)p[0] | ((unsigned)p[1] << 8) |
           ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
}

static int read_at(HANDLE f, ULONGLONG off, void *buf, DWORD len)
{
    LARGE_INTEGER li;
    DWORD total_got = 0;
    unsigned char *p = (unsigned char *)buf;

    li.QuadPart = (LONGLONG)off;
    if (!SetFilePointerEx(f, li, NULL, FILE_BEGIN))
        return 0;
    while (total_got < len) {
        DWORD got = 0;
        DWORD want = len - total_got;
        if (!ReadFile(f, p + total_got, want, &got, NULL) || got == 0)
            return 0;
        total_got += got;
    }
    return 1;
}

static void wc_append(wchar_t *buf, size_t cap, size_t *len, const wchar_t *s)
{
    while (*s && *len + 1 < cap)
        buf[(*len)++] = *s++;
    buf[*len] = L'\0';
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

/* Decrypt payload in-memory using hardware-accelerated AES-256-CBC via BCrypt */
static int decrypt_payload(const unsigned char *cipher, DWORD cipher_len,
                           unsigned char **out_plain, DWORD *out_plain_len)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD res = 0;
    unsigned char iv_copy[16];
    unsigned char key[32];
    int i;

    for (i = 0; i < 32; i++) {
        key[i] = ENC_KEY_MASK[i] ^ ENC_KEY_MASKED[i];
    }
    memcpy(iv_copy, ENC_IV, 16);

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) {
        SecureZeroMemory(key, sizeof(key));
        return 0;
    }
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
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

    unsigned char *plain = (unsigned char *)malloc(cipher_len);
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

    /* PKCS#7 unpad */
    if (res > 0) {
        unsigned char pad = plain[res - 1];
        if (pad > 0 && pad <= 16 && (DWORD)pad <= res) {
            res -= pad;
        }
    }
    *out_plain = plain;
    *out_plain_len = res;
    return 1;
}

/* In-memory LZMA2 decompressor */
static int decompress_lzma2_mem(const unsigned char *in_buf, size_t in_size,
                                unsigned char *out_buf, size_t out_size)
{
    xz_crc32_init();
    struct xz_dec *s = xz_dec_init(XZ_DYNALLOC, 256U << 20);
    if (!s) return 0;

    struct xz_buf b;
    b.out = out_buf;
    b.out_pos = 0;
    b.out_size = out_size;
    b.in = in_buf;
    b.in_pos = 0;
    b.in_size = in_size;

    enum xz_ret ret;
    do {
        ret = xz_dec_run(s, &b);
    } while (ret == XZ_OK);

    xz_dec_end(s);
    return (ret == XZ_STREAM_END && b.out_pos == out_size);
}

/* Unpack in-memory ZIP payload directly to dest */
static int extract_payload(const unsigned char *mem, size_t size, const wchar_t *dest)
{
    size_t pos = 0;
    int files = 0;

    while (pos + 30 <= size) {
        const unsigned char *hdr = mem + pos;
        if (hdr[0] != 'P' || hdr[1] != 'K' || hdr[2] != 3 || hdr[3] != 4)
            break;
        unsigned method = rd16(hdr + 8);
        unsigned csize = rd32(hdr + 18);
        unsigned usize = rd32(hdr + 22);
        unsigned nlen = rd16(hdr + 26);
        unsigned elen = rd16(hdr + 28);
        size_t data = pos + 30 + nlen + elen;
        if (method != 0 || csize != usize || nlen == 0 || nlen >= 512 ||
            data + csize > size) {
            fail(L"corrupt payload");
            return 0;
        }

        wchar_t name[512], target[1024], parent[1024];
        int n_w = MultiByteToWideChar(CP_UTF8, 0, (const char *)(mem + pos + 30),
                                      (int)nlen, name, 511);
        if (n_w <= 0) {
            fail(L"bad entry name");
            return 0;
        }
        name[n_w] = L'\0';
        for (int k = 0; k < n_w; k++) {
            if (name[k] == L'/')
                name[k] = L'\\';
        }
        if (wcsstr(name, L"..") != NULL) {
            fail(L"unsafe path in payload");
            return 0;
        }
        if (_snwprintf_s(target, 1024, _TRUNCATE, L"%s\\%s", dest, name) < 0) {
            fail(L"path too long");
            return 0;
        }

        if (name[n_w - 1] == L'\\') {
            ensure_dirs(target);
        } else {
            HANDLE out;
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
                fail(L"cannot create extracted file");
                return 0;
            }
            if (csize > 0) {
                DWORD put = 0;
                if (!WriteFile(out, mem + data, (DWORD)csize, &put, NULL) || put != (DWORD)csize) {
                    CloseHandle(out);
                    fail(L"cannot write extracted file");
                    return 0;
                }
            }
            CloseHandle(out);
            files++;
        }
        pos = data + csize;
    }
    if (files == 0) {
        fail(L"no files unpacked from payload");
        return 0;
    }
    return files;
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

static BOOL WINAPI on_ctrl(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT) {
        if (g_child != 0)
            GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, g_child);
        return TRUE;
    }
    return FALSE;
}

static int keep_temp(int argc, wchar_t **argv)
{
    wchar_t v[8];
    int i;

    v[0] = L'\0';
    if (GetEnvironmentVariableW(L"CPYTHONIZER_ONEFILE_KEEP", v, 8) > 0 &&
        v[0] != L'0')
        return 1;
    for (i = 1; i < argc; i++)
        if (!wcscmp(argv[i], L"--cpythonizer-keep"))
            return 1;
    return 0;
}

int wmain(int argc, wchar_t **argv)
{
    wchar_t self[MAX_PATH], tmpdir[1024], child[1024];
    wchar_t cmdline[4096];
    unsigned char trailer[TRAILER_SIZE];
    ULONGLONG size, payload = 0, start;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD code = 1;
    HANDLE self_file;
    size_t len = 0;
    int i;

    if (GetModuleFileNameW(NULL, self, MAX_PATH) == 0) {
        fail(L"cannot resolve own path");
        return 1;
    }
    self_file = CreateFileW(self, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (self_file == INVALID_HANDLE_VALUE) {
        fail(L"cannot open own executable");
        return 1;
    }
    if (!GetFileSizeEx(self_file, (LARGE_INTEGER *)&size) ||
        size < TRAILER_SIZE ||
        !read_at(self_file, size - TRAILER_SIZE, trailer, TRAILER_SIZE)) {
        fail(L"cannot read onefile trailer");
        CloseHandle(self_file);
        return 1;
    }
    int is_lzma = (memcmp(trailer, PAYLOAD_MAGIC_LZMA, 8) == 0);
    int is_raw = (memcmp(trailer, PAYLOAD_MAGIC_RAW, 8) == 0);
    if (!is_lzma && !is_raw) {
        fail(L"not a cpythonizer onefile executable");
        CloseHandle(self_file);
        return 1;
    }
    ULONGLONG uncomp = 0;
    for (i = 0; i < 8; i++)
        payload |= (ULONGLONG)trailer[8 + i] << (8 * i);
    for (i = 0; i < 8; i++)
        uncomp |= (ULONGLONG)trailer[16 + i] << (8 * i);
    if (payload == 0 || payload + TRAILER_SIZE > size || uncomp == 0) {
        fail(L"corrupt payload trailer");
        CloseHandle(self_file);
        return 1;
    }
    start = size - TRAILER_SIZE - payload;

    unsigned char *cipher_buf = (unsigned char *)malloc((size_t)payload);
    if (cipher_buf == NULL) {
        fail(L"out of memory for encrypted payload");
        CloseHandle(self_file);
        return 1;
    }
    if (!read_at(self_file, start, cipher_buf, (DWORD)payload)) {
        fail(L"cannot read encrypted payload");
        free(cipher_buf);
        CloseHandle(self_file);
        return 1;
    }
    CloseHandle(self_file);

    unsigned char *plain_buf = NULL;
    DWORD plain_len = 0;
    if (!decrypt_payload(cipher_buf, (DWORD)payload, &plain_buf, &plain_len)) {
        fail(L"payload decryption failed");
        free(cipher_buf);
        return 1;
    }
    free(cipher_buf);

    if (!make_temp_dir(TEMP_PREFIX, tmpdir, 1024)) {
        fail(L"cannot create a temp folder");
        free(plain_buf);
        return 1;
    }
    say(tmpdir);

    if (is_lzma) {
        unsigned char *zip_buf = (unsigned char *)malloc((size_t)uncomp);
        if (zip_buf == NULL) {
            fail(L"out of memory for decompression");
            free(plain_buf);
            cleanup(tmpdir);
            return 1;
        }
        if (!decompress_lzma2_mem(plain_buf, (size_t)plain_len, zip_buf, (size_t)uncomp)) {
            fail(L"LZMA2 decompression failed");
            free(plain_buf);
            free(zip_buf);
            cleanup(tmpdir);
            return 1;
        }
        free(plain_buf);
        if (!extract_payload(zip_buf, (size_t)uncomp, tmpdir)) {
            cleanup(tmpdir);
            free(zip_buf);
            return 1;
        }
        free(zip_buf);
    } else {
        if (!extract_payload(plain_buf, (size_t)plain_len, tmpdir)) {
            cleanup(tmpdir);
            free(plain_buf);
            return 1;
        }
        free(plain_buf);
    }

    if (_snwprintf_s(child, 1024, _TRUNCATE, L"%s\\%s", tmpdir, CHILD_NAME) < 0) {
        fail(L"temp path too long");
        cleanup(tmpdir);
        return 1;
    }
    if (GetFileAttributesW(child) == INVALID_FILE_ATTRIBUTES) {
        fail(L"payload does not contain the program");
        cleanup(tmpdir);
        return 1;
    }

    /* argv[0] is the original EXE, so the program never sees the temp path. */
    wc_append(cmdline, 4096, &len, L"\"");
    wc_append(cmdline, 4096, &len, self);
    wc_append(cmdline, 4096, &len, L"\"");
    for (i = 1; i < argc; i++) {
        wc_append(cmdline, 4096, &len, L" ");
        wc_append(cmdline, 4096, &len, argv[i]);
    }

    /* Pass temp folder via environment variables for PyInstaller compatibility. */
    SetEnvironmentVariableW(L"CPYTHONIZER_TEMP", tmpdir);
    SetEnvironmentVariableW(L"_MEIPASS", tmpdir);

    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    memset(&pi, 0, sizeof pi);
    if (!CreateProcessW(child, cmdline, NULL, NULL, FALSE,
                        CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si, &pi)) {
        fail(L"cannot start the program");
        cleanup(tmpdir);
        return 1;
    }
    g_child = pi.dwProcessId;
    SetConsoleCtrlHandler(on_ctrl, TRUE);
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (keep_temp(argc, argv)) {
        say(L"temp folder kept (--cpythonizer-keep)");
    } else {
        cleanup(tmpdir);
    }
    return (int)code;
}
""")


STUB_VCXPROJ_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Release|x64">
      <Configuration>Release</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
    <VCProjectVersion>{PROJECT_VERSION}</VCProjectVersion>
    <ProjectGuid>{GUID}</ProjectGuid>
    <RootNamespace>{NAME}</RootNamespace>
    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.Default.props" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'" Label="Configuration">
    <ConfigurationType>Application</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>{TOOLSET}</PlatformToolset>
    <WholeProgramOptimization>true</WholeProgramOptimization>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.props" />
  <ImportGroup Label="ExtensionSettings" />
  <ImportGroup Label="Shared" />
  <ImportGroup Label="PropertySheets" Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <Import Project="$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
  </ImportGroup>
  <PropertyGroup Label="UserMacros" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <OutDir>{OUTDIR}\\</OutDir>
    <IntDir>{INTDIR}\\</IntDir>
    <TargetName>{NAME}</TargetName>
    <GenerateDebugInformation>{GENERATE_DEBUG}</GenerateDebugInformation>
  </PropertyGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <ClCompile>
      <WarningLevel>Level3</WarningLevel>
      <Optimization>MaxSpeed</Optimization>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <PreprocessorDefinitions>NDEBUG;{DEF_SUBSYSTEM};XZ_USE_CRC32;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <AdditionalIncludeDirectories>{XZ_DIR};%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
      <CompileAs>CompileAsC</CompileAs>
      <DisableSpecificWarnings>4267;%(DisableSpecificWarnings)</DisableSpecificWarnings>
      <!-- Pure Win32 launcher: static CRT so the stub runs on a bare PC. -->
      <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
      <DebugInformationFormat>{DEBUG_FORMAT}</DebugInformationFormat>
    </ClCompile>
    <Link>
      <SubSystem>{SUBSYSTEM}</SubSystem>
      <GenerateDebugInformation>{GENERATE_DEBUG}</GenerateDebugInformation>
      <EnableCOMDATFolding>true</EnableCOMDATFolding>
      <OptimizeReferences>true</OptimizeReferences>
      <AdditionalDependencies>kernel32.lib;advapi32.lib;bcrypt.lib;%(AdditionalDependencies)</AdditionalDependencies>
      <EntryPointSymbol>wmainCRTStartup</EntryPointSymbol>
    </Link>
  </ItemDefinitionGroup>
  <ItemGroup>
    <ClCompile Include="{CFILE}" />
    <ClCompile Include="{XZ_DIR}\\xz_crc32.c" />
    <ClCompile Include="{XZ_DIR}\\xz_dec_lzma2.c" />
    <ClCompile Include="{XZ_DIR}\\xz_dec_stream.c" />
{RESOURCE_ITEM}
  </ItemGroup>
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.targets" />
  <ImportGroup Label="ExtensionTargets" />
</Project>
"""


def aes_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Encrypt data with AES-256-CBC and PKCS#7 padding using native Windows BCrypt."""
    import ctypes
    from ctypes import wintypes

    bcrypt = ctypes.windll.bcrypt

    h_alg = wintypes.HANDLE()
    status = bcrypt.BCryptOpenAlgorithmProvider(
        ctypes.byref(h_alg),
        ctypes.c_wchar_p("AES"),
        None,
        0,
    )
    if status != 0:
        raise RuntimeError(f"BCryptOpenAlgorithmProvider failed: {status:#x}")

    try:
        mode = "ChainingModeCBC".encode("utf-16le") + b"\x00\x00"
        status = bcrypt.BCryptSetProperty(
            h_alg,
            ctypes.c_wchar_p("ChainingMode"),
            mode,
            len(mode),
            0,
        )
        if status != 0:
            raise RuntimeError(f"BCryptSetProperty failed: {status:#x}")

        h_key = wintypes.HANDLE()
        status = bcrypt.BCryptGenerateSymmetricKey(
            h_alg,
            ctypes.byref(h_key),
            None,
            0,
            key,
            len(key),
            0,
        )
        if status != 0:
            raise RuntimeError(f"BCryptGenerateSymmetricKey failed: {status:#x}")

        try:
            pad_len = 16 - (len(data) % 16)
            padded_data = data + bytes([pad_len] * pad_len)

            out_len = wintypes.ULONG(0)
            iv_copy = bytearray(iv)
            status = bcrypt.BCryptEncrypt(
                h_key,
                padded_data,
                len(padded_data),
                None,
                (ctypes.c_ubyte * len(iv_copy)).from_buffer(iv_copy),
                len(iv_copy),
                None,
                0,
                ctypes.byref(out_len),
                0,
            )
            if status != 0:
                raise RuntimeError(f"BCryptEncrypt query failed: {status:#x}")

            out_buf = (ctypes.c_ubyte * out_len.value)()
            iv_copy2 = bytearray(iv)
            cb_result = wintypes.ULONG(0)
            status = bcrypt.BCryptEncrypt(
                h_key,
                padded_data,
                len(padded_data),
                None,
                (ctypes.c_ubyte * len(iv_copy2)).from_buffer(iv_copy2),
                len(iv_copy2),
                out_buf,
                len(out_buf),
                ctypes.byref(cb_result),
                0,
            )
            if status != 0:
                raise RuntimeError(f"BCryptEncrypt failed: {status:#x}")

            return bytes(out_buf[:cb_result.value])
        finally:
            bcrypt.BCryptDestroyKey(h_key)
    finally:
        bcrypt.BCryptCloseAlgorithmProvider(h_alg, 0)


def write_stub_c(work: Path, app_name: str, mask: bytes, masked_key: bytes, iv: bytes) -> Path:
    """Emit stub.c with per-build random AES keys and program name baked in."""
    key_mask_str = ", ".join(f"0x{b:02x}" for b in mask)
    masked_key_str = ", ".join(f"0x{b:02x}" for b in masked_key)
    iv_str = ", ".join(f"0x{b:02x}" for b in iv)

    src = STUB_C.substitute(
        CHILD_NAME=f"{app_name}.exe",
        TEMP_PREFIX=app_name,
        KEY_MASK=key_mask_str,
        KEY_MASKED=masked_key_str,
        ENC_IV=iv_str,
    )
    path = work / f"{app_name}_stub.c"
    path.write_text(src, encoding="utf-8")
    return path


def build_stub(work: Path, app_name: str, out_dir: Path, release,
               msbuild: Path, mask: bytes, masked_key: bytes, iv: bytes,
               rc_file: Path | None = None,
               release_mode: bool = False, noconsole: bool = False,
               keep_pdb: bool = False) -> tuple[Path, Path | None]:
    """Compile the stub. Returns (stub_exe, stub_pdb)."""
    guid = str(uuid.uuid4()).upper()
    c_file = write_stub_c(work, app_name, mask=mask, masked_key=masked_key, iv=iv)
    name = f"{app_name}_stub"
    resource_item = f'    <ResourceCompile Include="{rc_file.name}" />' if rc_file else ""
    subsystem = "Windows" if noconsole else "Console"
    def_subsystem = "_WINDOWS" if noconsole else "_CONSOLE"
    generate_debug = "true" if (keep_pdb or not release_mode) else "false"
    debug_format = "ProgramDatabase" if (keep_pdb or not release_mode) else "None"
    xz_dir = (Path(__file__).parent / "xz").resolve()
    proj = STUB_VCXPROJ_TEMPLATE.format(
        GUID="{" + guid + "}",
        NAME=name,
        PROJECT_VERSION=release.project_version,
        TOOLSET=release.toolset,
        OUTDIR=str(out_dir),
        INTDIR=str(work / "obj_stub"),
        CFILE=str(c_file),
        XZ_DIR=str(xz_dir),
        RESOURCE_ITEM=resource_item,
        SUBSYSTEM=subsystem,
        DEF_SUBSYSTEM=def_subsystem,
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
    print(f"[cpythonizer] Building onefile stub ({release.label}, {subsystem}): {c_file}")
    build_sln(msbuild, sln)
    exe = out_dir / f"{name}.exe"
    if not exe.is_file():
        raise RuntimeError(f"Stub build finished but EXE missing: {exe}")
    pdb = out_dir / f"{name}.pdb"
    emit_debug = keep_pdb or not release_mode
    return exe, pdb if pdb.is_file() and emit_debug else None


def make_payload(stage: Path, out: Path, key: bytes, iv: bytes, compress: str = "none") -> tuple[int, int, int]:
    """Zip the staged program + runtime, optionally compress with LZMA2, and encrypt with AES-256.

    Returns (files_count, encrypted_size, uncompressed_size).
    """
    import lzma

    out.parent.mkdir(parents=True, exist_ok=True)
    raw_zip = out.with_name(out.name + ".raw.zip")
    if raw_zip.exists():
        raw_zip.unlink()
    files = 0
    with zipfile.ZipFile(raw_zip, "w", zipfile.ZIP_STORED, allowZip64=True) as zf:
        for src in sorted(stage.rglob("*")):
            if src.is_file():
                zf.write(src, src.relative_to(stage).as_posix())
                files += 1

    uncomp_size = raw_zip.stat().st_size
    raw_bytes = raw_zip.read_bytes()
    raw_zip.unlink(missing_ok=True)

    if compress == "lzma2":
        print(f"[cpythonizer] Compressing payload with LZMA2 max (preset 9 + extreme) ...")
        to_encrypt = lzma.compress(
            raw_bytes,
            preset=9 | lzma.PRESET_EXTREME,
            format=lzma.FORMAT_XZ,
            check=lzma.CHECK_CRC32,
        )
        comp_size = len(to_encrypt)
        ratio = (comp_size / uncomp_size) * 100
        print(f"[cpythonizer] LZMA2 compression: {uncomp_size // 1024} KB -> {comp_size // 1024} KB ({ratio:.1f}%)")
    else:
        to_encrypt = raw_bytes

    print(f"[cpythonizer] Encrypting payload with random AES-256 (Windows BCrypt) ...")
    enc_bytes = aes_encrypt(key, iv, to_encrypt)
    out.write_bytes(enc_bytes)
    enc_size = len(enc_bytes)

    return files, enc_size, uncomp_size


def pack(stub_exe: Path, payload: Path, out: Path, magic: bytes, uncomp_size: int) -> Path:
    """stub + encrypted payload + trailer -> the single self-extracting EXE."""
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    with open(stub_exe, "rb") as src, open(tmp, "wb") as dst:
        shutil.copyfileobj(src, dst, COPY_CHUNK)
        with open(payload, "rb") as pf:
            shutil.copyfileobj(pf, dst, COPY_CHUNK)
    with open(tmp, "ab") as dst:
        dst.write(magic)
        dst.write(payload.stat().st_size.to_bytes(8, "little"))
        dst.write(uncomp_size.to_bytes(8, "little"))
    tmp.replace(out)
    return out


def verify(exe: Path) -> bool:
    """Sanity check: the trailer must describe a payload inside this file."""
    try:
        size = exe.stat().st_size
        with open(exe, "rb") as fh:
            fh.seek(size - TRAILER_SIZE)
            trailer = fh.read(TRAILER_SIZE)
    except OSError:
        return False
    if len(trailer) != TRAILER_SIZE:
        return False
    magic = trailer[:8]
    if magic not in (MAGIC_RAW, MAGIC_LZMA):
        return False
    comp_size = int.from_bytes(trailer[8:16], "little")
    uncomp_size = int.from_bytes(trailer[16:24], "little")
    return comp_size > 0 and uncomp_size > 0 and comp_size + TRAILER_SIZE <= size


def assemble(stage: Path, app_name: str, work: Path, msbuild: Path, release,
             out_exe: Path, icon: Path | None = None,
             release_mode: bool = False, noconsole: bool = False,
             keep_pdb: bool = False, compress: str = "none") -> Path:
    """Fold the staged program + runtime into one self-extracting EXE."""
    import os

    if not (stage / f"{app_name}.exe").is_file():
        raise FileNotFoundError(f"Staged program missing: {stage / f'{app_name}.exe'}")

    stub_dir = work / "stub"
    if stub_dir.exists():
        shutil.rmtree(stub_dir, ignore_errors=True)
    stub_dir.mkdir(parents=True, exist_ok=True)

    stub_rc = None
    if icon is not None and icon.is_file():
        stub_rc = work / f"{app_name}_stub.rc"
        # Relative to work directory where .vcxproj lives
        stub_rc.write_text(f'1 ICON "{icon.name}"\n', encoding="utf-8")

    # Generate fresh per-build random AES-256 key, IV, and key mask
    key = os.urandom(32)
    iv = os.urandom(16)
    mask = os.urandom(32)
    masked_key = bytes(k ^ m for k, m in zip(key, mask))

    stub_exe, stub_pdb = build_stub(
        work, app_name, stub_dir, release, msbuild,
        mask=mask, masked_key=masked_key, iv=iv,
        rc_file=stub_rc, release_mode=release_mode, noconsole=noconsole,
        keep_pdb=keep_pdb,
    )

    payload = work / "payload.enc"
    files, enc_size, uncomp_size = make_payload(stage, payload, key=key, iv=iv, compress=compress)

    magic = MAGIC_LZMA if compress == "lzma2" else MAGIC_RAW
    exe = pack(stub_exe, payload, out_exe, magic, uncomp_size)
    if not verify(exe):
        raise RuntimeError(f"Packed onefile EXE failed its trailer check: {exe}")
    if stub_pdb is not None and (keep_pdb or not release_mode):
        # Named apart on purpose: these are the stub's symbols, the program
        # itself keeps its own PDB inside the payload.
        shutil.copy2(stub_pdb, out_exe.with_name(f"{app_name}-stub.pdb"))
    sub_str = " (Windowed / No Console)" if noconsole else ""
    rel_str = " (Release)" if release_mode else ""
    cmp_str = " (LZMA2 max)" if compress == "lzma2" else ""
    print(f"[cpythonizer] ONEFILE DONE ({release.label}{sub_str}{rel_str}{cmp_str}, AES-256 encrypted):\n"
          f"  EXE: {exe} ({exe.stat().st_size // (1024 * 1024)} MB, runs alone)\n"
          "  At startup it decrypts in memory, unpacks into %TEMP%\\<app>-<random>\\ and cleans up after itself.")
    return exe