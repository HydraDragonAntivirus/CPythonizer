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

MAGIC = b"CPYONE1\0"
TRAILER_SIZE = len(MAGIC) + 8
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
 * appended to this EXE as a stored ZIP; at startup it is unpacked into a
 * random folder under %TEMP% and executed from there under its own name.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define PAYLOAD_MAGIC "CPYONE1"
#define TRAILER_SIZE  16
#define COPY_CHUNK    (1024u * 1024u)
#define MAX_ATTEMPTS  32

/* Injected by the build. */
#define CHILD_NAME   L"$CHILD_NAME"     /* program inside the payload   */
#define TEMP_PREFIX  L"$TEMP_PREFIX"    /* random folder name prefix   */

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
    DWORD got = 0;

    li.QuadPart = (LONGLONG)off;
    if (!SetFilePointerEx(f, li, NULL, FILE_BEGIN))
        return 0;
    if (!ReadFile(f, buf, len, &got, NULL))
        return 0;
    return got == len;
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

/*
 * The payload is a normal ZIP, so the local entries are followed by a central
 * directory. Find the end-of-central-directory record to learn where the entry
 * data actually stops; everything past it is ignored while unpacking.
 */
static int find_data_end(HANDLE f, ULONGLONG start, ULONGLONG end,
                         ULONGLONG *data_end)
{
    ULONGLONG floor = (end - start > 22 + (64u << 10)) ? end - 22 - (64u << 10)
                                                       : start;
    ULONGLONG off;

    if (end < start + 22)
        return 0;
    for (off = end - 22;; off--) {
        unsigned char eocd[22];
        if (read_at(f, off, eocd, 22) && eocd[0] == 'P' && eocd[1] == 'K' &&
            eocd[2] == 5 && eocd[3] == 6) {
            unsigned cd_size = rd32(eocd + 12);
            *data_end = off - cd_size;
            return *data_end >= start;
        }
        if (off <= floor)
            return 0;
    }
}

/*
 * Unpack the stored-ZIP payload. Entries are written in order and nothing is
 * compressed, so the local file headers are enough - no central directory and
 * no inflate are needed.
 */
static int extract_payload(HANDLE self, ULONGLONG start, ULONGLONG size,
                           const wchar_t *dest)
{
    ULONGLONG pos = start, end = start + size;
    unsigned char *chunk = (unsigned char *)malloc(COPY_CHUNK);
    unsigned char hdr[30];
    int files = 0;

    if (chunk == NULL) {
        fail(L"out of memory");
        return 0;
    }
    while (pos + 30 <= end) {
        unsigned method, csize, usize, nlen, elen, i;
        unsigned char *raw;
        wchar_t name[512], target[1024], parent[1024];
        ULONGLONG data, off, left;

        if (!read_at(self, pos, hdr, 30))
            break;
        if (hdr[0] != 'P' || hdr[1] != 'K' || hdr[2] != 3 || hdr[3] != 4)
            break;
        method = rd16(hdr + 8);
        csize = rd32(hdr + 18);
        usize = rd32(hdr + 22);
        nlen = rd16(hdr + 26);
        elen = rd16(hdr + 28);
        data = pos + 30 + nlen + elen;
        if (method != 0 || csize != usize || nlen == 0 || nlen >= 512 ||
            data + csize > end) {
            fail(L"corrupt payload");
            free(chunk);
            return 0;
        }
        raw = (unsigned char *)malloc(nlen + 1);
        if (raw == NULL || !read_at(self, pos + 30, raw, nlen)) {
            free(raw);
            fail(L"cannot read payload entry");
            free(chunk);
            return 0;
        }
        raw[nlen] = 0;
        i = (unsigned)MultiByteToWideChar(CP_UTF8, 0, (const char *)raw,
                                          (int)nlen, name, 512);
        free(raw);
        if (i == 0 || i >= 512) {
            fail(L"bad entry name");
            free(chunk);
            return 0;
        }
        name[i] = L'\0';
        for (unsigned k = 0; k < i; k++) {
            if (name[k] == L'/')
                name[k] = L'\\';
        }
        if (wcsstr(name, L"..") != NULL) {
            fail(L"unsafe path in payload");
            free(chunk);
            return 0;
        }
        if (_snwprintf_s(target, 1024, _TRUNCATE, L"%s\\%s", dest, name) < 0) {
            fail(L"path too long");
            free(chunk);
            return 0;
        }

        if (name[i - 1] == '/' || name[i - 1] == '\\') {
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
                free(chunk);
                return 0;
            }
            off = data;
            left = csize;
            while (left > 0) {
                LARGE_INTEGER li;
                DWORD want = (DWORD)(left < COPY_CHUNK ? left : COPY_CHUNK);
                DWORD got = 0, put = 0;
                li.QuadPart = (LONGLONG)off;
                if (!SetFilePointerEx(self, li, NULL, FILE_BEGIN) ||
                    !ReadFile(self, chunk, want, &got, NULL) || got == 0 ||
                    !WriteFile(out, chunk, got, &put, NULL) || put != got) {
                    CloseHandle(out);
                    fail(L"cannot write extracted file");
                    free(chunk);
                    return 0;
                }
                off += got;
                left -= got;
            }
            CloseHandle(out);
            files++;
        }
        pos = data + csize;
    }
    free(chunk);
    if (pos != end || files == 0) {
        fail(L"payload was not fully unpacked");
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
    ULONGLONG size, payload = 0, start, data_end = 0;
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
        !read_at(self_file, size - TRAILER_SIZE, trailer, TRAILER_SIZE) ||
        memcmp(trailer, PAYLOAD_MAGIC, 8) != 0) {
        fail(L"not a cpythonizer onefile executable");
        CloseHandle(self_file);
        return 1;
    }
    for (i = 0; i < 8; i++)
        payload |= (ULONGLONG)trailer[8 + i] << (8 * i);
    if (payload == 0 || payload + TRAILER_SIZE > size) {
        fail(L"corrupt payload trailer");
        CloseHandle(self_file);
        return 1;
    }
    start = size - TRAILER_SIZE - payload;

    if (!make_temp_dir(TEMP_PREFIX, tmpdir, 1024)) {
        fail(L"cannot create a temp folder");
        CloseHandle(self_file);
        return 1;
    }
    if (!find_data_end(self_file, start, start + payload, &data_end)) {
        fail(L"corrupt payload archive");
        cleanup(tmpdir);
        CloseHandle(self_file);
        return 1;
    }
    say(tmpdir);
    if (!extract_payload(self_file, start, data_end - start, tmpdir)) {
        cleanup(tmpdir);
        CloseHandle(self_file);
        return 1;
    }
    CloseHandle(self_file);

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
    <GenerateDebugInformation>true</GenerateDebugInformation>
  </PropertyGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <ClCompile>
      <WarningLevel>Level3</WarningLevel>
      <Optimization>MaxSpeed</Optimization>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <PreprocessorDefinitions>NDEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <CompileAs>CompileAsC</CompileAs>
      <!-- Pure Win32 launcher: static CRT so the stub runs on a bare PC. -->
      <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
      <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
    </ClCompile>
    <Link>
      <SubSystem>Console</SubSystem>
      <GenerateDebugInformation>true</GenerateDebugInformation>
      <EnableCOMDATFolding>true</EnableCOMDATFolding>
      <OptimizeReferences>true</OptimizeReferences>
      <AdditionalDependencies>kernel32.lib;advapi32.lib;bcrypt.lib;%(AdditionalDependencies)</AdditionalDependencies>
      <EntryPointSymbol>wmainCRTStartup</EntryPointSymbol>
    </Link>
  </ItemDefinitionGroup>
  <ItemGroup>
    <ClCompile Include="{CFILE}" />
{RESOURCE_ITEM}
  </ItemGroup>
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.targets" />
  <ImportGroup Label="ExtensionTargets" />
</Project>
"""


def write_stub_c(work: Path, app_name: str) -> Path:
    """Emit stub.c with the payload's program name baked in."""
    src = STUB_C.substitute(CHILD_NAME=f"{app_name}.exe", TEMP_PREFIX=app_name)
    path = work / f"{app_name}_stub.c"
    path.write_text(src, encoding="utf-8")
    return path


def build_stub(work: Path, app_name: str, out_dir: Path, release,
               msbuild: Path, rc_file: Path | None = None) -> tuple[Path, Path | None]:
    """Compile the stub. Returns (stub_exe, stub_pdb)."""
    guid = str(uuid.uuid4()).upper()
    c_file = write_stub_c(work, app_name)
    name = f"{app_name}_stub"
    resource_item = f'    <ResourceCompile Include="{rc_file.name}" />' if rc_file else ""
    proj = STUB_VCXPROJ_TEMPLATE.format(
        GUID="{" + guid + "}",
        NAME=name,
        PROJECT_VERSION=release.project_version,
        TOOLSET=release.toolset,
        OUTDIR=str(out_dir),
        INTDIR=str(work / "obj_stub"),
        CFILE=str(c_file),
        RESOURCE_ITEM=resource_item,
    )
    (work / f"{name}.vcxproj").write_text(proj, encoding="utf-8")
    sln = work / f"{name}.sln"
    sln.write_text(
        SLN_TEMPLATE.format(NAME=name, GUID="{" + guid + "}",
                            SLN_MAJOR=release.major),
        encoding="utf-8",
    )
    print(f"[cpythonizer] Building onefile stub ({release.label}): {c_file}")
    build_sln(msbuild, sln)
    exe = out_dir / f"{name}.exe"
    if not exe.is_file():
        raise RuntimeError(f"Stub build finished but EXE missing: {exe}")
    pdb = out_dir / f"{name}.pdb"
    return exe, pdb if pdb.is_file() else None


def make_payload(stage: Path, out: Path) -> tuple[int, int]:
    """Zip the staged program + runtime (stored, no compression).

    Compression would buy almost nothing here: python314.zip, the .pyd modules
    and the DLLs are already compressed, and the stub has no inflate.
    """
    out.parent.mkdir(parents=True, exist_ok=True)
    files = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED, allowZip64=True) as zf:
        for src in sorted(stage.rglob("*")):
            if src.is_file():
                zf.write(src, src.relative_to(stage).as_posix())
                files += 1
    return files, out.stat().st_size


def pack(stub_exe: Path, payload: Path, out: Path) -> Path:
    """stub + payload + trailer -> the single self-extracting EXE."""
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    with open(stub_exe, "rb") as src, open(tmp, "wb") as dst:
        shutil.copyfileobj(src, dst, COPY_CHUNK)
        with open(payload, "rb") as pf:
            shutil.copyfileobj(pf, dst, COPY_CHUNK)
    with open(tmp, "ab") as dst:
        dst.write(MAGIC)
        dst.write(payload.stat().st_size.to_bytes(8, "little"))
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
    if len(trailer) != TRAILER_SIZE or trailer[:8] != MAGIC:
        return False
    payload = int.from_bytes(trailer[8:], "little")
    return payload > 0 and payload + TRAILER_SIZE <= size


def assemble(stage: Path, app_name: str, work: Path, msbuild: Path, release,
             out_exe: Path, icon: Path | None = None) -> Path:
    """Fold the staged program + runtime into one self-extracting EXE."""
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

    stub_exe, stub_pdb = build_stub(work, app_name, stub_dir, release, msbuild, rc_file=stub_rc)

    payload = work / "payload.zip"
    files, size = make_payload(stage, payload)
    print(f"[cpythonizer] Payload: {files} files, {size // (1024 * 1024)} MB (stored)")

    exe = pack(stub_exe, payload, out_exe)
    if not verify(exe):
        raise RuntimeError(f"Packed onefile EXE failed its trailer check: {exe}")
    if stub_pdb is not None:
        # Named apart on purpose: these are the stub's symbols, the program
        # itself keeps its own PDB inside the payload.
        shutil.copy2(stub_pdb, out_exe.with_name(f"{app_name}-stub.pdb"))
    print(f"[cpythonizer] ONEFILE DONE ({release.label}):\n"
          f"  EXE: {exe} ({exe.stat().st_size // (1024 * 1024)} MB, runs alone)\n"
          "  At startup it unpacks into %TEMP%\\<app>-<random>\\ and cleans up after itself.")
    return exe