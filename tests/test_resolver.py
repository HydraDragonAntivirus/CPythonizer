"""Compile resolve.h on its own and check every hidden import against GetProcAddress.

This is the test that should have existed all along. The loader resolves its Win32
entry points by walking export directories at run time, so a bug there produces a
binary that behaves differently depending on whether the API happens to be a
*forwarded* export: on Windows 11, 211 of kernel32's 1697 exports are forwarders,
and the resolver used to hand back the ASCII string "NTDLL.RtlAddVectoredExceptionHandler"
as if it were a function pointer. The affected API was only called on the verbose
code path, so every matrix run without verbose stayed green.

Comparing each resolved slot against GetProcAddress gives an oracle that does not
share any code with the resolver, which is the only way this class of bug is
caught: a "does the address look sane" check passes happily for a pointer into the
module's string table.

Run: python tests/test_resolver.py        (also collected by pytest if present)
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cpythonizer import zombie  # noqa: E402

GUARD_DIR = ROOT / "cpythonizer" / "obfuscate"

PROBE = r"""#include <stdio.h>
#include <windows.h>
#define CPY_HSTR(x) x
#define CPY_HWSTR(x) x
#include "resolve.h"

__API_BLOCK__

struct { const char *module; const char *name; unsigned slot; } probe[] = {
__ROWS__
};
#define NPROBE (sizeof(probe) / sizeof(probe[0]))

static HMODULE module_of(const char *name)
{
    char path[MAX_PATH];
    int n = sprintf_s(path, MAX_PATH, "%s", name);

    (void)n;
    return LoadLibraryExA(path, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
}

int main(void)
{
    unsigned i, wrong = 0, unresolved = 0;
    int rc = resolve_hidden_imports();

    for (i = 0; i < NPROBE; i++) {
        HMODULE m = module_of(probe[i].module);
        FARPROC truth = m ? GetProcAddress(m, probe[i].name) : NULL;
        void *got = g_api[probe[i].slot];

        if (!got) {
            unresolved++;
            printf("  UNRESOLVED %-34s %s!%s\n", probe[i].name, probe[i].module,
                   probe[i].name);
        } else if (!truth) {
            printf("  ORACLE?    %-34s %s!%s not exported\n", probe[i].name,
                   probe[i].module, probe[i].name);
        } else if (got != (void *)truth) {
            wrong++;
            printf("  MISMATCH   %-34s %s!%s got=%p GetProcAddress=%p%s\n",
                   probe[i].name, probe[i].module, probe[i].name, got,
                   (void *)truth,
                   got < (void *)0x10000 ? "  <- string, not code" : "");
        }
    }
    printf("rc=%d unresolved=%u wrong=%u total=%u\n", rc, unresolved, wrong,
           (unsigned)NPROBE);
    return 0;
}
"""


def _devcmd() -> Path | None:
    """Locate VsDevCmd.bat through vswhere, so the test needs no env setup."""
    vswhere = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe")
    if not vswhere.is_file():
        return None
    res = subprocess.run(
        [str(vswhere), "-latest", "-products", "*", "-requires",
         "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property",
         "installationPath"],
        capture_output=True, text=True)
    if res.returncode != 0 or not res.stdout.strip():
        return None
    bat = Path(res.stdout.strip()) / "Common7" / "Tools" / "VsDevCmd.bat"
    return bat if bat.is_file() else None


def check() -> str:
    """Return '' when every slot matches GetProcAddress, else the reason why not."""
    if shutil.which("cmd") is None:
        return "skip: Windows shell required"
    if not (GUARD_DIR / "resolve.h").is_file():
        return "skip: guard headers not present"
    devcmd = _devcmd()
    if not devcmd:
        return "skip: MSVC toolchain not found"

    rows = "\n".join(f'    {{ "{mod}", "{name}", A_{name} }},'
                     for mod, name, _, _ in zombie.HIDDEN_APIS)
    src = (PROBE.replace("__API_BLOCK__", zombie._api_block())
                .replace("__ROWS__", rows))
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        src_path, exe = tmpdir / "probe.c", tmpdir / "probe.exe"
        src_path.write_text(src, encoding="utf-8")
        bat = tmpdir / "build.bat"
        bat.write_text(f'call "{devcmd}" -arch=x64 >nul 2>&1\n'
                       f'cl /nologo /W3 /O1 /I"{GUARD_DIR}" "{src_path}" '
                       f'/Fe:"{exe}" /link /SUBSYSTEM:CONSOLE '
                       f'/ENTRY:mainCRTStartup\n', encoding="utf-8")
        build = subprocess.run(["cmd", "/c", str(bat)], capture_output=True,
                               text=True)
        if not exe.is_file():
            return f"probe did not build:\n{build.stdout}\n{build.stderr}"
        run = subprocess.run([str(exe)], capture_output=True, text=True,
                             timeout=120)

    lines = run.stdout.splitlines()
    line = next((ln for ln in lines if ln.startswith("rc=")), "")
    if not line:
        return f"probe produced no verdict: {run.stdout!r} {run.stderr!r}"
    fields = dict(part.split("=") for part in line.split())
    if fields["rc"] != "1":
        return f"resolver reported failure: {line}"
    if int(fields["total"]) != len(zombie.HIDDEN_APIS):
        return f"probe covered {fields['total']} slots, expected {len(zombie.HIDDEN_APIS)}"
    detail = "\n".join(ln for ln in lines if "  " in ln and not ln.startswith("rc="))
    if fields["unresolved"] != "0":
        return f"{fields['unresolved']} hidden imports did not resolve: {line}\n{detail}"
    if fields["wrong"] != "0":
        return (f"{fields['wrong']} slots do not match GetProcAddress, so the "
                f"resolver returned the wrong address: {line}\n{detail}")
    return ""


def test_hidden_imports_match_getprocaddress():
    problem = check()
    if problem.startswith("skip:"):
        try:
            import pytest  # noqa: F401
        except ImportError:
            print(problem)
            return
        pytest.skip(problem)
    assert not problem, problem


def main() -> int:
    problem = check()
    if problem:
        print(problem)
        return 0 if problem.startswith("skip:") else 1
    print(f"ok: all {len(zombie.HIDDEN_APIS)} hidden imports match GetProcAddress")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
