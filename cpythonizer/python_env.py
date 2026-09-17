"""Mandatory Python 3.14 environment: find + auto-install + dev files.

CPythonizer only works with CPython 3.14 (Python.h / python314.lib ABI).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import sysconfig
import urllib.request
from pathlib import Path

REQUIRED_MAJOR = 3
REQUIRED_MINOR = 14
FTP_URL = "https://www.python.org/ftp/python/3.14.7/python-3.14.7-amd64.exe"


def _is_python314(exe: Path) -> bool:
    """Check whether the given interpreter reports version 3.14."""
    try:
        out = subprocess.run(
            [str(exe), "-c", "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')"],
            capture_output=True, text=True, timeout=15,
        )
        return (out.stdout or "").strip() == f"{REQUIRED_MAJOR}.{REQUIRED_MINOR}"
    except (OSError, subprocess.SubprocessError):
        return False


def find_python314() -> Path | None:
    """Search well-known locations, the py launcher, PATH, then sys.executable."""
    cands: list[Path] = []
    # 1) Known fixed locations (fastest).
    for p in [
        Path(r"C:\Python314\python.exe"),
        Path(r"C:\Program Files\Python314\python.exe"),
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Python" / "Python314" / "python.exe",
    ]:
        cands.append(p)
    # 2) py launcher.
    py = shutil.which("py")
    if py:
        try:
            out = subprocess.run(
                [py, "-3.14", "-c", "import sys; print(sys.executable)"],
                capture_output=True, text=True, timeout=15,
            )
            exe = (out.stdout or "").strip().strip('"')
            if exe:
                cands.append(Path(exe))
        except (OSError, subprocess.SubprocessError):
            pass
    # 3) Interpreters on PATH.
    for name in ("python3.14", "python"):
        w = shutil.which(name)
        if w:
            cands.append(Path(w))
    for c in cands:
        try:
            if c.is_file() and _is_python314(c):
                return c
        except OSError:
            continue
    # 4) The current interpreter already is 3.14.
    if (sys.version_info[0], sys.version_info[1]) == (REQUIRED_MAJOR, REQUIRED_MINOR):
        return Path(sys.executable)
    return None


def repo_installer() -> Path | None:
    """Return install_python/python-3.14.7-amd64.exe if bundled in the repo."""
    here = Path(__file__).resolve().parent.parent
    p = here / "install_python" / "python-3.14.7-amd64.exe"
    if p.is_file() and p.stat().st_size > 10_000_000:
        return p
    return None


def download_official_installer(dest: Path) -> Path:
    """Download the official python.org 3.14 installer."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"[cpythonizer] Downloading official Python 3.14.7 installer:\n  {FTP_URL}\n  -> {dest}")
    urllib.request.urlretrieve(FTP_URL, dest)
    return dest


def silent_install(installer: Path, target_dir: Path | None = None) -> None:
    """Unattended install for the dev machine. May require admin rights."""
    args = [str(installer), "/quiet", "/passive", "PrependPath=1", "Include_test=0"]
    if target_dir is not None:
        args.append(f"TargetDir={target_dir}")
    # Default components already include headers (include/) and libs/.
    print("[cpythonizer] Installing Python 3.14 silently...")
    print("  " + " ".join(args))
    rc = subprocess.run(args).returncode
    if rc not in (0, 3010):
        raise RuntimeError(f"Python 3.14 install failed (code={rc})")


def ensure_python314(auto_install: bool = False) -> Path:
    """Return a Python 3.14 interpreter, optionally installing it first."""
    found = find_python314()
    if found is not None:
        print(f"[cpythonizer] Python 3.14 found: {found}")
        return found
    if not auto_install:
        raise FileNotFoundError(
            "Python 3.14 not found (required).\n"
            "Fix 1: run `cpythonizer doctor --install-python` (uses install_python/ "
            "from the repo, else downloads from python.org).\n"
            "Fix 2: run install_python/python-3.14.7-amd64.exe manually."
        )
    inst = repo_installer()
    if inst is None:
        tmp = Path(os.environ.get("TEMP", r"C:\Windows\Temp")) / "python-3.14.7-amd64.exe"
        if not (tmp.is_file() and tmp.stat().st_size > 10_000_000):
            download_official_installer(tmp)
        inst = tmp
    else:
        print(f"[cpythonizer] Using bundled installer: {inst}")
    silent_install(inst)
    found = find_python314()
    if found is None:
        raise RuntimeError(
            "Install finished but Python 3.14 is still not on PATH. "
            "Reopen the terminal or check C:\\Python314\\python.exe."
        )
    return found


class PyDev:
    """Locations of the files needed to compile: Python.h / .lib / .dll."""

    def __init__(self, exe: Path):
        self.exe = exe
        out = subprocess.run(
            [str(exe), "-c",
             "import sys, sysconfig; "
             "print(sys.base_prefix); "
             "print(sysconfig.get_path('include')); "
             "print(sys.version_info[0]); print(sys.version_info[1])"],
            capture_output=True, text=True, timeout=15,
        )
        if out.returncode != 0:
            raise RuntimeError(f"Could not query Python: {exe}\n{out.stderr}")
        lines = (out.stdout or "").splitlines()
        self.base = Path(lines[0].strip())
        self.include = Path(lines[1].strip())
        major, minor = int(lines[2].strip()), int(lines[3].strip())
        if (major, minor) != (REQUIRED_MAJOR, REQUIRED_MINOR):
            raise RuntimeError(f"CPythonizer requires Python 3.14, found: {major}.{minor} ({exe})")
        self.libs = self.base / "libs"
        self.dlls_dir = self.base / "DLLs"
        self.lib_dir = self.base / "Lib"
        self.ver = f"{major}{minor}"  # '314'
        self.dll_name = f"python{self.ver}.dll"  # python314.dll

    def check(self) -> None:
        """Verify that headers and import lib exist."""
        missing: list[str] = []
        if not (self.include / "Python.h").is_file():
            missing.append(f"{self.include / 'Python.h'} (Include)")
        lib = self.libs / f"python{self.ver}.lib"
        if not lib.is_file():
            missing.append(f"{lib} (libs)")
        if missing:
            raise FileNotFoundError(
                "Python development files missing:\n  - " + "\n  - ".join(missing) +
                "\nReinstall Python 3.14 with the official installer (default components)."
            )

    def runtime_dlls(self) -> list[Path]:
        """DLLs that MUST be copied next to the EXE (required copies)."""
        out: list[Path] = []
        for name in (self.dll_name, "python3.dll", "vcruntime140.dll", "vcruntime140_1.dll"):
            p = self.base / name
            if p.is_file():
                out.append(p)
        return out

    def lib_file(self) -> Path:
        """Import library used at link time (e.g. python314.lib)."""
        return self.libs / f"python{self.ver}.lib"
