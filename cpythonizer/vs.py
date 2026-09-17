"""Find Visual Studio 2022 + auto download/install when missing.

Goal: MSVC must exist on the DEVELOPMENT machine so the output can run
on another PC. The output EXE is built with the static CRT (/MT), so the
target PC needs no VS install and no Debug CRT.
"""
from __future__ import annotations

import os
import subprocess
import urllib.request
from pathlib import Path

VS_VERSION_RANGE = "[17.0,18.0)"  # VS2022 == major 17
REQUIRED_COMPONENT = "Microsoft.VisualStudio.Component.VC.Tools"

BUILD_TOOLS_URL = "https://aka.ms/vs/17/release/vs_buildtools.exe"
# Workload needed for a silent Build Tools install:
#   - MSVC v143 compiler + Windows 11 SDK, build-only (no IDE).
INSTALL_ARGS = [
    "--quiet", "--wait", "--norestart", "--nocache",
    "--add", "Microsoft.VisualStudio.Workload.VCTools",
    "--add", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
    "--add", "Microsoft.VisualStudio.Component.Windows11SDK.22621",
    "--includeRecommended",
]


def _candidate_vswhere_paths() -> list[Path]:
    """All well-known vswhere.exe locations."""
    cands: list[Path] = []
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    cands.append(Path(pf86) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe")
    cands.append(Path(pf) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe")
    # Also honor PATH, if present.
    from shutil import which
    w = which("vswhere")
    if w:
        cands.append(Path(w))
    return cands


def find_vswhere() -> Path | None:
    """Return vswhere.exe path or None."""
    for p in _candidate_vswhere_paths():
        if p.is_file():
            return p
    return None


def find_vs2022(vswhere: Path | None = None) -> Path | None:
    """Return the VS2022 install root (e.g. .../2022/Community) or None."""
    vw = vswhere or find_vswhere()
    if vw is not None and vw.is_file():
        try:
            out = subprocess.run(
                [
                    str(vw),
                    "-products", "*",
                    "-requires", REQUIRED_COMPONENT,
                    "-version", VS_VERSION_RANGE,
                    "-property", "installationPath",
                    "-format", "value",
                ],
                capture_output=True, text=True, timeout=30,
            )
            for line in (out.stdout or "").splitlines():
                line = line.strip()
                if line and Path(line).is_dir():
                    # Take the first valid hit (highest version first).
                    return Path(line)
        except (OSError, subprocess.SubprocessError):
            pass
    # Fallback: classic disk scan.
    for base in [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Microsoft Visual Studio" / "2022",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft Visual Studio" / "2022",
    ]:
        if not base.is_dir():
            continue
        for edition in ("Community", "Professional", "Enterprise", "BuildTools"):
            vcvars = base / edition / "VC" / "Auxiliary" / "Build" / "vcvarsall.bat"
            if vcvars.is_file():
                return base / edition
    return None


def get_vcvarsall(vs_root: Path | None = None) -> Path | None:
    """Return vcvarsall.bat path or None."""
    root = vs_root or find_vs2022()
    if root is None:
        return None
    p = root / "VC" / "Auxiliary" / "Build" / "vcvarsall.bat"
    return p if p.is_file() else None


def download_build_tools(dest: Path) -> Path:
    """Download vs_buildtools.exe to dest."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"[cpythonizer] Downloading VS2022 Build Tools:\n  {BUILD_TOOLS_URL}\n  -> {dest}")
    urllib.request.urlretrieve(BUILD_TOOLS_URL, dest)
    return dest


def ensure_vs2022(auto_install: bool = False, arch: str = "x64") -> Path:
    """Return the VS2022 root. If missing and auto_install=True, install silently."""
    found = find_vs2022()
    if found is not None and get_vcvarsall(found) is not None:
        print(f"[cpythonizer] VS2022 found: {found}")
        return found
    if not auto_install:
        raise FileNotFoundError(
            "VS2022 + MSVC (v143) not found.\n"
            "Fix 1: run `cpythonizer doctor --install-vs` (auto download/install).\n"
            "Fix 2: install 'Visual Studio 2022 Community' + 'Desktop development with C++' from "
            "https://visualstudio.microsoft.com/downloads manually."
        )
    # --- Automatic install ---
    if os.name != "nt":
        raise OSError("Automatic VS install is only supported on Windows.")
    tmp = Path(os.environ.get("TEMP", r"C:\Windows\Temp")) / "cpythonizer_vs_buildtools.exe"
    download_build_tools(tmp)
    cmd = [str(tmp), *INSTALL_ARGS]
    print("[cpythonizer] Installing VS2022 Build Tools silently (5-20 min, admin required)...")
    print("  " + " ".join(cmd))
    rc = subprocess.run(cmd).returncode
    if rc not in (0, 3010):
        raise RuntimeError(
            f"VS Build Tools install failed (code={rc}). "
            "Retry as administrator or install manually."
        )
    found = find_vs2022()
    if found is None:
        raise RuntimeError("Install finished but VS2022 is still not found. Please reboot.")
    print(f"[cpythonizer] VS2022 installed: {found}")
    if rc == 3010:
        print("[cpythonizer] WARNING: reboot required (code 3010).")
    return found
