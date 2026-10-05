"""Find Visual Studio (2026 / 2022) + auto download/install when missing.

Goal: MSVC must exist on the DEVELOPMENT machine so the output can run
on another PC. The output EXE is built with the static CRT (/MT), so the
target PC needs no VS install and no Debug CRT.

Everything that differs between Visual Studio major versions lives in
VsRelease: product major version, install folder, platform toolset and the
Build Tools bootstrapper URL. Detection then just walks the registry
newest-first, so VS2026 (v145) is preferred over VS2022 (v143) when both
are installed side by side.
"""
from __future__ import annotations

import os
import subprocess
import urllib.request
from dataclasses import dataclass
from pathlib import Path

REQUIRED_COMPONENT = "Microsoft.VisualStudio.Component.VC.Tools"
EDITIONS = ("Community", "Professional", "Enterprise", "BuildTools")


@dataclass(frozen=True)
class VsRelease:
    """One supported Visual Studio major version."""

    year: str             # product year as shown in the UI ("2026", "2022")
    major: str            # VS product major version ("18", "17")
    folder: str           # installer folder under "Microsoft Visual Studio"
    toolset: str          # MSBuild platform toolset ("v145", "v143")
    build_tools_url: str  # bootstrapper for the Build Tools SKU
    sdk_component: str    # Windows 11 SDK component for the silent install

    @property
    def label(self) -> str:
        """Short name, e.g. 'VS2026'."""
        return f"VS{self.year}"

    @property
    def version_range(self) -> str:
        """vswhere -version range, e.g. '[18.0,19.0)'."""
        return f"[{self.major}.0,{int(self.major) + 1}.0)"

    @property
    def project_version(self) -> str:
        """VCProjectVersion written into the .vcxproj, e.g. '18.0'."""
        return f"{self.major}.0"

    def install_args(self) -> list[str]:
        """Arguments for a silent, unattended Build Tools install."""
        return [
            "--quiet", "--wait", "--norestart", "--nocache",
            "--add", "Microsoft.VisualStudio.Workload.VCTools",
            "--add", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "--add", self.sdk_component,
            "--includeRecommended",
        ]


# Newest first: selector "auto" takes the first release found on the machine.
VS2026 = VsRelease(
    year="2026",
    major="18",
    folder="18",  # the 18.x installer uses .../Visual Studio/18, not /2026
    toolset="v145",
    build_tools_url="https://aka.ms/vs/18/release/vs_buildtools.exe",
    sdk_component="Microsoft.VisualStudio.Component.Windows11SDK.26100",
)
VS2022 = VsRelease(
    year="2022",
    major="17",
    folder="2022",
    toolset="v143",
    build_tools_url="https://aka.ms/vs/17/release/vs_buildtools.exe",
    sdk_component="Microsoft.VisualStudio.Component.Windows11SDK.22621",
)
RELEASES: tuple[VsRelease, ...] = (VS2026, VS2022)


class VsInstall:
    """A Visual Studio instance on disk: which release, installed where."""

    def __init__(self, release: VsRelease, root: Path):
        self.release = release
        self.root = root

    @property
    def vcvarsall(self) -> Path:
        return self.root / "VC" / "Auxiliary" / "Build" / "vcvarsall.bat"

    def msbuild(self) -> Path | None:
        """MSBuild.exe inside this install (Current first, then any version)."""
        p = self.root / "MSBuild" / "Current" / "Bin" / "MSBuild.exe"
        if p.is_file():
            return p
        for cand in sorted(self.root.glob("MSBuild/*/Bin/MSBuild.exe"), reverse=True):
            if cand.is_file():
                return cand
        return None

    def is_usable(self) -> bool:
        """True when both the compiler environment and MSBuild are present."""
        return self.vcvarsall.is_file() and self.msbuild() is not None

    def __str__(self) -> str:
        return f"{self.release.label} ({self.release.toolset}) at {self.root}"


def resolve_releases(selector: str = "auto") -> list[VsRelease]:
    """Map a selector ("auto" / "2026" / "vs2022" / "18" / "v145") to releases."""
    key = (selector or "auto").strip().lower()
    if key in ("", "auto"):
        return list(RELEASES)
    key = key.removeprefix("vs")
    for rel in RELEASES:
        if key in (rel.year, rel.major, rel.toolset):
            return [rel]
    raise ValueError(
        f"Unknown Visual Studio: {selector!r} (expected 'auto' or "
        + ", ".join(r.label for r in RELEASES) + ")"
    )


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


def _vswhere_root(vswhere: Path, release: VsRelease) -> Path | None:
    """Ask vswhere for the newest install matching this release."""
    try:
        out = subprocess.run(
            [
                str(vswhere),
                "-products", "*",
                "-requires", REQUIRED_COMPONENT,
                "-version", release.version_range,
                "-latest",
                "-property", "installationPath",
                "-format", "value",
            ],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for line in (out.stdout or "").splitlines():
        line = line.strip()
        if line and Path(line).is_dir():
            return Path(line)
    return None


def _scan_root(release: VsRelease) -> Path | None:
    """Fallback: classic disk scan when vswhere is missing or unhelpful."""
    for pf in (os.environ.get("ProgramFiles", r"C:\Program Files"),
               os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")):
        # 18.x installs under .../Visual Studio/18, 17.x under .../2022; check
        # both spellings so a hand-relocated install is still found.
        for folder in dict.fromkeys((release.folder, release.year)):
            base = Path(pf) / "Microsoft Visual Studio" / folder
            if not base.is_dir():
                continue
            for edition in EDITIONS:
                if (base / edition / "VC" / "Auxiliary" / "Build" / "vcvarsall.bat").is_file():
                    return base / edition
    return None


def find_vs(selector: str = "auto") -> VsInstall | None:
    """Return the best usable Visual Studio install, or None.

    "auto" walks the supported releases newest-first (VS2026, then VS2022) and
    returns the first one that has both vcvarsall.bat and MSBuild.
    """
    vswhere = find_vswhere()
    for release in resolve_releases(selector):
        root = _vswhere_root(vswhere, release) if vswhere else None
        root = root or _scan_root(release)
        if root is None:
            continue
        inst = VsInstall(release, root)
        if inst.is_usable():
            return inst
    return None


def get_vcvarsall(install: VsInstall | None = None) -> Path | None:
    """Return vcvarsall.bat for an install (auto-detected when omitted)."""
    inst = install if install is not None else find_vs()
    if inst is None:
        return None
    return inst.vcvarsall if inst.vcvarsall.is_file() else None


def download_build_tools(dest: Path, release: VsRelease = VS2022) -> Path:
    """Download the vs_buildtools.exe bootstrapper for a release to dest."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"[cpythonizer] Downloading {release.label} Build Tools:\n  {release.build_tools_url}\n  -> {dest}")
    urllib.request.urlretrieve(release.build_tools_url, dest)
    return dest


def ensure_vs(selector: str = "auto", auto_install: bool = False, arch: str = "x64") -> VsInstall:
    """Return a usable Visual Studio install.

    With auto_install=True a missing release is installed silently; otherwise
    a FileNotFoundError explains how to fix it.
    """
    releases = resolve_releases(selector)
    found = find_vs(selector)
    if found is not None:
        print(f"[cpythonizer] {found} found: {found.root}")
        return found
    if not auto_install:
        wanted = " or ".join(r.label for r in releases)
        raise FileNotFoundError(
            f"{wanted} + MSVC ({'/'.join(r.toolset for r in releases)}) not found.\n"
            "Fix 1: run `cpythonizer doctor --install-vs` (auto download/install).\n"
            "Fix 2: install 'Visual Studio 2026 Community' (or 2022) + "
            "'Desktop development with C++' from "
            "https://visualstudio.microsoft.com/downloads manually."
        )
    # --- Automatic install ---
    if os.name != "nt":
        raise OSError("Automatic VS install is only supported on Windows.")
    # With "auto" prefer the newest supported release.
    release = releases[0]
    tmp = Path(os.environ.get("TEMP", r"C:\Windows\Temp")) / f"cpythonizer_vs_{release.major}_buildtools.exe"
    download_build_tools(tmp, release)
    cmd = [str(tmp), *release.install_args()]
    print(f"[cpythonizer] Installing {release.label} Build Tools silently (5-20 min, admin required)...")
    print("  " + " ".join(cmd))
    rc = subprocess.run(cmd).returncode
    if rc not in (0, 3010):
        raise RuntimeError(
            f"{release.label} Build Tools install failed (code={rc}). "
            "Retry as administrator or install manually."
        )
    found = find_vs(selector)
    if found is None:
        raise RuntimeError(f"Install finished but {release.label} is still not found. Please reboot.")
    print(f"[cpythonizer] {release.label} installed: {found.root}")
    if rc == 3010:
        print("[cpythonizer] WARNING: reboot required (code 3010).")
    return found


def find_vs2022(vswhere: Path | None = None) -> Path | None:
    """Back-compat wrapper: the VS2022 install root, or None."""
    inst = find_vs("2022")
    return inst.root if inst is not None else None


def ensure_vs2022(auto_install: bool = False, arch: str = "x64") -> Path:
    """Back-compat wrapper: the VS2022 install root."""
    return ensure_vs("2022", auto_install=auto_install, arch=arch).root