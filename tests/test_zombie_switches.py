"""End-to-end checks for the zombie loader, including the switches themselves.

Everything else in tests/ works without a build; this one drives real MSBuild
runs and therefore takes several minutes. It is opt-in:

    CPXP_ZOMBIE_TESTS=1 python tests/test_zombie_switches.py

The point of this file is that a passing run has to *observe* the switches, not
just exit 0. An earlier matrix only checked the exit code, which is why a loader
that stored a forwarder string in an API slot and called it as a function pointer
stayed green: it crashed only with CPYTHONIZER_ONEFILE_VERBOSE=1, which that matrix
never set. Each check below names the switch it exercises so a future regression
points straight at the cause.
"""
from __future__ import annotations

import hashlib
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = Path(os.environ.get("CPXP_ZOMBIE_WORK",
                           Path(os.environ.get("TEMP", ".")) / "cpythonizer-zombie-tests"))

PROGRAM = '''\
import hashlib, os, sys

PAYLOAD = ("license=" * 9973).encode()
TABLE = {}
for i in range(4096):
    TABLE[i] = (i * 2654435761) % 0xFFFFFFFF
digest = hashlib.sha256(PAYLOAD).hexdigest()
checksum = sum(TABLE[i] * (i + 1) for i in range(0, 4096, 7)) % 0xFFFFFFFF


def _read(path):
    try:
        with open(path, "rb") as fh:
            return len(fh.read())
    except OSError:
        return -1


# --add-data through the PyInstaller-style lookup ...
BASE = getattr(sys, "_MEIPASS", None) or os.path.dirname(sys.executable)
data_size = _read(os.path.join(BASE, "probe.dat"))
# ... and through the plain "next to me" one, which is what untouched code does.
# In a frozen build __file__ is the string "built-in" unless the build puts a
# real path there, and then this comes back as -1.
file_size = _read(os.path.join(os.path.dirname(__file__), "probe.dat"))
print("ZPROBE", digest, checksum, len(sys.modules) > 0, os.name, data_size, file_size)
'''

MARKER = "ZPROBE"
DATA_BYTES = 4096


# --------------------------------------------------------------------------
# tiny PE reader, enough for the two header fields the checks need
# --------------------------------------------------------------------------

def pe_size_of_image(path: Path) -> int:
    data = path.read_bytes()
    nt = struct.unpack_from("<I", data, 0x3C)[0]
    return struct.unpack_from("<I", data, nt + 0x18 + 0x38)[0]


def pe_imported_dlls(path: Path) -> set[str]:
    data = path.read_bytes()
    nt = struct.unpack_from("<I", data, 0x3C)[0]
    opt = nt + 0x18
    magic = struct.unpack_from("<H", data, opt)[0]
    dd = opt + (0x70 if magic == 0x20B else 0x60)
    rva, size = struct.unpack_from("<II", data, dd + 8)
    if not rva:
        return set()

    sections = []
    nsec = struct.unpack_from("<H", data, nt + 0x6)[0]
    opt_size = struct.unpack_from("<H", data, nt + 0x14)[0]
    sh = nt + 0x18 + opt_size
    for i in range(nsec):
        base = sh + i * 40
        va, vsz = struct.unpack_from("<II", data, base + 12)
        raw, rsz = struct.unpack_from("<II", data, base + 20)
        sections.append((va, max(vsz, rsz), raw))

    def to_off(rva: int) -> int:
        for va, sz, raw in sections:
            if va <= rva < va + sz:
                return raw + (rva - va)
        return -1

    names = set()
    off = to_off(rva)
    while off >= 0 and off + 20 <= len(data):
        name_rva = struct.unpack_from("<I", data, off + 12)[0]
        if not name_rva:
            break
        noff = to_off(name_rva)
        if noff < 0:
            break
        raw = data[noff:data.index(b"\0", noff)]
        names.add(raw.decode("ascii", "replace"))
        off += 20
    return names


# --------------------------------------------------------------------------

def _run(args, env=None):
    return subprocess.run([sys.executable, "-m", "cpythonizer", *args],
                          cwd=ROOT, capture_output=True, text=True, env=env)


def _write_if_changed(path: Path, text: str) -> None:
    """Only touch the file when its content actually changed.

    The rebuild check below compares timestamps, so rewriting an identical probe
    on every run would invalidate all four builds and turn a two-second check
    into a five-minute one.
    """
    if not path.is_file() or path.read_text(encoding="utf-8") != text:
        path.write_text(text, encoding="utf-8")


def _newest_source_mtime() -> float:
    """Newest file that can change what a build produces."""
    roots = [ROOT / "cpythonizer", ROOT / "pyproject.toml"]
    newest = 0.0
    for item in roots:
        candidates = [item] if item.is_file() else list(item.rglob("*"))
        for path in candidates:
            if path.is_file() and path.suffix in (".py", ".h"):
                newest = max(newest, path.stat().st_mtime)
    return newest


def _build(name: str, source: Path, extra: list[str], stamp: Path) -> Path:
    dist = WORK / "dist"
    exe = dist / name / f"{name}.exe"
    # Reuse only while nothing that feeds the build has changed, so iterating on
    # the checks costs seconds instead of five minutes - and so a stale binary is
    # never mistaken for a passing test.
    cutoff = max(stamp.stat().st_mtime, _newest_source_mtime())
    if exe.is_file() and exe.stat().st_mtime > cutoff:
        print(f"    reusing {name} ({exe.stat().st_size // 1024} KB, unchanged sources)")
        return exe
    print(f"    building {name} ...", flush=True)
    started = time.time()
    res = _run(["vs-build", str(source), "--name", name, "--dist", str(dist),
                *extra])
    if res.returncode != 0:
        raise AssertionError(f"build {name} failed:\n{res.stdout[-4000:]}\n"
                             f"{res.stderr[-4000:]}")
    if not exe.is_file():
        raise AssertionError(f"build {name} produced no {exe}")
    print(f"    built {name} in {time.time() - started:.0f}s "
          f"({exe.stat().st_size // 1024} KB)", flush=True)
    return exe


def _execute(exe: Path, env_extra: dict[str, str] | None = None):
    env = os.environ.copy()
    env.update(env_extra or {})
    return subprocess.run([str(exe)], capture_output=True, text=True,
                          env=env, timeout=180)


def _log(res) -> str:
    """Loader diagnostics go to stderr, so stdout alone would miss them."""
    return res.stdout + res.stderr


def _data_sizes(output: str) -> tuple[int, int]:
    """Sizes of the --add-data file as seen via _MEIPASS and via __file__."""
    for line in output.splitlines():
        if line.startswith(MARKER):
            parts = line.split()
            if len(parts) >= 7:
                try:
                    return int(parts[-2]), int(parts[-1])
                except ValueError:
                    return -2, -2
    return -1, -1


def _temp_folder_of(output: str) -> Path | None:
    for line in output.splitlines():
        if line.startswith("[cpythonizer] temp folder:"):
            return Path(line.split(":", 1)[1].strip())
    return None


def _runs(exe: Path, count: int = 3, env_extra: dict[str, str] | None = None):
    outs = []
    for _ in range(count):
        res = _execute(exe, env_extra)
        outs.append((res.returncode, res.stdout))
    return outs


def check() -> list[str]:
    """Return a list of failures; empty means everything behaved."""
    if not os.environ.get("CPXP_ZOMBIE_TESTS"):
        return ["skip: set CPXP_ZOMBIE_TESTS=1 to run the builds"]
    WORK.mkdir(parents=True, exist_ok=True)
    src = WORK / "probe.py"
    _write_if_changed(src, PROGRAM)
    data = WORK / "probe.dat"
    # Written next to the entry as well as staged with --add-data: the plain
    # build resolves __file__ to the app folder, the frozen ones to the bundle,
    # and both must end up able to read it.
    blob = b"add-data-payload" * (DATA_BYTES // 16 + 1)
    if not data.is_file() or data.read_bytes() != blob:
        data.write_bytes(blob)
    add_data = ["--add-data", f"{data};."]
    bad: list[str] = []

    plain = _build("ZPlain", src, ["--release", *add_data], data)
    guarded = _build("ZGuard", src, ["--zombie", "--guard", "full", "--lzma2",
                                     "--release", *add_data], data)
    noad = _build("ZNoAd", src, ["--zombie", "--guard", "full", "--lzma2",
                                 "--release", "--no-antidump", *add_data], data)
    off = _build("ZGuardOff", src, ["--zombie", "--guard", "off", "--lzma2",
                                    "--release", *add_data], data)

    # 1. the program itself must behave identically, protected or not
    base = _runs(plain, 2)[0][1]
    if MARKER not in base:
        bad.append(f"plain build did not run the program: {base[:200]!r}")
    want_size = data.stat().st_size
    for name, exe in (("zombie guard full", guarded), ("zombie no-antidump", noad),
                      ("zombie guard off", off)):
        runs = _runs(exe, 3)
        for i, (code, out) in enumerate(runs):
            if code != 0:
                bad.append(f"{name} run {i}: exit {code}, output {out[:200]!r}")
            elif out != base:
                bad.append(f"{name} run {i}: output differs from the plain build\n"
                           f"  plain : {base.strip()[:200]}\n"
                           f"  zombie: {out.strip()[:200]}")

    # 1b. --add-data must actually be reachable at run time, in every mode, and
    #     through both lookups real code uses. Comparing against the plain build
    #     above is not enough on its own: if the file were missing everywhere,
    #     all four outputs would still match.
    for name, out in (("plain", base),
                      ("zombie guard full", _execute(guarded).stdout),
                      ("zombie no-antidump", _execute(noad).stdout),
                      ("zombie guard off", _execute(off).stdout)):
        meipass_size, file_size = _data_sizes(out)
        if meipass_size != want_size:
            bad.append(f"{name}: --add-data file read back as {meipass_size} bytes "
                       f"through sys._MEIPASS, expected {want_size}")
        if file_size != want_size:
            bad.append(f"{name}: --add-data file read back as {file_size} bytes "
                       f"through __file__, expected {want_size} (an embedded "
                       f"module reports __file__ as 'built-in' unless the build "
                       f"gives it a real path)")

    # 2. VERBOSE=1 must actually print diagnostics and still succeed. This is the
    #    check that used to be missing: the loader crashed only on this path.
    res = _execute(guarded, {"CPYTHONIZER_ONEFILE_VERBOSE": "1"})
    log = _log(res)
    lines = [ln for ln in log.splitlines() if ln.startswith("[cpythonizer]")]
    if res.returncode != 0:
        bad.append(f"VERBOSE=1 run failed with exit {res.returncode} "
                   f"({res.returncode & 0xFFFFFFFF:#x}): {log[-400:]!r}")
    if MARKER not in res.stdout:
        bad.append(f"VERBOSE=1 run did not reach the program: {log[:400]!r}")
    if len(lines) < 8:
        bad.append(f"VERBOSE=1 printed only {len(lines)} loader lines, expected "
                   f"at least 8 - the switch is not wired up")

    # 3. KEEP=1 must leave the dropped runtime behind for inspection, and the
    #    normal run must clean it up again.
    res = _execute(guarded, {"CPYTHONIZER_ONEFILE_VERBOSE": "1",
                             "CPYTHONIZER_ONEFILE_KEEP": "1"})
    kept = _temp_folder_of(_log(res))
    if kept is None or not kept.is_dir():
        bad.append(f"KEEP=1 did not leave a temp folder (path was {kept})")
    else:
        if MARKER not in res.stdout:
            bad.append("KEEP=1 run did not reach the program")
        import shutil
        shutil.rmtree(kept, ignore_errors=True)
    quiet = _temp_folder_of(_log(_execute(guarded, {"CPYTHONIZER_ONEFILE_VERBOSE": "1"})))
    if quiet is not None and quiet.is_dir():
        bad.append(f"temp folder {quiet} survived a normal run")

    # 4. anti-dump blanks SizeOfImage in the *mapped* image at run time - the
    #    dropped stub has to keep a valid one or Windows will not load it - so
    #    the switch is observed through the loader's own report.
    guarded_log = _log(_execute(guarded, {"CPYTHONIZER_ONEFILE_VERBOSE": "1"}))
    noad_log = _log(_execute(noad, {"CPYTHONIZER_ONEFILE_VERBOSE": "1"}))
    if "anti-dump: SizeOfImage -> 0" not in guarded_log:
        bad.append("default build never reported blanking SizeOfImage")
    if "anti-dump: SizeOfImage -> 0" in noad_log:
        bad.append("--no-antidump blanked SizeOfImage anyway")
    for label, path in (("guard", ROOT / "build" / "onefile_ZGuard" / "ZGuard.exe"),
                        ("no-antidump", ROOT / "build" / "onefile_ZNoAd" / "ZNoAd.exe")):
        if not path.is_file():
            bad.append(f"{label}: missing dropped stub {path}")
            continue
        if pe_size_of_image(path) == 0:
            bad.append(f"{label}: the dropped stub has SizeOfImage 0, so Windows "
                       f"cannot even load it")

    # 5. the guard must keep the crypto provider out of the import table
    off_dlls = pe_imported_dlls(off)
    guard_dlls = pe_imported_dlls(guarded)
    if "bcrypt.dll" not in off_dlls:
        bad.append(f"guard off still hides bcrypt.dll (imports: {sorted(off_dlls)})")
    if "bcrypt.dll" in guard_dlls:
        bad.append("guard full left bcrypt.dll in the import table")
    return bad


def test_zombie_switches():
    problems = check()
    skipped = [p for p in problems if p.startswith("skip:")]
    if skipped:
        print(skipped[0])
        return
    assert not problems, "\n".join(problems)


def main() -> int:
    problems = check()
    for problem in problems:
        print(problem)
    if any(p.startswith("skip:") for p in problems):
        return 0
    print("FAIL" if problems else "ok: zombie loader and its switches behave")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
