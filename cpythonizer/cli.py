"""Command line: cpythonizer doctor / vs-build."""
from __future__ import annotations

import argparse


def _vs_choices() -> list[str]:
    """'auto' plus every supported Visual Studio year (2026, 2022, ...)."""
    from .vs import RELEASES
    return ["auto"] + [r.year for r in RELEASES]


def cmd_doctor(args: argparse.Namespace) -> int:
    """Check the environment (Python 3.14 + Visual Studio), optionally installing missing parts."""
    from .python_env import ensure_python314, find_python314, PyDev
    from .vs import ensure_vs, find_vs, find_vswhere, get_vcvarsall

    print("== CPythonizer doctor (Python 3.14 + VS) ==")
    py = find_python314()
    print(f"Python 3.14 : {py if py else 'MISSING'}")
    vw = find_vswhere()
    print(f"vswhere.exe : {vw if vw else 'MISSING'}")
    vs = find_vs(args.vs)
    print(f"VS          : {vs if vs else 'MISSING'}"
          + (f" (requested {args.vs})" if args.vs != "auto" else ""))
    print(f"vcvarsall   : {get_vcvarsall(vs) if vs else 'MISSING'}")

    if args.install_python:
        py = ensure_python314(auto_install=True)
    if args.install_vs:
        vs = ensure_vs(args.vs, auto_install=True)

    if py is not None:
        try:
            dev = PyDev(py)
            dev.check()
            print(f"Python.h   : OK ({dev.include / 'Python.h'})")
            print(f"python lib : OK ({dev.lib_file()})")
            print("runtime    : " + ", ".join(p.name for p in dev.runtime_dlls()))
        except (FileNotFoundError, RuntimeError) as e:
            print(f"Python dev files issue: {e}")
            return 2
    ok = (py is not None) and (vs is not None)
    print("\nResult:", "READY" if ok else "MISSING (apply the fixes above)")
    return 0 if ok else 1


def cmd_vs_build(args: argparse.Namespace) -> int:
    """Cython-transpile to C, wrap in a VS project, compile with MSBuild."""
    from .cython_vs import build as vs_build

    out = vs_build(
        entry=args.entry,
        name=args.name,
        dist=args.dist,
        vs=args.vs,
        embed=getattr(args, "embed", True),
        onefile=getattr(args, "onefile", False),
        icon=getattr(args, "icon", None),
        include_packages=getattr(args, "include_packages", None),
        release=getattr(args, "release", False),
        noconsole=getattr(args, "noconsole", False),
        keep_pdb=getattr(args, "keep_pdb", False),
    )
    print(out)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser (doctor + vs-build subcommands)."""
    p = argparse.ArgumentParser(
        prog="cpythonizer",
        description="Python 3.14 -> Cython C -> Visual Studio 2026/2022 EXE+PDB.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor", help="Check env + optional automatic setup")
    d.add_argument("--install-python", action="store_true", help="Auto-install Python 3.14 if missing")
    d.add_argument("--install-vs", action="store_true", help="Auto-install Visual Studio Build Tools if missing")
    d.add_argument("--vs", default="auto", choices=_vs_choices(),
                   help="Visual Studio version to require (default: auto = newest installed)")
    d.set_defaults(func=cmd_doctor)

    v = sub.add_parser("vs-build", help="Cython --embed -> VS project -> MSBuild EXE+PDB")
    v.add_argument("entry", help="Entry .py file (e.g. main.py)")
    v.add_argument("--name", default=None, help="App/EXE/Project name (default: file name)")
    v.add_argument("--dist", default="dist", help="Output root folder (default: dist)")
    v.add_argument("--vs", default="auto", choices=_vs_choices(),
                   help="Visual Studio version to build with (default: auto = newest installed)")
    v.add_argument("--embed", action=argparse.BooleanOptionalAction, default=True,
                   help="Generate embedded main() entrypoint via cython --embed (default: True)")
    v.add_argument("--onefile", action="store_true",
                   help="Ship one self-extracting EXE: unpacks to a random %%TEMP%% folder, runs under its original name, cleans up")
    v.add_argument("--icon", default=None,
                   help="Application icon file (.ico or .png; PNG files are converted automatically)")
    v.add_argument("--include-package", "--package", dest="include_packages", action="append", default=[],
                   help="Third-party package to include (e.g. --include-package requests)")
    v.add_argument("--release", action="store_true", default=False,
                   help="Release build: strip debug symbols / PDB, apply max compiler optimizations and Cython speedups")
    v.add_argument("--keep-pdb", action="store_true", default=False,
                   help="Retain debug symbols (.pdb) even when building with --release")
    v.add_argument("--noconsole", "--windowed", dest="noconsole", action="store_true", default=False,
                   help="Hide the black console window at startup (for GUI apps like Tkinter, PyQt)")
    v.set_defaults(func=cmd_vs_build)
    return p


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
