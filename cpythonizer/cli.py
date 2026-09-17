"""Command line: cpythonizer doctor / vs-build."""
from __future__ import annotations

import argparse


def cmd_doctor(args: argparse.Namespace) -> int:
    """Check the environment (Python 3.14 + VS2022), optionally installing missing parts."""
    from .python_env import ensure_python314, find_python314, PyDev
    from .vs import ensure_vs2022, find_vs2022, find_vswhere, get_vcvarsall

    print("== CPythonizer doctor (Python 3.14 + VS2022) ==")
    py = find_python314()
    print(f"Python 3.14 : {py if py else 'MISSING'}")
    vw = find_vswhere()
    print(f"vswhere.exe : {vw if vw else 'MISSING'}")
    vs = find_vs2022()
    print(f"VS2022      : {vs if vs else 'MISSING'}")
    print(f"vcvarsall   : {get_vcvarsall(vs) if vs else 'MISSING'}")

    if args.install_python:
        py = ensure_python314(auto_install=True)
    if args.install_vs:
        from .vs import ensure_vs2022 as _ensure
        vs = _ensure(auto_install=True)

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

    out = vs_build(entry=args.entry, name=args.name, dist=args.dist)
    print(out)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser (doctor + vs-build subcommands)."""
    p = argparse.ArgumentParser(
        prog="cpythonizer",
        description="Python 3.14 -> Cython C -> Visual Studio 2022 EXE+PDB.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor", help="Check env + optional automatic setup")
    d.add_argument("--install-python", action="store_true", help="Auto-install Python 3.14 if missing")
    d.add_argument("--install-vs", action="store_true", help="Auto-install VS2022 Build Tools if missing")
    d.set_defaults(func=cmd_doctor)

    v = sub.add_parser("vs-build", help="Cython --embed -> VS2022 project -> MSBuild EXE+PDB")
    v.add_argument("entry", help="Entry .py file (e.g. main.py)")
    v.add_argument("--name", default=None, help="App/EXE/Project name (default: file name)")
    v.add_argument("--dist", default="dist", help="Output root folder (default: dist)")
    v.set_defaults(func=cmd_vs_build)
    return p


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
