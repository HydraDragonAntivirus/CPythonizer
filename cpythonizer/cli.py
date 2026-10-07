"""Command line: cpythonizer doctor / vs-build."""
from __future__ import annotations

import argparse
from pathlib import Path


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

    compress = "lzma2" if (getattr(args, "lzma2", False) or getattr(args, "compress", None) == "lzma2") else "none"
    zombie = getattr(args, "zombie", False)
    out = vs_build(
        entry=args.entry,
        name=args.name,
        dist=args.dist,
        vs=args.vs,
        embed=getattr(args, "embed", True),
        onefile=getattr(args, "onefile", False) or zombie,
        icon=getattr(args, "icon", None),
        include_packages=getattr(args, "include_packages", None),
        release=getattr(args, "release", False),
        noconsole=getattr(args, "noconsole", False),
        keep_pdb=getattr(args, "keep_pdb", False),
        compress=compress,
        lzma_preset=getattr(args, "lzma_preset", 9),
        lzma_extreme=getattr(args, "lzma_extreme", True),
        encrypt=getattr(args, "encrypt", True),
        obfuscate=getattr(args, "obfuscate", False),
        zombie=zombie,
        antidump=getattr(args, "antidump", True),
        guard=getattr(args, "guard", "off"),
        add_data=getattr(args, "add_data", None),
        hide_console=getattr(args, "hide_console", False),
    )
    print(out)
    return 0


def cmd_obfuscate(args: argparse.Namespace) -> int:
    """Obfuscate a Python source file."""
    import shutil
    from .obfuscator import strip_comments, randomize_function_names, add_random_comments, Encrypt

    src_path = Path(args.file).resolve()
    if not src_path.is_file():
        print(f"Error: File not found: {src_path}")
        return 1

    if args.aes:
        enc = Encrypt()
        if args.in_place:
            enc.encrypt(src_path)
        else:
            out_target = Path(args.out).resolve() if args.out else src_path.with_name(f"{src_path.stem}_aes.py")
            shutil.copy2(src_path, out_target)
            enc.encrypt(out_target)
            if not args.out:
                print(f"[cpythonizer] AES encrypted file written: {out_target}")
        return 0

    if args.b64:
        enc = Encrypt()
        if args.in_place:
            enc.encrypt(src_path)
        else:
            out_target = Path(args.out).resolve() if args.out else src_path.with_name(f"{src_path.stem}_enc.py")
            shutil.copy2(src_path, out_target)
            enc.encrypt(out_target)
            if not args.out:
                print(f"[cpythonizer] Base64 encoded file written: {out_target}")
        return 0

    code = src_path.read_text(encoding="utf-8")
    code = strip_comments(code)

    if args.rename_funcs or args.all:
        code, mapping = randomize_function_names(code)
        if mapping:
            print(f"[cpythonizer] Randomized {len(mapping)} function(s) via AST: {', '.join(mapping.keys())}")

    if args.random_comments or args.all:
        code = add_random_comments(code)

    if args.in_place:
        src_path.write_text(code, encoding="utf-8")
        print(f"[cpythonizer] Obfuscated (in-place): {src_path}")
    elif args.out:
        Path(args.out).resolve().write_text(code, encoding="utf-8")
        print(f"[cpythonizer] Obfuscated: {args.out}")
    else:
        print(code, end="")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser (doctor + vs-build + obfuscate subcommands)."""
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
    v.add_argument("--zombie", action="store_true",
                   help="Zombie loader (implies --onefile): the runtime is dropped to %%TEMP%%, but the program "
                        "itself is mapped in RAM and NEVER written to disk - the dropped EXE is an empty shell")
    v.add_argument("--no-antidump", dest="antidump", action="store_false", default=True,
                   help="Zombie mode: keep SizeOfImage intact instead of blanking it (anti-dump off)")
    v.add_argument("--guard", choices=["off", "basic", "full"], default="off",
                   help="Zombie mode: obfuscate the loader itself - 'basic' hides every fingerprinting "
                        "string and guards the two decrypt sites with the anti-debug probe set, 'full' "
                        "adds the hardware-breakpoint probe and fake protector sections (default: off)")
    v.add_argument("--encrypt", action=argparse.BooleanOptionalAction, default=True,
                   help="Encrypt onefile payload with per-build random AES-256 key (default: True, use --no-encrypt to disable)")
    v.add_argument("--lzma2", action="store_true", default=False,
                   help="Compress onefile payload with LZMA2 for maximum compression / minimum EXE size")
    v.add_argument("--compress", choices=["none", "lzma2"], default=None,
                   help="Onefile compression algorithm (none or lzma2)")
    v.add_argument("--lzma-preset", type=int, choices=range(0, 10), default=9,
                   help="LZMA2 compression preset level (0-9, default: 9)")
    v.add_argument("--lzma-extreme", action=argparse.BooleanOptionalAction, default=True,
                   help="Enable/disable LZMA2 extreme preset for extra compression ratio (default: True)")
    v.add_argument("--obfuscate", action="store_true", default=False,
                   help="Obfuscator: Strip comments, randomize function names via AST, and inject random step comments")
    v.add_argument("--icon", default=None,
                   help="Application icon file (.ico or .png; PNG files are converted automatically)")
    v.add_argument("--include-package", "--package", dest="include_packages", action="append", default=[],
                   help="Third-party package to include (e.g. --include-package requests)")
    v.add_argument("--add-data", dest="add_data", action="append", default=[], metavar="SRC;DEST",
                   help="Bundle a file or folder, PyInstaller style. Repeatable; "
                        "DEST is relative to the app folder (use '.' for the root). "
                        'e.g. --add-data "logo.png;." --add-data "assets;images"')
    v.add_argument("--release", action="store_true", default=False,
                   help="Release build: strip debug symbols / PDB, apply max compiler optimizations and Cython speedups")
    v.add_argument("--keep-pdb", action="store_true", default=False,
                   help="Retain debug symbols (.pdb) even when building with --release")
    v.add_argument("--noconsole", "--windowed", dest="noconsole", action="store_true", default=False,
                   help="Hide the black console window at startup (for GUI apps like Tkinter, PyQt)")
    v.add_argument("--hide-console", action="store_true", default=False,
                   help="Stop child processes from flashing a console window: hide the console "
                        "rather than removing it, so children inherit the hidden one. Combine "
                        "with --noconsole to keep the GUI subsystem too (recommended for GUI apps)")
    v.set_defaults(func=cmd_vs_build)

    o = sub.add_parser("obfuscate", help="Obfuscate Python source files")
    o.add_argument("file", help="Python source file to obfuscate")
    o.add_argument("--in-place", "-i", action="store_true", default=False,
                   help="Modify file in-place")
    o.add_argument("--out", "-o", default=None,
                   help="Output file path (default: stdout)")
    o.add_argument("--rename-funcs", action="store_true", default=False,
                   help="Randomize function names via AST")
    o.add_argument("--random-comments", action="store_true", default=False,
                   help="Insert randomized decoy comment lines for each step")
    o.add_argument("--all", "-a", action="store_true", default=False,
                   help="Apply all steps: strip comments + rename functions + insert random step comments")
    o.add_argument("--aes", action="store_true", default=False,
                   help="Encrypt file with AES-256-CBC + Base64 self-decrypting wrapper (Encrypt class)")
    o.add_argument("--b64", "--base64", dest="b64", action="store_true", default=False,
                   help="Wrap file in base64 exec encoding")
    o.set_defaults(func=cmd_obfuscate)
    return p


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
