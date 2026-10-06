"""Third-party package dependency scanner and bundler for CPythonizer."""
from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path


def scan_imports(files: list[Path] | Path, exclude_names: set[str] | None = None) -> set[str]:
    """Scan entry and local files for top-level module imports using AST."""
    if isinstance(files, Path):
        file_list = [files]
    else:
        file_list = list(files)

    imported: set[str] = set()
    for f in file_list:
        if not f.is_file():
            continue
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    imported.add(top)
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.level == 0:
                    top = node.module.split(".")[0]
                    imported.add(top)

    # Exclude standard library modules, built-ins, and local module names
    stdlib = getattr(sys, "stdlib_module_names", set())
    builtins = set(sys.builtin_module_names)
    exclude = (exclude_names or set()) | stdlib | builtins
    custom = {name for name in imported if name not in exclude}
    return custom


RESOLVE_SCRIPT = r"""
import importlib.metadata
import json
import re
import sys

modules = sys.argv[1:]
distributions = importlib.metadata.packages_distributions()

to_resolve = set()
for mod in modules:
    if mod in distributions:
        to_resolve.update(distributions[mod])
    else:
        # Maybe the module name is already the distribution name
        try:
            importlib.metadata.distribution(mod)
            to_resolve.add(mod)
        except Exception:
            pass

resolved = set()
queue = list(to_resolve)

while queue:
    dist = queue.pop(0)
    canonical = re.sub(r"[-_.]+", "-", dist).lower()
    if canonical in resolved:
        continue
    resolved.add(canonical)

    try:
        reqs = importlib.metadata.requires(dist) or []
    except Exception:
        continue

    for r in reqs:
        # Ignore extra requirements (e.g. extra == "socks")
        if "extra" in r:
            continue
        # Extract package name before any version specifier
        name = re.split(r"[<>=!~; ]", r.strip())[0].strip()
        if name:
            queue.append(name)

# Map canonical names back to actual installed distribution objects and their files
result_files = {}
for dist_name in resolved:
    try:
        d = importlib.metadata.distribution(dist_name)
    except Exception:
        continue
    
    files = []
    if d.files:
        for f in d.files:
            try:
                p = f.locate()
                if p.is_file():
                    # relative path inside site-packages
                    files.append((str(f), str(p)))
            except Exception:
                continue
    if files:
        result_files[d.metadata["Name"]] = files

print(json.dumps(result_files))
"""


def collect_packages(python_exe: Path, module_names: set[str]) -> dict[str, list[tuple[str, str]]]:
    """Given module names, resolve and collect distribution files using Python 3.14."""
    if not module_names:
        return {}

    r = subprocess.run(
        [str(python_exe), "-c", RESOLVE_SCRIPT, *sorted(module_names)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if r.returncode != 0 or not r.stdout.strip():
        return {}

    try:
        data = json.loads(r.stdout.strip())
        return {k: [(rel, src) for rel, src in v] for k, v in data.items()}
    except Exception:
        return {}


def stage_third_party(dev, out_dir: Path, packages_dict: dict[str, list[tuple[str, str]]]) -> int:
    """Copy all resolved third-party files into <out_dir>/site-packages/ and write python314._pth."""
    if not packages_dict:
        return 0

    site_dir = out_dir / "site-packages"
    site_dir.mkdir(parents=True, exist_ok=True)
    count = 0

    for dist_name, files in packages_dict.items():
        for rel_str, src_str in files:
            src = Path(src_str)
            if not src.is_file():
                continue
            dest = site_dir / Path(rel_str)
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(src, dest)
                count += 1
            except Exception:
                pass
        print(f"  + {dist_name} ({len(files)} files staged in site-packages)")

    # Ensure python314._pth is present so embedded Python searches site-packages
    pth_file = out_dir / f"python{dev.ver}._pth"
    pth_content = f"python{dev.ver}.zip\n.\nsite-packages\n"
    pth_file.write_text(pth_content, encoding="utf-8")
    print(f"  + {pth_file.name} configured with site-packages")
    return count
