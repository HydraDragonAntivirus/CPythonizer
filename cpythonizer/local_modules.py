"""Local / self module scanner and Cython transpiler for CPythonizer."""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
import re
import subprocess
import sys
import uuid


@dataclass
class LocalModule:
    """Represents a discovered local Python module to be compiled into a .pyd."""
    mod_name: str          # e.g. "utils", "core.network", "core.__init__"
    source_py: Path        # e.g. C:/app/core/network.py
    target_rel_dir: Path   # e.g. Path("core") or Path("")
    target_stem: str       # e.g. "network" or "utils" or "__init__"
    guid: str
    c_file: Path | None = None

    @property
    def safe_name(self) -> str:
        return re.sub(r"[^a-zA-Z0-9_]+", "_", self.mod_name)

    @property
    def proj_name(self) -> str:
        return f"mod_{self.safe_name}"


def find_project_root(entry_file: Path) -> Path:
    """Find the top-level project root directory containing the entry file."""
    cur = entry_file.parent.resolve()
    # If entry file is inside a package (folder with __init__.py), walk up to package root
    while (cur / "__init__.py").is_file() and cur.parent != cur:
        cur = cur.parent
    return cur


def extract_imports_from_file(py_file: Path) -> list[tuple[str, int]]:
    """Parse AST and return list of (imported_name, relative_level)."""
    if not py_file.is_file():
        return []

    try:
        tree = ast.parse(py_file.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []

    results: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                results.append((alias.name, 0))
        elif isinstance(node, ast.ImportFrom):
            level = node.level
            mod = node.module or ""
            if mod:
                results.append((mod, level))
            for alias in node.names:
                full = f"{mod}.{alias.name}" if mod else alias.name
                results.append((full, level))
    return results


def _get_module_name(file_path: Path, project_root: Path) -> str:
    """Compute the dotted Python module name for a file relative to project_root."""
    try:
        rel = file_path.resolve().relative_to(project_root.resolve())
    except ValueError:
        if file_path.name == "__init__.py":
            return file_path.parent.name
        return file_path.stem

    parts = list(rel.parts)
    if parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]
    return ".".join(parts)


def resolve_import_target(name: str, level: int, current_file: Path,
                          project_root: Path) -> tuple[str, Path] | None:
    """Given an import name and level, check if it corresponds to a local .py file.

    Returns (dotted_module_name, file_path) if found, else None.
    """
    top = name.split(".")[0]
    stdlib = getattr(sys, "stdlib_module_names", set())
    builtins = set(sys.builtin_module_names)
    if level == 0 and (top in stdlib or top in builtins):
        return None

    search_dirs: list[Path] = []
    if level == 0:
        # Search relative to current file's directory first, then project_root
        search_dirs.append(current_file.parent.resolve())
        pr = project_root.resolve()
        if pr not in search_dirs:
            search_dirs.append(pr)
    else:
        # Relative import
        base = current_file.parent.resolve()
        for _ in range(level - 1):
            base = base.parent
        search_dirs.append(base)

    parts = [p for p in name.split(".") if p]
    for search_dir in search_dirs:
        # 1. Exact module: search_dir / parts... / "part.py"
        if parts:
            cand_file = search_dir.joinpath(*parts).with_suffix(".py")
            if cand_file.is_file():
                mod_name = _get_module_name(cand_file, project_root)
                return mod_name, cand_file

            # 2. Package: search_dir / parts... / "__init__.py"
            cand_pkg = search_dir.joinpath(*parts, "__init__.py")
            if cand_pkg.is_file():
                mod_name = _get_module_name(cand_pkg, project_root)
                return mod_name, cand_pkg

            # 3. Truncate parts (in case name is module.function or package.module.attribute)
            for i in range(len(parts) - 1, 0, -1):
                sub_parts = parts[:i]
                cand = search_dir.joinpath(*sub_parts).with_suffix(".py")
                if cand.is_file():
                    mod_name = _get_module_name(cand, project_root)
                    return mod_name, cand
                cand_sub_pkg = search_dir.joinpath(*sub_parts, "__init__.py")
                if cand_sub_pkg.is_file():
                    mod_name = _get_module_name(cand_sub_pkg, project_root)
                    return mod_name, cand_sub_pkg

    return None


def scan_local_modules(entry_file: Path) -> list[LocalModule]:
    """Scan entry_file and recursively discover all local Python modules imported by the project."""
    entry_file = entry_file.resolve()
    project_root = find_project_root(entry_file)

    discovered: dict[str, Path] = {}
    visited_files: set[Path] = {entry_file}
    queue: list[Path] = [entry_file]

    while queue:
        cur_file = queue.pop(0)
        imports = extract_imports_from_file(cur_file)
        for name, level in imports:
            resolved = resolve_import_target(name, level, cur_file, project_root)
            if resolved is None:
                continue
            mod_name, mod_path = resolved
            mod_path = mod_path.resolve()
            if mod_path == entry_file:
                continue

            # If it's a package directory (__init__.py), also discover all other .py files in that package
            if mod_path.name == "__init__.py":
                pkg_dir = mod_path.parent
                for py_in_pkg in sorted(pkg_dir.rglob("*.py")):
                    py_in_pkg = py_in_pkg.resolve()
                    if (py_in_pkg == entry_file or py_in_pkg in visited_files or
                            any(p.startswith(".") or p == "__pycache__" for p in py_in_pkg.parts)):
                        continue
                    pkg_mod_name = _get_module_name(py_in_pkg, project_root)
                    if pkg_mod_name not in discovered:
                        discovered[pkg_mod_name] = py_in_pkg
                        visited_files.add(py_in_pkg)
                        queue.append(py_in_pkg)

            if mod_name not in discovered and mod_path not in visited_files:
                discovered[mod_name] = mod_path
                visited_files.add(mod_path)
                queue.append(mod_path)

    modules: list[LocalModule] = []
    for mod_name, src_py in discovered.items():
        if src_py.name == "__init__.py":
            target_stem = "__init__"
            parts = mod_name.split(".")
            if parts[-1] == "__init__":
                parts = parts[:-1]
            target_rel_dir = Path(*parts) if parts else Path("")
        else:
            parts = mod_name.split(".")
            target_stem = parts[-1]
            target_rel_dir = Path(*parts[:-1]) if len(parts) > 1 else Path("")

        guid = str(uuid.uuid4()).upper()
        modules.append(LocalModule(
            mod_name=mod_name,
            source_py=src_py,
            target_rel_dir=target_rel_dir,
            target_stem=target_stem,
            guid=guid,
        ))

    return modules


def cythonize_local_module(python_exe: Path, mod: LocalModule, workdir: Path,
                           release: bool = False) -> Path:
    """Transpile a local module to C using Cython."""
    workdir.mkdir(parents=True, exist_ok=True)
    out_c = workdir / f"local_{mod.safe_name}.c"
    print(f"[cpythonizer] Cython transpiling local module: {mod.mod_name} -> {out_c.name}")
    cmd = [str(python_exe), "-m", "cython", "-3", "--module-name", mod.mod_name]
    if release:
        cmd.extend([
            "-X", "boundscheck=False",
            "-X", "wraparound=False",
            "-X", "initializedcheck=False",
            "-X", "cdivision=True",
        ])
    cmd.extend(["--output-file", str(out_c), str(mod.source_py)])
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if r.returncode != 0 or not out_c.is_file():
        raise RuntimeError(f"Cython failed for {mod.mod_name}:\n{r.stdout}\n{r.stderr}")
    mod.c_file = out_c
    return out_c


PYD_VCXPROJ_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
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
    <ConfigurationType>DynamicLibrary</ConfigurationType>
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
    <TargetExt>.pyd</TargetExt>
    <GenerateDebugInformation>{GENERATE_DEBUG}</GenerateDebugInformation>
  </PropertyGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <ClCompile>
      <WarningLevel>Level3</WarningLevel>
      <Optimization>MaxSpeed</Optimization>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <IntrinsicFunctions>true</IntrinsicFunctions>
      <SDLCheck>true</SDLCheck>
      <PreprocessorDefinitions>NDEBUG;_WINDOWS;_USRDLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <ConformanceMode>true</ConformanceMode>
      <LanguageStandard>stdcpp17</LanguageStandard>
      <AdditionalIncludeDirectories>{INCLUDE};%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
      <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
      <DebugInformationFormat>{DEBUG_FORMAT}</DebugInformationFormat>
    </ClCompile>
    <Link>
      <SubSystem>Windows</SubSystem>
      <GenerateDebugInformation>{GENERATE_DEBUG}</GenerateDebugInformation>
      <EnableCOMDATFolding>true</EnableCOMDATFolding>
      <OptimizeReferences>true</OptimizeReferences>
      <AdditionalLibraryDirectories>{LIBDIR};%(AdditionalLibraryDirectories)</AdditionalLibraryDirectories>
      <AdditionalDependencies>{LIBNAME};kernel32.lib;user32.lib;advapi32.lib;ws2_32.lib;version.lib;shlwapi.lib;ole32.lib;shell32.lib;%(AdditionalDependencies)</AdditionalDependencies>
    </Link>
  </ItemDefinitionGroup>
  <ItemGroup>
    <ClCompile Include="{CFILE}" />
  </ItemGroup>
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.targets" />
  <ImportGroup Label="ExtensionTargets" />
</Project>
"""


def generate_local_pyd_project(workdir: Path, mod: LocalModule, stage_dir: Path,
                               include_dir: Path, lib_dir: Path, lib_name: str,
                               release, release_mode: bool = False,
                               keep_pdb: bool = False) -> Path:
    """Generate a .vcxproj file for a single local .pyd module."""
    out_dir = stage_dir / mod.target_rel_dir
    int_dir = workdir / f"obj_{mod.safe_name}"
    generate_debug = "true" if (keep_pdb or not release_mode) else "false"
    debug_format = "ProgramDatabase" if (keep_pdb or not release_mode) else "None"

    proj = PYD_VCXPROJ_TEMPLATE.format(
        GUID="{" + mod.guid + "}",
        NAME=mod.target_stem,
        PROJECT_VERSION=release.project_version,
        TOOLSET=release.toolset,
        OUTDIR=str(out_dir),
        INTDIR=str(int_dir),
        INCLUDE=str(include_dir),
        LIBDIR=str(lib_dir),
        LIBNAME=lib_name,
        CFILE=str(mod.c_file),
        GENERATE_DEBUG=generate_debug,
        DEBUG_FORMAT=debug_format,
    )
    vcxproj = workdir / f"{mod.proj_name}.vcxproj"
    vcxproj.write_text(proj, encoding="utf-8")
    return vcxproj
