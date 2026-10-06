"""Obfuscator utilities for CPythonizer.

Provides safe comment stripping, inline comment removal, and source pre-processing
prior to Cython transpilation.
"""
from __future__ import annotations

import io
from pathlib import Path
import tokenize


def strip_comments(source: str) -> str:
    """Safely strip all comments (inline and standalone) from Python source code.

    Uses Python's tokenize module so that '#' inside strings, raw strings,
    multiline docstrings, and regexes are completely preserved.
    """
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError):
        return _fallback_strip_comments(source)

    line_comments: dict[int, list[int]] = {}
    for tok in tokens:
        if tok.type == tokenize.COMMENT:
            sline, scol = tok.start
            line_comments.setdefault(sline, []).append(scol)

    lines = source.splitlines(keepends=True)
    new_lines: list[str] = []
    for line_no, line in enumerate(lines, start=1):
        if line_no in line_comments:
            first_comment_col = min(line_comments[line_no])
            prefix = line[:first_comment_col].rstrip()
            if prefix.strip():
                new_lines.append(prefix + "\n")
        else:
            new_lines.append(line)
    return "".join(new_lines)


def _fallback_strip_comments(source: str) -> str:
    """Line-based comment stripper used if tokenizer encounters syntax/indent errors."""
    lines = source.splitlines(keepends=True)
    new_lines: list[str] = []
    for line in lines:
        quote_count = line.count('"') + line.count("'")
        if '#' in line and quote_count % 2 == 0:
            parts = line.split('#', 1)
            line = parts[0].rstrip() + '\n'
        if line.strip():
            new_lines.append(line)
    return "".join(new_lines)


def remove_inline_comments(filename: str | Path, in_place: bool = False,
                           out_file: str | Path | None = None) -> str:
    """Read a Python file, remove inline and standalone comments, and optionally write back.

    Args:
        filename: Path to the Python source file.
        in_place: If True, overwrite the source file with cleaned content.
        out_file: If provided, write the cleaned content to this file path.

    Returns:
        The cleaned source string.
    """
    path = Path(filename).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Source file not found: {path}")

    source = path.read_text(encoding="utf-8")
    cleaned = strip_comments(source)

    if in_place:
        path.write_text(cleaned, encoding="utf-8")
    elif out_file:
        Path(out_file).resolve().write_text(cleaned, encoding="utf-8")

    return cleaned
