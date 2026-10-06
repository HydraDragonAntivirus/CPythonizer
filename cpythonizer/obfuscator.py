"""Obfuscator utilities for CPythonizer.

Features:
  - Safe inline and standalone comment stripper (tokenize-based)
  - AST-based function name randomizer
  - Randomized decoy step comment injector
  - Base64 exec source code encryptor / wrapper (Encrypt class)
"""
from __future__ import annotations

import ast
import base64
import io
from pathlib import Path
import random
import string
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
    """Read a Python file, remove inline and standalone comments, and optionally write back."""
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


class _FunctionRenamer(ast.NodeTransformer):
    """AST transformer that safely randomizes function definitions and references."""

    def __init__(self, skip_names: set[str] | None = None, only_private: bool = False):
        self.skip_names = set(skip_names or []) | {"main"}
        self.only_private = only_private
        self.mapping: dict[str, str] = {}
        self._in_class = False

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        prev = self._in_class
        self._in_class = True
        self.generic_visit(node)
        self._in_class = prev
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        is_dunder = node.name.startswith("__") and node.name.endswith("__")
        matches_privacy = (not self.only_private) or (node.name.startswith("_") and not is_dunder)
        if not is_dunder and not self._in_class and node.name not in self.skip_names and matches_privacy:
            if node.name not in self.mapping:
                rand_suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
                self.mapping[node.name] = f"_cpx_fn_{rand_suffix}"
            node.name = self.mapping[node.name]

        self.generic_visit(node)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        return self.visit_FunctionDef(node)  # type: ignore

    def visit_Name(self, node: ast.Name) -> ast.Name:
        if node.id in self.mapping:
            node.id = self.mapping[node.id]
        return node


def randomize_function_names(source: str, skip_names: set[str] | None = None,
                             only_private: bool = False) -> tuple[str, dict[str, str]]:
    """Randomize original non-dunder function names via AST.

    Returns:
        (transformed_source_code, mapping_dict)
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source, {}

    renamer = _FunctionRenamer(skip_names=skip_names, only_private=only_private)
    new_tree = renamer.visit(tree)
    ast.fix_missing_locations(new_tree)
    return ast.unparse(new_tree), renamer.mapping


def add_random_comments(source: str) -> str:
    """Insert randomized decoy comment lines before statements in code."""
    try:
        tree = ast.parse(source)
    except Exception:
        return source

    lines = source.splitlines(keepends=True)
    stmt_lines = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.stmt) and hasattr(node, "lineno"):
            stmt_lines.add(node.lineno)

    new_lines: list[str] = []
    for line_idx, line in enumerate(lines, start=1):
        if line_idx in stmt_lines and line.strip():
            indent = line[:len(line) - len(line.lstrip())]
            tag = "".join(random.choices(string.ascii_letters + string.digits, k=10))
            new_lines.append(f"{indent}# [cpx-step: {tag}]\n")
        new_lines.append(line)
    return "".join(new_lines)


def obfuscate_source(source: str, rename_funcs: bool = True,
                     add_comments: bool = True,
                     skip_names: set[str] | None = None,
                     only_private: bool = False) -> str:
    """Full obfuscation pipeline:

    1. Strip all inline and line comments
    2. Randomize function names via AST (if rename_funcs=True)
    3. Add randomized decoy step comments (if add_comments=True)
    """
    # Step 1: Strip existing comments
    cleaned = strip_comments(source)

    # Step 2: Randomize function names via AST
    if rename_funcs:
        cleaned, _ = randomize_function_names(cleaned, skip_names=skip_names, only_private=only_private)

    # Step 3: Add randomized comment lines for each step
    if add_comments:
        cleaned = add_random_comments(cleaned)

    return cleaned


class Encrypt:
    """AES-256-CBC source code encryptor/packer."""

    def __init__(self):
        self.YELLOW, self.GREEN = '\33[93m', '\033[1;32m'
        self.text = ""
        self.enc_txt = ""

    def generate_key_iv(self) -> tuple[bytes, bytes]:
        try:
            from Crypto.Random import get_random_bytes
            key = get_random_bytes(32)  # 256-bit anahtar
            iv = get_random_bytes(16)   # 128-bit IV
        except Exception:
            import os
            key = os.urandom(32)
            iv = os.urandom(16)
        return key, iv

    def encrypt_text(self, text: str, key: bytes, iv: bytes) -> bytes:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(text.encode("utf-8"), AES.block_size))
        return base64.b64encode(iv + ciphertext)

    def encrypt(self, filename: str | Path):
        print(f"\n{self.YELLOW}[*] Encrypting Source Codes...")
        filename = str(filename)
        self.text = ""
        with open(filename, "r", encoding="utf-8") as f:
            lines_list = f.readlines()
            for lines in lines_list:
                self.text += lines

            key, iv = self.generate_key_iv()
            self.enc_txt = self.encrypt_text(self.text, key, iv)

        with open(filename, "w", encoding="utf-8") as f:
            f.write(
                f"from Crypto.Cipher import AES\n"
                f"from Crypto.Util.Padding import unpad\n"
                f"import base64\n\n"
                f"def decrypt_text(encrypted_text, key):\n"
                f"    encrypted_text = base64.b64decode(encrypted_text)\n"
                f"    iv = encrypted_text[:16]\n"
                f"    ciphertext = encrypted_text[16:]\n"
                f"    cipher = AES.new(key, AES.MODE_CBC, iv)\n"
                f"    decrypted_text = unpad(cipher.decrypt(ciphertext), AES.block_size)\n"
                f"    return decrypted_text.decode()\n\n"
                f"key = {key}\n\n"
                f"exec(decrypt_text({self.enc_txt}, key))\n"
            )

        print(f"{self.GREEN}[+] Operation Completed Successfully!\n")


if __name__ == '__main__':
    test = Encrypt()
    filename = input("Please Enter Filename: ")
    test.encrypt(filename)
