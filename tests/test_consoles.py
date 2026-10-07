"""--hide-console: the injected snippet has to match the flags and find its anchor.

Fast, no build. The behaviour it protects is subtle enough to be worth pinning
down: an injection that silently fails to apply would ship a build whose console
behaviour is the opposite of what was asked for, and the symptom (a window that
flashes on every navigation) only shows up in the packaged app.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cpythonizer.consoles import (  # noqa: E402
    console_policy_code, inject_console_policy,
)

# Shaped like the two things that get patched: Cython's #if-selected entry point
# and the loaders' own stub.
CYTHON_C = """\
#include "Python.h"
static int __Pyx_main(int argc, char **argv)
#elif defined(_WIN32)
int wmain(int argc, wchar_t **argv)
#else
static int __Pyx_main(int argc, wchar_t **argv)
#endif
{
    return 0;
}
"""
STUB_C = """\
#include <windows.h>
int wmain(int argc, wchar_t **argv)
{
    return 0;
}
"""


def test_policy_per_flag_combination():
    assert console_policy_code(False, False) == ""
    assert "ShowWindow" in console_policy_code(False, True)
    assert "ShowWindow" not in console_policy_code(True, False)
    combined = console_policy_code(True, True)
    assert "AllocConsole" in combined, (
        "GUI subsystem has no console, so the combined mode has to make one for "
        "child processes to inherit")
    assert "ShowWindow" in combined


def _inject(tmp: Path, source: str, stub: bool) -> str:
    path = tmp / "probe.c"
    path.write_text(source, encoding="utf-8")
    inject_console_policy(path, noconsole=False, hide_console=True, stub=stub)
    return path.read_text(encoding="utf-8")


def test_injects_into_cython_entry_point(tmp_path):
    out = _inject(tmp_path, CYTHON_C, stub=False)
    assert "#include <windows.h>" in out, (
        "the generated C includes only Python.h, which does not declare "
        "GetConsoleWindow or ShowWindow")
    # The call lands after the #if/#else/#endif block that selects the signature,
    # i.e. at the brace of the branch that actually compiles on Windows.
    body = out.split("#endif\n{", 1)[1]
    assert "GetConsoleWindow()" in body.split("return 0;")[0], (
        "the call has to run before the program does anything else")
    assert out.count("GetConsoleWindow()") == 1, (
        "only the branch that compiles gets patched, not every signature")


def test_injects_into_stub_entry_point(tmp_path):
    out = _inject(tmp_path, STUB_C, stub=True)
    assert out.count("GetConsoleWindow()") == 1
    assert "#include <windows.h>" in out


def test_no_injection_without_the_flag(tmp_path):
    path = tmp_path / "probe.c"
    path.write_text(CYTHON_C, encoding="utf-8")
    before = path.read_text(encoding="utf-8")
    assert inject_console_policy(path, noconsole=True, hide_console=False) == ""
    assert path.read_text(encoding="utf-8") == before


def test_missing_anchor_is_an_error(tmp_path):
    path = tmp_path / "probe.c"
    path.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    try:
        inject_console_policy(path, noconsole=False, hide_console=True)
    except RuntimeError as exc:
        assert "--hide-console" in str(exc)
        return
    raise AssertionError("a patch that cannot be applied must fail the build, "
                         "not silently ship a console window")


def test_all():
    test_policy_per_flag_combination()
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        test_injects_into_cython_entry_point(tmp_path)
        test_injects_into_stub_entry_point(tmp_path)
        test_no_injection_without_the_flag(tmp_path)
        test_missing_anchor_is_an_error(tmp_path)


if __name__ == "__main__":
    test_all()
    print("ok: console policy injection")
