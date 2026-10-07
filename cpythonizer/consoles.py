"""Console policy for the built EXE: no window, hidden window, or both.

--noconsole switches the PE to IMAGE_SUBSYSTEM_WINDOWS_GUI. That gives no
console at all, which is the cleanest answer - but a process without a console
hands every console-application child a brand new console window, which is why a
Tkinter app whose screens each shell out once flashes a black rectangle on
every navigation.

--hide-console keeps the console subsystem and hides its window instead, so
children inherit the hidden console rather than allocating a visible one. Its
costs are honest ones: Windows creates the console before main() runs, so the
window can flash once at start-up, and the console object survives, so another
process could attach to it and read what the program printed.

Both flags together are the useful combination, and not a contradiction: the PE
is still GUI (so Windows creates nothing at start-up and sys.stdout stays None,
exactly like --noconsole), and the program allocates one hidden console of its
own so that children have something to inherit.
"""
from __future__ import annotations

from pathlib import Path

# Console subsystem already has one: just take it out of sight.
HIDE_EXISTING_C = """\
/* CPythonizer --hide-console: hide the console window, keep the subsystem. */
    {
        HWND __cp_console = GetConsoleWindow();
        if (__cp_console)
            ShowWindow(__cp_console, SW_HIDE);
    }
"""

# GUI subsystem has none: make one, hidden, so children inherit it instead of
# being given a visible console of their own.
ALLOC_HIDDEN_C = """\
/* CPythonizer --noconsole --hide-console: give the children a console to
   inherit, without ever showing one. */
    {
        if (!GetConsoleWindow() && AllocConsole()) {
            HWND __cp_console = GetConsoleWindow();
            if (__cp_console)
                ShowWindow(__cp_console, SW_HIDE);
        }
    }
"""

# Cython's generated entry point includes Python.h and nothing else, and
# Python.h does not declare the console API, so the Win32 header goes in first -
# the same order CPython's own embedding examples use.
_PROLOGUE_C = """\
/* CPythonizer: the console policy below needs the Win32 console API. */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

"""

# Cython's generated entry point is chosen by #if, so the brace to inject at is
# the one after the whole conditional block.
_CYTHON_ANCHORS = (
    "static int __Pyx_main(int argc, wchar_t **argv)\n#endif\n{\n",
    "static int __Pyx_main(int argc, char **argv)\n#endif\n{\n",
)
# The loaders' own stub templates declare wmain directly.
_STUB_ANCHORS = ("int wmain(int argc, wchar_t **argv)\n{\n",)


def console_policy_code(noconsole: bool, hide_console: bool) -> str:
    """The C snippet implementing the requested combination ('' when neither)."""
    if not hide_console:
        return ""
    return ALLOC_HIDDEN_C if noconsole else HIDE_EXISTING_C


def inject_console_policy(c_path: Path, *, noconsole: bool, hide_console: bool,
                          stub: bool = False) -> str:
    """Apply the policy to a generated .c. Returns 'noconsole', 'hide' or ''.

    Raises when the entry point cannot be found: silently skipping would ship a
    build whose console behaviour is the opposite of what was asked for.
    """
    code = console_policy_code(noconsole, hide_console)
    if not code:
        return ""
    anchors = _STUB_ANCHORS if stub else _CYTHON_ANCHORS
    text = c_path.read_text(encoding="utf-8", errors="replace")
    for anchor in anchors:
        if anchor in text:
            c_path.write_text(_PROLOGUE_C + text.replace(anchor, anchor + code, 1),
                              encoding="utf-8")
            return "alloc" if noconsole else "hide"
    wanted = "--noconsole --hide-console" if noconsole else "--hide-console"
    raise RuntimeError(
        f"{wanted}: could not find the entry point to patch in {c_path.name}")
