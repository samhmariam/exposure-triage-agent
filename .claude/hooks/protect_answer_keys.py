"""PreToolUse hook: block any change to the answer keys (lab/PLANTED.md, evals/answers/**).

File tools are checked by resolved path; Bash commands are blocked if they mention a protected
path at all (reads included: the Read deny rules don't cover `cat`). The Bash check is textual,
so it catches accidents, not deliberate obfuscation. Exit code 2 blocks the tool call and sends
stderr back to Claude. If this hook fails unexpectedly, it blocks rather than letting edits through.
"""

import json
import os
import re
import sys
from pathlib import Path

PROTECTED_FILES = ("lab/PLANTED.md",)
PROTECTED_DIRS = ("evals/answers",)
BASH_PATTERN = re.compile(r"planted\.md|evals[\\/]+answers", re.IGNORECASE)
FILE_TOOLS = {"Edit", "MultiEdit", "Write", "NotebookEdit"}


MSYS_DRIVE = re.compile(r"^/([A-Za-z])/")


def _native(path: str) -> str:
    """Git Bash may hand over /c/Users/...; turn it into C:/Users/... on Windows."""
    return MSYS_DRIVE.sub(r"\1:/", path) if os.name == "nt" else path


def _key(path: str) -> str:
    # normcase lower-cases and turns / into \ on Windows: apply it to both sides, then use /.
    return os.path.normcase(path).replace("\\", "/")


def protected_reason(path: str, root: Path) -> str | None:
    root_path = os.path.realpath(_native(str(root)))
    target = _native(path)
    if not os.path.isabs(target):
        target = os.path.join(root_path, target)
    try:
        rel = _key(os.path.relpath(os.path.realpath(target), root_path))
    except ValueError:
        return None  # another drive: outside the project
    for f in PROTECTED_FILES:
        if rel == _key(f):
            return f"{f} is an answer key"
    for d in PROTECTED_DIRS:
        if rel == _key(d) or rel.startswith(_key(d) + "/"):
            return f"{d}/ holds held-out eval answers"
    return None


def check(event: dict[str, object]) -> str | None:
    tool = event.get("tool_name")
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    root = Path(os.environ.get("CLAUDE_PROJECT_DIR") or str(event.get("cwd") or "."))
    if tool in FILE_TOOLS:
        path = tool_input.get("file_path") or tool_input.get("notebook_path")
        return protected_reason(path, root) if isinstance(path, str) else None
    if tool == "Bash":
        command = tool_input.get("command")
        if isinstance(command, str) and BASH_PATTERN.search(command):
            return "the command touches lab/PLANTED.md or evals/answers/ (reads included)"
    return None


def main() -> int:
    try:
        reason = check(json.load(sys.stdin))
    except Exception as exc:  # fail closed: a broken guard must not let edits through
        print(f"Blocked: protect_answer_keys hook failed ({exc!r}).", file=sys.stderr)
        return 2
    if reason is None:
        return 0
    print(
        f"Blocked: {reason} (CLAUDE.md rule 6, ADR 0003). Answer keys may only be changed by a "
        "human outside Claude Code; do not try another route.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
