"""PostToolUse hook: after an edit that can affect lint or tests, run ruff and the fast suite.

Failures go to stderr with exit code 2, which Claude Code feeds back to Claude. It only checks;
it never modifies files. The fast suite skips the Hypothesis property tests; the full suite is
still required before declaring a task done (CLAUDE.md).
"""

import json
import os
import subprocess
import sys
from pathlib import Path

RELEVANT_DIRS = ("src/", "tests/", "lab/", ".claude/hooks/")
RELEVANT_FILES = ("pyproject.toml",)
TAIL = 40
STEPS: list[tuple[str, list[str]]] = [
    ("ruff check", ["-m", "ruff", "check", "--quiet"]),
    ("ruff format --check", ["-m", "ruff", "format", "--check", "--quiet"]),
    (
        "fast tests",
        [
            "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
            "--ignore=tests/test_models_properties.py",
        ],
    ),
]  # fmt: skip


def relevant(path: str, root: Path) -> bool:
    try:
        rel = Path(os.path.realpath(path)).relative_to(os.path.realpath(root)).as_posix()
    except ValueError:
        return False  # outside the project
    if rel in RELEVANT_FILES:
        return True
    if rel.startswith("lab/"):
        return rel.endswith(".py")
    return rel.startswith(RELEVANT_DIRS)


def main() -> int:
    event = json.load(sys.stdin)
    tool_input = event.get("tool_input") or {}
    path = tool_input.get("file_path") or tool_input.get("notebook_path")
    root = Path(os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd") or ".")
    if not isinstance(path, str) or not relevant(path, root):
        return 0
    failures = []
    for name, args in STEPS:
        result = subprocess.run(
            [sys.executable, *args], cwd=root, capture_output=True, text=True, encoding="utf-8"
        )
        if result.returncode != 0:
            output = (result.stdout + result.stderr).strip().splitlines()[-TAIL:]
            header = f"--- {name} failed (exit {result.returncode}) ---"
            failures.append(header + "\n" + "\n".join(output))
    if not failures:
        return 0
    print(f"Checks failed after editing {path}:\n\n" + "\n\n".join(failures), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
