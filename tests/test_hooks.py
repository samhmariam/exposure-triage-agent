"""The Claude Code hooks in .claude/hooks/, loaded by path (they are scripts, not modules)."""

import importlib.util
import os
from pathlib import Path

import pytest

HOOKS = Path(__file__).parent.parent / ".claude" / "hooks"


def load(name):
    spec = importlib.util.spec_from_file_location(name, HOOKS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


protect = load("protect_answer_keys")
check = load("check_after_edit")


def edit(path):
    return {"tool_name": "Edit", "tool_input": {"file_path": str(path)}}


def bash(command):
    return {"tool_name": "Bash", "tool_input": {"command": command}}


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    return tmp_path


@pytest.mark.parametrize(
    "rel",
    [
        "lab/PLANTED.md",
        "lab/planted.md" if os.name == "nt" else "lab/PLANTED.md",  # Windows is case-insensitive
        "evals/answers/q1.json",
        "evals/answers/deep/nested.md",
        "lab/../lab/PLANTED.md",
    ],
)
def test_file_tools_on_answer_keys_are_blocked(root, rel):
    assert protect.check(edit(root / rel)) is not None
    assert protect.check({**edit(rel), "tool_name": "Write"}) is not None  # relative path too


@pytest.mark.parametrize(
    "rel", ["lab/inventory.yaml", "evals/questions/q1.json", "src/triage/sbom.py", "PLANTED.md"]
)
def test_other_files_are_allowed(root, rel):
    assert protect.check(edit(root / rel)) is None


def test_notebook_path_is_checked(root):
    event = {"tool_name": "NotebookEdit", "tool_input": {"notebook_path": "evals/answers/x.ipynb"}}
    assert protect.check(event) is not None


@pytest.mark.skipif(os.name != "nt", reason="Git Bash drive paths exist only on Windows")
def test_git_bash_style_paths_are_understood(root):
    drive, rest = str(root).split(":", 1)
    msys = f"/{drive.lower()}{rest.replace(os.sep, '/')}/lab/PLANTED.md"
    assert protect.check(edit(msys)) is not None


@pytest.mark.parametrize(
    "command",
    [
        "sed -i 's/a/b/' lab/PLANTED.md",
        "echo x >> lab/planted.md",
        "cat evals/answers/q1.json",
        r"type evals\answers\q1.json",
    ],
)
def test_bash_mentioning_answer_keys_is_blocked(root, command):
    assert protect.check(bash(command)) is not None


def test_ordinary_bash_is_allowed(root):
    assert protect.check(bash("uv run pytest -q")) is None


def test_other_tools_are_ignored(root):
    event = {"tool_name": "Read", "tool_input": {"file_path": "lab/PLANTED.md"}}
    assert protect.check(event) is None


@pytest.mark.parametrize(
    ("rel", "expected"),
    [
        ("src/triage/sbom.py", True),
        ("tests/fixtures/cve/CVE-2021-44228.json", True),
        ("lab/gen_sboms.py", True),
        ("pyproject.toml", True),
        (".claude/hooks/check_after_edit.py", True),
        ("lab/inventory.yaml", False),
        ("docs/learning-log.md", False),
        ("CLAUDE.md", False),
    ],
)
def test_checks_run_only_for_files_that_affect_lint_or_tests(tmp_path, rel, expected):
    assert check.relevant(str(tmp_path / rel), tmp_path) is expected


def test_files_outside_the_project_are_not_checked(tmp_path):
    assert check.relevant(str(tmp_path.parent / "elsewhere.py"), tmp_path) is False
