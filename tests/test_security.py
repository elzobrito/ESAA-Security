"""
tests/test_security.py
======================
OWASP security regression tests for ESAA-Security.

Covers:
  - A01 Path Traversal: assert_within_root rejects paths that escape root
  - A01 Path Traversal: validator rejects .. sequences and absolute paths
  - A01 Path Traversal: service.submit rejects file writes outside root
  - A03 Actor Injection: _assert_safe_actor rejects dangerous actor names
  - A03 Actor Injection: service.submit rejects malicious actor values
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from src.esaa.errors import ESAAError
from src.esaa.utils import assert_within_root, normalize_rel_path
from src.esaa.validator import _validate_safe_path
from src.esaa.service import _assert_safe_actor


# ---------------------------------------------------------------------------
# A01 – assert_within_root
# ---------------------------------------------------------------------------

class TestAssertWithinRoot:
    def test_valid_path_inside_root(self, tmp_path: Path) -> None:
        target = tmp_path / "src" / "file.py"
        assert_within_root(tmp_path, target)

    def test_exact_root_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ESAAError) as exc_info:
            assert_within_root(tmp_path, tmp_path)
        assert exc_info.value.code == "BOUNDARY_VIOLATION"

    def test_dotdot_escape_raises(self, tmp_path: Path) -> None:
        evil = tmp_path / "src" / ".." / ".." / "etc" / "passwd"
        with pytest.raises(ESAAError) as exc_info:
            assert_within_root(tmp_path, evil)
        assert exc_info.value.code == "BOUNDARY_VIOLATION"

    def test_absolute_sibling_raises(self, tmp_path: Path) -> None:
        sibling = tmp_path.parent / "other_project" / "secret.txt"
        with pytest.raises(ESAAError) as exc_info:
            assert_within_root(tmp_path, sibling)
        assert exc_info.value.code == "BOUNDARY_VIOLATION"

    def test_symlink_escape_raises(self, tmp_path: Path) -> None:
        outside = tmp_path.parent / "outside_secret.txt"
        outside.write_text("secret", encoding="utf-8")
        link = tmp_path / "evil_link.txt"
        link.symlink_to(outside)
        with pytest.raises(ESAAError) as exc_info:
            assert_within_root(tmp_path, link)
        assert exc_info.value.code == "BOUNDARY_VIOLATION"
        link.unlink()
        outside.unlink()

    def test_nested_valid_path(self, tmp_path: Path) -> None:
        target = tmp_path / "a" / "b" / "c" / "deep.txt"
        assert_within_root(tmp_path, target)


# ---------------------------------------------------------------------------
# A01 – _validate_safe_path (validator layer)
# ---------------------------------------------------------------------------

class TestValidateSafePath:
    @pytest.mark.parametrize("evil_path", [
        "../etc/passwd",
        "../../etc/shadow",
        "/etc/passwd",
        "/absolute/path",
        "src/../../outside",
        "a/b/../../../secret",
    ])
    def test_path_traversal_rejected(self, evil_path: str) -> None:
        with pytest.raises(ESAAError) as exc_info:
            _validate_safe_path(evil_path)
        assert exc_info.value.code == "BOUNDARY_VIOLATION"

    @pytest.mark.parametrize("safe_path", [
        "src/esaa/utils.py",
        "tests/test_foo.py",
        "docs/spec/readme.md",
        "file.txt",
    ])
    def test_valid_paths_accepted(self, safe_path: str) -> None:
        result = _validate_safe_path(safe_path)
        assert result

    def test_empty_path_rejected(self) -> None:
        with pytest.raises(ESAAError) as exc_info:
            _validate_safe_path("")
        assert exc_info.value.code == "BOUNDARY_VIOLATION"

    def test_windows_style_traversal_rejected(self) -> None:
        with pytest.raises(ESAAError) as exc_info:
            _validate_safe_path("..\\etc\\passwd")
        assert exc_info.value.code == "BOUNDARY_VIOLATION"


# ---------------------------------------------------------------------------
# A03 – _assert_safe_actor
# ---------------------------------------------------------------------------

class TestAssertSafeActor:
    @pytest.mark.parametrize("evil_actor", [
        "",
        "actor\ninjected",
        "actor\rinjected",
        "actor injected",
        "actor;rm -rf /",
        "actor|pipe",
        "actor`backtick`",
        "a" * 65,
        "../traversal",
        "actor<script>",
    ])
    def test_malicious_actor_rejected(self, evil_actor: str) -> None:
        with pytest.raises(ESAAError) as exc_info:
            _assert_safe_actor(evil_actor)
        assert exc_info.value.code == "INVALID_ACTOR"

    @pytest.mark.parametrize("safe_actor", [
        "agent-external",
        "claude-code",
        "orchestrator",
        "mock_agent",
        "Agent01",
        "a",
        "a" * 64,
    ])
    def test_valid_actor_accepted(self, safe_actor: str) -> None:
        _assert_safe_actor(safe_actor)


# ---------------------------------------------------------------------------
# A01 – service.submit rejects file writes outside root (integration)
# ---------------------------------------------------------------------------

class TestSubmitPathTraversal:
    @pytest.fixture
    def initialized_project(self, tmp_path: Path, repo_root: Path) -> Path:
        shutil.copytree(repo_root / ".roadmap", tmp_path / ".roadmap")
        from src.esaa.service import ESAAService
        svc = ESAAService(tmp_path)
        svc.init(force=True)
        return tmp_path

    def test_submit_refuses_escape_path(self, initialized_project: Path) -> None:
        from src.esaa.service import ESAAService
        from src.esaa.store import load_roadmap

        svc = ESAAService(initialized_project)
        roadmap = load_roadmap(initialized_project)
        assert roadmap is not None

        task = next(
            (t for t in roadmap["tasks"] if t.get("status") == "pending"),
            None,
        )
        if task is None:
            pytest.skip("No pending task available in seeded roadmap")

        malicious_output = {
            "activity_event": {
                "action": "complete",
                "task_id": task["task_id"],
                "verification": {"checks": ["manual"]},
            },
            "file_updates": [
                {
                    "path": "../outside_root.txt",
                    "content": "PWNED",
                }
            ],
        }

        with pytest.raises(ESAAError) as exc_info:
            svc.submit(malicious_output, actor="agent-test")
        assert exc_info.value.code == "BOUNDARY_VIOLATION"

        evil_file = initialized_project.parent / "outside_root.txt"
        assert not evil_file.exists()


# ---------------------------------------------------------------------------
# A03 – service.submit rejects malicious actor (integration)
# ---------------------------------------------------------------------------

class TestSubmitActorInjection:
    def test_submit_rejects_newline_actor(self, tmp_path: Path, repo_root: Path) -> None:
        shutil.copytree(repo_root / ".roadmap", tmp_path / ".roadmap")
        from src.esaa.service import ESAAService
        svc = ESAAService(tmp_path)
        svc.init(force=True)

        fake_output = {
            "activity_event": {
                "action": "complete",
                "task_id": "TASK-001",
                "verification": {"checks": ["manual"]},
            },
        }

        with pytest.raises(ESAAError) as exc_info:
            svc.submit(fake_output, actor="evil\nactor")
        assert exc_info.value.code == "INVALID_ACTOR"

    def test_submit_rejects_shell_injection_actor(self, tmp_path: Path, repo_root: Path) -> None:
        shutil.copytree(repo_root / ".roadmap", tmp_path / ".roadmap")
        from src.esaa.service import ESAAService
        svc = ESAAService(tmp_path)
        svc.init(force=True)

        fake_output = {
            "activity_event": {
                "action": "complete",
                "task_id": "TASK-001",
                "verification": {"checks": ["manual"]},
            },
        }

        with pytest.raises(ESAAError) as exc_info:
            svc.submit(fake_output, actor="agent; rm -rf /")
        assert exc_info.value.code == "INVALID_ACTOR"