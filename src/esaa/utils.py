from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .constants import RESERVED_ACTORS
from .errors import ESAAError

_ACTOR_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def canonical_json_bytes(value: Any) -> bytes:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    return text.encode("utf-8")


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def normalize_rel_path(path: str) -> str:
    norm = path.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    return norm


def assert_within_root(root: Path, target: Path) -> None:
    """Raise ESAAError if target is not strictly inside root (OWASP A01 – path traversal guard)."""
    resolved_root = root.resolve()
    resolved_target = target.resolve()
    if resolved_target == resolved_root:
        raise ESAAError(
            "BOUNDARY_VIOLATION",
            f"path must be inside project root, not the root itself: {target}",
        )
    try:
        resolved_target.relative_to(resolved_root)
    except ValueError:
        raise ESAAError(
            "BOUNDARY_VIOLATION",
            f"path escapes project root: {target}",
        )


def assert_safe_actor(actor: str) -> None:
    """Reject actor identifiers that could spoof logs or inject shell metacharacters (OWASP A03)."""
    if not _ACTOR_RE.match(actor):
        raise ESAAError(
            "INVALID_ACTOR",
            f"actor contains illegal characters or is too long: {actor!r}",
        )
    if actor in RESERVED_ACTORS:
        raise ESAAError(
            "INVALID_ACTOR",
            f"actor is reserved for orchestrator use: {actor!r}",
        )