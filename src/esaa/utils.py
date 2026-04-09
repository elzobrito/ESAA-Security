from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import ESAAError

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
    return path.replace("\\", "/").lstrip("./")

def assert_within_root(root: Path, target: Path) -> None:
    """Raise ESAAError if target is not strictly inside root (OWASP A01 – path traversal guard)."""
    try:
        resolved_root = root.resolve()
        resolved_target = target.resolve()
        resolved_target.relative_to(resolved_root)
    except ValueError:
        raise ESAAError(
            "BOUNDARY_VIOLATION",
            f"path escapes project root: {target}",
        )
