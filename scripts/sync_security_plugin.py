#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROADMAP = ROOT / ".roadmap" / "roadmap.security.json"
PLUGIN_ROADMAP = ROOT / "plugins" / "security-audit" / "0.1.0" / "roadmap.json"


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def build_plugin_roadmap(source: dict[str, Any]) -> dict[str, Any]:
    """Return the plugin roadmap derived from .roadmap/roadmap.security.json."""
    return {
        "meta": deepcopy(source["meta"]),
        "project": deepcopy(source["project"]),
        "methodology": deepcopy(source.get("methodology", {})),
        "execution_strategy": deepcopy(source.get("execution_strategy", {})),
        "tasks": deepcopy(source["tasks"]),
        "indexes": deepcopy(source.get("indexes", {})),
        "source_of_truth": {
            "path": ".roadmap/roadmap.security.json",
            "sync_command": "python3 scripts/sync_security_plugin.py",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Derive the packaged security-audit plugin roadmap from the canonical security roadmap."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if plugins/security-audit/0.1.0/roadmap.json is out of sync",
    )
    args = parser.parse_args()

    expected = build_plugin_roadmap(_read_json(SOURCE_ROADMAP))
    if args.check:
        current = _read_json(PLUGIN_ROADMAP)
        if current != expected:
            print(
                "plugins/security-audit/0.1.0/roadmap.json is out of sync with "
                ".roadmap/roadmap.security.json"
            )
            print("Run: python3 scripts/sync_security_plugin.py")
            return 1
        return 0

    _write_json(PLUGIN_ROADMAP, expected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
