from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .adapters.base import AgentAdapter
from .adapters.mock import MockAgentAdapter
from .constants import ESAA_VERSION, SCHEMA_VERSION
from .errors import CorruptedStoreError, ESAAError
from .projector import materialize
from .store import (
    append_events,
    ensure_event_store,
    load_agent_contract,
    load_agent_result_schema,
    load_roadmap,
    next_event_seq,
    parse_event_store,
    save_issues,
    save_lessons,
    save_roadmap,
)
from .utils import assert_within_root, ensure_parent, normalize_rel_path, utc_now_iso
from .validator import validate_agent_output

# ---------------------------------------------------------------------------
# actor validation – prevent log-injection / identifier spoofing (OWASP A03)
# ---------------------------------------------------------------------------
_ACTOR_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")

def _assert_safe_actor(actor: str) -> None:
    if not _ACTOR_RE.match(actor):
        raise ESAAError(
            "INVALID_ACTOR",
            f"actor contains illegal characters or is too long: {actor!r}",
        )

class ESAAService:
    def __init__(self, root: Path, adapter: AgentAdapter | None = None) -> None:
        self.root = root
        self.adapter = adapter or MockAgentAdapter()

    def init(self, run_id: str = "RUN-0001", master_correlation_id: str = "CID-ESAA-INIT", force: bool = False) -> dict[str, Any]:
        roadmap_dir = self.root / ".roadmap"
        roadmap_dir.mkdir(parents=True, exist_ok=True)

        if not force and (self.root / ".roadmap/activity.jsonl").exists():
            existing = (self.root / ".roadmap/activity.jsonl").read_text(encoding="utf-8").strip()
            if existing:
                raise ESAAError("INIT_BLOCKED", "event store already contains events; use --force to reinitialize")

        for rel in ("docs/spec", "docs/qa", "src", "tests"):
            (self.root / rel).mkdir(parents=True, exist_ok=True)

        events: list[dict[str, Any]] = []
        seq = 1
        events.append(
            make_event(
                seq,
                actor="orchestrator",
                action="run.start",
                payload={
                    "run_id": run_id,
                    "status": "initialized",
                    "master_correlation_id": master_correlation_id,
                    "baseline_id": "B-000",
                },
            )
        )
        seq += 1
        for task in seed_tasks():
            events.append(make_event(seq, actor="orchestrator", action="task.create", payload=task))
            seq += 1

        events.append(
            make_event(
                seq,
                actor="orchestrator",
                action="verify.start",
                payload={"strict": True},
            )
        )
        seq += 1

        roadmap_preview, _, _ = materialize(events)
        events.append(
            make_event(
                seq,
                actor="orchestrator",
                action="verify.ok",
                payload={"projection_hash_sha256": roadmap_preview["meta"]["run"]["projection_hash_sha256"]},
            )
        )

        path = ensure_event_store(self.root)
        path.write_text("", encoding="utf-8")
        append_events(self.root, events)
        roadmap, issues, lessons = materialize(events)
        save_roadmap(self.root, roadmap)
        save_issues(self.root, issues)
        save_lessons(self.root, lessons)
        return {
            "run_id": run_id,
            "events_written": len(events),
            "last_event_seq": roadmap["meta"]["run"]["last_event_seq"],
            "projection_hash_sha256": roadmap["meta"]["run"]["projection_hash_sha256"],
        }

    def project(self) -> dict[str, Any]:
        events = parse_event_store(self.root)
        roadmap, issues, lessons = materialize(events)
        save_roadmap(self.root, roadmap)
        save_issues(self.root, issues)
        save_lessons(self.root, lessons)
        return {
            "last_event_seq": roadmap["meta"]["run"]["last_event_seq"],
            "projection_hash_sha256": roadmap["meta"]["run"]["projection_hash_sha256"],
            "tasks": len(roadmap["tasks"]),
            "issues": len(issues["issues"]),
            "lessons": len(lessons["lessons"]),
        }

    def verify(self) -> dict[str, Any]:
        try:
            events = parse_event_store(self.root)
            projected, _, _ = materialize(events)
        except CorruptedStoreError as exc:
            return {
                "verify_status": "corrupted",
                "error_code": exc.code,
                "error_message": exc.message,
                "last_event_seq": None,
                "projection_hash_sha256": None,
            }

        stored = load_roadmap(self.root)
        if stored is None:
            return {
                "verify_status": "mismatch",
                "reason": "roadmap_missing",
                "last_event_seq": projected["meta"]["run"]["last_event_seq"],
                "projection_hash_sha256": projected["meta"]["run"]["projection_hash_sha256"],
            }

        computed_hash = projected["meta"]["run"]["projection_hash_sha256"]
        stored_hash = stored.get("meta", {}).get("run", {}).get("projection_hash_sha256")
        computed_seq = projected["meta"]["run"]["last_event_seq"]
        stored_seq = stored.get("meta", {}).get("run", {}).get("last_event_seq")

        if computed_hash == stored_hash and computed_seq == stored_seq:
            return {
                "verify_status": "ok",
                "last_event_seq": computed_seq,
                "projection_hash_sha256": computed_hash,
            }
        return {
            "verify_status": "mismatch",
            "last_event_seq": computed_seq,
            "projection_hash_sha256": computed_hash,
            "stored_last_event_seq": stored_seq,
            "stored_projection_hash_sha256": stored_hash,
        }

    def replay(self, until: str | None = None, write_views: bool = True) -> dict[str, Any]:
        events = parse_event_store(self.root)
        selected = events
        if until:
            if until.isdigit():
                seq_limit = int(until)
                selected = [ev for ev in events if int(ev["event_seq"]) <= seq_limit]
            else:
                out: list[dict[str, Any]] = []
                for event in events:
                    out.append(event)
                    if event["event_id"] == until:
                        break
                selected = out
        roadmap, issues, lessons = materialize(selected)
        if write_views:
            save_roadmap(self.root, roadmap)
            save_issues(self.root, issues)
            save_lessons(self.root, lessons)
        return {
            "events_replayed": len(selected),
            "last_event_seq": roadmap["meta"]["run"]["last_event_seq"],
            "projection_hash_sha256": roadmap["meta"]["run"]["projection_hash_sha256"],
            "verify_status": "ok",
        }

    def submit(self, agent_output: dict[str, Any], actor: str, dry_run: bool = False) -> dict[str, Any]:
        _assert_safe_actor(actor)

        events = parse_event_store(self.root)
        contract = load_agent_contract(self.root)
        schema = load_agent_result_schema(self.root)
        roadmap, _, _ = materialize(events)

        activity_event = agent_output.get("activity_event", {})
        task_id = activity_event.get("task_id")
        if not task_id:
            raise ESAAError("SCHEMA_INVALID", "activity_event.task_id is required")

        task = None
        for t in roadmap["tasks"]:
            if t["task_id"] == task_id:
                task = t
                break
        if not task:
            raise ESAAError("TASK_NOT_FOUND", f"task_id not found: {task_id}")

        current_seq = next_event_seq(events)
        new_events: list[dict[str, Any]] = []
        files_written = 0

        try:
            validated_event, file_updates = validate_agent_output(agent_output, schema, contract, task)
            agent_event = make_event(
                current_seq,
                actor=actor,
                action=validated_event["action"],
                payload=validated_event,
            )
            candidate_events = [agent_event]
            _ = materialize(events + candidate_events)

            if file_updates:
                write_event = make_event(
                    current_seq + 1,
                    actor="orchestrator",
                    action="orchestrator.file.write",
                    payload={
                        "task_id": task_id,
                        "files": [normalize_rel_path(item["path"]) for item in file_updates],
                    },
                )
                candidate_events.append(write_event)
                _ = materialize(events + candidate_events)

                if not dry_run:
                    for item in file_updates:
                        rel = normalize_rel_path(item["path"])
                        target = self.root / rel
                        assert_within_root(self.root, target)
                        ensure_parent(target)
                        target.write_text(item["content"], encoding="utf-8")
                        files_written += 1

            if validated_event["action"] == "issue.report":
                hotfix_event = build_hotfix_event(events + candidate_events, validated_event)
                if hotfix_event:
                    candidate_events.append(hotfix_event)
                    _ = materialize(events + candidate_events)

            new_events.extend(candidate_events)
        except ESAAError:
            raise

        all_events = events + new_events
        verify_start = make_event(
            next_event_seq(all_events),
            actor="orchestrator",
            action="verify.start",
            payload={"strict": True},
        )
        all_events.append(verify_start)
        new_events.append(verify_start)

        final_roadmap, final_issues, final_lessons = materialize(all_events)

        if all_tasks_done(final_roadmap["tasks"]) and final_roadmap["meta"]["run"]["status"] != "success":
            run_end = make_event(
                next_event_seq(all_events),
                actor="orchestrator",
                action="run.end",
                payload={"status": "success"},
            )
            all_events.append(run_end)
            new_events.append(run_end)
            final_roadmap, final_issues, final_lessons = materialize(all_events)

        verify_ok = make_event(
            next_event_seq(all_events),
            actor="orchestrator",
            action="verify.ok",
            payload={"projection_hash_sha256": final_roadmap["meta"]["run"]["projection_hash_sha256"]},
        )
        all_events.append(verify_ok)
        new_events.append(verify_ok)
        final_roadmap, final_issues, final_lessons = materialize(all_events)

        if not dry_run:
            append_events(self.root, new_events)
            save_roadmap(self.root, final_roadmap)
            save_issues(self.root, final_issues)
            save_lessons(self.root, final_lessons)

        return {
            "status": "accepted",
            "actor": actor,
            "task_id": task_id,
            "action": validated_event["action"],
            "events_appended": len(new_events),
            "files_written": files_written,
            "last_event_seq": final_roadmap["meta"]["run"]["last_event_seq"],
            "verify_status": final_roadmap["meta"]["run"]["verify_status"],
            "projection_hash_sha256": final_roadmap["meta"]["run"]["projection_hash_sha256"],
        }

    def process(self, dry_run: bool = False) -> dict[str, Any]:
        inbox = self.root / ".roadmap" / "inbox"
        if not inbox.exists():
            return {"processed": 0, "accepted": 0, "rejected": 0, "results": []}

        done_dir = inbox / "done"
        rejected_dir = inbox / "rejected"
        done_dir.mkdir(parents=True, exist_ok=True)
        rejected_dir.mkdir(parents=True, exist_ok=True)

        files = sorted(inbox.glob("*.json"))
        results: list[dict[str, Any]] = []
        accepted = 0
        rejected = 0

        for filepath in files:
            name = filepath.stem
            if "__" in name:
                actor, _task_id = name.split("__", 1)
            else:
                actor = "agent-external"

            try:
                _assert_safe_actor(actor)
                agent_output = json.loads(filepath.read_text(encoding="utf-8"))
                result = self.submit(agent_output, actor=actor, dry_run=dry_run)
                results.append(result)
                accepted += 1
                if not dry_run:
                    filepath.rename(done_dir / filepath.name)
            except (ESAAError, json.JSONDecodeError) as exc:
                error_info = {
                    "status": "rejected",
                    "file": filepath.name,
                    "error": str(exc),
                }
                if isinstance(exc, ESAAError):
                    error_info["error_code"] = exc.code
                    error_info["error"] = exc.message
                results.append(error_info)
                rejected += 1
                if not dry_run:
                    filepath.rename(rejected_dir / filepath.name)

        return {
            "processed": len(files),
            "accepted": accepted,
            "rejected": rejected,
            "results": results,
        }

    def run(self, steps: int = 1, dry_run: bool = False) -> dict[str, Any]:
        if steps < 1:
            raise ESAAError("INVALID_ARGUMENT", "steps must be >= 1")

        events = parse_event_store(self.root)
        contract = load_agent_contract(self.root)
        schema = load_agent_result_schema(self.root)
        new_events: list[dict[str, Any]] = []
        files_written = 0
        rejected = 0
        executed = 0

        for _ in range(steps):
            roadmap, _, _ = materialize(events + new_events)
            task = select_next_task(roadmap["tasks"])
            if not task:
                break
            executed += 1
            context = build_dispatch_context(roadmap, task, contract)
            current_seq = next_event_seq(events + new_events)

            output: dict[str, Any] | None = None
            try:
                output = self.adapter.execute(context)
                activity_event, file_updates = validate_agent_output(output, schema, contract, task)
                agent_event = make_event(
                    current_seq,
                    actor=self.adapter.agent_id,
                    action=activity_event["action"],
                    payload=activity_event,
                )
                candidate_events = [agent_event]
                _ = materialize(events + new_events + candidate_events)

                if file_updates:
                    write_event = make_event(
                        current_seq + 1,
                        actor="orchestrator",
                        action="orchestrator.file.write",
                        payload={
                            "task_id": task["task_id"],
                            "files": [normalize_rel_path(item["path"]) for item in file_updates],
                        },
                    )
                    candidate_events.append(write_event)
                    _ = materialize(events + new_events + candidate_events)

                    if not dry_run:
                        for item in file_updates:
                            rel = normalize_rel_path(item["path"])
                            target = self.root / rel
                            assert_within_root(self.root, target)
                            ensure_parent(target)
                            target.write_text(item["content"], encoding="utf-8")
                            files_written += 1

                if activity_event["action"] == "issue.report":
                    hotfix_event = build_hotfix_event(events + new_events + candidate_events, activity_event)
                    if hotfix_event:
                        candidate_events.append(hotfix_event)
                        _ = materialize(events + new_events + candidate_events)

                new_events.extend(candidate_events)
            except ESAAError as exc:
                rejected += 1
                reject_event = make_event(
                    current_seq,
                    actor="orchestrator",
                    action="output.rejected",
                    payload={
                        "task_id": task["task_id"],
                        "error_code": exc.code,
                        "message": exc.message,
                        "source_action": output.get("activity_event", {}).get("action", "unknown") if isinstance(output, dict) else "unknown",
                    },
                )
                new_events.append(reject_event)
            except ValueError as exc:
                rejected += 1
                reject_event = make_event(
                    current_seq,
                    actor="orchestrator",
                    action="output.rejected",
                    payload={
                        "task_id": task["task_id"],
                        "error_code": "LLM_PARSE_FAILED",
                        "message": str(exc),
                        "source_action": "unknown",
                    },
                )
                new_events.append(reject_event)

        final_events = events + new_events
        final_roadmap, final_issues, final_lessons = materialize(final_events)
        if all_tasks_done(final_roadmap["tasks"]) and final_roadmap["meta"]["run"]["status"] != "success":
            run_end = make_event(
                next_event_seq(final_events),
                actor="orchestrator",
                action="run.end",
                payload={"status": "success"},
            )
            final_events.append(run_end)
            new_events.append(run_end)
            final_roadmap, final_issues, final_lessons = materialize(final_events)

        verify_start = make_event(
            next_event_seq(final_events),
            actor="orchestrator",
            action="verify.start",
            payload={"strict": True},
        )
        final_events.append(verify_start)
        new_events.append(verify_start)

        final_roadmap, final_issues, final_lessons = materialize(final_events)
        verify_ok = make_event(
            next_event_seq(final_events),
            actor="orchestrator",
            action="verify.ok",
            payload={"projection_hash_sha256": final_roadmap["meta"]["run"]["projection_hash_sha256"]},
        )
        final_events.append(verify_ok)
        new_events.append(verify_ok)
        final_roadmap, final_issues, final_lessons = materialize(final_events)

        if not dry_run:
            append_events(self.root, new_events)
            save_roadmap(self.root, final_roadmap)
            save_issues(self.root, final_issues)
            save_lessons(self.root, final_lessons)

        return {
            "steps_requested": steps,
            "steps_executed": executed,
            "events_appended": len(new_events),
            "rejected": rejected,
            "files_written": files_written,
            "last_event_seq": final_roadmap["meta"]["run"]["last_event_seq"],
            "verify_status": final_roadmap["meta"]["run"]["verify_status"],
            "projection_hash_sha256": final_roadmap["meta"]["run"]["projection_hash_sha256"],
        }
}