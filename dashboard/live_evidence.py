"""Read-only, bounded live-demo reader. No Streamlit, pickle, eval or launch APIs.

Live telemetry is provisional demonstration evidence, not pinned research data.
RAW heartbeat comparisons are only meaningful within the same Linux boot.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import time

EVENT_SCHEMA = "live-telemetry-event-v1"
SNAPSHOT_SCHEMA = "live-telemetry-snapshot-v1"
POINTER_SCHEMA = "live-telemetry-pointer-v1"
TERMINAL = frozenset({"completed", "failed", "interrupted"})
RUN_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024
MAX_EVENT_TAIL_BYTES = 2 * 1024 * 1024
MAX_FINAL_BYTES = 4 * 1024 * 1024


@dataclass
class LiveEvidence:
    status: str
    snapshot: dict | None = None
    events: list[dict] = field(default_factory=list)
    path: Path | None = None
    run_id: str | None = None
    messages: list[str] = field(default_factory=list)

    @property
    def data(self):
        return self.snapshot

    @property
    def directory(self):
        return self.path.parent if self.path else None

    def as_dict(self) -> dict:
        return {"status": self.status, "snapshot": self.snapshot, "events": self.events,
                "path": str(self.path) if self.path else None, "run_id": self.run_id,
                "messages": self.messages}


def _pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(value):
    raise ValueError(f"Nonfinite JSON value: {value}")


def _decode(data):
    return json.loads(data, object_pairs_hook=_pairs, parse_constant=_constant)


def _read_json(path: Path, limit: int):
    if path.stat().st_size > limit:
        raise ValueError(f"{path.name} exceeds its bounded size limit")
    # Read at most limit+1 even if a file grows after the stat call.
    with path.open("rb") as source:
        content = source.read(limit + 1)
    if len(content) > limit:
        raise ValueError(f"{path.name} exceeds its bounded size limit")
    return _decode(content)


def _contained(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError("Live evidence path must be a nonempty relative string")
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts or "\\" in relative:
        raise ValueError("Live evidence path cannot escape its root")
    path = root / rel
    cursor = path
    while cursor != root:
        if cursor.is_symlink():
            raise ValueError("Symlink live evidence paths are not supported")
        cursor = cursor.parent
    if not path.resolve().is_relative_to(root):
        raise ValueError("Live evidence path resolves outside its root")
    return path


def _integer(value, name: str, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"Invalid {name}")
    return value


def _tail_events(path: Path, snapshot: dict, messages: list[str]) -> list[dict]:
    if not path.exists():
        messages.append("Event stream is missing; only the saved snapshot is available")
        return []
    size = path.stat().st_size
    start = max(0, size - MAX_EVENT_TAIL_BYTES)
    with path.open("rb") as source:
        source.seek(start)
        content = source.read(MAX_EVENT_TAIL_BYTES)
    if start:
        # The tail may start in the middle of a JSON record.
        _, separator, content = content.partition(b"\n")
        if not separator:
            messages.append("Event stream tail contains no complete bounded records")
            return []
        messages.append("Only the bounded event-stream tail was read")
    if content and not content.endswith(b"\n"):
        content = content.rpartition(b"\n")[0]
        messages.append("Incomplete final JSONL record ignored; no values inferred")
    seen = {}
    events = []
    previous = -1
    for line in content.splitlines():
        if not line.strip():
            continue
        value = _decode(line)
        if not isinstance(value, dict) or value.get("schema_version") != EVENT_SCHEMA:
            raise ValueError("Unsupported live-event schema")
        for key in ("run_id", "session_id", "boot_id"):
            if value.get(key) != snapshot.get(key):
                raise ValueError(f"Event {key} disagrees with snapshot identity")
        seq = _integer(value.get("seq"), "event sequence", 1)
        _integer(value.get("event_raw_ns"), "event RAW timestamp")
        _integer(value.get("produced_raw_ns"), "producer RAW timestamp")
        if seq in seen:
            if seen[seq] != value:
                raise ValueError(f"Contradictory duplicate event sequence {seq}")
            messages.append(f"Exact duplicate event sequence {seq} deduplicated")
            continue
        if seq < previous:
            raise ValueError("Out-of-order event sequence")
        seen[seq] = value
        previous = seq
        if seq > snapshot["seq"]:
            # Writer appends before publishing a snapshot; this race is normal.
            continue
        events.append(value)
    return events[-200:]


def read_live(root=None, run_id=None, now_raw_ns=None, boot_id=None,
              stale_seconds=5) -> LiveEvidence:
    """Read current or a named run under one configured demonstration root.

    Caller supplies root through trusted application/CLI configuration, never a
    browser evidence-path selector. This reader cannot start or control workers.
    """
    if root is None:
        project = Path(os.environ.get("ETC_PROJECT_ROOT", Path(__file__).resolve().parents[1]))
        root = project / "results/live_demo"
    requested = Path(root).absolute()
    if requested.is_symlink():
        return LiveEvidence("corrupt", messages=["Live-demo root cannot be a symlink"])
    directory_root = requested.resolve()
    if stale_seconds <= 0:
        return LiveEvidence("corrupt", messages=["Stale-heartbeat bound must be positive"])
    messages = []
    path = None
    snapshot = None
    try:
        pointer = None
        if run_id is None:
            pointer_path = _contained(directory_root, "current.json")
            if not pointer_path.exists():
                return LiveEvidence("idle", messages=["No live demonstration has been attached"])
            pointer = _read_json(pointer_path, 16384)
            if not isinstance(pointer, dict) or pointer.get("schema_version") != POINTER_SCHEMA:
                raise ValueError("Unsupported live-pointer schema")
            run_id = pointer.get("run_id")
        if not isinstance(run_id, str) or not RUN_PATTERN.fullmatch(run_id) or run_id == "control":
            raise ValueError("Invalid live-demo run ID")
        expected_relative = f"{run_id}/snapshot.json"
        if pointer and pointer.get("snapshot_path") != expected_relative:
            raise ValueError("Pointer snapshot path does not match its run ID")
        path = _contained(directory_root, expected_relative)
        if not path.exists():
            return LiveEvidence("unavailable", path=path, run_id=run_id,
                                messages=["Live snapshot is missing; no measurements inferred"])
        snapshot = _read_json(path, MAX_SNAPSHOT_BYTES)
        if not isinstance(snapshot, dict) or snapshot.get("schema_version") != SNAPSHOT_SCHEMA:
            raise ValueError("Unsupported live-snapshot schema")
        if snapshot.get("run_id") != run_id or snapshot.get("clock_domain") != "CLOCK_MONOTONIC_RAW":
            raise ValueError("Snapshot run identity or clock domain is invalid")
        for identity in ("session_id", "boot_id"):
            if not isinstance(snapshot.get(identity), str) or not snapshot[identity]:
                raise ValueError(f"Missing snapshot {identity}")
            if pointer and pointer.get(identity) != snapshot[identity]:
                raise ValueError(f"Pointer {identity} disagrees with snapshot")
        _integer(snapshot.get("seq"), "snapshot sequence", 1)
        _integer(snapshot.get("started_raw_ns"), "start RAW timestamp")
        heartbeat = _integer(snapshot.get("heartbeat_raw_ns"), "heartbeat RAW timestamp")
        if heartbeat < snapshot["started_raw_ns"]:
            raise ValueError("Heartbeat precedes run start in its RAW domain")
        if not isinstance(snapshot.get("metadata"), dict):
            raise ValueError("Live metadata is missing")
        samples = snapshot.get("samples", [])
        if not isinstance(samples, list) or len(samples) > 120:
            raise ValueError("Live sample history exceeds its bounded schema")
        if not isinstance(snapshot.get("recent_events", []), list) or len(snapshot.get("recent_events", [])) > 200:
            raise ValueError("Live event history exceeds its bounded schema")
        for sample in samples:
            if not isinstance(sample, dict) or not isinstance(sample.get("sample"), dict):
                raise ValueError("Malformed live sample")
            _integer(sample.get("raw_ns"), "sample RAW timestamp")
            _integer(sample.get("seq"), "sample sequence", 1)
        telemetry = snapshot.get("telemetry", {})
        if not isinstance(telemetry, dict):
            raise ValueError("Malformed telemetry health")
        if telemetry.get("dropped_events", 0):
            messages.append(f"Telemetry queue dropped {telemetry['dropped_events']} event(s); history has gaps")
        if telemetry.get("sample_history_evictions", 0) or telemetry.get("event_history_evictions", 0):
            messages.append("Large-payload dashboard history was bounded; append-only events remain available")
        messages.extend(str(error) for error in telemetry.get("errors", []))
        events_path = _contained(directory_root, f"{run_id}/events.jsonl")
        events = _tail_events(events_path, snapshot, messages)
        final_reference = snapshot.get("final_summary_file")
        if final_reference is not None:
            if not isinstance(final_reference, dict):
                raise ValueError("Malformed final-summary file reference")
            relative = final_reference.get("path")
            final_path = _contained(path.parent, relative)
            if final_path.stat().st_size > MAX_FINAL_BYTES:
                raise ValueError("Final summary exceeds bounded size limit")
            with final_path.open("rb") as source:
                content = source.read(MAX_FINAL_BYTES + 1)
            if len(content) > MAX_FINAL_BYTES:
                raise ValueError("Final summary exceeds bounded size limit")
            if hashlib.sha256(content).hexdigest() != final_reference.get("sha256"):
                raise ValueError("Live final-summary SHA-256 mismatch")
            referenced_summary = _decode(content)
            if not isinstance(referenced_summary, dict):
                raise ValueError("Referenced final summary is not a JSON object")
            if snapshot.get("final_summary") != referenced_summary:
                raise ValueError("Inline final summary disagrees with its hash-verified file")
        status = snapshot.get("status")
        if status not in {"preparing", "running", *TERMINAL}:
            raise ValueError("Unsupported live lifecycle status")
        if status in TERMINAL:
            if snapshot.get("final_summary") is None:
                messages.append("Terminal session has no final summary; partial evidence is retained")
        else:
            if boot_id is None:
                boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            if now_raw_ns is None:
                now_raw_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
            if boot_id != snapshot["boot_id"]:
                status = "interrupted"
                messages.append("Linux boot identity changed; no active worker or cross-boot RAW elapsed time is inferred")
            elif now_raw_ns < heartbeat:
                status = "stale"
                messages.append("RAW heartbeat is ahead of the reader clock; elapsed time is unavailable")
            elif now_raw_ns - heartbeat > stale_seconds * 1_000_000_000:
                status = "stale"
                messages.append("Producer heartbeat is stale; last samples are retained, not extrapolated")
        return LiveEvidence(status, snapshot, events, path, run_id, messages)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        return LiveEvidence("corrupt", snapshot, [], path, run_id,
                            messages + [f"Live evidence cannot be trusted: {type(exc).__name__}: {exc}"])
