"""Bounded, nonblocking live-demo telemetry; not a research qualification system.

One background writer owns append-only events.jsonl and atomically replaces the
read-only dashboard snapshot. Capture/sender callbacks only enqueue small samples.
Wall time is a display label. Heartbeats and elapsed time use MONOTONIC_RAW.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import threading
import time
import uuid

EVENT_SCHEMA = "live-telemetry-event-v1"
SNAPSHOT_SCHEMA = "live-telemetry-snapshot-v1"
POINTER_SCHEMA = "live-telemetry-pointer-v1"
TERMINAL_STATUSES = frozenset({"completed", "failed", "interrupted"})
RUN_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
RESERVED_FIELDS = frozenset({"schema_version", "run_id", "session_id", "boot_id",
                            "seq", "event", "event_raw_ns", "produced_raw_ns",
                            "wall_time_utc"})


def raw_ns() -> int:
    """No fallback to a different clock domain is permitted."""
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)


def current_boot_id() -> str:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError as exc:
        raise RuntimeError("Linux boot identity is required for RAW heartbeats") from exc
    if not value:
        raise RuntimeError("Linux boot identity is empty")
    return value


def _process_start_ticks() -> int:
    text = Path(f"/proc/{os.getpid()}/stat").read_text()
    return int(text[text.rfind(")") + 2:].split()[19])


def _wall_label() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _json_copy(value, max_bytes: int):
    encoded = json.dumps(value, allow_nan=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > max_bytes:
        raise ValueError("Telemetry payload exceeds its bounded size limit")
    return json.loads(encoded)


def _atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        # The worker may run under sudo with umask 077. The ordinary-user
        # dashboard must read these NEW synthetic diagnostic files immediately.
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(value, output, allow_nan=False, separators=(",", ":"))
            output.write("\n")
            output.flush()
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


class TelemetryWriter:
    """Single-run publisher. emit() never waits for disk or a full queue.

    Construct/close outside timing-sensitive worker callbacks. A queue overflow
    is explicit in the next snapshot and terminal summary; no fabricated samples
    fill the gap. Only finalization fsyncs the event stream. A hard process crash
    may therefore leave partial telemetry; the reader reports it as stale.
    """

    def __init__(self, directory, run_id: str, metadata: dict, *,
                 queue_capacity: int = 256, heartbeat_seconds: float = 1.0,
                 sample_limit: int = 120, event_limit: int = 200):
        if not isinstance(run_id, str) or not RUN_PATTERN.fullmatch(run_id) or run_id in {".", "..", "control"}:
            raise ValueError("Invalid live-demo run ID")
        if queue_capacity < 1 or not 0.05 <= heartbeat_seconds <= 5:
            raise ValueError("Invalid telemetry queue/heartbeat bounds")
        if not 1 <= sample_limit <= 120 or not 1 <= event_limit <= 200:
            raise ValueError("Invalid telemetry history bounds")
        requested = Path(directory).absolute()
        if requested.name != run_id or requested.is_symlink():
            raise ValueError("Telemetry directory must be the named nonsymlink run directory")
        new_directory = not requested.exists()
        requested.mkdir(parents=True, exist_ok=True)
        if new_directory:
            os.chmod(requested, 0o755)
        if requested.resolve() != requested:
            raise ValueError("Telemetry directory cannot resolve through a symlink")
        self.directory = requested
        self.events_path = requested / "events.jsonl"
        self.snapshot_path = requested / "snapshot.json"
        if self.events_path.exists() or self.snapshot_path.exists():
            raise FileExistsError("Existing live evidence will not be overwritten")
        self.run_id = run_id
        self.session_id = uuid.uuid4().hex
        self.boot_id = current_boot_id()
        self._metadata = _json_copy(metadata, 65536)
        self._queue = queue.Queue(maxsize=queue_capacity)
        self._heartbeat_seconds = heartbeat_seconds
        self._samples = deque(maxlen=sample_limit)
        self._events = deque(maxlen=event_limit)
        self._errors = deque(maxlen=20)
        self._sample_history_evictions = 0
        self._event_history_evictions = 0
        self._lock = threading.Lock()
        self._closed = False
        self._dropped = 0
        self._writer_error = None
        self._started = raw_ns()
        self._publisher = {"pid": os.getpid(), "start_ticks": _process_start_ticks(),
                           "heartbeat_definition": "telemetry publisher liveness, not traffic or sampler progress"}
        self._seq = 0
        self._state = {"status": "preparing", "phase": "preparing", "trial": 1,
                       "total_trials": self._metadata.get("total_trials", 1)}
        self._initial = threading.Event()
        self._thread = threading.Thread(target=self._work,
                                        name=f"live-telemetry-{run_id}", daemon=True)
        self._thread.start()
        if not self._initial.wait(5):
            raise RuntimeError("Telemetry writer did not initialize within five seconds")
        if self._writer_error:
            raise RuntimeError(self._writer_error)

    def emit(self, event: str, **fields) -> bool:
        if not isinstance(event, str) or not event or event.startswith("__"):
            raise ValueError("Invalid public telemetry event name")
        if RESERVED_FIELDS.intersection(fields):
            raise ValueError("Caller cannot override telemetry identity or clock fields")
        if "final_summary" in fields:
            raise ValueError("Final summaries must be supplied through close()")
        payload = _json_copy(fields, 65536)
        item = (event, payload, raw_ns())
        with self._lock:
            if self._closed or self._writer_error:
                return False
            try:
                self._queue.put_nowait(item)
            except queue.Full:
                self._dropped += 1
                return False
        return True

    def close(self, status: str = "completed", final_summary=None, error=None,
              final_summary_file=None, **fields) -> None:
        if status not in TERMINAL_STATUSES:
            raise ValueError("close() requires completed, failed or interrupted")
        if RESERVED_FIELDS.intersection(fields):
            raise ValueError("Caller cannot override telemetry identity or clock fields")
        payload = _json_copy(fields, 65536)
        payload.update(status=status, phase=status, error=str(error) if error is not None else None,
                       final_summary=_json_copy(final_summary, 2 * 1024 * 1024))
        if final_summary_file is not None:
            relative = Path(final_summary_file)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("Final summary file must be relative to this run")
            target = self.directory / relative
            if target.is_symlink() or not target.resolve().is_relative_to(self.directory):
                raise ValueError("Final summary file cannot escape this run")
            if target.stat().st_size > 4 * 1024 * 1024:
                raise ValueError("Final summary file exceeds its bounded size limit")
            with target.open("rb") as source:
                content = source.read(4 * 1024 * 1024 + 1)
            if len(content) > 4 * 1024 * 1024:
                raise ValueError("Final summary file exceeds its bounded size limit")
            payload["final_summary_file"] = {
                "path": relative.as_posix(),
                "sha256": hashlib.sha256(content).hexdigest()}
        with self._lock:
            if self._closed:
                if self._writer_error:
                    raise RuntimeError(self._writer_error)
                return
            self._closed = True
        if self._writer_error:
            raise RuntimeError(self._writer_error)
        try:
            self._queue.put(("__close__", payload, raw_ns()), timeout=5)
        except queue.Full as exc:
            raise RuntimeError("Telemetry finalization queue did not drain") from exc
        self._thread.join(5)
        if self._thread.is_alive():
            raise RuntimeError("Telemetry writer did not finalize within five seconds")
        if self._writer_error:
            raise RuntimeError(self._writer_error)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        status = "interrupted" if exc_type is KeyboardInterrupt else "failed" if exc else "completed"
        self.close(status, error=str(exc) if exc else None)
        return False

    def _snapshot(self, now: int, wall: str) -> dict:
        with self._lock:
            dropped = self._dropped
        snapshot = {"schema_version": SNAPSHOT_SCHEMA, "run_id": self.run_id,
                "session_id": self.session_id, "boot_id": self.boot_id,
                "seq": self._seq, "started_raw_ns": self._started,
                "heartbeat_raw_ns": now, "wall_time_utc": wall,
                "clock_domain": "CLOCK_MONOTONIC_RAW", "metadata": self._metadata,
                "publisher": self._publisher,
                **self._state, "samples": list(self._samples),
                "recent_events": list(self._events),
                "telemetry": {"dropped_events": dropped, "errors": list(self._errors),
                              "queue_capacity": self._queue.maxsize,
                              "sample_limit": self._samples.maxlen,
                              "event_limit": self._events.maxlen}}
        # Count bounds alone are insufficient when payloads approach 64 KiB.
        # Evict only dashboard history, never append-only events or final data.
        while len(json.dumps(snapshot, allow_nan=False, separators=(",", ":")).encode()) > 4 * 1024 * 1024 - 1024:
            if self._events:
                self._events.popleft()
                self._event_history_evictions += 1
                snapshot["recent_events"] = list(self._events)
            elif self._samples:
                self._samples.popleft()
                self._sample_history_evictions += 1
                snapshot["samples"] = list(self._samples)
            else:
                raise ValueError("Live snapshot core state exceeds its bounded size limit")
        snapshot["telemetry"].update(sample_history_evictions=self._sample_history_evictions,
                                     event_history_evictions=self._event_history_evictions)
        return snapshot

    def _record(self, output, event: str, fields: dict, produced: int) -> None:
        now = raw_ns()
        wall = _wall_label()
        self._seq += 1
        for key in ("phase", "trial", "total_trials", "status", "error", "final_summary",
                    "final_summary_file", "health", "final_sender", "final_accounting",
                    "sender_statistics", "phase_started_raw_ns", "phase_duration_seconds",
                    "measurement_started_raw_ns", "capture_accounting", "clock_audit", "verdicts",
                    "classification_results", "packet_progress", "source_example", "pcap_monitoring"):
            if key in fields:
                self._state[key] = fields[key]
        if event.endswith("_error") and fields.get("error"):
            self._errors.append(str(fields["error"]))
        if "status" not in fields and event != "heartbeat" and self._state["status"] == "preparing":
            if self._state["phase"] != "preparing":
                self._state["status"] = "running"
        if "sample" in fields:
            self._state["sample"] = fields["sample"]
            self._samples.append({"seq": self._seq, "raw_ns": produced,
                                  "phase": self._state["phase"],
                                  "trial": self._state["trial"], "sample": fields["sample"]})
        public_fields = {key: value for key, value in fields.items() if key != "final_summary"}
        if "final_summary" in fields:
            public_fields["final_summary_available"] = fields["final_summary"] is not None
        record = {"schema_version": EVENT_SCHEMA, "run_id": self.run_id,
                  "session_id": self.session_id, "boot_id": self.boot_id,
                  "seq": self._seq, "event": event, "event_raw_ns": now,
                  "produced_raw_ns": produced, "wall_time_utc": wall,
                  **public_fields}
        output.write(json.dumps(record, allow_nan=False, separators=(",", ":")) + "\n")
        output.flush()
        self._events.append(record)
        _atomic_json(self.snapshot_path, self._snapshot(now, wall))

    def _work(self) -> None:
        try:
            fd = os.open(self.events_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            os.fchmod(fd, 0o644)
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                self._record(output, "experiment_preparing", {"phase": "preparing"}, self._started)
                _atomic_json(self.directory.parent / "current.json", {
                    "schema_version": POINTER_SCHEMA, "run_id": self.run_id,
                    "session_id": self.session_id, "boot_id": self.boot_id,
                    "snapshot_path": f"{self.run_id}/snapshot.json", "updated_raw_ns": raw_ns()})
                self._initial.set()
                while True:
                    try:
                        event, fields, produced = self._queue.get(timeout=self._heartbeat_seconds)
                    except queue.Empty:
                        self._record(output, "heartbeat", {}, raw_ns())
                        continue
                    terminal = event == "__close__"
                    if terminal:
                        event = f"experiment_{fields['status']}"
                    self._record(output, event, fields, produced)
                    self._queue.task_done()
                    if terminal:
                        output.flush()
                        os.fsync(output.fileno())
                        break
        except Exception as exc:
            with self._lock:
                self._writer_error = f"Telemetry writer failed: {type(exc).__name__}: {exc}"
            self._state.update(status="failed", phase="failed", error=self._writer_error)
            # Best effort only: an unavailable filesystem may also prevent this
            # diagnostic. close() still raises and the previous heartbeat expires.
            try:
                diagnostic = self._snapshot(raw_ns(), _wall_label())
                diagnostic["telemetry"]["errors"] = [self._writer_error]
                _atomic_json(self.snapshot_path, diagnostic)
            except Exception:
                pass
            self._initial.set()
