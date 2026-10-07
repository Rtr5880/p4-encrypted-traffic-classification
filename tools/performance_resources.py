"""Read Linux child-process resources during one explicitly bounded window.

CPU is process CPU time divided by the sampling context's wall time, expressed
as a percentage of one CPU core. It can exceed 100% for a multithreaded process.
RSS maxima are sampled window measurements; VmHWM is a process-lifetime peak.
This module neither starts nor signals the monitored process.
"""

from __future__ import annotations

import math
import os
from pathlib import Path
import threading
import time
from typing import Any, Optional


def parse_proc_stat(text: str, expected_pid: int) -> dict[str, int]:
    """Parse fields without assuming the parenthesized comm lacks ')' or spaces."""
    prefix, separator, tail = text.strip().rpartition(")")
    if not separator or "(" not in prefix:
        raise ValueError("Malformed /proc/<pid>/stat: missing process comm")
    pid_text, _, _comm = prefix.partition("(")
    if int(pid_text.strip()) != expected_pid:
        raise ValueError("/proc stat PID does not match requested child")
    fields = tail.split()  # The first tail field is stat field 3, process state.
    if len(fields) < 20:
        raise ValueError("Malformed /proc/<pid>/stat: missing CPU/identity fields")
    result = {
        "utime_ticks": int(fields[11]),  # stat field 14
        "stime_ticks": int(fields[12]),  # stat field 15
        "start_time_ticks": int(fields[19]),  # stat field 22
    }
    if any(value < 0 for value in result.values()):
        raise ValueError("/proc stat contains a negative CPU/identity counter")
    return result


def parse_proc_status(text: str) -> dict[str, Optional[int]]:
    """Return Linux kB values (KiB) and optional thread count, without defaults."""
    result: dict[str, Optional[int]] = {
        "rss_kib": None,
        "vmhwm_kib": None,
        "threads": None,
    }
    keys = {"VmRSS": "rss_kib", "VmHWM": "vmhwm_kib", "Threads": "threads"}
    for line in text.splitlines():
        label, separator, value = line.partition(":")
        if not separator or label not in keys:
            continue
        parts = value.split()
        if not parts:
            raise ValueError(f"Missing value for {label} in process status")
        if label != "Threads" and (len(parts) != 2 or parts[1] != "kB"):
            raise ValueError(f"Unexpected unit for {label}; expected Linux kB (KiB)")
        if label == "Threads" and len(parts) != 1:
            raise ValueError("Malformed Threads value in process status")
        number = int(parts[0])
        if number < 0:
            raise ValueError(f"Negative {label} in process status")
        result[keys[label]] = number
    if result["rss_kib"] is None or result["vmhwm_kib"] is None:
        raise ValueError("Process status has no VmRSS or VmHWM measurement")
    return result


class ResourceSampler:
    """Sample a caller-owned Linux child; use one sampler per traffic window.

    Place the send and receive/drain phases inside the context if both belong to
    the benchmark window. The denominator covers context entry through the end
    snapshot, excluding the subsequent bounded sampler-thread join. Failed reads
    and PID reuse invalidate the aggregate instead of producing artificial zeros.
    """

    def __init__(
        self,
        pid: int,
        interval_seconds: float = 0.1,
        proc_root: str | os.PathLike[str] = "/proc",
        clock_ticks_per_second: Optional[int] = None,
    ) -> None:
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError("pid must be a positive caller-owned child PID")
        if not math.isfinite(interval_seconds) or interval_seconds < 0.05:
            raise ValueError("interval_seconds must be finite and at least 0.05")
        if clock_ticks_per_second is None:
            clock_ticks_per_second = int(os.sysconf("SC_CLK_TCK"))
        if (
            isinstance(clock_ticks_per_second, bool)
            or not isinstance(clock_ticks_per_second, int)
            or clock_ticks_per_second <= 0
        ):
            raise ValueError("clock_ticks_per_second must be a positive integer")
        self.pid = pid
        self.interval_seconds = float(interval_seconds)
        self.proc_root = Path(proc_root)
        self.clock_ticks_per_second = clock_ticks_per_second
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._samples: list[dict[str, Any]] = []
        self._errors: list[dict[str, Any]] = []
        self._thread: Optional[threading.Thread] = None
        self._window_start: Optional[float] = None
        self._window_end: Optional[float] = None
        self._entered = False
        self._completed = False

    def _snapshot(self, phase: str) -> None:
        with self._lock:
            try:
                process_dir = self.proc_root / str(self.pid)
                stat = parse_proc_stat(
                    (process_dir / "stat").read_text(encoding="utf-8"), self.pid
                )
                status = parse_proc_status(
                    (process_dir / "status").read_text(encoding="utf-8")
                )
                # Check identity on both sides of status to reject a PID reused
                # during the snapshot, as well as between separate snapshots.
                checked_stat = parse_proc_stat(
                    (process_dir / "stat").read_text(encoding="utf-8"), self.pid
                )
                if checked_stat["start_time_ticks"] != stat["start_time_ticks"]:
                    raise ValueError("PID reused while reading resource snapshot")
                if (
                    checked_stat["utime_ticks"] < stat["utime_ticks"]
                    or checked_stat["stime_ticks"] < stat["stime_ticks"]
                ):
                    raise ValueError("Process CPU counters regressed during snapshot")
                self._samples.append(
                    {
                        "phase": phase,
                        "elapsed_seconds": time.monotonic() - self._window_start,
                        **checked_stat,
                        **status,
                    }
                )
            except (OSError, ValueError, UnicodeError) as exc:
                self._errors.append(
                    {
                        "phase": phase,
                        "elapsed_seconds": time.monotonic() - self._window_start,
                        "type": type(exc).__name__,
                        "message": str(exc),
                    }
                )

    def _sample_loop(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            self._snapshot("interval")

    def __enter__(self) -> "ResourceSampler":
        if self._entered:
            raise RuntimeError("ResourceSampler cannot be reused")
        self._entered = True
        self._window_start = time.monotonic()
        self._snapshot("start")
        self._thread = threading.Thread(
            target=self._sample_loop,
            name=f"resource-sampler-{self.pid}",
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        self._stop.set()
        self._snapshot("end")
        self._window_end = time.monotonic()
        self._thread.join(timeout=1.0)
        self._completed = True
        if self._thread.is_alive():
            self._errors.append(
                {
                    "phase": "cleanup",
                    "elapsed_seconds": self._window_end - self._window_start,
                    "type": "TimeoutError",
                    "message": "Sampler thread did not stop within one second",
                }
            )
        return False

    def summary(self) -> dict[str, Any]:
        """Return completed-window aggregates; unknown values remain None."""
        if not self._completed:
            raise RuntimeError("Resource summary is available after context exit")
        duration = self._window_end - self._window_start
        samples = [dict(sample) for sample in self._samples]
        errors = [dict(error) for error in self._errors]
        start = next((sample for sample in samples if sample["phase"] == "start"), None)
        end = next((sample for sample in samples if sample["phase"] == "end"), None)
        identities = {sample["start_time_ticks"] for sample in samples}
        identity_valid = len(identities) == 1 and start is not None and end is not None
        if len(identities) > 1:
            errors.append(
                {"phase": "aggregate", "type": "ValueError", "message": "PID reused during measured window"}
            )
        cpu_monotonic = all(
            right["utime_ticks"] >= left["utime_ticks"]
            and right["stime_ticks"] >= left["stime_ticks"]
            for left, right in zip(samples, samples[1:])
        )
        if not cpu_monotonic:
            errors.append(
                {"phase": "aggregate", "type": "ValueError", "message": "Process CPU counters regressed during measured window"}
            )
        time_monotonic = duration > 0 and all(
            0 <= sample["elapsed_seconds"] <= duration for sample in samples
        ) and all(
            right["elapsed_seconds"] >= left["elapsed_seconds"]
            for left, right in zip(samples, samples[1:])
        )
        if not time_monotonic:
            errors.append(
                {"phase": "aggregate", "type": "ValueError", "message": "Sampling wall clock did not advance monotonically"}
            )
        valid = (
            len(samples) >= 2
            and identity_valid
            and cpu_monotonic
            and time_monotonic
            and not errors
        )
        cpu_seconds = (
            (
                end["utime_ticks"] + end["stime_ticks"]
                - start["utime_ticks"] - start["stime_ticks"]
            ) / self.clock_ticks_per_second
            if valid else None
        )
        # Do not mix memory values from different identities or partial windows.
        rss_values = [sample["rss_kib"] for sample in samples] if valid else []
        hwm_values = [sample["vmhwm_kib"] for sample in samples] if valid else []
        thread_values = [sample["threads"] for sample in samples if sample["threads"] is not None] if valid else []
        rss_max = max(rss_values) if rss_values else None
        baseline = start["rss_kib"] if valid else None
        return {
            "pid": self.pid,
            "valid": valid,
            "wall_duration_seconds": duration,
            "interval_seconds": self.interval_seconds,
            "sample_count": len(samples),
            "process_start_time_ticks": start["start_time_ticks"] if identity_valid else None,
            "window_definition": "Context entry through end snapshot; include traffic send/drain inside the context. Thread join is excluded.",
            "sampler_thread_stopped": not self._thread.is_alive(),
            "cpu": {
                "valid": valid,
                "seconds": cpu_seconds,
                "percent_one_core": 100.0 * cpu_seconds / duration if valid else None,
                "clock_ticks_per_second": self.clock_ticks_per_second,
                "interpretation": "Process CPU across all threads; 100% equals one fully occupied CPU core.",
            },
            "memory": {
                "valid": valid,
                "rss_baseline_kib": baseline,
                "rss_final_kib": end["rss_kib"] if valid else None,
                "rss_max_sampled_kib": rss_max,
                "rss_max_sampled_mib": rss_max / 1024.0 if rss_max is not None else None,
                "rss_increase_from_baseline_kib": rss_max - baseline if valid else None,
                "vmhwm_lifetime_kib": max(hwm_values) if hwm_values else None,
                "vmhwm_lifetime_mib": max(hwm_values) / 1024.0 if hwm_values else None,
                "interpretation": "RSS peak is sampled in this window; VmHWM is the high-water RSS for the entire process lifetime. Linux kB is KiB.",
            },
            "threads": {
                "baseline": start["threads"] if valid else None,
                "max_sampled": max(thread_values) if thread_values else None,
            },
            "samples": samples,
            "errors": errors,
        }
