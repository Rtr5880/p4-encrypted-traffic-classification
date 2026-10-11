"""Linux OS-accounted process resources bounded by CLOCK_MONOTONIC_RAW.

No process is launched or signalled. CPU tick/time numerators are Linux
accounting observations, not independently calibrated physical CPU time. RAW's
external rate qualification applies to elapsed time only. Memory peaks are
explicitly distinguished as sampled-window RSS and process-lifetime VmHWM.
"""
from __future__ import annotations

import math
import os
from pathlib import Path
import threading
import time
from typing import Any, Callable


CLOCK_DOMAIN = "CLOCK_MONOTONIC_RAW"
CPU_CAVEAT = (
    "Linux OS-accounted CPU ticks/SC_CLK_TCK divided by RAW elapsed seconds; "
    "100% represents one accounted CPU core and can exceed 100%. The CPU "
    "accounting numerator is not independently frequency-qualified. RAW's "
    "+/-0.1% elapsed-time qualification does not qualify physical CPU utilization."
)


def raw_clock_ns() -> int:
    if not hasattr(time, "CLOCK_MONOTONIC_RAW"):
        raise RuntimeError("CLOCK_MONOTONIC_RAW is unavailable; no fallback permitted")
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)


def parse_proc_stat(text: str, expected_pid: int) -> dict[str, int]:
    prefix, separator, tail = text.strip().rpartition(")")
    if not separator or "(" not in prefix:
        raise ValueError("Malformed /proc/<pid>/stat")
    if int(prefix.partition("(")[0].strip()) != expected_pid:
        raise ValueError("/proc stat PID differs from requested process")
    fields = tail.split()
    if len(fields) < 20:
        raise ValueError("Missing /proc stat CPU/identity fields")
    values = dict(utime_ticks=int(fields[11]), stime_ticks=int(fields[12]),
                  start_time_ticks=int(fields[19]))
    if any(value < 0 for value in values.values()):
        raise ValueError("Negative /proc CPU/identity counter")
    return values


def parse_proc_status(text: str) -> dict[str, int | None]:
    values = {"rss_kib": None, "vmhwm_kib": None, "threads": None}
    labels = {"VmRSS": "rss_kib", "VmHWM": "vmhwm_kib", "Threads": "threads"}
    for line in text.splitlines():
        label, separator, value = line.partition(":")
        if not separator or label not in labels:
            continue
        parts = value.split()
        if label == "Threads":
            if len(parts) != 1:
                raise ValueError("Malformed Threads observation")
        elif len(parts) != 2 or parts[1] != "kB":
            raise ValueError("Expected Linux kB (KiB) memory units")
        number = int(parts[0])
        if number < 0:
            raise ValueError("Negative process resource observation")
        values[labels[label]] = number
    if values["rss_kib"] is None or values["vmhwm_kib"] is None:
        raise ValueError("Missing VmRSS or VmHWM")
    return values


class RawResourceSampler:
    """Start/end callbacks bound resource snapshots; RAW supplies all durations.

    Event.wait is merely a bounded wake-up aid. Snapshot timestamps always use
    RAW; the thread does not pretend its waits are RAW sleeps. Interval sampling
    is approximate and a sampled RSS maximum is never labelled an exact peak.
    """

    def __init__(self, pid: int, interval_seconds: float = .1,
                 proc_root: str | os.PathLike = "/proc",
                 clock_ticks_per_second: int | None = None,
                 clock_ns: Callable[[], int] | None = None):
        if type(pid) is not int or pid <= 0:
            raise ValueError("pid must be a positive integer")
        if not math.isfinite(interval_seconds) or interval_seconds < .05:
            raise ValueError("interval_seconds must be finite and >=0.05")
        ticks = int(os.sysconf("SC_CLK_TCK")) if clock_ticks_per_second is None else clock_ticks_per_second
        if type(ticks) is not int or ticks <= 0:
            raise ValueError("clock_ticks_per_second must be a positive integer")
        self.pid, self.interval_seconds = pid, float(interval_seconds)
        self.proc_root, self.clock_ticks_per_second = Path(proc_root), ticks
        self.clock_ns = raw_clock_ns if clock_ns is None else clock_ns
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._samples: list[dict[str, Any]] = []
        self._errors: list[dict[str, Any]] = []
        self._thread = None
        self._start_ns = self._end_ns = None
        self._entered = self._completed = False

    def _snapshot(self, phase: str):
        with self._lock:
            bracket_start = self.clock_ns()
            try:
                folder = self.proc_root / str(self.pid)
                first = parse_proc_stat((folder / "stat").read_text(), self.pid)
                memory = parse_proc_status((folder / "status").read_text())
                last = parse_proc_stat((folder / "stat").read_text(), self.pid)
                if last["start_time_ticks"] != first["start_time_ticks"]:
                    raise ValueError("PID reused within snapshot")
                if any(last[key] < first[key] for key in ("utime_ticks", "stime_ticks")):
                    raise ValueError("CPU counters regressed within snapshot")
                bracket_end = self.clock_ns()
                if bracket_end < bracket_start:
                    raise ValueError("RAW clock regressed within snapshot")
                self._samples.append(dict(phase=phase,
                    raw_ns=bracket_end,
                    raw_elapsed_seconds=(bracket_end - self._start_ns) / 1e9,
                    snapshot_bracket_ns=bracket_end - bracket_start,
                    **last, **memory))
            except (OSError, ValueError, UnicodeError) as error:
                self._errors.append(dict(phase=phase, raw_ns=self.clock_ns(),
                                         type=type(error).__name__, message=str(error)))

    def _sample_loop(self):
        while not self._stop.wait(self.interval_seconds):
            self._snapshot("interval")

    def __enter__(self):
        if self._entered:
            raise RuntimeError("RawResourceSampler cannot be reused")
        self._entered = True
        self._start_ns = self.clock_ns()
        self._snapshot("start")
        self._thread = threading.Thread(target=self._sample_loop,
            name=f"raw-resource-{self.pid}", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self._stop.set()
        self._snapshot("end")
        self._end_ns = self.clock_ns()
        self._thread.join(timeout=1.)
        self._completed = True
        if self._thread.is_alive():
            self._errors.append(dict(phase="cleanup", type="TimeoutError",
                message="Resource thread did not stop within one second"))
        return False

    def summary(self):
        if not self._completed:
            raise RuntimeError("Resource window has not completed")
        samples, errors = list(self._samples), list(self._errors)
        start = next((row for row in samples if row["phase"] == "start"), None)
        end = next((row for row in samples if row["phase"] == "end"), None)
        identities = {row["start_time_ticks"] for row in samples}
        duration = (self._end_ns - self._start_ns) / 1e9
        if len(identities) != 1 or start is None or end is None:
            errors.append(dict(phase="aggregate", message="Incomplete identity or PID reuse"))
        if any(right["utime_ticks"] < left["utime_ticks"] or
               right["stime_ticks"] < left["stime_ticks"]
               for left, right in zip(samples, samples[1:])):
            errors.append(dict(phase="aggregate", message="CPU counters regressed"))
        if (duration <= 0 or any(not 0 <= row["raw_elapsed_seconds"] <= duration for row in samples)
                or any(right["raw_ns"] < left["raw_ns"] for left, right in zip(samples, samples[1:]))):
            errors.append(dict(phase="aggregate", message="RAW resource window invalid"))
        valid = len(samples) >= 2 and not errors
        user_ticks = end["utime_ticks"] - start["utime_ticks"] if valid else None
        system_ticks = end["stime_ticks"] - start["stime_ticks"] if valid else None
        cpu_seconds = (user_ticks + system_ticks) / self.clock_ticks_per_second if valid else None
        rss = max(row["rss_kib"] for row in samples) if valid else None
        hwm = max(row["vmhwm_kib"] for row in samples) if valid else None
        return dict(pid=self.pid, valid=valid, clock_domain=CLOCK_DOMAIN,
            raw_duration_seconds=duration, wall_duration_seconds=duration,
            raw_window_start_ns=self._start_ns, raw_window_end_ns=self._end_ns,
            interval_seconds=self.interval_seconds, sample_count=len(samples),
            process_start_time_ticks=start["start_time_ticks"] if valid else None,
            window_definition="Entry through end snapshot, excluding sampler join; callbacks must surround measurement sending only, excluding warm-up and drain.",
            sampler_thread_stopped=not self._thread.is_alive(),
            cpu=dict(valid=valid, seconds=cpu_seconds,
                user_ticks_delta=user_ticks, system_ticks_delta=system_ticks,
                percent_one_core=100 * cpu_seconds / duration if valid else None,
                clock_ticks_per_second=self.clock_ticks_per_second,
                nominal_accounting_tick_seconds=1 / self.clock_ticks_per_second,
                cpu_resolution_note="User/system CPU counters are exposed in clock ticks; low CPU-time differences may be quantization-limited. No calibrated physical CPU uncertainty interval is assigned.",
                denominator_clock=CLOCK_DOMAIN, interpretation=CPU_CAVEAT,
                independently_qualified_physical_cpu_time=False),
            memory=dict(valid=valid, rss_baseline_kib=start["rss_kib"] if valid else None,
                rss_final_kib=end["rss_kib"] if valid else None,
                rss_max_sampled_kib=rss, rss_max_sampled_mib=rss / 1024 if valid else None,
                rss_increase_from_baseline_kib=rss - start["rss_kib"] if valid else None,
                vmhwm_lifetime_kib=hwm, vmhwm_lifetime_mib=hwm / 1024 if valid else None,
                interpretation="RSS maximum is sampled during this measurement window, not an exact peak. VmHWM is process-lifetime high-water RSS and may include warm-up; Linux kB means KiB."),
            samples=samples, errors=errors)


def invalid_resource_report(reason):
    return dict(valid=False, clock_domain=CLOCK_DOMAIN, errors=[str(reason)],
                cpu=dict(valid=False, seconds=None, percent_one_core=None),
                memory=dict(valid=False, rss_max_sampled_mib=None, vmhwm_lifetime_mib=None))


class RawMeasurementResources:
    """Drop-in start/stop/report callbacks; never include warm-up or drain."""
    def __init__(self, switch_pid, runner_rss_limit_mib=512):
        self.monitors = {"bmv2": RawResourceSampler(switch_pid),
                         "runner": RawResourceSampler(os.getpid())}
        self.runner_rss_limit_mib = runner_rss_limit_mib
        self.started = self.stopped = False
        self.entered, self.errors = [], []

    def start(self):
        if self.started:
            raise RuntimeError("Resource callbacks cannot be reused")
        self.started = True
        self.cpu_start, self.raw_start_ns = time.process_time(), raw_clock_ns()
        try:
            for key, monitor in self.monitors.items():
                monitor.__enter__()
                self.entered.append(key)
        except BaseException as error:
            self.errors.append(f"Resource start failed: {error}")
            self.stop()
            raise

    def stop(self):
        if not self.started or self.stopped:
            return
        self.cpu_end, self.raw_end_ns = time.process_time(), raw_clock_ns()
        for key in self.entered:
            try:
                self.monitors[key].__exit__(None, None, None)
            except BaseException as error:
                self.errors.append(f"{key} resource stop failed: {error}")
        self.stopped = True

    def report(self):
        if not self.started or not self.stopped:
            raise RuntimeError("Resource callbacks did not complete")
        result = {}
        for key, monitor in self.monitors.items():
            try:
                result[key] = monitor.summary() if key in self.entered else invalid_resource_report("Sampler did not enter")
            except (ValueError, RuntimeError, OSError) as error:
                result[key] = invalid_resource_report(error)
        if self.errors:
            for value in result.values():
                value["valid"] = False
                value["cpu"]["valid"] = value["memory"]["valid"] = False
                value.setdefault("errors", []).extend(self.errors)
        duration = (self.raw_end_ns - self.raw_start_ns) / 1e9
        result.update(clock_domain=CLOCK_DOMAIN,
            runner_process_time_seconds=self.cpu_end - self.cpu_start,
            callback_raw_seconds=duration, callback_wall_seconds=duration,
            runner_process_time_interpretation="Python process_time is OS-accounted CPU, not separately frequency-qualified.",
            window_meaning="Callbacks bracket measurement sending only, excluding warm-up, socket setup, capture drain and CLI. Per-process snapshot windows and offsets are retained.",
            rss_limit_mib=self.runner_rss_limit_mib)
        return result
