"""Deterministic /proc fixtures: no switch, root, traffic, or extra dependency."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from performance_resources import ResourceSampler, parse_proc_stat, parse_proc_status


def stat_text(pid=42, user=100, system=30, start=999, comm="worker"):
    fields = ["S"] + ["0"] * 19
    fields[11], fields[12], fields[19] = str(user), str(system), str(start)
    return f"{pid} ({comm}) " + " ".join(fields) + "\n"


def status_text(rss=2048, hwm=4096, threads=4):
    text = f"Name:\tworker\nVmRSS:\t{rss} kB\nVmHWM:\t{hwm} kB\n"
    return text if threads is None else text + f"Threads:\t{threads}\n"


class ProcParsingTests(unittest.TestCase):
    def test_comm_may_contain_spaces_and_closing_parentheses(self):
        self.assertEqual(
            parse_proc_stat(stat_text(comm="worker ) unusual (name)"), 42),
            {"utime_ticks": 100, "stime_ticks": 30, "start_time_ticks": 999},
        )

    def test_stat_rejects_wrong_pid_missing_fields_and_negative_counters(self):
        for text in (stat_text(pid=43), "42 (worker) S", stat_text(user=-1)):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_proc_stat(text, 42)

    def test_status_kib_and_optional_threads(self):
        self.assertEqual(
            parse_proc_status(status_text(threads=None)),
            {"rss_kib": 2048, "vmhwm_kib": 4096, "threads": None},
        )

    def test_status_rejects_missing_and_wrong_units(self):
        for text in ("Threads: 2\n", status_text().replace("kB", "MB"), status_text(rss=-1)):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_proc_status(text)


class ResourceSamplerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory()
        self.proc_root = Path(self.fixture.name)
        self.process_dir = self.proc_root / "42"
        self.process_dir.mkdir()
        self.write_proc()

    def tearDown(self):
        self.fixture.cleanup()

    def write_proc(self, **kwargs):
        stat_kwargs = {key: kwargs[key] for key in ("user", "system", "start") if key in kwargs}
        status_kwargs = {key: kwargs[key] for key in ("rss", "hwm", "threads") if key in kwargs}
        (self.process_dir / "stat").write_text(stat_text(**stat_kwargs), encoding="utf-8")
        (self.process_dir / "status").write_text(status_text(**status_kwargs), encoding="utf-8")

    def sampler(self):
        # A large interval keeps fixtures deterministic: start/end snapshots only.
        return ResourceSampler(42, 10.0, self.proc_root, clock_ticks_per_second=100)

    def test_boundary_ticks_cpu_over_one_core_and_memory_units(self):
        sampler = self.sampler()
        # Enter, start snapshot, end snapshot, exit: exactly one wall second.
        with patch("performance_resources.time.monotonic", side_effect=[10.0, 10.0, 11.0, 11.0]):
            with sampler:
                self.write_proc(user=300, system=80, rss=3072, hwm=8192)
        result = sampler.summary()
        self.assertTrue(result["valid"])
        self.assertEqual(result["sample_count"], 2)
        self.assertEqual(result["cpu"]["seconds"], 2.5)
        self.assertEqual(result["cpu"]["percent_one_core"], 250.0)
        self.assertEqual(result["memory"]["rss_baseline_kib"], 2048)
        self.assertEqual(result["memory"]["rss_max_sampled_mib"], 3.0)
        self.assertEqual(result["memory"]["vmhwm_lifetime_mib"], 8.0)
        self.assertEqual(result["memory"]["rss_increase_from_baseline_kib"], 1024)
        self.assertTrue(result["sampler_thread_stopped"])

    def test_missing_process_is_invalid_not_zero_cpu(self):
        sampler = self.sampler()
        with sampler:
            (self.process_dir / "stat").unlink()
        result = sampler.summary()
        self.assertFalse(result["valid"])
        self.assertIsNone(result["cpu"]["seconds"])
        self.assertIsNone(result["memory"]["rss_max_sampled_kib"])
        self.assertEqual(result["errors"][0]["phase"], "end")

    def test_pid_reuse_invalidates_entire_window(self):
        sampler = self.sampler()
        with sampler:
            self.write_proc(start=1000)
        result = sampler.summary()
        self.assertFalse(result["valid"])
        self.assertIsNone(result["process_start_time_ticks"])
        self.assertTrue(any("PID reused" in error["message"] for error in result["errors"]))

    def test_intermediate_sample_keeps_rss_peak_when_end_rss_falls(self):
        sampler = self.sampler()
        with sampler:
            self.write_proc(rss=8192, hwm=8192)
            sampler._snapshot("interval")
            self.write_proc(rss=1024, hwm=8192)
        result = sampler.summary()
        self.assertTrue(result["valid"])
        self.assertEqual(result["sample_count"], 3)
        self.assertEqual(result["memory"]["rss_max_sampled_kib"], 8192)
        self.assertEqual(result["memory"]["rss_final_kib"], 1024)

    def test_intermediate_missing_status_is_invalid_even_if_end_recovers(self):
        sampler = self.sampler()
        with sampler:
            (self.process_dir / "status").unlink()
            sampler._snapshot("interval")
            self.write_proc()
        result = sampler.summary()
        self.assertFalse(result["valid"])
        self.assertIsNone(result["cpu"]["seconds"])
        self.assertEqual(result["errors"][0]["phase"], "interval")

    def test_individual_cpu_counter_regression_is_invalid_even_if_sum_grows(self):
        sampler = self.sampler()
        with sampler:
            self.write_proc(user=99, system=100)
        result = sampler.summary()
        self.assertFalse(result["valid"])
        self.assertIsNone(result["cpu"]["percent_one_core"])
        self.assertTrue(any("regressed" in error["message"] for error in result["errors"]))

    def test_zero_elapsed_window_is_invalid(self):
        sampler = self.sampler()
        with patch("performance_resources.time.monotonic", return_value=10.0):
            with sampler:
                pass
        self.assertFalse(sampler.summary()["valid"])
        self.assertIsNone(sampler.summary()["cpu"]["percent_one_core"])

    def test_backwards_snapshot_clock_is_invalid(self):
        sampler = self.sampler()
        with patch("performance_resources.time.monotonic", side_effect=[10.0, 10.5, 10.4, 11.0]):
            with sampler:
                pass
        result = sampler.summary()
        self.assertFalse(result["valid"])
        self.assertIsNone(result["cpu"]["seconds"])
        self.assertTrue(any("monotonically" in error["message"] for error in result["errors"]))

    def test_body_exception_propagates_and_thread_stops(self):
        sampler = self.sampler()
        with self.assertRaisesRegex(RuntimeError, "body failure"):
            with sampler:
                raise RuntimeError("body failure")
        self.assertTrue(sampler.summary()["sampler_thread_stopped"])

    def test_optional_threads_are_reported_as_unknown(self):
        self.write_proc(threads=None)
        sampler = self.sampler()
        with sampler:
            pass
        self.assertTrue(sampler.summary()["valid"])
        self.assertIsNone(sampler.summary()["threads"]["baseline"])

    def test_summary_requires_completed_window_and_sampler_cannot_be_reused(self):
        sampler = self.sampler()
        with self.assertRaises(RuntimeError):
            sampler.summary()
        with sampler:
            pass
        with self.assertRaises(RuntimeError):
            with sampler:
                pass


if __name__ == "__main__":
    unittest.main()
