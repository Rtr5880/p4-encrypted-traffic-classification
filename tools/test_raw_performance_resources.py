"""Nonprivileged deterministic resource-window tests; no timing experiment."""
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

import raw_performance_resources as resources


def proc_stat(pid, user, system, identity=42):
    fields = ["S"] + ["0"] * 21
    fields[11], fields[12], fields[19] = str(user), str(system), str(identity)
    return f"{pid} (process name) " + " ".join(fields)


class ResourceTests(unittest.TestCase):
    def fixture(self, root, pid, user, system, rss=8192, hwm=1048576, identity=42):
        folder = Path(root) / str(pid)
        folder.mkdir(exist_ok=True)
        (folder / "stat").write_text(proc_stat(pid, user, system, identity))
        (folder / "status").write_text(f"VmRSS:\t{rss} kB\nVmHWM:\t{hwm} kB\nThreads:\t2\n")

    def test_cpu_uses_raw_duration_not_monotonic(self):
        with tempfile.TemporaryDirectory() as folder:
            self.fixture(folder, 123, 20, 10)
            clock = iter([0, 0, 0, 2_000_000_000, 2_000_000_000, 2_000_000_000])
            sampler = resources.RawResourceSampler(123, proc_root=folder,
                clock_ticks_per_second=100, clock_ns=lambda: next(clock))
            with patch.object(resources.time, "monotonic", side_effect=AssertionError("MONOTONIC must not supply duration")):
                with sampler:
                    self.fixture(folder, 123, 120, 110, rss=12288)
            report = sampler.summary()
            self.assertTrue(report["valid"])
            self.assertEqual(report["raw_duration_seconds"], 2)
            self.assertEqual(report["cpu"]["seconds"], 2)
            self.assertEqual(report["cpu"]["percent_one_core"], 100)
            self.assertEqual(report["cpu"]["denominator_clock"], "CLOCK_MONOTONIC_RAW")
            self.assertFalse(report["cpu"]["independently_qualified_physical_cpu_time"])
            self.assertIn("not independently", report["cpu"]["interpretation"])
            self.assertEqual(report["memory"]["rss_max_sampled_mib"], 12)
            self.assertEqual(report["memory"]["vmhwm_lifetime_mib"], 1024)
            self.assertIn("may include warm-up", report["memory"]["interpretation"])

    def test_pid_reuse_invalidates_not_zero(self):
        with tempfile.TemporaryDirectory() as folder:
            self.fixture(folder, 123, 20, 10)
            clock = iter([0, 0, 0, 2_000_000_000, 2_000_000_000, 2_000_000_000])
            sampler = resources.RawResourceSampler(123, proc_root=folder,
                clock_ticks_per_second=100, clock_ns=lambda: next(clock))
            with sampler:
                self.fixture(folder, 123, 120, 110, identity=43)
            report = sampler.summary()
            self.assertFalse(report["valid"])
            self.assertIsNone(report["cpu"]["seconds"])
            self.assertIsNone(report["memory"]["rss_max_sampled_mib"])
            self.assertTrue(report["errors"])

    def test_clock_domain_cannot_silently_fallback(self):
        with patch.object(resources.time, "clock_gettime_ns", create=True, return_value=9) as clock:
            with patch.object(resources.time, "CLOCK_MONOTONIC_RAW", create=True, new=4):
                self.assertEqual(resources.raw_clock_ns(), 9)
                clock.assert_called_once_with(4)

    def test_bad_units_and_pid_rejected(self):
        with self.assertRaises(ValueError):
            resources.parse_proc_status("VmRSS: 100 MB\nVmHWM: 100 MB\n")
        with self.assertRaises(ValueError):
            resources.parse_proc_stat(proc_stat(123, 1, 2), 124)


if __name__ == "__main__":
    unittest.main()
