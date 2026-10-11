"""Makefile dispatch dry-runs only: no launch, preparation, sudo or traffic."""
from pathlib import Path
import subprocess
import re
import unittest

REPO = Path(__file__).resolve().parents[1]


class DashboardMakefileTests(unittest.TestCase):
    def dry_run(self, target, *variables):
        return subprocess.run(["make", "-f", str(REPO / "Makefile"), "-n", target, *variables],
                              cwd=REPO, capture_output=True, text=True, timeout=5)

    def test_synthetic_default_command_is_preserved(self):
        result = self.dry_run("dashboard-live")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("tools/run_live_demo.py", result.stdout)
        self.assertIn('--mode "rf_c" --rate "250" --workload "classification-heavy"', result.stdout)
        self.assertNotIn("run_pcap_demo.py", result.stdout)

    def test_pcap_default_is_compare_and_does_not_use_synthetic_rate(self):
        result = self.dry_run("dashboard-live", "DEMO=pcap")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("tools/run_pcap_demo.py", result.stdout)
        self.assertIn('--mode "compare" --example "voip"', result.stdout)
        self.assertNotIn("--rate", result.stdout)
        self.assertNotIn("run_live_demo.py", result.stdout)

    def test_explicit_pcap_model_example_and_port_are_forwarded(self):
        result = self.dry_run("dashboard-live", "DEMO=pcap", "MODE=rf_b", "EXAMPLE=streaming", "DASHBOARD_PORT=8502")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--mode "rf_b" --example "streaming" --dashboard-port "8502"', result.stdout)

    def test_explicit_synthetic_selection_is_unchanged(self):
        result = self.dry_run("dashboard-live", "MODE=rf_b", "RATE=500", "WORKLOAD=cached-forwarding")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--mode "rf_b" --rate "500" --workload "cached-forwarding"', result.stdout)

    def test_unknown_demo_fails_before_any_launcher(self):
        result = self.dry_run("dashboard-live", "DEMO=invalid")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsupported DEMO", result.stderr)
        self.assertNotIn("run_pcap_demo.py", result.stdout)
        self.assertNotIn("run_live_demo.py", result.stdout)

    def test_catalog_target_is_read_only_list(self):
        result = self.dry_run("dashboard-pcap-examples")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('tools/pcap_demo_examples.py" list', result.stdout)
        self.assertNotIn("launch", result.stdout)
        self.assertNotIn("sudo", result.stdout)

    def test_dashboard_target_uses_same_manager_not_second_application(self):
        result = self.dry_run("dashboard")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('tools/dashboard_process.py" start', result.stdout)
        self.assertNotIn("streamlit run", result.stdout)

    def test_stage1_stage2_regression_commands_remain_named(self):
        text = (REPO / "Makefile").read_text()
        self.assertIn("tools.test_dashboard_evidence tools.test_dashboard_performance tools.test_dashboard_app", text)
        self.assertIn("tools.test_dashboard_process tools.test_live_telemetry tools.test_live_demo_transport", text)
        self.assertNotIn("unittest discover", text)
        for deferred in ("benchmark-live:", "reproduce-all:", "native-full:"):
            self.assertNotIn(deferred, text)

    def test_exact_thirteen_practical_targets(self):
        text = (REPO / "Makefile").read_text()
        targets = set(re.findall(r"^([a-z][a-z-]*):", text, re.MULTILINE))
        self.assertEqual(targets, {"help", "dashboard", "dashboard-status", "dashboard-evidence-status",
                                  "dashboard-stop", "dashboard-live", "dashboard-test", "dashboard-live-test",
                                  "dashboard-pcap-examples", "dashboard-pcap-test", "test", "status", "demo"})

    def test_status_alias_is_read_only(self):
        result = self.dry_run("status")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('dashboard_process.py" status', result.stdout)
        self.assertIn('tools/dashboard_status.py', result.stdout)
        self.assertNotIn('run_live_demo.py', result.stdout)
        self.assertNotIn('sudo', result.stdout)

    def test_test_alias_has_explicit_nonprivileged_scope(self):
        result = self.dry_run("test")
        self.assertEqual(result.returncode, 0, result.stderr)
        for module in ("tools.test_dashboard_history", "tools.test_dashboard_details", "tools.test_live_dashboard", "tools.test_pcap_live_dashboard"):
            self.assertIn(module, result.stdout)
        self.assertNotIn('unittest discover', result.stdout)
        self.assertNotIn('sudo', result.stdout)

    def test_demo_alias_announces_authorization_and_keeps_both_dispatches(self):
        for selectors, script in (((), "run_live_demo.py"), (("DEMO=pcap",), "run_pcap_demo.py")):
            with self.subTest(selectors=selectors):
                result = self.dry_run("demo", *selectors)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("terminal sudo authorization", result.stdout)
                self.assertIn(script, result.stdout)
                self.assertNotRegex(result.stdout, r"(?m)^sudo\s")

    def test_deferred_wrappers_are_not_fake_targets(self):
        text = (REPO / "Makefile").read_text()
        for target in ("figures", "replay-all", "native-pilot", "native-full", "benchmark", "reproduce-eval", "reproduce-all"):
            self.assertNotRegex(text, rf"(?m)^{target}:")
        guide = (REPO / "docs/dashboard-stage4.md").read_text()
        self.assertIn("Deferred wrappers", guide)
        self.assertIn("not the whole research suite", guide)


if __name__ == "__main__":
    unittest.main(verbosity=2)
