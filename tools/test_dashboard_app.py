#!/usr/bin/env python3
"""Focused completed-dashboard UI/navigation/startup checks; no live traffic."""
from __future__ import annotations

import importlib
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from urllib.error import URLError
from urllib.request import urlopen

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

EXPECTED_PAGES = (
    ("Overview", "overview"),
    ("Classification", "classification"),
    ("P4 Correctness", "correctness"),
    ("Native Clock Evaluation", "native-clock"),
    ("Performance Evaluation", "performance"),
    ("Live Experiment Monitor", "live"),
    ("Experiment History", "history"),
)


def ui_text(app_test) -> str:
    """Read displayed textual elements without interpreting scientific metrics."""
    parts = []
    for kind in ("title", "header", "subheader", "markdown", "caption", "info", "warning", "error", "success", "text"):
        for element in getattr(app_test, kind):
            parts.append(str(element.value))
    return "\n".join(parts)


class TestDashboardNavigation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = importlib.import_module("dashboard.app")

    def test_seven_distinct_pages_and_routes(self):
        specs = self.app.PAGE_SPECS
        self.assertIsInstance(specs, tuple)
        self.assertEqual([(row["title"], row["slug"]) for row in specs], list(EXPECTED_PAGES))
        self.assertEqual(len({row["slug"] for row in specs}), 7)
        self.assertTrue(all(row["state"] == "ready" for row in specs))
        self.assertFalse(hasattr(self.app, "PLACEHOLDERS"))
        live = next(row for row in specs if row["slug"] == "live")
        self.assertEqual(live["state"], "ready")

    def test_navigation_uses_actual_streamlit_pages(self):
        store_class = importlib.import_module("dashboard.evidence").EvidenceStore
        calls = []

        def page_factory(callback, **kwargs):
            self.assertTrue(callable(callback))
            calls.append(kwargs)
            return object()

        with mock.patch.object(self.app.st, "Page", side_effect=page_factory):
            self.app.build_pages(store_class())
        self.assertEqual([row["title"] for row in calls], [title for title, _ in EXPECTED_PAGES])
        self.assertEqual(sum(bool(row.get("default")) for row in calls), 1)
        self.assertTrue(calls[0].get("default"))
        self.assertEqual([row["url_path"] for row in calls[1:]], [slug for _, slug in EXPECTED_PAGES[1:]])

    def test_sidebar_collapse_is_visible_without_hover(self):
        from dashboard.components import CSS
        self.assertIn('[data-testid="stSidebarCollapseButton"] { visibility:visible; }', CSS)

    def test_default_app_renders_without_exception(self):
        from streamlit.testing.v1 import AppTest

        result = AppTest.from_file(str(REPO / "dashboard/app.py"), default_timeout=60).run()
        self.assertEqual(len(result.exception), 0, [row.value for row in result.exception])
        self.assertTrue(ui_text(result).strip())

    def test_app_refuses_root_before_loading_evidence(self):
        from streamlit.testing.v1 import AppTest

        script = (
            "import sys\n"
            f"sys.path.insert(0, {str(REPO)!r})\n"
            "from unittest import mock\n"
            "from dashboard.app import main\n"
            "with mock.patch('os.geteuid', return_value=0):\n"
            "    main()\n"
        )
        result = AppTest.from_string(script, default_timeout=30).run()
        self.assertEqual(len(result.exception), 0)
        self.assertTrue(any("not with sudo" in element.value.lower() for element in result.error))
        self.assertEqual(len(result.metric), 0)

    def test_all_seven_page_renderers_without_exception(self):
        """Callable navigation has no switch_page file; test the same dispatcher."""
        from streamlit.testing.v1 import AppTest

        for title, _ in EXPECTED_PAGES:
            with self.subTest(page=title):
                script = (
                    "import sys\n"
                    f"sys.path.insert(0, {str(REPO)!r})\n"
                    "from dashboard.app import render_page\n"
                    "from dashboard.evidence import EvidenceStore\n"
                    f"render_page({title!r}, EvidenceStore())\n"
                )
                result = AppTest.from_string(script, default_timeout=60).run()
                self.assertEqual(len(result.exception), 0, [row.value for row in result.exception])
                self.assertTrue(ui_text(result).strip())
                self.assertNotIn("PAGE FOUNDATION", ui_text(result))
                if title in ("Classification", "P4 Correctness", "Native Clock Evaluation", "Experiment History"):
                    self.assertGreater(len(result.dataframe), 0, f"{title} must show actual evidence tables")
                    self.assertGreater(len(result.selectbox), 0, f"{title} must have a working evidence explorer")
                if title == "Live Experiment Monitor":
                    text = ui_text(result).lower()
                    self.assertTrue(any(word in text for word in ("inactive", "no experiment", "terminal", "demo-only")))
                    self.assertEqual(len(result.button), 0, "Browser must not expose a privileged live-launch button")

    def test_makefile_remains_bounded_and_regressions_are_named(self):
        text = (REPO / "Makefile").read_text(encoding="utf-8")
        self.assertIn("tools.test_dashboard_evidence tools.test_dashboard_performance tools.test_dashboard_app", text)
        self.assertNotIn("unittest discover", text)
        self.assertNotRegex(text, r"(?m)^\t@?(?:cd[^\n]*&&\s*)?sudo\s", "Make must not itself elevate the dashboard")
        for deferred in ("benchmark-live:", "reproduce-all:", "benchmark:"):
            self.assertNotIn(deferred, text)
        self.assertIn("dashboard-live:", text)
        self.assertIn("tools/dashboard_process.py", text)
        self.assertIn("tools/run_live_demo.py", text)
        self.assertIn("tools/run_pcap_demo.py", text)
        self.assertIn("dashboard-pcap-examples:", text)
        from tools.dashboard_process import dashboard_command
        command = dashboard_command(REPO, 8501)
        self.assertIn("--server.address=127.0.0.1", command)
        self.assertIn("--browser.gatherUsageStats=false", command)


class TestDashboardServerStartup(unittest.TestCase):
    def test_local_http_health_and_owned_process_cleanup(self):
        """Launch only Streamlit on an ephemeral local port; always stop our child."""
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.fail("Dashboard startup tests must run without sudo/root")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        command = [
            sys.executable, "-B", "-m", "streamlit", "run", str(REPO / "dashboard/app.py"),
            "--server.address=127.0.0.1", f"--server.port={port}",
            "--server.headless=true", "--browser.gatherUsageStats=false",
            "--server.fileWatcherType=none",
        ]
        with tempfile.TemporaryDirectory(prefix="etc-dashboard-startup-") as temporary:
            log_path = Path(temporary) / "server.log"
            with log_path.open("w", encoding="utf-8") as log:
                process = subprocess.Popen(command, cwd=temporary, stdout=log, stderr=subprocess.STDOUT)
                ready = False
                try:
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        if process.poll() is not None:
                            break
                        try:
                            with urlopen(f"http://127.0.0.1:{port}/_stcore/health", timeout=0.5) as response:
                                ready = response.status == 200 and response.read().strip() == b"ok"
                        except (URLError, OSError):
                            pass
                        if ready:
                            break
                        time.sleep(0.1)
                    self.assertTrue(ready, log_path.read_text(encoding="utf-8"))
                    with urlopen(f"http://127.0.0.1:{port}/", timeout=2) as response:
                        self.assertEqual(response.status, 200)
                        self.assertIn(b"<html", response.read().lower())
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
                self.assertIsNotNone(process.poll(), "Owned Streamlit test process was not cleaned up")


if __name__ == "__main__":
    unittest.main(verbosity=2)
