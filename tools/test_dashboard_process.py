"""Bounded normal-user dashboard lifecycle tests. No switch or packet sender."""
import json
import os
from pathlib import Path
import signal
import socket
import sys
import tempfile
import unittest
from unittest import mock

from tools import dashboard_process as manager


class DashboardProcessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="etc-dashboard-process-")
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        self.port = 18501
        self.identity = {"pid": 1234, "start_ticks": 5678, "uid": os.geteuid(),
                         "effective_uid": os.geteuid(), "command": manager.dashboard_command(self.repo, self.port)}
        self.record = {**self.identity, "schema_version": manager.SCHEMA,
                       "repo": str(self.repo), "port": self.port}

    def save_record(self):
        _, path = manager._control(self.repo, self.port)
        manager._write_record(path, self.record)
        return path

    def test_rejects_root_and_invalid_ports(self):
        with mock.patch.object(manager.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(ValueError, "Do not use sudo"):
                manager.ensure_dashboard(self.repo, self.port)
        for port in (0, 1023, 65536, True, "8501"):
            with self.assertRaises(ValueError):
                manager.validate_port(port)

    def test_exact_normal_user_command(self):
        command = manager.dashboard_command(self.repo, self.port)
        self.assertEqual(command[:5], [str(self.repo / ".venv/bin/python"), "-B", "-m", "streamlit", "run"])
        self.assertIn("--server.address=127.0.0.1", command)
        self.assertIn("--browser.gatherUsageStats=false", command)
        self.assertNotIn("sudo", command)

    def test_process_identity_reads_start_ticks_and_uids(self):
        base = self.repo / "proc/1234"
        base.mkdir(parents=True)
        fields = ["S"] + ["0"] * 18 + ["5678"] + ["0"] * 10
        (base / "stat").write_text("1234 (process name) " + " ".join(fields))
        (base / "status").write_text(f"Uid:\t{os.geteuid()}\t{os.geteuid()}\t0\t0\n")
        (base / "cmdline").write_bytes(b"\0".join(part.encode() for part in self.identity["command"]) + b"\0")
        self.assertEqual(manager.process_identity(1234, self.repo / "proc"), self.identity)
        self.assertIsNone(manager.process_identity(9999, self.repo / "proc"))

    def test_same_identity_requires_every_ownership_field(self):
        with mock.patch.object(manager, "process_identity", return_value=self.identity):
            self.assertTrue(manager._same_identity(self.record))
        for key in ("start_ticks", "uid", "effective_uid", "command"):
            changed = dict(self.identity)
            changed[key] = ["unrelated"] if key == "command" else changed[key] + 1
            with mock.patch.object(manager, "process_identity", return_value=changed):
                self.assertFalse(manager._same_identity(self.record))

    def test_reuse_never_spawns_second_server(self):
        self.save_record()
        with mock.patch.object(manager, "process_identity", return_value=self.identity), \
                mock.patch.object(manager, "health", return_value=True), \
                mock.patch.object(manager, "pid_listens", return_value=True), \
                mock.patch.object(manager.subprocess, "Popen") as spawn:
            result = manager.ensure_dashboard(self.repo, self.port)
        self.assertEqual(result["action"], "reused")
        spawn.assert_not_called()

    def test_adopt_exact_stage1_owner_and_preserve_pid(self):
        with mock.patch.object(manager, "port_occupied", return_value=True), \
                mock.patch.object(manager, "find_adoptable", return_value=[self.identity]), \
                mock.patch.object(manager, "process_identity", return_value=self.identity), \
                mock.patch.object(manager, "health", return_value=True), \
                mock.patch.object(manager.subprocess, "Popen") as spawn:
            result = manager.ensure_dashboard(self.repo, self.port)
        self.assertEqual(result["action"], "adopted")
        self.assertEqual(result["pid"], self.identity["pid"])
        spawn.assert_not_called()
        _, path = manager._control(self.repo, self.port)
        self.assertTrue(json.loads(path.read_text())["adopted"])

    def test_unrelated_occupied_port_is_not_killed_or_replaced(self):
        with mock.patch.object(manager, "port_occupied", return_value=True), \
                mock.patch.object(manager, "find_adoptable", return_value=[]), \
                mock.patch.object(manager.subprocess, "Popen") as spawn, \
                mock.patch.object(manager.os, "kill") as kill:
            with self.assertRaisesRegex(ValueError, "unrelated"):
                manager.ensure_dashboard(self.repo, self.port)
        spawn.assert_not_called()
        kill.assert_not_called()

    def test_changed_pid_identity_is_not_stopped(self):
        self.save_record()
        changed = dict(self.identity, start_ticks=999999)
        with mock.patch.object(manager, "process_identity", return_value=changed), \
                mock.patch.object(manager, "_signal_owned") as kill:
            result = manager.stop_dashboard(self.repo, self.port)
        self.assertEqual(result["action"], "stale_identity_not_stopped")
        kill.assert_not_called()

    def test_invalid_command_record_is_not_stopped(self):
        self.record["command"] = ["simple_switch"]
        self.save_record()
        with mock.patch.object(manager, "_signal_owned") as kill:
            with self.assertRaisesRegex(ValueError, "Ownership record invalid"):
                manager.stop_dashboard(self.repo, self.port)
        kill.assert_not_called()

    def test_pidfd_stop_signals_only_verified_dashboard(self):
        with mock.patch.object(manager, "_same_identity", return_value=True), \
                mock.patch.object(manager.os, "pidfd_open", return_value=41), \
                mock.patch.object(manager.signal, "pidfd_send_signal") as send, \
                mock.patch.object(manager.os, "close") as close:
            manager._signal_owned(self.record, signal.SIGTERM)
        send.assert_called_once_with(41, signal.SIGTERM)
        close.assert_called_once_with(41)

    def test_signal_refuses_identity_change(self):
        with mock.patch.object(manager, "_same_identity", return_value=False), \
                mock.patch.object(manager.os, "kill") as kill:
            with self.assertRaisesRegex(ValueError, "identity changed"):
                manager._signal_owned(self.record, signal.SIGTERM)
        kill.assert_not_called()

    def test_symlink_control_and_record_refused(self):
        outside = self.repo / "outside"
        outside.mkdir()
        parent = self.repo / "results/live_demo"
        parent.mkdir(parents=True)
        (parent / "control").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            manager.ensure_dashboard(self.repo, self.port)

    def test_atomic_record_has_no_partial_or_leftover_temporary_file(self):
        path = self.save_record()
        self.assertEqual(json.loads(path.read_text()), self.record)
        self.assertFalse(list(path.parent.glob(".dashboard-owner-*")))

    def test_stop_without_record_does_not_adopt_or_signal(self):
        with mock.patch.object(manager, "port_occupied", return_value=False), \
                mock.patch.object(manager, "_signal_owned") as kill:
            result = manager.stop_dashboard(self.repo, self.port)
        self.assertEqual(result["action"], "not_owned_not_stopped")
        kill.assert_not_called()

    def test_real_nonprivileged_start_reuse_status_stop(self):
        """Use an ephemeral port/control tree; never touch the actual 8501 app."""
        if os.geteuid() == 0:
            self.fail("Run the dashboard process tests as the ordinary user")
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        original_command = manager.dashboard_command
        with mock.patch.object(manager, "dashboard_command", side_effect=lambda repo, selected_port: original_command(manager.REPO, selected_port)):
            try:
                first = manager.ensure_dashboard(self.repo, port)
                self.assertEqual(first["action"], "started")
                second = manager.ensure_dashboard(self.repo, port)
                self.assertEqual(second["action"], "reused")
                self.assertEqual(first["pid"], second["pid"])
                self.assertTrue(manager.dashboard_status(self.repo, port)["running"])
            finally:
                stopped = manager.stop_dashboard(self.repo, port)
            self.assertEqual(stopped["action"], "stopped")
            self.assertFalse(stopped["experiment_affected"])
            self.assertFalse(manager.dashboard_status(self.repo, port)["running"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
