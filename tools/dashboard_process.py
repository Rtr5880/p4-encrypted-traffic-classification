#!/usr/bin/env python3
"""Normal-user Streamlit ownership manager. Never starts or stops BMv2."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import URLError
from urllib.request import urlopen

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
SCHEMA = "etc-dashboard-process-v2"
TERMINAL = {"completed", "failed", "interrupted", "stopped"}
_CHILDREN = {}  # Reap children created by this interpreter; never adopt wait ownership.


def require_user():
    if sys.platform != "linux" or not hasattr(os, "geteuid"):
        raise ValueError("Dashboard process management requires the normal Ubuntu/Linux user")
    if os.geteuid() == 0:
        raise ValueError("Do not use sudo for the dashboard; only the separate experiment worker needs root")


def validate_port(port):
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("Dashboard port must be an integer in [1024, 65535]")
    return port


def dashboard_command(repo=REPO, port=8501):
    repo = Path(repo).resolve()
    return [str(repo / ".venv/bin/python"), "-B", "-m", "streamlit", "run", str(repo / "dashboard/app.py"),
            "--server.address=127.0.0.1", f"--server.port={validate_port(port)}",
            "--server.headless=true", "--browser.gatherUsageStats=false"]


def process_identity(pid, proc_root=Path("/proc")):
    """PID + Linux process start ticks + real/effective UID + full argv."""
    if type(pid) is not int or pid <= 0:
        return None
    base = Path(proc_root) / str(pid)
    try:
        fields = (base / "stat").read_text().rsplit(")", 1)[1].split()
        if fields[0] == "Z":
            return None
        match = re.search(r"^Uid:\s+(\d+)\s+(\d+)", (base / "status").read_text(), re.M)
        if match is None:
            return None
        argv = [part.decode("utf-8", "strict") for part in (base / "cmdline").read_bytes().split(b"\0") if part]
        return {"pid": pid, "start_ticks": int(fields[19]), "uid": int(match[1]),
                "effective_uid": int(match[2]), "command": argv}
    except (OSError, ValueError, IndexError, UnicodeError):
        return None


def _record_valid(record, repo, port):
    allowed = dashboard_command(repo, port)
    return (isinstance(record, dict) and record.get("schema_version") == SCHEMA
            and record.get("repo") == str(Path(repo).resolve()) and record.get("port") == port
            and record.get("uid") == record.get("effective_uid") == os.geteuid()
            and type(record.get("pid")) is int and type(record.get("start_ticks")) is int
            and record.get("command") in (allowed, allowed + ["--server.fileWatcherType=none"]))


def _same_identity(record):
    actual = process_identity(record.get("pid"))
    return actual is not None and all(actual[key] == record[key]
            for key in ("pid", "start_ticks", "uid", "effective_uid", "command"))


def health(port):
    try:
        with urlopen(f"http://127.0.0.1:{port}/_stcore/health", timeout=.5) as response:
            return response.status == 200 and response.read(64).strip() == b"ok"
    except (URLError, OSError):
        return False


def port_occupied(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(.3)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def _listening_inodes(port, proc_root=Path("/proc")):
    inodes = set()
    for filename in ("tcp", "tcp6"):
        try:
            lines = (Path(proc_root) / "net" / filename).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) > 9 and fields[3] == "0A" and int(fields[1].rsplit(":", 1)[1], 16) == port:
                inodes.add(fields[9])
    return inodes


def pid_listens(pid, port, proc_root=Path("/proc")):
    inodes = _listening_inodes(port, proc_root)
    try:
        for descriptor in (Path(proc_root) / str(pid) / "fd").iterdir():
            try:
                target = os.readlink(descriptor)
                if target.startswith("socket:[") and target[8:-1] in inodes:
                    return True
            except OSError:
                continue
    except OSError:
        pass
    return False


def find_adoptable(repo, port, proc_root=Path("/proc")):
    expected = dashboard_command(repo, port)
    found = []
    for base in Path(proc_root).glob("[0-9]*"):
        identity = process_identity(int(base.name), proc_root)
        if (identity and identity["uid"] == identity["effective_uid"] == os.geteuid()
                and identity["command"] in (expected, expected + ["--server.fileWatcherType=none"])
                and pid_listens(identity["pid"], port, proc_root)):
            found.append(identity)
    return found


def _control(repo, port):
    path = Path(repo).resolve() / "results/live_demo/control"
    if path.is_symlink() or any(parent.is_symlink() for parent in (path.parent, path.parent.parent)):
        raise ValueError("Dashboard control directory must not traverse symlinks")
    path.mkdir(parents=True, exist_ok=True)
    if path.stat().st_uid != os.geteuid():
        raise ValueError("Dashboard control directory is not owned by the normal user")
    return path, path / ("dashboard.json" if port == 8501 else f"dashboard_{port}.json")


@contextmanager
def _locked(repo, port):
    control, record = _control(repo, port)
    lock_path = control / "dashboard.lock"
    if lock_path.is_symlink() or record.is_symlink():
        raise ValueError("Refusing symlink process-control files")
    with lock_path.open("a") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        yield control, record


def _read_record(path):
    try:
        value = json.loads(path.read_text())
        if not isinstance(value, dict):
            raise ValueError("Invalid dashboard ownership record")
        return value
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Unreadable dashboard ownership record: {error}") from error


def _write_record(path, record):
    fd, temporary = tempfile.mkstemp(prefix=".dashboard-owner-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(record, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def live_experiment_status(repo=REPO):
    """Reader state is evidence availability, not proof of worker ownership."""
    root = Path(repo).resolve() / "results/live_demo"
    try:
        from dashboard.live_evidence import read_live
        live = read_live(root=root)
        value = live.as_dict()
        status = value.get("status", "unavailable")
        return {"status": status, "run_id": value.get("run_id"),
                "active": status in {"preparing", "running", "starting", "warmup", "measuring", "draining", "accounting"},
                "phase": (value.get("snapshot") or value.get("data") or {}).get("phase"),
                "messages": value.get("messages", []), "meaning": "Telemetry heartbeat state; stale data is not an active-worker claim"}
    except (ImportError, ValueError, OSError, TypeError, AttributeError) as error:
        return {"status": "unavailable", "active": False, "run_id": None, "messages": [str(error)]}


def dashboard_status(repo=REPO, port=8501):
    require_user()
    port = validate_port(port)
    _, path = _control(repo, port)
    record = _read_record(path)
    result = {"schema_version": SCHEMA, "url": f"http://localhost:{port}", "port": port,
              "running": False, "owned": False, "status": "stopped", "pid": None,
              "live_experiment": live_experiment_status(repo)}
    if record:
        if not _record_valid(record, repo, port):
            result["status"] = "ownership_invalid"
        elif _same_identity(record):
            result.update(pid=record["pid"], owned=True, running=health(port),
                          status="running" if health(port) else "unhealthy")
        else:
            result["status"] = "stale_ownership"
    elif port_occupied(port):
        candidates = find_adoptable(repo, port)
        result.update(status="adoptable" if len(candidates) == 1 and health(port) else "unrelated_port_occupied",
                      running=len(candidates) == 1 and health(port), pid=candidates[0]["pid"] if len(candidates) == 1 else None)
    return result


def ensure_dashboard(repo=REPO, port=8501, timeout=25):
    require_user()
    repo = Path(repo).resolve()
    port = validate_port(port)
    with _locked(repo, port) as (control, record_path):
        record = _read_record(record_path)
        if record:
            if not _record_valid(record, repo, port):
                raise ValueError("Dashboard ownership record does not match this UID/repository/command; refusing replacement")
            if _same_identity(record):
                if not health(port) or not pid_listens(record["pid"], port):
                    raise ValueError("Owned dashboard is alive but unhealthy; inspect its log rather than starting a duplicate")
                return {**dashboard_status(repo, port), "action": "reused"}
            if process_identity(record["pid"]) is not None:
                raise ValueError("Recorded dashboard PID has a different identity; refusing to signal or replace it")
        if port_occupied(port):
            candidates = find_adoptable(repo, port)
            if len(candidates) != 1 or not health(port):
                raise ValueError(f"Port {port} is occupied by an unrelated or unverifiable service; nothing was stopped")
            record = {**candidates[0], "schema_version": SCHEMA, "repo": str(repo), "port": port,
                      "adopted": True, "ownership_note": "Exact Stage 1 command, same UID/start ticks and owned listening socket verified"}
            _write_record(record_path, record)
            return {**dashboard_status(repo, port), "action": "adopted"}
        command = dashboard_command(repo, port)
        if not Path(command[0]).is_file() or not Path(command[5]).is_file():
            raise ValueError("Existing .venv Python or dashboard/app.py is missing")
        log_path = control / f"dashboard_{port}.log"
        if log_path.is_symlink():
            raise ValueError("Refusing symlink dashboard log")
        with log_path.open("a") as log:
            child = subprocess.Popen(command, cwd=repo, stdin=subprocess.DEVNULL, stdout=log,
                                     stderr=subprocess.STDOUT, start_new_session=True)
        record = None
        try:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    raise ValueError(f"Dashboard startup failed; inspect {log_path}")
                identity = process_identity(child.pid)
                if identity and identity["command"] == command and health(port) and pid_listens(child.pid, port):
                    record = {**identity, "schema_version": SCHEMA, "repo": str(repo), "port": port,
                              "adopted": False, "log_path": str(log_path)}
                    _write_record(record_path, record)
                    _CHILDREN[child.pid] = child
                    return {**dashboard_status(repo, port), "action": "started"}
                time.sleep(.1)
            raise ValueError(f"Dashboard startup timed out; inspect {log_path}")
        except BaseException:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
            raise


def _signal_owned(record, sig):
    if not _same_identity(record):
        raise ValueError("Dashboard identity changed before stop; nothing was signalled")
    if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
        descriptor = os.pidfd_open(record["pid"])
        try:
            if not _same_identity(record):
                raise ValueError("Dashboard identity changed before pidfd signal")
            signal.pidfd_send_signal(descriptor, sig)
        finally:
            os.close(descriptor)
    else:
        os.kill(record["pid"], sig)


def stop_dashboard(repo=REPO, port=8501, timeout=5):
    require_user()
    port = validate_port(port)
    with _locked(repo, port) as (_, record_path):
        record = _read_record(record_path)
        if record is None:
            return {**dashboard_status(repo, port), "action": "not_owned_not_stopped"}
        if not _record_valid(record, repo, port):
            raise ValueError("Ownership record invalid; refusing to stop any process")
        if not _same_identity(record):
            return {**dashboard_status(repo, port), "action": "stale_identity_not_stopped"}
        _signal_owned(record, signal.SIGTERM)
        deadline = time.monotonic() + timeout
        while _same_identity(record) and time.monotonic() < deadline:
            time.sleep(.05)
        if _same_identity(record):
            _signal_owned(record, signal.SIGKILL)
            deadline = time.monotonic() + 2
            while _same_identity(record) and time.monotonic() < deadline:
                time.sleep(.05)
        if _same_identity(record):
            raise ValueError("Owned dashboard did not exit; retained ownership record")
        child = _CHILDREN.pop(record["pid"], None)
        if child is not None:
            child.wait(timeout=2)
        record_path.unlink()
        return {**dashboard_status(repo, port), "action": "stopped", "stopped_pid": record["pid"],
                "experiment_affected": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "status", "stop"))
    parser.add_argument("--port", type=int, default=8501)
    parser.add_argument("--repo", type=Path, default=REPO)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = {"start": ensure_dashboard, "status": dashboard_status, "stop": stop_dashboard}[args.action](args.repo, args.port)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Dashboard: {result['status']} ({result.get('action', 'status')}); URL: {result['url']}; PID: {result.get('pid')}")
            live = result["live_experiment"]
            print(f"Live experiment: {live['status']}; run={live.get('run_id')}; active={live.get('active', False)}")
            if args.action == "stop":
                print("Only the owned dashboard was targeted. An experiment worker, if active, is not stopped by this command.")
        return 0
    except (ValueError, OSError, RuntimeError) as error:
        print(f"DASHBOARD ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
