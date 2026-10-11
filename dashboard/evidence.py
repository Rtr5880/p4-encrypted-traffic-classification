"""Pinned, hash-verified historical evidence. No fitting, execution, or writes.

The registry is the authority for paths and expected hashes. A verified file is
authentic saved evidence, NOT necessarily a scientifically qualified result.
Scientific verdicts and per-metric gates remain in its unchanged JSON payload.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any


REGISTRY_SCHEMA = "dashboard-evidence-registry-v1"
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_JSONL_ROWS = 20_000
MAX_JSONL_LINE_BYTES = 1024 * 1024
MAX_HISTORY_ENTRIES = 256
HISTORY_SCHEMA = "dashboard-history-registry-v1"
KNOWN_ROLES = (
    "native_metrics", "controlled_replay", "rf_b", "rf_c",
    "raw_calibration", "higher_calibration", "performance_campaign",
)
CLASS_ORDER = ["CHAT", "FT", "MAIL", "P2P", "STREAMING", "VOIP"]


@dataclass(frozen=True)
class LoadedEvidence:
    role: str
    status: str
    data: dict[str, Any] | list[dict[str, Any]] | None
    path: Path | None
    sha256: str | None
    message: str
    entry: dict[str, Any]

    @property
    def verified(self) -> bool:
        return self.status == "verified"


class UnsupportedSchema(ValueError):
    """Authentic evidence whose schema this loader cannot interpret."""


def _strict_json(raw: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    def constant(value: str) -> None:
        raise ValueError(f"Non-finite JSON constant: {value}")

    def floating(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("Non-finite JSON number")
        return number

    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=constant, parse_float=floating)


def _require(value: Any, expected: type, name: str) -> None:
    if not isinstance(value, expected):
        raise ValueError(f"{name} must be a {expected.__name__}")


def _keys(data: dict[str, Any], required: tuple[str, ...], name: str) -> None:
    missing = [key for key in required if key not in data]
    if missing:
        raise ValueError(f"{name} is missing required keys: {', '.join(missing)}")


def _integer(value: Any, name: str) -> None:
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer")


def _relative_path(value: Any) -> Path:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise ValueError("Evidence path must be a nonempty portable relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or value in (".", ".."):
        raise ValueError("Evidence path must remain beneath its configured root")
    return path


def _features(data: Any, name: str) -> None:
    _require(data, dict, name)
    expected = {"size_min", "size_max", "size_sum", "iat_min", "iat_max", "iat_sum"}
    if name.endswith("_C"):
        expected.update(("reverse_packet_count", "direction_change_count"))
    if name.endswith(("_B", "_C")) and set(data) != expected:
        raise ValueError(f"{name} differs from the frozen six/eight feature definition")
    for key, value in data.items():
        _integer(value, f"{name}.{key}")


def _forest_report(data: Any, name: str) -> None:
    _require(data, dict, name)
    _keys(data, ("leaves", "scores", "prediction"), name)
    for key, length in (("leaves", 10), ("scores", 6)):
        values = data[key]
        if not isinstance(values, list) or len(values) != length:
            raise ValueError(f"{name}.{key} must contain {length} integers")
        for value in values:
            _integer(value, f"{name}.{key}")
    _integer(data["prediction"], f"{name}.prediction")
    if "valid" in data and (type(data["valid"]) is not int or data["valid"] not in (0, 1)):
        raise ValueError(f"{name}.valid must be the recorded 0/1 debug flag")
    # Before packet eight, debug reports deliberately carry valid=0 and the
    # no-prediction sentinel 255. Retain it; never turn it into a class decision.
    if data.get("valid") == 0:
        if data["prediction"] != 255 or any(data["leaves"]) or any(data["scores"]):
            raise ValueError(f"{name}: invalid report must retain the zero-score/leaf, prediction-255 sentinel")
    elif data["prediction"] >= 6:
        raise ValueError(f"{name}.prediction is outside the six-class ordering")


def _validate_detail_rows(rows: list[dict[str, Any]], parent_adapter: str, relative: str) -> None:
    """Validate supported historical record shapes, without recalculating verdicts."""
    identities = set()
    if parent_adapter == "native_run" and relative == "outcomes.jsonl":
        for row in rows:
            _keys(row, ("case_id", "record_id", "model", "label", "status", "timing",
                        "packet_checks", "features_B", "features_C", "clock_quality"), "native outcome")
            if row["model"] not in ("B", "C") or row["label"] not in CLASS_ORDER:
                raise ValueError("Unexpected native model or class")
            if not isinstance(row["case_id"], str) or not isinstance(row["record_id"], str):
                raise ValueError("Native record identities must be strings")
            identity = (row["case_id"], row["model"])
            if identity in identities:
                raise ValueError("Duplicate native case/model outcome")
            identities.add(identity)
            for key in ("timing", "clock_quality"):
                _require(row[key], dict, key)
            for key in ("features_B", "features_C"):
                _features(row[key], key)
            _require(row["status"], str, "status")
            _require(row["packet_checks"], list, "packet_checks")
            if row["status"] == "verified_classified" and len(row["packet_checks"]) != 8:
                raise ValueError("Verified native classification must have eight packet checks")
            for packet in row["packet_checks"]:
                _require(packet, dict, "packet check")
                for key in ("expected_fields", "feature_report"):
                    if key in packet:
                        _require(packet[key], dict, key)
                if packet.get("rf_report") is not None:
                    _forest_report(packet["rf_report"], "rf_report")
        return
    if parent_adapter == "controlled_replay" and Path(relative).name in (
        "expected_n8_instances.jsonl", "expected_rf_B.jsonl", "expected_rf_C.jsonl", "decisions.jsonl"
    ):
        for row in rows:
            _keys(row, ("record_id", "instance_id", "packet_id", "collision_excluded",
                        "features_B", "features_C"), "controlled decision")
            if not isinstance(row["record_id"], str) or not isinstance(row["instance_id"], str):
                raise ValueError("Controlled record identities must be strings")
            if row["record_id"] in identities:
                raise ValueError("Duplicate controlled decision identity")
            identities.add(row["record_id"])
            _integer(row["packet_id"], "packet_id")
            if type(row["collision_excluded"]) is not bool:
                raise ValueError("collision_excluded must be boolean")
            for key in ("features_B", "features_C"):
                _features(row[key], key)
            if Path(relative).name.startswith("expected_rf_"):
                _forest_report(row, "expected forest")
            if Path(relative).name == "decisions.jsonl":
                _require(row.get("feature_report"), dict, "feature_report")
                _forest_report(row.get("rf_report"), "rf_report")


def _metric_block(data: Any, name: str) -> None:
    _require(data, dict, name)
    _keys(data, ("accuracy", "macro_f1", "macro_precision", "macro_recall",
                 "confusion_matrix", "per_class", "records", "class_order"), name)
    if data["class_order"] != CLASS_ORDER:
        raise ValueError(f"{name}: unsupported class ordering")
    if isinstance(data["records"], bool) or not isinstance(data["records"], int):
        raise ValueError(f"{name}.records must be an integer")
    for key in ("accuracy", "macro_f1", "macro_precision", "macro_recall"):
        value = data[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
            raise ValueError(f"{name}.{key} must be a fraction in [0, 1]")
    matrix = data["confusion_matrix"]
    if not isinstance(matrix, list) or len(matrix) != 6 or any(
        not isinstance(row, list) or len(row) != 6 or any(
            isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in row
        ) for row in matrix
    ):
        raise ValueError(f"{name}: expected a six-class count confusion matrix")
    if sum(map(sum, matrix)) != data["records"]:
        raise ValueError(f"{name}: matrix count does not match saved population")
    _require(data["per_class"], dict, f"{name}.per_class")
    for index, label in enumerate(CLASS_ORDER):
        stats = data["per_class"].get(label)
        _require(stats, dict, f"{name}.per_class.{label}")
        _keys(stats, ("precision", "recall", "f1", "support"), label)
        if stats["support"] != sum(matrix[index]):
            raise ValueError(f"{name}: per-class support disagrees with saved matrix")


def _validate_payload(data: Any, entry: dict[str, Any]) -> None:
    _require(data, dict, "Evidence JSON root")
    adapter = entry.get("adapter")
    allowed = {"native_metrics", "controlled_replay", "forest",
               "calibration_summary", "calibration_trial", "performance_campaign",
               "native_run", "native_population", "history_summary", "recovery_report"}
    if adapter not in allowed:
        raise UnsupportedSchema(f"Unsupported evidence adapter: {adapter!r}")
    if "schema_value" in entry:
        field = entry.get("schema_field", "schema_version")
        if data.get(field) != entry["schema_value"]:
            raise UnsupportedSchema(
                f"Expected {field}={entry['schema_value']!r}; found {data.get(field)!r}"
            )
    if adapter == "native_metrics":
        _keys(data, ("class_order", "models", "common_paired_population",
                     "timing_deviation", "clock_quality", "limitations",
                     "expected_records_per_model", "labels_verified_per_flow"), adapter)
        _require(data["models"], dict, "models")
        paired = data["common_paired_population"]
        _require(paired, dict, "common_paired_population")
        _keys(paired, ("capture_time_metrics_on_same_records", "native_metrics",
                       "records", "coverage", "case_ids"), "paired population")
        for model in ("B", "C"):
            _metric_block(paired["capture_time_metrics_on_same_records"].get(model),
                          f"Capture-time RF-{model}")
            _metric_block(paired["native_metrics"].get(model), f"Native RF-{model}")
            if model not in data["models"]:
                raise ValueError(f"Missing RF-{model} native model report")
        if data["class_order"] != CLASS_ORDER:
            raise ValueError("Unexpected native class order")
        if len(paired["case_ids"]) != paired["records"] or len(set(paired["case_ids"])) != paired["records"]:
            raise ValueError("Paired population identifiers are inconsistent")
    elif adapter == "controlled_replay":
        _keys(data, ("status", "captures", "captures_checked", "accuracy_scored",
                     "native_clock_replay", "performance_measured", "output_sha256"), adapter)
        _require(data["captures"], list, "captures")
        if len(data["captures"]) != data["captures_checked"]:
            raise ValueError("Controlled replay capture count is inconsistent")
        for capture in data["captures"]:
            _require(capture, dict, "capture")
            _keys(capture, ("capture", "models", "preparation", "status"), "capture")
            for model in ("B", "C"):
                _require(capture["models"].get(model), dict, f"RF-{model} capture result")
    elif adapter == "forest":
        _keys(data, ("classes", "feature_order", "feature_set", "parameters",
                     "score_scale", "trees", "domains"), adapter)
        if data["classes"] != CLASS_ORDER or data["feature_set"] != entry.get("feature_set"):
            raise ValueError("Forest class/feature identity differs from pinned role")
        _require(data["trees"], list, "trees")
        if len(data["trees"]) != data["parameters"].get("n_estimators"):
            raise ValueError("Forest tree count disagrees with saved configuration")
        for tree in data["trees"]:
            _require(tree, dict, "tree")
            _require(tree.get("nodes"), list, "tree.nodes")
    elif adapter == "calibration_summary":
        _keys(data, ("status", "trials", "verdicts", "protocol", "raw_rate_qualified",
                     "expected_trials", "attempted_trials", "valid_trials",
                     "artifact_hashes", "kernel_forwarding_latency_qualified"), adapter)
        _require(data["trials"], list, "trials")
        if len(set(data["trials"])) != len(data["trials"]):
            raise ValueError("Duplicate trial identities in calibration evidence")
        if "expected_trial_count" in entry and data["expected_trials"] != entry["expected_trial_count"]:
            raise ValueError("Unexpected calibration schedule size")
    elif adapter == "calibration_trial":
        _keys(data, ("mode", "workload", "rate_pps", "repetition", "metrics",
                     "metric_validity", "verdicts", "raw_rate_qualified", "valid",
                     "kernel_forwarding_latency_qualified"), adapter)
        for key in ("metrics", "metric_validity", "verdicts"):
            _require(data[key], dict, key)
        for key, expected in entry.get("identity", {}).items():
            if data.get(key) != expected:
                raise ValueError(f"Calibration trial {key} differs from pinned identity")
    elif adapter == "native_run":
        _keys(data, ("status", "output_sha256", "expected_cases_per_model",
                     "expected_model_case_evaluations", "verified_classified_evaluations",
                     "native_clock", "raw_clock_clean", "passed"), adapter)
        _require(data["status"], str, "status")
        _require(data["output_sha256"], dict, "output_sha256")
        for key in ("expected_cases_per_model", "expected_model_case_evaluations", "verified_classified_evaluations"):
            _integer(data[key], key)
        for key in ("native_clock", "raw_clock_clean", "passed"):
            if type(data[key]) is not bool:
                raise ValueError(f"{key} must be boolean")
    elif adapter == "native_population":
        _keys(data, ("cases", "classes", "population", "input_sha256", "models_fitted"), adapter)
        _require(data["cases"], list, "cases")
        _require(data["input_sha256"], dict, "input_sha256")
        if data["classes"] != CLASS_ORDER:
            raise ValueError("Unexpected population class ordering")
        identities = set()
        for case in data["cases"]:
            _require(case, dict, "population case")
            _keys(case, ("case_id", "capture", "record", "packets", "relative_us",
                         "features_B", "features_C"), "population case")
            if not isinstance(case["case_id"], str) or case["case_id"] in identities:
                raise ValueError("Population case identities are invalid or duplicated")
            identities.add(case["case_id"])
            for key in ("capture", "record"):
                _require(case[key], dict, key)
            for key in ("packets", "relative_us"):
                _require(case[key], list, key)
            if len(case["packets"]) != 8 or len(case["relative_us"]) != 8:
                raise ValueError("Population case must have eight source packets/times")
            for packet in case["packets"]:
                _require(packet, dict, "source packet")
            for elapsed in case["relative_us"]:
                _integer(elapsed, "relative_us")
            for key in ("features_B", "features_C"):
                _features(case[key], key)
    elif adapter in ("history_summary", "recovery_report"):
        if adapter == "history_summary":
            _keys(data, ("status",), adapter)
            _require(data["status"], str, "status")
        else:
            _keys(data, ("source_run", "historical_final_summary_absent", "passed",
                         "attempted_trials", "local_valid_trials", "local_failed_trials"), adapter)
            for key in ("attempted_trials", "local_valid_trials", "local_failed_trials"):
                _integer(data[key], key)
        if "passed" in data and type(data["passed"]) is not bool:
            raise ValueError("Historical passed field must be boolean")
        for key in ("verdicts", "output_sha256", "artifact_hashes"):
            if key in data:
                _require(data[key], dict, key)
    else:
        _keys(data, ("status", "headline_counts", "metric_policy", "cells", "trials",
                     "supported_packet_delivery", "supported_rf_completion",
                     "clock_diagnosis", "evidence_roots", "prominent_warning"), adapter)
        _require(data["cells"], list, "cells")
        _require(data["trials"], list, "trials")
        if len(data["trials"]) != data["headline_counts"].get("acquired"):
            raise ValueError("Campaign trial population disagrees with headline count")


class EvidenceStore:
    """Read-only store with configurable roots; no unchecked child-path discovery.

    ETC_PROJECT_ROOT relocates project-relative pinned evidence.
    ETC_EXTERNAL_EVIDENCE_ROOT relocates the final report export directory.
    ETC_DASHBOARD_REGISTRY selects an explicit alternative registry.
    """

    def __init__(self, registry_path: str | Path | None = None,
                 project_root: str | Path | None = None,
                 history_path: str | Path | None = None) -> None:
        self.project_root = Path(project_root or os.environ.get("ETC_PROJECT_ROOT")
                                 or Path(__file__).resolve().parents[1]).expanduser().resolve()
        self.registry_path = Path(registry_path or os.environ.get("ETC_DASHBOARD_REGISTRY")
                                  or self.project_root / "config/dashboard-evidence.json").expanduser().resolve()
        self.history_path = Path(history_path or os.environ.get("ETC_DASHBOARD_HISTORY_REGISTRY")
                                 or os.environ.get("ETC_DASHBOARD_HISTORY")
                                 or self.project_root / "config/dashboard-history.json").expanduser().resolve()
        self.registry: dict[str, Any] = {}
        self.entries: dict[str, dict[str, Any]] = {}
        self._registry_error: tuple[str, str] | None = None
        try:
            raw = self.registry_path.read_bytes()
            if len(raw) > MAX_JSON_BYTES:
                raise ValueError("Registry exceeds size limit")
            registry = _strict_json(raw)
            _require(registry, dict, "Registry")
            if registry.get("schema_version") != REGISTRY_SCHEMA:
                raise UnsupportedSchema("Unsupported evidence registry schema")
            _require(registry.get("entries"), dict, "Registry entries")
            self.registry = registry
            self.entries = registry["entries"]
        except FileNotFoundError:
            self._registry_error = ("unavailable", f"Registry not found: {self.registry_path}")
        except UnsupportedSchema as exc:
            self._registry_error = ("unsupported", str(exc))
        except (OSError, ValueError, TypeError) as exc:
            self._registry_error = ("corrupt", f"Cannot load registry: {exc}")

    def _root(self, entry: dict[str, Any]) -> Path:
        root = entry.get("root", "project")
        if root == "project":
            return self.project_root
        if root == "external":
            value = os.environ.get("ETC_EXTERNAL_EVIDENCE_ROOT") or self.registry.get("external_root")
            if not value:
                raise FileNotFoundError("External evidence root is not configured")
            return Path(value).expanduser().resolve()
        raise ValueError(f"Unsupported registry root: {root!r}")

    def _load_entry(self, role: str, entry: dict[str, Any]) -> LoadedEvidence:
        path: Path | None = None
        digest: str | None = None
        safe_entry = entry if isinstance(entry, dict) else {}
        try:
            _require(entry, dict, "Registry entry")
            expected = entry.get("sha256")
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise ValueError("Registry entry has no valid pinned SHA-256")
            rel = _relative_path(entry.get("path"))
            root = self._root(entry)
            path = (root / rel).resolve()
            if not path.is_relative_to(root):
                raise ValueError("Evidence symlink/path escapes its configured root")
            if path.stat().st_size > MAX_JSON_BYTES:
                raise ValueError("Evidence JSON exceeds size limit")
            raw = path.read_bytes()
            if len(raw) > MAX_JSON_BYTES:
                raise ValueError("Evidence JSON exceeds size limit")
            digest = hashlib.sha256(raw).hexdigest()
            if digest != expected:
                raise ValueError("Evidence SHA-256 does not match pinned registry")
            data = _strict_json(raw)
            _validate_payload(data, entry)
            return LoadedEvidence(role, "verified", data, path, digest,
                                  "Pinned bytes and supported JSON schema verified; scientific verdicts remain separate.", entry)
        except FileNotFoundError as exc:
            return LoadedEvidence(role, "unavailable", None, path, digest, str(exc), safe_entry)
        except UnsupportedSchema as exc:
            return LoadedEvidence(role, "unsupported", None, path, digest, str(exc), safe_entry)
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
            return LoadedEvidence(role, "corrupt", None, path, digest, str(exc), safe_entry)

    def load(self, role: str) -> LoadedEvidence:
        if self._registry_error:
            status, message = self._registry_error
            return LoadedEvidence(role, status, None, None, None, message, {})
        entry = self.entries.get(role)
        if entry is None:
            return LoadedEvidence(role, "unavailable", None, None, None,
                                  f"No pinned evidence role: {role}", {})
        return self._load_entry(role, entry)

    def load_child(self, parent_role: str, relative: str, format: str = "json") -> LoadedEvidence:
        """Read one explicitly sealed child. Never discovers or executes files.

        JSONL is strict, bounded and fully validated; unlike live telemetry, an
        incomplete final line is not silently ignored in closed research evidence.
        """
        role = f"{parent_role}:{relative}"
        parent = self.load(parent_role)
        entry = {"parent_role": parent_role, "relative": relative, "format": format,
                 "run_id": parent.entry.get("run_id")}
        path = None
        digest = None
        if not parent.verified:
            return LoadedEvidence(role, parent.status, None, None, None,
                                  f"Parent evidence is not verified: {parent.message}", entry)
        try:
            if format not in ("json", "jsonl"):
                raise UnsupportedSchema(f"Unsupported sealed child format: {format!r}")
            rel = _relative_path(relative)
            if rel.suffix != "." + format:
                raise UnsupportedSchema("Child filename does not match its declared JSON format")
            _require(parent.data, dict, "Parent evidence")
            seals = parent.data.get("output_sha256", parent.data.get("artifact_hashes"))
            _require(seals, dict, "Parent child seal")
            expected = seals.get(relative)
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise ValueError("Requested child is not explicitly hash-sealed by the pinned parent")
            entry["sha256"] = expected
            assert parent.path is not None
            root = parent.path.parent.resolve()
            path = (root / rel).resolve()
            if not path.is_relative_to(root):
                raise ValueError("Sealed child symlink/path escapes its pinned run directory")
            if path.stat().st_size > MAX_JSON_BYTES:
                raise ValueError("Sealed child exceeds size limit")
            raw = path.read_bytes()
            if len(raw) > MAX_JSON_BYTES:
                raise ValueError("Sealed child exceeds size limit")
            digest = hashlib.sha256(raw).hexdigest()
            if digest != expected:
                raise ValueError("Sealed child SHA-256 differs from its pinned parent")
            if format == "json":
                data = _strict_json(raw)
                _require(data, dict, "Sealed child JSON root")
            else:
                data = []
                for number, line in enumerate(raw.splitlines(), 1):
                    if not line.strip():
                        continue
                    if len(line) > MAX_JSONL_LINE_BYTES:
                        raise ValueError(f"JSONL line {number} exceeds size limit")
                    if len(data) >= MAX_JSONL_ROWS:
                        raise ValueError("JSONL row count exceeds limit")
                    row = _strict_json(line)
                    _require(row, dict, f"JSONL row {number}")
                    data.append(row)
                _validate_detail_rows(data, parent.entry.get("adapter", ""), relative)
                if parent.entry.get("adapter") == "native_run" and relative == "outcomes.jsonl":
                    if len(data) != parent.data["expected_model_case_evaluations"]:
                        raise ValueError("Native outcomes count differs from its pinned run summary")
            final_parent = self.load(parent_role)
            if not final_parent.verified or final_parent.sha256 != parent.sha256:
                raise ValueError("Pinned parent changed while reading its sealed child")
            return LoadedEvidence(role, "verified", data, path, digest,
                                  "Pinned parent, child seal and bounded strict JSON verified; saved verdicts remain separate.", entry)
        except FileNotFoundError as exc:
            return LoadedEvidence(role, "unavailable", None, path, digest, str(exc), entry)
        except UnsupportedSchema as exc:
            return LoadedEvidence(role, "unsupported", None, path, digest, str(exc), entry)
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
            return LoadedEvidence(role, "corrupt", None, path, digest, str(exc), entry)

    def history_entries(self) -> list[dict[str, Any]]:
        """Explicit curated catalogue metadata; no newest-run promotion or globs."""
        try:
            if self.history_path.stat().st_size > MAX_JSON_BYTES:
                raise ValueError("History registry exceeds size limit")
            raw = self.history_path.read_bytes()
            if len(raw) > MAX_JSON_BYTES:
                raise ValueError("History registry exceeds size limit")
            payload = _strict_json(raw)
            _require(payload, dict, "History registry")
            if payload.get("schema_version") != HISTORY_SCHEMA:
                raise UnsupportedSchema("Unsupported history registry schema")
            entries = payload.get("entries")
            _require(entries, list, "History entries")
            if len(entries) > MAX_HISTORY_ENTRIES:
                raise ValueError("History entry count exceeds limit")
            identities = set()
            for entry in entries:
                _require(entry, dict, "History entry")
                _keys(entry, ("id", "family", "category", "label", "scope", "run_id", "path", "sha256", "adapter"), "History entry")
                for key in ("id", "family", "category", "label", "scope", "run_id"):
                    if not isinstance(entry[key], str) or not entry[key]:
                        raise ValueError(f"History {key} must be a nonempty string")
                if entry["id"] in identities:
                    raise ValueError("Duplicate history identity")
                identities.add(entry["id"])
                _relative_path(entry["path"])
                if not isinstance(entry["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
                    raise ValueError("History entry must have a pinned SHA-256")
            return entries
        except FileNotFoundError as exc:
            status, message = "unavailable", str(exc)
        except UnsupportedSchema as exc:
            status, message = "unsupported", str(exc)
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
            status, message = "corrupt", str(exc)
        return [{"id": "history-registry", "label": "History catalogue unavailable",
                 "registry_status": status, "message": message}]

    def load_history(self, history_id: str | None = None) -> list[LoadedEvidence]:
        entries = self.history_entries()
        if entries and "registry_status" in entries[0]:
            row = entries[0]
            return [LoadedEvidence("history-registry", row["registry_status"], None,
                                   self.history_path, None, row["message"], row)]
        selected = [row for row in entries if history_id is None or row["id"] == history_id]
        if not selected and history_id is not None:
            return [LoadedEvidence(f"history:{history_id}", "unavailable", None, None, None,
                                   "No explicitly curated history identity", {"id": history_id})]
        return [self._load_entry(f"history:{row['id']}", row) for row in selected]

    def calibration_trials(self) -> list[LoadedEvidence]:
        parent = self.load("raw_calibration")
        children = parent.entry.get("children", [])
        if not isinstance(children, list):
            return [LoadedEvidence("raw_calibration.trials", "corrupt", None,
                                   parent.path, None, "Pinned calibration children must be a list", {})]
        if not parent.verified:
            return [LoadedEvidence(f"raw_calibration.{index + 1:03d}", parent.status,
                                   None, None, None, f"Parent evidence not verified: {parent.message}",
                                   child if isinstance(child, dict) else {})
                    for index, child in enumerate(children)]
        try:
            assert parent.data is not None
            parent_rel = Path(parent.entry["path"]).parent
            names = []
            for child in children:
                _require(child, dict, "Pinned calibration child")
                if child.get("root", "project") != parent.entry.get("root", "project"):
                    raise ValueError("Calibration child root differs from parent")
                rel = Path(child["path"])
                if rel.parent.parent != parent_rel or rel.name != "qualified_trial_summary.json":
                    raise ValueError("Calibration child is not inside its pinned trial directory")
                names.append(rel.parent.name)
                if child["sha256"] != parent.data["artifact_hashes"].get(str(rel.relative_to(parent_rel))):
                    raise ValueError("Calibration child hash disagrees with verified parent seal")
            if names != parent.data["trials"] or len(set(names)) != len(names):
                raise ValueError("Pinned calibration child identities/order differ from verified parent")
        except (ValueError, TypeError, KeyError) as exc:
            return [LoadedEvidence("raw_calibration.trials", "corrupt", None,
                                   parent.path, None, str(exc), parent.entry)]
        return [self._load_entry(f"raw_calibration.{index + 1:03d}", child)
                for index, child in enumerate(children)]

    def status_rows(self) -> list[dict[str, Any]]:
        roles = list(self.entries) or list(KNOWN_ROLES)
        evidence = [self.load(role) for role in roles]
        if "raw_calibration" in roles:
            evidence.extend(self.calibration_trials())
        return [{"role": item.role, "status": item.status,
                 "path": str(item.path) if item.path is not None else None,
                 "sha256": item.sha256, "expected_sha256": item.entry.get("sha256"),
                 "run_id": item.entry.get("run_id"), "message": item.message}
                for item in evidence]
