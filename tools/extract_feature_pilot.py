#!/usr/bin/env python3
"""Read ONE inventoried capture and validate first-4/8 B/C feature extraction.

Standard library plus TShark. Originals are never changed. Output is pilot-only:
capture-scoped bidirectional five-tuples are candidate conversations, NOT final
sessions. No timeout, tuple-reuse handling, model fitting or split assignment.
"""

import argparse
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid


B_FEATURES = ("size_min", "size_max", "size_sum", "iat_min", "iat_max", "iat_sum")
C_FEATURES = B_FEATURES + ("reverse_packet_count", "direction_change_count")
WINDOWS = (4, 8)
FIELDS = (
    "frame.number", "frame.time_epoch", "frame.len", "frame.cap_len",
    "frame.protocols", "ip.version", "ip.src", "ip.dst", "ip.proto",
    "ip.len", "ip.hdr_len", "ip.frag_offset", "ip.flags.mf",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
)
LABEL_REFERENCE = (
    "https://github.com/gfraysse/NOMS2024_Encrypted_Traffic_Classification/"
    "blob/main/iscxvpn2016-vpn-classifier.py"
)


def timestamp_ns(text):
    """Parse nonnegative epoch seconds exactly; never pass through float."""
    match = re.fullmatch(r"(\d+)(?:\.(\d{1,9}))?", text)
    if match is None:
        raise ValueError(f"Unsupported timestamp: {text!r}")
    return int(match[1]) * 1_000_000_000 + int((match[2] or "").ljust(9, "0"))


def parse_tshark_bool(text):
    """Accept TShark's textual and numeric Boolean forms, not truthy strings."""
    value = text.strip().lower()
    if value in ("true", "1"):
        return True
    if value in ("false", "0"):
        return False
    raise ValueError(f"Unsupported Boolean value: {text!r}")


class FieldValueError(ValueError):
    """Retain the field name without creating a counter key for every value."""

    def __init__(self, field):
        super().__init__(field)
        self.field = field


def read_field(row, field, converter=int):
    try:
        return converter(row[field])
    except (ValueError, TypeError) as error:
        raise FieldValueError(field) from error


@dataclass(frozen=True)
class Packet:
    frame: int
    timestamp_ns: int
    src: str
    dst: str
    sport: int
    dport: int
    protocol: int
    size: int


def make_key(packet):
    endpoints = sorted(((packet.src, packet.sport), (packet.dst, packet.dport)))
    return packet.protocol, endpoints[0], endpoints[1]


def decode_fields(values):
    """Reject unsupported/ambiguous rows, rather than mix header layers."""
    if len(values) != len(FIELDS):
        raise ValueError(f"TShark row has {len(values)} fields; expected {len(FIELDS)}")
    row = dict(zip(FIELDS, values))
    protocols = row["frame.protocols"].split(":")
    if "ipv6" in protocols:
        return None, "ipv6_or_ipv6_tunnel"
    if not row["ip.version"]:
        return None, "non_ipv4"
    if any("," in row[name] for name in FIELDS if name.startswith(("ip.", "tcp.", "udp."))):
        return None, "multiple_header_occurrences"
    if protocols.count("ip") != 1:
        return None, "ambiguous_ip_layer"
    if protocols[:2] != ["raw", "ip"]:
        return None, "unsupported_encapsulation_pilot_requires_raw_ip"
    try:
        if read_field(row, "ip.version") != 4:
            return None, "non_ipv4"
        src = str(read_field(row, "ip.src", ipaddress.IPv4Address))
        dst = str(read_field(row, "ip.dst", ipaddress.IPv4Address))
        proto = read_field(row, "ip.proto")
        if proto not in (6, 17):
            return None, "non_tcp_udp"
        if (read_field(row, "ip.frag_offset", lambda value: int(value, 0))
                or read_field(row, "ip.flags.mf", parse_tshark_bool)):
            return None, "ipv4_fragment"
        wire_size = read_field(row, "frame.len")
        captured_size = read_field(row, "frame.cap_len")
        if captured_size < wire_size:
            return None, "truncated_frame"
        size = read_field(row, "ip.len")
        header_size = read_field(row, "ip.hdr_len")
        if not (20 <= header_size <= 60 and header_size % 4 == 0):
            return None, "invalid_ipv4_header_length"
        if not (header_size + (20 if proto == 6 else 8) <= size <= 65535):
            return None, "invalid_ipv4_total_length"
        if size > captured_size:
            return None, "truncated_ip_packet"
        transport, other = ("tcp", "udp") if proto == 6 else ("udp", "tcp")
        if protocols.count(transport) != 1 or any(row[f"{other}.{name}"] for name in ("srcport", "dstport")):
            return None, "ambiguous_transport_layer"
        sport = read_field(row, f"{transport}.srcport")
        dport = read_field(row, f"{transport}.dstport")
        if not (0 <= sport <= 65535 and 0 <= dport <= 65535):
            return None, "invalid_port"
        if 53 in (sport, dport):
            return None, "port_53_baseline_exclusion"
        if (src, sport) == (dst, dport):
            return None, "identical_endpoints_direction_ambiguous"
        frame = read_field(row, "frame.number")
        if frame < 1:
            return None, "invalid_frame_number"
        return Packet(frame, read_field(row, "frame.time_epoch", timestamp_ns), src, dst,
                      sport, dport, proto, size), None
    except FieldValueError as error:
        return None, f"missing_or_invalid_header_field:{error.field}"


class FlowAccumulator:
    """Bounded first-eight state plus whole-conversation audit counters."""

    def __init__(self, first_packet, capture_id, capture_sha256, initial_class,
                 label_policy="capture-only"):
        if label_policy not in ("capture-only", "reference-port"):
            raise ValueError("Unknown label policy")
        self.key = make_key(first_packet)
        self.forward_endpoint = (first_packet.src, first_packet.sport)
        self.capture_id = capture_id
        self.capture_sha256 = capture_sha256
        identity = json.dumps([capture_id, capture_sha256, self.key], separators=(",", ":"))
        self.conversation_id = hashlib.sha256(identity.encode()).hexdigest()
        self.initial_class = initial_class
        self.label = initial_class
        self.label_basis = "capture_activity_hint"
        if (label_policy == "reference-port" and initial_class != "STREAMING"
                and {first_packet.sport, first_packet.dport} & {80, 443}):
            self.label, self.label_basis = "BROWSING", "port_80_443_heuristic"
        self.count = 0
        self.snapshots = {}
        self.trace = []
        self.features = dict.fromkeys(C_FEATURES, 0)
        self.raw_backward_steps = 0
        self.timestamp_adjustments = 0
        self.max_timestamp_adjustment_ns = 0
        self.max_gap_us = 0
        self.last_raw_ns = None
        self.effective_ns = None
        self.previous_direction = None
        self.add(first_packet)

    def add(self, packet):
        if make_key(packet) != self.key:
            raise ValueError("Packet does not belong to this bidirectional conversation")
        if not (0 <= packet.timestamp_ns and 0 < packet.size <= 65535):
            raise ValueError("Invalid packet timestamp or IPv4 length")
        if (packet.src, packet.sport) == (packet.dst, packet.dport):
            raise ValueError("Cannot orient identical endpoints")
        direction = "F" if (packet.src, packet.sport) == self.forward_endpoint else "R"
        gap = None
        adjustment = 0
        if self.count:
            self.raw_backward_steps += packet.timestamp_ns < self.last_raw_ns
            effective = max(self.effective_ns, packet.timestamp_ns)
            adjustment = effective - packet.timestamp_ns
            self.timestamp_adjustments += adjustment > 0
            self.max_timestamp_adjustment_ns = max(self.max_timestamp_adjustment_ns, adjustment)
            gap = effective // 1000 - self.effective_ns // 1000
            self.max_gap_us = max(self.max_gap_us, gap)
        else:
            effective = packet.timestamp_ns
        self.count += 1
        self.last_raw_ns, self.effective_ns = packet.timestamp_ns, effective
        if self.count <= max(WINDOWS):
            f = self.features
            f["size_min"] = packet.size if self.count == 1 else min(f["size_min"], packet.size)
            f["size_max"] = max(f["size_max"], packet.size)
            f["size_sum"] += packet.size
            if gap is not None:
                f["iat_min"] = gap if self.count == 2 else min(f["iat_min"], gap)
                f["iat_max"] = max(f["iat_max"], gap)
                f["iat_sum"] += gap
            f["reverse_packet_count"] += direction == "R"
            f["direction_change_count"] += self.count > 1 and direction != self.previous_direction
            self.trace.append({
                "frame": packet.frame, "raw_timestamp_ns": packet.timestamp_ns,
                "effective_timestamp_us": effective // 1000,
                "timestamp_adjustment_ns": adjustment, "size_bytes": packet.size,
                "direction": direction, "iat_us": gap,
            })
            if self.count in WINDOWS:
                if f["size_sum"] >= 2**19 or any(f[name] >= 2**48 for name in B_FEATURES if name.startswith("iat_")):
                    raise ValueError("Feature exceeds proposed unsigned width; no silent wrap/clipping")
                self.snapshots[self.count] = {
                    "features": dict(f), "trace": [dict(item) for item in self.trace],
                    "raw_backward_steps": self.raw_backward_steps,
                    "timestamp_adjustments": self.timestamp_adjustments,
                    "max_timestamp_adjustment_ns": self.max_timestamp_adjustment_ns,
                }
        self.previous_direction = direction

    def record(self, n):
        snapshot = self.snapshots[n]
        return {
            "schema_version": 1, "pilot_only": True, "training_ready": False,
            "record_id": f"{self.conversation_id}:n{n}",
            "candidate_conversation_id": self.conversation_id,
            "capture_id": self.capture_id, "capture_sha256": self.capture_sha256,
            "n": n, "label": self.label, "label_basis": self.label_basis,
            "initial_class": self.initial_class, "features": snapshot["features"],
            "debug_metadata_not_model_inputs": {
                "key": self.key, "forward_endpoint": self.forward_endpoint,
                "eligible_packets_in_conversation": self.count,
                "max_gap_us_entire_conversation": self.max_gap_us,
                "prefix_raw_backward_steps": snapshot["raw_backward_steps"],
                "prefix_timestamp_adjustments": snapshot["timestamp_adjustments"],
                "prefix_max_timestamp_adjustment_ns": snapshot["max_timestamp_adjustment_ns"],
                "trace": snapshot["trace"],
            },
        }


def fingerprint(path):
    before = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("Capture changed while hashing")
    return before, digest.hexdigest()


def select_capture(manifest_path, capture_name):
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise ValueError("Unsupported capture inventory schema")
    matches = [row for row in manifest["captures"] if row["filename"] == capture_name]
    if len(matches) != 1:
        raise ValueError("Select exactly one inventoried filename")
    capture = matches[0]
    if capture.get("include_in_baseline") is not True or not capture.get("initial_class"):
        raise ValueError("Selected capture is excluded or has no initial class")
    path = Path(capture["path"])
    print(f"Checking capture size and SHA-256: {path}", flush=True)
    stat, digest = fingerprint(path)
    if digest != capture["sha256"] or stat.st_size != capture["size_bytes"]:
        raise ValueError("Capture fingerprint differs from inventory; stop and review")
    return capture, path, stat


def write_json(path, data):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2)
        stream.write("\n")


def process_capture(command, out_dir, capture, label_policy, max_conversations):
    flows = {}
    rejected = Counter()
    total = 0
    with (out_dir / "tshark.stderr.log").open("x", encoding="utf-8") as stderr, \
            (out_dir / "field_parse_errors.jsonl").open("x", encoding="utf-8") as field_errors:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr,
                                   text=True, encoding="utf-8", errors="strict")
        try:
            for line in process.stdout:
                total += 1
                values = line.rstrip("\r\n").split("\t")
                packet, reason = decode_fields(values)
                if packet is None:
                    rejected[reason] += 1
                    # Keep a bounded local sample, not one diagnostic per packet.
                    if reason.startswith("missing_or_invalid_header_field:") and rejected[reason] <= 3:
                        field = reason.split(":", 1)[1]
                        field_errors.write(json.dumps({
                            "frame": values[FIELDS.index("frame.number")][:160],
                            "field": field,
                            "raw_value": values[FIELDS.index(field)][:160],
                            "reason": reason,
                        }) + "\n")
                else:
                    key = make_key(packet)
                    if key not in flows:
                        if len(flows) >= max_conversations:
                            raise ValueError("Conversation memory guard reached; no data silently dropped")
                        flows[key] = FlowAccumulator(packet, capture["capture_id"], capture["sha256"],
                                                     capture["initial_class"], label_policy)
                    else:
                        flows[key].add(packet)
                if total % 100000 == 0:
                    print(f"Read {total:,} frames; {len(flows):,} candidate conversations...", flush=True)
            code = process.wait()
            if code:
                raise ValueError(f"TShark exited with code {code}; inspect tshark.stderr.log")
        except BaseException:
            if process.poll() is None:
                process.kill()
            process.wait()
            raise
        finally:
            process.stdout.close()
    if not total or not flows:
        raise ValueError(f"No eligible conversations among {total} frames. Rejections: {dict(rejected)}")
    return flows, total, rejected


def save_results(out_dir, flows, total, rejected):
    by_n = {}
    for n in WINDOWS:
        included, short = Counter(), Counter()
        adjusted_prefixes = 0
        with (out_dir / f"features_n{n}.jsonl").open("x", encoding="utf-8") as stream:
            for flow in flows.values():
                if n in flow.snapshots:
                    included[flow.label] += 1
                    adjusted_prefixes += flow.snapshots[n]["timestamp_adjustments"] > 0
                    stream.write(json.dumps(flow.record(n), separators=(",", ":")) + "\n")
                else:
                    short[flow.label] += 1
        by_n[str(n)] = {
            "records": sum(included.values()), "eligible_by_provisional_class": dict(sorted(included.items())),
            "short_conversations": sum(short.values()), "short_by_provisional_class": dict(sorted(short.items())),
            "prefixes_with_timestamp_adjustments": adjusted_prefixes,
        }
    return {
        "status": "pilot_complete", "pilot_only": True, "training_ready": False,
        "frames_read": total, "eligible_packets": sum(flow.count for flow in flows.values()),
        "rejected_frames_by_first_reason": dict(sorted(rejected.items())),
        "field_conversion_diagnostics": "field_parse_errors.jsonl (up to 3 samples per failing field)",
        "candidate_conversations": len(flows), "windows": by_n,
        "per_conversation_timing_entire_capture": {
            "raw_backward_steps": sum(flow.raw_backward_steps for flow in flows.values()),
            "timestamp_adjustments": sum(flow.timestamp_adjustments for flow in flows.values()),
            "max_timestamp_adjustment_ns": max(flow.max_timestamp_adjustment_ns for flow in flows.values()),
            "largest_gap_us": max(flow.max_gap_us for flow in flows.values()),
            "conversations_with_gap_over_60s_audit_only": sum(flow.max_gap_us > 60_000_000 for flow in flows.values()),
        },
        "warning": "No timeout or tuple-reuse handling. Provisional labels, not verified activity ground truth. No train/test splits.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path.home() / "p4/etc-training/metadata/capture_inventory.json")
    parser.add_argument("--capture", required=True, help="One filename from the inventory")
    parser.add_argument("--output-root", type=Path, default=Path.home() / "p4/etc-training/pilot_results")
    parser.add_argument("--label-policy", choices=("capture-only", "reference-port"), default="capture-only")
    parser.add_argument("--max-conversations", type=int, default=50000)
    parser.add_argument("--tshark", default="tshark")
    args = parser.parse_args(argv)
    out_dir = None
    try:
        if args.max_conversations < 1:
            raise ValueError("--max-conversations must be positive")
        capture, path, before = select_capture(args.manifest.expanduser(), args.capture)
        version = subprocess.run([args.tshark, "--version"], capture_output=True, text=True,
                                 encoding="utf-8", check=True).stdout
        command = [args.tshark, "-n", "-r", str(path), "-T", "fields",
                   "-E", "occurrence=a", "-E", "aggregator=,"]
        for field in FIELDS:
            command.extend(["-e", field])
        output_root = args.output_root.expanduser()
        output_root.mkdir(parents=True, exist_ok=True)
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:10]
        out_dir = output_root / run_id
        out_dir.mkdir(exist_ok=False)
        write_json(out_dir / "policy.json", {
            "schema_version": 1, "pilot_only": True, "training_ready": False,
            "capture": capture, "tshark_command": command, "tshark_version": version,
            "extractor_sha256": fingerprint(Path(__file__))[1],
            "features_B": B_FEATURES, "features_C": C_FEATURES, "windows": WINDOWS,
            "size": "IPv4 ip.len in bytes, header plus payload; NOT Ethernet frame length",
            "timing": "Capture order; per-conversation running maximum in integer ns; floor each effective timestamp to us, then difference; N-1 gaps; real zeros retained",
            "orientation": "First eligible observed sender per candidate conversation is forward; not necessarily client",
            "grouping": "Capture identity + protocol + unordered endpoint pair; no timeout, no reset, no tuple-reuse disambiguation",
            "label_policy": args.label_policy, "label_reference": LABEL_REFERENCE,
            "labels_are_weak": True,
            "reference_port_rule": "If selected: either port 80/443 becomes BROWSING, except STREAMING; not proof of browsing",
            "filter": "Raw-IP encapsulation only, single IPv4 TCP/UDP layer; selected field/length validation; exclude fragments, truncation, either port 53, identical endpoints; retain ACK/control/retransmitted packets",
            "header_validation_limit": "Not a complete TCP/UDP option, length or checksum validator",
            "boolean_input_forms": "Case-insensitive True/False or 1/0; unknown/empty flags rejected",
            "field_conversion_diagnostics": "Counts by field; at most 3 local frame/value samples per failing field in field_parse_errors.jsonl",
            "proposed_feature_widths_bits": {"size_min": 16, "size_max": 16, "size_sum": 19,
                "iat_min": 48, "iat_max": 48, "iat_sum": 48, "reverse_packet_count": 3, "direction_change_count": 3},
            "p4_resource_allocation_verified": False,
            "model_inputs": "ONLY the explicit B or C feature allowlist; no identifiers, ports, addresses, labels, timestamps or trace fields",
            "short_policy": "Exclude separately for each N; count per provisional class",
            "max_conversations": args.max_conversations,
            "sixty_second_audit": "Only a descriptive gap count, NOT a chosen timeout",
            "limitations": ["Not session-disjoint training data", "Not verification of encryption or media content",
                "Synthetic arithmetic and offline capture timing do not establish live BMv2 timing fidelity"],
        })
        print("PILOT ONLY: reading one capture; originals unchanged; no training.", flush=True)
        flows, total, rejected = process_capture(command, out_dir, capture, args.label_policy, args.max_conversations)
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("Capture changed during extraction; results rejected")
        summary = save_results(out_dir, flows, total, rejected)
        write_json(out_dir / "summary.json", summary)
        print(json.dumps(summary, indent=2))
        print(f"Evidence saved to: {out_dir}")
        print("PILOT COMPLETE — NOT TRAINING-READY. Review summary and hand-check traces next.")
        return 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        if out_dir is not None:
            write_json(out_dir / "failure.json", {"status": "failed", "training_ready": False, "error": str(error)})
        print(f"ERROR: {error}", file=sys.stderr)
        if out_dir is not None:
            print(f"Incomplete diagnostic output only: {out_dir}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
