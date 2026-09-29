#!/usr/bin/env python3
"""Export paired B/C first-N features from explicit candidate flow instances.

Raw captures and the original pilot are never changed. Labels remain capture
hints; this is NOT a verified-session dataset or an automatic training pipeline.
"""

import argparse
from collections import Counter
from contextlib import ExitStack
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import uuid

import extract_feature_pilot as pilot
from evaluate_idle_timeouts import select_names


B_FEATURES, C_FEATURES, WINDOWS = pilot.B_FEATURES, pilot.C_FEATURES, pilot.WINDOWS
TCP_FIELDS = ("tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset",
              "tcp.seq_raw", "tcp.ack_raw", "tcp.len")
FIELDS = pilot.FIELDS + TCP_FIELDS
POLICY_VERSION = "instances-v1"


@dataclass(frozen=True)
class Tcp:
    syn: bool
    ack: bool
    fin: bool
    rst: bool
    seq: int
    ack_number: int
    payload_len: int

    @property
    def bare_syn(self):
        return self.syn and not self.ack and not self.rst and not self.fin


def decode_fields(values):
    """Reuse packet eligibility; additionally require valid TCP boundary fields."""
    if len(values) != len(FIELDS):
        raise ValueError(f"TShark row has {len(values)} fields; expected {len(FIELDS)}")
    packet, reason = pilot.decode_fields(values[:len(pilot.FIELDS)])
    if packet is None:
        return None, None, reason
    row = dict(zip(TCP_FIELDS, values[len(pilot.FIELDS):]))
    if packet.protocol == 17:
        if any(row.values()):
            return None, None, "unexpected_tcp_control_fields_in_udp"
        return packet, None, None
    if any("," in value for value in row.values()):
        return None, None, "multiple_tcp_control_fields"
    try:
        flags = [pilot.read_field(row, name, pilot.parse_tshark_bool) for name in TCP_FIELDS[:4]]
        seq, ack, length = [pilot.read_field(row, name) for name in TCP_FIELDS[4:]]
    except pilot.FieldValueError as error:
        return None, None, f"missing_or_invalid_header_field:{error.field}"
    if not (0 <= seq < 2**32 and 0 <= ack < 2**32 and 0 <= length <= packet.size - 40):
        return None, None, "invalid_tcp_sequence_or_payload_length"
    return packet, Tcp(*flags, seq, ack, length), None


class Prefix:
    """Incremental features freeze at N; diagnostic traces are offline-only."""

    def __init__(self, first_packet):
        self.forward = (first_packet.src, first_packet.sport)
        self.count = 0
        self.last_us = None
        self.previous_direction = None
        self.features = dict.fromkeys(C_FEATURES, 0)
        self.trace, self.snapshots = [], {}
        self.adjustments = 0

    def add(self, packet, effective_ns, tcp):
        self.count += 1
        if self.count > max(WINDOWS):
            return
        now_us = effective_ns // 1000
        gap = None if self.last_us is None else now_us - self.last_us
        if gap is not None and gap < 0:
            raise ValueError("Effective time went backwards")
        direction = "F" if (packet.src, packet.sport) == self.forward else "R"
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
        adjustment = effective_ns - packet.timestamp_ns
        self.adjustments += adjustment > 0
        self.trace.append({"frame": packet.frame, "raw_timestamp_ns": packet.timestamp_ns,
            "effective_timestamp_us": now_us, "timestamp_adjustment_ns": adjustment,
            "size_bytes": packet.size, "direction": direction, "iat_us": gap,
            "tcp": None if tcp is None else asdict(tcp)})
        self.last_us, self.previous_direction = now_us, direction
        if self.count in WINDOWS:
            if f["size_sum"] >= 2**19 or any(f[k] >= 2**48 for k in B_FEATURES if k.startswith("iat_")):
                raise ValueError("Feature width exceeded; no silent clipping or wraparound")
            self.snapshots[self.count] = {
                "features_B": {k: f[k] for k in B_FEATURES},
                "features_C": dict(f), "trace": list(self.trace),
                "timestamp_adjustments": self.adjustments,
            }


class Instance:
    def __init__(self, packet, tcp, index, first_us, start_reason):
        self.index, self.first_frame, self.last_frame = index, packet.frame, packet.frame
        self.first_us = self.last_us = first_us
        self.start_reason = start_reason
        self.prefix = Prefix(packet)
        self.starts_with_bare_syn = bool(tcp and tcp.bare_syn)
        self.syns = {}  # At most two endpoint -> initial raw sequence numbers.
        self.non_syn_seen = False
        self.fin_endpoints = set()
        self.tcp_counts = Counter()

    def fresh_syn(self, packet, tcp):
        if tcp is None or not tcp.bare_syn:
            return False
        endpoint = packet.src, packet.sport
        if len(self.fin_endpoints) == 2:
            return True
        if self.syns.get(endpoint) == tcp.seq:
            return False  # Repeated opening signature; do not split retransmissions.
        if not self.non_syn_seen and self.syns and endpoint not in self.syns:
            return False  # Possible simultaneous open from the opposite endpoint.
        return True

    def observe_tcp(self, packet, tcp):
        if tcp is None:
            return
        endpoint, peer = (packet.src, packet.sport), (packet.dst, packet.dport)
        for name in ("syn", "fin", "rst"):
            self.tcp_counts[name] += getattr(tcp, name)
        if tcp.syn:
            self.syns.setdefault(endpoint, tcp.seq)
            if tcp.ack and not self.non_syn_seen:
                # SYN+ACK may be the first captured segment. Its ACK supplies
                # a candidate peer ISN for recognizing a late opening SYN.
                self.syns.setdefault(peer, (tcp.ack_number - 1) % 2**32)
        else:
            self.non_syn_seen = True
        if tcp.fin:
            self.fin_endpoints.add(endpoint)


@dataclass
class Parent:
    identity: str
    key: tuple
    last_raw_ns: int
    effective_ns: int
    count: int = 0
    next_index: int = 1
    active: object = None
    max_gap_us: int = 0


class Extractor:
    """One active candidate instance per tuple; never retain all packet bodies."""

    def __init__(self, capture, outputs, instances, idle_seconds=60,
                 boundary_policy="idle-tcp", max_conversations=50000):
        if type(idle_seconds) is not int or idle_seconds < 1:
            raise ValueError("idle_seconds must be a positive integer")
        if boundary_policy not in ("idle-only", "idle-tcp") or max_conversations < 1:
            raise ValueError("Invalid boundary policy or conversation limit")
        self.capture, self.outputs, self.instance_stream = capture, outputs, instances
        self.idle_us, self.boundary_policy = idle_seconds * 1_000_000, boundary_policy
        self.policy_id = f"{POLICY_VERSION}:{boundary_policy}:{idle_seconds}s"
        self.max_conversations, self.parents = max_conversations, {}
        self.eligible_packets = self.closed_packets = self.closed_instances = 0
        self.raw_backward_steps = self.timestamp_adjustments = self.max_adjustment_ns = 0
        self.start_reasons, self.end_reasons = Counter(), Counter()
        self.windows = {str(n): {"records": 0, "short_instances": 0,
            "prefixes_with_timestamp_adjustments": 0, "observation_delay_us_sum": 0,
            "observation_delay_us_max": 0} for n in WINDOWS}
        self.finished = False

    def close(self, parent, reason):
        instance = parent.active
        if instance is None:
            raise ValueError("Cannot close an absent instance")
        instance_id = f"{parent.identity}:{self.policy_id}:{instance.index}"
        metadata = {
            "schema_version": 1, "training_ready": False, "instance_id": instance_id,
            "parent_candidate_conversation_id": parent.identity,
            "capture_id": self.capture["capture_id"], "capture_sha256": self.capture["sha256"],
            "policy_id": self.policy_id, "instance_index": instance.index,
            "label": self.capture["initial_class"], "label_basis": "capture_activity_hint",
        }
        debug = {"key": parent.key, "forward_endpoint": instance.prefix.forward,
            "first_frame": instance.first_frame, "last_frame": instance.last_frame,
            "first_effective_us": instance.first_us, "last_effective_us": instance.last_us,
            "eligible_packets": instance.prefix.count, "start_reason": instance.start_reason,
            "end_reason": reason, "starts_with_bare_syn": instance.starts_with_bare_syn,
            "tcp_flag_counts": dict(instance.tcp_counts),
            "fin_directions_seen": len(instance.fin_endpoints)}
        self.instance_stream.write(json.dumps(dict(metadata, debug_metadata_not_model_inputs=debug), separators=(",", ":")) + "\n")
        for n in WINDOWS:
            stats = self.windows[str(n)]
            if n not in instance.prefix.snapshots:
                stats["short_instances"] += 1
                continue
            snapshot = instance.prefix.snapshots[n]
            trace = snapshot["trace"]
            delay = trace[-1]["effective_timestamp_us"] - trace[0]["effective_timestamp_us"]
            record = dict(metadata, record_id=f"{instance_id}:n{n}", n=n,
                features_B=snapshot["features_B"], features_C=snapshot["features_C"],
                debug_metadata_not_model_inputs=dict(debug, trace=trace,
                    decision_frame=trace[-1]["frame"], observation_delay_us=delay,
                    prefix_timestamp_adjustments=snapshot["timestamp_adjustments"]))
            self.outputs[n].write(json.dumps(record, separators=(",", ":")) + "\n")
            stats["records"] += 1
            stats["prefixes_with_timestamp_adjustments"] += snapshot["timestamp_adjustments"] > 0
            stats["observation_delay_us_sum"] += delay
            stats["observation_delay_us_max"] = max(stats["observation_delay_us_max"], delay)
        self.closed_instances += 1
        self.closed_packets += instance.prefix.count
        self.end_reasons[reason] += 1
        parent.active = None

    def add(self, packet, tcp):
        if self.finished:
            raise ValueError("Extractor already finished")
        if (packet.protocol == 6) != (tcp is not None):
            raise ValueError("TCP metadata does not match packet protocol")
        key = pilot.make_key(packet)
        parent = self.parents.get(key)
        gap_us = None
        if parent is None:
            if len(self.parents) >= self.max_conversations:
                raise ValueError("Conversation memory guard reached; no data silently dropped")
            identity = json.dumps([self.capture["capture_id"], self.capture["sha256"], key], separators=(",", ":"))
            parent = Parent(hashlib.sha256(identity.encode()).hexdigest(), key,
                            packet.timestamp_ns, packet.timestamp_ns)
            self.parents[key] = parent
        else:
            self.raw_backward_steps += packet.timestamp_ns < parent.last_raw_ns
            effective = max(parent.effective_ns, packet.timestamp_ns)
            adjustment = effective - packet.timestamp_ns
            self.timestamp_adjustments += adjustment > 0
            self.max_adjustment_ns = max(self.max_adjustment_ns, adjustment)
            gap_us = effective // 1000 - parent.effective_ns // 1000
            parent.max_gap_us = max(parent.max_gap_us, gap_us)
            parent.last_raw_ns, parent.effective_ns = packet.timestamp_ns, effective
        start_reason = "first_observed" if parent.count == 0 else "after_tcp_rst"
        if parent.active is not None:
            if gap_us >= self.idle_us:
                self.close(parent, "idle_timeout")
                start_reason = "idle_timeout"
            elif self.boundary_policy == "idle-tcp" and parent.active.fresh_syn(packet, tcp):
                self.close(parent, "fresh_tcp_syn")
                start_reason = "fresh_tcp_syn"
        elif parent.count and gap_us >= self.idle_us:
            start_reason = "idle_after_tcp_rst"
        if parent.active is None:
            parent.active = Instance(packet, tcp, parent.next_index,
                                     parent.effective_ns // 1000, start_reason)
            parent.next_index += 1
            self.start_reasons[start_reason] += 1
        instance = parent.active
        instance.prefix.add(packet, parent.effective_ns, tcp)
        instance.last_frame, instance.last_us = packet.frame, parent.effective_ns // 1000
        instance.observe_tcp(packet, tcp)
        parent.count += 1
        self.eligible_packets += 1
        # The reset packet belongs to the old instance and may be its Nth packet.
        if self.boundary_policy == "idle-tcp" and tcp is not None and tcp.rst:
            self.close(parent, "tcp_rst")

    def finish(self):
        if self.finished:
            raise ValueError("Extractor already finished")
        self.finished = True
        for parent in self.parents.values():
            if parent.active is not None:
                self.close(parent, "capture_end")
        if self.closed_packets != self.eligible_packets:
            raise ValueError("Packet conservation check failed")
        if sum(self.start_reasons.values()) != self.closed_instances:
            raise ValueError("Instance accounting failed")
        for stats in self.windows.values():
            if stats["records"] + stats["short_instances"] != self.closed_instances:
                raise ValueError("Prefix accounting failed")
        return {"filename": self.capture["filename"], "capture_id": self.capture["capture_id"],
            "capture_sha256": self.capture["sha256"], "provisional_class": self.capture["initial_class"],
            "candidate_conversations": len(self.parents), "instances": self.closed_instances,
            "eligible_packets": self.eligible_packets, "windows": self.windows,
            "start_reasons": dict(self.start_reasons), "end_reasons": dict(self.end_reasons),
            "timing": {"raw_backward_steps": self.raw_backward_steps,
                "timestamp_adjustments": self.timestamp_adjustments,
                "max_timestamp_adjustment_ns": self.max_adjustment_ns,
                "largest_parent_gap_us": max((p.max_gap_us for p in self.parents.values()), default=0)}}


def process_capture(command, directory, capture, args):
    rejected, total = Counter(), 0
    with ExitStack() as stack:
        outputs = {n: stack.enter_context((directory / f"features_n{n}.jsonl").open("x", encoding="utf-8")) for n in WINDOWS}
        instances = stack.enter_context((directory / "instances.jsonl").open("x", encoding="utf-8"))
        stderr = stack.enter_context((directory / "tshark.stderr.log").open("x", encoding="utf-8"))
        errors = stack.enter_context((directory / "field_parse_errors.jsonl").open("x", encoding="utf-8"))
        extractor = Extractor(capture, outputs, instances, args.idle_seconds,
                              args.boundary_policy, args.max_conversations)
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr,
                                   text=True, encoding="utf-8", errors="strict")
        try:
            for line in process.stdout:
                total += 1
                values = line.rstrip("\r\n").split("\t")
                packet, tcp, reason = decode_fields(values)
                if packet is not None:
                    extractor.add(packet, tcp)
                else:
                    rejected[reason] += 1
                    if reason.startswith("missing_or_invalid_header_field:") and rejected[reason] <= 3:
                        name = reason.split(":", 1)[1]
                        errors.write(json.dumps({"frame": values[0][:160], "field": name,
                                                "raw_value": values[FIELDS.index(name)][:160]}) + "\n")
                if total % 100000 == 0:
                    print(f"  Read {total:,} frames; {len(extractor.parents):,} parent tuples", flush=True)
            code = process.wait()
            if code:
                raise ValueError(f"TShark exited with code {code}; inspect {directory / 'tshark.stderr.log'}")
        except BaseException:
            if process.poll() is None:
                process.kill()
            process.wait()
            raise
        finally:
            process.stdout.close()
        if not extractor.eligible_packets:
            raise ValueError(f"No eligible packets; rejections: {dict(rejected)}")
        result = extractor.finish()
    result.update(frames_read=total, rejected_frames_by_first_reason=dict(sorted(rejected.items())))
    if result["eligible_packets"] + sum(rejected.values()) != total:
        raise ValueError("Capture accounting failed")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path.home() / "p4/etc-training/metadata/capture_inventory.json")
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--capture", action="append")
    selection.add_argument("--all-included", action="store_true")
    parser.add_argument("--idle-seconds", type=int, default=60)
    parser.add_argument("--boundary-policy", choices=("idle-only", "idle-tcp"), default="idle-tcp")
    parser.add_argument("--max-conversations", type=int, default=50000)
    parser.add_argument("--output-root", type=Path, default=Path.home() / "p4/etc-training/results/flow_instances")
    parser.add_argument("--tshark", default="tshark")
    args = parser.parse_args(argv)
    directory = None
    try:
        if args.idle_seconds < 1 or args.max_conversations < 1:
            raise ValueError("Idle seconds and conversation limit must be positive")
        manifest_path = args.manifest.expanduser()
        manifest_hash = pilot.fingerprint(manifest_path)[1]
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        names = select_names(manifest, args.capture, args.all_included)
        selected = [c for c in manifest["captures"] if c["filename"] in names]
        if len({c["capture_id"] for c in selected}) != len(selected) or len({c["sha256"] for c in selected}) != len(selected):
            raise ValueError("Duplicate capture identity/content; review before extracting dependent copies")
        version = subprocess.run([args.tshark, "--version"], capture_output=True, text=True,
                                 encoding="utf-8", check=True).stdout
        root = args.output_root.expanduser()
        root.mkdir(parents=True, exist_ok=True)
        directory = root / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:10])
        directory.mkdir(exist_ok=False)
        pilot.write_json(directory / "policy.json", {
            "schema_version": 1, "policy_version": POLICY_VERSION,
            "training_ready": False, "label_policy": "capture-only", "labels_verified": False,
            "idle_seconds": args.idle_seconds, "boundary_policy": args.boundary_policy,
            "hard_timeout": None, "windows": WINDOWS,
            "features_B": B_FEATURES, "features_C": C_FEATURES,
            "timing": "Capture order; parent-tuple running maximum in integer ns; floor timestamps to us before subtracting; N-1 gaps; no initial zero",
            "idle_rule": "Gap >= threshold before arrival; arriving packet starts new instance; every eligible packet refreshes last-seen",
            "tcp_rule": "idle-tcp: fresh bare SYN signature starts instance; repeated opening SYN and possible simultaneous open stay together; RST included then closes instance",
            "fin_rule": "FIN is observed, not immediate expiry; both-FIN observation makes a later bare SYN a new instance",
            "post_rst_rule": "Subsequent packets start a candidate continuation, even without SYN; explicitly marked, not verified new connections",
            "tcp_limitations": "No receive-window/RST acceptability validation, complete handshake/FIN-ACK tracking, TIME-WAIT or disambiguation of same-ISN tuple reuse; late segments may be ambiguous",
            "orientation": "First eligible sender of EACH instance defines forward, not necessarily client",
            "size": "IPv4 ip.len in bytes, not Ethernet length or TCP payload length",
            "model_input_rule": "ONLY features_B or features_C; all IDs, ports, flags, traces and timing metadata are excluded",
            "grouping_rule": "Retain parent_candidate_conversation_id and capture provenance; instance IDs are NOT proof of independent sessions",
            "p4_semantics_verified": False, "train_test_split_assigned": False,
            "captures": names, "manifest_sha256": manifest_hash, "tshark_version": version,
            "source_sha256": {Path(p).name: pilot.fingerprint(Path(p))[1] for p in
                              (__file__, pilot.__file__, Path(__file__).with_name("evaluate_idle_timeouts.py"))},
        })
        print("INSTANCE EXTRACTION: originals unchanged; provisional labels; no training.", flush=True)
        results = []
        for i, name in enumerate(names, 1):
            if pilot.fingerprint(manifest_path)[1] != manifest_hash:
                raise ValueError("Inventory changed during extraction")
            print(f"\n[{i}/{len(names)}] {name}", flush=True)
            capture, path, before = pilot.select_capture(manifest_path, name)
            child = directory / f"capture_{i:03d}"
            child.mkdir()
            command = [args.tshark, "-n", "-r", str(path), "-T", "fields", "-E", "occurrence=a", "-E", "aggregator=,"]
            for name_field in FIELDS:
                command.extend(["-e", name_field])
            pilot.write_json(child / "source.json", {"capture": capture, "tshark_command": command})
            result = process_capture(command, child, capture, args)
            after = path.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError("Capture changed during extraction")
            result["evidence_directory"] = child.name
            results.append(result)
            print(f"Instances: {result['instances']}; N4: {result['windows']['4']['records']}; N8: {result['windows']['8']['records']}")
            print(f"End reasons: {result['end_reasons']}")
        if pilot.fingerprint(manifest_path)[1] != manifest_hash:
            raise ValueError("Inventory changed during extraction")
        pilot.write_json(directory / "summary.json", {
            "status": "instance_extraction_complete", "training_ready": False,
            "captures_evaluated": len(results), "captures": results,
            "warning": "Feature records are paired B/C but labels and session independence are not verified. No train/test split or trained model.",
        })
        print(f"\nEvidence saved to: {directory}")
        print("INSTANCE EXTRACTION COMPLETE — run validate_instance_output.py next; NOT TRAINING-READY.")
        return 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        if directory is not None:
            pilot.write_json(directory / "failure.json", {"status": "failed", "training_ready": False, "error": str(error)})
        print(f"ERROR: {error}", file=sys.stderr)
        if directory is not None:
            print(f"Incomplete output; do not use: {directory}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
