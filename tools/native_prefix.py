"""Read-only preparation of one isolated, frozen held-out eight-packet prefix.

Selection uses protocol, duration and stable record ID, never class labels or
predictions. This is not whole-capture replay or a six-class accuracy evaluation.
Original packet bodies, timestamps, extraction records and split assignments are
never changed. The native runner schedules capture-relative time but does not
inject capture timestamps into P4.
"""

from dataclasses import asdict
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import struct

import extract_feature_pilot as pilot
import extract_flow_instances as instances
from pcap_replay_io import iter_capture


PREPARED_RUN = "20260929T124705Z_4c1cb93953"
DEFAULT_CAPTURE = "vpn_hangouts_audio2.pcap"
B_FEATURES, C_FEATURES = pilot.B_FEATURES, pilot.C_FEATURES


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path):
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream)


def read_jsonl(path):
    with Path(path).open(encoding="utf-8") as stream:
        for line in stream:
            yield json.loads(line)


def _verify(path, expected, hashes):
    path = Path(path).resolve()
    actual = sha256_file(path)
    if expected is not None and actual != expected:
        raise ValueError(f"Frozen input checksum mismatch: {path}")
    hashes[str(path)] = actual
    return actual


def decode_raw_packet(raw_ip, frame, timestamp_ns):
    """Decode outer IPv4/TCP/UDP, returning the existing Packet/Tcp types.

    This is a structural decoder, not a payload dissector. It rejects incomplete
    datagrams, fragments, DNS, ambiguous endpoints and malformed transport
    headers. Captured checksums are preserved and not rewritten or validated.
    """
    if not isinstance(raw_ip, bytes) or len(raw_ip) < 20:
        raise ValueError("Incomplete raw IPv4 header")
    if type(frame) is not int or frame < 1 or type(timestamp_ns) is not int or timestamp_ns < 0:
        raise ValueError("Invalid frame number or timestamp")
    version, ihl = raw_ip[0] >> 4, (raw_ip[0] & 15) * 4
    total = struct.unpack_from("!H", raw_ip, 2)[0]
    fragment = struct.unpack_from("!H", raw_ip, 6)[0]
    proto = raw_ip[9]
    if version != 4 or not 20 <= ihl <= 60 or ihl > len(raw_ip):
        raise ValueError("Invalid IPv4 version/header length")
    if fragment & 0x3FFF:
        raise ValueError("IPv4 fragment is ineligible")
    if proto not in (6, 17):
        raise ValueError("Outer protocol is not TCP or UDP")
    minimum = 20 if proto == 6 else 8
    if not ihl + minimum <= total <= len(raw_ip):
        raise ValueError("Truncated IPv4 packet or invalid total length")
    src, dst = (str(ipaddress.IPv4Address(raw_ip[start:start + 4])) for start in (12, 16))
    sport, dport = struct.unpack_from("!HH", raw_ip, ihl)
    if 53 in (sport, dport):
        raise ValueError("Port 53 baseline exclusion")
    if (src, sport) == (dst, dport):
        raise ValueError("Identical endpoints cannot define direction")
    tcp = None
    if proto == 6:
        tcp_len = (raw_ip[ihl + 12] >> 4) * 4
        if not 20 <= tcp_len <= total - ihl:
            raise ValueError("Invalid TCP data offset")
        seq, ack_number = struct.unpack_from("!II", raw_ip, ihl + 4)
        flags = raw_ip[ihl + 13]
        tcp = instances.Tcp(bool(flags & 2), bool(flags & 16), bool(flags & 1),
                            bool(flags & 4), seq, ack_number, total - ihl - tcp_len)
    else:
        udp_len = struct.unpack_from("!H", raw_ip, ihl + 4)[0]
        if not 8 <= udp_len <= total - ihl:
            raise ValueError("Invalid UDP length")
    return pilot.Packet(frame, timestamp_ns, src, dst, sport, dport, proto, total), tcp


def feature_statistics(packets, effective_us=None):
    """Independent arithmetic oracle for exactly eight eligible packet objects."""
    if len(packets) != 8:
        raise ValueError("Native pilot needs exactly eight packets")
    key = pilot.make_key(packets[0])
    if any(pilot.make_key(packet) != key for packet in packets):
        raise ValueError("Prefix mixes bidirectional conversation keys")
    times = ([packet.timestamp_ns // 1000 for packet in packets]
             if effective_us is None else list(effective_us))
    if len(times) != 8 or any(type(value) is not int or value < 0 for value in times):
        raise ValueError("Need eight nonnegative integer microsecond timestamps")
    gaps = [right - left for left, right in zip(times, times[1:])]
    if min(gaps) < 0:
        raise ValueError("Timestamp regression in isolated prefix")
    sizes = [packet.size for packet in packets]
    forward = packets[0].src, packets[0].sport
    reverse = [(packet.src, packet.sport) != forward for packet in packets]
    b = dict(zip(B_FEATURES, (min(sizes), max(sizes), sum(sizes),
                             min(gaps), max(gaps), sum(gaps))))
    c = dict(b, reverse_packet_count=sum(reverse),
             direction_change_count=sum(a != b for a, b in zip(reverse, reverse[1:])))
    return b, c


def select_record(table_rows, extraction_rows, capture_id, max_duration_seconds=2.0):
    """Choose first-instance, unadjusted, bidirectional N8; prefer UDP then ID."""
    if not math.isfinite(max_duration_seconds) or not 0 < max_duration_seconds < 60:
        raise ValueError("Pilot duration must be positive and less than the 60-second idle timeout")
    heldout = {row["record_id"]: row for row in table_rows
               if row["capture_id"] == capture_id and row["partition"] == "test" and row["n"] == 8}
    candidates = []
    for row in extraction_rows:
        if row["record_id"] not in heldout:
            continue
        debug = row["debug_metadata_not_model_inputs"]
        trace = debug["trace"]
        if row["n"] != 8 or row["instance_index"] != 1 or debug["start_reason"] != "first_observed":
            continue
        if len(trace) != 8 or debug["prefix_timestamp_adjustments"] != 0:
            continue
        raw = [entry["raw_timestamp_ns"] for entry in trace]
        effective = [entry["effective_timestamp_us"] for entry in trace]
        if any(entry["timestamp_adjustment_ns"] != 0 for entry in trace):
            continue
        if effective != [stamp // 1000 for stamp in raw] or any(b < a for a, b in zip(raw, raw[1:])):
            continue
        if effective[-1] - effective[0] > int(max_duration_seconds * 1_000_000):
            continue
        if trace[0]["direction"] != "F" or not any(entry["direction"] == "R" for entry in trace):
            continue
        if trace[0]["frame"] != debug["first_frame"] or trace[-1]["frame"] != debug["decision_frame"]:
            raise ValueError("Frozen trace disagrees with first/decision frame metadata")
        if any(b["frame"] <= a["frame"] for a, b in zip(trace, trace[1:])):
            raise ValueError("Frozen prefix frame order is invalid")
        table = heldout[row["record_id"]]
        for name in ("instance_id", "parent_candidate_conversation_id", "capture_sha256", "features_B", "features_C"):
            if table[name] != row[name]:
                raise ValueError(f"Prepared/extraction record mismatch: {name}")
        candidates.append((debug["key"][0] != 17, row["record_id"], table, row))
    if not candidates:
        raise ValueError("No first-instance bidirectional held-out N8 prefix within the pilot duration limit")
    chosen = min(candidates, key=lambda item: item[:2])
    return chosen[2], chosen[3], len(candidates)


def validate_original_packets(extraction_record, raw_records):
    """Confirm eight exact raw frames reproduce the frozen features and trace."""
    debug = extraction_record["debug_metadata_not_model_inputs"]
    trace = debug["trace"]
    if len(raw_records) != 8:
        raise ValueError("Original capture did not supply all eight selected frames")
    packets, bodies = [], []
    forward = tuple(debug["forward_endpoint"])
    for entry, raw in zip(trace, raw_records):
        if raw.number != entry["frame"] or raw.timestamp_ns != entry["raw_timestamp_ns"]:
            raise ValueError("Original frame number/timestamp disagrees with frozen trace")
        if raw.linktype not in (101, 228) or raw.captured_len != raw.wire_len:
            raise ValueError("Selected frame is not complete raw IPv4")
        packet, tcp = decode_raw_packet(raw.data, raw.number, raw.timestamp_ns)
        direction = "F" if (packet.src, packet.sport) == forward else "R"
        if packet.size != entry["size_bytes"] or direction != entry["direction"]:
            raise ValueError("Original packet size/direction disagrees with frozen trace")
        if (None if tcp is None else asdict(tcp)) != entry["tcp"]:
            raise ValueError("Original TCP boundary fields disagree with frozen trace")
        packets.append(packet)
        bodies.append({"original_frame": raw.number, "timestamp_ns": raw.timestamp_ns,
                       "raw_ip_hex": raw.data.hex(), "sha256": hashlib.sha256(raw.data).hexdigest()})
    b, c = feature_statistics(packets)
    if b != extraction_record["features_B"] or c != extraction_record["features_C"]:
        raise ValueError("Independent original-packet features disagree with frozen extraction")
    times = [packet.timestamp_ns // 1000 for packet in packets]
    for position, entry in enumerate(trace):
        gap = None if position == 0 else times[position] - times[position - 1]
        if entry["effective_timestamp_us"] != times[position] or entry["iat_us"] != gap:
            raise ValueError("Frozen per-packet IAT disagrees with independent timestamps")
    if json.loads(json.dumps(pilot.make_key(packets[0]))) != debug["key"]:
        raise ValueError("Original packet key disagrees with frozen extraction")
    if debug["observation_delay_us"] != times[-1] - times[0]:
        raise ValueError("Frozen observation delay disagrees with independent timestamps")
    return bodies, b, c, [stamp - times[0] for stamp in times]


def prepare_prefix(repo, capture_name=DEFAULT_CAPTURE, max_duration_seconds=2.0):
    """Return a JSON-serialisable pilot bundle; read files but write nothing."""
    repo = Path(repo).resolve()
    prepared = repo / "results" / "baseline_preparation" / PREPARED_RUN
    manifest_path = prepared / "manifest.json"
    manifest = read_json(manifest_path)
    if manifest["status"] != "prepared":
        raise ValueError("Frozen baseline preparation is incomplete")
    hashes = {}
    _verify(manifest_path, None, hashes)
    table_path = prepared / "table_n8.jsonl"
    _verify(table_path, manifest["payload_sha256"]["table_n8.jsonl"], hashes)
    extraction_root = Path(manifest["extraction_run"]).resolve()
    for filename in ("policy.json", "summary.json"):
        _verify(extraction_root / filename, manifest["extraction_sha256"][filename], hashes)
    policy = read_json(extraction_root / "policy.json")
    if policy["idle_seconds"] != 60 or policy["boundary_policy"] != "idle-tcp":
        raise ValueError("Native pilot requires the frozen 60-second idle/TCP policy")
    if tuple(policy["features_B"]) != B_FEATURES or tuple(policy["features_C"]) != C_FEATURES:
        raise ValueError("Frozen feature order mismatch")
    inventory_path = repo / "metadata" / "capture_inventory.json"
    _verify(inventory_path, policy["manifest_sha256"], hashes)
    inventory = read_json(inventory_path)
    capture_matches = [item for item in inventory["captures"] if item["filename"] == capture_name]
    if len(capture_matches) != 1 or not capture_matches[0]["include_in_baseline"]:
        raise ValueError("Capture name is absent, ambiguous or excluded by the frozen inventory")
    capture = capture_matches[0]
    summary = read_json(extraction_root / "summary.json")
    matched = [item for item in summary["captures"] if item["capture_id"] == capture["capture_id"]]
    if len(matched) != 1:
        raise ValueError("Capture missing or duplicated in frozen extraction summary")
    relative = Path(matched[0]["evidence_directory"]) / "features_n8.jsonl"
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Unsafe extraction evidence directory")
    extraction_path = extraction_root / relative
    _verify(extraction_path, manifest["extraction_sha256"][relative.as_posix()], hashes)
    record, extracted, candidate_count = select_record(read_jsonl(table_path), read_jsonl(extraction_path),
                                                      capture["capture_id"], max_duration_seconds)
    if extracted["capture_sha256"] != capture["sha256"]:
        raise ValueError("Frozen extraction capture checksum differs from inventory")
    capture_path = Path(capture["path"]).resolve()
    if capture_path.stat().st_size != capture["size_bytes"]:
        raise ValueError("Original capture size changed")
    _verify(capture_path, capture["sha256"], hashes)
    selected_numbers = {item["frame"] for item in extracted["debug_metadata_not_model_inputs"]["trace"]}
    raw_records = []
    for raw in iter_capture(capture_path):
        if raw.number in selected_numbers:
            raw_records.append(raw)
        if raw.number >= max(selected_numbers):
            break
    bodies, b, c, relative_us = validate_original_packets(extracted, raw_records)
    return {"schema_version": 1, "pilot_only": True, "accuracy_scored": False,
            "whole_capture_replay": False, "native_clock_required": True,
            "record": record, "extraction_record": extracted, "packets": bodies,
            "input_sha256": hashes, "capture": capture, "features_B": b, "features_C": c,
            "relative_us": relative_us,
            "selection": {"policy": "held-out N8; first instance; first_observed; zero timestamp adjustments; bidirectional; duration cap; prefer UDP then lexicographic record ID",
                          "max_duration_seconds": max_duration_seconds, "eligible_candidates": candidate_count,
                          "uses_labels_or_predictions": False},
            "limitations": ["Only one isolated first-observed prefix; not a complete verified session.",
                            "All background traffic and later packets are omitted.",
                            "Pilot selection is structurally restricted and not representative accuracy sampling.",
                            "Capture-relative gaps schedule sends, but P4 must use actual ingress time."]}
