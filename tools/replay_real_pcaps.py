#!/usr/bin/env python3
"""Controlled real-PCAP RF-B/C correctness and coverage, without accuracy scoring.

Read raw bytes independently of TShark's reference fields. Preserve capture order,
including rejected and post-eight packets. Run each model in a fresh private BMv2
process. A bounded FIFO feed prevents replay bursts from overflowing its queues.
"""
import argparse
from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timezone
import errno
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import select
import shutil
import stat
import struct
import subprocess
import sys
import time
import uuid
import zlib

import extract_feature_pilot as pilot
import extract_flow_instances as instances
from evaluate_idle_timeouts import select_names
import integrate_rf as integration
import pcap_replay_io as capture_io
import prepare_rf_deployment as reference
import test_p4_features as feature_helpers

require = feature_helpers.require
write_json = feature_helpers.write_json
SLOTS = 65536
ETHERNET = bytes.fromhex('02000000000202000000000188b5')
RF_OFFSET = 14 + 71
BODY_OFFSET = RF_OFFSET + 52


def digest(path):
    return pilot.fingerprint(Path(path))[1]


def json_line(stream, value):
    stream.write(json.dumps(value, separators=(',', ':'), allow_nan=False) + '\n')


class Discard:
    def write(self, text):
        return len(text)


class ReplayOracle(instances.Extractor):
    """Reuse the frozen extractor, retaining a packet-eight RST's closed instance."""
    def close(self, parent, reason):
        self.last_closed = parent.active
        super().close(parent, reason)


def slot_for(packet, slots=SLOTS):
    # P4 orders addresses numerically. The offline ID uses its original string key.
    endpoints = sorted(((int(ipaddress.IPv4Address(packet.src)), packet.sport),
                        (int(ipaddress.IPv4Address(packet.dst)), packet.dport)))
    lo, hi = endpoints
    return zlib.crc32(struct.pack('!BIHIH', packet.protocol, *lo, *hi)) % slots


def wrap_packet(record, origin_us):
    require(record.linktype in (101, 228), f'Frame {record.number}: expected Raw IPv4 linktype')
    require(record.data and record.data[0] >> 4 == 4,
            f'Frame {record.number}: non-IPv4 Raw-IP packet; adapter does not reinterpret it')
    require(0 < record.number < 2**32, 'Packet ID exceeds test header width')
    stamp = record.timestamp_ns // 1000 - origin_us
    require(0 <= stamp < 2**48, 'Controlled timestamp outside 48-bit range')
    return ETHERNET + struct.pack('!II', 0x45544354, record.number) + stamp.to_bytes(6, 'big') + record.data


def scan_capture(path):
    count = byte_count = truncated = backward = 0
    minimum = maximum = previous = None
    for record in capture_io.iter_capture(path):
        require(record.linktype in (101, 228), 'Only Raw IP/IPv4 captures are supported')
        require(record.data and record.data[0] >> 4 == 4,
                f'Frame {record.number}: expected outer IPv4; refusing silent filtering')
        count += 1
        byte_count += record.captured_len
        truncated += record.captured_len < record.wire_len
        stamp = record.timestamp_ns
        backward += previous is not None and stamp < previous
        minimum = stamp if minimum is None else min(minimum, stamp)
        maximum = stamp if maximum is None else max(maximum, stamp)
        previous = stamp
    require(count > 0, 'Capture has no packets')
    origin = minimum // 1000
    require(maximum // 1000 - origin < 2**48, 'Capture duration exceeds controlled timestamp range')
    return {'frames': count, 'captured_bytes': byte_count, 'capture_truncated_frames': truncated,
            'capture_order_backward_steps': backward, 'origin_us': origin,
            'minimum_timestamp_ns': minimum, 'maximum_timestamp_ns': maximum}


def check_raw_against_tshark(record, values):
    """Compare separately decoded raw/field identities before using reference fields."""
    row = dict(zip(instances.FIELDS, values, strict=True))
    require(int(row['frame.number']) == record.number, 'Raw reader/TShark frame order mismatch')
    require(pilot.timestamp_ns(row['frame.time_epoch']) == record.timestamp_ns,
            f'Frame {record.number}: raw reader/TShark timestamp mismatch')
    require(int(row['frame.cap_len']) == record.captured_len and int(row['frame.len']) == record.wire_len,
            f'Frame {record.number}: raw reader/TShark capture length mismatch')


def expectation(oracle, packet, tcp, owners, origin_us, slots=SLOTS):
    """Compute state and collision decisions without consulting BMv2 output."""
    key = pilot.make_key(packet)
    slot = slot_for(packet, slots)
    owner = owners.setdefault(slot, key)
    collision = owner != key
    oracle.last_closed = None
    oracle.add(packet, tcp)  # Includes colliders so their missing instances are known.
    parent = oracle.parents[key]
    instance = parent.active or oracle.last_closed
    require(instance is not None, 'Missing reference instance')
    prefix = instance.prefix
    instance_id = f'{parent.identity}:{oracle.policy_id}:{instance.index}'
    fields = {'slot': slot, 'ip_proto': packet.protocol,
              'src_addr': int(ipaddress.IPv4Address(packet.src)),
              'dst_addr': int(ipaddress.IPv4Address(packet.dst)),
              'src_port': packet.sport, 'dst_port': packet.dport}
    if collision:
        fields.update(status=3, reason=0, count=0, instance=0, effective_us=0,
                      direction=0, active=0, flags=0)
        fields.update({feature_helpers.FEATURE_NAMES.get(k, k): 0 for k in instances.C_FEATURES})
    else:
        boundary = 0
        if prefix.count == 1:
            boundary = {'first_observed': 1, 'idle_timeout': 2, 'idle_after_tcp_rst': 2,
                        'fresh_tcp_syn': 3, 'after_tcp_rst': 4}[instance.start_reason]
        fields.update(status=2 if prefix.count == 8 else 1, reason=0,
                      count=min(prefix.count, 8), instance=instance.index,
                      effective_us=parent.effective_ns // 1000 - origin_us,
                      direction=int((packet.src, packet.sport) != prefix.forward),
                      active=int(parent.active is not None), flags=boundary)
        fields.update({feature_helpers.FEATURE_NAMES.get(k, k): v for k, v in prefix.features.items()})
    decision = None
    if prefix.count == 8:
        decision = {'packet_id': packet.frame, 'instance_id': instance_id,
                    'record_id': instance_id + ':n8', 'parent_candidate_conversation_id': parent.identity,
                    'slot': slot, 'collision_excluded': collision,
                    'features_B': {k: prefix.features[k] for k in instances.B_FEATURES},
                    'features_C': dict(prefix.features)}
    return fields, decision, key, instance_id, collision


def verify_saved_instances(saved_root, capture, decisions, audit):
    """Reconnect the replay to the existing validated extraction population."""
    summary = integration.read_json(saved_root / 'summary.json')
    policy = integration.read_json(saved_root / 'policy.json')
    require(summary['status'] == 'instance_extraction_complete' and not (saved_root / 'failure.json').exists(),
            'Original extraction has no successful completion')
    require(policy['idle_seconds'] == 60 and policy['boundary_policy'] == 'idle-tcp'
            and policy['features_C'] == list(instances.C_FEATURES), 'Frozen extraction policy mismatch')
    for filename, expected_hash in policy['source_sha256'].items():
        path = Path(instances.__file__).parent / filename
        require(path.parent == Path(instances.__file__).parent and digest(path) == expected_hash,
                f'Frozen extractor source changed: {filename}')
    matches = [r for r in summary['captures'] if r['capture_id'] == capture['capture_id']]
    require(len(matches) == 1 and matches[0]['capture_sha256'] == capture['sha256'],
            'Capture missing/changed in original extraction')
    saved = matches[0]
    child = (saved_root / saved['evidence_directory']).resolve()
    require(child.is_relative_to(saved_root), 'Invalid extraction evidence path')
    path = child / 'features_n8.jsonl'
    rows = integration.read_rows(path)
    actual = {r['record_id']: r for r in decisions}
    require(len(actual) == len(decisions) == len(rows) and len({r['record_id'] for r in rows}) == len(rows),
            'Duplicate/missing saved N8 records')
    for row in rows:
        other = actual.get(row['record_id'])
        require(other is not None and row['features_B'] == other['features_B']
                and row['features_C'] == other['features_C']
                and row['debug_metadata_not_model_inputs']['decision_frame'] == other['packet_id'],
                f"Original N8 record differs: {row['record_id']}")
    for key in ('instances', 'eligible_packets', 'candidate_conversations', 'windows', 'start_reasons', 'end_reasons', 'timing'):
        require(audit[key] == saved[key], f'Original extraction audit changed: {key}')
    return {'verified_n8_records': len(rows), 'path': str(path), 'sha256': digest(path),
            'summary_sha256': digest(saved_root / 'summary.json'), 'policy_sha256': digest(saved_root / 'policy.json')}


def prepare_capture(args, capture, path, directory, exports):
    scan = scan_capture(path)
    write_json(directory / 'capture_scan.json', scan)
    command = [args.tshark, '-n', '-r', str(path), '-T', 'fields', '-E', 'occurrence=a', '-E', 'aggregator=,']
    for field in instances.FIELDS:
        command.extend(['-e', field])
    write_json(directory / 'source.json', {'capture': capture, 'tshark_command': command})
    decisions, owners, collided_parents, collided_instances = [], {}, set(), set()
    counts = Counter(dict.fromkeys(('packets', 'eligible_packets', 'rejected_packets',
                                    'admitted_packets', 'collision_packets'), 0))
    rejections = Counter()
    with ExitStack() as stack:
        expected_stream = stack.enter_context(gzip.open(directory / 'expected_packets.jsonl.gz', 'xt', encoding='utf-8', compresslevel=1))
        instance_stream = stack.enter_context(gzip.open(directory / 'oracle_instances.jsonl.gz', 'xt', encoding='utf-8', compresslevel=1))
        oracle = ReplayOracle(capture, {4: Discard(), 8: Discard()}, instance_stream,
                              max_conversations=args.max_conversations)
        writer = stack.enter_context(capture_io.ClassicPcapWriter(directory / 'adapted.pcap', nanosecond=False))
        stderr = stack.enter_context((directory / 'tshark.stderr.log').open('x'))
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr, text=True,
                                   encoding='utf-8', errors='strict')
        try:
            for record in capture_io.iter_capture(path):
                line = process.stdout.readline()
                require(line, f'TShark ended before frame {record.number}')
                values = line.rstrip('\r\n').split('\t')
                check_raw_against_tshark(record, values)
                packet, tcp, reason = instances.decode_fields(values)
                frame = wrap_packet(record, scan['origin_us'])
                writer.write((record.timestamp_ns // 1000) * 1000, frame)
                expected = {'packet_id': record.number, 'observed_us': record.timestamp_ns // 1000 - scan['origin_us']}
                row = {'fields': expected, 'raw_length': len(record.data),
                       'raw_sha256': hashlib.sha256(record.data).hexdigest()}
                counts['packets'] += 1
                if packet is None:
                    require(not reason.startswith('missing_or_invalid_header_field:'),
                            f'Frame {record.number}: reference field conversion error: {reason}')
                    expected['status'] = 0
                    row['reference_rejection'] = reason
                    counts['rejected_packets'] += 1
                    rejections[reason] += 1
                else:
                    fields, decision, key, instance_id, collision = expectation(
                        oracle, packet, tcp, owners, scan['origin_us'])
                    expected.update(fields)
                    counts['eligible_packets'] += 1
                    if collision:
                        counts['collision_packets'] += 1
                        collided_parents.add(key)
                        collided_instances.add(instance_id)
                    else:
                        counts['admitted_packets'] += 1
                    if decision is not None:
                        decisions.append(decision)
                json_line(expected_stream, row)
                if record.number % 100000 == 0:
                    print(f'  Adapted/reference-checked {record.number:,}/{scan["frames"]:,} packets', flush=True)
            require(not process.stdout.readline(), 'TShark returned extra frames')
            require(process.wait(timeout=30) == 0, 'TShark failed; inspect tshark.stderr.log')
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            process.stdout.close()
        audit = oracle.finish()
    require(counts['packets'] == scan['frames'] and counts['eligible_packets'] + counts['rejected_packets'] == counts['packets'],
            'Adapter packet accounting mismatch')
    saved = verify_saved_instances(args.instances_run, capture, decisions, audit)
    excluded = sum(r['collision_excluded'] for r in decisions)
    expected_count = len(decisions) - excluded
    require(len(decisions) == audit['windows']['8']['records'], 'Reference decision completeness mismatch')
    admitted = [r for r in decisions if not r['collision_excluded']]
    expected_rf = {}
    for model in ('B', 'C'):
        expected_rf[model] = {}
        if admitted:
            features = [[r['features_' + model][k] for k in exports[model]['feature_order']] for r in admitted]
            leaves, _, scores = reference.predict_export(exports[model], features)
            for i, row in enumerate(admitted):
                expected_rf[model][row['packet_id']] = {'leaves': leaves[i].tolist(), 'scores': scores[i].tolist(),
                                                       'prediction': int(scores[i].argmax())}
        with (directory / f'expected_rf_{model}.jsonl').open('x', encoding='utf-8') as out:
            for row in admitted:
                json_line(out, {**row, **expected_rf[model][row['packet_id']]})
    with (directory / 'expected_n8_instances.jsonl').open('x', encoding='utf-8') as out:
        for row in decisions:
            json_line(out, row)
    result = {**dict(counts), 'scan': scan, 'reference_audit': audit, 'saved_extraction': saved,
              'reference_rejections': dict(rejections), 'expected_n8_instances': len(decisions),
              'collision_excluded_parents': len(collided_parents),
              'collision_excluded_instances_all_lengths': len(collided_instances),
              'collision_excluded_n8_instances': excluded,
              'collision_excluded_short_instances': len(collided_instances) - excluded,
              'expected_classifications': expected_count,
              'classification_coverage': expected_count / len(decisions) if decisions else None}
    write_json(directory / 'preparation.json', result)
    return result, expected_rf, {r['packet_id']: r for r in admitted}


def verify_frame(frame, row, model, expected_rf):
    feature = feature_helpers.decode_report(frame)
    for name, expected in row['fields'].items():
        require(feature[name] == expected,
                f"Frame {row['fields']['packet_id']}: {name}: P4={feature[name]} Python={expected}")
    require(feature['reserved'] == 0, 'Unexpected feature report reserved value')
    require(len(frame) == BODY_OFFSET + row['raw_length'], 'Original IP packet length changed in replay')
    require(hashlib.sha256(frame[BODY_OFFSET:]).hexdigest() == row['raw_sha256'],
            'Original IP bytes changed in replay')
    rf = integration.decode_rf(frame, RF_OFFSET)
    integration.check_rf(rf, model, expected_rf)
    return feature, rf


def mismatch_details(frame, row, error):
    """Keep the original failure even when malformed bytes cannot be decoded."""
    details = {'frame': row['fields']['packet_id'], 'error': str(error), 'expected': row,
               'observed_packet_length': len(frame),
               'observed_report_prefix_hex': frame[:BODY_OFFSET].hex()}
    for name, decoder in (('observed_feature', feature_helpers.decode_report),
                          ('observed_rf', lambda data: integration.decode_rf(data, RF_OFFSET))):
        try:
            details[name] = decoder(frame)
        except (ValueError, struct.error) as decode_error:
            details[name + '_decode_error'] = str(decode_error)
    return details


def write_nonblocking(fd, data, process, timeout):
    view = memoryview(data)
    deadline = time.monotonic() + timeout
    while view:
        require(process.poll() is None, 'Private BMv2 process exited while sending')
        require(time.monotonic() < deadline, 'Timed out feeding private BMv2 FIFO')
        try:
            n = os.write(fd, view)
            require(n > 0, 'FIFO write made no progress')
            view = view[n:]
        except BlockingIOError:
            select.select([], [fd], [], 0.05)


def run_replay(args, program, capture_dir, model, prepared, expected_rf, decision_metadata):
    """One input FIFO; <=32 packets outstanding, preserving exact file order."""
    directory = capture_dir / ('RF_' + model)
    directory.mkdir()
    fifo = directory / 'input_in.pcap'
    os.mkfifo(fifo, 0o600)
    with capture_io.ClassicPcapWriter(directory / 'output_in.pcap', nanosecond=False):
        pass
    output = directory / 'output_out.pcap'
    command = [str(args.switch), '--use-files', '0', '-i', '1@input', '-i', '2@output',
               '--thrift-port', str(feature_helpers.free_port()),
               '--device-id', str(100000 + uuid.uuid4().int % 100000000),
               '--notifications-addr', 'ipc://notifications.ipc', '--log-console', '-L', 'warn', str(program)]
    write_json(directory / 'command.json', command)
    sent = received = 0
    decisions, class_counts, rejection_reasons = set(), Counter(), Counter()
    status_counts = Counter()
    fd = None
    with ExitStack() as stack:
        log = stack.enter_context((directory / 'switch.log').open('x'))
        evidence = stack.enter_context((directory / 'decisions.jsonl').open('x', encoding='utf-8'))
        packets = iter(capture_io.iter_capture(capture_dir / 'adapted.pcap'))
        expected_file = stack.enter_context(gzip.open(capture_dir / 'expected_packets.jsonl.gz', 'rt', encoding='utf-8'))
        process = subprocess.Popen(command, cwd=directory, stdout=log, stderr=subprocess.STDOUT)
        tail = stack.enter_context(capture_io.PcapTailReader(output))
        def compare_output(record):
            nonlocal received
            line = expected_file.readline()
            require(line, 'Unexpected additional BMv2 output frame')
            row = json.loads(line)
            number = row['fields']['packet_id']
            require(number == received + 1, 'Reference packet sequence broken')
            try:
                feature, rf = verify_frame(record.data, row, model, expected_rf.get(number))
            except ValueError as error:
                write_json(directory / 'mismatch.json', mismatch_details(record.data, row, error))
                raise
            received += 1
            status_counts[str(feature['status'])] += 1
            if feature['status'] == 0:
                rejection_reasons[str(feature['reason'])] += 1
            if rf['valid']:
                require(number not in decisions, 'Duplicate classification')
                decisions.add(number)
                class_counts[rf['prediction']] += 1
                json_line(evidence, {**decision_metadata[number], 'feature_report': feature, 'rf_report': rf})
        try:
            deadline = time.monotonic() + args.stall_seconds
            while fd is None:
                require(process.poll() is None, 'BMv2 startup failed; inspect switch.log')
                require(time.monotonic() < deadline, 'Timed out opening BMv2 input FIFO')
                try:
                    fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
                except OSError as error:
                    if error.errno != errno.ENXIO:
                        raise
                    time.sleep(0.01)
            write_nonblocking(fd, struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 131072, 1), process, args.stall_seconds)
            while sent < prepared['packets']:
                batch = bytearray()
                for _ in range(min(32, prepared['packets'] - sent)):
                    record = next(packets)
                    sec, sub = divmod(record.timestamp_ns // 1000, 1000000)
                    batch.extend(struct.pack('<IIII', sec, sub, len(record.data), len(record.data)))
                    batch.extend(record.data)
                    sent += 1
                write_nonblocking(fd, batch, process, args.stall_seconds)
                if sent == prepared['packets']:
                    os.close(fd)
                    fd = None
                deadline = time.monotonic() + args.stall_seconds
                while received < sent:
                    require(process.poll() is None, 'BMv2 stopped before completing replay')
                    before = received
                    for record in tail.poll():
                        compare_output(record)
                    if received != before:
                        deadline = time.monotonic() + args.stall_seconds
                    else:
                        require(time.monotonic() < deadline, f'BMv2 replay stalled at {received}/{sent}; no exclusions for missing packets')
                        time.sleep(0.001)
                require(received == sent, 'BMv2 produced more outputs than packets sent')
                if sent % 100000 == 0 or sent == prepared['packets']:
                    print(f'  RF-{model}: checked {received:,}/{prepared["packets"]:,} packet reports', flush=True)
            require(next(packets, None) is None and not expected_file.readline(), 'Unconsumed input/reference packets')
            time.sleep(0.1)
            for record in tail.poll():
                compare_output(record)
        finally:
            if fd is not None:
                os.close(fd)
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            # Only the named pipe created above, in this unique evidence directory.
            if fifo.exists() and stat.S_ISFIFO(fifo.stat().st_mode):
                fifo.unlink()
            packets.close()
        for record in tail.finish():
            compare_output(record)
    require(decisions == set(expected_rf) == set(decision_metadata), 'Missing/extra packet-eight decision IDs')
    require(len(decisions) == prepared['expected_n8_instances'] - prepared['collision_excluded_n8_instances'],
            'Instance-level collision accounting failed')
    require(status_counts['3'] == prepared.get('collision_packets', 0), 'Collision packet accounting failed')
    require(status_counts['0'] == prepared['rejected_packets'], 'Rejection accounting failed')
    result = {'model': model, 'packets_checked': received, 'classifications': len(decisions),
              'status_counts': dict(status_counts), 'p4_rejection_reasons': dict(rejection_reasons),
              'predicted_class_counts': {name: class_counts[i] for i, name in enumerate(reference.baseline.CLASSES)},
              'eligibility_mismatches': 0, 'instance_mismatches': 0, 'feature_mismatches': 0,
              'leaf_mismatches': 0, 'score_mismatches': 0, 'class_mismatches': 0,
              'raw_packet_byte_mismatches': 0, 'missing_or_extra_decisions': 0}
    write_json(directory / 'summary.json', result)
    print(f'  PASS RF-{model}: {received:,} packets; {len(decisions)} classifications; zero parity mismatches', flush=True)
    archive_created(output)
    return result


def archive_created(path):
    """Losslessly archive this run's temporary capture; verify before removing it."""
    target = path.with_name(path.name + '.gz')
    expected = digest(path)
    with path.open('rb') as source, gzip.open(target, 'xb', compresslevel=1) as output:
        shutil.copyfileobj(source, output, 1024 * 1024)
    result = hashlib.sha256()
    with gzip.open(target, 'rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            result.update(chunk)
    require(result.hexdigest() == expected, 'Compressed capture verification failed')
    path.unlink()  # Only caller-created adapted/output PCAP; verified gzip remains.


def source_paths(repo):
    names = ('replay_real_pcaps.py', 'pcap_replay_io.py', 'extract_feature_pilot.py',
             'extract_flow_instances.py', 'evaluate_idle_timeouts.py', 'integrate_rf.py',
             'prepare_rf_deployment.py', 'generate_rf_p4.py', 'rf_parity_probes.py',
             'test_p4_features.py', 'train_capture_baseline.py', 'tune_capture_baseline.py')
    return [repo / 'tools' / name for name in names] + [repo / 'p4' / name for name in
            ('rf_b.p4', 'rf_c.p4', 'rf-models.json', 'flow_features.p4')]


def main(argv=None):
    repo = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--capture', action='append', help='Inventoried filename; repeat for several captures')
    group.add_argument('--all-included', action='store_true', help='Run correctness/coverage for all included captures')
    parser.add_argument('--manifest', type=Path, default=repo / 'metadata/capture_inventory.json')
    parser.add_argument('--instances-run', type=Path, default=repo / 'results/flow_instances/20260929T111314Z_e8151a1c48')
    parser.add_argument('--deployment', type=Path, default=repo / 'results/rf_deployment/20260929T221518Z_a61fc37702')
    parser.add_argument('--output-root', type=Path, default=repo / 'results/real_pcap_replay')
    parser.add_argument('--p4c', type=Path, default=Path.home() / 'p4/p4c-build/p4c')
    parser.add_argument('--switch', type=Path, default=Path.home() / 'p4/behavioral-model/targets/simple_switch/simple_switch')
    parser.add_argument('--tshark', default='tshark')
    parser.add_argument('--stall-seconds', type=int, default=60)
    parser.add_argument('--max-conversations', type=int, default=50000)
    args = parser.parse_args(argv)
    run = None
    try:
        for name in ('manifest', 'instances_run', 'deployment', 'output_root', 'p4c', 'switch'):
            setattr(args, name, getattr(args, name).expanduser().resolve())
        require(args.stall_seconds >= 5 and args.max_conversations > 0, 'Invalid resource/time limits')
        manifest = integration.read_json(args.manifest)
        names = select_names(manifest, args.capture, args.all_included)
        hashes = {str(p): digest(p) for p in source_paths(repo)}
        manifest_hash = digest(args.manifest)
        exports, _, _ = integration.load_deployment(args.deployment)
        provenance = integration.read_json(repo / 'p4/rf-models.json')
        require(provenance['base_feature_source_sha256'] == digest(repo / 'p4/flow_features.p4'),
                'Shared feature checkpoint changed')
        for model in ('B', 'C'):
            require(provenance['models'][model]['source_sha256'] == digest(repo / 'p4' / f'rf_{model.lower()}.p4')
                    and provenance['models'][model]['forest_integer_sha256'] ==
                    digest(args.deployment / f'n8_RF_{model}/forest_integer.json'), 'P4/export provenance mismatch')
        args.output_root.mkdir(parents=True, exist_ok=True)
        run = args.output_root / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '_' + uuid.uuid4().hex[:10])
        run.mkdir()
        write_json(run / 'run_config.json', {
            'stage': 'controlled-real-pcap-parity-v1', 'captures': names, 'manifest_sha256': manifest_hash,
            'source_sha256': hashes, 'deployment': str(args.deployment), 'instances_run': str(args.instances_run),
            'p4c_sha256': digest(args.p4c), 'switch_sha256': digest(args.switch),
            'tshark_version': subprocess.run([args.tshark, '--version'], capture_output=True, text=True, check=True).stdout,
            'flow_slots': SLOTS, 'n': 8, 'idle_seconds': 60, 'boundary_policy': 'idle-tcp',
            'timing': 'floor(original nanoseconds / 1000) minus capture-wide minimum microseconds; original order; existing per-parent clamp',
            'transport': 'Single ingress FIFO; batches <=32; wait for every debug report; native time ignored',
            'fresh_switch_per_model_per_capture': True, 'whole_capture_order_preserved': True,
            'new_model_fits': 0, 'accuracy_scored': False, 'native_clock_replay': False,
            'performance_measured': False, 'test_timestamps': True, 'debug_report': True,
            'collision_policy': 'First eligible tuple retains slot for whole process; no reclamation',
            'evidence_storage': 'Lossless gzip after verification; unique run; no raw dataset edits'})
        programs = {}
        for model in ('B', 'C'):
            print(f'Compiling frozen RF-{model} controlled/debug build...', flush=True)
            programs[model] = integration.compile_program(args.p4c, repo / 'p4' / f'rf_{model.lower()}.p4',
                                                        run / f'RF_{model}.json', True, True, SLOTS)
        results = []
        for i, name in enumerate(names, 1):
            print(f'[{i}/{len(names)}] {name}: preparing full capture in original order', flush=True)
            require(digest(args.manifest) == manifest_hash, 'Inventory changed during replay')
            capture, path, before = pilot.select_capture(args.manifest, name)
            # WSL virtual free space alone overstates capacity on a nearly-full C:.
            needed = max(512 * 1024**2, capture['size_bytes'] * 6)
            roots = [args.output_root] + ([Path('/mnt/c')] if Path('/mnt/c').is_dir() else [])
            for root in roots:
                require(shutil.disk_usage(root).free > needed,
                        f'Insufficient working space on {root}; need >{needed / 1024**3:.2f} GiB for this capture')
            child = run / f'capture_{i:03d}'
            child.mkdir()
            prepared, expected_rf, decision_metadata = prepare_capture(args, capture, path, child, exports)
            models = {model: run_replay(args, programs[model], child, model, prepared,
                                       expected_rf[model], decision_metadata) for model in ('B', 'C')}
            require(models['B']['status_counts'] == models['C']['status_counts'], 'B/C state population differs')
            after, capture_hash = pilot.fingerprint(path)
            require(capture_hash == capture['sha256'] and (before.st_size, before.st_mtime_ns) ==
                    (after.st_size, after.st_mtime_ns), 'Original capture changed during replay')
            archive_created(child / 'adapted.pcap')
            result = {'capture': name, 'capture_id': capture['capture_id'], 'evidence_directory': child.name,
                      'preparation': prepared, 'models': models, 'status': 'controlled_parity_pass'}
            write_json(child / 'summary.json', result)
            results.append(result)
        require(hashes == {str(p): digest(p) for p in source_paths(repo)}, 'Source changed during replay')
        require(digest(args.manifest) == manifest_hash, 'Inventory changed during replay')
        outputs = {str(p.relative_to(run)): digest(p) for p in sorted(run.rglob('*')) if p.is_file()}
        write_json(run / 'summary.json', {'status': 'controlled_real_pcap_parity_pass', 'captures': results,
                   'captures_checked': len(results), 'source_sha256': hashes, 'output_sha256': outputs,
                   'accuracy_scored': False, 'native_clock_replay': False, 'performance_measured': False})
        print(f'CONTROLLED REAL-PCAP PARITY PASS — RF-B and RF-C.\nEvidence saved to: {run}', flush=True)
        print('Next user stage: review/repeat these correctness checks. Research accuracy has not been scored.')
        return 0
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, StopIteration, subprocess.SubprocessError, KeyboardInterrupt) as error:
        if run is not None:
            write_json(run / 'failure.json', {'error': str(error), 'usable_as_success': False, 'accuracy_scored': False})
        print(f'CONTROLLED REPLAY FAILED: {error}\nIncomplete evidence: {run}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
