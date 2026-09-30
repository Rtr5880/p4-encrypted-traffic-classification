#!/usr/bin/env python3
"""Compile and exercise the actual BMv2 feature extractor without sudo.

Packet-file correctness tests, NOT live-interface performance measurements.
Uses the existing Python instance extractor as the independent state oracle.
Only writes new evidence; never modifies captures or a running user switch.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import io
import ipaddress
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
import uuid

import extract_feature_pilot as pilot
import extract_flow_instances as instances

FIELDS = [('magic', 4), ('version', 1), ('status', 1), ('reason', 1), ('count', 1),
          ('packet_id', 4), ('observed_us', 6), ('effective_us', 6), ('slot', 4), ('instance', 4),
          ('ip_proto', 1), ('src_addr', 4), ('dst_addr', 4), ('src_port', 2), ('dst_port', 2),
          ('size_min', 2), ('size_max', 2), ('size_sum', 4), ('iat_min', 4), ('iat_max', 4),
          ('iat_sum', 4), ('reverse_count', 1), ('direction_changes', 1),
          ('direction', 1), ('active', 1), ('flags', 1), ('reserved', 1)]
FEATURE_NAMES = {'reverse_packet_count': 'reverse_count', 'direction_change_count': 'direction_changes'}


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')


def write_pcap(path, frames):
    # Classic little-endian PCAP, full Ethernet frames. File mode ignores time.
    with Path(path).open('xb') as stream:
        stream.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 131072, 1))
        for i, frame in enumerate(frames):
            stream.write(struct.pack('<IIII', 1, i, len(frame), len(frame)))
            stream.write(frame)


def read_pcap(path, partial=False):
    if not Path(path).exists():
        return []
    raw = Path(path).read_bytes()
    if len(raw) < 24:
        require(partial, 'Missing PCAP global header')
        return []
    endian = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>'}.get(raw[:4])
    require(endian, 'Unsupported output PCAP magic')
    # BMv2 file writer declares DLT_NULL even for Ethernet bytes: decode bytes,
    # not the global linktype. Every captured record must still be complete.
    frames, pos = [], 24
    while pos < len(raw):
        if len(raw) - pos < 16:
            require(partial, 'Truncated PCAP record header')
            break
        _, _, caplen, wirelen = struct.unpack_from(endian + 'IIII', raw, pos)
        require(caplen == wirelen, 'Truncated capture record')
        if len(raw) - pos - 16 < caplen:
            require(partial, 'Truncated PCAP packet')
            break
        frames.append(raw[pos + 16:pos + 16 + caplen])
        pos += 16 + caplen
    return frames


def checksum(raw):
    if len(raw) % 2:
        raw += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(raw) // 2), raw))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def event(number, flow=1, stamp=1000000, reverse=False, proto=17, size=80,
          flags='A', seq=100, ack=0, invalid=None, ip_options=False, tcp_options=False):
    src, dst = f'10.1.{flow // 250}.{flow % 250 + 1}', '192.0.2.200'
    sport, dport = 10000 + flow, 443
    if reverse:
        src, dst, sport, dport = dst, src, dport, sport
    if invalid == 'dns':
        dport = 53
    if invalid == 'same_endpoint':
        dst, dport = src, sport
    return {'number': number, 'flow': flow, 'stamp': stamp, 'src': src, 'dst': dst,
            'sport': sport, 'dport': dport, 'proto': proto, 'size': size,
            'flags': flags, 'seq': seq, 'ack': ack, 'invalid': invalid,
            'ip_options': ip_options, 'tcp_options': tcp_options}


def wire_packet(e, controlled):
    ihl = 24 if e['ip_options'] else 20
    thl = 24 if e['tcp_options'] else 20
    payload_len = e['size'] - ihl - (thl if e['proto'] == 6 else 8)
    require(payload_len >= 0, 'Fixture size too small')
    flags = sum(bit for name, bit in [('F', 1), ('S', 2), ('R', 4), ('A', 16)] if name in e['flags'])
    if e['proto'] == 6:
        transport = struct.pack('!HHIIBBHHH', e['sport'], e['dport'], e['seq'], e['ack'],
                                (thl // 4) << 4, flags, 4096, 0, 0)
        if e['tcp_options']:
            transport += b'\x01' * 4
    else:
        transport = struct.pack('!HHHH', e['sport'], e['dport'], payload_len + 8, 0)
    transport += b'X' * payload_len
    src, dst = ipaddress.IPv4Address(e['src']).packed, ipaddress.IPv4Address(e['dst']).packed
    if e['proto'] == 6:
        check = checksum(src + dst + struct.pack('!BBH', 0, 6, len(transport)) + transport)
        transport = transport[:16] + struct.pack('!H', check) + transport[18:]
    bad = e['invalid']
    version_ihl = (4 << 4) | (ihl // 4)
    if bad == 'version':
        version_ihl = (6 << 4) | (ihl // 4)
    if bad == 'ihl':
        version_ihl = 0x44
    ip_length = 10 if bad == 'length' else e['size']
    fragment = 0x2000 if bad == 'fragment' else 0
    proto = 1 if bad == 'protocol' else e['proto']
    ip = struct.pack('!BBHHHBBH4s4s', version_ihl, 0, ip_length, e['number'] & 65535,
                     fragment, 64, proto, 0, src, dst)
    if e['ip_options']:
        ip += b'\x01' * 4
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    body = ip + transport
    if bad == 'truncated':
        body = body[:-5]
    if bad == 'truncated_tcp':
        body = body[:ihl + 10]
    eth = bytes.fromhex('020000000002020000000001') + struct.pack('!H', 0x88b5 if controlled else 0x0800)
    if controlled:
        prefix = struct.pack('!II', 0x45544354 if bad != 'magic' else 0, e['number']) + e['stamp'].to_bytes(6, 'big')
        return eth + prefix + body
    return eth + body


def decode_report(frame):
    require(len(frame) >= 14 + 71 and frame[12:14] == b'\x88\xb6', 'Missing feature debug header')
    row, pos = {}, 14
    for name, length in FIELDS:
        row[name] = int.from_bytes(frame[pos:pos + length], 'big')
        pos += length
    require(row['magic'] == 0x45544352 and row['version'] == 1, 'Unknown feature report version')
    return row


class Oracle(instances.Extractor):
    def close(self, parent, reason):
        self.last_closed = parent.active
        super().close(parent, reason)


def compare(events, reports, controlled, allow_collisions=False):
    require(len(reports) == len(events), 'Missing/extra output records')
    ids = [r['packet_id'] for r in reports]
    require(len(set(ids)) == len(ids), 'Duplicate packet report')
    require(set(ids) == {e['number'] for e in events}, 'Missing/unknown packet IDs')
    require(ids == [e['number'] for e in events], 'Diagnostic packet order changed')
    if not controlled:
        times = [r['observed_us'] for r in reports]
        require(min(times) > 0 and max(times) > min(times) and times == sorted(times),
                'Implausible native ingress clock: zero, constant or backwards')
    by_id = {r['packet_id']: r for r in reports}
    sink = io.StringIO()
    oracle = Oracle({'capture_id': 'synthetic', 'sha256': '0' * 64,
                     'initial_class': 'VOIP', 'filename': 'synthetic'},
                    {4: io.StringIO(), 8: io.StringIO()}, sink)
    counters, observed_slots, decisions = Counter(), {}, []
    for e in events:
        r = by_id[e['number']]
        if e['invalid']:
            require(r['status'] == 0, f"Packet {e['number']}: unsupported fixture admitted")
            counters['rejected'] += 1
            continue
        require(r['ip_proto'] == e['proto'] and r['src_addr'] == int(ipaddress.IPv4Address(e['src'])) and
                r['dst_addr'] == int(ipaddress.IPv4Address(e['dst'])) and
                (r['src_port'], r['dst_port']) == (e['sport'], e['dport']), 'Report tuple differs from input')
        stamp = e['stamp'] if controlled else r['observed_us']
        if controlled:
            require(r['observed_us'] == stamp, 'Controlled timestamp not used')
        packet = pilot.Packet(e['number'], stamp * 1000, e['src'], e['dst'],
                              e['sport'], e['dport'], e['proto'], e['size'])
        key = pilot.make_key(packet)
        # A collision must be genuine and must never evict/mutate the owner.
        owner = observed_slots.get(r['slot'])
        if r['status'] == 3:
            require(allow_collisions and owner is not None and owner != key, 'Unexpected/spurious collision')
            counters['collisions'] += 1
            continue
        require(owner is None or owner == key, 'Hash alias admitted as same flow')
        observed_slots[r['slot']] = key
        tcp = None
        if e['proto'] == 6:
            tcp = instances.Tcp('S' in e['flags'], 'A' in e['flags'], 'F' in e['flags'],
                                'R' in e['flags'], e['seq'], e['ack'],
                                e['size'] - (24 if e['ip_options'] else 20) - (24 if e['tcp_options'] else 20))
        oracle.last_closed = None
        oracle.add(packet, tcp)
        parent = oracle.parents[key]
        instance = parent.active if parent.active is not None else oracle.last_closed
        require(instance is not None, 'Oracle instance absent')
        prefix = instance.prefix
        expected_status = 2 if prefix.count == 8 else 1
        expected_boundary = 0
        if prefix.count == 1:
            expected_boundary = {'first_observed': 1, 'idle_timeout': 2, 'idle_after_tcp_rst': 2,
                                 'fresh_tcp_syn': 3, 'after_tcp_rst': 4}[instance.start_reason]
        expected = {'status': expected_status, 'reason': 0, 'count': min(prefix.count, 8),
                    'instance': instance.index, 'effective_us': parent.effective_ns // 1000,
                    'active': int(parent.active is not None), 'flags': expected_boundary,
                    'direction': int((packet.src, packet.sport) != prefix.forward)}
        expected.update({FEATURE_NAMES.get(k, k): v for k, v in prefix.features.items()})
        for field, value in expected.items():
            require(r[field] == value, f"Packet {e['number']} flow {e['flow']}: {field} P4={r[field]} Python={value}")
        counters['eligible'] += 1
        if expected_status == 2:
            counters['decisions'] += 1
            decisions.append({'packet_id': e['number'], 'flow': e['flow'], 'instance': instance.index,
                              'features_C': dict(prefix.features)})
    audit = oracle.finish()
    require(audit['windows']['8']['records'] == counters['decisions'], 'Decision completeness mismatch')
    if allow_collisions:
        require(counters['collisions'] > 0 and counters['decisions'] > 0, 'Collision fixture did not exercise both paths')
    return {'packets': len(events), **dict(counters), 'short_instances': audit['windows']['8']['short_instances'],
            'decisions_detail': decisions, 'feature_mismatches': 0, 'instance_mismatches': 0}


def fixtures():
    events = []
    def add(flow, stamp, **kwargs):
        events.append(event(len(events) + 1, flow=flow, stamp=stamp, **kwargs))
    # Bidirectional UDP, backwards/equal timestamps, state refresh after packet8,
    # then a true idle reset. Interleaving is exercised below as well.
    for i, stamp in enumerate([1000, 2000, 1999, 2000, 3000, 4000, 5000, 6000, 50000000, 100000000]):
        add(1, stamp, reverse=i % 3 == 1, size=60 + i * 3)
    for i in range(8):
        add(1, 160000000 + i * 10, reverse=i % 2 == 0, size=93)
    # Seven packets: no decision. Cross-flow isolation including interleaving.
    for i in range(8):
        if i < 7:
            add(2, 10000 + i * 2, reverse=i % 2 == 1)
        add(3, 10000 + i * 3, reverse=i % 2 == 0, ip_options=True)
    # Largest in-instance gaps and exact idle boundary.
    for i in range(9):
        add(4, 1 + i * 59999999, size=65535)
    for i in range(8):
        add(4, 1 + 8 * 59999999 + 60000000 + i, size=120)
    # Retransmitted SYN + SYNACK inferred peer, ordinary traffic, RST at packet8;
    # backwards post-RST timestamp must retain the parent's monotonic clock.
    for i in range(8):
        add(5, 100000 + i * 10, proto=6, flags='S' if i < 2 else ('SA' if i == 2 else ('RA' if i == 7 else 'A')),
            reverse=i == 2 or i % 2 == 1 and i > 2, seq=500 if i == 2 else 100, ack=101 if i == 2 else 0,
            tcp_options=True)
    for i in range(8):
        add(5, 100050 + i * 10, proto=6, reverse=i % 2 == 0, flags='A')
    # Fresh SYN splits an otherwise reused tuple; duplicate opening stays.
    for i in range(8):
        add(6, 200000 + i, proto=6, flags='A')
    for i in range(8):
        add(6, 200100 + i, proto=6, flags='S' if i < 2 else 'A', seq=900)
    # Both FIN directions, final ACK retained, same-signature bare SYN new.
    for i, flags in enumerate(['S', 'SA', 'A', 'FA', 'FA', 'A', 'A', 'A']):
        add(7, 300000 + i, proto=6, flags=flags, reverse=i in (1, 4), seq=500 if i == 1 else 100, ack=101)
    for i in range(8):
        add(7, 300100 + i, proto=6, flags='S' if i == 0 else 'A', seq=100)
    # First observed SYNACK, later bare SYN must match inferred opening ISN.
    for i in range(8):
        add(8, 400000 + i, proto=6, flags='SA' if i == 0 else ('S' if i == 1 else 'A'),
            reverse=i == 1, seq=500 if i == 0 else 100, ack=101)
    # Possible simultaneous open with distinct ISNs, repeated opposite SYN.
    for i in range(8):
        add(9, 500000 + i, proto=6, flags='S' if i < 3 else 'A',
            reverse=i in (1, 2), seq=200 if i in (1, 2) else 100)
    # SYNACK ack=0 infers uint32 peer ISN 0xffffffff. Repeated bare SYN after
    # ordinary data still belongs to this instance until both FINs are seen.
    for i in range(9):
        add(10, 600000 + i, proto=6, flags='SA' if i == 0 else ('S' if i in (1, 6) else 'A'),
            reverse=i in (1, 6), seq=500 if i == 0 else 0xffffffff, ack=0)
    # Ineligible traffic must not keep a resident tuple alive before timeout.
    for i in range(7):
        add(11, 700000 + i, proto=6)
    add(11, 60700005, proto=6, invalid='fragment')
    for i in range(8):
        add(11, 60700006 + i, proto=6, flags='S' if i == 0 else 'A', seq=999)
    # Both FINs observed AFTER the prefix froze must still affect next SYN.
    for i in range(8):
        add(12, 800000 + i, proto=6, flags='S' if i == 0 else 'A')
    add(12, 800100, proto=6, flags='FA')
    add(12, 800101, proto=6, flags='FA', reverse=True)
    for i in range(8):
        add(12, 800102 + i, proto=6, flags='S' if i == 0 else 'A')
    # Numeric and textual endpoint sorting disagree, but first sender defines F.
    for i in range(8):
        add(13, 900000 + i, reverse=i % 2 == 1)
        events[-1]['src'], events[-1]['dst'] = (('10.0.0.10', '10.0.0.2') if i % 2 == 0 else ('10.0.0.2', '10.0.0.10'))
    # Invalid packets injected on an existing tuple must not advance features.
    for invalid in ['dns', 'same_endpoint', 'version', 'ihl', 'length', 'fragment',
                    'protocol', 'truncated', 'magic', 'truncated_tcp']:
        add(1, 160000100, proto=6 if invalid == 'truncated_tcp' else 17, invalid=invalid)
    add(1, 160000200)
    return events


def collision_fixture():
    # FLOW_SLOTS=1 forces all distinct tuples to collide with flow1.
    events = []
    for i in range(18):
        for flow in (1, 2):
            # Colliding flow carries extreme times and resets: if it ever writes
            # resident state, subsequent flow1 reports cannot match Python.
            events.append(event(len(events) + 1, flow=flow,
                                stamp=1000 + i if flow == 1 else 900000000 + i,
                                reverse=i % 2 == 1, proto=6,
                                flags='RA' if flow == 2 or i == 7 else 'A'))
    return events


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def run_switch(binary, json_file, directory, frames, expected, timeout=20, ingress_port=1):
    directory.mkdir()
    require(ingress_port in (1, 2), 'Only the two prototype ports are supported')
    write_pcap(directory / 'input_in.pcap', frames if ingress_port == 1 else [])
    write_pcap(directory / 'output_in.pcap', frames if ingress_port == 2 else [])
    output_path = directory / ('output_out.pcap' if ingress_port == 1 else 'input_out.pcap')
    command = [str(binary), '--use-files', '1', '-i', '1@input', '-i', '2@output',
               '--thrift-port', str(free_port()), '--device-id', str(100000 + uuid.uuid4().int % 100000000),
               # Relative to this process's unique cwd. Long absolute evidence
               # paths exceed Unix-domain socket sun_path (nanomsg asserts).
               '--notifications-addr', 'ipc://notifications.ipc',
               '--log-console', '-L', 'warn', str(json_file)]
    write_json(directory / 'command.json', command)
    with (directory / 'switch.log').open('x') as log:
        process = subprocess.Popen(command, cwd=directory, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + timeout
            complete_since = None
            while time.monotonic() < deadline:
                require(process.poll() is None, f'BMv2 exited early; inspect {directory / "switch.log"}')
                output = read_pcap(output_path, partial=True)
                require(len(output) <= expected, 'Extra BMv2 output packets')
                if len(output) == expected:
                    complete_since = complete_since or time.monotonic()
                    if time.monotonic() - complete_since >= 0.3:
                        break
                time.sleep(0.03)
            else:
                raise ValueError(f'BMv2 output timeout: received {len(output)}/{expected}; {directory}')
        finally:
            # Only this exact child process; no pkill, no user switch touched.
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
    output = read_pcap(output_path)
    require(len(output) == expected, 'Final packet accounting mismatch')
    return output


def compile_program(p4c, source, destination, controlled, debug, slots):
    # p4c is a driver: -o names a DIRECTORY, not a JSON file.
    build_directory = destination.parent / (destination.stem + '_build')
    command = [str(p4c), '--std', 'p4-16', '--target', 'bmv2', '--arch', 'v1model',
               '-I', str(p4c.parent / 'p4include'), f'-DTEST_TIMESTAMPS={int(controlled)}',
               f'-DDEBUG_REPORT={int(debug)}', f'-DFLOW_SLOTS={slots}',
               '-o', str(build_directory), str(source)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    write_json(destination.with_suffix('.compile.json'), {'command': command, 'returncode': result.returncode,
                                                         'stdout': result.stdout, 'stderr': result.stderr})
    require(result.returncode == 0, f'P4 compilation failed: {result.stderr}')
    generated = build_directory / (source.stem + '.json')
    require(generated.is_file(), 'Compiler did not create requested JSON')
    return generated


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    repo = Path(__file__).resolve().parent.parent
    parser.add_argument('--source', type=Path, default=repo / 'p4/flow_features.p4')
    parser.add_argument('--p4c', type=Path, default=Path.home() / 'p4/p4c-build/p4c')
    parser.add_argument('--switch', type=Path, default=Path.home() / 'p4/behavioral-model/targets/simple_switch/simple_switch')
    parser.add_argument('--output-root', type=Path, default=repo / 'results/p4_features')
    args = parser.parse_args(argv)
    run = None
    try:
        for path in (args.source, args.p4c, args.switch):
            require(path.is_file(), f'Required file missing: {path}')
        sources = [args.source, Path(__file__), Path(instances.__file__), Path(pilot.__file__)]
        hashes = {str(p.resolve()): digest(p) for p in sources}
        args.output_root.mkdir(parents=True, exist_ok=True)
        run = args.output_root / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '_' + uuid.uuid4().hex[:10])
        run.mkdir()
        write_json(run / 'provenance.json', {'source_sha256': hashes, 'p4c_sha256': digest(args.p4c),
                    'switch_sha256': digest(args.switch), 'test_mode': 'BMv2 packet-file, no real-time replay',
                    'not_tested': ['RF inference', 'real PCAP replay', 'live network interfaces',
                                   'throughput/latency', 'hardware feasibility', 'clock wrap']})
        results = {}
        for mode, controlled, debug, slots in [('controlled', True, True, 65536),
                                             ('native_clock', False, True, 65536),
                                             ('collision', True, True, 1),
                                             ('forwarding', False, False, 65536),
                                             ('forwarding_reverse', False, False, 65536)]:
            print(f'Compiling and running BMv2: {mode}...', flush=True)
            program = run / (mode + '.json')
            program = compile_program(args.p4c, args.source, program, controlled, debug, slots)
            if mode == 'controlled':
                events = fixtures()
            elif mode == 'collision':
                events = collision_fixture()
            else:
                # No claim of reproducing the original PCAP IAT. Oracle below
                # receives each actual switch ingress time from the debug report.
                events = [event(i + 1, flow=20 + i % 2, stamp=1000 + i,
                                reverse=i % 3 == 0, proto=6 if i % 2 else 17,
                                size=70 + i, ip_options=i % 4 == 0, tcp_options=i % 2 == 1)
                          for i in range(24)]
            write_json(run / (mode + '_inputs.json'), events)
            frames = [wire_packet(e, controlled) for e in events]
            output = run_switch(args.switch, program.resolve(), run / mode, frames, len(frames),
                                ingress_port=2 if mode == 'forwarding_reverse' else 1)
            if debug:
                reports = [decode_report(f) for f in output]
                write_json(run / (mode + '_reports.json'), reports)
                result = compare(events, reports, controlled, mode == 'collision')
            else:
                require(output == frames, 'Non-debug forwarding changed packet bytes/order')
                result = {'packets': len(frames), 'unchanged_forwarded_packets': len(frames)}
            results[mode] = result
            print(f"PASS {mode}: {result['packets']} packets; decisions={result.get('decisions', 'not instrumented')}", flush=True)
        require(hashes == {str(p.resolve()): digest(p) for p in sources}, 'Source changed during testing')
        output_hashes = {str(p.relative_to(run)): digest(p) for p in sorted(run.rglob('*')) if p.is_file()}
        write_json(run / 'summary.json', {'status': 'feature_tests_passed', 'p4_feature_tests': results,
                    'rf_inference_implemented': False, 'real_capture_replay_verified': False,
                    'live_interface_tested': False, 'performance_measured': False,
                    'output_sha256': output_hashes,
                    'scope': 'synthetic supported IPv4 TCP/UDP cases; exact feature/state/decision checks',
                    'collision_policy': 'full-key check, report collision, never silently overwrite; finite capacity, no eviction'})
        print(f'P4 FEATURE TESTS PASS — NOT RF inference or live-performance verification.\nEvidence saved to: {run}')
        return 0
    except (ValueError, OSError, KeyError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        if run is not None:
            write_json(run / 'failure.json', {'error': str(error), 'usable_as_success': False})
        print(f'ERROR: {error}\nEvidence: {run}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
