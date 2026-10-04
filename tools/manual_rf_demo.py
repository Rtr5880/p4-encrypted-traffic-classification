#!/usr/bin/env python3
"""User-operated traffic sender for the live, two-port RF demonstration.

Builds one bidirectional UDP flow. Python sends and captures Ethernet frames;
the running P4 switch extracts features and makes its own classification.
Use a fresh source port for each invocation, or restart your demo switch.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import threading
import time
import uuid

HOSTS = ('p1_host1', 'p1_host2')
PEERS = {'p1_host1': 'p1_sw1', 'p1_sw1': 'p1_host1',
         'p1_host2': 'p1_sw2', 'p1_sw2': 'p1_host2'}


def packet_plan(count, source_port):
    if count not in (7, 8, 12) or type(source_port) is not int or not 1024 <= source_port <= 65535:
        raise ValueError('Use 7, 8 or 12 packets and a source port in 1024..65535')
    return [{'sequence': i, 'direction': 'F' if i % 2 else 'R',
             'sender': HOSTS[0] if i % 2 else HOSTS[1],
             'receiver': HOSTS[1] if i % 2 else HOSTS[0],
             'src': '10.254.0.1' if i % 2 else '10.254.0.2',
             'dst': '10.254.0.2' if i % 2 else '10.254.0.1',
             'sport': source_port if i % 2 else 443,
             'dport': 443 if i % 2 else source_port,
             'ip_size': 120 + ((i - 1) % 3) * 20} for i in range(1, count + 1)]


def validate_links(links):
    by_name = {link['ifname']: link for link in links}
    for name, peer in PEERS.items():
        if name not in by_name:
            raise ValueError(f'Missing demo interface: {name}; complete T1 setup first')
        link = by_name[name]
        if link.get('linkinfo', {}).get('info_kind') != 'veth' or link.get('link') != peer:
            raise ValueError(f'{name}: expected the veth peer {peer}')
        if 'UP' not in link.get('flags', []) or 'LOWER_UP' not in link.get('flags', []):
            raise ValueError(f'{name}: interface or its peer is down')
        if link.get('master'):
            raise ValueError(f'{name}: remove this demo from the bridge before using the isolated sender')
    return {name: by_name[name]['address'] for name in HOSTS}


def make_frame(spec, macs, token):
    from scapy.all import Ether, IP, UDP, Raw
    marker = token + struct.pack('!H', spec['sequence'])
    payload = marker + b'X' * (spec['ip_size'] - 20 - 8 - len(marker))
    packet = (Ether(src=macs[spec['sender']], dst=macs[spec['receiver']]) /
              IP(src=spec['src'], dst=spec['dst'], id=spec['sequence']) /
              UDP(sport=spec['sport'], dport=spec['dport']) / Raw(payload))
    # Serialize now so checksum/length values and expected bytes are definite.
    return bytes(packet)


class CaptureCheck:
    """One outbound observation plus one forwarded observation per sequence."""
    def __init__(self, plan, frames, token):
        self.plan = {p['sequence']: p for p in plan}
        self.frames = frames
        self.token = token
        self.observed = {}
        self.duplicates = Counter()
        self.errors = []
        self.completed = threading.Event()

    def observe(self, packet):
        raw = bytes(packet)
        # Our frames are Ethernet + fixed IPv4(20) + UDP(8), without IP options.
        if len(raw) < 42 + len(self.token) + 2 or raw[12:14] != b'\x08\x00':
            return
        if raw[14] != 0x45 or raw[23] != 17 or raw[42:42 + len(self.token)] != self.token:
            return
        seq = int.from_bytes(raw[42 + len(self.token):44 + len(self.token)], 'big')
        if seq not in self.plan:
            self.errors.append(f'Unexpected tagged sequence {seq}')
            return
        spec = self.plan[seq]
        iface = getattr(packet, 'sniffed_on', '')
        role = 'sent' if iface == spec['sender'] else ('received' if iface == spec['receiver'] else None)
        if role is None:
            self.errors.append(f'Sequence {seq}: unexpected capture interface {iface}')
            return
        if raw != self.frames[seq]:
            self.errors.append(f'Sequence {seq} on {iface}: packet bytes changed')
            return
        key = (seq, role)
        if key in self.observed:
            self.duplicates[role] += 1
        else:
            self.observed[key] = packet
        if len(self.observed) == 2 * len(self.plan):
            self.completed.set()

    def report(self):
        missing = [{'sequence': seq, 'role': role} for seq in self.plan for role in ('sent', 'received')
                   if (seq, role) not in self.observed]
        return {'sent_observed': sum(role == 'sent' for _, role in self.observed),
                'received_observed': sum(role == 'received' for _, role in self.observed),
                'expected_packets': len(self.plan), 'missing': missing,
                'duplicates': dict(self.duplicates), 'errors': self.errors,
                'forwarding_passed': not missing and not self.errors and not self.duplicates,
                'rf_counters_checked_by_script': False,
                'meaning': 'Matching frames captured at both virtual endpoints; inspect RF counters in T2'}


def save_evidence(root, plan, check, run_id):
    from scapy.all import wrpcap
    root_existed = root.exists()
    root.mkdir(parents=True, exist_ok=True)
    run = root / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '_' + run_id[:10])
    run.mkdir()
    files = [run / 'packet_plan.json', run / 'summary.json']
    files[0].write_text(json.dumps(plan, indent=2) + '\n')
    report = check.report()
    report['sender_source_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    files[1].write_text(json.dumps(report, indent=2) + '\n')
    for role in ('sent', 'received'):
        # Preserve capture arrival order; sorting by planned sequence would hide reordering.
        packets = [packet for (_, seen_role), packet in check.observed.items() if seen_role == role]
        if packets:
            path = run / (role + '.pcap')
            wrpcap(str(path), packets)
            files.append(path)
    # sudo is needed for packets, but the student should own the new evidence.
    if os.geteuid() == 0 and os.environ.get('SUDO_UID', '').isdigit() and os.environ.get('SUDO_GID', '').isdigit():
        owner_uid, owner_gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
        for path in files + [run] + ([] if root_existed else [root]):
            os.chown(path, owner_uid, owner_gid)
    return run


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packets', type=int, choices=(7, 8, 12), required=True)
    parser.add_argument('--source-port', type=int, required=True, help='Fresh flow identifier; choose a different port on reruns')
    parser.add_argument('--dry-run', action='store_true', help='Print the packet plan; send/capture nothing')
    parser.add_argument('--output-root', type=Path,
                        default=Path(__file__).resolve().parent.parent / 'results/manual_rf_demo')
    args = parser.parse_args(argv)
    try:
        plan = packet_plan(args.packets, args.source_port)
        print(f'One bidirectional UDP flow: 10.254.0.1:{args.source_port} <-> 10.254.0.2:443')
        print('F = host1 to host2; R = host2 to host1. Alternate direction; sizes are IPv4 bytes.')
        for p in plan:
            print(f"  Packet {p['sequence']:2}: {p['direction']}  {p['sender']} -> {p['receiver']}  IP size={p['ip_size']}")
        if args.dry_run:
            print('DRY RUN: no interfaces accessed, no packets sent, no output files created.')
            return 0
        if sys.platform != 'linux' or os.geteuid() != 0:
            raise ValueError('Run the live sender in Ubuntu using sudo and the explicit bmv2-venv Python path')
        links = json.loads(subprocess.run(['ip', '-d', '-j', 'link', 'show'],
                            check=True, capture_output=True, text=True).stdout)
        macs = validate_links(links)
        for host in HOSTS:
            if Path(f'/proc/sys/net/ipv4/conf/{host}/forwarding').read_text().strip() != '0':
                raise ValueError(f'{host}: IPv4 forwarding is enabled; this demo expects isolated endpoints')
        from scapy.all import AsyncSniffer, Ether, sendp
        run_id = uuid.uuid4().hex
        token = b'RFDEMO' + bytes.fromhex(run_id)
        frames = {p['sequence']: make_frame(p, macs, token) for p in plan}
        check = CaptureCheck(plan, frames, token)
        ready = threading.Event()
        sniffer = AsyncSniffer(iface=list(HOSTS), store=False, prn=check.observe, started_callback=ready.set)
        sniffer.start()
        try:
            if not ready.wait(5):
                raise ValueError('Capture did not become ready; no traffic sent')
            print('Both capture endpoints ready. Sending the flow...', flush=True)
            for p in plan:
                sendp(Ether(frames[p['sequence']]), iface=p['sender'], verbose=False)
                time.sleep(.10)
            check.completed.wait(5)
            # Observe any extra copies before closing the capture.
            time.sleep(.20)
        finally:
            if sniffer.running:
                sniffer.stop()
        run = save_evidence(args.output_root.expanduser().absolute(), plan, check, run_id)
        report = check.report()
        print(f"Observed outbound: {report['sent_observed']}/{args.packets}; forwarded: {report['received_observed']}/{args.packets}")
        print('FORWARDING: ' + ('PASS' if report['forwarding_passed'] else 'FAIL'))
        print(f'Evidence saved to: {run}')
        print('Now read all six RF decision counters in T2; this script does not inspect them.')
        if not report['forwarding_passed']:
            print(json.dumps(report, indent=2))
        return 0 if report['forwarding_passed'] else 1
    except (ValueError, OSError, subprocess.SubprocessError, ImportError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
