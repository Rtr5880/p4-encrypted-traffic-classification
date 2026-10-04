"""Verify flow identity and prevent false success from outbound-only captures."""
import importlib.util
import struct
import unittest

import manual_rf_demo as demo


class CapturedPacket:
    def __init__(self, raw, iface):
        self.raw = raw
        self.sniffed_on = iface

    def __bytes__(self):
        return self.raw


class DemoCaptureTests(unittest.TestCase):
    def setUp(self):
        self.plan = demo.packet_plan(7, 47107)
        self.token = b'RFDEMO' + b'A' * 16
        self.frames = {}
        for p in self.plan:
            # Capture checker only needs recognizable header offsets and token.
            raw = bytearray(42)
            raw[12:14] = b'\x08\x00'
            raw[14] = 0x45
            raw[23] = 17
            self.frames[p['sequence']] = bytes(raw) + self.token + struct.pack('!H', p['sequence']) + b'X' * 10
        self.check = demo.CaptureCheck(self.plan, self.frames, self.token)

    def observe(self, spec, role, raw=None):
        self.check.observe(CapturedPacket(raw or self.frames[spec['sequence']], spec[role]))

    def test_bidirectional_packets_share_one_canonical_tuple(self):
        for count in (7, 8, 12):
            plan = demo.packet_plan(count, 47107)
            keys = {tuple(sorted(((p['src'], p['sport']), (p['dst'], p['dport'])))) for p in plan}
            self.assertEqual(len(keys), 1)
            self.assertTrue(all(p['sender'] != p['receiver'] for p in plan))
            self.assertEqual([p['direction'] for p in plan[:4]], ['F', 'R', 'F', 'R'])
        eight = demo.packet_plan(8, 47108)
        self.assertEqual(sum(p['ip_size'] for p in eight), 1100)
        self.assertEqual(sum(p['direction'] == 'R' for p in eight), 4)

    def test_source_port_changes_flow_identity(self):
        self.assertNotEqual(demo.packet_plan(7, 47107)[0]['sport'], demo.packet_plan(8, 47108)[0]['sport'])
        for count, port in ((9, 47107), (7, 53), (8, 70000)):
            with self.assertRaises(ValueError):
                demo.packet_plan(count, port)

    def test_outbound_only_is_not_forwarding_success(self):
        for p in self.plan:
            self.observe(p, 'sender')
        report = self.check.report()
        self.assertEqual(report['sent_observed'], 7)
        self.assertEqual(report['received_observed'], 0)
        self.assertFalse(report['forwarding_passed'])

    def test_both_endpoints_required_with_reverse_orientation(self):
        for p in self.plan:
            self.observe(p, 'sender')
            self.observe(p, 'receiver')
        self.assertTrue(self.check.report()['forwarding_passed'])
        self.assertTrue(self.check.completed.is_set())

    def test_duplicate_does_not_replace_missing_receiver(self):
        for p in self.plan:
            self.observe(p, 'sender')
            self.observe(p, 'sender')
        report = self.check.report()
        self.assertEqual(report['sent_observed'], 7)
        self.assertEqual(report['duplicates'], {'sent': 7})
        self.assertFalse(report['forwarding_passed'])

    def test_byte_change_or_wrong_iface_fails(self):
        p = self.plan[0]
        changed = self.frames[1][:-1] + b'Y'
        self.observe(p, 'receiver', changed)
        self.check.observe(CapturedPacket(self.frames[1], 'eth0'))
        self.assertEqual(len(self.check.report()['errors']), 2)
        self.assertFalse(self.check.report()['forwarding_passed'])

    def test_unrelated_background_ignored(self):
        self.check.observe(CapturedPacket(b'background', 'p1_host1'))
        raw = self.frames[1].replace(self.token, b'OTHER_' + b'B' * 16)
        self.check.observe(CapturedPacket(raw, 'p1_host2'))
        self.assertEqual(self.check.report()['errors'], [])
        self.assertEqual(self.check.report()['received_observed'], 0)

    @unittest.skipUnless(importlib.util.find_spec('scapy'), 'Frame construction check uses bmv2-venv Scapy')
    def test_constructed_frames_have_expected_headers_and_lengths(self):
        from scapy.all import Ether, IP, UDP
        macs = {'p1_host1': '02:00:00:00:00:01', 'p1_host2': '02:00:00:00:00:02'}
        for p in self.plan:
            frame = demo.make_frame(p, macs, self.token)
            packet = Ether(frame)
            self.assertEqual(len(frame), p['ip_size'] + 14)
            self.assertEqual(packet[IP].len, p['ip_size'])
            self.assertEqual((packet[IP].src, packet[IP].dst), (p['src'], p['dst']))
            self.assertEqual((packet[UDP].sport, packet[UDP].dport), (p['sport'], p['dport']))
            self.assertEqual(packet.src, macs[p['sender']])
            self.assertEqual(packet.dst, macs[p['receiver']])
            self.assertNotEqual(packet[UDP].chksum, 0)


if __name__ == '__main__':
    unittest.main()
