"""Binary-format and incremental-reading checks independent of the replay adapter."""
from dataclasses import FrozenInstanceError
from pathlib import Path
import struct
import tempfile
import unittest

from pcap_replay_io import CaptureError, ClassicPcapWriter, PcapTailReader, iter_capture


def classic(endian="<", nano=False, rows=None, snaplen=65535, linktype=101):
    magic = {(False, "<"): b"\xd4\xc3\xb2\xa1", (False, ">"): b"\xa1\xb2\xc3\xd4",
             (True, "<"): b"\x4d\x3c\xb2\xa1", (True, ">"): b"\xa1\xb2\x3c\x4d"}[(nano, endian)]
    out = magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, snaplen, linktype)
    for seconds, fraction, data, wire in rows or []:
        out += struct.pack(endian + "IIII", seconds, fraction, len(data), wire) + data
    return out


def block(kind, body, endian="<"):
    assert len(body) % 4 == 0
    length = 12 + len(body)
    return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)


def section(endian="<"):
    return block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian)


def option(code, value, endian="<"):
    return struct.pack(endian + "HH", code, len(value)) + value + b"\0" * (-len(value) % 4)


def interface(endian="<", linktype=101, resolution=6, offset=0):
    opts = option(9, bytes([resolution]), endian) + option(14, struct.pack(endian + "q", offset), endian)
    return block(1, struct.pack(endian + "HHI", linktype, 0, 65535) + opts + b"\0" * 4, endian)


def packet(ticks, data=b"\x45\0\x00\x14", endian="<", iface=0, wire=None):
    wire = len(data) if wire is None else wire
    body = struct.pack(endian + "IIIII", iface, ticks >> 32, ticks & 0xFFFFFFFF, len(data), wire)
    return block(6, body + data + b"\0" * (-len(data) % 4), endian)


class CaptureIOTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "capture.pcap"

    def tearDown(self):
        self.temp.cleanup()

    def records(self, raw, **kwargs):
        self.path.write_bytes(raw)
        return list(iter_capture(self.path, **kwargs))

    def test_classic_both_endians_both_precisions_and_backwards_order(self):
        payloads = [b"\x45\x00\xff\x01", b"\x45\x80", b"\xff\0"]
        for endian in ("<", ">"):
            for nano in (False, True):
                with self.subTest(endian=endian, nano=nano):
                    rows = [(2, 123, payloads[0], 4), (2, 122, payloads[1], 2), (3, 0, payloads[2], 2)]
                    rec = self.records(classic(endian, nano, rows))
                    factor = 1 if nano else 1000
                    self.assertEqual([r.timestamp_ns for r in rec], [2_000_000_000 + 123 * factor,
                                      2_000_000_000 + 122 * factor, 3_000_000_000])
                    self.assertEqual([r.data for r in rec], payloads)
                    self.assertEqual([r.number for r in rec], [1, 2, 3])
                    self.assertEqual(rec[0].linktype, 101)
                    with self.assertRaises(FrozenInstanceError):
                        rec[0].number = 5

    def test_snap_truncation_preserves_lengths(self):
        raw = classic(rows=[(1, 0, b"abc", 60)])
        record, = self.records(raw)
        self.assertEqual((record.captured_len, record.wire_len, record.data), (3, 60, b"abc"))
        record, = self.records(section() + interface() + packet(1, b"abc", wire=60))
        self.assertEqual((record.captured_len, record.wire_len), (3, 60))

    def test_pcapng_multi_interface_and_changed_section_endian(self):
        raw = section() + interface(resolution=9) + interface(linktype=228, resolution=0x80 | 10)
        raw += packet(2000000011, b"first") + packet(1024, b"second", iface=1)
        raw += section(">") + interface(">", resolution=6, offset=-1) + packet(1_000_007, b"third", ">")
        rec = self.records(raw)
        self.assertEqual([r.timestamp_ns for r in rec], [2_000_000_011, 1_000_000_000, 7000])
        self.assertEqual([r.linktype for r in rec], [101, 228, 101])
        self.assertEqual([r.number for r in rec], [1, 2, 3])
        self.assertEqual([r.data for r in rec], [b"first", b"second", b"third"])

    def test_pcapng_binary_subnanosecond_rejected_unless_exact(self):
        header = section() + interface(resolution=0x80 | 30)
        self.assertEqual(self.records(header + packet(1 << 30))[0].timestamp_ns, 1_000_000_000)
        with self.assertRaisesRegex(CaptureError, "not exactly representable"):
            self.records(header + packet(1))
        header = section() + interface(resolution=10)
        self.assertEqual(self.records(header + packet(10))[0].timestamp_ns, 1)
        with self.assertRaisesRegex(CaptureError, "not exactly representable"):
            self.records(header + packet(1))

    def test_section_resets_interface_ids(self):
        raw = section() + interface() + section(">") + packet(1, endian=">")
        with self.assertRaisesRegex(CaptureError, "unknown interface"):
            self.records(raw)

    def test_declared_section_length_is_respected(self):
        body = interface() + packet(1000)
        def sized_header(length):
            return block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, length))
        self.assertEqual(len(self.records(sized_header(len(body)) + body)), 1)
        for delta in (-4, 4):
            with self.subTest(delta=delta), self.assertRaisesRegex(CaptureError, "section length"):
                self.records(sized_header(len(body) + delta) + body)
        with self.assertRaisesRegex(CaptureError, "section length"):
            self.records(sized_header(len(body) + 4) + body + section(">"))

    def test_classic_invalid_lengths_fraction_and_record_limit(self):
        for raw, message in [
            (classic(rows=[(1, 0, b"abc", 2)]), "exceeds original"),
            (classic(rows=[(1, 0, b"abc", 3)], snaplen=2), "exceeds interface snaplen"),
            (classic(rows=[(1, 1_000_000, b"a", 1)]), "fraction"),
        ]:
            with self.subTest(message=message), self.assertRaisesRegex(CaptureError, message):
                self.records(raw)
        with self.assertRaisesRegex(CaptureError, "exceeds limit"):
            self.records(classic(rows=[(1, 0, b"abc", 3)]), max_record_bytes=2)

    def test_truncated_classic_file_fails_at_each_boundary(self):
        raw = classic(rows=[(1, 0, b"abcd", 4)])
        for length in (0, 3, 4, 23, 25, 39, 40, 43):
            with self.subTest(length=length), self.assertRaisesRegex(CaptureError, "Truncated"):
                self.records(raw[:length])

    def test_pcapng_truncated_or_corrupt_blocks_fail(self):
        raw = section() + interface() + packet(1000, b"abcdefg")
        for length in (3, 8, 11, 27, len(raw) - 1, len(raw) - 5):
            with self.subTest(length=length), self.assertRaises(CaptureError):
                self.records(raw[:length])
        with self.assertRaisesRegex(CaptureError, "lengths disagree"):
            self.records(raw[:-4] + struct.pack("<I", 999))
        with self.assertRaisesRegex(CaptureError, "exceeds original"):
            self.records(section() + interface() + packet(1, b"ab", wire=1))
        with self.assertRaisesRegex(CaptureError, "option"):
            self.records(section() + block(1, struct.pack("<HHI", 101, 0, 65535) + struct.pack("<HH", 9, 20)))

    def test_pcapng_unsupported_packet_or_unknown_blocks_not_silently_skipped(self):
        for kind in (2, 3, 0xDEADBEEF):
            with self.subTest(kind=kind), self.assertRaisesRegex(CaptureError, "Unsupported"):
                self.records(section() + block(kind, b"\0" * 8))

    def test_writer_roundtrip_and_exclusive_create(self):
        with ClassicPcapWriter(self.path) as writer:
            writer.write(2_000_000_005, b"ethernet bytes")
            writer.write(1_000_000_001, b"next")
            self.assertEqual(writer.frames_count, 2)
        rec = list(iter_capture(self.path))
        self.assertEqual([r.timestamp_ns for r in rec], [2_000_000_005, 1_000_000_001])
        self.assertEqual([r.data for r in rec], [b"ethernet bytes", b"next"])
        self.assertEqual(rec[0].linktype, 1)
        with self.assertRaises(FileExistsError):
            ClassicPcapWriter(self.path)

    def test_writer_refuses_lossy_timestamp_and_impossible_length(self):
        with ClassicPcapWriter(self.path, nanosecond=False) as writer:
            with self.assertRaisesRegex(CaptureError, "cannot be represented"):
                writer.write(1, b"x")
            with self.assertRaisesRegex(CaptureError, "exceeds original"):
                writer.write(1000, b"abc", wire_len=2)
            writer.write(1000, b"abc")
        self.assertEqual(len(list(iter_capture(self.path))), 1)

    def test_tail_resumes_partial_header_and_data_without_duplicates(self):
        raw = classic(">", True, [(2, 10, b"alpha", 5), (1, 30, b"beta", 4)], linktype=0)
        observed = []
        with PcapTailReader(self.path) as tail:
            self.assertEqual(list(tail.poll()), [])  # file may not exist yet
            with self.path.open("wb") as output:
                for byte in raw:
                    output.write(bytes([byte]))
                    output.flush()
                    observed.extend(tail.poll())
                    self.assertEqual(list(tail.poll()), [])
            self.assertEqual(list(tail.finish()), [])
            self.assertEqual(tail.frames_count, 2)
        self.assertEqual([r.data for r in observed], [b"alpha", b"beta"])
        self.assertEqual([r.timestamp_ns for r in observed], [2_000_000_010, 1_000_000_030])
        self.assertEqual([r.linktype for r in observed], [0, 0])

    def test_tail_finish_rejects_truncation_but_accepts_empty_valid_file(self):
        raw = classic(rows=[(1, 0, b"abcd", 4)])
        for length in (0, 23, 26, 40, 43):
            self.path.write_bytes(raw[:length])
            with self.subTest(length=length), PcapTailReader(self.path) as tail:
                self.assertEqual(list(tail.poll()), [])
                with self.assertRaisesRegex(CaptureError, "[Tt]runcated"):
                    list(tail.finish())
        self.path.write_bytes(classic())
        with PcapTailReader(self.path) as tail:
            self.assertEqual(list(tail.finish()), [])

    def test_tail_rejects_impossible_record_and_rescinded_bytes(self):
        self.path.write_bytes(classic(rows=[(1, 0, b"abc", 2)]))
        with PcapTailReader(self.path) as tail, self.assertRaisesRegex(CaptureError, "exceeds original"):
            list(tail.poll())
        self.path.write_bytes(classic(rows=[(1, 0, b"abc", 3)]))
        with PcapTailReader(self.path) as tail:
            self.assertEqual(len(list(tail.poll())), 1)
            self.path.write_bytes(b"")
            with self.assertRaisesRegex(CaptureError, "was truncated"):
                list(tail.poll())


if __name__ == "__main__":
    unittest.main()
