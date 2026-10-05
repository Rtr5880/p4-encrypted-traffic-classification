"""Bounded-memory capture I/O for controlled replay; packet order is never changed.

PCAPNG timestamps are represented exactly as integer nanoseconds. A timestamp
whose fractional part cannot be expressed in nanoseconds is rejected, not rounded.
Snap-truncated records retain both lengths so the replay adapter can reject them.
"""
from dataclasses import dataclass
from pathlib import Path
import struct


MAX_RECORD_BYTES = 16 * 1024 * 1024
MAX_BLOCK_BYTES = 64 * 1024 * 1024
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


class CaptureError(ValueError):
    """Unsupported or malformed input that must not silently lose packets."""


@dataclass(frozen=True)
class PacketRecord:
    number: int
    timestamp_ns: int
    captured_len: int
    wire_len: int
    linktype: int
    data: bytes


def _require(condition, message):
    if not condition:
        raise CaptureError(message)


def _read_exact(stream, count, description):
    data = stream.read(count)
    _require(len(data) == count, f"Truncated {description}: wanted {count}, got {len(data)} bytes")
    return data


def _classic_header(raw):
    _require(len(raw) == 24, "Truncated PCAP global header")
    _require(raw[:4] in MAGICS, "Unsupported classic PCAP magic")
    endian, units = MAGICS[raw[:4]]
    major, minor, _zone, _sigfigs, snaplen, linktype = struct.unpack(endian + "HHiiII", raw[4:])
    _require((major, minor) == (2, 4), f"Unsupported PCAP version {major}.{minor}")
    # Upper bits can carry extended link metadata; do not silently discard them.
    _require(linktype <= 0xFFFF, "Extended PCAP linktype metadata is unsupported")
    return endian, units, snaplen, linktype


def _lengths(caplen, wirelen, snaplen, maximum):
    _require(caplen <= maximum, f"Captured packet length {caplen} exceeds limit {maximum}")
    _require(caplen <= wirelen, "Captured packet length exceeds original wire length")
    _require(snaplen == 0 or caplen <= snaplen, "Captured packet length exceeds interface snaplen")


def _classic_record_header(raw, header, maximum):
    endian, units, snaplen, _linktype = header
    seconds, fraction, caplen, wirelen = struct.unpack(endian + "IIII", raw)
    _require(fraction < units, "PCAP timestamp fraction exceeds its resolution")
    _lengths(caplen, wirelen, snaplen, maximum)
    return seconds * 1_000_000_000 + fraction * (1_000_000_000 // units), caplen, wirelen


def _iter_classic(stream, first, maximum):
    header = _classic_header(first + _read_exact(stream, 20, "PCAP global header"))
    number = 0
    while True:
        raw = stream.read(16)
        if not raw:
            return
        _require(len(raw) == 16, "Truncated PCAP record header")
        stamp, caplen, wirelen = _classic_record_header(raw, header, maximum)
        data = _read_exact(stream, caplen, "PCAP packet data")
        number += 1
        yield PacketRecord(number, stamp, caplen, wirelen, header[3], data)


def _options(raw, endian):
    pos = 0
    while pos < len(raw):
        _require(pos + 4 <= len(raw), "Truncated PCAPNG option header")
        code, length = struct.unpack_from(endian + "HH", raw, pos)
        pos += 4
        if code == 0:
            _require(length == 0, "Invalid PCAPNG end-of-options length")
            _require(not any(raw[pos:]), "Nonzero bytes after PCAPNG end-of-options")
            return
        padded = (length + 3) & ~3
        _require(pos + padded <= len(raw), "Truncated PCAPNG option value")
        yield code, raw[pos:pos + length]
        pos += padded


def _interface(body, endian):
    _require(len(body) >= 8, "Truncated PCAPNG interface block")
    linktype, reserved, snaplen = struct.unpack_from(endian + "HHI", body)
    _require(reserved == 0, "Nonzero PCAPNG interface reserved field")
    resolution, offset, seen = 1_000_000, 0, set()
    for code, value in _options(body[8:], endian):
        if code in (9, 14):
            _require(code not in seen, f"Duplicate PCAPNG interface timestamp option {code}")
            seen.add(code)
        if code == 9:
            _require(len(value) == 1, "Invalid PCAPNG timestamp resolution option")
            resolution = 2 ** (value[0] & 127) if value[0] & 128 else 10 ** value[0]
        elif code == 14:
            _require(len(value) == 8, "Invalid PCAPNG timestamp offset option")
            offset = struct.unpack(endian + "q", value)[0]
    return linktype, snaplen, resolution, offset


def _iter_pcapng(stream, first, maximum):
    endian, interfaces, number, section_end = None, [], 0, None
    prefix = first + _read_exact(stream, 4, "PCAPNG first block header")
    while prefix:
        _require(len(prefix) == 8, "Truncated PCAPNG block header")
        block_start = stream.tell() - 8
        is_section = prefix[:4] == PCAPNG_MAGIC
        if is_section and section_end is not None:
            _require(block_start == section_end, "PCAPNG declared section length disagrees with next section")
        if is_section:
            bom = _read_exact(stream, 4, "PCAPNG byte-order magic")
            _require(bom in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"),
                     "Invalid PCAPNG byte-order magic")
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
        else:
            _require(endian is not None, "PCAPNG packet before section header")
        block_type, total = struct.unpack(endian + "II", prefix)
        _require(total >= (28 if is_section else 12) and total % 4 == 0,
                 "Invalid PCAPNG block length")
        _require(total <= MAX_BLOCK_BYTES, f"PCAPNG block exceeds {MAX_BLOCK_BYTES}-byte limit")
        if not is_section and section_end is not None:
            _require(block_start + total <= section_end, "PCAPNG block exceeds declared section length")
        rest = (bom if is_section else b"") + _read_exact(
            stream, total - (12 if is_section else 8), "PCAPNG block")
        _require(struct.unpack(endian + "I", rest[-4:])[0] == total,
                 "PCAPNG leading/trailing block lengths disagree")
        body = rest[:-4]
        if is_section:
            major, minor, section_length = struct.unpack_from(endian + "HHq", body, 4)
            _require((major, minor) == (1, 0), f"Unsupported PCAPNG version {major}.{minor}")
            _require(section_length >= -1, "Invalid PCAPNG section length")
            list(_options(body[16:], endian))
            interfaces = []
            section_end = None if section_length == -1 else stream.tell() + section_length
        elif block_type == 1:
            interfaces.append(_interface(body, endian))
        elif block_type == 6:
            _require(len(body) >= 20, "Truncated PCAPNG enhanced packet block")
            interface_id, high, low, caplen, wirelen = struct.unpack_from(endian + "IIIII", body)
            _require(interface_id < len(interfaces), "PCAPNG packet refers to unknown interface")
            linktype, snaplen, resolution, offset = interfaces[interface_id]
            _lengths(caplen, wirelen, snaplen, maximum)
            padded = (caplen + 3) & ~3
            _require(20 + padded <= len(body), "Truncated PCAPNG enhanced packet data")
            list(_options(body[20 + padded:], endian))
            stamp, remainder = divmod(((high << 32) | low) * 1_000_000_000, resolution)
            _require(remainder == 0, "PCAPNG timestamp is not exactly representable in nanoseconds")
            stamp += offset * 1_000_000_000
            number += 1
            yield PacketRecord(number, stamp, caplen, wirelen, linktype, body[20:20 + caplen])
        elif block_type in (4, 5, 10):
            # Name resolution, interface statistics, decryption secrets: metadata only.
            pass
        elif block_type in (2, 3):
            raise CaptureError(f"Unsupported packet-bearing PCAPNG block type {block_type}")
        else:
            raise CaptureError(f"Unsupported PCAPNG block type {block_type}; refusing to skip it")
        prefix = stream.read(8)
    if section_end is not None:
        _require(stream.tell() == section_end, "PCAPNG file ends before declared section length")


def iter_capture(path, *, max_record_bytes=MAX_RECORD_BYTES):
    """Yield all source records in file order. No linktype filtering or rewriting."""
    _require(type(max_record_bytes) is int and max_record_bytes > 0, "Invalid packet length limit")
    with Path(path).open("rb") as stream:
        first = _read_exact(stream, 4, "capture magic")
        if first == PCAPNG_MAGIC:
            yield from _iter_pcapng(stream, first, max_record_bytes)
        else:
            yield from _iter_classic(stream, first, max_record_bytes)


class ClassicPcapWriter:
    """Streaming little-endian writer; defaults to exclusive creation and nanoseconds."""

    def __init__(self, path, *, linktype=1, nanosecond=True, exclusive=True,
                 snaplen=MAX_RECORD_BYTES):
        _require(type(linktype) is int and 0 <= linktype <= 65535, "Invalid linktype")
        _require(type(snaplen) is int and 0 < snaplen <= 0xFFFFFFFF, "Invalid snaplen")
        self.units = 1_000_000_000 if nanosecond else 1_000_000
        self.snaplen = snaplen
        self.frames_count = 0
        self.stream = Path(path).open("xb" if exclusive else "wb")
        magic = b"\x4d\x3c\xb2\xa1" if nanosecond else b"\xd4\xc3\xb2\xa1"
        self.stream.write(magic + struct.pack("<HHIIII", 2, 4, 0, 0, snaplen, linktype))

    def write(self, timestamp_ns, data, wire_len=None):
        _require(type(timestamp_ns) is int and timestamp_ns >= 0, "PCAP timestamp must be a nonnegative integer")
        _require(isinstance(data, bytes), "Packet data must be immutable bytes")
        seconds, nano = divmod(timestamp_ns, 1_000_000_000)
        factor = 1_000_000_000 // self.units
        _require(seconds <= 0xFFFFFFFF and nano % factor == 0, "Timestamp cannot be represented by output PCAP")
        wire_len = len(data) if wire_len is None else wire_len
        _require(type(wire_len) is int and 0 <= wire_len <= 0xFFFFFFFF, "Invalid wire length")
        _lengths(len(data), wire_len, self.snaplen, self.snaplen)
        self.stream.write(struct.pack("<IIII", seconds, nano // factor, len(data), wire_len))
        self.stream.write(data)
        self.frames_count += 1

    def flush(self):
        self.stream.flush()

    def close(self):
        self.stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()


class PcapTailReader:
    """Read newly completed classic-PCAP records in O(total file size).

poll() may run while BMv2 appends output. Partial headers/data stay buffered for
the next call. finish() is called after the writer stops; incomplete tails fail.
The declared linktype is retained, including BMv2's DLT_NULL (0) output quirk.
Each generator must be exhausted before another call to poll() or finish().
"""

    def __init__(self, path, *, max_record_bytes=MAX_RECORD_BYTES):
        _require(type(max_record_bytes) is int and max_record_bytes > 0, "Invalid packet length limit")
        self.path, self.maximum = Path(path), max_record_bytes
        self.stream, self.header = None, None
        self.header_bytes, self.record_header, self.data = bytearray(), bytearray(), bytearray()
        self.pending = None
        self.frames_count = 0
        self.finished = False

    def _fill(self, buffer, target):
        buffer.extend(self.stream.read(target - len(buffer)))
        return len(buffer) == target

    def poll(self):
        _require(not self.finished, "Cannot poll a finished tail reader")
        if self.stream is None:
            try:
                self.stream = self.path.open("rb")
            except FileNotFoundError:
                return
        _require(self.path.stat().st_size >= self.stream.tell(), "Growing PCAP was truncated")
        if self.header is None:
            if not self._fill(self.header_bytes, 24):
                return
            self.header = _classic_header(bytes(self.header_bytes))
        while True:
            if self.pending is None:
                if not self._fill(self.record_header, 16):
                    return
                self.pending = _classic_record_header(bytes(self.record_header), self.header, self.maximum)
            stamp, caplen, wirelen = self.pending
            if not self._fill(self.data, caplen):
                return
            self.frames_count += 1
            record = PacketRecord(self.frames_count, stamp, caplen, wirelen, self.header[3], bytes(self.data))
            self.pending = None
            self.record_header.clear()
            self.data.clear()
            yield record

    def finish(self):
        yield from self.poll()
        _require(self.header is not None, "Missing or truncated output PCAP global header")
        _require(self.pending is None and not self.record_header and not self.data,
                 "Truncated output PCAP record at end of replay")
        self.finished = True

    def close(self):
        if self.stream is not None:
            self.stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
