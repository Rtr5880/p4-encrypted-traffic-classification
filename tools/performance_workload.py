"""Deterministic synthetic traffic for a normal-build RF performance benchmark.

The payload tag identifies packets for forwarding accounting. It carries no
capture timestamp, feature vector, reference activity label, or RF prediction.
Packets use ordinary Ethernet/IPv4/UDP headers and a valid IPv4 checksum; the
zero UDP checksum is permitted for IPv4. Frame sizes include Ethernet headers
and exclude FCS, preamble and the inter-frame gap.

Flow tuples are selected into distinct P4 CRC32 state slots. This deliberately
measures classifier/forwarder cost without state-table collisions; it is not a
measurement of natural traffic, hash-table capacity or classification accuracy.
"""

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import math
import struct
import zlib


FLOW_SLOTS = 65536
MAX_FLOWS = 4096
MAX_PACKETS = 100000
CLASSIFY_AT = 8
DEFAULT_FRAME_BYTES = 128
TAG_MAGIC = b"ETCP"
TAG_VERSION = 1
TAG = struct.Struct("!4sB3x16sQII")
MIN_FRAME_BYTES = 14 + 20 + 8 + TAG.size
MAX_FRAME_BYTES = 14 + 1500


def _integer(value, name, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def ipv4_checksum(data):
    """Return the Internet checksum, including a final odd-byte pad if needed."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


@dataclass(frozen=True)
class FlowTuple:
    src: str
    dst: str
    sport: int
    dport: int
    protocol: int = 17

    def __post_init__(self):
        src = int(ipaddress.IPv4Address(self.src))
        dst = int(ipaddress.IPv4Address(self.dst))
        _integer(self.sport, "source port", 1, 65535)
        _integer(self.dport, "destination port", 1, 65535)
        if self.protocol != 17 or type(self.protocol) is not int:
            raise ValueError("Performance workloads require UDP (17)")
        if 53 in (self.sport, self.dport) or (src, self.sport) == (dst, self.dport):
            raise ValueError("Flow tuple is excluded by the frozen P4 eligibility policy")

    @property
    def slot(self):
        # This exactly matches P4's protocol ++ low-IP ++ low-port ++ high-IP
        # ++ high-port network-order bit concatenation and CRC32 modulo 65536.
        low, high = sorted(((int(ipaddress.IPv4Address(self.src)), self.sport),
                            (int(ipaddress.IPv4Address(self.dst)), self.dport)))
        return zlib.crc32(struct.pack("!BIHIH", self.protocol, *low, *high)) % FLOW_SLOTS

    def reversed(self):
        return FlowTuple(self.dst, self.src, self.dport, self.sport, self.protocol)

    def as_dict(self):
        return {"src": self.src, "dst": self.dst, "sport": self.sport,
                "dport": self.dport, "protocol": self.protocol, "slot": self.slot}


def select_flows(count, namespace=0, reserved_slots=()):
    """Choose deterministic benchmark-range tuples, excluding reserved slots.

    Reserve warm-up slots when constructing the measurement plan so warm-up
    cannot consume a measurement flow's eighth-packet classification event.
    """
    _integer(count, "flow count", 1, MAX_FLOWS)
    _integer(namespace, "namespace", 0, 65533)
    occupied = set()
    for slot in reserved_slots:
        occupied.add(_integer(slot, "reserved slot", 0, FLOW_SLOTS - 1))
    if count > FLOW_SLOTS - len(occupied):
        raise ValueError("Not enough unreserved P4 state slots")
    src = str(ipaddress.IPv4Address(0xC6120001 + namespace))
    dst = "198.19.0.1"
    result = []
    # Bounded candidate search; typical small workloads finish near count.
    for candidate in range(FLOW_SLOTS * 64):
        flow = FlowTuple(src, dst, 20000 + candidate % 40000,
                         20000 + candidate // 40000)
        if flow.slot in occupied:
            continue
        occupied.add(flow.slot)
        result.append(flow)
        if len(result) == count:
            return tuple(result)
    raise ValueError("Bounded candidate search could not fill the requested slots")


@dataclass(frozen=True)
class DecodedFrame:
    sequence: int
    run_token: bytes
    flow_id: int
    packet_ordinal: int
    flow: FlowTuple
    frame_bytes: int
    source_mac: bytes
    destination_mac: bytes


def parse_frame(frame):
    """Decode our normal-build tag, checking the complete datagram structure."""
    if not isinstance(frame, bytes) or not MIN_FRAME_BYTES <= len(frame) <= MAX_FRAME_BYTES:
        raise ValueError("Frame is outside the complete tagged Ethernet size range")
    if frame[12:14] != b"\x08\x00" or frame[14] != 0x45:
        raise ValueError("Expected ordinary Ethernet/IPv4 with a 20-byte IP header")
    ip_header = frame[14:34]
    _, _, total_len, _, fragment, _, protocol, _, src, dst = struct.unpack(
        "!BBHHHBBH4s4s", ip_header)
    if total_len != len(frame) - 14 or fragment & 0x3FFF or protocol != 17:
        raise ValueError("Invalid IPv4 length, fragment or transport protocol")
    if ipv4_checksum(ip_header) != 0:
        raise ValueError("Invalid IPv4 checksum")
    sport, dport, udp_length, udp_checksum = struct.unpack_from("!HHHH", frame, 34)
    if udp_length != total_len - 20 or udp_checksum != 0:
        raise ValueError("Expected complete UDP with the IPv4 optional zero checksum")
    magic, version, run_token, sequence, flow_id, ordinal = TAG.unpack_from(frame, 42)
    if magic != TAG_MAGIC or version != TAG_VERSION or frame[47:50] != b"\x00" * 3:
        raise ValueError("Missing or unsupported performance payload tag")
    if ordinal < 1:
        raise ValueError("Packet ordinal is one-based")
    flow = FlowTuple(str(ipaddress.IPv4Address(src)), str(ipaddress.IPv4Address(dst)),
                     sport, dport)
    return DecodedFrame(sequence, run_token, flow_id, ordinal, flow,
                        len(frame), frame[6:12], frame[0:6])


@dataclass(frozen=True)
class WorkloadPlan:
    name: str
    flows: tuple
    packets_per_flow: int
    run_id: str
    frame_bytes: int = DEFAULT_FRAME_BYTES

    def __post_init__(self):
        if self.name not in ("classification-heavy", "cached-forwarding", "warm-up"):
            raise ValueError("Unknown performance workload")
        if not isinstance(self.flows, tuple) or not all(isinstance(flow, FlowTuple) for flow in self.flows):
            raise ValueError("Flows must be an immutable tuple of FlowTuple values")
        _integer(len(self.flows), "flow count", 1, MAX_FLOWS)
        _integer(self.packets_per_flow, "packets per flow", CLASSIFY_AT, MAX_PACKETS)
        _integer(self.frame_bytes, "frame bytes", MIN_FRAME_BYTES, MAX_FRAME_BYTES)
        if not isinstance(self.run_id, str) or not self.run_id or len(self.run_id.encode("utf-8")) > 1024:
            raise ValueError("run_id must be nonempty text of at most 1024 UTF-8 bytes")
        if self.packet_count > MAX_PACKETS:
            raise ValueError(f"Workload exceeds the {MAX_PACKETS}-packet safety limit")
        if self.name == "classification-heavy" and self.packets_per_flow != CLASSIFY_AT:
            raise ValueError("Classification-heavy workloads use exactly eight packets per fresh flow")
        if self.name == "cached-forwarding" and self.packets_per_flow <= CLASSIFY_AT:
            raise ValueError("Cached-forwarding workloads need packets after the eighth packet")
        if len({flow.slot for flow in self.flows}) != len(self.flows):
            raise ValueError("Workload contains colliding P4 state slots")
        benchmark_range = ipaddress.IPv4Network("198.18.0.0/15")
        if any(ipaddress.IPv4Address(ip) not in benchmark_range
               for flow in self.flows for ip in (flow.src, flow.dst)):
            raise ValueError("Workloads must use the isolated 198.18.0.0/15 benchmark range")

    @property
    def packet_count(self):
        return len(self.flows) * self.packets_per_flow

    @property
    def flow_count(self):
        return len(self.flows)

    @property
    def expected_classifications(self):
        return self.flow_count

    @property
    def slots(self):
        return tuple(flow.slot for flow in self.flows)

    @property
    def run_token(self):
        return hashlib.sha256(self.run_id.encode("utf-8")).digest()[:16]

    @property
    def source_mac(self):
        return b"\x02" + hashlib.sha256(b"src\x00" + self.run_token).digest()[:5]

    @property
    def destination_mac(self):
        return b"\x02" + hashlib.sha256(b"dst\x00" + self.run_token).digest()[:5]

    def _check_sequence(self, sequence):
        return _integer(sequence, "sequence", 0, self.packet_count - 1)

    def flow_for(self, sequence):
        self._check_sequence(sequence)
        flow = self.flows[sequence % self.flow_count]
        return flow.reversed() if self.packet_in_flow(sequence) % 2 == 0 else flow

    def packet_in_flow(self, sequence):
        self._check_sequence(sequence)
        return sequence // self.flow_count + 1

    def decision_positions(self):
        """Zero-based eighth-packet positions, assuming fresh state and no loss."""
        return tuple(7 * self.flow_count + index for index in range(self.flow_count))

    def frame_for(self, sequence):
        flow = self.flow_for(sequence)
        ordinal = self.packet_in_flow(sequence)
        payload = TAG.pack(TAG_MAGIC, TAG_VERSION, self.run_token, sequence,
                           sequence % self.flow_count, ordinal)
        pad_length = self.frame_bytes - 42 - TAG.size
        pattern = hashlib.sha256(b"padding\x00" + self.run_token).digest()
        payload += (pattern * ((pad_length + len(pattern) - 1) // len(pattern)))[:pad_length]
        udp = struct.pack("!HHHH", flow.sport, flow.dport, 8 + len(payload), 0)
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, self.frame_bytes - 14,
                             sequence & 65535, 0x4000, 64, 17, 0,
                             ipaddress.IPv4Address(flow.src).packed,
                             ipaddress.IPv4Address(flow.dst).packed)
        header = header[:10] + struct.pack("!H", ipv4_checksum(header)) + header[12:]
        return self.destination_mac + self.source_mac + b"\x08\x00" + header + udp + payload

    def sequence_from_frame(self, frame):
        """Return our sequence or None for unrelated/malformed tagged traffic.

        This associates packets; callers should also compare the received bytes
        with frame_for(sequence) to detect any forwarding corruption.
        """
        try:
            decoded = parse_frame(frame)
        except (ValueError, TypeError, struct.error):
            return None
        if decoded.run_token != self.run_token or not 0 <= decoded.sequence < self.packet_count:
            return None
        sequence = decoded.sequence
        if (decoded.flow_id != sequence % self.flow_count
                or decoded.packet_ordinal != self.packet_in_flow(sequence)
                or decoded.flow != self.flow_for(sequence)
                or decoded.frame_bytes != self.frame_bytes
                or decoded.source_mac != self.source_mac
                or decoded.destination_mac != self.destination_mac):
            return None
        return sequence

    def nominal_offset_ns(self, sequence, packets_per_second):
        """Uniform offered schedule; timestamps are not injected into packets."""
        self._check_sequence(sequence)
        if (isinstance(packets_per_second, bool)
                or not isinstance(packets_per_second, (int, float))
                or not math.isfinite(packets_per_second) or packets_per_second <= 0):
            raise ValueError("Offered packets per second must be finite and positive")
        if self.flow_count / packets_per_second >= 60:
            raise ValueError("Per-flow packet spacing would trigger the 60-second idle reset")
        numerator, denominator = float(packets_per_second).as_integer_ratio()
        return sequence * 1_000_000_000 * denominator // numerator

    def manifest(self):
        value = {
            "schema_version": 1, "workload": self.name, "run_id": self.run_id,
            "run_token_hex": self.run_token.hex(), "packet_count": self.packet_count,
            "flow_count": self.flow_count, "packets_per_flow": self.packets_per_flow,
            "frame_bytes": self.frame_bytes, "ipv4_bytes": self.frame_bytes - 14,
            "frame_size_convention": "Ethernet header included; FCS/preamble/IFG excluded",
            "source_mac": self.source_mac.hex(":"),
            "destination_mac": self.destination_mac.hex(":"),
            "ether_type": "0x0800", "ip_protocol": "UDP", "udp_checksum": 0,
            "ipv4_checksum_valid": True, "classify_at_packet": CLASSIFY_AT,
            "expected_classifications_if_fresh_state_and_no_loss": self.expected_classifications,
            "decision_sequence_positions_zero_based": list(self.decision_positions()),
            "round_robin": True, "logical_direction": "alternating forward/reverse per flow",
            "physical_path": "ingress port 1 to egress port 2",
            "state_slots": FLOW_SLOTS, "engineered_collision_free": True,
            "state_slot_policy": "unique CRC32 slot for every flow; reserved warm-up slots excluded by builder",
            "accuracy_oracle": None, "ground_truth_activity_labels": None,
            "traffic_kind": "synthetic performance traffic",
            "ports_and_addresses_are_model_inputs": False,
            "flow_tuples": [flow.as_dict() for flow in self.flows],
        }
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        value["workload_recipe_sha256"] = hashlib.sha256(encoded).hexdigest()
        return value


def build_workload(name, flow_count, packets_per_flow, run_id,
                   frame_bytes=DEFAULT_FRAME_BYTES, namespace=0, reserved_slots=()):
    """Build a bounded immutable plan; generate each packet only when requested."""
    return WorkloadPlan(name, select_flows(flow_count, namespace, reserved_slots),
                        packets_per_flow, run_id, frame_bytes)
