"""Deterministic phase traffic for the full normal-build performance benchmark.

Eight fresh flows are interleaved until each has eight (classification-heavy)
or 32 (cached-forwarding) packets, then the next fresh block starts. This keeps
classification events distributed through the offered window. The last block
may be incomplete; manifests describe its actual packets and decisions.

The ordinary Ethernet/IPv4/UDP encoding and accounting tag are shared with the
frozen pilot workload. Tags contain no injected clock, model prediction, feature
vector or activity label. The fast receive decoder only associates a frame:
the transport must compare its complete bytes with the prebuilt sent frame.
"""

from dataclasses import dataclass, field
from decimal import Decimal
import hashlib
import ipaddress
import json
import math
import struct
import zlib

from performance_workload import (
    CLASSIFY_AT, DEFAULT_FRAME_BYTES, FLOW_SLOTS, FlowTuple,
    MAX_FRAME_BYTES, MIN_FRAME_BYTES, TAG, TAG_MAGIC, TAG_VERSION,
    ipv4_checksum, parse_frame,
)


MAX_RATE_PPS = 10_000
MAX_RATE = MAX_RATE_PPS
MAX_TOTAL_PACKETS = 500_000
MAX_OCCUPIED_SLOTS = 60_000
MAX_WARMUP_SECONDS = 10
MAX_MEASUREMENT_SECONDS = 60
CONCURRENCY = 8
_TAG_OFFSET = 42
_SEQUENCE_OFFSET = _TAG_OFFSET + 24
_SEQUENCE_TAIL = struct.Struct("!QII")
_KEY = struct.Struct("!BIHIH")
_WORKLOAD_PACKETS = {"classification-heavy": 8, "cached-forwarding": 32}
_BENCHMARK_RANGE = ipaddress.IPv4Network("198.18.0.0/15")


def _integer(value, name, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def _finite_number(value, name, minimum, maximum, *, lower_inclusive=True):
    if (type(value) not in (int, float) or value > maximum
            or (value < minimum if lower_inclusive else value <= minimum)
            or not math.isfinite(value)):
        bracket = "[" if lower_inclusive else "("
        raise ValueError(f"{name} must be finite and in {bracket}{minimum}, {maximum}]")
    return value


def _packet_count(rate_pps, seconds, phase):
    # Decimal text accepts ordinary exact decimal recipes such as 3 * 0.5 only
    # when their result is integral; it does not silently round a phase length.
    product = Decimal(str(rate_pps)) * Decimal(str(seconds))
    if product != product.to_integral_value():
        raise ValueError(f"{phase} rate * seconds must be an integer packet count")
    return int(product)


def _allocated_flow_count(packet_count, packets_per_flow, concurrency=CONCURRENCY):
    block_packets = concurrency * packets_per_flow
    return ((packet_count + block_packets - 1) // block_packets) * concurrency


def select_flows(count, namespace=0):
    """Select one combined, collision-free tuple pool for both phases.

    Every candidate has a distinct ordinary UDP key. Compute the frozen P4 key
    directly while searching, then instantiate its existing FlowTuple class.
    At most 60,000 of the 65,536 state slots may be occupied by one phase pair.
    """
    _integer(count, "combined flow count", 0, MAX_OCCUPIED_SLOTS)
    _integer(namespace, "namespace", 0, 65533)
    if not count:
        return ()
    src_integer = 0xC6120001 + namespace
    dst_integer = 0xC6130001
    src = str(ipaddress.IPv4Address(src_integer))
    dst = str(ipaddress.IPv4Address(dst_integer))
    occupied = set()
    result = []
    # Source is numerically below destination for every permitted namespace.
    # Thus this packing exactly matches FlowTuple.slot's endpoint sorting.
    for candidate in range(FLOW_SLOTS * 64):
        sport = 20000 + candidate % 40000
        dport = 20000 + candidate // 40000
        slot = zlib.crc32(_KEY.pack(17, src_integer, sport, dst_integer, dport)) % FLOW_SLOTS
        if slot in occupied:
            continue
        occupied.add(slot)
        result.append(FlowTuple(src, dst, sport, dport))
        if len(result) == count:
            return tuple(result)
    raise ValueError("Bounded candidate search could not fill the requested CRC32 slots")


@dataclass(frozen=True)
class BenchmarkPlan:
    name: str
    phase: str
    flows: tuple
    packet_count: int
    packets_per_flow: int
    run_id: str
    frame_bytes: int = DEFAULT_FRAME_BYTES
    concurrency: int = CONCURRENCY
    _slots: tuple = field(init=False, repr=False, compare=False)
    _wire_flows: tuple = field(init=False, repr=False, compare=False)
    _reverse_flows: tuple = field(init=False, repr=False, compare=False)
    _run_token: bytes = field(init=False, repr=False, compare=False)
    _source_mac: bytes = field(init=False, repr=False, compare=False)
    _destination_mac: bytes = field(init=False, repr=False, compare=False)
    _ethernet_header: bytes = field(init=False, repr=False, compare=False)
    _tag_prefix: bytes = field(init=False, repr=False, compare=False)
    _padding: bytes = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        if not isinstance(self.name, str) or self.name not in _WORKLOAD_PACKETS:
            raise ValueError("Unknown full benchmark workload")
        if self.phase not in ("warmup", "measurement"):
            raise ValueError("Phase must be warmup or measurement")
        _integer(self.concurrency, "concurrency", CONCURRENCY, CONCURRENCY)
        expected_packets = _WORKLOAD_PACKETS[self.name]
        _integer(self.packets_per_flow, "packets per flow", expected_packets, expected_packets)
        _integer(self.packet_count, "packet count", 0 if self.phase == "warmup" else 1,
                 MAX_TOTAL_PACKETS)
        _integer(self.frame_bytes, "frame bytes", MIN_FRAME_BYTES, MAX_FRAME_BYTES)
        if not isinstance(self.run_id, str) or not self.run_id or len(self.run_id.encode("utf-8")) > 1024:
            raise ValueError("run_id must be nonempty text of at most 1024 UTF-8 bytes")
        if not isinstance(self.flows, tuple) or not all(isinstance(flow, FlowTuple) for flow in self.flows):
            raise ValueError("Flows must be an immutable tuple of existing FlowTuple values")
        expected_flows = _allocated_flow_count(self.packet_count, self.packets_per_flow, self.concurrency)
        if len(self.flows) != expected_flows or len(self.flows) > MAX_OCCUPIED_SLOTS:
            raise ValueError("Flow count must allocate complete eight-flow blocks within the slot limit")
        slots = tuple(flow.slot for flow in self.flows)
        if len(set(slots)) != len(slots):
            raise ValueError("Workload contains colliding P4 state slots")
        if any(ipaddress.IPv4Address(ip) not in _BENCHMARK_RANGE
               for flow in self.flows for ip in (flow.src, flow.dst)):
            raise ValueError("Workloads must use the isolated 198.18.0.0/15 benchmark range")
        token_input = (self.run_id + "\x00" + self.name + "\x00" + self.phase).encode("utf-8")
        token = hashlib.sha256(token_input).digest()[:16]
        source_mac = b"\x02" + hashlib.sha256(b"src\x00" + token).digest()[:5]
        destination_mac = b"\x02" + hashlib.sha256(b"dst\x00" + token).digest()[:5]
        pattern = hashlib.sha256(b"padding\x00" + token).digest()
        pad_length = self.frame_bytes - _TAG_OFFSET - TAG.size
        object.__setattr__(self, "_slots", slots)
        object.__setattr__(self, "_wire_flows", tuple(
            (ipaddress.IPv4Address(flow.src).packed, ipaddress.IPv4Address(flow.dst).packed,
             flow.sport, flow.dport) for flow in self.flows))
        object.__setattr__(self, "_reverse_flows", tuple(flow.reversed() for flow in self.flows))
        object.__setattr__(self, "_run_token", token)
        object.__setattr__(self, "_source_mac", source_mac)
        object.__setattr__(self, "_destination_mac", destination_mac)
        object.__setattr__(self, "_ethernet_header", destination_mac + source_mac + b"\x08\x00")
        object.__setattr__(self, "_tag_prefix", TAG.pack(TAG_MAGIC, TAG_VERSION, token, 0, 0, 0)[:24])
        object.__setattr__(self, "_padding", (pattern * ((pad_length + 31) // 32))[:pad_length])

    @property
    def flow_count(self):
        """Allocated slots, including unused members of a partial final block."""
        return len(self.flows)

    @property
    def used_flow_count(self):
        groups, remainder = divmod(self.packet_count, self.concurrency * self.packets_per_flow)
        return groups * self.concurrency + min(remainder, self.concurrency)

    @property
    def slots(self):
        return self._slots

    @property
    def run_token(self):
        return self._run_token

    @property
    def source_mac(self):
        return self._source_mac

    @property
    def destination_mac(self):
        return self._destination_mac

    @property
    def expected_classifications(self):
        groups, remainder = divmod(self.packet_count, self.concurrency * self.packets_per_flow)
        return groups * self.concurrency + max(0, min(self.concurrency,
                                                   remainder - (CLASSIFY_AT - 1) * self.concurrency))

    @property
    def expected_cached_packets(self):
        groups, remainder = divmod(self.packet_count, self.concurrency * self.packets_per_flow)
        return (groups * self.concurrency * (self.packets_per_flow - CLASSIFY_AT)
                + max(0, remainder - CLASSIFY_AT * self.concurrency))

    @property
    def actual_packets_per_flow(self):
        groups, remainder = divmod(self.packet_count, self.concurrency * self.packets_per_flow)
        counts = [self.packets_per_flow] * (groups * self.concurrency)
        if remainder:
            rounds, extra = divmod(remainder, self.concurrency)
            counts.extend(rounds + (index < extra) for index in range(self.concurrency))
        return tuple(counts)

    def _check_sequence(self, sequence):
        return _integer(sequence, "sequence", 0, self.packet_count - 1)

    def _coordinates(self, sequence):
        group, in_block = divmod(sequence, self.concurrency * self.packets_per_flow)
        return group * self.concurrency + in_block % self.concurrency, in_block // self.concurrency + 1

    def flow_id_for(self, sequence):
        self._check_sequence(sequence)
        return self._coordinates(sequence)[0]

    def packet_in_flow(self, sequence):
        self._check_sequence(sequence)
        return self._coordinates(sequence)[1]

    def flow_for(self, sequence):
        self._check_sequence(sequence)
        flow_id, ordinal = self._coordinates(sequence)
        return self._reverse_flows[flow_id] if ordinal % 2 == 0 else self.flows[flow_id]

    def decision_positions(self):
        """Actual zero-based eighth-packet positions with fresh state/no loss."""
        block_packets = self.concurrency * self.packets_per_flow
        return tuple(position for block_start in range(0, self.packet_count, block_packets)
                     for position in range(block_start + (CLASSIFY_AT - 1) * self.concurrency,
                                           block_start + CLASSIFY_AT * self.concurrency)
                     if position < self.packet_count)

    def frame_for(self, sequence):
        self._check_sequence(sequence)
        flow_id, ordinal = self._coordinates(sequence)
        src, dst, sport, dport = self._wire_flows[flow_id]
        if ordinal % 2 == 0:
            src, dst, sport, dport = dst, src, dport, sport
        payload = TAG.pack(TAG_MAGIC, TAG_VERSION, self.run_token, sequence, flow_id, ordinal) + self._padding
        udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, self.frame_bytes - 14,
                             sequence & 65535, 0x4000, 64, 17, 0, src, dst)
        header = header[:10] + struct.pack("!H", ipv4_checksum(header)) + header[12:]
        return self._ethernet_header + header + udp + payload

    def sequence_from_frame(self, frame):
        """Associate a phase tag efficiently; full-byte integrity is external.

        Fixed-offset decoding deliberately avoids constructing IP addresses or
        FlowTuple objects in the capture path. Corruption outside the association
        fields can still associate and must fail the transport's full-byte check.
        """
        if (type(frame) is not bytes or len(frame) != self.frame_bytes
                or frame[:14] != self._ethernet_header
                or frame[_TAG_OFFSET:_SEQUENCE_OFFSET] != self._tag_prefix):
            return None
        sequence, flow_id, ordinal = _SEQUENCE_TAIL.unpack_from(frame, _SEQUENCE_OFFSET)
        if sequence >= self.packet_count or (flow_id, ordinal) != self._coordinates(sequence):
            return None
        return sequence

    def nominal_offset_ns(self, sequence, packets_per_second):
        """Offered schedule only; timestamps are never inserted into packets."""
        self._check_sequence(sequence)
        _finite_number(packets_per_second, "offered packets per second", 1, MAX_RATE_PPS)
        numerator, denominator = float(packets_per_second).as_integer_ratio()
        return sequence * 1_000_000_000 * denominator // numerator

    def manifest(self):
        counts = self.actual_packets_per_flow
        value = {
            "schema_version": 2, "workload": self.name, "phase": self.phase,
            "run_id": self.run_id, "run_token_hex": self.run_token.hex(),
            "packet_count": self.packet_count, "flow_count": self.flow_count,
            "allocated_flow_count": self.flow_count, "used_flow_count": self.used_flow_count,
            "unused_allocated_flow_count": self.flow_count - self.used_flow_count,
            "completed_flow_count": sum(count == self.packets_per_flow for count in counts),
            "actual_packets_per_flow": list(counts), "packets_per_flow": self.packets_per_flow,
            "concurrency": self.concurrency, "block_packets": self.concurrency * self.packets_per_flow,
            "complete_block_count": self.packet_count // (self.concurrency * self.packets_per_flow),
            "partial_final_block_packets": self.packet_count % (self.concurrency * self.packets_per_flow),
            "frame_bytes": self.frame_bytes, "ipv4_bytes": self.frame_bytes - 14,
            "frame_size_convention": "Ethernet header included; FCS/preamble/IFG excluded",
            "source_mac": self.source_mac.hex(":"), "destination_mac": self.destination_mac.hex(":"),
            "ether_type": "0x0800", "ip_protocol": "UDP", "udp_checksum": 0,
            "ipv4_checksum_valid": True, "classify_at_packet": CLASSIFY_AT,
            "expected_classifications": self.expected_classifications,
            "expected_classifications_if_fresh_state_and_no_loss": self.expected_classifications,
            "preclassification_packet_count": self.packet_count - self.expected_classifications - self.expected_cached_packets,
            "classification_packet_count": self.expected_classifications,
            "cached_forwarding_packet_count": self.expected_cached_packets,
            "decision_sequence_positions_zero_based": list(self.decision_positions()),
            "round_robin": True, "round_robin_scope": "eight-flow fresh blocks",
            "logical_direction": "alternating forward/reverse per flow",
            "physical_path": "ingress port 1 to egress port 2",
            "state_slots": FLOW_SLOTS, "engineered_collision_free": True,
            "state_slot_policy": "one combined unique CRC32 slot pool split between warmup and measurement",
            "accuracy_oracle": None, "ground_truth_activity_labels": None,
            "traffic_kind": "synthetic performance traffic", "ports_and_addresses_are_model_inputs": False,
            "flow_tuples": [flow.as_dict() for flow in self.flows],
        }
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        value["workload_recipe_sha256"] = hashlib.sha256(encoded).hexdigest()
        return value


def build_phase_pair(rate_pps, warmup_seconds, measurement_seconds, workload, run_id,
                     frame_bytes=DEFAULT_FRAME_BYTES, namespace=0, concurrency=CONCURRENCY):
    """Build exact-duration warmup/measurement plans with separate keys and slots.

    A zero-second warmup is supported for unit tests and smoke checks. The full
    benchmark runner's normal warmup is five seconds. One run_id identifies a
    recipe block reused byte-for-byte across model and forwarding modes.
    """
    _finite_number(rate_pps, "rate", 1, MAX_RATE_PPS)
    _finite_number(warmup_seconds, "warmup seconds", 0, MAX_WARMUP_SECONDS)
    _finite_number(measurement_seconds, "measurement seconds", 0, MAX_MEASUREMENT_SECONDS,
                   lower_inclusive=False)
    _integer(namespace, "namespace", 0, 65533)
    _integer(concurrency, "concurrency", CONCURRENCY, CONCURRENCY)
    _integer(frame_bytes, "frame bytes", MIN_FRAME_BYTES, MAX_FRAME_BYTES)
    if not isinstance(workload, str) or workload not in _WORKLOAD_PACKETS:
        raise ValueError("Unknown full benchmark workload")
    if not isinstance(run_id, str) or not run_id or len(run_id.encode("utf-8")) > 1024:
        raise ValueError("run_id must be nonempty text of at most 1024 UTF-8 bytes")
    warm_packets = _packet_count(rate_pps, warmup_seconds, "warmup")
    measured_packets = _packet_count(rate_pps, measurement_seconds, "measurement")
    if measured_packets < 1:
        raise ValueError("Measurement requires at least one packet")
    if warm_packets + measured_packets > MAX_TOTAL_PACKETS:
        raise ValueError(f"Combined phases exceed the {MAX_TOTAL_PACKETS}-packet safety limit")
    packets_per_flow = _WORKLOAD_PACKETS[workload]
    warm_flow_count = _allocated_flow_count(warm_packets, packets_per_flow, concurrency)
    measured_flow_count = _allocated_flow_count(measured_packets, packets_per_flow, concurrency)
    if warm_flow_count + measured_flow_count > MAX_OCCUPIED_SLOTS:
        raise ValueError(f"Combined phases exceed the {MAX_OCCUPIED_SLOTS}-slot safety limit")
    flows = select_flows(warm_flow_count + measured_flow_count, namespace)
    warmup = BenchmarkPlan(workload, "warmup", flows[:warm_flow_count], warm_packets,
                           packets_per_flow, run_id, frame_bytes, concurrency)
    measurement = BenchmarkPlan(workload, "measurement", flows[warm_flow_count:], measured_packets,
                                packets_per_flow, run_id, frame_bytes, concurrency)
    return warmup, measurement
