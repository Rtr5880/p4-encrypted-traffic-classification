/* Shared RF-B/RF-C feature extractor; inference is deliberately not present yet.
 * Build defaults are live timestamps and unmodified Ethernet forwarding.
 * TEST_TIMESTAMPS and DEBUG_REPORT are test-only compiler definitions.
 * Packed register entries retain full tuple tags: collisions fail closed for
 * classification (normal forwarding continues), never overwrite another flow.
 */
#include <core.p4>
#include <v1model.p4>

#ifndef FLOW_SLOTS
#define FLOW_SLOTS 65536
#endif
#ifndef TEST_TIMESTAMPS
#define TEST_TIMESTAMPS 0
#endif
#ifndef DEBUG_REPORT
#define DEBUG_REPORT 0
#endif
#if TEST_TIMESTAMPS && !DEBUG_REPORT
#error TEST_TIMESTAMPS_requires_DEBUG_REPORT_test_build
#endif

const bit<48> IDLE_US = 60000000;
const bit<32> TEST_MAGIC = 0x45544354;
const bit<32> REPORT_MAGIC = 0x45544352;
error { BadIPv4, BadTCP }

header ethernet_t { bit<48> dst; bit<48> src; bit<16> ether_type; }
header test_t { bit<32> magic; bit<32> packet_id; bit<48> timestamp_us; }
header ipv4_t {
    bit<4> version; bit<4> ihl; bit<8> tos; bit<16> total_len;
    bit<16> identification; bit<3> flags; bit<13> frag_offset;
    bit<8> ttl; bit<8> protocol; bit<16> checksum;
    bit<32> src; bit<32> dst;
}
header options_t { varbit<320> data; }
header tcp_t {
    bit<16> src; bit<16> dst; bit<32> seq; bit<32> ack_number;
    bit<4> offset; bit<3> reserved; bit<9> flags;
    bit<16> window; bit<16> checksum; bit<16> urgent;
}
header udp_t { bit<16> src; bit<16> dst; bit<16> length; bit<16> checksum; }

/* 71 bytes, in network byte order. Feature fields are snapshots at min(count,8).
 * status: 0 rejected, 1 eligible, 2 exactly packet 8, 3 tag collision.
 * reason: 0 eligible, 1 unsupported, 2 parser/truncation, 3 invalid lengths,
 *         4 fragment, 5 port 53, 6 identical endpoints, 7 test magic.
 * flags: 0 continuing, 1 new parent, 2 idle reset, 3 new SYN, 4 after RST.
 */
header report_t {
    bit<32> magic; bit<8> version; bit<8> status; bit<8> reason; bit<8> count;
    bit<32> packet_id; bit<48> observed_us; bit<48> effective_us;
    bit<32> slot; bit<32> instance; bit<8> ip_proto;
    bit<32> src_addr; bit<32> dst_addr; bit<16> src_port; bit<16> dst_port;
    bit<16> size_min; bit<16> size_max; bit<32> size_sum;
    bit<32> iat_min; bit<32> iat_max; bit<32> iat_sum;
    bit<8> reverse_count; bit<8> direction_changes;
    bit<8> direction; bit<8> active; bit<8> flags; bit<8> reserved;
}
struct headers_t {
    ethernet_t ethernet; test_t test; report_t report;
    ipv4_t ip; options_t ip_options; tcp_t tcp;
    options_t tcp_options; udp_t udp;
}

struct metadata_t {
    bit<32> l2_bytes; bit<32> ip_bytes; bit<32> tcp_bytes;
    bit<16> sport; bit<16> dport;
    bit<32> lo_ip; bit<16> lo_port; bit<32> hi_ip; bit<16> hi_port;
    bit<1> source_hi; bit<1> direction;
    bit<32> slot; bit<48> observed; bit<48> effective; bit<48> gap;
    bit<8> status; bit<8> reason; bit<8> boundary;
    bool eligible; bool collision; bool fresh; bool reset_instance;
    bool syn; bool ack; bool fin; bool rst; bool bare_syn;
    bit<429> packed;
    bit<1> s_seen; bit<8> s_protocol;
    bit<32> s_lo_ip; bit<16> s_lo_port; bit<32> s_hi_ip; bit<16> s_hi_port;
    bit<1> s_active; bit<32> s_instance; bit<48> s_last;
    bit<1> s_forward_hi; bit<4> s_count; bit<1> s_previous;
    bit<1> s_syn_lo_valid; bit<1> s_syn_hi_valid; bit<1> s_non_syn;
    bit<1> s_fin_lo; bit<1> s_fin_hi;
    bit<32> s_syn_lo; bit<32> s_syn_hi;
    bit<16> s_size_min; bit<16> s_size_max; bit<32> s_size_sum;
    bit<32> s_iat_min; bit<32> s_iat_max; bit<32> s_iat_sum;
    bit<4> s_reverse; bit<4> s_changes;
}

parser FeatureParser(packet_in packet, out headers_t hdr,
              inout metadata_t meta, inout standard_metadata_t sm) {
    state start {
        meta.l2_bytes = 14;
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            0x0800: parse_ip;
#if TEST_TIMESTAMPS
            0x88b5: parse_test;
#endif
            default: accept;
        }
    }
#if TEST_TIMESTAMPS
    state parse_test {
        packet.extract(hdr.test);
        meta.l2_bytes = 28;
        transition parse_ip;
    }
#endif
    state parse_ip {
        packet.extract(hdr.ip);
        verify(hdr.ip.version == 4 && hdr.ip.ihl >= 5, error.BadIPv4);
        meta.ip_bytes = (bit<32>) hdr.ip.ihl * 4;
        transition select(hdr.ip.ihl) { 5: choose_transport; default: parse_ip_options; }
    }
    state parse_ip_options {
        packet.extract(hdr.ip_options, (meta.ip_bytes - 20) * 8);
        transition choose_transport;
    }
    state choose_transport {
        /* Do not attempt to parse transport fields inside non-first fragments. */
        transition select(hdr.ip.frag_offset, hdr.ip.protocol) {
            (0, 6): parse_tcp;
            (0, 17): parse_udp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        verify(hdr.tcp.offset >= 5, error.BadTCP);
        meta.tcp_bytes = (bit<32>) hdr.tcp.offset * 4;
        transition select(hdr.tcp.offset) { 5: accept; default: parse_tcp_options; }
    }
    state parse_tcp_options {
        packet.extract(hdr.tcp_options, (meta.tcp_bytes - 20) * 8);
        transition accept;
    }
    state parse_udp { packet.extract(hdr.udp); transition accept; }
}

control FeatureVerify(inout headers_t hdr, inout metadata_t meta) { apply { } }

control FeatureIngress(inout headers_t hdr, inout metadata_t meta,
                inout standard_metadata_t sm) {
    register<bit<429>>(FLOW_SLOTS) flow_state;

    action unpack_state() {
        meta.s_seen = meta.packed[428:428];
        meta.s_protocol = meta.packed[427:420];
        meta.s_lo_ip = meta.packed[419:388];
        meta.s_lo_port = meta.packed[387:372];
        meta.s_hi_ip = meta.packed[371:340];
        meta.s_hi_port = meta.packed[339:324];
        meta.s_active = meta.packed[323:323];
        meta.s_instance = meta.packed[322:291];
        meta.s_last = meta.packed[290:243];
        meta.s_forward_hi = meta.packed[242:242];
        meta.s_count = meta.packed[241:238];
        meta.s_previous = meta.packed[237:237];
        meta.s_syn_lo_valid = meta.packed[236:236];
        meta.s_syn_hi_valid = meta.packed[235:235];
        meta.s_non_syn = meta.packed[234:234];
        meta.s_fin_lo = meta.packed[233:233];
        meta.s_fin_hi = meta.packed[232:232];
        meta.s_syn_lo = meta.packed[231:200];
        meta.s_syn_hi = meta.packed[199:168];
        meta.s_size_min = meta.packed[167:152];
        meta.s_size_max = meta.packed[151:136];
        meta.s_size_sum = meta.packed[135:104];
        meta.s_iat_min = meta.packed[103:72];
        meta.s_iat_max = meta.packed[71:40];
        meta.s_iat_sum = meta.packed[39:8];
        meta.s_reverse = meta.packed[7:4];
        meta.s_changes = meta.packed[3:0];
    }
    action pack_state() {
        meta.packed = meta.s_seen ++ meta.s_protocol ++
            meta.s_lo_ip ++ meta.s_lo_port ++ meta.s_hi_ip ++ meta.s_hi_port ++
            meta.s_active ++ meta.s_instance ++ meta.s_last ++
            meta.s_forward_hi ++ meta.s_count ++ meta.s_previous ++
            meta.s_syn_lo_valid ++ meta.s_syn_hi_valid ++ meta.s_non_syn ++
            meta.s_fin_lo ++ meta.s_fin_hi ++ meta.s_syn_lo ++ meta.s_syn_hi ++
            meta.s_size_min ++ meta.s_size_max ++ meta.s_size_sum ++
            meta.s_iat_min ++ meta.s_iat_max ++ meta.s_iat_sum ++
            meta.s_reverse ++ meta.s_changes;
    }
    action begin_instance() {
        meta.s_active = 1;
        meta.s_instance = meta.s_instance + 1;
        meta.s_forward_hi = meta.source_hi;
        meta.s_count = 0;
        meta.s_previous = 0;
        meta.s_syn_lo_valid = 0; meta.s_syn_hi_valid = 0;
        meta.s_syn_lo = 0; meta.s_syn_hi = 0;
        meta.s_non_syn = 0; meta.s_fin_lo = 0; meta.s_fin_hi = 0;
        meta.s_size_min = 0; meta.s_size_max = 0; meta.s_size_sum = 0;
        meta.s_iat_min = 0; meta.s_iat_max = 0; meta.s_iat_sum = 0;
        meta.s_reverse = 0; meta.s_changes = 0;
    }
    action update_prefix() {
        /* Only seven REAL gaps are accumulated: the first packet has no IAT. */
        if (meta.s_count < 8) {
            if (meta.s_count == 0) {
                meta.s_size_min = hdr.ip.total_len;
                meta.s_size_max = hdr.ip.total_len;
            } else {
                if (hdr.ip.total_len < meta.s_size_min) { meta.s_size_min = hdr.ip.total_len; }
                if (hdr.ip.total_len > meta.s_size_max) { meta.s_size_max = hdr.ip.total_len; }
                if (meta.s_count == 1 || meta.gap < (bit<48>) meta.s_iat_min) {
                    meta.s_iat_min = (bit<32>) meta.gap;
                }
                if (meta.gap > (bit<48>) meta.s_iat_max) { meta.s_iat_max = (bit<32>) meta.gap; }
                meta.s_iat_sum = meta.s_iat_sum + (bit<32>) meta.gap;
                if (meta.direction != meta.s_previous) { meta.s_changes = meta.s_changes + 1; }
            }
            meta.s_size_sum = meta.s_size_sum + (bit<32>) hdr.ip.total_len;
            if (meta.direction == 1) { meta.s_reverse = meta.s_reverse + 1; }
            meta.s_previous = meta.direction;
            meta.s_count = meta.s_count + 1;
            if (meta.s_count == 8) { meta.status = 2; }
        }
    }
    action observe_tcp() {
        /* setdefault semantics preserve the first observed/inferred ISN. */
        if (hdr.tcp.isValid()) {
            if (meta.syn) {
                if (meta.source_hi == 0) {
                    if (meta.s_syn_lo_valid == 0) {
                        meta.s_syn_lo_valid = 1; meta.s_syn_lo = hdr.tcp.seq;
                    }
                    if (meta.ack && meta.s_non_syn == 0 && meta.s_syn_hi_valid == 0) {
                        meta.s_syn_hi_valid = 1; meta.s_syn_hi = hdr.tcp.ack_number - 1;
                    }
                } else {
                    if (meta.s_syn_hi_valid == 0) {
                        meta.s_syn_hi_valid = 1; meta.s_syn_hi = hdr.tcp.seq;
                    }
                    if (meta.ack && meta.s_non_syn == 0 && meta.s_syn_lo_valid == 0) {
                        meta.s_syn_lo_valid = 1; meta.s_syn_lo = hdr.tcp.ack_number - 1;
                    }
                }
            } else { meta.s_non_syn = 1; }
            if (meta.fin) {
                if (meta.source_hi == 0) { meta.s_fin_lo = 1; }
                else { meta.s_fin_hi = 1; }
            }
            /* A reset can be packet 8. Close AFTER updating the feature prefix. */
            if (meta.rst) { meta.s_active = 0; }
        }
    }
    action emit_report() {
        hdr.report.setValid();
        hdr.report.magic = REPORT_MAGIC; hdr.report.version = 1;
        hdr.report.status = meta.status; hdr.report.reason = meta.reason;
        hdr.report.count = 0; hdr.report.packet_id = 0;
        hdr.report.observed_us = meta.observed; hdr.report.effective_us = 0;
        hdr.report.slot = 0; hdr.report.instance = 0; hdr.report.ip_proto = 0;
        hdr.report.src_addr = 0; hdr.report.dst_addr = 0;
        hdr.report.src_port = 0; hdr.report.dst_port = 0;
        hdr.report.size_min = 0; hdr.report.size_max = 0; hdr.report.size_sum = 0;
        hdr.report.iat_min = 0; hdr.report.iat_max = 0; hdr.report.iat_sum = 0;
        hdr.report.reverse_count = 0; hdr.report.direction_changes = 0;
        hdr.report.direction = 0; hdr.report.active = 0;
        hdr.report.flags = 0; hdr.report.reserved = 0;
        if (hdr.ip.isValid()) {
            hdr.report.packet_id = (bit<32>) hdr.ip.identification;
            hdr.report.ip_proto = hdr.ip.protocol;
            hdr.report.src_addr = hdr.ip.src; hdr.report.dst_addr = hdr.ip.dst;
        }
        if (hdr.test.isValid()) { hdr.report.packet_id = hdr.test.packet_id; }
        if (meta.eligible) {
            hdr.report.src_port = meta.sport; hdr.report.dst_port = meta.dport;
            hdr.report.slot = meta.slot;
            if (!meta.collision) {
                hdr.report.count = (bit<8>) meta.s_count;
                hdr.report.effective_us = meta.effective;
                hdr.report.instance = meta.s_instance;
                hdr.report.size_min = meta.s_size_min; hdr.report.size_max = meta.s_size_max;
                hdr.report.size_sum = meta.s_size_sum;
                hdr.report.iat_min = meta.s_iat_min; hdr.report.iat_max = meta.s_iat_max;
                hdr.report.iat_sum = meta.s_iat_sum;
                hdr.report.reverse_count = (bit<8>) meta.s_reverse;
                hdr.report.direction_changes = (bit<8>) meta.s_changes;
                hdr.report.direction = (bit<8>) meta.direction;
                hdr.report.active = (bit<8>) meta.s_active; hdr.report.flags = meta.boundary;
            }
        }
        hdr.ethernet.ether_type = 0x88b6;
    }

    apply {
        meta.status = 0; meta.reason = 1; meta.boundary = 0;
        meta.eligible = false; meta.collision = false;
        meta.fresh = false; meta.reset_instance = false;
        meta.syn = false; meta.ack = false; meta.fin = false; meta.rst = false;
        meta.bare_syn = false; meta.observed = sm.ingress_global_timestamp;
#if TEST_TIMESTAMPS
        if (hdr.test.isValid()) { meta.observed = hdr.test.timestamp_us; }
#endif
        if (sm.parser_error != error.NoError) { meta.reason = 2; }
        else if (hdr.test.isValid() && hdr.test.magic != TEST_MAGIC) { meta.reason = 7; }
        else if (hdr.ip.isValid()) {
            if (hdr.ip.frag_offset != 0 || (hdr.ip.flags & 1) != 0) { meta.reason = 4; }
            else if ((bit<32>) hdr.ip.total_len + meta.l2_bytes > sm.packet_length) { meta.reason = 2; }
            else if (hdr.tcp.isValid() || hdr.udp.isValid()) {
                meta.reason = 0;
                if (hdr.tcp.isValid()) {
                    meta.sport = hdr.tcp.src; meta.dport = hdr.tcp.dst;
                    if ((bit<32>) hdr.ip.total_len < meta.ip_bytes + meta.tcp_bytes) { meta.reason = 3; }
                    meta.syn = (hdr.tcp.flags & 2) != 0;
                    meta.ack = (hdr.tcp.flags & 16) != 0;
                    meta.fin = (hdr.tcp.flags & 1) != 0;
                    meta.rst = (hdr.tcp.flags & 4) != 0;
                    meta.bare_syn = meta.syn && !meta.ack && !meta.fin && !meta.rst;
                } else {
                    meta.sport = hdr.udp.src; meta.dport = hdr.udp.dst;
                    if ((bit<32>) hdr.ip.total_len < meta.ip_bytes + 8) { meta.reason = 3; }
                }
                if (meta.reason == 0) {
                    if (meta.sport == 53 || meta.dport == 53) { meta.reason = 5; }
                    else if (hdr.ip.src == hdr.ip.dst && meta.sport == meta.dport) { meta.reason = 6; }
                    else { meta.eligible = true; meta.status = 1; }
                }
            }
        }
        if (meta.eligible) {
            meta.source_hi = 0;
            if (hdr.ip.src > hdr.ip.dst || (hdr.ip.src == hdr.ip.dst && meta.sport > meta.dport)) {
                meta.source_hi = 1;
                meta.lo_ip = hdr.ip.dst; meta.lo_port = meta.dport;
                meta.hi_ip = hdr.ip.src; meta.hi_port = meta.sport;
            } else {
                meta.lo_ip = hdr.ip.src; meta.lo_port = meta.sport;
                meta.hi_ip = hdr.ip.dst; meta.hi_port = meta.dport;
            }
            hash(meta.slot, HashAlgorithm.crc32, (bit<32>) 0,
                 {hdr.ip.protocol, meta.lo_ip, meta.lo_port, meta.hi_ip, meta.hi_port}, (bit<32>) FLOW_SLOTS);
            @atomic {
                flow_state.read(meta.packed, meta.slot);
                unpack_state();
                meta.collision = meta.s_seen == 1 &&
                    (meta.s_protocol != hdr.ip.protocol || meta.s_lo_ip != meta.lo_ip ||
                     meta.s_lo_port != meta.lo_port || meta.s_hi_ip != meta.hi_ip ||
                     meta.s_hi_port != meta.hi_port);
                if (meta.collision) { meta.status = 3; }
                else {
                    meta.effective = meta.observed;
                    meta.gap = 0;
                    if (meta.s_seen == 0) {
                        meta.s_seen = 1; meta.s_protocol = hdr.ip.protocol;
                        meta.s_lo_ip = meta.lo_ip; meta.s_lo_port = meta.lo_port;
                        meta.s_hi_ip = meta.hi_ip; meta.s_hi_port = meta.hi_port;
                        meta.boundary = 1; meta.reset_instance = true;
                    } else {
                        if (meta.effective < meta.s_last) { meta.effective = meta.s_last; }
                        meta.gap = meta.effective - meta.s_last;
                        if (meta.gap >= IDLE_US) {
                            meta.boundary = 2; meta.reset_instance = true;
                        } else if (meta.s_active == 0) {
                            meta.boundary = 4; meta.reset_instance = true;
                        } else if (meta.bare_syn) {
                            meta.fresh = true;
                            if (meta.s_fin_lo == 1 && meta.s_fin_hi == 1) { meta.fresh = true; }
                            else if (meta.source_hi == 0 && meta.s_syn_lo_valid == 1 && meta.s_syn_lo == hdr.tcp.seq) {
                                meta.fresh = false;
                            } else if (meta.source_hi == 1 && meta.s_syn_hi_valid == 1 && meta.s_syn_hi == hdr.tcp.seq) {
                                meta.fresh = false;
                            } else if (meta.s_non_syn == 0 &&
                                ((meta.source_hi == 0 && meta.s_syn_lo_valid == 0 && meta.s_syn_hi_valid == 1) ||
                                 (meta.source_hi == 1 && meta.s_syn_hi_valid == 0 && meta.s_syn_lo_valid == 1))) {
                                meta.fresh = false;
                            }
                            if (meta.fresh) { meta.boundary = 3; meta.reset_instance = true; }
                        }
                    }
                    if (meta.reset_instance) { begin_instance(); }
                    meta.direction = meta.source_hi ^ meta.s_forward_hi;
                    update_prefix();
                    observe_tcp();
                    /* Refresh on EVERY eligible packet, including after packet 8. */
                    meta.s_last = meta.effective;
                    pack_state();
                    flow_state.write(meta.slot, meta.packed);
                }
            }
        }
#if DEBUG_REPORT
        emit_report();
        sm.egress_spec = 2;
#else
        if (sm.ingress_port == 1) { sm.egress_spec = 2; }
        else if (sm.ingress_port == 2) { sm.egress_spec = 1; }
        else { mark_to_drop(sm); }
#endif
        if (!hdr.ethernet.isValid()) { mark_to_drop(sm); }
    }
}
control FeatureEgress(inout headers_t hdr, inout metadata_t meta,
               inout standard_metadata_t sm) { apply { } }
control FeatureCompute(inout headers_t hdr, inout metadata_t meta) { apply { } }
control FeatureDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
#if DEBUG_REPORT
        packet.emit(hdr.report);
#else
        packet.emit(hdr.test);
#endif
        packet.emit(hdr.ip); packet.emit(hdr.ip_options);
        packet.emit(hdr.tcp); packet.emit(hdr.tcp_options); packet.emit(hdr.udp);
    }
}
V1Switch(FeatureParser(), FeatureVerify(), FeatureIngress(), FeatureEgress(), FeatureCompute(), FeatureDeparser()) main;
