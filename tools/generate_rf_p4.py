#!/usr/bin/env python3
"""Generate the selected integer Random Forests as standalone BMv2 P4 programs.

This generator does not train models or change the feature-only checkpoint.
The integrated variant performs inference once, on eligible packet eight. The
vector variant is explicitly a test harness: input feature vectors bypass flow
extraction so exported tree predicates, leaf scores and argmax can be checked.
Both variants contain exactly the same RFInfer control.
"""
import hashlib

from prepare_rf_deployment import DOMAINS, FEATURES, validate_export

BASE_SOURCE_SHA256 = '6624ddf3f70acd376ccb02454800daeb9fcb30c7f59a6a63e326e0e88453ba4a'
RF_REPORT_BYTES = 52
RF_VECTOR_BYTES = 40


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _replace_once(source, anchor, replacement):
    """Fail closed instead of silently modifying a different source revision."""
    _require(source.count(anchor) == 1, f'Expected exactly one integration anchor: {anchor!r}')
    return source.replace(anchor, replacement, 1)


def _types():
    fields = [f'    bit<32> f{i};' for i in range(8)]
    fields += [f'    bit<16> leaf{i};' for i in range(10)]
    fields += [f'    bit<32> score{i};' for i in range(6)]
    fields += ['    bit<8> prediction;']
    report = ['    bit<32> magic;', '    bit<8> version; bit<8> valid;',
              '    bit<8> model; bit<8> prediction;']
    report += [f'    bit<16> leaf{i};' for i in range(10)]
    report += [f'    bit<32> score{i};' for i in range(6)]
    return ('/* RF debug report: exactly 52 network-order bytes; invalid outputs are zero. */\n'
            'struct rf_meta_t {\n' + '\n'.join(fields) + '\n}\n'
            'header rf_report_t {\n' + '\n'.join(report) + '\n}\n')


def _branch_lines(export, tree_id, node_id, indent):
    """Keep native node IDs; collapse out-of-domain constant predicates safely."""
    node = export['trees'][tree_id]['nodes'][node_id]
    pad = ' ' * indent
    if node['kind'] == 'leaf':
        return [f'{pad}leaf_t{tree_id}_n{node_id}();']
    index, cut = node['feature_index'], node['cut']
    upper = DOMAINS[export['feature_order'][index]]['max']
    if cut == -1:
        return [f'{pad}/* Node {node_id}: always right within the frozen domain. */'] + \
            _branch_lines(export, tree_id, node['right'], indent)
    if cut == upper:
        return [f'{pad}/* Node {node_id}: always left within the frozen domain. */'] + \
            _branch_lines(export, tree_id, node['left'], indent)
    return ([f'{pad}if (rf.f{index} <= 32w{cut}) {{'] +
            _branch_lines(export, tree_id, node['left'], indent + 4) +
            [f'{pad}}} else {{'] +
            _branch_lines(export, tree_id, node['right'], indent + 4) + [f'{pad}}}'])


def _classifier(export):
    """All probability aggregation executes inside the generated P4 control."""
    lines = [
        '/* Ten trees; independently rounded Q24 probability leaves, not hard votes.',
        ' * Maximum per-class sum is 10 * 2^24 = 167772160 < 2^28.',
        ' * Integer cuts already preserve sklearn float32-input branch semantics.',
        ' * This static control-flow encoding needs no runtime table population.',
        ' */',
        'control RFInfer(inout rf_meta_t rf) {',
        '    bit<32> best_score;',
    ]
    for tree_id, tree in enumerate(export['trees']):
        for node_id, node in enumerate(tree['nodes']):
            if node['kind'] != 'leaf':
                continue
            lines += [f'    action leaf_t{tree_id}_n{node_id}() {{',
                      f'        rf.leaf{tree_id} = 16w{node_id};']
            lines += [f'        rf.score{i} = rf.score{i} + 32w{score};'
                      for i, score in enumerate(node['scores'])]
            lines += ['    }']
    lines += ['    apply {']
    lines += [f'        rf.score{i} = 32w0;' for i in range(6)]
    lines += [f'        rf.leaf{i} = 16w0;' for i in range(10)]
    for tree_id in range(10):
        lines += [f'        /* Tree {tree_id}, starting at native node 0. */']
        lines += _branch_lines(export, tree_id, 0, 8)
    lines += ['        rf.prediction = 8w0;', '        best_score = rf.score0;',
              '        /* Strict > while scanning upward keeps the lowest class index on ties. */']
    for i in range(1, 6):
        lines += [f'        if (rf.score{i} > best_score) {{',
                  f'            best_score = rf.score{i}; rf.prediction = 8w{i};', '        }']
    lines += ['    }', '}', '']
    return '\n'.join(lines)


def _report_control(export):
    model = 0 if export['feature_set'] == 'B' else 1
    lines = [
        'control RFMakeReport(inout rf_report_t report, in rf_meta_t rf, in bit<8> valid) {',
        '    apply {',
        '        report.setValid();',
        '        report.magic = 32w0x52464952; report.version = 8w1;',
        f'        report.model = 8w{model}; report.valid = valid;',
        '        report.prediction = 8w255;',
    ]
    lines += [f'        report.leaf{i} = 16w0;' for i in range(10)]
    lines += [f'        report.score{i} = 32w0;' for i in range(6)]
    lines += ['        if (valid == 8w1) {', '            report.prediction = rf.prediction;']
    lines += [f'            report.leaf{i} = rf.leaf{i};' for i in range(10)]
    lines += [f'            report.score{i} = rf.score{i};' for i in range(6)]
    lines += ['        }', '    }', '}', '']
    return '\n'.join(lines)


def _integrated(export, base_source, classifier):
    source = _replace_once(
        base_source,
        '/* Shared RF-B/RF-C feature extractor; inference is deliberately not present yet.\n',
        f'/* Generated RF-{export["feature_set"]} integration over the sealed shared feature extractor.\n')
    source = _replace_once(source, 'struct headers_t {\n', _types() + '\nstruct headers_t {\n')
    source = _replace_once(source, '    ethernet_t ethernet; test_t test; report_t report;\n',
                           '    ethernet_t ethernet; test_t test; report_t report; rf_report_t rf_report;\n')
    source = _replace_once(source, 'struct metadata_t {\n',
                           'struct metadata_t {\n    rf_meta_t rf;\n')
    source = _replace_once(source, 'control FeatureIngress(inout headers_t hdr, inout metadata_t meta,\n',
                           classifier + _report_control(export) + '\n' +
                           'control FeatureIngress(inout headers_t hdr, inout metadata_t meta,\n')
    source = _replace_once(source, '    register<bit<429>>(FLOW_SLOTS) flow_state;\n',
                           '    register<bit<429>>(FLOW_SLOTS) flow_state;\n'
                           '    RFInfer() rf_infer;\n'
                           '    RFMakeReport() rf_report;\n'
                           '    /* Observable one-shot decisions also retain inference in normal builds. */\n'
                           '    counter(6, CounterType.packets) rf_decisions;\n')
    feature_fields = ['s_size_min', 's_size_max', 's_size_sum', 's_iat_min',
                      's_iat_max', 's_iat_sum', 's_reverse', 's_changes']
    hook = ['        /* The complete prefix snapshot is classified exactly once, at eligible packet 8. */',
            '        if (meta.status == 2) {']
    hook += [f'            meta.rf.f{i} = (bit<32>) meta.{field};'
             for i, field in enumerate(feature_fields)]
    hook += ['            rf_infer.apply(meta.rf);',
             '            rf_decisions.count((bit<32>) meta.rf.prediction);',
             '        }', '#if DEBUG_REPORT', '        emit_report();',
             '        if (meta.status == 2) { rf_report.apply(hdr.rf_report, meta.rf, 8w1); }',
             '        else { rf_report.apply(hdr.rf_report, meta.rf, 8w0); }']
    source = _replace_once(source, '#if DEBUG_REPORT\n        emit_report();', '\n'.join(hook))
    source = _replace_once(source, '        packet.emit(hdr.report);\n',
                           '        packet.emit(hdr.report);\n        packet.emit(hdr.rf_report);\n')
    return source


def _vectors(export, classifier):
    upper = [DOMAINS[name]['max'] for name in FEATURES['C']]
    vector_fields = '\n'.join(f'    bit<32> f{i};' for i in range(8))
    copy_fields = '\n'.join(f'            meta.rf.f{i} = hdr.vector.f{i};' for i in range(8))
    zero_fields = '\n'.join(f'            hdr.vector.f{i} = 32w0;' for i in range(8))
    domain_checks = ' &&\n            '.join(f'hdr.vector.f{i} <= 32w{bound}'
                                             for i, bound in enumerate(upper))
    return f'''/* GENERATED TEST-ONLY vector inference harness for RF-{export['feature_set']}.
 * This bypasses feature extraction; it is not a live traffic classifier.
 * Input: Ethernet 0x88b7 + 40-byte RFVT vector; output: 0x88b8 + same vector
 * and 52-byte RFIR report. Nonphysical but in-domain diagnostic vectors are
 * deliberate. Both B and C validate all eight independent feature bounds.
 */
#include <core.p4>
#include <v1model.p4>

{_types()}
header ethernet_t {{ bit<48> dst; bit<48> src; bit<16> ether_type; }}
header rf_vector_t {{
    bit<32> magic; bit<32> packet_id;
{vector_fields}
}}
struct headers_t {{ ethernet_t ethernet; rf_vector_t vector; rf_report_t rf_report; }}
struct metadata_t {{ rf_meta_t rf; bit<8> valid; }}

parser RFVectorParser(packet_in packet, out headers_t hdr,
                      inout metadata_t meta, inout standard_metadata_t sm) {{
    state start {{
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {{ 0x88b7: parse_vector; default: accept; }}
    }}
    state parse_vector {{ packet.extract(hdr.vector); transition accept; }}
}}
control RFVectorVerify(inout headers_t hdr, inout metadata_t meta) {{ apply {{ }} }}
{classifier}
{_report_control(export)}
control RFVectorIngress(inout headers_t hdr, inout metadata_t meta,
                        inout standard_metadata_t sm) {{
    RFInfer() rf_infer;
    RFMakeReport() rf_report;
    apply {{
        meta.valid = 8w0;
        if (sm.parser_error == error.NoError && hdr.vector.isValid() &&
            hdr.ethernet.ether_type == 16w0x88b7 && hdr.vector.magic == 32w0x52465654 &&
            {domain_checks}) {{
{copy_fields}
            rf_infer.apply(meta.rf);
            meta.valid = 8w1;
        }}
        /* Echo complete parsed vectors even on domain/magic rejection. A
         * missing/truncated vector has no reliable fields and is reported as zero.
         */
        if (!hdr.vector.isValid()) {{
            hdr.vector.setValid(); hdr.vector.magic = 32w0; hdr.vector.packet_id = 32w0;
{zero_fields}
        }}
        rf_report.apply(hdr.rf_report, meta.rf, meta.valid);
        hdr.ethernet.ether_type = 16w0x88b8;
        sm.egress_spec = 9w2;
        if (!hdr.ethernet.isValid()) {{ mark_to_drop(sm); }}
    }}
}}
control RFVectorEgress(inout headers_t hdr, inout metadata_t meta,
                       inout standard_metadata_t sm) {{ apply {{ }} }}
control RFVectorCompute(inout headers_t hdr, inout metadata_t meta) {{ apply {{ }} }}
control RFVectorDeparser(packet_out packet, in headers_t hdr) {{
    apply {{ packet.emit(hdr.ethernet); packet.emit(hdr.vector); packet.emit(hdr.rf_report); }}
}}
V1Switch(RFVectorParser(), RFVectorVerify(), RFVectorIngress(), RFVectorEgress(),
         RFVectorCompute(), RFVectorDeparser()) main;
'''


def generate_sources(export, base_source):
    """Return integrated/vectors P4 strings after validating the sealed inputs.

    CRLF-to-LF normalization is allowed for a text read across Windows/WSL; any
    other checkpoint change requires an explicit review and generator update.
    The caller is responsible for deployment artifact hash verification and for
    writing new files without replacing the original feature-only source.
    """
    validate_export(export)
    _require(isinstance(base_source, str), 'Feature checkpoint source must be text')
    base_source = base_source.replace('\r\n', '\n')
    _require(hashlib.sha256(base_source.encode('utf-8')).hexdigest() == BASE_SOURCE_SHA256,
             'Feature-only checkpoint differs from the reviewed sealed source')
    classifier = _classifier(export)
    return {'integrated': _integrated(export, base_source, classifier),
            'vectors': _vectors(export, classifier)}
