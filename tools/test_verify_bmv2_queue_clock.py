"""Queue receipt contract tests; no compiler, traffic, root or live switch."""
import copy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import verify_bmv2_queue_clock as contract


def save_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def artifact(path):
    return {'path': str(path.resolve()), 'sha256': contract.sha256_file(path)}


def original_header():
    return ('// fixture prefix\nclass QueueingLogicRL {\n' + contract.OLD_RL +
            '\n};\nclass QueueingLogicPriRL {\n' + contract.OLD_PRI + '\n};\n')


def upgraded_header():
    return original_header().replace(contract.OLD_RL, contract.NEW_RL).replace(
        contract.OLD_PRI, contract.NEW_PRI)


def queue_signature(operation, suffix=''):
    return ('bm::QueueingLogicPriRL<std::unique_ptr<bm::Packet, '
            'std::default_delete<bm::Packet> >, EgressThreadMapper>::' +
            operation + '(unsigned long, bm::Packet*)' + suffix)


def emitted_function(address, operation, clocks=('steady',), suffix=''):
    body = ''.join('  {:x}:\tcall 1000 <std::chrono::_V2::{}_clock::now()@plt>\n'.format(
        address + index * 5, clock) for index, clock in enumerate(clocks))
    body += '  {:x}:\tret'.format(address + len(clocks) * 5)
    return '{:x} <{}>:\n{}\n\n'.format(address, queue_signature(operation, suffix), body)


def valid_disassembly():
    return emitted_function(0x100, 'push_front') + emitted_function(0x200, 'pop_back')


class ApprovedUpgradeTests(unittest.TestCase):
    def test_only_the_two_approved_clock_blocks_pass(self):
        contract.approved_upgrade(original_header(), upgraded_header())

    def test_any_other_header_change_is_rejected(self):
        before, after = original_header(), upgraded_header()
        for changed in (after + '// additional change\n', after.replace('fixture prefix', 'new prefix'),
                        after.replace(contract.NEW_RL, contract.OLD_RL),
                        after.replace(contract.NEW_PRI, contract.OLD_PRI)):
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    contract.approved_upgrade(before, changed)

    def test_missing_or_duplicate_original_clock_blocks_are_rejected(self):
        before = original_header()
        for changed in (before.replace(contract.OLD_RL, ''), before.replace(contract.OLD_PRI, ''),
                        before + contract.OLD_RL, before + contract.OLD_PRI):
            with self.subTest(changed=changed):
                after = changed.replace(contract.OLD_RL, contract.NEW_RL).replace(
                    contract.OLD_PRI, contract.NEW_PRI)
                with self.assertRaises(ValueError):
                    contract.approved_upgrade(changed, after)


class CompiledQueueClockTests(unittest.TestCase):
    def test_actual_packet_prirl_enqueue_and_dequeue_use_steady_clock(self):
        result = contract.compiled_queue_functions(valid_disassembly())
        self.assertEqual(set(result), {'push_front', 'pop_back'})
        for operation, item in result.items():
            self.assertEqual(item['signature'], queue_signature(operation))
            self.assertIn('steady_clock::now()', item['disassembly'])

    def test_multiple_steady_calls_in_a_function_pass(self):
        disassembly = (emitted_function(0x100, 'push_front', ('steady', 'steady')) +
                       emitted_function(0x200, 'pop_back', ('steady', 'steady')))
        self.assertEqual(set(contract.compiled_queue_functions(disassembly)),
                         {'push_front', 'pop_back'})

    def test_stale_system_clock_operation_is_rejected(self):
        for operation in ('push_front', 'pop_back'):
            disassembly = ''.join(emitted_function(address, name,
                                     ('system',) if name == operation else ('steady',))
                                  for address, name in ((0x100, 'push_front'), (0x200, 'pop_back')))
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                contract.compiled_queue_functions(disassembly)

    def test_mixed_steady_and_system_calls_are_rejected(self):
        for operation in ('push_front', 'pop_back'):
            disassembly = valid_disassembly() + emitted_function(
                0x300, operation, ('steady', 'system'), ' [clone .isra.0]')
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                contract.compiled_queue_functions(disassembly)

    def test_stale_overload_cannot_hide_behind_another_steady_overload(self):
        for operation in ('push_front', 'pop_back'):
            disassembly = valid_disassembly() + emitted_function(
                0x300, operation, ('system',), ' [clone .isra.0]')
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                contract.compiled_queue_functions(disassembly)

    def test_each_operation_must_have_a_compiled_clock_call(self):
        for operation in ('push_front', 'pop_back'):
            other = 'pop_back' if operation == 'push_front' else 'push_front'
            for disassembly in (emitted_function(0x100, other),
                                emitted_function(0x100, other) + emitted_function(0x200, operation, ())):
                with self.subTest(operation=operation, disassembly=disassembly):
                    with self.assertRaises(ValueError):
                        contract.compiled_queue_functions(disassembly)

    def test_unrelated_queue_or_packet_instantiation_does_not_satisfy_contract(self):
        for changed in (valid_disassembly().replace('QueueingLogicPriRL', 'QueueingLogicRL'),
                        valid_disassembly().replace('bm::Packet,', 'OtherPacket,')):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                contract.compiled_queue_functions(changed)


class QueueReceiptTests(unittest.TestCase):
    def fixture(self, root):
        build = root / 'behavioral-model'
        target = build / 'targets/simple_switch'
        (target / '.libs').mkdir(parents=True)
        queue = build / 'include/bm/bm_sim/queueing.h'
        queue.parent.mkdir(parents=True)
        switch = target / 'simple_switch'
        paths = {'wrapper': switch, 'elf': target / '.libs/simple_switch',
                 'header': target / 'simple_switch.h', 'source': target / 'simple_switch.cpp',
                 'queue_header': queue}
        for name, path in paths.items():
            path.write_text(upgraded_header() if name == 'queue_header' else 'current ' + name,
                            encoding='utf-8')
        backups = root / 'before'
        backups.mkdir()
        old_elf = backups / 'simple_switch.elf'
        old_elf.write_text('previous elf', encoding='utf-8')
        old_queue = backups / 'queueing.h'
        old_queue.write_text(original_header(), encoding='utf-8')
        current_artifacts = {name: artifact(path) for name, path in paths.items()}
        previous = {'schema': 'bmv2-steady-clock-v1', 'compiled_clock_verified': True,
                    'elapsed_clock': 'std::chrono::steady_clock',
                    'epoch_clock': 'std::chrono::system_clock', 'switch': str(switch),
                    'artifacts': {name: item for name, item in current_artifacts.items()
                                  if name != 'queue_header'}}
        previous['artifacts'] = copy.deepcopy(previous['artifacts'])
        previous['artifacts']['elf']['sha256'] = contract.sha256_file(old_elf)
        previous_path = backups / 'clock_receipt.json'
        save_json(previous_path, previous)
        current_v1 = dict(previous, artifacts={name: item for name, item in current_artifacts.items()
                                              if name != 'queue_header'})
        compatible_path = root / 'feature_clock_receipt.json'
        save_json(compatible_path, current_v1)
        evidence_paths = {'previous_receipt': previous_path, 'previous_elf': old_elf,
                          'previous_queue_header': old_queue}
        for name in ('queue_test_source', 'queue_test_executable', 'queue_test_log', 'verifier_source'):
            path = root / name
            path.write_text('sealed ' + name, encoding='utf-8')
            evidence_paths[name] = path
        receipt = {'schema': contract.SCHEMA, 'compiled_clock_verified': True,
                   'compiled_queue_clock_verified': True,
                   'elapsed_clock': 'std::chrono::steady_clock',
                   'queue_clock': 'std::chrono::steady_clock',
                   'epoch_clock': 'std::chrono::system_clock', 'switch': str(switch),
                   'artifacts': current_artifacts,
                   'upgrade_evidence': {name: artifact(path) for name, path in evidence_paths.items()},
                   'previous_feature_clock_receipt': dict(previous, receipt_path=str(previous_path),
                                                          receipt_sha256=contract.sha256_file(previous_path)),
                   'feature_clock_receipt': artifact(compatible_path),
                   'old_native_results_reinterpreted_as_new_binary': False}
        receipt_path = root / 'queue_clock_receipt.json'
        save_json(receipt_path, receipt)
        return switch, paths, evidence_paths, receipt_path, receipt

    def test_valid_receipt_preserves_distinct_old_and_current_elf(self):
        with TemporaryDirectory() as temp:
            switch, _, _, path, receipt = self.fixture(Path(temp))
            result = contract.verify_receipt(path, switch)
            self.assertEqual(result['receipt_sha256'], contract.sha256_file(path))
            self.assertEqual(result['receipt_path'], str(path.resolve()))
            self.assertNotEqual(receipt['artifacts']['elf']['sha256'],
                                receipt['previous_feature_clock_receipt']['artifacts']['elf']['sha256'])

    def test_every_current_artifact_is_hash_checked(self):
        for name in ('wrapper', 'elf', 'header', 'source', 'queue_header'):
            with self.subTest(name=name), TemporaryDirectory() as temp:
                switch, paths, _, path, _ = self.fixture(Path(temp))
                paths[name].write_text('changed after attestation', encoding='utf-8')
                with self.assertRaises(ValueError):
                    contract.verify_receipt(path, switch)

    def test_every_upgrade_backup_or_test_evidence_is_hash_checked(self):
        for name in ('previous_receipt', 'previous_elf', 'previous_queue_header', 'queue_test_source',
                     'queue_test_executable', 'queue_test_log', 'verifier_source'):
            with self.subTest(name=name), TemporaryDirectory() as temp:
                switch, _, evidence, path, _ = self.fixture(Path(temp))
                evidence[name].write_text('changed evidence', encoding='utf-8')
                with self.assertRaises(ValueError):
                    contract.verify_receipt(path, switch)

    def test_current_artifact_cannot_point_to_an_identical_backup(self):
        with TemporaryDirectory() as temp:
            switch, paths, _, path, receipt = self.fixture(Path(temp))
            impostor = Path(temp) / 'different_elf'
            impostor.write_bytes(paths['elf'].read_bytes())
            receipt['artifacts']['elf'] = artifact(impostor)
            save_json(path, receipt)
            with self.assertRaises(ValueError):
                contract.verify_receipt(path, switch)

    def test_missing_artifact_or_wrong_switch_is_rejected(self):
        for change in ('missing_queue', 'different_switch'):
            with self.subTest(change=change), TemporaryDirectory() as temp:
                switch, _, _, path, receipt = self.fixture(Path(temp))
                if change == 'missing_queue':
                    del receipt['artifacts']['queue_header']
                else:
                    receipt['switch'] = str(Path(temp) / 'other_switch')
                save_json(path, receipt)
                with self.assertRaises(ValueError):
                    contract.verify_receipt(path, switch)

    def test_wrong_schema_or_false_clock_flags_are_rejected(self):
        for field, value in (('schema', 'bmv2-steady-clock-v1'), ('compiled_clock_verified', False),
                             ('compiled_queue_clock_verified', False),
                             ('elapsed_clock', 'std::chrono::system_clock'),
                             ('queue_clock', 'std::chrono::system_clock')):
            with self.subTest(field=field), TemporaryDirectory() as temp:
                switch, _, _, path, receipt = self.fixture(Path(temp))
                receipt[field] = value
                save_json(path, receipt)
                with self.assertRaises(ValueError):
                    contract.verify_receipt(path, switch)

    def test_resealed_previous_elf_still_must_match_historical_receipt(self):
        with TemporaryDirectory() as temp:
            switch, _, evidence, path, receipt = self.fixture(Path(temp))
            evidence['previous_elf'].write_text('another old elf', encoding='utf-8')
            receipt['upgrade_evidence']['previous_elf'] = artifact(evidence['previous_elf'])
            save_json(path, receipt)
            with self.assertRaises(ValueError):
                contract.verify_receipt(path, switch)

    def test_resealed_previous_header_still_requires_only_approved_diff(self):
        with TemporaryDirectory() as temp:
            switch, _, evidence, path, receipt = self.fixture(Path(temp))
            evidence['previous_queue_header'].write_text(original_header() + '// extra\n', encoding='utf-8')
            receipt['upgrade_evidence']['previous_queue_header'] = artifact(evidence['previous_queue_header'])
            save_json(path, receipt)
            with self.assertRaises(ValueError):
                contract.verify_receipt(path, switch)

    def test_embedded_previous_provenance_and_hash_cannot_change(self):
        for changed_field in ('elapsed_clock', 'receipt_sha256'):
            with self.subTest(changed_field=changed_field), TemporaryDirectory() as temp:
                switch, _, _, path, receipt = self.fixture(Path(temp))
                receipt['previous_feature_clock_receipt'][changed_field] = 'changed'
                save_json(path, receipt)
                with self.assertRaises(ValueError):
                    contract.verify_receipt(path, switch)

    def test_compatible_feature_receipt_cannot_change(self):
        with TemporaryDirectory() as temp:
            switch, _, _, path, receipt = self.fixture(Path(temp))
            compatible = Path(receipt['feature_clock_receipt']['path'])
            compatible.write_text(compatible.read_text(encoding='utf-8') + '\n', encoding='utf-8')
            with self.assertRaises(ValueError):
                contract.verify_receipt(path, switch)


if __name__ == '__main__':
    unittest.main()
