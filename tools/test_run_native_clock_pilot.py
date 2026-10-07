"""Native-clock runner fault injection; no interfaces or real switches used."""
import copy
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import native_prefix as prefix
from pcap_replay_io import iter_capture
import rf_parity_probes as probes
import run_native_clock_pilot as runner
import test_native_prefix as fixtures


def diagnostic_export(feature_set):
    """A diagnostic-only forest, never a substitute for the fitted RF pair."""
    export = probes.synthetic_export()
    if feature_set == "C":
        export["feature_set"] = "C"
        export["feature_order"] = list(runner.reference.FEATURES["C"])
        export["domains"] = copy.deepcopy({name: runner.reference.DOMAINS[name]
                                            for name in export["feature_order"]})
    runner.reference.validate_export(export)
    return export


def make_bundle_and_frames(feature_set="B", times=None):
    _, _, raw_records = fixtures.make_fixture()
    capture = {"capture_id": "fixture/cap.pcap", "filename": "cap.pcap",
               "sha256": "0" * 64, "initial_class": "VOIP"}
    original_packets = [prefix.decode_raw_packet(row.data, row.number, row.timestamp_ns)[0]
                        for row in raw_records]
    original_b, original_c = prefix.feature_statistics(original_packets)
    origin = raw_records[0].timestamp_ns // 1000
    relative_us = [row.timestamp_ns // 1000 - origin for row in raw_records]
    bundle = {"capture": capture, "record": {}, "features_B": original_b,
              "features_C": original_c, "relative_us": relative_us,
              "packets": [{"original_frame": row.number, "raw_ip_hex": row.data.hex()}
                          for row in raw_records]}
    exports = {s: diagnostic_export(s) for s in "BC"}
    bundle["original_predictions"] = {s: runner.predict(exports[s], original_c) for s in "BC"}
    # Deliberately different from capture timings; correctness uses actual time.
    times = ([300000, 300200, 301500, 301510, 301800, 302999, 303100, 303110]
             if times is None else times)
    oracle = runner.replay.ReplayOracle(capture, {4: io.StringIO(), 8: io.StringIO()}, io.StringIO())
    owners, frames = {}, []
    for saved, observed_us in zip(bundle["packets"], times):
        raw = bytes.fromhex(saved["raw_ip_hex"])
        packet, tcp = prefix.decode_raw_packet(raw, saved["original_frame"], observed_us * 1000)
        fields, decision, *_ = runner.replay.expectation(oracle, packet, tcp, owners, 0)
        fields.update(magic=0x45544352, version=1, reserved=0, observed_us=observed_us,
                      packet_id=struct.unpack_from("!H", raw, 4)[0])
        feature_header = b"".join(fields[name].to_bytes(width, "big")
                                   for name, width in runner.helpers.FIELDS)
        prediction = {"leaves": [0] * 10, "scores": [0] * 6, "prediction": 255}
        if decision:
            bundle["record"] = {"record_id": decision["record_id"], "partition": "test", "n": 8}
            prediction = runner.predict(exports[feature_set], decision["features_C"])
        rf_header = struct.pack("!IBBBB10H6I", runner.integration.RF_MAGIC, 1,
                                int(decision is not None), "BC".index(feature_set), prediction["prediction"],
                                *prediction["leaves"], *prediction["scores"])
        frames.append(bytes.fromhex("02000000000202000000000188b6") + feature_header + rf_header + raw)
    oracle.finish()
    return bundle, exports[feature_set], frames


def mutate_feature(frame, name, value):
    raw = bytearray(frame)
    position = 14
    for field, length in runner.helpers.FIELDS:
        if field == name:
            raw[position:position + length] = value.to_bytes(length, "big")
            return bytes(raw)
        position += length
    raise AssertionError(f"Unknown feature field: {name}")


class NativeComparisonTests(unittest.TestCase):
    def test_both_models_use_native_clock_not_original_timing(self):
        for s in "BC":
            with self.subTest(model=s):
                bundle, export, frames = make_bundle_and_frames(s)
                result = runner.compare_native(bundle, export, frames)
                self.assertTrue(result["passed"])
                self.assertTrue(result["parity_passed"])
                self.assertTrue(result["clock_quality"]["clean"])
                self.assertEqual(result["clock_quality"]["raw_backward_steps"], 0)
                self.assertEqual(result["decisions"], 1)
                self.assertEqual(result["timing"]["native_features_C"]["iat_sum"], 3110)
                self.assertEqual(result["timing"]["original_features_C"]["iat_sum"], 181390)
                self.assertNotEqual(result["timing"]["native_iats_us"], result["timing"]["original_iats_us"])

    def test_real_backward_clock_retains_clamped_parity_but_pilot_fails(self):
        times = [300000, 300200, 301500, 301400, 301450, 302999, 303100, 303110]
        for model in "BC":
            with self.subTest(model=model):
                bundle, export, frames = make_bundle_and_frames(model, times)
                result = runner.compare_native(bundle, export, frames)
                self.assertTrue(result["parity_passed"])
                self.assertFalse(result["passed"])
                self.assertEqual(result["decisions"], 1)
                self.assertEqual(len(result["packet_checks"]), 8)
                quality = result["clock_quality"]
                self.assertFalse(quality["clean"])
                self.assertEqual(quality["raw_backward_steps"], 1)
                self.assertEqual(quality["max_backward_step_us"], 100)
                self.assertEqual(quality["timestamp_adjustments"], 2)
                self.assertEqual(quality["events"][0]["position"], 4)
                self.assertEqual(quality["events"][0]["previous_observed_us"], 301500)
                self.assertEqual(quality["events"][0]["observed_us"], 301400)
                self.assertEqual(result["timing"]["native_iats_us"],
                                 [200, 1300, -100, 50, 1549, 101, 10])
                self.assertEqual(result["timing"]["native_features_C"]["iat_min"], 0)
                self.assertEqual(result["packet_checks"][3]["expected_fields"]["effective_us"], 301500)
                self.assertEqual(result["packet_checks"][4]["expected_fields"]["effective_us"], 301500)

    def test_backward_clock_still_rejects_corrupt_clamped_state(self):
        times = [300000, 300200, 301500, 301400, 301450, 302999, 303100, 303110]
        bundle, export, frames = make_bundle_and_frames(times=times)
        for field in ("effective_us", "iat_min", "iat_sum"):
            with self.subTest(field=field):
                corrupt = frames.copy()
                value = runner.helpers.decode_report(corrupt[4])[field]
                corrupt[4] = mutate_feature(corrupt[4], field, value + 1)
                with self.assertRaisesRegex(ValueError, field):
                    runner.compare_native(bundle, export, corrupt)

    def test_repeated_identical_ip_ids_and_packet_bodies_are_allowed(self):
        bundle, export, frames = make_bundle_and_frames()
        self.assertEqual({row["feature_report"]["packet_id"]
                          for row in runner.compare_native(bundle, export, frames)["packet_checks"]}, {0})
        self.assertEqual(bundle["packets"][-1]["raw_ip_hex"], bundle["packets"][-2]["raw_ip_hex"])

    def test_oracle_does_not_trust_reported_feature_or_effective_time(self):
        bundle, export, frames = make_bundle_and_frames()
        for field in ("size_min", "size_sum", "iat_min", "iat_sum", "reverse_count",
                      "direction_changes", "effective_us", "direction", "instance", "packet_id"):
            corrupt = frames.copy()
            old = runner.helpers.decode_report(corrupt[-1])[field]
            corrupt[-1] = mutate_feature(corrupt[-1], field, old + 1)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                runner.compare_native(bundle, export, corrupt)

    def test_rf_intermediate_prediction_and_model_mismatches_fail(self):
        bundle, export, frames = make_bundle_and_frames()
        for offset, message in ((85 + 9, "leaf ID"), (85 + 31, "score sum"),
                                (85 + 7, "argmax"), (85 + 6, "model identifier")):
            corrupt = frames.copy()
            changed = bytearray(corrupt[-1])
            changed[offset] ^= 1
            corrupt[-1] = bytes(changed)
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, message):
                runner.compare_native(bundle, export, corrupt)

    def test_original_bytes_are_verified_before_feature_comparison(self):
        bundle, export, frames = make_bundle_and_frames()
        corrupt = frames.copy()
        changed = bytearray(corrupt[3])
        changed[runner.BODY_OFFSET + 30] ^= 1
        corrupt[3] = bytes(changed)
        with self.assertRaisesRegex(ValueError, "IP bytes changed"):
            runner.compare_native(bundle, export, corrupt)

    def test_early_decision_and_missing_decision_fail(self):
        bundle, export, frames = make_bundle_and_frames()
        for position, valid in ((0, 1), (7, 0)):
            corrupt = frames.copy()
            changed = bytearray(corrupt[position])
            changed[85 + 5] = valid
            corrupt[position] = bytes(changed)
            with self.subTest(position=position), self.assertRaises(ValueError):
                runner.compare_native(bundle, export, corrupt)

    def test_bad_clock_or_missing_reordered_reports_cannot_pass(self):
        bundle, export, frames = make_bundle_and_frames()
        cases = [frames[:-1], frames + [frames[-1]], frames[::-1],
                 [mutate_feature(frame, "observed_us", 0) for frame in frames],
                 [mutate_feature(frame, "observed_us", 200) for frame in frames]]
        for corrupt in cases:
            with self.assertRaises(ValueError):
                runner.compare_native(bundle, export, corrupt)


class FakeCommands:
    """Realistic ip -d -j peer-name schema; host demo links must stay untouched."""
    def __init__(self):
        self.state = {"p1_sw1": {"ifname": "p1_sw1", "ifindex": 1, "ifalias": "existing-user-link",
                                 "link": "p1_host1", "linkinfo": {"info_kind": "veth"}},
                      "p1_host1": {"ifname": "p1_host1", "ifindex": 2, "link": "p1_sw1",
                                   "linkinfo": {"info_kind": "veth"}}}
        self.calls, self.deletions, self.next_index = [], [], 100
        self.fail_sysctl = False

    def __call__(self, argv):
        self.calls.append(argv.copy())
        if argv == ["ip", "-d", "-j", "link", "show"]:
            return json.dumps(list(self.state.values()))
        if argv[:3] == ["ip", "link", "add"]:
            left, right = argv[3], argv[-1]
            for name, peer in ((left, right), (right, left)):
                self.state[name] = {"ifname": name, "ifindex": self.next_index,
                                    "link": peer, "linkinfo": {"info_kind": "veth"}}
                self.next_index += 1
            return ""
        if argv[:4] == ["ip", "link", "set", "dev"]:
            if argv[5] == "alias":
                self.state[argv[4]]["ifalias"] = argv[6]
            return ""
        if argv[:4] == ["ip", "link", "delete", "dev"]:
            name = argv[4]
            peer = self.state[name]["link"]
            self.deletions.append(name)
            self.state.pop(name)
            self.state.pop(peer)
            return ""
        if argv[:2] == ["sysctl", "-w"]:
            if self.fail_sysctl:
                raise ValueError("fixture sysctl failure")
            return ""
        raise AssertionError(f"Unexpected command: {argv}")


class OwnedLinkTests(unittest.TestCase):
    def test_create_and_cleanup_only_new_pairs_and_cleanup_is_idempotent(self):
        fake = FakeCommands()
        original = copy.deepcopy(fake.state)
        with patch.object(runner, "command", side_effect=fake):
            with runner.OwnedLinks("abcdef") as links:
                self.assertEqual(len(links.owned), 4)
                self.assertTrue(all(fake.state[name]["ifalias"] == links.alias for name in links.names))
            links.cleanup()
        self.assertEqual(fake.state, original)
        self.assertEqual(len(fake.deletions), 2)
        self.assertFalse(links.cleanup_errors)

    def test_existing_name_refused_before_any_mutation(self):
        fake = FakeCommands()
        fake.state["npabcdefs1"] = {"ifname": "npabcdefs1", "ifindex": 1000}
        before = copy.deepcopy(fake.state)
        with patch.object(runner, "command", side_effect=fake), self.assertRaisesRegex(ValueError, "already exists"):
            with runner.OwnedLinks("abcdef"):
                self.fail("Must not enter")
        self.assertEqual(before, fake.state)
        self.assertEqual(len(fake.calls), 1)

    def test_changed_ownership_never_deletes_affected_pair(self):
        for property_name, changed_value in (("ifindex", 9999), ("ifalias", "third-party"),
                                             ("link", "different-peer"),
                                             ("linkinfo", {"info_kind": "bridge"})):
            fake = FakeCommands()
            with patch.object(runner, "command", side_effect=fake):
                links = runner.OwnedLinks("abcdef")
                links.__enter__()
                fake.state[links.names[0]][property_name] = changed_value
                links.cleanup()
            with self.subTest(property=property_name):
                self.assertEqual(fake.deletions, [links.names[2]])
                self.assertIn(links.names[0], fake.state)
                self.assertIn(links.names[1], fake.state)
                self.assertTrue(links.cleanup_errors)
                self.assertIn("p1_sw1", fake.state)

    def test_partial_setup_failure_cleans_created_pair_and_preserves_demo(self):
        fake = FakeCommands()
        fake.fail_sysctl = True
        before = copy.deepcopy(fake.state)
        with patch.object(runner, "command", side_effect=fake), self.assertRaisesRegex(ValueError, "sysctl failure"):
            with runner.OwnedLinks("abcdef"):
                self.fail("Must not enter")
        self.assertEqual(fake.state, before)
        self.assertEqual(fake.deletions, ["npabcdefs1"])

    def test_missing_peer_is_not_deleted_and_token_is_restricted(self):
        fake = FakeCommands()
        with patch.object(runner, "command", side_effect=fake):
            links = runner.OwnedLinks("abcdef")
            links.__enter__()
            fake.state.pop(links.names[1])
            links.cleanup()
        self.assertNotIn(links.names[0], fake.deletions)
        self.assertTrue(links.cleanup_errors)
        for token in ("ABCDEF", "a", "abcdef;rm", "../bad"):
            with self.assertRaises(ValueError):
                runner.OwnedLinks(token)


class ObservedPcapTests(unittest.TestCase):
    def test_nanosecond_wall_read_times_and_original_bytes_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "observed.pcap"
            frames = [bytes.fromhex("0200000000020200000000010800") + fixtures.udp(size)
                      for size in (50, 74)]
            times = [1700000000123456789, 1700000000987654321]
            runner.write_observed_pcap(path, [{"frame_hex": frame.hex(), "wall_ns": stamp}
                                              for frame, stamp in zip(frames, times)])
            records = list(iter_capture(path))
            self.assertEqual([row.timestamp_ns for row in records], times)
            self.assertEqual([row.data for row in records], frames)
            self.assertEqual([row.linktype for row in records], [1, 1])
            with self.assertRaises(FileExistsError):
                runner.write_observed_pcap(path, [])


if __name__ == "__main__":
    unittest.main()
