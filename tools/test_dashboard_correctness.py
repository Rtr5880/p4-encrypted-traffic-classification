"""Nonprivileged correctness-page arithmetic and UI tests; no BMv2 execution."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from dashboard.views import correctness as page


def record_fixture():
    features = dict(zip(page.FEATURES, [40, 338, 984, 66, 4876225, 5718527, 4, 7]))
    instance = dict(packet_id=17, instance_id="parent:instances-v1:idle-tcp:60s:1", record_id="parent:instance1:n8",
                    parent_candidate_conversation_id="parent", slot=123,
                    collision_excluded=False, features_B={k: features[k] for k in page.FEATURES[:6]},
                    features_C=features)
    expected = {**copy.deepcopy(instance), "leaves": list(range(10)),
                "scores": [1, 20, 3, 4, 5, 6], "prediction": 1}
    actual = {**copy.deepcopy(instance),
              "feature_report": {**{page.REPORT_FIELDS.get(k, k): v for k, v in features.items()},
                                 "count": 8, "status": 2, "packet_id": 17, "slot": 123, "instance": 1,
                                 "observed_us": 6000000, "effective_us": 6000000},
              "rf_report": {"leaves": list(range(10)), "scores": [1, 20, 3, 4, 5, 6],
                            "prediction": 1, "valid": 1, "model": 0}}
    return instance, expected, actual


def summary_fixture():
    report = {key: 0 for key in page.PARITY_FIELDS + page.INTEGRITY_FIELDS}
    report.update(packets_checked=20, classifications=1)
    prep = dict(packets=20, eligible_packets=18, admitted_packets=18, collision_packets=0,
                expected_n8_instances=1, expected_classifications=1,
                collision_excluded_n8_instances=0, collision_excluded_parents=0,
                collision_excluded_instances_all_lengths=0, collision_excluded_short_instances=0,
                reference_audit={"instances": 3, "provisional_class": "CHAT",
                                 "windows": {"8": {"short_instances": 2}}})
    return dict(captures_checked=1, status="controlled_real_pcap_parity_pass", captures=[{
        "capture": "fixture.pcap", "capture_id": "fixtures/fixture.pcap",
        "evidence_directory": "capture_001", "status": "controlled_parity_pass",
        "preparation": prep, "models": {"B": copy.deepcopy(report), "C": copy.deepcopy(report)},
    }])


def evidence(data, role="controlled_replay", verified=True, path="fixture.json"):
    return SimpleNamespace(data=data, role=role, verified=verified,
                           status="verified" if verified else "hash_mismatch",
                           message="Fixture hash mismatch" if not verified else "",
                           path=Path(path), sha256="a" * 64,
                           entry={"run_id": "test-fixture"})


class FixtureStore:
    def __init__(self, failure="", collision=False):
        self.failure = failure
        self.summary = summary_fixture()
        self.instance, self.expected, self.actual = record_fixture()
        if collision:
            self.instance["collision_excluded"] = True

    def load(self, role):
        return evidence(self.summary, verified=self.failure != "parent")

    def load_child(self, parent, relative, format="jsonl"):
        assert parent == "controlled_replay" and format == "jsonl"
        if relative.endswith("expected_n8_instances.jsonl"):
            data = [self.instance]
        elif "expected_rf_" in relative:
            data = [] if self.instance["collision_excluded"] else [self.expected]
        else:
            actual = copy.deepcopy(self.actual)
            if "RF_C/" in relative:
                actual["rf_report"]["model"] = 1
            data = [] if self.instance["collision_excluded"] else [actual]
        return evidence(data, role=relative, verified=self.failure != "child", path=relative)


class TestCorrectnessArithmetic(unittest.TestCase):
    def test_summary_distinguishes_checked_eligible_short_and_decisions(self):
        total = page.replay_summary(summary_fixture())
        self.assertEqual(total["packets"], 20)
        self.assertEqual(total["eligible_packets"], 18)
        self.assertEqual(total["instances"], 3)
        self.assertEqual(total["short_instances"], 2)
        self.assertEqual(total["models"]["B"]["classifications"], 1)

    def test_missing_count_does_not_become_zero(self):
        data = summary_fixture()
        del data["captures"][0]["models"]["C"]["leaf_mismatches"]
        with self.assertRaises(KeyError):
            page.replay_summary(data)

    def test_negative_and_boolean_counts_rejected(self):
        for value in [-1, True, 0.0, None]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                page.count(value, "fixture")

    def test_short_population_must_reconcile(self):
        data = summary_fixture()
        data["captures"][0]["preparation"]["reference_audit"]["instances"] = 4
        with self.assertRaisesRegex(ValueError, "short/N8"):
            page.replay_summary(data)

    def test_collision_accounting_must_reconcile(self):
        data = summary_fixture()
        data["captures"][0]["preparation"]["collision_excluded_n8_instances"] = 1
        with self.assertRaisesRegex(ValueError, "collision/N8"):
            page.replay_summary(data)

    def test_quality_table_retains_both_models_and_denominators(self):
        rows = page.capture_quality_rows(summary_fixture())
        self.assertEqual([row["Model"] for row in rows], ["RF-B", "RF-C"])
        self.assertEqual(rows[0]["Checked packets"], 20)
        self.assertEqual(rows[0]["Eligible packets"], 18)
        self.assertEqual(rows[0]["Admitted-N8 completion (%)"], 100)


class TestCorrectnessDecision(unittest.TestCase):
    def setUp(self):
        self.instance, self.expected, self.actual = record_fixture()

    def test_actual_features_are_report_fields_not_copied_expected_metadata(self):
        self.actual["features_C"]["size_min"] = 999999
        detail = page.decision_detail(self.instance, self.expected, self.actual, "B")
        self.assertTrue(detail["all_match"])
        self.assertEqual(detail["features"][0]["P4 report"], 40)
        self.assertFalse(detail["features"][-1]["Forest input"])
        self.assertEqual(detail["feature_report"]["count"], 8)
        self.assertEqual(self.instance["packet_id"], 17)

    def test_feature_leaf_score_and_prediction_mismatches_are_separate(self):
        self.actual["feature_report"]["size_min"] += 1
        self.actual["rf_report"]["leaves"][0] += 1
        self.actual["rf_report"]["scores"][0] += 1
        self.actual["rf_report"]["prediction"] = 0
        detail = page.decision_detail(self.instance, self.expected, self.actual, "B")
        for level in ["Features", "Ten leaves", "Six scores", "Prediction"]:
            self.assertFalse(detail["verdicts"][level])
        self.assertTrue(detail["verdicts"]["Identity"])

    def test_rf_c_consumes_all_eight_features_and_checks_model_identity(self):
        self.actual["rf_report"]["model"] = 1
        detail = page.decision_detail(self.instance, self.expected, self.actual, "C")
        self.assertTrue(detail["all_match"])
        self.assertTrue(all(row["Forest input"] for row in detail["features"]))

    def test_trigger_and_identity_mismatches_are_not_hidden(self):
        self.actual["feature_report"]["count"] = 7
        self.actual["instance_id"] = "different"
        detail = page.decision_detail(self.instance, self.expected, self.actual, "B")
        self.assertFalse(detail["verdicts"]["Identity"])
        self.assertFalse(detail["verdicts"]["Packet-eight trigger"])

    def test_identity_uses_actual_report_not_copied_reference_metadata(self):
        self.actual["feature_report"]["slot"] = 999
        detail = page.decision_detail(self.instance, self.expected, self.actual, "B")
        self.assertFalse(detail["verdicts"]["Identity"])
        self.actual["feature_report"]["slot"] = 123
        self.actual["feature_report"]["instance"] = 2
        detail = page.decision_detail(self.instance, self.expected, self.actual, "B")
        self.assertFalse(detail["verdicts"]["Identity"])

    def test_collision_exclusion_does_not_invent_decision(self):
        self.instance["collision_excluded"] = True
        detail = page.decision_detail(self.instance, None, None, "B")
        self.assertEqual(detail["state"], "collision_excluded")
        self.assertNotIn("prediction", detail)
        with self.assertRaises(ValueError):
            page.decision_detail(self.instance, self.expected, self.actual, "B")

    def test_missing_actual_does_not_become_parity_pass(self):
        detail = page.decision_detail(self.instance, self.expected, None, "B")
        self.assertEqual(detail["state"], "missing_decision")
        self.assertNotIn("all_match", detail)

    def test_saved_vectors_and_class_order_are_checked(self):
        self.actual["rf_report"]["scores"] = [1, 2]
        with self.assertRaisesRegex(ValueError, "6 saved"):
            page.decision_detail(self.instance, self.expected, self.actual, "B")
        self.actual = record_fixture()[2]
        self.actual["rf_report"]["prediction"] = 6
        with self.assertRaisesRegex(ValueError, "six-class"):
            page.decision_detail(self.instance, self.expected, self.actual, "B")

    def test_duplicate_record_ids_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            page._index([self.instance, self.instance], "fixture")


class TestCorrectnessPage(unittest.TestCase):
    def render(self, failure="", collision=False):
        from streamlit.testing.v1 import AppTest
        script = (
            "import sys\n"
            f"sys.path.insert(0, {str(REPO)!r})\n"
            "from dashboard.views.correctness import render\n"
            "from tools.test_dashboard_correctness import FixtureStore\n"
            f"render(FixtureStore(failure={failure!r}, collision={collision!r}))\n"
        )
        result = AppTest.from_string(script, default_timeout=30).run()
        self.assertEqual(len(result.exception), 0, [row.value for row in result.exception])
        return result

    def text(self, result):
        return "\n".join(str(item.value) for kind in ("markdown", "caption", "error", "warning")
                         for item in getattr(result, kind))

    def test_usable_page_has_quality_and_four_level_instance_detail(self):
        result = self.render()
        text = self.text(result)
        self.assertIn("Parity is not classification accuracy", text)
        self.assertIn("Features: PASS", text)
        self.assertIn("Ten leaves: PASS", text)
        self.assertIn("Six scores: PASS", text)
        self.assertIn("Prediction: PASS", text)
        self.assertIn("controlled packet/report accounting", text)
        self.assertGreaterEqual(len(result.dataframe), 5)
        self.assertEqual(len(result.button), 0)

    def test_model_selection_reaches_rf_c_detail(self):
        result = self.render()
        result.radio[0].set_value("C").run()
        self.assertEqual(len(result.exception), 0)
        self.assertIn("RF-C / P4 prediction", self.text(result))

    def test_hash_failure_withholds_detail_without_replacement(self):
        result = self.render(failure="child")
        self.assertIn("Instance detail is withheld", self.text(result))
        self.assertNotIn("Features: PASS", self.text(result))

    def test_parent_unverified_stops_all_metrics(self):
        result = self.render(failure="parent")
        self.assertIn("Evidence unavailable", self.text(result))
        self.assertEqual(len(result.dataframe), 0)

    def test_collision_ui_reports_exclusion_not_prediction(self):
        result = self.render(collision=True)
        self.assertIn("Collision-excluded N8 instance", self.text(result))
        self.assertNotIn("P4 prediction", self.text(result))

    def test_real_pinned_evidence_counts_without_running_experiments(self):
        from dashboard.evidence import EvidenceStore
        store = EvidenceStore()
        source = store.load("controlled_replay")
        if not source.verified:
            self.skipTest("Pinned historical evidence is not present in this checkout")
        total = page.replay_summary(source.data)
        self.assertEqual((total["captures"], total["packets"], total["eligible_packets"]),
                         (29, 4111471, 4081521))
        self.assertEqual((total["instances"], total["short_instances"],
                          total["expected_n8_instances"], total["collision_excluded_n8_instances"]),
                         (5450, 3369, 2081, 3))
        self.assertEqual(total["models"]["B"]["classifications"], 2078)
        self.assertEqual(len(page.capture_quality_rows(source.data)), 58)

    def test_actual_pinned_children_and_page_render_without_experiment_execution(self):
        from dashboard.evidence import EvidenceStore
        from streamlit.testing.v1 import AppTest
        store = EvidenceStore()
        source = store.load("controlled_replay")
        if not source.verified:
            self.skipTest("Pinned historical evidence is not present in this checkout")
        directory = source.data["captures"][0]["evidence_directory"]
        instance_source = store.load_child("controlled_replay", directory + "/expected_n8_instances.jsonl", format="jsonl")
        self.assertTrue(instance_source.verified, instance_source.message)
        instances = page._index(instance_source.data, "instances")
        for model in ("B", "C"):
            expected_source = store.load_child("controlled_replay", directory + f"/expected_rf_{model}.jsonl", format="jsonl")
            actual_source = store.load_child("controlled_replay", directory + f"/RF_{model}/decisions.jsonl", format="jsonl")
            self.assertTrue(expected_source.verified, expected_source.message)
            self.assertTrue(actual_source.verified, actual_source.message)
            expected = page._index(expected_source.data, "expected")
            actual = page._index(actual_source.data, "actual")
            key = next(iter(instances))
            self.assertTrue(page.decision_detail(instances[key], expected[key], actual[key], model)["all_match"])
        script = (
            "import sys\n" f"sys.path.insert(0, {str(REPO)!r})\n"
            "from dashboard.views.correctness import render\n"
            "from dashboard.evidence import EvidenceStore\n" "render(EvidenceStore())\n"
        )
        result = AppTest.from_string(script, default_timeout=30).run()
        self.assertEqual(len(result.exception), 0, [row.value for row in result.exception])
        self.assertIn("4,111,471", self.text(result))
        self.assertIn("4,081,521", self.text(result))
        self.assertIn("Features: PASS", self.text(result))
        self.assertNotIn("Evidence unavailable", self.text(result))

    def test_all_saved_decisions_and_collision_exclusions_are_inspectable(self):
        from dashboard.evidence import EvidenceStore
        store = EvidenceStore()
        source = store.load("controlled_replay")
        if not source.verified:
            self.skipTest("Pinned historical evidence is not present in this checkout")
        compared = {"B": 0, "C": 0}
        excluded = {"B": 0, "C": 0}
        for capture in source.data["captures"]:
            directory = capture["evidence_directory"]
            child = store.load_child("controlled_replay", directory + "/expected_n8_instances.jsonl", format="jsonl")
            self.assertTrue(child.verified, child.message)
            instances = page._index(child.data, "instances")
            for model in ("B", "C"):
                expected_child = store.load_child("controlled_replay", directory + f"/expected_rf_{model}.jsonl", format="jsonl")
                actual_child = store.load_child("controlled_replay", directory + f"/RF_{model}/decisions.jsonl", format="jsonl")
                self.assertTrue(expected_child.verified, expected_child.message)
                self.assertTrue(actual_child.verified, actual_child.message)
                expected = page._index(expected_child.data, "expected")
                actual = page._index(actual_child.data, "actual")
                self.assertEqual(set(expected), set(actual))
                self.assertTrue(set(actual).issubset(instances))
                for key, instance in instances.items():
                    detail = page.decision_detail(instance, expected.get(key), actual.get(key), model)
                    if instance["collision_excluded"]:
                        self.assertEqual(detail["state"], "collision_excluded")
                        excluded[model] += 1
                    else:
                        self.assertEqual(detail["state"], "compared", key)
                        self.assertTrue(detail["all_match"], key)
                        compared[model] += 1
        self.assertEqual(compared, {"B": 2078, "C": 2078})
        self.assertEqual(excluded, {"B": 3, "C": 3})


if __name__ == "__main__":
    unittest.main()
