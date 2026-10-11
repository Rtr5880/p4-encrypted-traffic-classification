"""Read-only classification transforms and Streamlit presentation regressions."""
import copy
import unittest

from dashboard.evidence import CLASS_ORDER, EvidenceStore
from dashboard.views.classification import (class_name, comparison_rows,
    confusion_values, load_pairs, metric_blocks, paired_outcomes, per_class_rows)


def outcome(model, identity="case-1", truth="VOIP", capture=5, native=5):
    return {"model": model, "case_id": identity, "record_id": identity,
            "label": truth, "capture_time_prediction": capture, "prediction": native}


class ClassificationTransforms(unittest.TestCase):
    def test_class_order_and_unknown_values(self):
        self.assertEqual(class_name(1), "FT")
        self.assertEqual(class_name("STREAMING"), "STREAMING")
        for invalid in (True, 6, -1, "BROWSING", None, 2.0):
            self.assertIsNone(class_name(invalid))

    def test_pairs_join_by_identity_not_file_order(self):
        rows = [outcome("C", "z"), outcome("B", "a"), outcome("C", "a"), outcome("B", "z")]
        self.assertEqual([p["case_id"] for p in paired_outcomes(rows, ["z", "a"])], ["z", "a"])

    def test_duplicate_missing_or_extra_pair_rejected(self):
        valid = [outcome("B"), outcome("C")]
        for rows, ids in [(valid + [outcome("B")], None), ([valid[0]], None), (valid, ["other"]), (valid, ["case-1", "case-1"])]:
            with self.assertRaises(ValueError):
                paired_outcomes(rows, ids)

    def test_label_and_record_identity_must_agree(self):
        rows = [outcome("B"), outcome("C", truth="FT")]
        with self.assertRaises(ValueError):
            paired_outcomes(rows)
        rows[1]["label"] = "VOIP"
        rows[1]["record_id"] = "unrelated"
        with self.assertRaises(ValueError):
            paired_outcomes(rows)

    def test_capture_and_native_comparisons_are_separate(self):
        pair = paired_outcomes([outcome("B", capture=1, native=5), outcome("C", capture=5, native=1)])
        capture, native = comparison_rows(pair, "capture")[0], comparison_rows(pair, "native")[0]
        self.assertTrue(capture["C fixes B"])
        self.assertTrue(native["C introduces error"])
        self.assertEqual(capture["RF-B"], "FT")
        self.assertEqual(native["RF-B"], "VOIP")

    def test_missing_prediction_is_not_fabricated(self):
        pair = paired_outcomes([outcome("B", native=None), outcome("C")])
        with self.assertRaises(ValueError):
            comparison_rows(pair, "native")

    def test_row_normalization_and_zero_support(self):
        matrix = [[0] * 6 for _ in range(6)]
        matrix[1][0], matrix[1][1] = 1, 3
        values = confusion_values(matrix, True)
        self.assertEqual(values[1][:2], [.25, .75])
        self.assertEqual(values[0], [None] * 6)
        self.assertEqual(confusion_values(matrix)[1][1], 3)

    def test_bad_matrix_rejected(self):
        for matrix in ([[1]], [[-1] * 6 for _ in range(6)], [[True] * 6 for _ in range(6)]):
            with self.assertRaises(ValueError):
                confusion_values(matrix)

    def test_saved_metric_population_guard(self):
        store = EvidenceStore()
        loaded = store.load("native_metrics")
        self.assertTrue(loaded.verified, loaded.message)
        for domain in ("capture", "native"):
            blocks = metric_blocks(loaded.data, domain)
            self.assertEqual(blocks["B"]["records"], 398)
            self.assertEqual(sum(r["Support"] for r in per_class_rows(blocks)), 398)
        changed = copy.deepcopy(loaded.data)
        changed["common_paired_population"]["native_metrics"]["C"]["records"] = 397
        with self.assertRaises(ValueError):
            metric_blocks(changed, "native")

    def test_real_sealed_outcomes_match_saved_matrices(self):
        store = EvidenceStore()
        metrics = store.load("native_metrics").data
        child, pairs, error = load_pairs(store, metrics)
        self.assertTrue(child.verified, child.message)
        self.assertIsNone(error)
        self.assertEqual(len(pairs), 398)
        for domain in ("capture", "native"):
            rows = comparison_rows(pairs, domain)
            blocks = metric_blocks(metrics, domain)
            for model in ("B", "C"):
                matrix = [[0] * 6 for _ in range(6)]
                for row in rows:
                    matrix[CLASS_ORDER.index(row["Capture-derived label"])][CLASS_ORDER.index(row["RF-" + model])] += 1
                self.assertEqual(matrix, blocks[model]["confusion_matrix"])


class ClassificationPresentation(unittest.TestCase):
    def test_real_page_and_controls(self):
        from streamlit.testing.v1 import AppTest
        app = AppTest.from_string("from dashboard.views.classification import render\nfrom dashboard.evidence import EvidenceStore\nrender(EvidenceStore())").run(timeout=45)
        self.assertFalse(app.exception, str(app.exception))
        self.assertGreaterEqual(len(app.dataframe), 4)
        app.radio(key="classification_domain").set_value("Native-clock replay").run(timeout=45)
        self.assertFalse(app.exception, str(app.exception))
        app.radio(key="classification_matrix").set_value("Row-normalized").run(timeout=45)
        self.assertFalse(app.exception, str(app.exception))
        app.selectbox(key="classification_error_kind").set_value("C fixes B").run(timeout=45)
        self.assertFalse(app.exception, str(app.exception))

    def test_unavailable_evidence_is_explicit(self):
        from streamlit.testing.v1 import AppTest
        app = AppTest.from_string("from dashboard.views.classification import render\nfrom dashboard.evidence import EvidenceStore\nrender(EvidenceStore(registry_path='/nonexistent-stage4-registry.json'))").run(timeout=20)
        self.assertFalse(app.exception, str(app.exception))
        self.assertEqual(len(app.dataframe), 0)
        self.assertTrue(any("Evidence unavailable" in e.value for e in app.markdown))


if __name__ == "__main__":
    unittest.main()
