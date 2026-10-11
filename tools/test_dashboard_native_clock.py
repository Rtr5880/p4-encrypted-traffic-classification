"""Saved native observation transforms; no timing experiment or privileged run."""
import unittest

from dashboard.evidence import EvidenceStore
from dashboard.views.classification import load_pairs
from dashboard.views.native_clock import (changed_case_rows, ecdf_values, forest_rows,
    numeric_list, packet_rows, timing_distribution, timing_rows)


def row(model="B", capture=1, native=5):
    return {"model": model, "capture_time_prediction": capture, "prediction": native,
            "timing": {"original_iats_us": [10] * 7, "raw_native_iats_us": [-1, 12, 13, 14, 15, 16, 17],
                       "effective_native_iats_us": [0, 11, 13, 14, 15, 16, 17]}}


class NativeTimingTransforms(unittest.TestCase):
    def test_numeric_lists_preserve_negative_raw_values(self):
        self.assertEqual(numeric_list([-1, 0, 1], 3), [-1, 0, 1])
        for value in ([True], [float("nan")], [float("inf")], None):
            self.assertIsNone(numeric_list(value))
        self.assertIsNone(numeric_list([1], 7))

    def test_raw_and_clamped_gaps_stay_separate(self):
        gaps = timing_rows(row())
        self.assertEqual(len(gaps), 7)
        self.assertEqual(gaps[0]["Native raw IAT (µs)"], -1)
        self.assertEqual(gaps[0]["Native effective IAT (µs)"], 0)
        self.assertEqual(gaps[0]["Raw − capture (µs)"], -11)

    def test_missing_gap_array_rejected(self):
        value = row()
        del value["timing"]["effective_native_iats_us"]
        with self.assertRaises(ValueError):
            timing_rows(value)

    def test_filter_does_not_drop_outliers(self):
        pair = {"case_id": "one", "label": "VOIP", "B": row(), "C": row("C", capture=5)}
        pair["B"]["timing"]["raw_native_iats_us"][-1] = 1000000
        rows, missing = timing_distribution([pair], changed_only=True)
        self.assertEqual(len(rows), 7)
        self.assertEqual(missing, [])
        self.assertEqual(max(r["absolute_us"] for r in rows), 999990)

    def test_incomplete_rows_counted_not_invented(self):
        pair = {"case_id": "one", "label": "VOIP", "B": row(), "C": row("C")}
        pair["C"]["timing"] = {}
        rows, missing = timing_distribution([pair])
        self.assertEqual(len(rows), 7)
        self.assertEqual(missing, [("one", "C")])

    def test_changes_use_labels_and_actual_predictions(self):
        pair = {"case_id": "one", "label": "VOIP", "B": row(), "C": row("C", capture=5)}
        changes = changed_case_rows([pair])
        self.assertEqual(len(changes), 1)
        self.assertFalse(changes[0]["Capture correct"])
        self.assertTrue(changes[0]["Native correct"])

    def test_ecdf_keeps_all_actual_values(self):
        x, y = ecdf_values([10, 2, 2, 10000])
        self.assertEqual(x, [2, 2, 10, 10000])
        self.assertEqual(y, [.25, .5, .75, 1])
        self.assertEqual(ecdf_values([]), ([], []))

    def test_real_saved_observations_and_forest_arrays(self):
        store = EvidenceStore()
        metrics = store.load("native_metrics").data
        child, pairs, error = load_pairs(store, metrics)
        self.assertTrue(child.verified, child.message)
        self.assertIsNone(error)
        rows, skipped = timing_distribution(pairs)
        self.assertEqual(len(rows), 398 * 2 * 7)
        self.assertEqual(skipped, [])
        for model in ("B", "C"):
            saved = pairs[0][model]
            self.assertEqual(len(packet_rows(saved)), 8)
            leaves, scores = forest_rows(saved)
            self.assertEqual(len(leaves), 10)
            self.assertEqual(len(scores), 6)
            self.assertTrue(all(r["Match"] for r in leaves + scores))
            changes = [r for r in changed_case_rows(pairs) if r["Model"] == "RF-" + model]
            actual = metrics["common_paired_population"]["native_vs_capture"][model]["prediction_changes"]
            self.assertEqual(len(changes), actual)

    def test_packet_and_forest_missing_arrays_are_withheld(self):
        with self.assertRaises(ValueError):
            packet_rows(row())
        with self.assertRaises(ValueError):
            forest_rows(row())


class NativeTimingPresentation(unittest.TestCase):
    def test_real_page_and_filters(self):
        from streamlit.testing.v1 import AppTest
        app = AppTest.from_string("from dashboard.views.native_clock import render\nfrom dashboard.evidence import EvidenceStore\nrender(EvidenceStore())").run(timeout=45)
        self.assertFalse(app.exception, str(app.exception))
        self.assertGreaterEqual(len(app.dataframe), 4)
        app.selectbox(key="native_distribution_model").set_value("C").run(timeout=45)
        self.assertFalse(app.exception, str(app.exception))
        app.checkbox(key="native_distribution_changed").set_value(True).run(timeout=45)
        self.assertFalse(app.exception, str(app.exception))
        app.selectbox(key="native_inspect_model").set_value("C").run(timeout=45)
        self.assertFalse(app.exception, str(app.exception))

    def test_unavailable_evidence_no_timing_plots(self):
        from streamlit.testing.v1 import AppTest
        app = AppTest.from_string("from dashboard.views.native_clock import render\nfrom dashboard.evidence import EvidenceStore\nrender(EvidenceStore(registry_path='/nonexistent-stage4-registry.json'))").run(timeout=20)
        self.assertFalse(app.exception, str(app.exception))
        self.assertEqual(len(app.dataframe), 0)
        self.assertTrue(any("Evidence unavailable" in e.value for e in app.markdown))


if __name__ == "__main__":
    unittest.main()
