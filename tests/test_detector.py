"""
tests/test_detector.py - Unit Tests for detector.py
Validates the Express API adapter, feature engineering, Isolation Forest anomaly
detection, schema compliance, error handling, and data integrity.
Uses mocked HTTP responses (no live backend or external network required).
"""

import unittest
from unittest.mock import patch, MagicMock
import numpy as np
import pandas as pd
import requests

from detector import (
    run_full_detection_pipeline,
    _extract_anomaly_features,
    _run_isolation_forest,
    ALERT_COLUMNS,
    SKLEARN_AVAILABLE,
)


class TestDetectorAdapter(unittest.TestCase):
    """Test suite for detector.py Express API integration and error handling."""

    def setUp(self):
        """Set up standard sample test data."""
        self.sample_df = pd.DataFrame(
            [
                {
                    "timestamp": "2026-10-18T09:00:00Z",
                    "event_type": "login",
                    "status": "failed",
                    "source_ip": "198.51.100.25",
                    "destination_ip": "192.0.2.20",
                    "user": "admin",
                    "message": "Failed login attempt",
                    "request_count": 3,
                }
            ]
        )

    # 1. Suspicious Result Test
    @patch("detector.requests.post")
    def test_suspicious_result(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "totalLogs": 1,
            "suspiciousCount": 1,
            "safeCount": 0,
            "severitySummary": {"high": 1, "medium": 0, "low": 0},
            "results": [
                {
                    "log": "login failed Failed login attempt",
                    "suspicious": True,
                    "severity": "HIGH",
                    "alerts": ["Possible SQL injection"],
                    "recommendation": "Investigate immediately and review the related security logs.",
                }
            ],
        }
        mock_post.return_value = mock_response

        res = run_full_detection_pipeline(self.sample_df)

        self.assertIn("events", res)
        self.assertIn("alerts", res)
        self.assertIn("summary", res)
        self.assertIn("warnings", res)

        alerts = res["alerts"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts.columns.tolist(), ALERT_COLUMNS)

        alert_row = alerts.iloc[0]
        self.assertEqual(alert_row["alert_id"], "ALT-0001")
        self.assertEqual(alert_row["source_ip"], "198.51.100.25")
        self.assertEqual(alert_row["event_type"], "login")
        self.assertEqual(alert_row["severity"], "HIGH")
        self.assertEqual(alert_row["detection_type"], "Rule-Based")
        self.assertEqual(alert_row["detection_reason"], "Possible SQL injection")
        self.assertIn("Investigate immediately", alert_row["recommended_action"])

        summary = res["summary"]
        self.assertEqual(summary["total_events"], 1)
        self.assertEqual(summary["total_alerts"], 1)
        self.assertEqual(summary["rule_alert_count"], 1)
        self.assertEqual(summary["anomaly_alert_count"], 0)
        self.assertEqual(summary["severity_breakdown"]["HIGH"], 1)
        self.assertEqual(summary["severity_breakdown"]["CRITICAL"], 0)

    # 2. Safe Result Test
    @patch("detector.requests.post")
    def test_safe_result_not_counted_as_alert(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "totalLogs": 1,
            "suspiciousCount": 0,
            "safeCount": 1,
            "severitySummary": {"high": 0, "medium": 0, "low": 1},
            "results": [
                {
                    "log": "login success Normal login",
                    "suspicious": False,
                    "severity": "LOW",
                    "alerts": [],
                    "recommendation": "No immediate action required. Continue monitoring.",
                }
            ],
        }
        mock_post.return_value = mock_response

        res = run_full_detection_pipeline(self.sample_df)

        alerts = res["alerts"]
        self.assertEqual(len(alerts), 0)
        self.assertEqual(alerts.columns.tolist(), ALERT_COLUMNS)

        summary = res["summary"]
        self.assertEqual(summary["total_alerts"], 0)
        self.assertEqual(summary["rule_alert_count"], 0)
        self.assertEqual(summary["anomaly_alert_count"], 0)
        self.assertEqual(summary["severity_breakdown"]["LOW"], 0)

    # 3. Empty DataFrame Test
    @patch("detector.requests.post")
    def test_empty_dataframe(self, mock_post):
        empty_df = pd.DataFrame()
        res = run_full_detection_pipeline(empty_df)

        # Must not call API for empty dataframe
        mock_post.assert_not_called()

        self.assertEqual(len(res["events"]), 0)
        self.assertEqual(len(res["alerts"]), 0)
        self.assertEqual(res["summary"]["total_events"], 0)
        self.assertEqual(res["summary"]["total_alerts"], 0)
        self.assertTrue(any("No security log records" in w for w in res["warnings"]))

    # 4. Missing Optional Fields Test
    @patch("detector.requests.post")
    def test_missing_optional_fields(self, mock_post):
        minimal_df = pd.DataFrame(
            [
                {
                    "timestamp": "2026-10-18T10:00:00Z",
                    "event_type": "firewall",
                    "status": "blocked",
                }
            ]
        )
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "totalLogs": 1,
            "suspiciousCount": 1,
            "safeCount": 0,
            "severitySummary": {"high": 1, "medium": 0, "low": 0},
            "results": [
                {
                    "log": "firewall blocked",
                    "suspicious": True,
                    "severity": "HIGH",
                    "alerts": ["Possible unauthorized access"],
                    "recommendation": "Review firewall rules.",
                }
            ],
        }
        mock_post.return_value = mock_response

        res = run_full_detection_pipeline(minimal_df)
        alerts = res["alerts"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts.iloc[0]["source_ip"], "Unknown")
        self.assertEqual(alerts.iloc[0]["event_type"], "firewall")

    # 5. Timeout & Connection Failure Test
    @patch("detector.requests.post")
    def test_timeout_and_connection_failure(self, mock_post):
        # Subtest A: Timeout
        mock_post.side_effect = requests.exceptions.ConnectTimeout("Connection timed out")
        res_timeout = run_full_detection_pipeline(self.sample_df)

        self.assertEqual(len(res_timeout["alerts"]), 0)
        self.assertEqual(len(res_timeout["events"]), 1)
        self.assertEqual(res_timeout["summary"]["total_alerts"], 0)
        self.assertTrue(any("timed out" in w for w in res_timeout["warnings"]))

        # Subtest B: Connection Refused
        mock_post.side_effect = requests.exceptions.ConnectionError("Connection refused")
        res_conn = run_full_detection_pipeline(self.sample_df)

        self.assertEqual(len(res_conn["alerts"]), 0)
        self.assertEqual(len(res_conn["events"]), 1)
        self.assertEqual(res_conn["summary"]["total_alerts"], 0)
        self.assertTrue(any("Unable to connect" in w for w in res_conn["warnings"]))

    # 6. Non-2xx Response Test
    @patch("detector.requests.post")
    def test_non_2xx_response(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_post.side_effect = None
        mock_post.return_value = mock_response

        res = run_full_detection_pipeline(self.sample_df)

        self.assertEqual(len(res["alerts"]), 0)
        self.assertEqual(res["summary"]["total_alerts"], 0)
        self.assertTrue(any("HTTP 500" in w for w in res["warnings"]))

    # 7. Malformed JSON & Schema Test
    @patch("detector.requests.post")
    def test_malformed_json_and_schema(self, mock_post):
        # Case A: Invalid JSON
        mock_resp_invalid_json = MagicMock()
        mock_resp_invalid_json.status_code = 200
        mock_resp_invalid_json.json.side_effect = ValueError("Invalid JSON string")
        mock_post.return_value = mock_resp_invalid_json

        res_a = run_full_detection_pipeline(self.sample_df)
        self.assertEqual(len(res_a["alerts"]), 0)
        self.assertTrue(any("invalid JSON" in w for w in res_a["warnings"]))

        # Case B: Missing 'results' key
        mock_resp_missing_key = MagicMock()
        mock_resp_missing_key.status_code = 200
        mock_resp_missing_key.json.side_effect = None
        mock_resp_missing_key.json.return_value = {"status": "ok", "message": "no results array"}
        mock_post.return_value = mock_resp_missing_key

        res_b = run_full_detection_pipeline(self.sample_df)
        self.assertEqual(len(res_b["alerts"]), 0)
        self.assertTrue(any("missing 'results' array" in w for w in res_b["warnings"]))

    # 8. Metadata Preservation & Non-Mutation Test
    @patch("detector.requests.post")
    def test_metadata_preservation(self, mock_post):
        original_df = pd.DataFrame(
            [
                {
                    "timestamp": "2026-10-18T12:00:00Z",
                    "event_type": "request",
                    "status": "success",
                    "source_ip": "10.0.0.55",
                    "custom_metadata": "audit_stage_1",
                    "request_count": 42,
                    "message": "select * from users where id=1 or 1=1",
                }
            ]
        )
        df_copy_before = original_df.copy(deep=True)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "totalLogs": 1,
            "suspiciousCount": 1,
            "safeCount": 0,
            "severitySummary": {"high": 1, "medium": 0, "low": 0},
            "results": [
                {
                    "log": "request success select * from users where id=1 or 1=1",
                    "suspicious": True,
                    "severity": "HIGH",
                    "alerts": ["Possible SQL injection"],
                    "recommendation": "Investigate immediately.",
                }
            ],
        }
        mock_post.return_value = mock_response

        res = run_full_detection_pipeline(original_df)

        pd.testing.assert_frame_equal(original_df, df_copy_before)
        events = res["events"]
        self.assertIn("custom_metadata", events.columns)
        self.assertEqual(events.iloc[0]["custom_metadata"], "audit_stage_1")
        self.assertEqual(events.iloc[0]["request_count"], 42)

        alert = res["alerts"].iloc[0]
        self.assertEqual(alert["source_ip"], "10.0.0.55")
        self.assertEqual(alert["timestamp"], "2026-10-18T12:00:00Z")
        self.assertEqual(alert["event_type"], "request")


class TestIsolationForestAnomalyDetection(unittest.TestCase):
    """Test suite for feature extraction, anomaly scoring, and model edge cases."""

    def _create_varied_dataset(self, n_rows=10):
        """Generates a synthetic varied dataset."""
        rows = []
        for i in range(n_rows):
            rows.append(
                {
                    "timestamp": f"2026-10-18T09:{i:02d}:00Z",
                    "event_type": "login" if i % 2 == 0 else "request",
                    "status": "success" if i < 8 else "failed",
                    "source_ip": f"192.168.1.{10 + (i % 3)}",
                    "message": f"Log message {i}",
                    "request_count": 1 if i < 8 else 500,  # last 2 are volumetric spikes
                }
            )
        return pd.DataFrame(rows)

    # 9. Feature Engineering on Insufficiently Sized Datasets (< 5 records)
    def test_feature_engineering_too_small_dataset(self):
        small_df = pd.DataFrame(
            [
                {"event_type": "login", "status": "success", "request_count": 1},
                {"event_type": "login", "status": "failed", "request_count": 2},
            ]
        )
        features_df, skip_reason = _extract_anomaly_features(small_df)
        self.assertIsNone(features_df)
        self.assertIsNotNone(skip_reason)
        self.assertIn("minimum required for anomaly detection is 5", skip_reason)

    # 10. Feature Engineering on Constant / Zero-Variance Dataset
    def test_feature_engineering_constant_dataset(self):
        constant_df = pd.DataFrame(
            [
                {"event_type": "login", "status": "success", "source_ip": "10.0.0.1", "request_count": 1}
                for _ in range(8)
            ]
        )
        features_df, skip_reason = _extract_anomaly_features(constant_df)
        self.assertIsNone(features_df)
        self.assertIsNotNone(skip_reason)
        self.assertIn("zero variance", skip_reason)

    # 11. Feature Engineering with Missing, Non-Numeric, and Non-Finite Values
    def test_feature_engineering_non_finite_values(self):
        messy_df = pd.DataFrame(
            [
                {"event_type": "login", "status": "success", "request_count": np.nan, "source_ip": "10.0.0.1"},
                {"event_type": "request", "status": "failed", "request_count": np.inf, "source_ip": "10.0.0.2"},
                {"event_type": "firewall", "status": "blocked", "request_count": -np.inf, "source_ip": "10.0.0.3"},
                {"event_type": "api", "status": "error", "request_count": "invalid_number", "source_ip": "10.0.0.4"},
                {"event_type": "login", "status": "success", "request_count": 10, "source_ip": "10.0.0.1"},
                {"event_type": "request", "status": "success", "request_count": 5, "source_ip": "10.0.0.2"},
            ]
        )
        features_df, skip_reason = _extract_anomaly_features(messy_df)
        self.assertIsNone(skip_reason)
        self.assertIsNotNone(features_df)
        self.assertEqual(len(features_df), 6)
        # Verify no NaN or infinite values remain
        self.assertFalse(np.isnan(features_df.values).any())
        self.assertFalse(np.isinf(features_df.values).any())

    # 12. Non-Mutation of Input DataFrame in Feature Extraction
    def test_feature_engineering_non_mutation(self):
        varied_df = self._create_varied_dataset(8)
        df_copy_before = varied_df.copy(deep=True)
        _extract_anomaly_features(varied_df)
        pd.testing.assert_frame_equal(varied_df, df_copy_before)

    # 13. Anomaly Detection Behavior When scikit-learn is Absent / Mocked
    @patch("detector.SKLEARN_AVAILABLE", False)
    def test_graceful_handling_when_sklearn_missing(self):
        varied_df = self._create_varied_dataset(8)
        with patch("detector.requests.post") as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: {"results": [{"suspicious": False} for _ in range(8)]},
            )
            res = run_full_detection_pipeline(varied_df)

        self.assertEqual(res["summary"]["anomaly_alert_count"], 0)
        self.assertTrue(
            any("scikit-learn is not installed" in w for w in res["warnings"])
        )
        # Ensure no fabricated anomaly columns
        self.assertNotIn("anomaly_score", res["events"].columns)
        self.assertNotIn("is_anomaly", res["events"].columns)

    # 14. Anomaly Columns, Score Semantics, and Alert Creation (Mocked Model)
    def test_anomaly_scoring_and_alert_generation(self):
        varied_df = self._create_varied_dataset(8)

        # Mock IsolationForest behavior
        mock_model_cls = MagicMock()
        mock_instance = MagicMock()
        mock_model_cls.return_value = mock_instance

        # 8 samples: 7 normal (score > 0), 1 outlier (score = -0.35)
        decision_scores = np.array([0.15, 0.20, 0.12, 0.18, 0.14, 0.19, 0.11, -0.35])
        predictions = np.array([1, 1, 1, 1, 1, 1, 1, -1])

        mock_instance.decision_function.return_value = decision_scores
        mock_instance.predict.return_value = predictions

        with patch("detector.SKLEARN_AVAILABLE", True), \
             patch("detector.IsolationForest", mock_model_cls), \
             patch("detector.requests.post") as mock_post:

            # Backend reports all safe for rules
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: {"results": [{"suspicious": False} for _ in range(8)]},
            )

            res = run_full_detection_pipeline(varied_df, contamination=0.1)

        # Validate score semantics and attached telemetry
        events = res["events"]
        self.assertIn("anomaly_score", events.columns)
        self.assertIn("is_anomaly", events.columns)
        self.assertEqual(events.iloc[7]["anomaly_score"], -0.35)
        self.assertTrue(events.iloc[7]["is_anomaly"])
        self.assertFalse(events.iloc[0]["is_anomaly"])

        # Validate anomaly alert schema
        alerts = res["alerts"]
        self.assertEqual(len(alerts), 1)
        alert_row = alerts.iloc[0]
        self.assertEqual(alert_row["detection_type"], "Anomaly Detection")
        self.assertEqual(alert_row["severity"], "MEDIUM")
        self.assertIn("-0.35", alert_row["detection_reason"])
        self.assertIn("Isolation Forest", alert_row["detection_reason"])

        # Validate separate summary counts
        summary = res["summary"]
        self.assertEqual(summary["total_alerts"], 1)
        self.assertEqual(summary["rule_alert_count"], 0)
        self.assertEqual(summary["anomaly_alert_count"], 1)
        self.assertEqual(summary["severity_breakdown"]["MEDIUM"], 1)

    # 15. Separate Rule and Anomaly Counts with De-duplication
    def test_separate_rule_and_anomaly_counts_deduplication(self):
        varied_df = self._create_varied_dataset(10)

        mock_model_cls = MagicMock()
        mock_instance = MagicMock()
        mock_model_cls.return_value = mock_instance

        # Sample 0 is an outlier according to model (predict = -1)
        # Sample 1 is an outlier according to model (predict = -1)
        # Samples 2..9 are inliers (predict = 1)
        mock_instance.decision_function.return_value = np.array(
            [-0.25, -0.15, 0.1, 0.2, 0.3, 0.4, 0.1, 0.2, 0.3, 0.4]
        )
        mock_instance.predict.return_value = np.array([-1, -1, 1, 1, 1, 1, 1, 1, 1, 1])

        with patch("detector.SKLEARN_AVAILABLE", True), \
             patch("detector.IsolationForest", mock_model_cls), \
             patch("detector.requests.post") as mock_post:

            # Backend rule-based detection flags Sample 0 as SQL injection!
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: {
                    "results": [
                        {
                            "suspicious": True,
                            "severity": "HIGH",
                            "alerts": ["Possible SQL injection"],
                            "recommendation": "Review immediately",
                        }
                    ] + [{"suspicious": False, "severity": "LOW"} for _ in range(9)]
                },
            )

            res = run_full_detection_pipeline(varied_df)

        alerts = res["alerts"]
        # Sample 0 generated 1 Rule-Based alert.
        # Sample 1 was NOT rule-flagged, so it generated 1 Anomaly Detection alert.
        # Sample 0 is NOT duplicated as a second alert!
        self.assertEqual(len(alerts), 2)

        types = alerts["detection_type"].tolist()
        self.assertEqual(types.count("Rule-Based"), 1)
        self.assertEqual(types.count("Anomaly Detection"), 1)

        summary = res["summary"]
        self.assertEqual(summary["rule_alert_count"], 1)
        self.assertEqual(summary["anomaly_alert_count"], 1)
        self.assertEqual(summary["total_alerts"], 2)
        self.assertEqual(summary["severity_breakdown"]["HIGH"], 1)
        self.assertEqual(summary["severity_breakdown"]["MEDIUM"], 1)

    # 16. Real scikit-learn Integration Test (executed if scikit-learn is installed)
    @unittest.skipUnless(SKLEARN_AVAILABLE, "scikit-learn is not installed in the local environment")
    def test_real_isolation_forest_execution(self):
        varied_df = self._create_varied_dataset(20)
        with patch("detector.requests.post") as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: {"results": [{"suspicious": False} for _ in range(20)]},
            )
            res1 = run_full_detection_pipeline(varied_df, random_state=42)
            res2 = run_full_detection_pipeline(varied_df, random_state=42)

        # Reproducibility check with fixed random seed
        pd.testing.assert_series_equal(res1["events"]["anomaly_score"], res2["events"]["anomaly_score"])
        pd.testing.assert_series_equal(res1["events"]["is_anomaly"], res2["events"]["is_anomaly"])


if __name__ == "__main__":
    unittest.main()
