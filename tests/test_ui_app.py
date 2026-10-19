"""
tests/test_ui_app.py - Automated UI & Integration Tests for Streamlit Dashboard
Validates the complete dashboard user experience, navigation, CSV upload validation,
live backend connection, Isolation Forest telemetry rendering, metric counters,
and error handling using Streamlit AppTest.
"""

import io
import os
import unittest
import pandas as pd
from streamlit.testing.v1 import AppTest


class TestStreamlitDashboard(unittest.TestCase):
    """End-to-end automated UI test suite for app.py."""

    @classmethod
    def setUpClass(cls):
        # Path to root app.py
        cls.app_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "app.py")
        # Load sample synthetic CSV
        cls.csv_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "synthetic_security_logs.csv"
        )
        with open(cls.csv_path, "rb") as f:
            cls.valid_csv_bytes = f.read()

    def test_app_starts_without_exception(self):
        """Verify the dashboard boots cleanly without uncaught exceptions."""
        at = AppTest.from_file(self.app_path, default_timeout=30).run()
        self.assertEqual(len(at.exception), 0)

        # Check navigation radio options
        self.assertGreater(len(at.radio), 0)
        nav_radio = at.radio[0]
        self.assertIn("Dashboard", nav_radio.options)
        self.assertIn("Log Upload", nav_radio.options)
        self.assertIn("Alerts", nav_radio.options)
        self.assertIn("About", nav_radio.options)

        # Confirm detector.py is detected as Available in the sidebar
        sidebar_content = " ".join(
            [s.value for s in at.sidebar.success] + [m.value for m in at.sidebar.markdown]
        )
        self.assertIn("Available", sidebar_content)

    def test_navigate_to_log_upload_button(self):
        """Verify 'Navigate to Log Upload' button switches to Log Upload page and updates sidebar radio."""
        at = AppTest.from_file(self.app_path, default_timeout=30).run()
        self.assertEqual(len(at.exception), 0)
        self.assertEqual(at.sidebar.radio[0].value, "Dashboard")

        # Find and click button
        upload_btn = [b for b in at.button if b.label == "Navigate to Log Upload"]
        self.assertEqual(len(upload_btn), 1)
        upload_btn[0].click().run(timeout=30)

        self.assertEqual(len(at.exception), 0)
        self.assertEqual(at.sidebar.radio[0].value, "Log Upload")
        self.assertGreater(len(at.file_uploader), 0)

    def test_csv_upload_valid_file(self):
        """Verify CSV upload validation succeeds on valid synthetic security logs."""
        at = AppTest.from_file(self.app_path, default_timeout=30).run()

        # Switch to Log Upload page
        at.sidebar.radio[0].set_value("Log Upload").run(timeout=30)
        self.assertEqual(len(at.exception), 0)

        # Upload valid CSV
        at.file_uploader[0].upload("synthetic_security_logs.csv", self.valid_csv_bytes).run(
            timeout=30
        )
        self.assertEqual(len(at.exception), 0)

        # Verify success message rendered
        success_texts = [s.value for s in at.success]
        self.assertTrue(
            any("CSV Validation Passed" in s and "12" in s for s in success_texts),
            f"Expected validation success message, got: {success_texts}",
        )

    def test_csv_upload_missing_required_columns(self):
        """Verify uploading CSV without required columns displays clear error."""
        invalid_csv = b"source_ip,message\n192.0.2.10,Unauthorized access\n"

        at = AppTest.from_file(self.app_path, default_timeout=30).run()
        at.sidebar.radio[0].set_value("Log Upload").run(timeout=30)
        at.file_uploader[0].upload("missing_cols.csv", invalid_csv).run(timeout=30)

        self.assertEqual(len(at.exception), 0)
        error_texts = [e.value for e in at.error]
        self.assertTrue(
            any("CSV Validation Failed" in e for e in error_texts),
            f"Expected validation error banner, got: {error_texts}",
        )

    def test_full_live_detection_pipeline_flow(self):
        """
        Verify end-to-end integration: upload valid CSV, trigger live detection,
        and verify Dashboard & Alerts page telemetry, KPIs, and dataframes.
        """
        at = AppTest.from_file(self.app_path, default_timeout=30).run()

        # 1. Upload CSV
        at.sidebar.radio[0].set_value("Log Upload").run(timeout=30)
        at.file_uploader[0].upload("synthetic_security_logs.csv", self.valid_csv_bytes).run(
            timeout=30
        )
        self.assertEqual(len(at.exception), 0)

        # 2. Trigger detection button
        detect_buttons = [b for b in at.button if "Analyze Logs" in b.label]
        self.assertGreater(len(detect_buttons), 0)
        detect_buttons[0].click().run(timeout=30)
        self.assertEqual(len(at.exception), 0)

        # 3. Check Dashboard page KPIs
        at.sidebar.radio[0].set_value("Dashboard").run(timeout=30)
        self.assertEqual(len(at.exception), 0)

        # Metrics should now reflect real analysis results
        metrics_dict = {m.label: m.value for m in at.metric}
        self.assertIn("Total Events Ingested", metrics_dict)
        self.assertEqual(metrics_dict["Total Events Ingested"], "12")

        self.assertIn("Total Alerts", metrics_dict)
        self.assertEqual(metrics_dict["Total Alerts"], "3")

        self.assertIn("Rule-Based Alerts", metrics_dict)
        self.assertEqual(metrics_dict["Rule-Based Alerts"], "2")

        self.assertIn("Anomaly Alerts", metrics_dict)
        self.assertEqual(metrics_dict["Anomaly Alerts"], "1")

        # 4. Check Alerts page
        at.sidebar.radio[0].set_value("Alerts").run(timeout=30)
        self.assertEqual(len(at.exception), 0)

        # Alerts table should be displayed
        self.assertGreater(len(at.dataframe), 0)
        alerts_df = at.dataframe[0].value
        self.assertEqual(len(alerts_df), 3)

        # Verify required columns exist in alert dataframe
        for col in ["alert_id", "source_ip", "event_type", "severity", "detection_type"]:
            self.assertIn(col, alerts_df.columns)

    def test_too_small_dataset_handling(self):
        """Verify handling of datasets with < 5 records skips anomaly detection without crashing."""
        small_csv = (
            b"timestamp,event_type,status,source_ip,message,request_count\n"
            b"2026-10-18T09:00:00Z,login,success,192.0.2.10,Normal login,1\n"
            b"2026-10-18T09:02:00Z,request,success,192.0.2.11,Normal request,1\n"
        )
        at = AppTest.from_file(self.app_path, default_timeout=30).run()
        at.sidebar.radio[0].set_value("Log Upload").run(timeout=30)
        at.file_uploader[0].upload("small.csv", small_csv).run(timeout=30)

        detect_buttons = [b for b in at.button if "Analyze Logs" in b.label]
        detect_buttons[0].click().run(timeout=30)
        self.assertEqual(len(at.exception), 0)

        at.sidebar.radio[0].set_value("Dashboard").run(timeout=30)
        metrics_dict = {m.label: m.value for m in at.metric}
        self.assertEqual(metrics_dict["Total Events Ingested"], "2")
        self.assertEqual(metrics_dict["Anomaly Alerts"], "0")

        # Warning about dataset size should be rendered in expander
        warning_texts = [w.value for w in at.warning]
        self.assertTrue(
            any("minimum required for anomaly detection is 5" in w for w in warning_texts),
            f"Expected minimum sample warning, got: {warning_texts}",
        )

    def test_backend_connection_failure_handled_gracefully(self):
        """Verify that when backend is unreachable, the dashboard displays clear warning."""
        from unittest.mock import patch
        import requests

        with patch(
            "detector.requests.post",
            side_effect=requests.exceptions.ConnectionError("Connection refused to backend"),
        ):
            at = AppTest.from_file(self.app_path, default_timeout=30).run()
            at.sidebar.radio[0].set_value("Log Upload").run(timeout=30)
            at.file_uploader[0].upload("synthetic_security_logs.csv", self.valid_csv_bytes).run(
                timeout=30
            )

            detect_buttons = [b for b in at.button if "Analyze Logs" in b.label]
            detect_buttons[0].click().run(timeout=30)
            self.assertEqual(len(at.exception), 0)

            # Warning must be clearly presented on Dashboard
            at.sidebar.radio[0].set_value("Dashboard").run(timeout=30)
            warning_texts = [w.value for w in at.warning]
            self.assertTrue(
                any("Backend service" in w or "Unable to connect" in w or "Connection refused" in w for w in warning_texts),
                f"Expected connection failure warning, got: {warning_texts}",
            )
            # Safe rows must NOT be falsely claimed as rule alerts
            metrics_dict = {m.label: m.value for m in at.metric}
            self.assertEqual(metrics_dict["Rule-Based Alerts"], "0")

    def test_incident_intelligence_empty_state(self):
        """Verify Incident Intelligence page displays guidance when no logs loaded."""
        at = AppTest.from_file(self.app_path, default_timeout=30).run()
        self.assertEqual(len(at.exception), 0)

        # Navigate to Incident Intelligence
        at.sidebar.radio[0].set_value("Incident Intelligence").run(timeout=30)
        self.assertEqual(len(at.exception), 0)

        # Markdown should contain guidance
        all_md = " ".join([m.value for m in at.markdown])
        self.assertIn("No Log Telemetry Loaded", all_md)

    def test_incident_intelligence_live_flow_and_metrics(self):
        """Verify Incident Intelligence page renders correlated incidents, KPIs, and attack stories."""
        at = AppTest.from_file(self.app_path, default_timeout=30).run()

        # Upload valid logs
        at.sidebar.radio[0].set_value("Log Upload").run(timeout=30)
        at.file_uploader[0].upload("synthetic_security_logs.csv", self.valid_csv_bytes).run(timeout=30)
        self.assertEqual(len(at.exception), 0)

        # Analyze logs
        detect_buttons = [b for b in at.button if "Analyze Logs" in b.label]
        self.assertGreater(len(detect_buttons), 0)
        detect_buttons[0].click().run(timeout=30)
        self.assertEqual(len(at.exception), 0)

        # Switch to Incident Intelligence
        at.sidebar.radio[0].set_value("Incident Intelligence").run(timeout=30)
        self.assertEqual(len(at.exception), 0)

        # Check KPI metrics
        metrics_dict = {m.label: m.value for m in at.metric}
        self.assertIn("Correlated Incidents", metrics_dict)
        self.assertEqual(metrics_dict["Correlated Incidents"], "3")
        self.assertIn("Peak Risk Score", metrics_dict)

        # Verify attack story narratives rendered
        all_md = " ".join([m.value for m in at.markdown])
        self.assertIn("What Was Observed", all_md)
        self.assertIn("Why It Is Suspicious", all_md)
        self.assertIn("Verified Telemetry Facts", all_md)

    def test_about_page_features(self):
        """Verify About page documents Attack Story Generator and Risk Prioritization."""
        at = AppTest.from_file(self.app_path, default_timeout=30).run()
        at.sidebar.radio[0].set_value("About").run(timeout=30)
        self.assertEqual(len(at.exception), 0)

        all_md = " ".join([m.value for m in at.markdown])
        self.assertIn("Attack Story Generator", all_md)
        self.assertIn("Risk Prioritization", all_md)


if __name__ == "__main__":
    unittest.main()

