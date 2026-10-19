"""
tests/test_incident_intelligence.py - Comprehensive Unit Tests for Incident Intelligence
Validates:
1. Risk score boundaries ([0, 100]) and priority thresholds.
2. Incident grouping logic by source IP and correlation window.
3. Separation of unattributed / missing source IPs without false correlation.
4. Chronological ordering of events within an incident.
5. Missing, unparseable, and conflicting fields.
6. Empty, None, and zero-alert inputs.
7. Deduplication of duplicate alert entries.
8. Attack story narrative generation and factual integrity (no invented facts).
9. Sublinear volume scaling preventing event flood distortion.
"""

import unittest
import pandas as pd
import numpy as np

from incident_intelligence import (
    classify_risk_priority,
    calculate_incident_risk,
    generate_attack_story,
    group_alerts_into_incidents,
    build_incident_intelligence,
    IncidentEvent,
    CorrelatedIncident,
    parse_timestamp_safe,
    is_known_ip,
    PRIORITY_CRITICAL_THRESHOLD,
    PRIORITY_HIGH_THRESHOLD,
    PRIORITY_MEDIUM_THRESHOLD,
    PRIORITY_LOW_THRESHOLD,
)


class TestRiskPrioritization(unittest.TestCase):
    """Test suite for risk scoring formula, factor breakdown, and priority thresholds."""

    def test_priority_threshold_exact_boundaries(self):
        """Verify exact boundary values for priority level classification."""
        self.assertEqual(classify_risk_priority(100), "Critical")
        self.assertEqual(classify_risk_priority(75), "Critical")
        self.assertEqual(classify_risk_priority(74), "High")
        self.assertEqual(classify_risk_priority(50), "High")
        self.assertEqual(classify_risk_priority(49), "Medium")
        self.assertEqual(classify_risk_priority(25), "Medium")
        self.assertEqual(classify_risk_priority(24), "Low")
        self.assertEqual(classify_risk_priority(0), "Low")

    def test_risk_score_clamping_boundaries(self):
        """Verify risk score is strictly clamped between 0 and 100 under extreme conditions."""
        # Extreme negative / out-of-range inputs
        self.assertEqual(classify_risk_priority(-50), "Low")
        self.assertEqual(classify_risk_priority(150), "Critical")

        # Test calculate_incident_risk bounds
        empty_risk = calculate_incident_risk([])
        self.assertEqual(empty_risk.score, 0)
        self.assertEqual(empty_risk.priority, "Low")

    def test_single_low_severity_alert(self):
        """Verify single low-severity alert scores in the Low priority tier."""
        ev = IncidentEvent(
            alert_id="ALT-0001",
            timestamp=pd.Timestamp("2026-10-18 09:00:00Z"),
            timestamp_str="2026-10-18 09:00:00 UTC",
            source_ip="192.0.2.10",
            destination_ip="192.0.2.20",
            event_type="request",
            status="success",
            severity="LOW",
            detection_type="System",
            detection_reason="Informational request notice",
            recommended_action="No immediate action required.",
            raw_message="Normal user telemetry",
        )
        risk = calculate_incident_risk([ev])
        self.assertGreaterEqual(risk.score, 0)
        self.assertLess(risk.score, 25)
        self.assertEqual(risk.priority, "Low")
        self.assertIn("Detection Severity Baseline", [f["factor"] for f in risk.contributing_factors])

    def test_high_impact_sqli_exploit_scores_high_or_critical(self):
        """Verify high-impact exploit signature (SQLi) receives significant priority."""
        ev = IncidentEvent(
            alert_id="ALT-0001",
            timestamp=pd.Timestamp("2026-10-18 09:16:00Z"),
            timestamp_str="2026-10-18 09:16:00 UTC",
            source_ip="198.51.100.44",
            destination_ip="192.0.2.20",
            event_type="request",
            status="blocked",
            severity="HIGH",
            detection_type="Rule-Based",
            detection_reason="Possible SQL injection: union select from accounts",
            recommended_action="Investigate database query logs immediately.",
            raw_message="Blocked probe - union select from accounts",
        )
        risk = calculate_incident_risk([ev])
        # Base (40) + Rule SQLi (20) + Behavior blocked (5) = 65 -> High priority
        self.assertGreaterEqual(risk.score, 60)
        self.assertIn(risk.priority, ("High", "Critical"))
        self.assertTrue(any("Rule-Based" in f["factor"] for f in risk.contributing_factors))

    def test_multi_event_multi_vector_critical_scoring(self):
        """Verify correlated multi-stage attack from same IP reaches Critical priority."""
        ev1 = IncidentEvent(
            alert_id="ALT-0001",
            timestamp=pd.Timestamp("2026-10-18 09:16:00Z"),
            timestamp_str="2026-10-18 09:16:00 UTC",
            source_ip="198.51.100.44",
            destination_ip="192.0.2.20",
            event_type="request",
            status="blocked",
            severity="HIGH",
            detection_type="Rule-Based",
            detection_reason="Possible SQL injection",
            recommended_action="Investigate SQL query",
            raw_message="Blocked probe",
        )
        ev2 = IncidentEvent(
            alert_id="ALT-0002",
            timestamp=pd.Timestamp("2026-10-18 09:18:00Z"),
            timestamp_str="2026-10-18 09:18:00 UTC",
            source_ip="198.51.100.44",
            destination_ip="192.0.2.20",
            event_type="login",
            status="failed",
            severity="HIGH",
            detection_type="Rule-Based",
            detection_reason="Failed login attempt - authentication failure",
            recommended_action="Review auth logs",
            raw_message="Login failed for guest",
        )
        risk = calculate_incident_risk([ev1, ev2])
        # Base: High (40) + multi-high bonus (5) + Rules: SQLi (20) + auth (10) capped at 25 +
        # Behavior: multi-vector (10) + failure (5) = 15 + Volume (2) = 87 -> Critical
        self.assertGreaterEqual(risk.score, 75)
        self.assertEqual(risk.priority, "Critical")

    def test_volume_scaling_prevents_excessive_skew(self):
        """Verify a flood of 100 identical low alerts cannot exceed maximum volume cap (10 pts)."""
        events = [
            IncidentEvent(
                alert_id=f"ALT-{i:04d}",
                timestamp=pd.Timestamp("2026-10-18 09:00:00Z") + pd.Timedelta(seconds=i),
                timestamp_str=f"2026-10-18 09:00:{i:02d} UTC",
                source_ip="192.0.2.50",
                destination_ip="192.0.2.20",
                event_type="ping",
                status="success",
                severity="LOW",
                detection_type="Telemetry",
                detection_reason="Routine ping",
                recommended_action="Monitor",
                raw_message="Echo ping",
            )
            for i in range(100)
        ]
        risk = calculate_incident_risk(events)
        # Volume score should be strictly capped at 10
        self.assertEqual(risk.score_breakdown["volume"], 10)
        # Score must not blow up to 100 just because of event count
        self.assertLess(risk.score, 50)


class TestIncidentGrouping(unittest.TestCase):
    """Test suite for alert correlation, temporal windows, and IP attribution."""

    def setUp(self):
        self.sample_alerts = pd.DataFrame([
            {
                "alert_id": "ALT-0001",
                "timestamp": "2026-10-18T09:16:00Z",
                "source_ip": "198.51.100.44",
                "event_type": "request",
                "severity": "HIGH",
                "detection_type": "Rule-Based",
                "detection_reason": "Possible SQL injection",
                "recommended_action": "Investigate immediately",
            },
            {
                "alert_id": "ALT-0002",
                "timestamp": "2026-10-18T09:18:00Z",
                "source_ip": "198.51.100.25",
                "event_type": "login",
                "severity": "MEDIUM",
                "detection_type": "Rule-Based",
                "detection_reason": "Failed login attempt",
                "recommended_action": "Review auth logs",
            },
            {
                "alert_id": "ALT-0003",
                "timestamp": "2026-10-18T09:20:00Z",
                "source_ip": "203.0.113.99",
                "event_type": "request",
                "severity": "MEDIUM",
                "detection_type": "Anomaly Detection",
                "detection_reason": "Statistical outlier detected by Isolation Forest (score: -0.150)",
                "recommended_action": "Review event telemetry",
            },
        ])

    def test_different_ips_form_separate_incidents(self):
        """Verify alerts from different source IPs are NOT lumped together."""
        incidents = group_alerts_into_incidents(self.sample_alerts)
        self.assertEqual(len(incidents), 3)

        source_ips = {inc.source_ip for inc in incidents}
        self.assertEqual(source_ips, {"198.51.100.44", "198.51.100.25", "203.0.113.99"})

    def test_same_ip_within_window_grouped_together(self):
        """Verify multiple alerts from the same source IP within 30 min form ONE incident."""
        same_ip_df = pd.DataFrame([
            {
                "alert_id": "ALT-0001",
                "timestamp": "2026-10-18T09:10:00Z",
                "source_ip": "198.51.100.44",
                "event_type": "request",
                "severity": "MEDIUM",
                "detection_type": "Rule-Based",
                "detection_reason": "Port scan detected",
                "recommended_action": "Check firewall",
            },
            {
                "alert_id": "ALT-0002",
                "timestamp": "2026-10-18T09:16:00Z",
                "source_ip": "198.51.100.44",
                "event_type": "request",
                "severity": "HIGH",
                "detection_type": "Rule-Based",
                "detection_reason": "Possible SQL injection",
                "recommended_action": "Investigate DB queries",
            },
        ])
        incidents = group_alerts_into_incidents(same_ip_df, correlation_window_minutes=30)
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.source_ip, "198.51.100.44")
        self.assertEqual(inc.event_count, 2)
        self.assertEqual(len(inc.events), 2)

    def test_same_ip_outside_window_separated(self):
        """Verify alerts from the same IP separated by 2 hours form separate incidents."""
        spread_ip_df = pd.DataFrame([
            {
                "alert_id": "ALT-0001",
                "timestamp": "2026-10-18T08:00:00Z",
                "source_ip": "198.51.100.44",
                "event_type": "login",
                "severity": "MEDIUM",
                "detection_type": "Rule-Based",
                "detection_reason": "Failed login attempt",
                "recommended_action": "Review auth",
            },
            {
                "alert_id": "ALT-0002",
                "timestamp": "2026-10-18T11:00:00Z",  # 3 hours later
                "source_ip": "198.51.100.44",
                "event_type": "request",
                "severity": "HIGH",
                "detection_type": "Rule-Based",
                "detection_reason": "Possible SQL injection",
                "recommended_action": "Investigate DB queries",
            },
        ])
        incidents = group_alerts_into_incidents(spread_ip_df, correlation_window_minutes=30)
        self.assertEqual(len(incidents), 2)
        self.assertEqual(incidents[0].source_ip, "198.51.100.44")
        self.assertEqual(incidents[1].source_ip, "198.51.100.44")

    def test_unattributed_ips_not_conflated(self):
        """Verify alerts with Unknown / missing source IP remain isolated and not lumped together."""
        unknown_ip_df = pd.DataFrame([
            {
                "alert_id": "ALT-0001",
                "timestamp": "2026-10-18T09:00:00Z",
                "source_ip": "Unknown",
                "event_type": "login",
                "severity": "MEDIUM",
                "detection_type": "Rule-Based",
                "detection_reason": "Failed login",
                "recommended_action": "Review auth",
            },
            {
                "alert_id": "ALT-0002",
                "timestamp": "2026-10-18T09:05:00Z",
                "source_ip": "N/A",
                "event_type": "request",
                "severity": "HIGH",
                "detection_type": "Anomaly Detection",
                "detection_reason": "Statistical anomaly",
                "recommended_action": "Investigate",
            },
        ])
        incidents = group_alerts_into_incidents(unknown_ip_df)
        self.assertEqual(len(incidents), 2)
        self.assertTrue(all(inc.is_unattributed_ip for inc in incidents))

    def test_chronological_ordering_guarantee(self):
        """Verify events within an incident are strictly sorted in chronological order."""
        shuffled_df = pd.DataFrame([
            {
                "alert_id": "ALT-0003",
                "timestamp": "2026-10-18T09:30:00Z",
                "source_ip": "192.0.2.77",
                "event_type": "logout",
                "severity": "LOW",
                "detection_type": "System",
                "detection_reason": "Session termination",
                "recommended_action": "None",
            },
            {
                "alert_id": "ALT-0001",
                "timestamp": "2026-10-18T09:00:00Z",
                "source_ip": "192.0.2.77",
                "event_type": "login",
                "severity": "MEDIUM",
                "detection_type": "Rule-Based",
                "detection_reason": "Failed login",
                "recommended_action": "Check user",
            },
            {
                "alert_id": "ALT-0002",
                "timestamp": "2026-10-18T09:15:00Z",
                "source_ip": "192.0.2.77",
                "event_type": "request",
                "severity": "HIGH",
                "detection_type": "Rule-Based",
                "detection_reason": "SQL injection",
                "recommended_action": "Block query",
            },
        ])
        incidents = group_alerts_into_incidents(shuffled_df, correlation_window_minutes=60)
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        event_ids = [e.alert_id for e in inc.events]
        self.assertEqual(event_ids, ["ALT-0001", "ALT-0002", "ALT-0003"])
        self.assertEqual(inc.start_time, pd.Timestamp("2026-10-18 09:00:00 UTC"))
        self.assertEqual(inc.end_time, pd.Timestamp("2026-10-18 09:30:00 UTC"))


class TestMissingDataAndRobustness(unittest.TestCase):
    """Test suite for missing timestamps, missing IPs, empty inputs, and duplicates."""

    def test_empty_dataframe_input(self):
        """Verify empty DataFrame input returns safe structured result without crashing."""
        res = build_incident_intelligence(pd.DataFrame())
        self.assertFalse(res["has_data"])
        self.assertEqual(len(res["incidents"]), 0)
        self.assertEqual(res["summary"]["total_incidents"], 0)
        self.assertIn("No security alerts", res["message"])

    def test_none_input(self):
        """Verify None input is gracefully handled."""
        res = build_incident_intelligence(None)
        self.assertFalse(res["has_data"])
        self.assertEqual(len(res["incidents"]), 0)

    def test_missing_timestamps_safe_handling(self):
        """Verify missing or invalid timestamps do not crash the pipeline."""
        df_no_ts = pd.DataFrame([
            {
                "alert_id": "ALT-0001",
                "timestamp": None,
                "source_ip": "192.0.2.100",
                "event_type": "request",
                "severity": "HIGH",
                "detection_type": "Rule-Based",
                "detection_reason": "Unauthorized access",
                "recommended_action": "Check access log",
            },
            {
                "alert_id": "ALT-0002",
                "timestamp": "InvalidDateString",
                "source_ip": "192.0.2.100",
                "event_type": "login",
                "severity": "MEDIUM",
                "detection_type": "Rule-Based",
                "detection_reason": "Failed login",
                "recommended_action": "Check password",
            },
        ])
        incidents = group_alerts_into_incidents(df_no_ts)
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.event_count, 2)
        self.assertIn("Unspecified timeframe", inc.time_span_str)

    def test_duplicate_alerts_deduplication(self):
        """Verify identical duplicate alerts are safely deduplicated."""
        dup_df = pd.DataFrame([
            {
                "alert_id": "ALT-0001",
                "timestamp": "2026-10-18T09:00:00Z",
                "source_ip": "192.0.2.10",
                "event_type": "request",
                "severity": "HIGH",
                "detection_type": "Rule-Based",
                "detection_reason": "SQL injection",
                "recommended_action": "Review",
            },
            {
                "alert_id": "ALT-0001",  # Exact duplicate
                "timestamp": "2026-10-18T09:00:00Z",
                "source_ip": "192.0.2.10",
                "event_type": "request",
                "severity": "HIGH",
                "detection_type": "Rule-Based",
                "detection_reason": "SQL injection",
                "recommended_action": "Review",
            },
        ])
        incidents = group_alerts_into_incidents(dup_df)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].event_count, 1)


class TestAttackStoryIntegrity(unittest.TestCase):
    """Test suite ensuring attack stories are factual, non-inventive, and defensible."""

    def test_story_contains_factual_sections(self):
        """Verify attack story produces all required factual and analytical sections."""
        ev = IncidentEvent(
            alert_id="ALT-0001",
            timestamp=pd.Timestamp("2026-10-18 09:16:00Z"),
            timestamp_str="2026-10-18 09:16:00 UTC",
            source_ip="198.51.100.44",
            destination_ip="192.0.2.20",
            event_type="request",
            status="blocked",
            severity="HIGH",
            detection_type="Rule-Based",
            detection_reason="Possible SQL injection - union select",
            recommended_action="Investigate query logs",
            raw_message="Blocked probe",
        )
        risk = calculate_incident_risk([ev])
        story = generate_attack_story([ev], source_ip="198.51.100.44", risk=risk)

        # Check required fields
        self.assertIsNotNone(story.headline)
        self.assertIn("198.51.100.44", story.headline)
        self.assertIn("198.51.100.44", story.what_was_observed)
        self.assertIn("SQL injection", story.why_it_is_suspicious)

        # Observed facts vs possible interpretations
        self.assertGreater(len(story.observed_facts), 0)
        self.assertGreater(len(story.possible_interpretations), 0)
        self.assertTrue(any("Hypothesis" in p for p in story.possible_interpretations))
        self.assertTrue(any("Alternative Benign" in p for p in story.possible_interpretations))

        # Recommended investigation steps (strictly advisory, no blocking)
        self.assertGreater(len(story.recommended_investigation_steps), 0)
        for step in story.recommended_investigation_steps:
            # Must NOT recommend automatic destructive actions
            self.assertNotIn("iptables -A", step)
            self.assertNotIn("drop packet", step.lower())
            self.assertNotIn("ban ip automatically", step.lower())

    def test_story_does_not_invent_ip_when_unattributed(self):
        """Verify story explicitly acknowledges unattributed IP without inventing one."""
        ev = IncidentEvent(
            alert_id="ALT-0001",
            timestamp=pd.Timestamp("2026-10-18 09:20:00Z"),
            timestamp_str="2026-10-18 09:20:00 UTC",
            source_ip="Unknown",
            destination_ip="N/A",
            event_type="request",
            status="success",
            severity="MEDIUM",
            detection_type="Anomaly Detection",
            detection_reason="Statistical outlier",
            recommended_action="Review telemetry",
            raw_message="",
        )
        risk = calculate_incident_risk([ev])
        story = generate_attack_story([ev], source_ip="Unknown", risk=risk, is_unattributed=True)

        self.assertIn("Unattributed Source", story.headline)
        self.assertIn("unspecified or unavailable", story.what_was_observed.lower())


if __name__ == "__main__":
    unittest.main()
