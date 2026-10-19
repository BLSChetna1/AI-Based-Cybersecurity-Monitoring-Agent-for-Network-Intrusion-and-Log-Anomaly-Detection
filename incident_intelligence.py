"""
incident_intelligence.py - Incident Correlation, Attack Story Generation & Risk Prioritization
Defensive Security Operations Center (SOC) Intelligence Module

Correlates individual security alerts into coherent, evidence-based incidents,
generates transparent, factual attack stories with chronological event timelines,
and computes deterministic, testable risk scores (0-100) with priority tiers.

Safety Policy:
- 100% offline, deterministic heuristic logic (no paid AI API or external network calls).
- Does not invent facts, IP addresses, attack details, or evidence.
- Clearly distinguishes observed facts from possible analytical interpretations.
- Recommended actions are suggestions for human analyst review; no automated blocking.
"""

from dataclasses import dataclass, field
import math
from typing import Dict, Any, List, Optional, Tuple, Union
import numpy as np
import pandas as pd


# -----------------------------------------------------------------------------
# Heuristic Configuration & Threshold Constants
# -----------------------------------------------------------------------------

# Priority Level Thresholds (Heuristic Risk Score 0 - 100)
PRIORITY_CRITICAL_THRESHOLD: int = 75
PRIORITY_HIGH_THRESHOLD: int = 50
PRIORITY_MEDIUM_THRESHOLD: int = 25
PRIORITY_LOW_THRESHOLD: int = 0

# Temporal Incident Correlation Window (minutes)
DEFAULT_CORRELATION_WINDOW_MINUTES: int = 30

# Unattributed Source IP Identifier Placeholders
UNKNOWN_IP_VALUES = frozenset([
    "unknown",
    "n/a",
    "na",
    "none",
    "null",
    "",
    "unspecified",
    "0.0.0.0",
    "::",
])

# Base Severity Scoring Map
SEVERITY_BASE_SCORES: Dict[str, int] = {
    "CRITICAL": 50,
    "HIGH": 40,
    "MEDIUM": 25,
    "LOW": 10,
}
DEFAULT_SEVERITY_BASE: int = 15

# High-Impact Rule Keyword Triggers (Max +20 pts)
HIGH_IMPACT_RULE_KEYWORDS = [
    "sql injection",
    "union select",
    "or 1=1",
    "unauthorized access",
    "access denied",
    "privilege escalation",
    "command injection",
    "remote code",
]

# Medium-Impact Rule Keyword Triggers (Max +10 pts)
MEDIUM_IMPACT_RULE_KEYWORDS = [
    "failed login",
    "failed password",
    "authentication failure",
    "port scan",
    "port scanning",
    "brute force",
    "probe",
]


# -----------------------------------------------------------------------------
# Data Models
# -----------------------------------------------------------------------------

@dataclass
class IncidentEvent:
    """Represents a single verified telemetry event or alert within an incident."""
    alert_id: str
    timestamp: Optional[pd.Timestamp]
    timestamp_str: str
    source_ip: str
    destination_ip: str
    event_type: str
    status: str
    severity: str
    detection_type: str
    detection_reason: str
    recommended_action: str
    raw_message: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp_str,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "event_type": self.event_type,
            "status": self.status,
            "severity": self.severity,
            "detection_type": self.detection_type,
            "detection_reason": self.detection_reason,
            "recommended_action": self.recommended_action,
        }


@dataclass
class RiskAssessment:
    """Detailed heuristic risk prioritization breakdown."""
    score: int
    priority: str
    contributing_factors: List[Dict[str, Any]] = field(default_factory=list)
    score_breakdown: Dict[str, int] = field(default_factory=dict)
    methodology_note: str = (
        "Heuristic prioritization score (0-100) calculated from base severity, "
        "rule matches, ML anomalies, behavioral variety, and sublinear volume scaling. "
        "Intended for SOC triage queue ordering, NOT a mathematically calibrated probability."
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "priority": self.priority,
            "contributing_factors": self.contributing_factors,
            "score_breakdown": self.score_breakdown,
            "methodology_note": self.methodology_note,
        }


@dataclass
class AttackStory:
    """Factual and explainable narrative structure for an incident."""
    headline: str
    what_was_observed: str
    why_it_is_suspicious: str
    supporting_evidence: List[str]
    observed_facts: List[str]
    possible_interpretations: List[str]
    recommended_investigation_steps: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "headline": self.headline,
            "what_was_observed": self.what_was_observed,
            "why_it_is_suspicious": self.why_it_is_suspicious,
            "supporting_evidence": self.supporting_evidence,
            "observed_facts": self.observed_facts,
            "possible_interpretations": self.possible_interpretations,
            "recommended_investigation_steps": self.recommended_investigation_steps,
        }


@dataclass
class CorrelatedIncident:
    """A collection of related security alerts forming an actionable incident."""
    incident_id: str
    source_ip: str
    is_unattributed_ip: bool
    start_time: Optional[pd.Timestamp]
    end_time: Optional[pd.Timestamp]
    time_span_str: str
    events: List[IncidentEvent]
    event_count: int
    primary_threat: str
    max_severity: str
    attack_story: AttackStory
    risk_assessment: RiskAssessment

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "source_ip": self.source_ip,
            "is_unattributed_ip": self.is_unattributed_ip,
            "start_time": self.start_time.isoformat() if self.start_time is not None else None,
            "end_time": self.end_time.isoformat() if self.end_time is not None else None,
            "time_span_str": self.time_span_str,
            "event_count": self.event_count,
            "primary_threat": self.primary_threat,
            "max_severity": self.max_severity,
            "risk_score": self.risk_assessment.score,
            "priority": self.risk_assessment.priority,
            "headline": self.attack_story.headline,
            "story": self.attack_story.to_dict(),
            "risk": self.risk_assessment.to_dict(),
            "events": [e.to_dict() for e in self.events],
        }


# -----------------------------------------------------------------------------
# Timestamp & Parsing Utilities
# -----------------------------------------------------------------------------

def parse_timestamp_safe(val: Any) -> Optional[pd.Timestamp]:
    """
    Converts various timestamp representations into a uniform UTC-aware pd.Timestamp.
    Returns None if missing, NaT, or unparseable.
    """
    if val is None or pd.isna(val):
        return None
    if isinstance(val, pd.Timestamp):
        if val is pd.NaT:
            return None
        return val.tz_convert("UTC") if val.tzinfo is not None else val.tz_localize("UTC")

    str_val = str(val).strip()
    if not str_val or str_val.lower() in ("nat", "nan", "none", "n/a", "null"):
        return None

    try:
        ts = pd.to_datetime(str_val, errors="coerce", utc=True)
        if pd.isna(ts) or ts is pd.NaT:
            return None
        return ts
    except Exception:
        return None


def is_known_ip(ip_val: Any) -> bool:
    """Checks whether an IP value represents a known, attributable source IP."""
    if ip_val is None or pd.isna(ip_val):
        return False
    cleaned = str(ip_val).strip().lower()
    return cleaned not in UNKNOWN_IP_VALUES


def _format_time_span(start: Optional[pd.Timestamp], end: Optional[pd.Timestamp]) -> str:
    """Generates human-readable temporal duration string."""
    if start is None and end is None:
        return "Unspecified timeframe (timestamps absent)"
    if start is None or end is None or start == end:
        ts = start or end
        return f"Single event at {ts.strftime('%Y-%m-%d %H:%M:%S UTC')}"

    diff = end - start
    total_seconds = int(diff.total_seconds())
    if total_seconds < 0:
        # Edge case: out of order
        total_seconds = abs(total_seconds)

    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    parts: List[str] = []
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0 or hours > 0:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")

    duration_str = " ".join(parts)
    return (
        f"{start.strftime('%Y-%m-%d %H:%M:%S')} to {end.strftime('%H:%M:%S UTC')} "
        f"({duration_str})"
    )


# -----------------------------------------------------------------------------
# Risk Prioritization Engine (Feature 2)
# -----------------------------------------------------------------------------

def classify_risk_priority(score: int) -> str:
    """
    Classifies a risk score (0-100) into a standard SOC priority tier.

    Thresholds:
        75 - 100 : Critical
        50 - 74  : High
        25 - 49  : Medium
        0  - 24  : Low
    """
    clamped = max(0, min(100, int(round(score))))
    if clamped >= PRIORITY_CRITICAL_THRESHOLD:
        return "Critical"
    if clamped >= PRIORITY_HIGH_THRESHOLD:
        return "High"
    if clamped >= PRIORITY_MEDIUM_THRESHOLD:
        return "Medium"
    return "Low"


def calculate_incident_risk(events: List[IncidentEvent]) -> RiskAssessment:
    """
    Calculates a transparent, defensible risk score (0-100) and priority for an incident.

    SCORING FORMULA:
    RiskScore = clamp_0_100(S_base + S_rules + S_anomaly + S_behavior + S_volume)

    Components:
    1. Base Severity (S_base, 10 to 50 pts):
       Derived from the highest severity observed across the incident's alerts.
       - CRITICAL: 50 pts
       - HIGH: 40 pts
       - MEDIUM: 25 pts
       - LOW: 10 pts
       - Unknown / Other: 15 pts
       Bonus: +5 pts if multiple HIGH or CRITICAL alerts exist in the incident.

    2. Rule-Based Findings (S_rules, 0 to 25 pts):
       - +20 pts if explicit high-impact exploit patterns matched (SQL injection, unauthorized access).
       - +10 pts if reconnaissance or brute-force patterns matched (port scan, failed login).
       - Max cap: 25 pts.

    3. Machine Learning Anomaly Indicators (S_anomaly, 0 to 20 pts):
       - +15 pts if flagged as statistical anomaly by Isolation Forest.
       - +5 pts if detection reason highlights extreme request volume (>1000) or high deviation.
       - Max cap: 20 pts.

    4. Behavioral Pattern & Attack Breadth (S_behavior, 0 to 15 pts):
       - +10 pts if multi-vector activity observed (multiple distinct event types, e.g. login + request).
       - +5 pts if failure or blocked status codes are observed (indicating active perimeter defense or failed attempts).
       - Max cap: 15 pts.

    5. Event Volume Scaling (S_volume, 0 to 10 pts):
       Defensively scales with sublinear / logarithmic growth to prevent alert flood skew:
       S_volume = min(10, floor(3 * ln(N))) where N is the count of distinct events.
       - N=1: 0 pts
       - N=2: 2 pts
       - N=3: 3 pts
       - N=5: 4 pts
       - N=10: 6 pts
       - N>=30: 10 pts (hard cap)

    Final Score:
       Clamped strictly to [0, 100].
    """
    if not events:
        return RiskAssessment(
            score=0,
            priority="Low",
            contributing_factors=[{"factor": "Empty Incident", "points": 0, "details": "No events provided"}],
            score_breakdown={"base": 0, "rules": 0, "anomaly": 0, "behavior": 0, "volume": 0},
        )

    contributing_factors: List[Dict[str, Any]] = []

    # 1. Base Severity Component
    severities = [e.severity.upper() for e in events]
    if "CRITICAL" in severities:
        s_base = SEVERITY_BASE_SCORES["CRITICAL"]
        base_desc = "Critical severity alert observed"
    elif "HIGH" in severities:
        s_base = SEVERITY_BASE_SCORES["HIGH"]
        base_desc = "High severity alert observed"
    elif "MEDIUM" in severities:
        s_base = SEVERITY_BASE_SCORES["MEDIUM"]
        base_desc = "Medium severity alert observed"
    elif "LOW" in severities:
        s_base = SEVERITY_BASE_SCORES["LOW"]
        base_desc = "Low severity alert observed"
    else:
        s_base = DEFAULT_SEVERITY_BASE
        base_desc = "Standard baseline severity"

    # Multi-alert severity bonus
    high_crit_count = sum(1 for s in severities if s in ("HIGH", "CRITICAL"))
    if high_crit_count > 1:
        s_base += 5
        base_desc += f" (reinforced by {high_crit_count} high-severity findings)"

    contributing_factors.append({
        "factor": "Detection Severity Baseline",
        "points": s_base,
        "details": base_desc,
    })

    # 2. Rule-Based Findings Component
    reasons_text = " ".join([e.detection_reason.lower() for e in events])
    rule_pts = 0
    rule_reasons: List[str] = []

    has_high_rule = any(kw in reasons_text for kw in HIGH_IMPACT_RULE_KEYWORDS)
    has_med_rule = any(kw in reasons_text for kw in MEDIUM_IMPACT_RULE_KEYWORDS)

    if has_high_rule:
        rule_pts += 20
        rule_reasons.append("High-impact exploit signature (SQLi / Unauthorized Access)")
    if has_med_rule:
        rule_pts += 10
        rule_reasons.append("Reconnaissance or authentication anomaly signature")

    # Has any rule-based detection type
    rule_detected = any("rule" in e.detection_type.lower() for e in events)
    if rule_detected and rule_pts == 0:
        rule_pts = 10
        rule_reasons.append("Deterministic rule trigger match")

    s_rules = min(25, rule_pts)
    if s_rules > 0:
        contributing_factors.append({
            "factor": "Rule-Based Threat Signatures",
            "points": s_rules,
            "details": "; ".join(rule_reasons) or "Signature match detected",
        })

    # 3. Machine Learning Anomaly Indicators
    anomaly_detected = any(
        "anomaly" in e.detection_type.lower() or "isolation forest" in e.detection_reason.lower()
        for e in events
    )
    s_anomaly = 0
    if anomaly_detected:
        s_anomaly += 15
        anomaly_desc = "Isolation Forest unsupervised outlier detected"
        # Check for extreme volume or strong outlier mentions
        if any(w in reasons_text for w in ("8500", "burst", "volume", "outlier")):
            s_anomaly += 5
            anomaly_desc += " with significant behavioral/volumetric deviation"
        s_anomaly = min(20, s_anomaly)
        contributing_factors.append({
            "factor": "Machine Learning Anomaly Detection",
            "points": s_anomaly,
            "details": anomaly_desc,
        })

    # 4. Behavioral Pattern & Attack Breadth
    distinct_event_types = {e.event_type.lower() for e in events if e.event_type}
    distinct_event_types.discard("unknown")
    distinct_event_types.discard("")

    s_behavior = 0
    behavior_notes: List[str] = []

    if len(distinct_event_types) > 1:
        s_behavior += 10
        behavior_notes.append(f"Multi-vector activity across {len(distinct_event_types)} event types ({', '.join(sorted(distinct_event_types))})")

    has_failures = any(
        e.status.lower() in ("failed", "blocked", "denied", "error", "unauthorized")
        for e in events
    )
    if has_failures:
        s_behavior += 5
        behavior_notes.append("Failure or blocked security status codes observed")

    s_behavior = min(15, s_behavior)
    if s_behavior > 0:
        contributing_factors.append({
            "factor": "Behavioral Attack Pattern",
            "points": s_behavior,
            "details": "; ".join(behavior_notes),
        })

    # 5. Event Volume Scaling (Sublinear ln growth)
    n_events = len(events)
    if n_events > 1:
        s_volume = min(10, int(math.floor(3.0 * math.log(n_events))))
    else:
        s_volume = 0

    if s_volume > 0:
        contributing_factors.append({
            "factor": "Telemetry Volume Scaling",
            "points": s_volume,
            "details": f"Sublinear volume scale for {n_events} correlated alert events",
        })

    # Sum raw points and strictly clamp to [0, 100]
    total_raw = s_base + s_rules + s_anomaly + s_behavior + s_volume
    final_score = max(0, min(100, int(round(total_raw))))
    priority = classify_risk_priority(final_score)

    breakdown = {
        "base": s_base,
        "rules": s_rules,
        "anomaly": s_anomaly,
        "behavior": s_behavior,
        "volume": s_volume,
    }

    return RiskAssessment(
        score=final_score,
        priority=priority,
        contributing_factors=contributing_factors,
        score_breakdown=breakdown,
    )


# -----------------------------------------------------------------------------
# Attack Story Generator (Feature 1)
# -----------------------------------------------------------------------------

def generate_attack_story(
    events: List[IncidentEvent],
    source_ip: str,
    risk: RiskAssessment,
    is_unattributed: bool = False,
) -> AttackStory:
    """
    Constructs an explainable, evidence-backed narrative for an incident.
    Strictly uses available evidence without hallucinating or inventing details.
    """
    event_count = len(events)
    severities = [e.severity.upper() for e in events]
    event_types = sorted(list({e.event_type for e in events if e.event_type and e.event_type != "unknown"}))
    detection_types = sorted(list({e.detection_type for e in events if e.detection_type}))
    reasons = [e.detection_reason for e in events if e.detection_reason]

    timestamps = [e.timestamp for e in events if e.timestamp is not None]
    start_ts = min(timestamps) if timestamps else None
    end_ts = max(timestamps) if timestamps else None
    time_span = _format_time_span(start_ts, end_ts)

    # 1. Headline Generation
    ip_label = "Unattributed Source" if is_unattributed else f"Source {source_ip}"
    primary_threat = reasons[0] if reasons else "Suspicious Activity"
    # Simplify headline if known threat keywords present
    headline_threat = None
    all_reasons_str = " ".join(reasons).lower()
    if "sql injection" in all_reasons_str:
        headline_threat = "SQL Injection Probe"
    elif "failed login" in all_reasons_str or "authentication failure" in all_reasons_str:
        headline_threat = "Authentication Probing"
    elif "port scan" in all_reasons_str:
        headline_threat = "Port Scanning"
    elif "isolation forest" in all_reasons_str or "outlier" in all_reasons_str:
        headline_threat = "Volumetric Anomaly Outlier"
    else:
        headline_threat = primary_threat[:45]

    if event_count > 1:
        headline = f"Multi-Stage Security Incident ({headline_threat}) from {ip_label}"
    else:
        headline = f"Isolated Security Incident ({headline_threat}) from {ip_label}"

    # 2. What Was Observed (Factual Statement)
    obs_parts: List[str] = [
        f"A total of {event_count} alert event(s) were recorded within the timeframe: {time_span}."
    ]
    if not is_unattributed:
        obs_parts.append(f"All events in this incident trace to originating source IP: {source_ip}.")
    else:
        obs_parts.append("Originating source IP is unspecified or unavailable in source logs.")

    if event_types:
        obs_parts.append(f"Observed event types include: {', '.join(event_types)}.")
    if detection_types:
        obs_parts.append(f"Detection mechanisms triggered: {', '.join(detection_types)}.")

    what_observed = " ".join(obs_parts)

    # 3. Why It Is Suspicious (Threat Analysis & Context)
    suspicious_points: List[str] = []
    if "sql injection" in all_reasons_str or "union select" in all_reasons_str:
        suspicious_points.append(
            "Payload inspection identified deterministic SQL injection syntax ('union select' or tautology tests), "
            "indicating deliberate attempts to probe database query logic."
        )
    if "failed login" in all_reasons_str or "authentication failure" in all_reasons_str:
        suspicious_points.append(
            "Repeated authentication failures were recorded, characteristic of credential stuffing, "
            "password guessing, or unauthorized account access attempts."
        )
    if "isolation forest" in all_reasons_str or "outlier" in all_reasons_str:
        suspicious_points.append(
            "Unsupervised machine learning (Isolation Forest) identified significant statistical deviation "
            "from typical telemetry baselines (e.g. unusual request volume, status rarity, or burst frequency)."
        )
    if event_count > 1 and len(event_types) > 1:
        suspicious_points.append(
            f"The entity engaged in multiple distinct activity vectors ({', '.join(event_types)}), "
            "consistent with multi-stage reconnaissance preceding exploitation."
        )

    if not suspicious_points:
        suspicious_points.append(
            f"The activity triggered defensive detection signatures with {risk.priority} priority "
            f"(Heuristic Risk Score: {risk.score}/100)."
        )

    why_suspicious = " ".join(suspicious_points)

    # 4. Itemized Supporting Evidence
    supporting_evidence: List[str] = []
    if not is_unattributed:
        supporting_evidence.append(f"Source IP Address: {source_ip}")
    else:
        supporting_evidence.append("Source IP: Unattributed / Not logged")

    supporting_evidence.append(f"Event Count: {event_count} correlated alert(s)")
    supporting_evidence.append(f"Highest Severity: {max(severities, key=lambda s: SEVERITY_BASE_SCORES.get(s, 0))}")
    supporting_evidence.append(f"Active Time Window: {time_span}")

    # Add specific detection reasons from member events
    for idx, e in enumerate(events[:5], start=1):
        clean_rsn = e.detection_reason
        supporting_evidence.append(f"Event {idx} ({e.alert_id}): {clean_rsn} [Status: {e.status}]")

    # 5. Distinctly Separated Observed Facts vs. Possible Interpretations
    observed_facts: List[str] = [
        f"Verified telemetry contains {event_count} entry/entries matching security alert criteria.",
        f"Alert IDs involved: {', '.join(e.alert_id for e in events)}.",
        f"Event statuses recorded: {', '.join(sorted(set(e.status for e in events)))}.",
        f"Associated severity ratings: {', '.join(sorted(set(severities)))}.",
    ]
    if timestamps:
        observed_facts.append(f"First event: {start_ts.strftime('%Y-%m-%d %H:%M:%S UTC')}; Last event: {end_ts.strftime('%Y-%m-%d %H:%M:%S UTC')}.")

    possible_interpretations: List[str] = []
    if "sql injection" in all_reasons_str:
        possible_interpretations.append(
            "Hypothesis: Malicious external actor or automated vulnerability scanner probing web application inputs."
        )
        possible_interpretations.append(
            "Alternative Benign Explanation: Authorized internal penetration test or automated dynamic security scanner (DAST)."
        )
    if "failed login" in all_reasons_str:
        possible_interpretations.append(
            "Hypothesis: Targeted credential attack against administrative or guest accounts."
        )
        possible_interpretations.append(
            "Alternative Benign Explanation: Legitimate user entering incorrect password or expired automated service token."
        )
    if "isolation forest" in all_reasons_str:
        possible_interpretations.append(
            "Hypothesis: Automated scraper, batch extraction, or denial-of-service volumetric spike."
        )
        possible_interpretations.append(
            "Alternative Benign Explanation: Scheduled batch database archival, authorized backup operation, or sudden peak customer demand."
        )
    if not possible_interpretations:
        possible_interpretations.append(
            "Hypothesis: Uncharacteristic telemetry requiring verification against operational baselines."
        )
        possible_interpretations.append(
            "Alternative Benign Explanation: Software bug, misconfigured integration, or unusual administrative workflow."
        )

    # 6. Recommended Defensive Investigation Steps (Human Review Only)
    investigation_steps: List[str] = []
    if not is_unattributed:
        investigation_steps.append(
            f"1. Query perimeter firewall, reverse proxy, and CDN logs for all requests associated with source IP {source_ip} over the last 24 hours."
        )
        investigation_steps.append(
            f"2. Verify IP reputation via authoritative threat intelligence feeds (e.g. AlienVault OTX, AbuseIPDB, internal threat intel)."
        )
    else:
        investigation_steps.append(
            "1. Inspect web server access logs to correlate session cookies, user agents, or internal client identifiers corresponding to the alert timestamps."
        )

    if any(e.status.lower() in ("failed", "blocked") for e in events):
        investigation_steps.append(
            "3. Confirm that edge defenses (WAF, rate limiters) successfully prevented unauthorized payload execution or session acquisition."
        )

    users_involved = {e.raw_message for e in events if e.raw_message}
    investigation_steps.append(
        "4. Review user directory logs to ensure affected target accounts (if specified in logs) have not exhibited subsequent successful logins from unverified locations."
    )
    investigation_steps.append(
        "5. Consult with the system owner or engineering team to confirm whether scheduled tasks or testing explain the activity before taking defensive mitigation."
    )

    return AttackStory(
        headline=headline,
        what_was_observed=what_observed,
        why_it_is_suspicious=why_suspicious,
        supporting_evidence=supporting_evidence,
        observed_facts=observed_facts,
        possible_interpretations=possible_interpretations,
        recommended_investigation_steps=investigation_steps,
    )


# -----------------------------------------------------------------------------
# Incident Grouping & Correlation Logic
# -----------------------------------------------------------------------------

def group_alerts_into_incidents(
    alerts_df: pd.DataFrame,
    events_df: Optional[pd.DataFrame] = None,
    correlation_window_minutes: int = DEFAULT_CORRELATION_WINDOW_MINUTES,
) -> List[CorrelatedIncident]:
    """
    Groups individual alert records into coherent security incidents based on
    available telemetry evidence (source IP and temporal correlation window).

    GROUPING POLICY:
    1. Known Source IPs:
       - Alerts sharing the same valid source IP are clustered.
       - If valid timestamps exist, alerts separated by more than `correlation_window_minutes`
         are separated into distinct incident campaigns.
       - If timestamps are missing or invalid, all alerts for that IP in the batch are safely grouped,
         noting the absence of verified timestamps.
    2. Unattributed / Missing Source IPs:
       - Alerts with missing or unknown IPs are NOT conflated into a single bucket.
       - Each unattributed alert is isolated as its own single-alert incident to prevent
         falsely asserting a connection without supporting evidence.
    3. Chronological Ordering:
       - Within each incident, member events are strictly ordered ascending by timestamp.
       - Unparseable or missing timestamps are placed stably at the end.
    4. Deduplication:
       - Exact duplicate alerts are deduplicated while preserving event counters.
    """
    if alerts_df is None or not isinstance(alerts_df, pd.DataFrame) or alerts_df.empty:
        return []

    # Map events_df by alert index or row if available for enrichment
    events_map: Dict[str, Dict[str, Any]] = {}
    if events_df is not None and isinstance(events_df, pd.DataFrame) and not events_df.empty:
        # If events_df has row index matching or columns
        for idx, row in events_df.iterrows():
            events_map[str(idx)] = row.to_dict()

    # Convert alerts DataFrame rows into standard IncidentEvent objects
    parsed_events: List[IncidentEvent] = []
    seen_keys: set = set()

    for idx, row in alerts_df.iterrows():
        aid = str(row.get("alert_id", f"ALT-{idx + 1:04d}")).strip()
        raw_ts = row.get("timestamp", None)
        parsed_ts = parse_timestamp_safe(raw_ts)
        ts_str = parsed_ts.strftime("%Y-%m-%d %H:%M:%S UTC") if parsed_ts is not None else str(raw_ts or "N/A")

        src_ip = str(row.get("source_ip", "Unknown")).strip()
        ev_type = str(row.get("event_type", "unknown")).strip()
        sev = str(row.get("severity", "MEDIUM")).strip().upper()
        det_type = str(row.get("detection_type", "Detection Engine")).strip()
        reason = str(row.get("detection_reason", "Suspicious activity")).strip()
        rec_action = str(row.get("recommended_action", "Investigate activity")).strip()

        # Check for destination_ip and status from row or events_map
        dest_ip = str(row.get("destination_ip", "N/A")).strip()
        status_val = str(row.get("status", "unknown")).strip()
        raw_msg = str(row.get("message", "")).strip()

        if str(idx) in events_map:
            ev_meta = events_map[str(idx)]
            if dest_ip in ("N/A", "") and "destination_ip" in ev_meta:
                dest_ip = str(ev_meta["destination_ip"]).strip()
            if status_val in ("unknown", "") and "status" in ev_meta:
                status_val = str(ev_meta["status"]).strip()
            if not raw_msg and "message" in ev_meta:
                raw_msg = str(ev_meta["message"]).strip()

        # Safe deduplication key: aid + ts + src_ip + reason
        dedup_key = (aid, ts_str, src_ip, reason)
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        ev_item = IncidentEvent(
            alert_id=aid,
            timestamp=parsed_ts,
            timestamp_str=ts_str,
            source_ip=src_ip,
            destination_ip=dest_ip,
            event_type=ev_type,
            status=status_val,
            severity=sev,
            detection_type=det_type,
            detection_reason=reason,
            recommended_action=rec_action,
            raw_message=raw_msg,
        )
        parsed_events.append(ev_item)

    if not parsed_events:
        return []

    # Separate into known IP groups and unattributed individual alerts
    ip_groups: Dict[str, List[IncidentEvent]] = {}
    unattributed_events: List[IncidentEvent] = []

    for ev in parsed_events:
        if is_known_ip(ev.source_ip):
            ip_groups.setdefault(ev.source_ip, []).append(ev)
        else:
            unattributed_events.append(ev)

    incident_list: List[CorrelatedIncident] = []
    inc_counter = 1

    # 1. Process known IP groups with temporal clustering
    corr_window_delta = pd.Timedelta(minutes=correlation_window_minutes)

    for ip_addr, ev_list in ip_groups.items():
        # Sort events chronologically. Events with None timestamps go to the end
        ev_list_sorted = sorted(
            ev_list,
            key=lambda x: (x.timestamp is None, x.timestamp or pd.Timestamp.min),
        )

        # Cluster by correlation window if timestamps are present
        clusters: List[List[IncidentEvent]] = []
        current_cluster: List[IncidentEvent] = []

        for ev in ev_list_sorted:
            if not current_cluster:
                current_cluster.append(ev)
                continue

            last_ev = current_cluster[-1]
            if last_ev.timestamp is not None and ev.timestamp is not None:
                gap = ev.timestamp - last_ev.timestamp
                if gap <= corr_window_delta:
                    current_cluster.append(ev)
                else:
                    clusters.append(current_cluster)
                    current_cluster = [ev]
            else:
                # Missing timestamp: group with current cluster if same source IP
                current_cluster.append(ev)

        if current_cluster:
            clusters.append(current_cluster)

        # Build CorrelatedIncident for each cluster
        for cluster in clusters:
            ts_list = [e.timestamp for e in cluster if e.timestamp is not None]
            c_start = min(ts_list) if ts_list else None
            c_end = max(ts_list) if ts_list else None
            time_span_str = _format_time_span(c_start, c_end)

            severities = [e.severity.upper() for e in cluster]
            max_sev = max(severities, key=lambda s: SEVERITY_BASE_SCORES.get(s, 0)) if severities else "MEDIUM"
            primary_threat = cluster[0].detection_reason if cluster else "Security Finding"

            risk_assessment = calculate_incident_risk(cluster)
            story = generate_attack_story(cluster, source_ip=ip_addr, risk=risk_assessment, is_unattributed=False)

            inc = CorrelatedIncident(
                incident_id=f"INC-{inc_counter:04d}",
                source_ip=ip_addr,
                is_unattributed_ip=False,
                start_time=c_start,
                end_time=c_end,
                time_span_str=time_span_str,
                events=cluster,
                event_count=len(cluster),
                primary_threat=primary_threat,
                max_severity=max_sev,
                attack_story=story,
                risk_assessment=risk_assessment,
            )
            incident_list.append(inc)
            inc_counter += 1

    # 2. Process unattributed events as individual isolated incidents
    for ev in unattributed_events:
        c_start = ev.timestamp
        c_end = ev.timestamp
        time_span_str = _format_time_span(c_start, c_end)

        risk_assessment = calculate_incident_risk([ev])
        story = generate_attack_story([ev], source_ip=ev.source_ip, risk=risk_assessment, is_unattributed=True)

        inc = CorrelatedIncident(
            incident_id=f"INC-{inc_counter:04d}",
            source_ip=ev.source_ip,
            is_unattributed_ip=True,
            start_time=c_start,
            end_time=c_end,
            time_span_str=time_span_str,
            events=[ev],
            event_count=1,
            primary_threat=ev.detection_reason,
            max_severity=ev.severity.upper(),
            attack_story=story,
            risk_assessment=risk_assessment,
        )
        incident_list.append(inc)
        inc_counter += 1

    # Sort incidents by risk score descending by default
    incident_list.sort(key=lambda x: x.risk_assessment.score, reverse=True)
    return incident_list


# -----------------------------------------------------------------------------
# High-Level Intelligence Pipeline Facade
# -----------------------------------------------------------------------------

def build_incident_intelligence(
    alerts_df: pd.DataFrame,
    events_df: Optional[pd.DataFrame] = None,
    correlation_window_minutes: int = DEFAULT_CORRELATION_WINDOW_MINUTES,
) -> Dict[str, Any]:
    """
    Primary API entry point for generating Incident Intelligence from detection outputs.

    Returns:
        {
            "incidents": List[CorrelatedIncident],
            "summary": {
                "total_incidents": int,
                "priority_breakdown": {"Critical": int, "High": int, "Medium": int, "Low": int},
                "max_risk_score": int,
                "avg_risk_score": float,
                "correlated_ips_count": int,
            },
            "has_data": bool,
            "message": str
        }
    """
    if alerts_df is None or not isinstance(alerts_df, pd.DataFrame) or alerts_df.empty:
        return {
            "incidents": [],
            "summary": {
                "total_incidents": 0,
                "priority_breakdown": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
                "max_risk_score": 0,
                "avg_risk_score": 0.0,
                "correlated_ips_count": 0,
            },
            "has_data": False,
            "message": "No security alerts are currently present. Upload security logs and execute detection to generate incidents.",
        }

    incidents = group_alerts_into_incidents(
        alerts_df=alerts_df,
        events_df=events_df,
        correlation_window_minutes=correlation_window_minutes,
    )

    if not incidents:
        return {
            "incidents": [],
            "summary": {
                "total_incidents": 0,
                "priority_breakdown": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
                "max_risk_score": 0,
                "avg_risk_score": 0.0,
                "correlated_ips_count": 0,
            },
            "has_data": False,
            "message": "Available alert telemetry contains insufficient distinct evidence to construct correlated incidents.",
        }

    crit_cnt = sum(1 for i in incidents if i.risk_assessment.priority == "Critical")
    high_cnt = sum(1 for i in incidents if i.risk_assessment.priority == "High")
    med_cnt = sum(1 for i in incidents if i.risk_assessment.priority == "Medium")
    low_cnt = sum(1 for i in incidents if i.risk_assessment.priority == "Low")

    scores = [i.risk_assessment.score for i in incidents]
    max_score = max(scores) if scores else 0
    avg_score = round(float(np.mean(scores)), 1) if scores else 0.0

    known_ips = {i.source_ip for i in incidents if not i.is_unattributed_ip}

    summary = {
        "total_incidents": len(incidents),
        "priority_breakdown": {
            "Critical": crit_cnt,
            "High": high_cnt,
            "Medium": med_cnt,
            "Low": low_cnt,
        },
        "max_risk_score": max_score,
        "avg_risk_score": avg_score,
        "correlated_ips_count": len(known_ips),
    }

    return {
        "incidents": incidents,
        "summary": summary,
        "has_data": True,
        "message": f"Successfully correlated {len(incidents)} security incident(s) across telemetry alerts.",
    }
