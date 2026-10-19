"""
detector.py - Detection Engine & Backend Integration Adapter
Member 1 / Member 2 Integration Bridge

Connects the Streamlit cybersecurity dashboard to Member 2's Express/Node.js
backend service (POST /api/analyze-logs) and provides Isolation Forest machine
learning anomaly detection across ingested security log telemetry.
"""

from typing import Dict, Any, List, Optional, Tuple, Set
import os
import requests
import numpy as np
import pandas as pd

# Optional scikit-learn import with graceful fallback if package is not yet installed
try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    IsolationForest = None
    SKLEARN_AVAILABLE = False


# Default backend API endpoint configuration
DEFAULT_API_BASE_URL: str = os.getenv("CYBER_AGENT_API_URL", "http://localhost:5000")
DEFAULT_API_TIMEOUT: float = float(os.getenv("CYBER_AGENT_API_TIMEOUT", "10.0"))

# Isolation Forest configuration defaults
DEFAULT_CONTAMINATION: float = float(os.getenv("CYBER_AGENT_CONTAMINATION", "0.05"))
DEFAULT_RANDOM_STATE: int = 42
MIN_SAMPLES_FOR_ANOMALY: int = 5

# Required schema columns for alerts
ALERT_COLUMNS: List[str] = [
    "alert_id",
    "timestamp",
    "source_ip",
    "event_type",
    "severity",
    "detection_type",
    "detection_reason",
    "recommended_action",
]


def _build_log_string(row: pd.Series) -> str:
    """
    Constructs a minimal, non-sensitive string representation of an ingested log
    record to evaluate against detection patterns in Member 2's backend.

    Excludes sensitive identifiers (usernames, internal network IP maps, passwords)
    while preserving event type, status, and message context.
    """
    msg = str(row.get("message", "")).strip() if pd.notna(row.get("message")) else ""
    event_type = (
        str(row.get("event_type", "")).strip()
        if pd.notna(row.get("event_type"))
        else ""
    )
    status = (
        str(row.get("status", "")).strip() if pd.notna(row.get("status")) else ""
    )

    parts: List[str] = []
    if event_type and event_type.lower() != "unknown":
        parts.append(event_type)
    if status and status.lower() != "unknown":
        parts.append(status)
    if msg:
        parts.append(msg)

    return " - ".join(parts) if parts else (msg or "system event")


def _empty_alerts_df() -> pd.DataFrame:
    """Returns an empty DataFrame containing all required alert columns."""
    return pd.DataFrame(columns=ALERT_COLUMNS)


def _call_backend_api(
    logs: List[str], api_base_url: str, timeout: float
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Submits log lines to Member 2's Express backend API (POST /api/analyze-logs).

    Returns:
        Tuple of (response_data, error_warning_message)
    """
    url = f"{api_base_url.rstrip('/')}/api/analyze-logs"
    payload = {"logs": logs}

    try:
        response = requests.post(
            url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )

        if response.status_code != 200:
            err_detail = response.text[:200] if response.text else "No error details"
            return (
                None,
                f"Backend service at {url} returned HTTP {response.status_code}: {err_detail}",
            )

        try:
            data = response.json()
        except Exception as json_err:
            return (
                None,
                f"Backend service at {url} returned invalid JSON: {str(json_err)}",
            )

        if not isinstance(data, dict):
            return (
                None,
                f"Backend service at {url} returned unexpected response format (expected JSON object).",
            )

        return data, None

    except requests.exceptions.Timeout:
        return (
            None,
            f"Backend service at {url} timed out after {timeout} seconds.",
        )
    except requests.exceptions.ConnectionError:
        return (
            None,
            f"Unable to connect to backend detection service at {url}. "
            "Please verify that Member 2's Express server is running (e.g. 'node backend/server.js').",
        )
    except requests.exceptions.RequestException as req_err:
        return (
            None,
            f"Network request to backend service at {url} failed: {str(req_err)}",
        )
    except Exception as unexpected_err:
        return (
            None,
            f"Unexpected error communicating with backend service at {url}: {str(unexpected_err)}",
        )


def _extract_anomaly_features(
    df: pd.DataFrame,
) -> Tuple[Optional[pd.DataFrame], Optional[str]]:
    """
    Extracts statistical and behavioral telemetry features from the input DataFrame
    for Isolation Forest anomaly detection.

    DEFENSIBLE FEATURE ENGINEERING POLICY:
    1. log_request_count: Log-scaled request/event count (np.log1p) to normalize burst rates.
    2. is_failure_status: Indicator (1.0 / 0.0) for security events with failure/blocked/error status.
    3. event_type_rarity: Inverted event type frequency (1.0 - freq). Rare event types have higher rarity.
    4. status_rarity: Inverted status frequency (1.0 - freq). Rare statuses have higher rarity.
    5. source_ip_event_share: Normalized batch event volume per source IP (frequency of events from this IP).
       NOTE: IP addresses are NEVER mapped to arbitrary numeric magnitudes or integers.

    Returns:
        Tuple of (features_dataframe, reason_if_skipped)
    """
    if len(df) < MIN_SAMPLES_FOR_ANOMALY:
        return (
            None,
            f"Dataset has {len(df)} record(s); minimum required for anomaly detection is {MIN_SAMPLES_FOR_ANOMALY}.",
        )

    features: Dict[str, Any] = {}

    # Feature 1: request_count (log-transformed)
    if "request_count" in df.columns:
        num_counts = (
            pd.to_numeric(df["request_count"], errors="coerce")
            .fillna(1.0)
            .clip(lower=0.0)
        )
        features["log_request_count"] = np.log1p(num_counts).values
    else:
        features["log_request_count"] = np.zeros(len(df), dtype=float)

    # Feature 2 & 3: status-based indicators
    if "status" in df.columns:
        st_clean = df["status"].astype(str).str.lower().str.strip()
        features["is_failure_status"] = (
            st_clean.isin(["failed", "blocked", "denied", "error", "unauthorized"])
            .astype(float)
            .values
        )
        st_freq = (
            st_clean.map(st_clean.value_counts(normalize=True))
            .fillna(0.0)
            .astype(float)
            .values
        )
        features["status_rarity"] = 1.0 - st_freq
    else:
        features["is_failure_status"] = np.zeros(len(df), dtype=float)
        features["status_rarity"] = np.zeros(len(df), dtype=float)

    # Feature 4: event_type rarity
    if "event_type" in df.columns:
        et_clean = df["event_type"].astype(str).str.lower().str.strip()
        et_freq = (
            et_clean.map(et_clean.value_counts(normalize=True))
            .fillna(0.0)
            .astype(float)
            .values
        )
        features["event_type_rarity"] = 1.0 - et_freq
    else:
        features["event_type_rarity"] = np.zeros(len(df), dtype=float)

    # Feature 5: source IP concentration (share of total events from this source)
    if "source_ip" in df.columns:
        ip_clean = df["source_ip"].astype(str).str.strip()
        ip_freq = (
            ip_clean.map(ip_clean.value_counts(normalize=True))
            .fillna(0.0)
            .astype(float)
            .values
        )
        features["source_ip_event_share"] = ip_freq
    else:
        features["source_ip_event_share"] = np.zeros(len(df), dtype=float)

    features_df = pd.DataFrame(features, index=df.index)

    # Sanitize non-finite values (NaN, inf, -inf)
    features_df = features_df.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    # Guard against constant / zero-variance dataset
    variances = features_df.var()
    if variances.sum() == 0.0 or (features_df.nunique() <= 1).all():
        return (
            None,
            "Input features have zero variance across all records; statistical outliers cannot be isolated.",
        )

    return features_df, None


def _run_isolation_forest(
    events_df: pd.DataFrame,
    contamination: float,
    random_state: int,
) -> Tuple[Optional[np.ndarray], Optional[np.ndarray], Optional[str]]:
    """
    Fits Isolation Forest and computes anomaly scores and labels.

    Score semantics:
    - decision_scores: Scikit-learn decision_function output.
      Negative values correspond to anomalies (isolated faster / statistical outliers),
      positive values correspond to inliers (require deeper tree splits / typical patterns).
    - is_anomaly: Boolean array where True indicates prediction == -1.
    """
    if not SKLEARN_AVAILABLE or IsolationForest is None:
        return (
            None,
            None,
            "scikit-learn is not installed in the environment; Isolation Forest anomaly detection was skipped. "
            "Install scikit-learn from requirements.txt to enable machine learning anomaly detection.",
        )

    features_df, skip_reason = _extract_anomaly_features(events_df)
    if skip_reason is not None or features_df is None:
        return None, None, skip_reason

    try:
        # Contamination must be within (0, 0.5]
        safe_contamination = max(0.01, min(0.5, float(contamination)))
        model = IsolationForest(
            n_estimators=100,
            contamination=safe_contamination,
            random_state=random_state,
            n_jobs=1,
        )
        model.fit(features_df)
        decision_scores = model.decision_function(features_df)
        predictions = model.predict(features_df)
        is_anomaly = (predictions == -1)
        return decision_scores, is_anomaly, None
    except Exception as exc:
        return None, None, f"Isolation Forest training failed: {str(exc)}"


def run_full_detection_pipeline(
    df: pd.DataFrame,
    api_base_url: Optional[str] = None,
    timeout: Optional[float] = None,
    contamination: Optional[float] = None,
    random_state: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Executes the full defensive detection pipeline across ingested security logs.
    Combines Member 2's Express API rule-based detection with scikit-learn
    Isolation Forest unsupervised anomaly detection.

    Public interface expected by app.py:
        run_full_detection_pipeline(df: pandas.DataFrame) -> dict

    Returns:
        {
            "events": pandas.DataFrame,
            "alerts": pandas.DataFrame,
            "summary": {
                "total_events": int,
                "total_alerts": int,
                "severity_breakdown": {
                    "CRITICAL": int,
                    "HIGH": int,
                    "MEDIUM": int,
                    "LOW": int
                },
                "rule_alert_count": int,
                "anomaly_alert_count": int,
                "top_offending_ips": dict,
                "common_threats": dict
            },
            "warnings": list
        }
    """
    base_url = (api_base_url or DEFAULT_API_BASE_URL).rstrip("/")
    request_timeout = timeout if timeout is not None else DEFAULT_API_TIMEOUT
    model_contamination = (
        contamination if contamination is not None else DEFAULT_CONTAMINATION
    )
    model_random_state = (
        random_state if random_state is not None else DEFAULT_RANDOM_STATE
    )

    warnings: List[str] = []

    # 1. Guard against None or invalid DataFrame input
    if df is None or not isinstance(df, pd.DataFrame):
        warnings.append("Pipeline received invalid input: expected a pandas DataFrame.")
        return {
            "events": pd.DataFrame(),
            "alerts": _empty_alerts_df(),
            "summary": {
                "total_events": 0,
                "total_alerts": 0,
                "severity_breakdown": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                },
                "rule_alert_count": 0,
                "anomaly_alert_count": 0,
                "top_offending_ips": {},
                "common_threats": {},
            },
            "warnings": warnings,
        }

    # 2. Guard against empty DataFrame input (avoid calling backend API with empty payload)
    if df.empty:
        warnings.append("No security log records provided for analysis.")
        return {
            "events": df.copy(),
            "alerts": _empty_alerts_df(),
            "summary": {
                "total_events": 0,
                "total_alerts": 0,
                "severity_breakdown": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                },
                "rule_alert_count": 0,
                "anomaly_alert_count": 0,
                "top_offending_ips": {},
                "common_threats": {},
            },
            "warnings": warnings,
        }

    # Defensive copy to avoid mutating the caller's DataFrame
    events_df = df.copy()

    # 3. Format minimal log representations for pattern analysis
    log_strings = [_build_log_string(row) for _, row in events_df.iterrows()]

    # 4. Invoke Member 2's Express backend API for rule-based analysis
    backend_data, api_error = _call_backend_api(
        log_strings, api_base_url=base_url, timeout=request_timeout
    )

    alert_records: List[Dict[str, Any]] = []
    rule_flagged_indices: Set[int] = set()

    if api_error:
        warnings.append(api_error)
    elif backend_data is not None:
        raw_results = backend_data.get("results")
        if not isinstance(raw_results, list):
            warnings.append(
                f"Backend response missing 'results' array: received keys {list(backend_data.keys())}."
            )
        else:
            if len(raw_results) != len(events_df):
                warnings.append(
                    f"Backend returned {len(raw_results)} results for {len(events_df)} submitted records; "
                    "mapping alerts to matching record indices."
                )

            num_to_process = min(len(events_df), len(raw_results))
            for idx in range(num_to_process):
                res = raw_results[idx]
                if not isinstance(res, dict):
                    continue

                # A record is an alert ONLY if explicitly identified as suspicious
                if res.get("suspicious") is True:
                    rule_flagged_indices.add(idx)
                    orig_row = events_df.iloc[idx]

                    raw_alerts = res.get("alerts")
                    if isinstance(raw_alerts, list) and raw_alerts:
                        reason = ", ".join(str(a) for a in raw_alerts)
                    elif isinstance(raw_alerts, str) and raw_alerts.strip():
                        reason = raw_alerts.strip()
                    else:
                        reason = "Suspicious rule match"

                    rec = (
                        str(res.get("recommendation", "")).strip()
                        or "Investigate immediately and review the related security logs."
                    )

                    raw_sev = str(res.get("severity", "MEDIUM")).strip().upper()
                    severity = (
                        raw_sev
                        if raw_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
                        else "MEDIUM"
                    )

                    alert_records.append(
                        {
                            "alert_id": f"ALT-{len(alert_records) + 1:04d}",
                            "timestamp": orig_row.get("timestamp", "N/A"),
                            "source_ip": orig_row.get("source_ip", "Unknown"),
                            "event_type": orig_row.get("event_type", "unknown"),
                            "severity": severity,
                            "detection_type": "Rule-Based",
                            "detection_reason": reason,
                            "recommended_action": rec,
                        }
                    )

    rule_alert_count = len(alert_records)

    # 5. Execute Isolation Forest Anomaly Detection
    decision_scores, is_anomaly, anomaly_notice = _run_isolation_forest(
        events_df,
        contamination=model_contamination,
        random_state=model_random_state,
    )

    anomaly_alert_count = 0
    if anomaly_notice is not None:
        warnings.append(anomaly_notice)

    if decision_scores is not None and is_anomaly is not None:
        # Attach telemetry to events DataFrame (negative score = anomaly, positive = inlier)
        events_df["anomaly_score"] = np.round(decision_scores, 4)
        events_df["is_anomaly"] = is_anomaly.tolist()

        # Generate anomaly alerts for records not already flagged by rule matches
        for idx, flag in enumerate(is_anomaly):
            if flag:
                if idx in rule_flagged_indices:
                    # Do not duplicate an existing alert for the same event row
                    continue

                orig_row = events_df.iloc[idx]
                score_val = float(decision_scores[idx])

                alert_records.append(
                    {
                        "alert_id": f"ALT-{len(alert_records) + 1:04d}",
                        "timestamp": orig_row.get("timestamp", "N/A"),
                        "source_ip": orig_row.get("source_ip", "Unknown"),
                        "event_type": orig_row.get("event_type", "unknown"),
                        "severity": "MEDIUM",
                        "detection_type": "Anomaly Detection",
                        "detection_reason": (
                            f"Statistical outlier detected by Isolation Forest (score: {score_val:.3f}; "
                            "unusual activity volume or status pattern)"
                        ),
                        "recommended_action": (
                            "Review event telemetry and user/IP baseline activity to determine if "
                            "unusual activity represents an unauthorized operation."
                        ),
                    }
                )
                anomaly_alert_count += 1

    alerts_df = (
        pd.DataFrame(alert_records, columns=ALERT_COLUMNS)
        if alert_records
        else _empty_alerts_df()
    )

    # 6. Compute unified summary statistics
    total_alerts = len(alerts_df)

    if not alerts_df.empty:
        high_cnt = int((alerts_df["severity"] == "HIGH").sum())
        med_cnt = int((alerts_df["severity"] == "MEDIUM").sum())
        low_cnt = int((alerts_df["severity"] == "LOW").sum())
        crit_cnt = int((alerts_df["severity"] == "CRITICAL").sum())

        top_ips = alerts_df["source_ip"].value_counts().head(5).to_dict()
        threats = alerts_df["detection_reason"].value_counts().head(5).to_dict()
    else:
        high_cnt = 0
        med_cnt = 0
        low_cnt = 0
        crit_cnt = 0
        top_ips = {}
        threats = {}

    summary = {
        "total_events": len(events_df),
        "total_alerts": total_alerts,
        "severity_breakdown": {
            "CRITICAL": crit_cnt,
            "HIGH": high_cnt,
            "MEDIUM": med_cnt,
            "LOW": low_cnt,
        },
        "rule_alert_count": rule_alert_count,
        "anomaly_alert_count": anomaly_alert_count,
        "top_offending_ips": top_ips,
        "common_threats": threats,
    }

    return {
        "events": events_df,
        "alerts": alerts_df,
        "summary": summary,
        "warnings": warnings,
    }
