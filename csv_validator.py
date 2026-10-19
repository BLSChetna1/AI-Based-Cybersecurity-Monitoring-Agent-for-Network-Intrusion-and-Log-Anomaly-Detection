"""
csv_validator.py - Frontend CSV Log Validation Module
Member 1: Frontend Ingestion, UI Validation, and Backend Integration

Provides reusable validation and normalization for security log CSV files
before passing them to the detection engine or rendering in the dashboard.
"""

from dataclasses import dataclass, field
import io
import os
from typing import Optional, List, Dict, Any, Union
import warnings as std_warnings
import pandas as pd


@dataclass
class ValidationResult:
    """
    Standardized result object returned by validate_uploaded_csv.
    Supports both attribute access (result.is_valid) and dict access (result['is_valid']).
    """
    is_valid: bool
    df: Optional[pd.DataFrame]
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    skipped_rows: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert the result to a standard Python dictionary."""
        return {
            "is_valid": self.is_valid,
            "df": self.df,
            "errors": self.errors,
            "warnings": self.warnings,
            "skipped_rows": self.skipped_rows,
        }

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def __bool__(self) -> bool:
        return self.is_valid


# Canonical required columns
REQUIRED_COLUMNS = ["timestamp", "event_type", "status"]

# Supported column header aliases
COLUMN_ALIASES: Dict[str, str] = {
    # source_ip aliases
    "src_ip": "source_ip",
    "client_ip": "source_ip",
    "source": "source_ip",
    # destination_ip aliases
    "dst_ip": "destination_ip",
    "dest_ip": "destination_ip",
    "target_ip": "destination_ip",
    # status aliases
    "action": "status",
    "result": "status",
    # event_type aliases
    "type": "event_type",
    "event": "event_type",
    # user aliases
    "username": "user",
    "account": "user",
    # message aliases
    "payload": "message",
    "details": "message",
    "log_message": "message",
    # request_count aliases
    "count": "request_count",
    "requests": "request_count",
    "volume": "request_count",
}


def _parse_timestamps(series: pd.Series) -> pd.Series:
    """
    Parses timestamp series into a uniform UTC-aware datetime representation.

    TIMESTAMP TIMEZONE POLICY:
    - All valid timestamps are converted to a consistent UTC-aware format (tz='UTC').
    - Timestamps with explicit timezone offsets (e.g., 'Z', '+00:00', '-05:00') are
      converted directly to UTC.
    - Timestamps without timezone information (naive) are interpreted as UTC by policy.
      This guarantees a consistent, sortable temporal baseline without implying that an
      unknown original local timezone can be guessed.

    Supports ISO formats, SQL space-separated timestamps, slash-separated dates
    (including day-first like 18/10/2026), and date-only values. Genuinely invalid or
    malformed timestamps are coerced to NaT.
    """
    # Clean whitespace first
    cleaned = series.apply(lambda x: x.strip() if isinstance(x, str) else x)

    # Parse with utc=True so mixed timezone conventions (e.g. Z vs naive) do not drop valid rows
    with std_warnings.catch_warnings():
        std_warnings.filterwarnings(
            "ignore",
            message="Parsing dates in .* format when dayfirst=True was specified",
            category=UserWarning,
        )
        try:
            parsed = pd.to_datetime(
                cleaned, errors="coerce", utc=True, format="mixed", dayfirst=True
            )
        except Exception:
            # Fallback for earlier pandas versions or specific edge cases
            parsed = pd.to_datetime(cleaned, errors="coerce", utc=True, dayfirst=True)

    return parsed


def validate_uploaded_csv(uploaded_file: Any) -> ValidationResult:
    """
    Validates and normalizes an uploaded security log CSV file.

    Parameters:
        uploaded_file: A file path (str/Path), file-like object (BytesIO, StringIO),
                       or Streamlit UploadedFile object.

    Returns:
        ValidationResult containing:
        - is_valid: bool indicating if validation passed
        - df: Cleaned and normalized pd.DataFrame, or None if validation failed
        - errors: List of human-readable error messages
        - warnings: List of human-readable warning messages
        - skipped_rows: Number of rows skipped due to invalid timestamps
    """
    errors: List[str] = []
    warnings: List[str] = []

    # 1. Check for empty upload or None
    if uploaded_file is None:
        return ValidationResult(
            is_valid=False,
            df=None,
            errors=["No file was uploaded. Please upload a valid CSV log file."],
            warnings=warnings,
            skipped_rows=0,
        )

    # 2. Check for empty files or whitespace-only content
    raw_content: Optional[Union[bytes, str]] = None
    if isinstance(uploaded_file, (str, os.PathLike)):
        if not os.path.exists(uploaded_file):
            return ValidationResult(
                is_valid=False,
                df=None,
                errors=[f"File not found: {uploaded_file}"],
                warnings=warnings,
                skipped_rows=0,
            )
        if os.path.getsize(uploaded_file) == 0:
            return ValidationResult(
                is_valid=False,
                df=None,
                errors=["Uploaded file is empty (0 bytes)."],
                warnings=warnings,
                skipped_rows=0,
            )
        with open(uploaded_file, "rb") as f:
            raw_content = f.read()
    elif hasattr(uploaded_file, "read"):
        if hasattr(uploaded_file, "seek"):
            uploaded_file.seek(0)
        raw_content = uploaded_file.read()
        if hasattr(uploaded_file, "seek"):
            uploaded_file.seek(0)
    elif hasattr(uploaded_file, "getvalue"):
        raw_content = uploaded_file.getvalue()

    if raw_content is not None:
        stripped_content = raw_content.strip()
        if len(stripped_content) == 0:
            return ValidationResult(
                is_valid=False,
                df=None,
                errors=["Uploaded file is empty or contains only whitespace."],
                warnings=warnings,
                skipped_rows=0,
            )

    # 3. Read CSV data safely (handle parsing and Unicode decoding errors)
    df: Optional[pd.DataFrame] = None
    read_target: Any = uploaded_file
    if isinstance(raw_content, bytes):
        read_target = io.BytesIO(raw_content)
    elif isinstance(raw_content, str):
        read_target = io.StringIO(raw_content)

    try:
        try:
            df = pd.read_csv(read_target, encoding="utf-8")
        except UnicodeDecodeError:
            if hasattr(read_target, "seek"):
                read_target.seek(0)
            df = pd.read_csv(read_target, encoding="latin1")
            warnings.append("File was decoded using 'latin1' fallback encoding.")
    except pd.errors.EmptyDataError:
        return ValidationResult(
            is_valid=False,
            df=None,
            errors=["The uploaded CSV contains no data rows."],
            warnings=warnings,
            skipped_rows=0,
        )
    except (pd.errors.ParserError, Exception) as e:
        return ValidationResult(
            is_valid=False,
            df=None,
            errors=[f"CSV parsing error: {str(e)}"],
            warnings=warnings,
            skipped_rows=0,
        )

    if df is None or df.empty or len(df.columns) == 0:
        return ValidationResult(
            is_valid=False,
            df=None,
            errors=["Uploaded file contains headers but has no data rows."],
            warnings=warnings,
            skipped_rows=0,
        )

    # 4. Normalize column headers (strip whitespace and lowercase)
    normalized_headers = [str(c).strip().lower() for c in df.columns]

    # 5. Check alias mappings and detect duplicate column name collisions
    mapping_groups: Dict[str, List[str]] = {}
    for original_col, norm_col in zip(df.columns, normalized_headers):
        canonical_target = COLUMN_ALIASES.get(norm_col, norm_col)
        mapping_groups.setdefault(canonical_target, []).append(original_col)

    # Detect conflicts where multiple distinct columns map to the same target name
    conflicts: List[str] = []
    for canonical_name, orig_cols in mapping_groups.items():
        if len(orig_cols) > 1:
            conflicts.append(
                f"columns {orig_cols} both resolve to '{canonical_name}'"
            )

    if conflicts:
        errors.append(
            f"Duplicate column mapping conflict: {'; '.join(conflicts)}. "
            "Please resolve duplicate/conflicting columns in your CSV to avoid data ambiguity."
        )
        return ValidationResult(
            is_valid=False,
            df=None,
            errors=errors,
            warnings=warnings,
            skipped_rows=0,
        )

    # Apply canonical aliases and normalized names to DataFrame columns
    df.columns = [
        COLUMN_ALIASES.get(norm_col, norm_col) for norm_col in normalized_headers
    ]

    # 6. Verify required columns ('timestamp', 'event_type', 'status')
    missing_required = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing_required:
        errors.append(
            f"Missing required column(s): {missing_required}. "
            "The CSV must contain 'timestamp', 'event_type', and 'status' (or recognized aliases)."
        )
        return ValidationResult(
            is_valid=False,
            df=None,
            errors=errors,
            warnings=warnings,
            skipped_rows=0,
        )

    # 7. Trim whitespace from all string/object column values
    for col in df.columns:
        df[col] = df[col].apply(lambda x: x.strip() if isinstance(x, str) else x)

    # 8. Parse timestamps with errors='coerce'
    parsed_timestamps = _parse_timestamps(df["timestamp"])
    invalid_mask = parsed_timestamps.isna()
    skipped_rows = int(invalid_mask.sum())

    # 9. Drop rows with invalid or missing timestamps and report skipped count
    if skipped_rows > 0:
        warnings.append(
            f"Skipped {skipped_rows} row(s) due to missing, invalid, or unparseable timestamps."
        )
        df = df.loc[~invalid_mask].copy()
        parsed_timestamps = parsed_timestamps.loc[~invalid_mask]

    if df.empty:
        errors.append("Validation failed: No valid data rows remain after dropping invalid timestamps.")
        return ValidationResult(
            is_valid=False,
            df=None,
            errors=errors,
            warnings=warnings,
            skipped_rows=skipped_rows,
        )

    df["timestamp"] = parsed_timestamps

    # 10. Normalize event_type and status to lowercase, replace missing/blank with 'unknown'
    for req_col in ["event_type", "status"]:
        df[req_col] = df[req_col].apply(
            lambda x: "unknown"
            if pd.isna(x) or str(x).strip().lower() in ("", "nan", "none", "null")
            else str(x).strip().lower()
        )

    # 11 & 12. Ensure all optional columns exist and fill defaults
    # Optional 1: source_ip (default: 'Unknown')
    if "source_ip" not in df.columns:
        df["source_ip"] = "Unknown"
    else:
        df["source_ip"] = df["source_ip"].apply(
            lambda x: "Unknown"
            if pd.isna(x) or str(x).strip().lower() in ("", "nan", "none", "null")
            else str(x).strip()
        )

    # Optional 2: destination_ip (default: 'N/A')
    if "destination_ip" not in df.columns:
        df["destination_ip"] = "N/A"
    else:
        df["destination_ip"] = df["destination_ip"].apply(
            lambda x: "N/A"
            if pd.isna(x) or str(x).strip().lower() in ("", "nan", "none", "null")
            else str(x).strip()
        )

    # Optional 3: user (default: 'N/A')
    if "user" not in df.columns:
        df["user"] = "N/A"
    else:
        df["user"] = df["user"].apply(
            lambda x: "N/A"
            if pd.isna(x) or str(x).strip().lower() in ("", "nan", "none", "null")
            else str(x).strip()
        )

    # Optional 4: message (default: empty string '')
    if "message" not in df.columns:
        df["message"] = ""
    else:
        df["message"] = df["message"].apply(
            lambda x: ""
            if pd.isna(x) or str(x).strip().lower() in ("nan", "none", "null")
            else str(x).strip()
        )

    # Optional 5: request_count (numeric default: 1)
    if "request_count" not in df.columns:
        df["request_count"] = 1
    else:
        numeric_count = pd.to_numeric(df["request_count"], errors="coerce").fillna(1)
        df["request_count"] = numeric_count.apply(
            lambda x: int(x) if isinstance(x, (int, float)) and x > 0 else 1
        )

    # 13. Preserve other non-conflicting extra columns (already retained in df)
    # Reset index for clean contiguous integer indexing
    df = df.reset_index(drop=True)

    return ValidationResult(
        is_valid=True,
        df=df,
        errors=errors,
        warnings=warnings,
        skipped_rows=skipped_rows,
    )
