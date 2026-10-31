"""Validation and normalization shared by CSV, packet capture, and the UI."""
import pandas as pd
from src.domain_utils import normalize_domain, registered_domain


def prepare_traffic(df):
    required = {"timestamp", "src_ip", "domain"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(sorted(missing)))
    if df.empty:
        raise ValueError("No DNS queries found in the input.")
    df = df.copy()
    if df[list(required)].isna().any().any():
        raise ValueError("Timestamp, source IP, and domain cannot be empty.")
    numeric = pd.to_numeric(df["timestamp"], errors="coerce")
    if pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    elif numeric.notna().all():
        df["timestamp"] = pd.to_datetime(numeric, unit="s", utc=True, errors="coerce")
    else:
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce", format="mixed")
    if df["timestamp"].isna().any():
        raise ValueError("Invalid timestamps. Use ISO datetimes or Unix seconds.")
    df["src_ip"] = df["src_ip"].astype(str).str.strip()
    from ipaddress import ip_address
    for address in df["src_ip"].unique():
        try:
            ip_address(address)
        except ValueError as exc:
            raise ValueError(f"Invalid source IP: {address!r}") from exc
    df["domain"] = df["domain"].map(normalize_domain)
    # Derive this field rather than trusting potentially inconsistent uploaded values.
    df["registered_domain"] = df["domain"].map(registered_domain)
    if "label" not in df:
        df["label"] = None
    else:
        df["label"] = df["label"].astype("string").str.strip().str.lower()
    if "response_code" not in df and "rcode" in df:
        df["response_code"] = df["rcode"]
    return df.sort_values("timestamp").reset_index(drop=True)


def load_traffic(path, max_rows=None):
    return prepare_traffic(pd.read_csv(path, nrows=max_rows))


_extract_registered_domain = registered_domain
