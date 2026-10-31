"""
timing.py -- Signal 3: Inter-Query Timing Regularity

Detects suspiciously clock-regular (beacon-like) DNS query patterns.

Real human DNS activity is bursty and irregular.
Malware beaconing is too regular -- queries arrive at nearly fixed intervals.

Method:
    1. Group queries by (src_ip, registered_domain)
    2. Compute inter-arrival time gaps (diff of sorted timestamps)
    3. CV = sigma / mu  (Coefficient of Variation)
       Low CV (near 0) = too regular = suspicious
       High CV (>1)    = messy/human = normal
    4. Timing regularity score: T = 1 / (1 + CV)
       T near 1.0 = beacon (alarm!)
       T near 0.0 = random (benign)

Minimum queries required: 3
"""

import numpy as np
import pandas as pd
from typing import Optional


def coefficient_of_variation(intervals: list) -> Optional[float]:
    """
    Compute CV = sigma/mu of the given intervals.

    Returns None if insufficient data or mean is zero.
    """
    arr = np.array(intervals, dtype=float)
    if len(arr) < 2:
        return None
    mu = np.mean(arr)
    sigma = np.std(arr, ddof=1)
    if mu <= 0:
        return None
    return float(sigma / mu)


def timing_regularity_score(intervals: list) -> Optional[float]:
    """
    Compute timing regularity score T in [0, 1].
    T = 1 / (1 + CV)

    Returns None if fewer than 2 intervals.
    """
    cv = coefficient_of_variation(intervals)
    if cv is None:
        return None
    return round(1.0 / (1.0 + cv), 6)


def compute_timing_features(df: pd.DataFrame, min_queries: int = 3) -> pd.DataFrame:
    """
    Compute timing regularity scores per (src_ip, registered_domain) pair.

    Parameters
    ----------
    df : pd.DataFrame
        Columns required: [timestamp, src_ip, registered_domain]
        timestamp may be datetime or numeric (Unix seconds).
    min_queries : int
        Minimum queries to compute a score (default 3).

    Returns
    -------
    pd.DataFrame with timing features per group.
    """
    records = []

    if pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
        df = df.copy()
        df["ts_sec"] = df["timestamp"].map(lambda t: t.timestamp())
    else:
        df = df.copy()
        df["ts_sec"] = df["timestamp"].astype(float)

    groups = df.groupby(["src_ip", "registered_domain"], sort=False)

    for (src_ip, reg_domain), grp in groups:
        times = grp["ts_sec"].sort_values().values
        query_count = len(times)

        if query_count < min_queries:
            records.append({
                "src_ip": src_ip, "registered_domain": reg_domain,
                "query_count": query_count,
                "mean_interval_sec": np.nan, "std_interval_sec": np.nan,
                "cv": np.nan, "timing_score": np.nan,
            })
            continue

        intervals = np.diff(times).tolist()
        cv = coefficient_of_variation(intervals)
        t_score = timing_regularity_score(intervals)

        records.append({
            "src_ip": src_ip, "registered_domain": reg_domain,
            "query_count": query_count,
            "mean_interval_sec": round(float(np.mean(intervals)), 4),
            "std_interval_sec": round(float(np.std(intervals, ddof=1)), 4),
            "cv": round(cv, 6) if cv is not None else np.nan,
            "timing_score": t_score if t_score is not None else np.nan,
        })

    return pd.DataFrame(records)


if __name__ == "__main__":
    import datetime
    base = datetime.datetime(2024, 1, 1, 12, 0, 0)

    # Beacon: queries every exactly 60 seconds
    beacon_times = [base + datetime.timedelta(seconds=60 * i) for i in range(20)]
    np.random.seed(42)
    human_times = sorted(
        [base + datetime.timedelta(seconds=int(x)) for x in np.random.exponential(300, 20)]
    )

    rows = []
    for t in beacon_times:
        rows.append({"timestamp": t, "src_ip": "10.0.0.1", "registered_domain": "evil.com"})
    for t in human_times:
        rows.append({"timestamp": t, "src_ip": "10.0.0.2", "registered_domain": "google.com"})

    df_test = pd.DataFrame(rows)
    result = compute_timing_features(df_test)
    print(result[["src_ip","registered_domain","query_count","cv","timing_score"]].to_string(index=False))
    print("\nHigh timing_score (~1.0) = beacon/malware")
    print("Low  timing_score (~0.0) = human/normal")
