"""Bounded timeline aggregation and host-level triage summaries."""
import math
import pandas as pd


def activity_timeline(scored, max_buckets=120):
    """Avoid allocating one row per minute across arbitrarily long captures."""
    if max_buckets < 1:
        raise ValueError("max_buckets must be positive")
    duration = (scored.timestamp.max() - scored.timestamp.min()).total_seconds()
    seconds = max(60, math.ceil(duration / max_buckets))
    timeline = (scored.set_index("timestamp")
                .resample(pd.Timedelta(seconds=seconds), origin="start")
                .agg(queries=("domain", "size"), flagged=("is_anomaly", "sum")))
    return timeline, seconds


def host_summary(scored):
    """Rank clients by flagged query count, then maximum score."""
    summary = scored.groupby("src_ip").agg(
        total_queries=("domain", "size"), unique_domains=("domain", "nunique"),
        flagged_queries=("is_anomaly", "sum"), peak_score=("anomaly_score", "max"),
        first_seen=("timestamp", "min"), last_seen=("timestamp", "max"),
    )
    summary["flagged_percent"] = (100 * summary.flagged_queries / summary.total_queries).round(1)
    return summary.sort_values(["flagged_queries", "peak_score"], ascending=False).reset_index()
