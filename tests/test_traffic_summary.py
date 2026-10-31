"""Summaries preserve counts without growing with the capture's time span."""
import pandas as pd
import pytest
from src.traffic_summary import activity_timeline, host_summary


def sample():
    return pd.DataFrame({"timestamp": pd.to_datetime(["2020-01-01", "2025-01-01", "2025-01-01"], utc=True),
                         "src_ip": ["10.0.0.1", "10.0.0.2", "10.0.0.2"],
                         "domain": ["a.example.com", "b.example.com", "b.example.com"],
                         "is_anomaly": [False, True, True], "anomaly_score": [.2, .8, .9]})


def test_long_capture_timeline_stays_bounded_and_preserves_counts():
    timeline, seconds = activity_timeline(sample())
    assert len(timeline) <= 121
    assert seconds > 60
    assert timeline.queries.sum() == 3
    assert timeline.flagged.sum() == 2


def test_single_timestamp_has_one_bucket():
    timeline, seconds = activity_timeline(sample().iloc[[0]])
    assert len(timeline) == 1
    assert seconds == 60
    assert timeline.queries.iloc[0] == 1


def test_hosts_ranked_by_actual_findings_and_unique_names():
    summary = host_summary(sample())
    host = summary.iloc[0]
    assert host.src_ip == "10.0.0.2"
    assert host.total_queries == 2
    assert host.unique_domains == 1
    assert host.flagged_queries == 2
    assert host.peak_score == .9
    assert host.flagged_percent == 100
    assert summary.iloc[1].flagged_percent == 0


def test_invalid_bucket_limit():
    with pytest.raises(ValueError):
        activity_timeline(sample(), 0)
