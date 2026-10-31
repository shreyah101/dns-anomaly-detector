"""
tests/test_timing.py -- Unit tests for the Timing Regularity signal.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from src.features.timing import (
    coefficient_of_variation,
    timing_regularity_score,
    compute_timing_features,
)


class TestCoefficientOfVariation:
    def test_single_element_returns_none(self):
        assert coefficient_of_variation([5.0]) is None

    def test_empty_returns_none(self):
        assert coefficient_of_variation([]) is None

    def test_all_same_returns_zero(self):
        cv = coefficient_of_variation([10.0, 10.0, 10.0, 10.0])
        assert cv == 0.0

    def test_zero_mean_returns_none(self):
        cv = coefficient_of_variation([0.0, 0.0, 0.0])
        assert cv is None

    def test_high_variance_returns_high_cv(self):
        intervals = [1, 100, 1, 100, 1, 100]
        cv = coefficient_of_variation(intervals)
        assert cv > 0.5

    def test_nonnegative(self):
        cv = coefficient_of_variation([5, 10, 15, 20])
        assert cv >= 0.0


class TestTimingRegularityScore:
    def test_regular_intervals_score_near_one(self):
        # Perfectly regular: CV = 0 -> T = 1.0
        intervals = [60.0] * 20
        t = timing_regularity_score(intervals)
        assert t is not None
        assert abs(t - 1.0) < 1e-4

    def test_very_irregular_score_near_zero(self):
        # High variance -> high CV -> T near 0
        np.random.seed(1)
        intervals = list(np.random.exponential(100, 50))
        t = timing_regularity_score(intervals)
        assert t is not None
        assert t < 0.5

    def test_score_between_zero_and_one(self):
        for seed in [1, 2, 3, 42, 99]:
            np.random.seed(seed)
            intervals = list(np.random.exponential(30, 20))
            t = timing_regularity_score(intervals)
            assert t is None or (0.0 <= t <= 1.0)

    def test_insufficient_intervals_returns_none(self):
        assert timing_regularity_score([60.0]) is None
        assert timing_regularity_score([]) is None


class TestComputeTimingFeatures:
    @staticmethod
    def _make_df(src_ip, domain, times):
        return pd.DataFrame({
            "timestamp": times,
            "src_ip": src_ip,
            "registered_domain": domain,
        })

    def test_beacon_host_has_high_timing_score(self):
        base = datetime(2024, 1, 1, 12, 0, 0)
        times = [base + timedelta(seconds=60 * i) for i in range(20)]
        df = self._make_df("10.0.0.1", "evil.com", times)
        result = compute_timing_features(df)
        row = result[result["registered_domain"] == "evil.com"].iloc[0]
        assert row["timing_score"] > 0.8, f"Expected high score for beacon, got {row['timing_score']}"

    def test_human_host_has_low_timing_score(self):
        base = datetime(2024, 1, 1, 12, 0, 0)
        np.random.seed(42)
        gaps = np.random.exponential(300, 20)
        times = [base + timedelta(seconds=int(s)) for s in np.cumsum(gaps)]
        df = self._make_df("192.168.1.5", "google.com", times)
        result = compute_timing_features(df)
        row = result[result["registered_domain"] == "google.com"].iloc[0]
        assert row["timing_score"] < 0.5, f"Expected low score for human, got {row['timing_score']}"

    def test_insufficient_queries_gives_nan(self):
        base = datetime(2024, 1, 1)
        times = [base, base + timedelta(seconds=30)]  # only 2 queries
        df = self._make_df("10.0.0.9", "test.com", times)
        result = compute_timing_features(df, min_queries=3)
        row = result.iloc[0]
        assert pd.isna(row["timing_score"])

    def test_output_dataframe_has_required_columns(self):
        base = datetime(2024, 1, 1)
        times = [base + timedelta(seconds=60 * i) for i in range(10)]
        df = self._make_df("10.0.0.1", "test.net", times)
        result = compute_timing_features(df)
        for col in ["src_ip", "registered_domain", "query_count", "cv", "timing_score"]:
            assert col in result.columns
