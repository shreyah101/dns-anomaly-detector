"""
tests/test_adversarial.py
Automated Unit Tests for Adversarial Dictionary-DGA and Spectral Jittered Beaconing
"""

import numpy as np
import pytest
from src.features.adversarial_defense import (
    segment_dictionary_words, detect_dictionary_dga, compute_spectral_periodicity
)


def test_segment_dictionary_words():
    # 3 English words concatenated
    text = "elephantwindoworange"
    tokens = segment_dictionary_words(text)
    assert len(tokens) == 3
    assert tokens == ["elephant", "window", "orange"]


def test_detect_dictionary_dga_flagged():
    dga_domain = "bananaorangemonkeyticket.net"
    res = detect_dictionary_dga(dga_domain)
    assert res["is_dictionary_dga"] is True
    assert res["dga_score"] >= 0.70
    assert res["word_count"] >= 3


def test_detect_dictionary_dga_benign_brand_clean():
    clean_domain = "apple.com"
    res = detect_dictionary_dga(clean_domain)
    assert res["is_dictionary_dga"] is False
    assert res["dga_score"] < 0.35


def test_compute_spectral_periodicity_fixed_beacon():
    # Perfectly fixed 30s intervals
    intervals = [30.0] * 10
    res = compute_spectral_periodicity(intervals)
    assert res["has_periodic_beacon"] is True
    assert res["spectral_score"] == 1.0


def test_compute_spectral_periodicity_jittered_beacon():
    # 30s intervals with 20% random jitter (24s - 36s)
    np.random.seed(42)
    intervals = [30.0 + float(x) for x in np.random.uniform(-6.0, 6.0, 15)]
    res = compute_spectral_periodicity(intervals)
    assert res["spectral_score"] >= 0.35


def test_compute_spectral_periodicity_random_intervals():
    # Exponential human-like browsing intervals
    np.random.seed(42)
    intervals = list(np.random.exponential(120.0, 15))
    res = compute_spectral_periodicity(intervals)
    assert res["has_periodic_beacon"] is False
