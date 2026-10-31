"""
tests/test_entropy.py -- Unit tests for the Shannon Entropy signal.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.features.entropy import shannon_entropy, extract_subdomain_label, compute_entropy_score


class TestShannonEntropy:
    def test_empty_string_returns_zero(self):
        assert shannon_entropy("") == 0.0

    def test_single_char_returns_zero(self):
        assert shannon_entropy("a") == 0.0

    def test_two_same_chars_returns_zero(self):
        assert shannon_entropy("aa") == 0.0

    def test_two_different_chars_returns_one(self):
        result = shannon_entropy("ab")
        assert abs(result - 1.0) < 1e-4

    def test_normal_domain_has_low_entropy(self):
        h = shannon_entropy("mail")
        assert h < 3.5, f"Expected low entropy for 'mail', got {h}"

    def test_dga_domain_has_high_entropy(self):
        h = shannon_entropy("7f9q2z1xkp3m")
        assert h > 3.2, f"Expected high entropy for DGA label, got {h}"

    def test_entropy_is_nonnegative(self):
        for word in ["hello", "world", "xyz", "aaaaa", "a1b2c3"]:
            assert shannon_entropy(word) >= 0.0

    def test_entropy_bounded_by_log2_alphabet(self):
        import math
        text = "7f9q2z1xkp3m"
        unique = len(set(text))
        max_entropy = math.log2(unique)
        h = shannon_entropy(text)
        assert h <= max_entropy + 1e-4  # Allow small rounding error


class TestExtractLabel:
    def test_extracts_subdomain(self):
        label = extract_subdomain_label("mail.google.com")
        assert label == "mail"

    def test_extracts_multi_subdomain(self):
        label = extract_subdomain_label("a.b.evil.net")
        assert "a" in label

    def test_no_subdomain_returns_domain(self):
        label = extract_subdomain_label("google.com")
        assert "google" in label

    def test_dga_domain(self):
        label = extract_subdomain_label("7f9q2z1xkp3m.badsite.com")
        assert label == "7f9q2z1xkp3m"


class TestComputeEntropyScore:
    def test_returns_dict_with_required_keys(self):
        result = compute_entropy_score("mail.google.com")
        assert "domain" in result
        assert "label" in result
        assert "entropy" in result
        assert "label_length" in result
        assert "entropy_per_char" in result

    def test_entropy_per_char_is_consistent(self):
        result = compute_entropy_score("mail.google.com")
        expected = result["entropy"] / max(result["label_length"], 1)
        assert abs(result["entropy_per_char"] - expected) < 1e-4

    def test_dga_higher_than_normal(self):
        normal = compute_entropy_score("mail.google.com")
        dga    = compute_entropy_score("7f9q2z1xkp3m.badsite.com")
        assert dga["entropy"] > normal["entropy"]
