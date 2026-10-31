"""
tests/test_bigram.py -- Unit tests for the Bigram KL-Divergence signal.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.features.bigram_kl import kl_divergence, _get_bigrams


class TestGetBigrams:
    def test_single_char_returns_empty(self):
        assert len(_get_bigrams("a")) == 0

    def test_two_chars_returns_one_bigram(self):
        bg = _get_bigrams("ab")
        assert bg["ab"] == 1

    def test_counts_repeated_bigrams(self):
        bg = _get_bigrams("aaaa")
        assert bg["aa"] == 3

    def test_strips_dots(self):
        bg = _get_bigrams("ma.il")
        assert "." not in "".join(bg.keys())

    def test_case_insensitive(self):
        bg_lower = _get_bigrams("mail")
        bg_upper = _get_bigrams("MAIL")
        assert dict(bg_lower) == dict(bg_upper)


class TestKLDivergence:
    """
    These tests use a minimal inline reference to avoid needing the file.
    """

    @staticmethod
    def _simple_ref():
        # Simple English-like bigram frequencies
        return {
            "ma": 0.05, "ai": 0.04, "il": 0.04, "th": 0.08,
            "he": 0.07, "er": 0.06, "an": 0.05, "in": 0.05,
            "on": 0.04, "en": 0.04, "re": 0.04, "nd": 0.03,
            "at": 0.03, "es": 0.03, "or": 0.03, "te": 0.03,
        }

    def test_zero_for_single_char_label(self):
        ref = self._simple_ref()
        result = kl_divergence("a", reference=ref)
        assert result == 0.0

    def test_nonnegative(self):
        ref = self._simple_ref()
        for word in ["mail", "google", "7f9q2z1", "xkzqvw"]:
            assert kl_divergence(word, reference=ref) >= 0.0

    def test_english_word_lower_than_random_string(self):
        ref = self._simple_ref()
        kl_english = kl_divergence("mailer", reference=ref)
        kl_random  = kl_divergence("zqxvwjkp", reference=ref)
        # English word should have lower KL vs English reference
        assert kl_english <= kl_random, (
            f"Expected English word to have lower KL. "
            f"Got mail={kl_english:.4f}, random={kl_random:.4f}"
        )

    def test_empty_string_returns_zero(self):
        ref = self._simple_ref()
        assert kl_divergence("", reference=ref) == 0.0

    def test_returns_float(self):
        ref = self._simple_ref()
        result = kl_divergence("hello", reference=ref)
        assert isinstance(result, float)
