"""
bigram_kl.py -- Signal 2: Bigram KL-Divergence

Compares character-pair (bigram) distribution of a domain label
against a reference English bigram frequency table.

Formula:  KL(P||Q) = sum( P(x) * log( P(x) / Q(x) ) )

  P = observed bigrams in domain label
  Q = reference English bigrams

Normal domain   (google, amazon) : KL ~ 0.1 - 1.0
DGA / encoded   (7f9q2z1xkp)    : KL ~ 2.5 - 6.0
"""

import json
import math
import os
from collections import Counter
from typing import Dict

_BIGRAM_FILE = os.path.join(
    os.path.dirname(__file__), "..", "..", "data", "bigram_english.json"
)
_reference_bigrams: Dict[str, float] = {}
_EPSILON = 1e-9


def load_reference_bigrams(path: str = None) -> Dict[str, float]:
    """Load English reference bigram probability table from JSON."""
    global _reference_bigrams
    if _reference_bigrams and path is None:
        return _reference_bigrams
    fpath = path or _BIGRAM_FILE
    if not os.path.exists(fpath):
        raise FileNotFoundError(
            f"Bigram reference file not found at '{fpath}'. "
            "Run python main.py --setup first."
        )
    with open(fpath, "r", encoding="utf-8") as f:
        _reference_bigrams = json.load(f)
    return _reference_bigrams


def _get_bigrams(text: str) -> Dict[str, int]:
    """Return frequency count of all consecutive character pairs."""
    text = text.lower().replace(".", "").replace("-", "")
    return Counter(text[i : i + 2] for i in range(len(text) - 1))


def kl_divergence(domain_label: str, reference: Dict[str, float] = None) -> float:
    """
    Compute KL divergence between domain label bigrams and English reference.

    Parameters
    ----------
    domain_label : str -- Label string to analyse (subdomain portion).
    reference : dict  -- Bigram reference table. Loads from file if None.

    Returns
    -------
    float -- KL divergence (>= 0). Higher = more anomalous.
    """
    if reference is None:
        reference = load_reference_bigrams()

    label = domain_label.lower().replace(".", "").replace("-", "")
    if len(label) < 2:
        return 0.0

    obs_counts = _get_bigrams(label)
    total = sum(obs_counts.values())
    if total == 0:
        return 0.0

    obs_prob = {bg: cnt / total for bg, cnt in obs_counts.items()}
    kl = 0.0
    for bg, p_x in obs_prob.items():
        q_x = reference.get(bg, _EPSILON)
        kl += p_x * math.log((p_x + _EPSILON) / (q_x + _EPSILON))

    return round(max(kl, 0.0), 6)


def compute_kl_score(domain: str) -> dict:
    """
    Compute KL-divergence features for a full domain name.

    Returns dict with keys: domain, label, kl_divergence, unique_bigrams
    """
    try:
        from src.features.entropy import extract_subdomain_label
    except ImportError:
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
        from src.features.entropy import extract_subdomain_label

    label = extract_subdomain_label(domain)
    kl = kl_divergence(label)
    bigrams = _get_bigrams(label)
    return {
        "domain": domain,
        "label": label,
        "kl_divergence": kl,
        "unique_bigrams": len(bigrams),
    }


if __name__ == "__main__":
    test_domains = [
        "mail.google.com",
        "www.amazon.com",
        "accounts.youtube.com",
        "7f9q2z1xkp3m.badsite.com",
        "a2b3c4d5e6f7.tunnel.net",
        "xkzqvwjprtlm.evil.org",
    ]
    try:
        ref = load_reference_bigrams()
        print(f"{'Domain':<40} {'Label':<20} {'KL Div':>8}")
        print("-" * 72)
        for d in test_domains:
            r = compute_kl_score(d)
            print(f"{r['domain']:<40} {r['label']:<20} {r['kl_divergence']:>8.4f}")
    except FileNotFoundError as e:
        print(f"Error: {e}")
