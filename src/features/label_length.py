"""
src/features/label_length.py
Signal 5: Domain Label Length Scoring

DGA (Domain Generation Algorithm) malware typically produces
long, randomly-generated subdomain labels (15–32 characters).
Legitimate subdomains rarely exceed 12 characters.

This module converts raw label length into a normalized suspicion
score using a sigmoid-like mapping around a human-behavioral baseline.
"""

import math


# Statistical baseline from real-world DNS studies:
#   Mean label length for legitimate domains ≈ 7 characters
#   DGA / hex-encoded labels: 16–32 characters
LENGTH_BENIGN_MEAN = 7.0
LENGTH_BENIGN_STD  = 3.0

# Hard thresholds for explanation tier
LENGTH_LOW_THRESHOLD  = 9    # below this = very normal
LENGTH_HIGH_THRESHOLD = 15   # above this = highly suspicious


def label_length_score(label: str) -> float:
    """
    Convert domain label length to a suspicion score in [0, 1].

    Uses a z-score relative to the benign baseline, then maps
    to [0, 1] with a logistic function.

    Args:
        label: The subdomain label string (e.g., '7f9q2z1xkp3m').

    Returns:
        float in [0, 1] — higher means more suspicious.
    """
    if not label:
        return 0.0

    length = len(label)

    # Z-score relative to benign baseline
    z = (length - LENGTH_BENIGN_MEAN) / LENGTH_BENIGN_STD

    # Logistic (sigmoid) mapping — centred so z=0 -> score≈0.30
    # This ensures even average-length labels contribute a low-but-non-zero score
    score = 1.0 / (1.0 + math.exp(-0.8 * (z - 1.0)))

    return round(min(max(score, 0.0), 1.0), 6)


def compute_label_length_scores(df) -> "pd.DataFrame":
    """
    Compute label length scores for every domain in the DataFrame.

    Args:
        df: DataFrame with 'domain' and optionally 'subdomain_label' or 'label'.

    Returns:
        DataFrame with columns [domain, label_length_raw, length_score]
    """
    import pandas as pd

    def _score_row(row) -> dict:
        domain = str(row.get("domain", "") or "")
        label = str(row.get("subdomain_label", "") or row.get("label", "") or "")
        if label in ("benign", "malicious", "") and domain:
            try:
                from src.features.entropy import extract_subdomain_label
                label = extract_subdomain_label(domain)
            except Exception:
                label = domain.split(".")[0]
        length = len(label)
        score = label_length_score(label)
        return {
            "domain": domain,
            "label_length_raw": length,
            "length_score": score,
        }

    records = [_score_row(row) for _, row in df.iterrows()]
    result = pd.DataFrame(records).drop_duplicates("domain")
    return result
