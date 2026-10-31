"""
src/features/adversarial_defense.py
Advanced Adversarial Evasion Resistance:
1. Dictionary-Based DGA Detection (Suppobox / Matsnu word-gluing evasion)
2. Jittered C2 Beacon Detection (Autocorrelation & Spectral Harmonic Peak Analysis)

Addresses critical blind spots where naive entropy or coefficient-of-variation
detectors fail against modern evasive malware.
"""
from src.domain_utils import extract_domain


import math
import numpy as np
import pandas as pd
from typing import List, Dict, Optional

# Core English word set for dictionary DGA segmentation (~350 common roots)
COMMON_ENGLISH_WORDS = {
    "apple", "banana", "orange", "lemon", "window", "door", "table", "chair",
    "water", "river", "mountain", "forest", "tree", "plant", "flower", "grass",
    "cloud", "rain", "storm", "sun", "moon", "star", "light", "shadow",
    "fire", "earth", "metal", "stone", "rock", "sand", "ocean", "sea",
    "fish", "bird", "animal", "horse", "dog", "cat", "lion", "tiger", "bear",
    "monkey", "elephant", "wolf", "fox", "rabbit", "mouse", "eagle", "hawk",
    "book", "paper", "pen", "pencil", "letter", "word", "story", "music",
    "song", "sound", "voice", "color", "red", "blue", "green", "yellow",
    "white", "black", "gold", "silver", "iron", "copper", "glass", "bottle",
    "house", "room", "wall", "floor", "roof", "street", "road", "bridge",
    "city", "town", "village", "country", "state", "world", "space", "time",
    "year", "month", "week", "day", "hour", "minute", "second", "morning",
    "night", "evening", "spring", "summer", "autumn", "winter", "north", "south",
    "east", "west", "center", "circle", "square", "line", "point", "number",
    "first", "second", "third", "power", "energy", "force", "speed", "motion",
    "life", "heart", "mind", "hand", "foot", "head", "face", "eye", "ear",
    "mouth", "tooth", "voice", "body", "blood", "bone", "skin", "hair",
    "food", "bread", "meat", "fruit", "sugar", "salt", "milk", "coffee", "tea",
    "ship", "boat", "car", "train", "plane", "wheel", "engine", "motor",
    "ticket", "travel", "journey", "flight", "market", "money", "bank", "gold",
    "king", "queen", "prince", "leader", "chief", "guard", "soldier", "army",
    "peace", "war", "battle", "fight", "game", "play", "sport", "ball",
    "run", "walk", "jump", "fly", "swim", "sleep", "wake", "dream",
    "stand", "sit", "watch", "listen", "speak", "talk", "read", "write",
    "think", "know", "learn", "teach", "find", "lose", "give", "take",
    "make", "build", "break", "open", "close", "start", "stop", "change",
    "great", "small", "large", "little", "long", "short", "high", "low",
    "deep", "wide", "fast", "slow", "hard", "soft", "heavy", "light",
    "hot", "cold", "warm", "cool", "clean", "dirty", "fresh", "sweet",
    "happy", "sad", "strong", "weak", "young", "old", "new", "bright",
    "dark", "safe", "wild", "free", "rich", "poor", "clear", "loud",
    "simple", "complex", "secret", "silent", "ancient", "modern", "future",
    "system", "network", "server", "service", "client", "portal", "cloud",
}


def segment_dictionary_words(text: str) -> List[str]:
    """
    Segment a string into candidate English dictionary words using
    a dynamic greedy longest-match algorithm.

    Parameters
    ----------
    text : str
        Lower-case domain label (e.g. 'elephantwindoworange').

    Returns
    -------
    List[str] : identified dictionary word tokens.
    """
    text = text.lower().replace("-", "").replace(".", "")
    n = len(text)
    if n < 3:
        return [text] if text in COMMON_ENGLISH_WORDS else []

    # Dynamic forward matching for longest valid dictionary tokens
    tokens = []
    i = 0
    while i < n:
        longest_match = None
        for j in range(min(n, i + 15), i + 2, -1):
            sub = text[i:j]
            if sub in COMMON_ENGLISH_WORDS:
                longest_match = sub
                break
        if longest_match:
            tokens.append(longest_match)
            i += len(longest_match)
        else:
            i += 1

    return tokens


def detect_dictionary_dga(domain_or_label: str) -> dict:
    """
    Detect dictionary-based DGA domains (e.g. Suppobox, Matsnu) that evade
    Shannon entropy and Bigram KL by stringing multiple real words together.

    Parameters
    ----------
    domain_or_label : str
        Domain name or subdomain label.

    Returns
    -------
    dict with:
        is_dictionary_dga (bool), dga_score (float),
        word_count (int), tokens (list), coverage_ratio (float)
    """
    # Extract candidate label
    parts = domain_or_label.lower().split(".")
    label = parts[0] if len(parts) >= 2 else domain_or_label.lower()

    tokens = segment_dictionary_words(label)
    word_count = len(tokens)
    matched_chars = sum(len(w) for w in tokens)
    coverage = matched_chars / max(len(label), 1)

    # Legitimate domains are typically 1 single word (e.g. 'google', 'apple')
    # Dictionary DGAs glue 3 to 6 words together (e.g. 'bananaorangemonkeyticket')
    if word_count >= 3 and coverage >= 0.70 and len(label) >= 14:
        score = min(0.60 + 0.10 * word_count + 0.20 * coverage, 1.0)
        is_dga = True
        reason = f"Concatenation of {word_count} dictionary words ({', '.join(tokens)}) evades standard entropy."
    elif word_count == 2 and coverage >= 0.85 and len(label) >= 16:
        score = 0.55
        is_dga = False
        reason = f"Two dictionary words detected ({', '.join(tokens)}), borderline length."
    else:
        score = 0.10 if word_count <= 1 else 0.25
        is_dga = False
        reason = "Normal lexical composition."

    return {
        "domain": domain_or_label,
        "is_dictionary_dga": is_dga,
        "dga_score": round(score, 4),
        "word_count": word_count,
        "tokens": tokens,
        "coverage_ratio": round(coverage, 4),
        "reason": reason,
    }


def compute_spectral_periodicity(intervals: List[float]) -> dict:
    """
    Detect periodic C2 beaconing even in the presence of random jitter (20%-50%),
    where naive Coefficient of Variation (CV) fails.

    Uses normalized autocorrelation and power spectral peak-to-noise ratio.

    Parameters
    ----------
    intervals : List[float]
        Sequence of inter-query arrival intervals in seconds.

    Returns
    -------
    dict with:
        has_periodic_beacon (bool), spectral_score (float),
        dominant_period_sec (float or None), peak_to_noise_ratio (float)
    """
    if len(intervals) < 6:
        return {
            "has_periodic_beacon": False,
            "spectral_score": 0.10,
            "dominant_period_sec": None,
            "peak_to_noise_ratio": 0.0,
            "reason": "Insufficient intervals (< 6) for spectral periodicity analysis."
        }

    arr = np.array(intervals, dtype=float)
    mu = np.mean(arr)
    if mu <= 0:
        return {"has_periodic_beacon": False, "spectral_score": 0.0, "dominant_period_sec": None, "peak_to_noise_ratio": 0.0}

    # Centered autocorrelation
    norm_arr = arr - mu
    var = np.var(norm_arr)
    if var == 0:
        # Perfectly fixed interval
        return {
            "has_periodic_beacon": True,
            "spectral_score": 1.0,
            "dominant_period_sec": round(float(mu), 2),
            "peak_to_noise_ratio": 99.0,
            "reason": f"Deterministic clock beacon with zero variance at {mu:.1f}s."
        }

    # Autocorrelation for lags up to half array length
    max_lag = min(len(arr) // 2, 8)
    autocorr = []
    for lag in range(1, max_lag + 1):
        ac = np.mean(norm_arr[:-lag] * norm_arr[lag:]) / var
        autocorr.append(ac)

    # FFT Power Spectral Density
    fft_vals = np.abs(np.fft.rfft(norm_arr)) ** 2
    if len(fft_vals) > 2:
        fft_peak = np.max(fft_vals[1:])
        fft_mean = np.mean(fft_vals[1:])
        pnr = float(fft_peak / (fft_mean + 1e-6))
    else:
        pnr = 1.0

    max_ac = float(max(autocorr)) if autocorr else 0.0

    # Under 30% jitter, autocorrelation at lag 1 or harmonic power peak remains elevated
    if pnr > 3.0 or max_ac > 0.45:
        spectral_score = min(0.50 + 0.10 * pnr + 0.30 * max_ac, 1.0)
        has_beacon = True
        reason = f"Harmonic spectral peak (PNR={pnr:.2f}, max_autocorr={max_ac:.2f}) indicates jittered C2 beaconing."
    else:
        spectral_score = max(min(pnr / 6.0, 0.40), 0.05)
        has_beacon = False
        reason = "No significant spectral harmonics found; timing appears stochastic."

    return {
        "has_periodic_beacon": has_beacon,
        "spectral_score": round(spectral_score, 4),
        "dominant_period_sec": round(float(mu), 2),
        "peak_to_noise_ratio": round(pnr, 2),
        "reason": reason,
    }


def compute_adversarial_scores(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute adversarial evasion scores across a DNS DataFrame.

    Parameters
    ----------
    df : pd.DataFrame
        Must contain 'domain'.

    Returns
    -------
    pd.DataFrame with:
        domain, dict_dga_score, is_dict_dga, dict_words_found
    """
    records = []
    for d in df["domain"]:
        res = detect_dictionary_dga(str(d))
        records.append({
            "domain": d,
            "dict_dga_score": res["dga_score"],
            "is_dict_dga": res["is_dictionary_dga"],
            "dict_words_found": ", ".join(res["tokens"]) if res["tokens"] else "none",
        })

    return pd.DataFrame(records).drop_duplicates("domain")


if __name__ == "__main__":
    test_cases = [
        "elephantwindoworange.com",      # Dictionary DGA (3 words)
        "bananaorangemonkeyticket.net",  # Dictionary DGA (4 words)
        "apple.com",                     # Normal 1-word brand
        "microsoft.com",                 # Normal brand
        "mail.google.com",               # Normal service
    ]
    print(f"{'Domain':<35} {'Dict DGA?':<12} {'Score':<8} {'Tokens'}")
    print("-" * 75)
    for t in test_cases:
        r = detect_dictionary_dga(t)
        print(f"{r['domain']:<35} {str(r['is_dictionary_dga']):<12} {r['dga_score']:<8.4f} {r['tokens']}")
