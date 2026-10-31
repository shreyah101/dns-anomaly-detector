"""
entropy.py -- Signal 1: Shannon Entropy

Measures character-level randomness of a domain label.
Higher entropy = more random-looking = more suspicious.

Formula:  H = -sum( p(c) * log2(p(c)) )

Normal domains   (mail.google)   : H ~ 2.0 - 3.5 bits
DGA / tunneled   (7f9q2z1xkp3m)  : H ~ 4.0 - 5.0 bits
"""
from src.domain_utils import extract_domain


import math
from collections import Counter


def shannon_entropy(text: str) -> float:
    """
    Compute Shannon entropy (bits) of the characters in text.

    Parameters
    ----------
    text : str  -- Input string (domain label).

    Returns
    -------
    float -- Entropy in bits. Returns 0.0 for strings of length <= 1.
    """
    text = text.lower().strip()
    if len(text) <= 1:
        return 0.0
    counts = Counter(text)
    total = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 6)


def extract_subdomain_label(domain: str) -> str:
    """
    Extract the subdomain label from a full domain for entropy analysis.

    Examples
    --------
    '7f9q2z1.badsite.com' -> '7f9q2z1'
    'mail.google.com'     -> 'mail'
    'a.b.evil.net'        -> 'a.b'
    """
    try:
        import tldextract
        ext = extract_domain(domain)
        if ext.subdomain:
            return ext.subdomain
        elif ext.domain:
            return ext.domain
        else:
            return domain
    except Exception:
        parts = domain.rstrip(".").split(".")
        if len(parts) >= 3:
            return ".".join(parts[:-2])
        elif len(parts) == 2:
            return parts[0]
        return domain


def compute_entropy_score(domain: str) -> dict:
    """
    Compute entropy-based features for a given full domain name.

    Returns dict with keys:
        domain, label, label_length, entropy, entropy_per_char
    """
    label = extract_subdomain_label(domain)
    h = shannon_entropy(label)
    length = len(label)
    return {
        "domain": domain,
        "label": label,
        "subdomain_label": label,
        "label_length": length,
        "entropy": h,
        "entropy_per_char": round(h / max(length, 1), 6),
    }


if __name__ == "__main__":
    test_domains = [
        "mail.google.com",
        "www.amazon.com",
        "7f9q2z1xkp3m.badsite.com",
        "a2b3c4d5e6f7.tunnel.net",
        "accounts.youtube.com",
        "xkzqvwjprtlm.evil.org",
    ]
    print(f"{'Domain':<40} {'Label':<20} {'Entropy':>8} {'Length':>7}")
    print("-" * 80)
    for d in test_domains:
        r = compute_entropy_score(d)
        print(f"{r['domain']:<40} {r['label']:<20} {r['entropy']:>8.4f} {r['label_length']:>7}")
