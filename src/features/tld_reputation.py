"""
src/features/tld_reputation.py
Signal 4: TLD (Top-Level Domain) Reputation Scoring

Malware operators heavily prefer free, anonymous, or unregulated TLDs
because they can register thousands of throwaway domains cheaply.
This module scores the registered TLD based on its abuse frequency.
"""
from src.domain_utils import extract_domain


import tldextract

# Static illustrative project priors; not a measured or current reputation feed.
# Score range: 0.0 (very trusted) -> 1.0 (heavily abused)
TLD_RISK_TABLE = {
    # Heavily abused / free registrar TLDs
    ".tk": 0.95,
    ".ml": 0.93,
    ".ga": 0.92,
    ".cf": 0.91,
    ".gq": 0.90,
    ".pw": 0.88,
    ".top": 0.80,
    ".xyz": 0.75,
    ".biz": 0.70,
    ".click": 0.72,
    ".link": 0.68,
    ".club": 0.65,
    ".online": 0.63,
    ".site": 0.62,
    ".icu": 0.60,
    ".live": 0.58,
    ".info": 0.45,
    ".cc": 0.50,
    ".in": 0.40,
    ".cn": 0.35,
    ".ru": 0.35,
    ".su": 0.40,
    # Country TLDs often used for DGA
    ".ws": 0.55,
    ".to": 0.48,
    # Standard/trusted TLDs
    ".com": 0.10,
    ".net": 0.12,
    ".org": 0.08,
    ".edu": 0.02,
    ".gov": 0.01,
    ".io": 0.15,
    ".co": 0.15,
    ".uk": 0.08,
    ".de": 0.06,
    ".fr": 0.07,
    ".au": 0.06,
    ".ca": 0.05,
    ".jp": 0.05,
    ".br": 0.10,
}

# Known benign and commonly whitelisted registered base domains
WHITELIST_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "twitter.com", "x.com",
    "instagram.com", "linkedin.com", "microsoft.com", "apple.com",
    "amazon.com", "netflix.com", "github.com", "stackoverflow.com",
    "wikipedia.org", "reddit.com", "whatsapp.com", "zoom.us",
    "dropbox.com", "spotify.com", "adobe.com", "cloudflare.com",
    "akamai.com", "fastly.com", "yahoo.com", "bing.com", "duckduckgo.com",
    "twitch.tv", "tiktok.com", "snapchat.com", "pinterest.com",
    "ebay.com", "paypal.com", "stripe.com", "shopify.com",
    "bbc.com", "cnn.com", "nytimes.com", "theguardian.com",
    "vit.ac.in", "vitap.ac.in", "bits-pilani.ac.in",
}


def get_tld_risk_score(domain: str) -> dict:
    """
    Compute the TLD reputation risk score for a domain.

    Args:
        domain: Fully qualified domain name (e.g., 'mail.google.com').

    Returns:
        dict with keys:
            tld (str)          – The extracted TLD (.com, .tk, etc.)
            tld_score (float)  – Risk score 0.0 (safe) to 1.0 (dangerous)
            is_whitelisted (bool) – True if in known-good list
            registered_domain (str)
    """
    try:
        import tldextract
        ext = extract_domain(domain)
        tld = f".{ext.suffix}" if ext.suffix else ".unknown"
        registered_domain = f"{ext.domain}.{ext.suffix}" if ext.domain else domain.lower()
    except Exception:
        parts = domain.rstrip(".").split(".")
        tld = f".{parts[-1]}" if len(parts) > 1 else ".unknown"
        registered_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()

    # Whitelist check — skip scoring for known-legit domains
    is_whitelisted = registered_domain.lower() in WHITELIST_DOMAINS

    # Look up risk table; default neutral score for unknown TLDs
    tld_score = TLD_RISK_TABLE.get(tld, 0.20) if not is_whitelisted else 0.0

    return {
        "domain": domain,
        "tld": tld,
        "tld_score": tld_score,
        "is_whitelisted": is_whitelisted,
        "registered_domain": registered_domain,
    }


def compute_tld_scores(df) -> "pd.DataFrame":
    """
    Apply TLD reputation scoring to every row in the traffic DataFrame.

    Args:
        df: DataFrame with a 'domain' column.

    Returns:
        DataFrame with columns [domain, tld, tld_score, is_whitelisted]
    """
    import pandas as pd
    records = [get_tld_risk_score(d) for d in df["domain"]]
    result = pd.DataFrame(records).drop_duplicates("domain")
    return result[["domain", "tld", "tld_score", "is_whitelisted"]]
