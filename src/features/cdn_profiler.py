"""
src/features/cdn_profiler.py
Intelligent Content Delivery Network (CDN) & Cloud Architecture Profiler

Prevents false positive alarms on legitimate enterprise cloud services and CDNs
(such as AWS CloudFront, Akamai, Azure Edge, Google 1e100, Fastly) which frequently
deploy hex-hashed or tokenized dynamic routing subdomains.
"""

import pandas as pd
from typing import Dict, Tuple

# Known CDN & Cloud infrastructure provider apex domains and patterns
KNOWN_CDN_DOMAINS = {
    "akamaiedge.net": "Akamai CDN",
    "akamai.net": "Akamai CDN",
    "akadns.net": "Akamai Edge DNS",
    "cloudfront.net": "AWS CloudFront",
    "amazonaws.com": "AWS Cloud Infrastructure",
    "azureedge.net": "Microsoft Azure Edge",
    "trafficmanager.net": "Azure Traffic Manager",
    "fastly.net": "Fastly CDN",
    "fastlylb.net": "Fastly Load Balancer",
    "cloudflare.net": "Cloudflare Edge",
    "1e100.net": "Google Global Cache",
    "googleusercontent.com": "Google User Content CDN",
    "fbcdn.net": "Meta Facebook CDN",
    "edgesuite.net": "Akamai EdgeSuite",
    "msecnd.net": "Microsoft Production CDN",
}

# Subdomain prefix tokens commonly used by legitimate cloud load balancers
CDN_ROUTING_TOKENS = {
    "dualstack", "edge", "edgekey", "dscg", "lb", "cdn", "cache",
    "prod", "corp", "origin", "static", "res", "assets"
}


def profile_cdn_domain(domain: str) -> dict:
    """
    Profile a domain to determine if it is an authentic enterprise CDN or
    Cloud service rather than an adversarial DGA or exfiltration channel.

    Parameters
    ----------
    domain : str
        FQDN to evaluate.

    Returns
    -------
    dict with:
        is_cdn (bool), cdn_provider (str or None),
        attenuation_factor (float) : multiplier to attenuate false alarms (0.0 to 1.0)
    """
    domain = domain.lower().strip()
    parts = domain.rstrip(".").split(".")

    if len(parts) < 2:
        return {"is_cdn": False, "cdn_provider": None, "attenuation_factor": 1.0}

    # Match registered domain against CDN directory
    reg_domain = ".".join(parts[-2:])
    provider = KNOWN_CDN_DOMAINS.get(reg_domain)

    # Check 3-part domains (e.g. s3.amazonaws.com)
    if not provider and len(parts) >= 3:
        reg_domain_3 = ".".join(parts[-3:])
        provider = KNOWN_CDN_DOMAINS.get(reg_domain_3)

    if provider:
        # Check if subdomains contain legitimate routing tokens
        has_cdn_token = any(tok in parts[:-2] for tok in CDN_ROUTING_TOKENS)
        attenuation = 0.20 if has_cdn_token else 0.35
        return {
            "is_cdn": True,
            "cdn_provider": provider,
            "attenuation_factor": attenuation,
            "reason": f"Known provider suffix ({provider}); tenant trust has not been verified."
        }

    return {
        "is_cdn": False,
        "cdn_provider": None,
        "attenuation_factor": 1.0,
        "reason": "Standard non-CDN domain."
    }


def compute_cdn_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Generate CDN profiling records for every domain in DataFrame.

    Parameters
    ----------
    df : pd.DataFrame with 'domain'.

    Returns
    -------
    pd.DataFrame with: [domain, is_cdn, cdn_provider, cdn_attenuation]
    """
    records = []
    for d in df["domain"]:
        res = profile_cdn_domain(str(d))
        records.append({
            "domain": d,
            "is_cdn": res["is_cdn"],
            "cdn_provider": res["cdn_provider"] or "N/A",
            "cdn_attenuation": res["attenuation_factor"],
        })

    return pd.DataFrame(records).drop_duplicates("domain")


if __name__ == "__main__":
    test_domains = [
        "d123456abcdef8.cloudfront.net",
        "a1873.dscg.akamai.net",
        "s3.dualstack.us-east-1.amazonaws.com",
        "qxa3e3u61mpzga8d3.dga.tk",
        "c6d8205dc3d3b1b5cbb67fe.phishing.cn",
    ]
    print(f"{'Domain':<42} {'Is CDN?':<10} {'Provider':<24} {'Attenuation'}")
    print("-" * 88)
    for d in test_domains:
        r = profile_cdn_domain(d)
        print(f"{d:<42} {str(r['is_cdn']):<10} {str(r['cdn_provider']):<24} {r['attenuation_factor']:.2f}")
