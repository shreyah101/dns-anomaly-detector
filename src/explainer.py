"""
explainer.py -- Plain-English Multi-Signal Explanation Engine (v3 Final Review)

For every flagged anomaly, this module produces a human-readable, mathematically
grounded explanation of WHY the domain was flagged, detailing individual signal
breaches, severity tiers, and recommended mitigation actions.

Signals Evaluated:
  1. Shannon Character Entropy (H)
  2. Bigram KL-Divergence from English (D_KL)
  3. Inter-Query Timing Regularity (T) & Clock Periodicity
  4. Top-Level Domain (TLD) Reputation & Whitelist Filtering
  5. Subdomain Structural Label Length
  6. DNS Tunneling & Encoded Payload Exfiltration (Hex/Base32/Base64)
  7. Adversarial Dictionary-DGA Lexical Composition
"""

from typing import Optional, Dict, List

# Calibrated signal thresholds
ENTROPY_LOW    = 3.0   # below this = normal
ENTROPY_HIGH   = 3.8   # above this = suspicious

KL_LOW         = 4.0   # below this = natural English phonotactics
KL_HIGH        = 8.0   # above this = unnatural / non-English bigrams

TIMING_LOW     = 0.35  # below this = irregular / human-like
TIMING_HIGH    = 0.70  # above this = automated beaconing

TLD_LOW        = 0.20
TLD_HIGH       = 0.60

LENGTH_LOW     = 10
LENGTH_HIGH    = 15


def _entropy_verdict(entropy: float, label: str) -> dict:
    if entropy >= ENTROPY_HIGH:
        level = "HIGH"
        flag = True
        reason = (
            f"Label '{label}' exhibits Shannon entropy {entropy:.2f} bits. "
            f"High character-level randomness, typical of algorithmic DGA generation "
            f"or binary exfiltration chunks."
        )
    elif entropy >= ENTROPY_LOW:
        level = "MEDIUM"
        flag = False
        reason = (
            f"Label '{label}' has entropy {entropy:.2f} bits. "
            f"Slightly elevated character diversity, but within acceptable limits."
        )
    else:
        level = "LOW"
        flag = False
        reason = (
            f"Label '{label}' has entropy {entropy:.2f} bits. "
            f"Normal lexical distribution typical of readable words."
        )
    return {"signal": "Shannon Entropy (H)", "level": level, "flag": flag, "reason": reason, "value": round(entropy, 4)}


def _kl_verdict(kl: float, label: str) -> dict:
    if kl >= KL_HIGH:
        level = "HIGH"
        flag = True
        reason = (
            f"Bigram KL divergence D_KL = {kl:.2f} vs English reference. "
            f"Character transitions in '{label}' differ from the bundled English reference. "
            f"High concentration of anomalous consonant pairs or digit transitions."
        )
    elif kl >= KL_LOW:
        level = "MEDIUM"
        flag = False
        reason = (
            f"Bigram KL divergence = {kl:.2f}. "
            f"Slight divergence from English bigram frequency, but acceptable."
        )
    else:
        level = "LOW"
        flag = False
        reason = (
            f"Bigram KL divergence = {kl:.2f}. "
            f"Character pairs follow natural English language patterns."
        )
    return {"signal": "Bigram KL-Divergence", "level": level, "flag": flag, "reason": reason, "value": round(kl, 4)}


def _timing_verdict(timing_score: float, cv: float = None) -> dict:
    cv_str = f"CV = {cv:.3f}" if cv is not None and not (cv != cv) else "CV = N/A"

    if timing_score is None or (timing_score != timing_score):
        return {
            "signal": "Timing Regularity (T)", "level": "UNKNOWN", "flag": False,
            "reason": "Insufficient query history to evaluate temporal periodicity.",
            "value": None
        }

    if timing_score >= TIMING_HIGH:
        level = "HIGH"
        flag = True
        reason = (
            f"Timing regularity index T = {timing_score:.3f} ({cv_str}). "
            f"Queries arrive at deterministic clock intervals with near-zero jitter. "
            f"Regular automated traffic; investigate its purpose."
        )
    elif timing_score >= TIMING_LOW:
        level = "MEDIUM"
        flag = False
        reason = (
            f"Timing regularity score T = {timing_score:.3f} ({cv_str}). "
            f"Moderate temporal periodicity detected."
        )
    else:
        level = "LOW"
        flag = False
        reason = (
            f"Timing regularity score T = {timing_score:.3f} ({cv_str}). "
            f"Query arrival times are bursty and irregular (human browsing pattern)."
        )
    return {"signal": "Timing Regularity (T)", "level": level, "flag": flag, "reason": reason, "value": round(timing_score, 4)}


def _tld_verdict(tld_score: float, tld: str = None, is_whitelisted: bool = False) -> dict:
    if is_whitelisted:
        return {
            "signal": "TLD Reputation", "level": "SAFE", "flag": False,
            "reason": f"Domain is in the local known-name list. This does not establish that its subdomains are safe.",
            "value": 0.0
        }
    tld_name = tld or "N/A"
    if tld_score >= TLD_HIGH:
        level = "HIGH"
        flag = True
        reason = f"TLD '{tld_name}' has empirical abuse risk score {tld_score:.2f} (heavily abused/free registrar)."
    elif tld_score >= TLD_LOW:
        level = "MEDIUM"
        flag = False
        reason = f"TLD '{tld_name}' has moderate risk score {tld_score:.2f}."
    else:
        level = "LOW"
        flag = False
        reason = f"TLD '{tld_name}' is standard commercial/educational registry (risk {tld_score:.2f})."
    return {"signal": "TLD Reputation", "level": level, "flag": flag, "reason": reason, "value": round(tld_score, 4)}


def _length_verdict(raw_length: int, length_score: float = None) -> dict:
    if raw_length >= LENGTH_HIGH:
        level = "HIGH"
        flag = True
        reason = f"Subdomain length is {raw_length} characters (typical DGA/tunneling payload size)."
    elif raw_length >= LENGTH_LOW:
        level = "MEDIUM"
        flag = False
        reason = f"Subdomain length is {raw_length} characters (slightly elevated but within range)."
    else:
        level = "LOW"
        flag = False
        reason = f"Subdomain length is {raw_length} characters (concise human-readable label)."
    return {"signal": "Label Length", "level": level, "flag": flag, "reason": reason, "value": raw_length}


def _tunnel_verdict(tunnel_score: float, scheme: str = None, payload_bytes: int = 0, sample: str = None) -> Optional[dict]:
    if tunnel_score is None or tunnel_score < 0.35:
        return None
    flag = tunnel_score >= 0.50
    level = "HIGH" if tunnel_score >= 0.70 else "MEDIUM"
    sample_str = f" | Decoded preview: '{sample}'" if sample and sample != "N/A" else ""
    reason = (
        f"Tunnel score {tunnel_score:.2f} (Scheme: {scheme or 'ENCODED'}, "
        f"Payload ~{payload_bytes} bytes{sample_str})."
    )
    return {"signal": "DNS Tunneling / Exfil", "level": level, "flag": flag, "reason": reason, "value": round(tunnel_score, 4)}


def _adversarial_verdict(dict_score: float, tokens: list = None) -> Optional[dict]:
    if dict_score is None or dict_score < 0.40:
        return None
    tok_str = ", ".join(tokens) if tokens else "multiple"
    return {
        "signal": "Dictionary-DGA Evasion", "level": "HIGH", "flag": True,
        "reason": f"Concatenation of {len(tokens) if tokens else 3}+ dictionary words [{tok_str}] matching the dictionary concatenation heuristic.",
        "value": round(dict_score, 4)
    }


def explain(row: dict) -> dict:
    """
    Generate an exhaustive, multi-signal explainability breakdown for a query row.
    """
    domain        = row.get("domain", "unknown")
    entropy       = float(row.get("entropy", 0.0))
    kl            = float(row.get("kl_divergence", 0.0))
    timing        = row.get("timing_score", None)
    cv            = row.get("cv", None)
    tld_score     = float(row.get("tld_score", 0.15))
    tld           = row.get("tld", "")
    is_wl         = bool(row.get("is_whitelisted", False))
    raw_length    = int(row.get("label_length_raw", row.get("label_length", len(domain.split(".")[0]))))
    score         = float(row.get("anomaly_score", 0.0))
    is_anomaly    = bool(row.get("is_anomaly", False))
    sev           = row.get("severity", "LOW")

    # Optional deep features
    tunnel_s      = row.get("tunnel_score", None)
    enc_scheme    = row.get("encoding_scheme", None)
    payload_b     = row.get("estimated_payload_bytes", 0)
    decoded_s     = row.get("decoded_sample", None)
    dict_dga_s    = row.get("dict_dga_score", None)
    dict_tokens   = row.get("dict_words_found", "")
    dict_tok_list = [w.strip() for w in dict_tokens.split(",") if w.strip()] if isinstance(dict_tokens, str) else []

    sub_label = row.get("subdomain_label", None) or row.get("label_y", None) or row.get("label", None)
    if sub_label in ("benign", "malicious", None, ""):
        sub_label = domain.split(".")[0]

    signals = [
        _entropy_verdict(entropy, str(sub_label)),
        _kl_verdict(kl, str(sub_label)),
        _timing_verdict(float(timing) if timing is not None and timing == timing else None, float(cv) if cv is not None and cv == cv else None),
        _tld_verdict(tld_score, tld, is_wl),
        _length_verdict(raw_length),
    ]

    t_diag = _tunnel_verdict(float(tunnel_s) if tunnel_s is not None else None, enc_scheme, int(payload_b or 0), decoded_s)
    if t_diag:
        signals.append(t_diag)

    a_diag = _adversarial_verdict(float(dict_dga_s) if dict_dga_s is not None else None, dict_tok_list)
    if a_diag:
        signals.append(a_diag)

    flags_triggered = sum(s["flag"] for s in signals)

    if is_anomaly:
        overall = f"{sev} RISK -- Heuristic score exceeds the 0.60 review cutoff."
        rec = "Review the source host, query history, and destination ownership before applying any block rules."
    else:
        overall = "BELOW REVIEW CUTOFF -- Available evidence does not exceed the heuristic threshold."
        rec = "Retain the observation; a low score does not establish that a domain is safe."

    return {
        "domain": domain,
        "anomaly_score": round(score, 4),
        "is_anomaly": is_anomaly,
        "severity": sev,
        "true_label": row.get("label") if isinstance(row.get("label"), str) else None,
        "overall_verdict": overall,
        "recommendation": rec,
        "flags_triggered": flags_triggered,
        "signals": signals,
    }


def format_report(explanation: dict) -> str:
    """Format explanation into a clean CLI report."""
    lines = []
    sep = "=" * 74
    lines.append(sep)
    icon = "[CRITICAL ALERT]" if explanation.get("severity") == "CRITICAL" else "[ANOMALY ALERT]" if explanation["is_anomaly"] else "[CLEAN QUERY   ]"
    lines.append(f"  Domain        : {explanation['domain']}")
    lines.append(f"  Anomaly Score : {explanation['anomaly_score']:.4f}  {icon}")
    lines.append(f"  Severity Tier : {explanation.get('severity', 'LOW')}")
    if explanation.get("true_label"):
        lines.append(f"  Ground Truth  : {str(explanation['true_label']).upper()}")
    lines.append(f"  Diagnosis     : {explanation['overall_verdict']}")
    lines.append(f"  SOC Action    : {explanation['recommendation']}")
    lines.append("")
    lines.append("  Mathematical Signal Breakdown:")
    for sig in explanation["signals"]:
        flag_mark = "[!]" if sig["flag"] else "[ ]"
        val_str = f"{sig['value']}" if sig["value"] is not None else "N/A"
        lines.append(f"    {flag_mark} {sig['signal']:<24} ({sig['level']:<6}) : {val_str}")
        lines.append(f"        -- {sig['reason']}")
    lines.append(sep)
    return "\n".join(lines)
