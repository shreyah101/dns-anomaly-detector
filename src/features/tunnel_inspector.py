"""
src/features/tunnel_inspector.py
Signal 6 / Deep Forensic Inspection: DNS Tunnelling & Exfiltration Decoder

DNS Tunneling encapsulates external protocols (SSH, HTTP, file exfiltration)
inside DNS queries (typically TXT, A, or CNAME records) using Base16 (Hex),
Base32, or Base64 encoding.

This module provides:
1. Multi-scheme encoding detection (Hex, Base32, Base64).
2. Subdomain payload extraction and decoded byte reconstruction.
3. Exfiltrated volume estimation (bytes leaked per client and per destination).
4. Tunneling suspicion score S_tunnel in [0.0, 1.0].
"""

import base64
import binascii
import re
import string
import pandas as pd
import numpy as np


def detect_encoding_scheme(text: str) -> dict:
    """
    Detect whether a subdomain label is encoded using Hex, Base32, or Base64,
    and attempt to decode candidate plain text.

    Parameters
    ----------
    text : str
        Subdomain label candidate.

    Returns
    -------
    dict with keys:
        is_encoded (bool), scheme (str), confidence (float),
        decoded_text (str or None), raw_bytes_len (int)
    """
    cleaned = text.strip().replace("-", "").replace("_", "")
    if len(cleaned) < 8:
        return {
            "is_encoded": False,
            "scheme": "PLAIN",
            "confidence": 0.0,
            "decoded_text": None,
            "raw_bytes_len": 0,
        }

    # 1. Test Hex / Base16 (0-9, a-f)
    if len(cleaned) % 2 == 0 and all(c in string.hexdigits for c in cleaned):
        try:
            raw = bytes.fromhex(cleaned)
            decoded_ascii = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw)
            printable_ratio = sum(32 <= b <= 126 for b in raw) / len(raw)
            return {
                "is_encoded": True,
                "scheme": "HEX / BASE16",
                "confidence": 0.95 if printable_ratio > 0.6 else 0.85,
                "decoded_text": decoded_ascii,
                "raw_bytes_len": len(raw),
            }
        except Exception:
            pass

    # 2. Test Base64 (mixed case A-Z, a-z, 0-9, +, /, =)
    has_mixed_case = bool(re.search(r"[a-z]", cleaned) and re.search(r"[A-Z]", cleaned))
    has_b64_special = ("+" in cleaned) or ("/" in cleaned) or ("=" in text)
    b64_chars = set(string.ascii_letters + string.digits + "+/=")

    if (has_mixed_case or has_b64_special) and len(cleaned) >= 8 and set(cleaned).issubset(b64_chars):
        pad_len = (4 - (len(cleaned) % 4)) % 4
        padded = cleaned + ("=" * pad_len)
        try:
            raw = base64.b64decode(padded)
            if len(raw) > 2:
                decoded_ascii = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw)
                printable_ratio = sum(32 <= b <= 126 for b in raw) / len(raw)
                return {
                    "is_encoded": True,
                    "scheme": "BASE64 (dnscat2-style)",
                    "confidence": 0.95 if printable_ratio > 0.4 else 0.80,
                    "decoded_text": decoded_ascii,
                    "raw_bytes_len": len(raw),
                }
        except Exception:
            pass

    # 3. Test Base32 (all uppercase A-Z and digits 2-7, used by Iodine DNS Tunnel)
    upper_cleaned = cleaned.upper()
    b32_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
    if not (re.search(r"[8901]", upper_cleaned)) and set(upper_cleaned).issubset(b32_chars) and len(upper_cleaned) >= 8:
        pad_len = (8 - (len(upper_cleaned) % 8)) % 8
        padded = upper_cleaned + ("=" * pad_len)
        try:
            raw = base64.b32decode(padded, casefold=True)
            if len(raw) > 2:
                decoded_ascii = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw)
                return {
                    "is_encoded": True,
                    "scheme": "BASE32 (Iodine-style)",
                    "confidence": 0.92,
                    "decoded_text": decoded_ascii,
                    "raw_bytes_len": len(raw),
                }
        except Exception:
            pass

    return {
        "is_encoded": False,
        "scheme": "UNENCODED / RANDOM",
        "confidence": 0.10,
        "decoded_text": None,
        "raw_bytes_len": 0,
    }


def inspect_tunneling_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Perform deep inspection of DNS tunneling and exfiltration behaviors across
    the traffic DataFrame.

    Parameters
    ----------
    df : pd.DataFrame
        Must contain 'domain', 'src_ip', and optionally 'subdomain_label' or 'qtype'.

    Returns
    -------
    pd.DataFrame with tunneling metrics per domain:
        domain, tunnel_score, encoding_scheme, estimated_payload_bytes,
        decoded_sample, is_tunneling_candidate
    """
    records = []

    for _, row in df.drop_duplicates([c for c in ["domain", "qtype"] if c in df]).iterrows():
        domain = str(row.get("domain", "")).lower()
        sub_label = str(row.get("subdomain_label", "") or "")
        if not sub_label:
            parts = domain.rstrip(".").split(".")
            sub_label = parts[0] if len(parts) > 2 else ""

        qtype = str(row.get("qtype", "A")).upper()

        enc = detect_encoding_scheme(sub_label)
        sub_len = len(sub_label)

        # Baseline length scoring
        len_weight = min(max((sub_len - 12) / 24.0, 0.0), 1.0)

        # Encoding weight
        enc_weight = enc["confidence"] if enc["is_encoded"] else 0.0

        # TXT record weight (TXT queries carry disproportionate tunneling traffic)
        qtype_weight = 0.30 if qtype in ("TXT", "NULL", "ANY") else 0.0

        # Subdomain depth (multiple dot-separated labels like chunk1.chunk2.tunnel.io)
        num_labels = domain.count(".")
        depth_weight = 0.20 if num_labels >= 3 else 0.0

        # Composite tunneling score
        tunnel_score = round(
            min(0.40 * enc_weight + 0.35 * len_weight + 0.15 * qtype_weight + 0.10 * depth_weight, 1.0),
            4
        )

        records.append({
            "domain": domain,
            "tunnel_score": tunnel_score,
            "encoding_scheme": enc["scheme"],
            "estimated_payload_bytes": enc["raw_bytes_len"] if enc["is_encoded"] else 0,
            "decoded_sample": enc["decoded_text"] if enc["decoded_text"] else "N/A",
            "is_tunneling_candidate": tunnel_score >= 0.50,
        })

    result = pd.DataFrame(records).sort_values("tunnel_score", ascending=False).drop_duplicates("domain")
    return result


def aggregate_exfiltration_by_host(df: pd.DataFrame, tunnel_df: pd.DataFrame = None) -> pd.DataFrame:
    """
    Aggregate total estimated exfiltrated volume and suspect query counts per source host.

    Parameters
    ----------
    df : pd.DataFrame
        Traffic logs with 'src_ip', 'domain', 'timestamp'.
    tunnel_df : pd.DataFrame, optional
        Output from inspect_tunneling_features.

    Returns
    -------
    pd.DataFrame with [src_ip, total_queries, suspect_tunnel_queries,
                        total_exfiltrated_bytes, exfil_risk_level]
    """
    if tunnel_df is None:
        tunnel_df = inspect_tunneling_features(df)

    merged = df.merge(tunnel_df, on="domain", how="left")

    records = []
    for src_ip, group in merged.groupby("src_ip"):
        total_q = len(group)
        suspect_q = int(group["is_tunneling_candidate"].sum())
        total_bytes = int(group.loc[group["is_tunneling_candidate"], "estimated_payload_bytes"].sum())

        if total_bytes > 500 or suspect_q >= 5:
            risk = "HIGH VOLUME CANDIDATE"
        elif total_bytes > 100 or suspect_q >= 2:
            risk = "HIGH RISK"
        elif suspect_q >= 1:
            risk = "SUSPICIOUS"
        else:
            risk = "NORMAL"

        records.append({
            "src_ip": src_ip,
            "total_queries": total_q,
            "suspect_tunnel_queries": suspect_q,
            "total_exfiltrated_bytes": total_bytes,
            "exfil_risk_level": risk,
        })

    return pd.DataFrame(records).sort_values("total_exfiltrated_bytes", ascending=False).reset_index(drop=True)


if __name__ == "__main__":
    test_labels = [
        "61646d696e2d70617373776f7264",  # Hex: admin-password
        "MFRGGZDFMY======",             # Base32: admin
        "dGVzdGluZyBleGZpbA==",         # Base64: testing exfil
        "mail",                         # Normal word
        "google",                       # Normal brand
    ]
    print(f"{'Label':<35} {'Scheme':<22} {'Conf':<6} {'Decoded Text'}")
    print("-" * 75)
    for lbl in test_labels:
        res = detect_encoding_scheme(lbl)
        print(f"{lbl:<35} {res['scheme']:<22} {res['confidence']:<6.2f} {res['decoded_text']}")
