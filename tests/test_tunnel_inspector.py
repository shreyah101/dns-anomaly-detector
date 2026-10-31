"""
tests/test_tunnel_inspector.py
Automated Unit Tests for DNS Tunneling & Payload Forensic Inspection
"""

import pandas as pd
import pytest
from src.features.tunnel_inspector import (
    detect_encoding_scheme, inspect_tunneling_features, aggregate_exfiltration_by_host
)


def test_detect_hex_encoding():
    # 'admin-password' in hex
    hex_str = "61646d696e2d70617373776f7264"
    res = detect_encoding_scheme(hex_str)
    assert res["is_encoded"] is True
    assert "HEX" in res["scheme"]
    assert res["decoded_text"] == "admin-password"
    assert res["raw_bytes_len"] == 14


def test_detect_base64_encoding():
    # 'testing exfil' in base64
    b64_str = "dGVzdGluZyBleGZpbA=="
    res = detect_encoding_scheme(b64_str)
    assert res["is_encoded"] is True
    assert "BASE64" in res["scheme"]
    assert res["decoded_text"] == "testing exfil"


def test_detect_plain_text():
    plain = "mail"
    res = detect_encoding_scheme(plain)
    assert res["is_encoded"] is False
    assert res["scheme"] == "PLAIN"
    assert res["decoded_text"] is None


def test_inspect_tunneling_features_dataframe():
    df = pd.DataFrame([
        {"domain": "61646d696e2d70617373776f7264.tunnel.io", "subdomain_label": "61646d696e2d70617373776f7264", "qtype": "TXT"},
        {"domain": "mail.google.com", "subdomain_label": "mail", "qtype": "A"},
    ])
    result = inspect_tunneling_features(df)
    assert len(result) == 2
    assert "tunnel_score" in result.columns
    assert "encoding_scheme" in result.columns

    # Tunneling row should have high score
    tunnel_row = result[result["domain"] == "61646d696e2d70617373776f7264.tunnel.io"].iloc[0]
    benign_row = result[result["domain"] == "mail.google.com"].iloc[0]

    assert tunnel_row["tunnel_score"] > benign_row["tunnel_score"]
    assert bool(tunnel_row["is_tunneling_candidate"]) is True
    assert bool(benign_row["is_tunneling_candidate"]) is False


def test_aggregate_exfiltration_by_host():
    df = pd.DataFrame([
        {"domain": "chunk1.tunnel.io", "subdomain_label": "61646d696e2d70617373776f726401", "src_ip": "10.0.0.50"},
        {"domain": "chunk2.tunnel.io", "subdomain_label": "61646d696e2d70617373776f726402", "src_ip": "10.0.0.50"},
        {"domain": "google.com", "subdomain_label": "google", "src_ip": "10.0.0.50"},
        {"domain": "wikipedia.org", "subdomain_label": "wikipedia", "src_ip": "10.0.0.51"},
    ])
    exfil_df = aggregate_exfiltration_by_host(df)
    assert len(exfil_df) == 2
    host_50 = exfil_df[exfil_df["src_ip"] == "10.0.0.50"].iloc[0]
    assert host_50["suspect_tunnel_queries"] >= 2
    assert host_50["total_exfiltrated_bytes"] > 0
