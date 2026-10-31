"""
tests/test_mitigation.py
Automated Unit Tests for Automated Incident Response & Mitigation Generator
"""

import os
import tempfile
import pandas as pd
from src.mitigation import (
    generate_suricata_rules, generate_bind_rpz_zone, generate_pihole_blocklist,
    generate_iptables_script, generate_windows_firewall_script, generate_stix_bundle,
    export_all_mitigations
)


def sample_anomalies_df():
    return pd.DataFrame([
        {"domain": "c6d8205dc3d3b1b5cbb67fe.phishing.cn", "anomaly_score": 0.85, "severity": "CRITICAL"},
        {"domain": "qxa3e3u61mpzga8d3.dga.tk", "anomaly_score": 0.81, "severity": "HIGH"},
    ])


def test_generate_suricata_rules():
    df = sample_anomalies_df()
    rules = generate_suricata_rules(df)
    assert "drop dns $HOME_NET" in rules
    assert "c6d8205dc3d3b1b5cbb67fe.phishing.cn" in rules
    assert "sid:3000001" in rules


def test_generate_bind_rpz_zone():
    df = sample_anomalies_df()
    rpz = generate_bind_rpz_zone(df)
    assert "$TTL 300" in rpz
    assert "c6d8205dc3d3b1b5cbb67fe.phishing.cn CNAME ." in rpz


def test_generate_pihole_blocklist():
    df = sample_anomalies_df()
    blocklist = generate_pihole_blocklist(df)
    assert "0.0.0.0 c6d8205dc3d3b1b5cbb67fe.phishing.cn" in blocklist
    assert "0.0.0.0 qxa3e3u61mpzga8d3.dga.tk" in blocklist


def test_generate_stix_bundle():
    df = sample_anomalies_df()
    bundle = generate_stix_bundle(df)
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) == 2
    assert "indicator" == bundle["objects"][0]["type"]
    assert "T1568.002" in str(bundle)


def test_export_all_mitigations():
    with tempfile.TemporaryDirectory() as tmpdir:
        df = sample_anomalies_df()
        paths = export_all_mitigations(df, output_dir=tmpdir)
        for key, p in paths.items():
            assert os.path.exists(p)
            assert os.path.getsize(p) > 20
