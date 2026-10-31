"""Regression checks for ingestion, scoring, packet responses, and evaluation."""
import io
import uuid
import numpy as np
import pandas as pd
import pytest
from src.dns_parser import load_traffic
from src.pipeline import analyze_traffic, inspect_domain
from src.scorer import evaluate
from src.mitigation import generate_stix_bundle, generate_windows_firewall_script, generate_iptables_script


def traffic(domains):
    return pd.DataFrame({"domain": domains, "timestamp": np.arange(len(domains)) * 30 + 1700000000,
                         "src_ip": ["10.0.0.1"] * len(domains)})


def test_csv_epoch_response_codes_and_untrusted_grouping():
    frame = load_traffic(io.StringIO("timestamp,src_ip,domain,registered_domain,response_code\n1700000000,10.0.0.1,Mail.Google.COM.,evil.com,NXDOMAIN\n"))
    assert frame.domain.iloc[0] == "mail.google.com"
    assert frame.registered_domain.iloc[0] == "google.com"
    assert frame.timestamp.iloc[0].year == 2023
    assert frame.response_code.iloc[0] == "NXDOMAIN"


@pytest.mark.parametrize("domain", ["", "x; rm -rf /", "https://example.com", "a..com", "a"*64+".com"])
def test_invalid_domains(domain):
    with pytest.raises(ValueError):
        inspect_domain(domain)


def test_scores_do_not_depend_on_other_domains():
    domain = "qxa3e3u61mpzga8d3.dga.tk"
    single = inspect_domain(domain)
    batch = analyze_traffic(traffic([domain, "mail.google.com"]))[0]
    assert single["anomaly_score"] == batch.loc[batch.domain == domain, "anomaly_score"].iloc[0]
    assert pd.isna(single["timing_score"])
    homogeneous = analyze_traffic(traffic([domain]))[0]
    assert bool(homogeneous.is_anomaly.iloc[0])


def test_encoded_subdomain_cannot_bypass_known_name():
    row = inspect_domain("61646d696e2d70617373776f7264.google.com")
    assert row["anomaly_score"] > 0
    assert row["tunnel_score"] >= 0.5


def test_missing_responses_not_inferred_from_lexical_features():
    result = analyze_traffic(traffic(["qxa3e3u61mpzga8d3.dga.tk"]))
    assert result[2].observed_responses.iloc[0] == 0
    assert pd.isna(result[2].nxdomain_rate.iloc[0])


def test_timing_uses_seconds_with_any_datetime_resolution():
    frame = traffic(["beacon.example.com"] * 12)
    timing = analyze_traffic(frame)[1]
    assert timing.mean_interval_sec.iloc[0] == 30
    assert timing.timing_score.iloc[0] == 1


def test_invalid_weights_are_rejected():
    for weights in [{"entropy": 0}, {"entropy": -1}, {"entropy": float("nan")}]:
        with pytest.raises(ValueError):
            analyze_traffic(traffic(["example.com"]), weights=weights)


def test_evaluation_excludes_unknown_labels_and_handles_ties():
    frame = pd.DataFrame({"label": ["benign", "malicious", None, "other"],
                          "is_anomaly": [False, False, True, True], "anomaly_score": [.5, .5, 1, 1]})
    result = evaluate(frame)
    assert result["evaluated_rows"] == 2
    assert result["auc"] == .5
    assert result["fp"] == 0
    assert evaluate(frame.iloc[:1])["auc"] is None


def test_export_formats_use_valid_identifiers_and_wire_labels():
    frame = pd.DataFrame({"domain": ["evil.example.com", "evil.example.com"], "anomaly_score": [.8, .8]})
    bundle = generate_stix_bundle(frame)
    assert len(bundle["objects"]) == 1
    uuid.UUID(bundle["id"].split("--")[1])
    uuid.UUID(bundle["objects"][0]["id"].split("--")[1])
    assert "Join-Path $env:SystemRoot" in generate_windows_firewall_script(frame)
    assert "--hex-string '|046576696c076578616d706c6503636f6d00|'" in generate_iptables_script(frame)


def test_packet_responses_do_not_become_extra_queries(tmp_path):
    from scapy.all import IP, UDP, DNS, DNSQR, wrpcap
    from src.pcap_analyzer import load_pcap_traffic
    query = IP(src="10.0.0.1", dst="8.8.8.8")/UDP(sport=51000, dport=53)/DNS(id=7, qd=DNSQR(qname="missing.example.com"))
    response = IP(src="8.8.8.8", dst="10.0.0.1")/UDP(sport=53, dport=51000)/DNS(id=7, qr=1, rcode=3, qd=DNSQR(qname="missing.example.com"))
    query.time, response.time = 1700000000, 1700000001
    filename = tmp_path / "response.pcap"
    wrpcap(str(filename), [query, response])
    frame = load_pcap_traffic(str(filename))
    assert len(frame) == 1
    assert frame.src_ip.iloc[0] == "10.0.0.1"
    assert frame.response_code.iloc[0] == "NXDOMAIN"
    assert analyze_traffic(frame)[2].nxdomain_rate.iloc[0] == 1


def test_uploaded_feature_columns_are_recomputed():
    frame = traffic(["example.com"])
    frame["tld_score"] = 1.0
    frame["timing_score"] = 1.0
    frame["anomaly_score"] = 1.0
    result = analyze_traffic(frame)[0]
    assert result.tld_score.iloc[0] == 0.1
    assert pd.isna(result.timing_score.iloc[0])
    assert result.anomaly_score.iloc[0] < 0.6


def test_missing_label_does_not_break_plain_text_report():
    from src.explainer import explain, format_report
    row = inspect_domain("example.com")
    row["label"] = pd.NA
    assert "example.com" in format_report(explain(row))


def test_malformed_capture_has_readable_error(tmp_path):
    from src.pcap_analyzer import load_pcap_traffic
    filename = tmp_path / "invalid.pcap"
    filename.write_bytes(b"not a packet capture")
    with pytest.raises(ValueError, match="valid PCAP"):
        load_pcap_traffic(str(filename))
