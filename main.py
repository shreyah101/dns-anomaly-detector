"""
main.py -- CLI Entry Point for Explainable DNS Anomaly Detector (v3 Final Review)

Usage:
    python main.py                           # Run standard detection on synthetic CSV
    python main.py --pcap data/sample.pcap   # Analyze real PCAP/PCAPNG network packet capture
    python main.py --setup                   # Generate bigram table + synthetic CSV + sample PCAP
    python main.py --domain <name>           # Test custom domain (with decoding & DGA analysis)
    python main.py --domain <name> --beacon  # Simulate fixed C2 beacon timing
    python main.py --report --top 10         # Show full plain-English explanations
    python main.py --export-rules rules/     # Export Suricata, BIND RPZ, Pi-hole, iptables & STIX
    python main.py --sniff                   # Real-time live DNS query packet sniffer
    python main.py --z 2.5                   # Custom statistical threshold
"""

import argparse
import os
import sys
import numpy as np
import pandas as pd

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from src.dns_parser import load_traffic
from src.features.tunnel_inspector import aggregate_exfiltration_by_host
from src.mitigation import export_all_mitigations
from src.pcap_analyzer import load_pcap_traffic, generate_synthetic_pcap
from src.scorer import evaluate
from src.explainer import explain, format_report

BIGRAM_FILE = os.path.join(PROJECT_ROOT, "data", "bigram_english.json")
TRAFFIC_FILE = os.path.join(PROJECT_ROOT, "data", "synthetic_traffic.csv")
SAMPLE_PCAP_FILE = os.path.join(PROJECT_ROOT, "data", "sample_traffic.pcap")


def test_single_domain(domain: str, is_beacon: bool = False):
    """Analyze a single custom domain with multi-signal explainability, encoding decoding, and DGA checks."""
    print("=" * 74)
    print(f"  ANALYZING CUSTOM DOMAIN: {domain}")
    print("=" * 74)

    from src.pipeline import inspect_domain
    row = inspect_domain(domain, beacon=is_beacon)
    if is_beacon:
        print("Timing: simulated 30-second intervals (not observed traffic)")
    print(format_report(explain(row)))


def run_pipeline(
    df: pd.DataFrame,
    z_threshold: float,
    weights: dict,
    show_report: bool,
    top_n: int,
    export_rules_dir: str = None
):
    """Run the complete multi-signal detection and incident response pipeline."""
    print("=" * 74)
    print("  DNS ANOMALY DETECTOR")
    print("=" * 74)

    label_info = {}
    if "label" in df.columns and df["label"].notna().any():
        label_info = df["label"].value_counts().to_dict()
    print(f"[+] Loaded {len(df)} DNS records")
    if label_info:
        print(f"    Ground-truth distribution: {label_info}")

    from src.pipeline import analyze_traffic
    scored, timing_df, nxdomain_df, tunnel_df, adv_df, cdn_df = analyze_traffic(df, z_threshold, weights)

    anomalies = scored[scored["is_anomaly"]].copy()
    threshold_val = scored["threshold"].iloc[0] if len(scored) > 0 else 0
    sev_counts = scored["severity"].value_counts().to_dict() if "severity" in scored.columns else {}

    print()
    print("=" * 74)
    print("  DETECTION RESULTS SUMMARY")
    print("=" * 74)
    print(f"  Total queries analysed : {len(scored)}")
    print(f"  Anomalies detected     : {len(anomalies)} ({(len(anomalies)/max(len(scored),1))*100:.1f}%)")
    print(f"  Clean queries          : {(~scored['is_anomaly']).sum()}")
    print(f"  Risk cutoff            : {threshold_val:.4f}  (batch outlier z={z_threshold})")
    if sev_counts:
        print(f"  CRITICAL threats       : {sev_counts.get('CRITICAL', 0)}")
        print(f"  HIGH risk queries      : {sev_counts.get('HIGH', 0)}")
        print(f"  MEDIUM risk queries    : {sev_counts.get('MEDIUM', 0)}")
    print()

    # Evaluation against ground truth if present
    metrics = evaluate(scored)
    if metrics:
        print(f"  Evaluation Metrics (Ground Truth):")
        print(f"    Precision : {metrics['precision']*100:.1f}%   |   Recall : {metrics['recall']*100:.1f}%")
        print(f"    F1-Score  : {metrics['f1']:.3f}     |   AUC    : {metrics['auc'] if metrics['auc'] is not None else 'N/A'}")
        print()

    # Host-level Exfiltration summary
    exfil_summary = aggregate_exfiltration_by_host(df, tunnel_df)
    critical_exfil = exfil_summary[exfil_summary["total_exfiltrated_bytes"] > 0]
    if not critical_exfil.empty:
        print("  Estimated Encoded Payload Candidates:")
        for _, r in critical_exfil.head(5).iterrows():
            print(f"    Host {r['src_ip']}: ~{r['total_exfiltrated_bytes']} bytes across {r['suspect_tunnel_queries']} queries [{r['exfil_risk_level']}]")
        print()

    # Top anomalies table
    if len(anomalies) > 0:
        base_cols = ["domain", "src_ip", "entropy", "kl_divergence", "timing_score",
                     "tld_score", "tunnel_score", "anomaly_score", "severity"]
        sel_cols = [c for c in base_cols if c in anomalies.columns]
        if "label" in anomalies.columns and anomalies["label"].notna().any():
            sel_cols.append("label")

        disp = anomalies.nlargest(top_n, "anomaly_score")[sel_cols].copy()
        col_names = {
            "domain": "Domain", "src_ip": "Src IP", "entropy": "Entropy",
            "kl_divergence": "KL Div", "timing_score": "Timing",
            "tld_score": "TLD", "tunnel_score": "Tunnel",
            "anomaly_score": "Score", "severity": "Severity", "label": "Ground Truth"
        }
        disp = disp.rename(columns={k: v for k, v in col_names.items() if k in disp.columns})

        print(f"  Top {min(top_n, len(anomalies))} Flagged Anomalies:")
        try:
            from tabulate import tabulate
            print(tabulate(disp, headers="keys", tablefmt="simple", floatfmt=".4f", showindex=False))
        except ImportError:
            print(disp.to_string(index=False))
        print()

    # Full plain-English diagnostic report
    if show_report and len(anomalies) > 0:
        print()
        print("=" * 74)
        print("  PLAIN-ENGLISH DIAGNOSTIC BREAKDOWN")
        print("=" * 74)
        for _, row in anomalies.nlargest(top_n, "anomaly_score").iterrows():
            exp = explain(row.to_dict())
            print(format_report(exp))
            print()

    # Automated incident response rule export
    if export_rules_dir and len(anomalies) > 0:
        paths = export_all_mitigations(anomalies, output_dir=export_rules_dir)
        print(f"[+] Reviewable Defense Configurations Exported to '{export_rules_dir}':")
        for k, v in paths.items():
            print(f"    - {k:<10}: {v}")
        print()

    return scored, anomalies


def setup():
    """Build English reference bigrams, synthetic CSV, and sample PCAP capture."""
    print("=" * 74)
    print("  SETUP: Generating Reference Data & Sample Captures...")
    print("=" * 74)
    from src.generator import build_bigram_table, generate_benign_traffic, generate_malicious_traffic, save_traffic_csv
    import random

    build_bigram_table(BIGRAM_FILE)

    benign = generate_benign_traffic(n_queries=400)
    malicious = generate_malicious_traffic(n_queries=100)
    all_records = benign + malicious
    random.shuffle(all_records)
    save_traffic_csv(all_records, TRAFFIC_FILE)

    # Generate sample PCAP
    generate_synthetic_pcap(SAMPLE_PCAP_FILE, n_records=100)
    print("[+] Setup complete.\n")


def main():
    parser = argparse.ArgumentParser(
        description="Explainable Statistical DNS Anomaly Detector (v3 Final Review)"
    )
    parser.add_argument("--setup", action="store_true", help="Generate bigrams, synthetic CSV, and sample PCAP")
    parser.add_argument("--pcap", type=str, default=None, help="Path to .pcap or .pcapng network capture file")
    parser.add_argument("--domain", type=str, default=None, help="Inspect a custom domain in real time")
    parser.add_argument("--beacon", action="store_true", help="Simulate C2 beacon timing for custom domain")
    parser.add_argument("--input", default=TRAFFIC_FILE, help="Path to input DNS traffic CSV (default: synthetic)")
    parser.add_argument("--z", type=float, default=2.0, help="Z-score for the separate batch outlier diagnostic (default: 2.0)")
    parser.add_argument("--report", action="store_true", help="Print full plain-English explanations for anomalies")
    parser.add_argument("--top", type=int, default=15, help="Number of top anomalies to display (default: 15)")
    parser.add_argument("--export-rules", type=str, default=None, help="Directory to export Suricata/RPZ/Pi-hole rules")
    parser.add_argument("--sniff", action="store_true", help="Start real-time live DNS query packet sniffer")

    # Weights
    parser.add_argument("--w-entropy", type=float, default=0.25, help="Weight for Shannon entropy")
    parser.add_argument("--w-kl", type=float, default=0.25, help="Weight for Bigram KL-divergence")
    parser.add_argument("--w-timing", type=float, default=0.15, help="Weight for timing regularity")
    parser.add_argument("--w-tld", type=float, default=0.15, help="Weight for TLD reputation")
    parser.add_argument("--w-length", type=float, default=0.10, help="Weight for label length")
    parser.add_argument("--w-tunnel", type=float, default=0.05, help="Weight for tunneling inspection")
    parser.add_argument("--w-adv", type=float, default=0.05, help="Weight for dictionary-DGA defense")

    args = parser.parse_args()
    if args.top < 1 or not np.isfinite(args.z) or args.z < 0:
        parser.error("--top must be positive and --z must be finite and non-negative")

    if args.setup:
        setup()

    if args.sniff:
        from src.live_sniffer import live_sniff_dns
        def alert_cb(evt):
            print(f"[{evt['timestamp'].strftime('%H:%M:%S')}] {evt['src_ip']:<15} -> {evt['domain']}")
        live_sniff_dns(alert_cb, duration_sec=20)
        return

    if args.domain:
        test_single_domain(args.domain, is_beacon=args.beacon)
        return

    # Ingest from PCAP or CSV
    if args.pcap:
        if not os.path.exists(args.pcap):
            print(f"[!] PCAP file not found: '{args.pcap}'")
            sys.exit(1)
        df = load_pcap_traffic(args.pcap)
    else:
        if not os.path.exists(args.input):
            print(f"[!] Input file not found: '{args.input}'")
            print("    Run: python main.py --setup  to generate datasets.")
            sys.exit(1)
        df = load_traffic(args.input)

    weights = {
        "entropy": args.w_entropy,
        "kl_divergence": args.w_kl,
        "timing": args.w_timing,
        "tld": args.w_tld,
        "length": args.w_length,
        "tunneling": args.w_tunnel,
        "adversarial": args.w_adv,
    }

    run_pipeline(df, args.z, weights, args.report, args.top, export_rules_dir=args.export_rules)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, ImportError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
