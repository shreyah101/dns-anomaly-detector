"""Streamlit interface for inspecting DNS traffic and its supporting evidence."""
import io
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.dns_parser import load_traffic
from src.pipeline import analyze_traffic, inspect_domain
from src.scorer import DEFAULT_WEIGHTS, evaluate
from src.explainer import explain, format_report
from src.features.tunnel_inspector import aggregate_exfiltration_by_host
from src.pcap_analyzer import load_pcap_traffic, generate_synthetic_pcap
from src.mitigation import (generate_suricata_rules, generate_bind_rpz_zone,
    generate_pihole_blocklist, generate_iptables_script,
    generate_windows_firewall_script, generate_stix_bundle)

from dashboard.theme import apply_dark_theme, style_axes, line_chart, BLUE, AMBER, BACKGROUND
from src.traffic_summary import activity_timeline, host_summary

st.set_page_config(page_title="DNS Traffic Analysis", layout="wide")
apply_dark_theme()


@st.cache_data(show_spinner=False, max_entries=4, ttl=900)
def analyze_bytes(content, kind, z, weights):
    if kind == "csv":
        frame = load_traffic(io.BytesIO(content))
    else:
        # Temporary captures are closed before Scapy opens them on Windows.
        with tempfile.NamedTemporaryFile(suffix="." + kind, delete=False) as handle:
            handle.write(content)
            filename = handle.name
        try:
            frame = load_pcap_traffic(filename)
        finally:
            os.unlink(filename)
    return analyze_traffic(frame, z, weights)


def render_evidence(row):
    report = explain(row)
    st.subheader(row["domain"])
    st.caption(f"Client {row['src_ip']} | Severity {row['severity']} | Score {row['anomaly_score']:.3f}")
    st.write(report["overall_verdict"])
    st.dataframe(pd.DataFrame(report["signals"])[["signal", "value", "level", "reason"]],
                 hide_index=True, use_container_width=True)
    st.caption(report["recommendation"])
    st.download_button("Download evidence report", format_report(report), "dns_evidence.txt", key="evidence_"+str(row.get("src_ip"))+row["domain"])


with st.sidebar:
    st.title("DNS Analysis")
    st.caption("COMPUTER NETWORKS / BCSE308P")
    page = st.radio("Workspace", ["Traffic analysis", "Domain inspector", "Method & project"])
    st.divider()
    with st.expander("Analysis settings"):
        z = st.slider("Batch outlier z-score", 0.5, 4.0, 2.0, 0.1,
                      help="Controls the separate batch outlier marker. Risk flags use a fixed 0.60 cutoff.")
        weights = {key: st.number_input(key.replace("_", " ").title(), min_value=0.0,
                   max_value=1.0, value=float(value), step=0.05, key="weight_"+key)
                   for key, value in DEFAULT_WEIGHTS.items()}
        st.caption("Positive weights are normalized to sum to one. Encoding and dictionary heuristics add fixed score adjustments.")
    st.caption("Statistical heuristics for triage. Scores are not probabilities of malicious activity.")

st.title("DNS traffic analysis")
st.caption("Inspect query patterns, compare statistical signals, and review the evidence behind each finding.")

if page == "Traffic analysis":
    with st.container(border=True):
        c1, c2 = st.columns([1, 2])
        source = c1.selectbox("Traffic source", ["Included CSV sample", "Upload CSV", "Upload PCAP / PCAPNG", "Generate sample PCAP"])
        upload = None
        if source.startswith("Upload"):
            upload = c2.file_uploader("Select traffic file", type=["csv"] if source == "Upload CSV" else ["pcap", "pcapng"])
        else:
            c2.write("The included data is synthetic and intended for demonstration and regression checks.")
        run = st.button("Analyze traffic", type="primary", disabled=sum(weights.values()) == 0)
        st.caption("CSV requires timestamp, src_ip, domain. Optional: label, qtype, response_code. Timestamps may be ISO datetimes or Unix seconds.")
    if sum(weights.values()) == 0:
        st.error("Set at least one signal weight above zero.")
    signature = (source, upload.name if upload else None, hashlib.sha256(upload.getvalue()).hexdigest() if upload else None, z, tuple(weights.items()))
    if run:
        try:
            if source.startswith("Upload") and upload is None:
                raise ValueError("Choose a file before running analysis.")
            with st.spinner("Parsing traffic and computing features..."):
                if source == "Included CSV sample":
                    content, kind = (ROOT / "data/synthetic_traffic.csv").read_bytes(), "csv"
                elif source == "Generate sample PCAP":
                    with tempfile.TemporaryDirectory() as directory:
                        capture = Path(directory) / "sample.pcap"
                        generate_synthetic_pcap(str(capture), 120)
                        content = capture.read_bytes()
                    kind = "pcap"
                else:
                    content, kind = upload.getvalue(), Path(upload.name).suffix[1:].lower()
                result = analyze_bytes(content, kind, z, weights)
            st.session_state["analysis"] = (result, signature, source)
        except (ValueError, OSError, ImportError, EOFError) as exc:
            st.error(f"Analysis could not run: {exc}")
    if "analysis" not in st.session_state:
        st.info("Choose a source and select Analyze traffic to begin.")
    else:
        result, saved_signature, saved_source = st.session_state["analysis"]
        scored, timing, nx, tunnel, adv, cdn = result
        if signature != saved_signature:
            st.warning("Inputs or settings changed. Results below are from the previous run; select Analyze traffic to update them.")
        st.caption(f"RESULTS / {saved_source} / {scored['timestamp'].min()} to {scored['timestamp'].max()}")
        flagged = scored[scored["is_anomaly"]]
        cols = st.columns(4)
        for col, title, value in zip(cols, ["DNS queries", "Unique domains", "Flagged queries", "Source hosts"],
                                    [len(scored), scored.domain.nunique(), len(flagged), scored.src_ip.nunique()]):
            col.metric(title, f"{value:,}")
        overview, findings, hosts, validation, exports = st.tabs(["Overview", "Query evidence", "Host activity", "Evaluation", "Export rules"])
        with overview:
            left, right = st.columns(2)
            with left:
                st.subheader("Score distribution")
                fig, ax = plt.subplots(figsize=(6, 3))
                ax.hist(scored.anomaly_score, bins=np.linspace(0, 1, 26), color=BLUE, edgecolor=BACKGROUND)
                ax.axvline(0.60, color=AMBER, linestyle="--", label="Risk cutoff 0.60")
                ax.set(xlabel="Heuristic score", ylabel="Queries", xlim=(0, 1))
                ax.legend(frameon=False)
                style_axes(fig, ax)
                fig.tight_layout()
                st.pyplot(fig)
                plt.close(fig)
            with right:
                st.subheader("Traffic over time")
                activity, bucket_seconds = activity_timeline(scored)
                series = activity.rename_axis("timestamp").reset_index().melt(
                    id_vars="timestamp", var_name="series", value_name="count")
                line_chart(series, "timestamp:T", "count:Q", "Time (UTC)", "Queries", "series:N")
                st.caption(f"Each time bucket spans {pd.Timedelta(seconds=bucket_seconds)}. Empty intervals contain zero queries.")
            st.caption(f"Batch outlier threshold: {scored.batch_threshold.iloc[0]:.3f}. "
                       f"{int(scored.is_statistical_outlier.sum())} queries exceed it. This is a relative diagnostic, separate from the risk cutoff.")
            st.download_button("Download all scored queries", scored.to_csv(index=False), "dns_analysis.csv", "text/csv")
        with findings:
            f1, f2, f3 = st.columns([1, 1, 2])
            only_flags = f1.checkbox("Flagged only", value=True)
            host = f2.selectbox("Source host", ["All hosts"] + sorted(scored.src_ip.unique().tolist()))
            search = f3.text_input("Domain contains")
            view = scored.copy()
            if only_flags:
                view = view[view.is_anomaly]
            if host != "All hosts":
                view = view[view.src_ip == host]
            if search:
                view = view[view.domain.str.contains(search, case=False, regex=False)]
            view = view.sort_values("anomaly_score", ascending=False)
            st.caption(f"{len(view)} queries match the filters.")
            st.dataframe(view[["timestamp", "domain", "src_ip", "anomaly_score", "severity", "is_statistical_outlier"]], hide_index=True, use_container_width=True)
            if not view.empty:
                candidates = view.drop_duplicates(["domain", "src_ip"]).reset_index(drop=True)
                selected = st.selectbox("Inspect a domain / host pair", candidates.index,
                                        format_func=lambda i: f"{candidates.loc[i, 'domain']} | {candidates.loc[i, 'src_ip']}")
                render_evidence(candidates.loc[selected].to_dict())
            else:
                st.info("No queries match these filters. Queries below the cutoff can still be inspected by clearing Flagged only.")
        with hosts:
            st.subheader("Clients to review")
            summary = host_summary(scored)
            st.dataframe(summary, hide_index=True, use_container_width=True)
            st.download_button("Download host summary", summary.to_csv(index=False), "dns_hosts.csv", "text/csv")
            st.subheader("Timing by client and registered domain")
            st.dataframe(timing, hide_index=True, use_container_width=True)
            st.caption("At least three queries are required. Regular timing can also occur in legitimate software.")
            st.subheader("Observed DNS response failures")
            st.dataframe(nx, hide_index=True, use_container_width=True)
            st.caption("NXDOMAIN rates use observed response codes only. Empty rates mean no responses were available.")
            st.subheader("Encoded payload candidates")
            st.dataframe(tunnel[tunnel.is_tunneling_candidate], hide_index=True, use_container_width=True)
            st.dataframe(aggregate_exfiltration_by_host(scored[["src_ip", "domain", "timestamp"]], tunnel), hide_index=True, use_container_width=True)
            st.caption("Byte counts estimate decoded candidate data, including repeated queries; they do not establish data theft or unique transferred volume.")
        with validation:
            metrics = evaluate(scored)
            if not metrics:
                st.info("Evaluation requires benign / malicious ground-truth labels. Unlabeled queries are excluded.")
            else:
                st.caption(f"Evaluated {metrics['evaluated_rows']} labeled queries. Synthetic sample results do not establish real-world accuracy.")
                c = st.columns(4)
                for col, key in zip(c, ["precision", "recall", "f1", "accuracy"]):
                    col.metric(key.title(), f"{metrics[key]:.3f}")
                st.dataframe(pd.DataFrame([[metrics['tn'], metrics['fp']], [metrics['fn'], metrics['tp']]],
                    index=["Actual benign", "Actual malicious"], columns=["Below cutoff", "Flagged"]), use_container_width=True)
                if metrics["auc"] is None:
                    st.info("ROC AUC is undefined when only one ground-truth class is present.")
                else:
                    st.write(f"ROC AUC: {metrics['auc']:.3f}")
                    line_chart(pd.DataFrame({"fpr": metrics['roc_fpr'], "tpr": metrics['roc_tpr']}),
                               "fpr:Q", "tpr:Q", "False positive rate", "True positive rate")
                with st.expander("Inspect classification errors"):
                    labeled = scored[scored.label.isin(["benign", "malicious"])]
                    errors = labeled[(labeled.label.eq("malicious") & ~labeled.is_anomaly) |
                                     (labeled.label.eq("benign") & labeled.is_anomaly)]
                    st.dataframe(errors[["domain", "src_ip", "label", "anomaly_score", "severity"]],
                                 hide_index=True, use_container_width=True)
                    st.caption(f"{len(errors)} classification errors in the available ground truth. These examples help identify detector limitations.")
        with exports:
            st.write("Review individual findings before using these configuration drafts. Downloads do not apply changes to the system.")
            domains = sorted(flagged.domain.unique().tolist())
            chosen = st.multiselect("Domains to include", domains)
            if chosen:
                targets = flagged[flagged.domain.isin(chosen)].drop_duplicates("domain")
                options = {"Suricata": (generate_suricata_rules, "dns.rules"),
                           "BIND / Unbound RPZ": (generate_bind_rpz_zone, "dns.rpz"),
                           "Hosts blocklist": (generate_pihole_blocklist, "blocklist.txt"),
                           "Linux UDP DNS filter": (generate_iptables_script, "dns_filter.sh"),
                           "Windows hosts file": (generate_windows_firewall_script, "dns_hosts.ps1"),
                           "STIX 2.1": (lambda df: json.dumps(generate_stix_bundle(df), indent=2), "indicators.json")}
                choice = st.selectbox("Export format", list(options))
                generator, filename = options[choice]
                code = generator(targets)
                st.code(code, language="json" if filename.endswith("json") else "text")
                st.download_button("Download configuration", code, filename)
                st.caption("Suricata syntax targets Suricata, not Snort. Linux rules cover plaintext UDP DNS only. The Windows export modifies hosts, not Defender Firewall. Encrypted DNS is outside these filters.")
            else:
                st.info("Select flagged domains to prepare an export.")

elif page == "Domain inspector":
    st.subheader("Inspect a domain")
    st.write("Analyze the name using the same features and scoring rules as traffic analysis. A single name provides no observed timing or DNS response history.")
    with st.form("inspect"):
        domain = st.text_input("Domain name", "61646d696e2d70617373776f7264.tunnel.io")
        beacon = st.checkbox("Add a simulated 30-second beacon history", value=False)
        submit = st.form_submit_button("Inspect domain", type="primary")
    st.caption("Examples: mail.google.com / elephantwindoworange.com / qxa3e3u61mpzga8d3.dga.tk")
    if submit:
        try:
            row = inspect_domain(domain, beacon, weights)
            st.session_state["inspection"] = (row, beacon, tuple(weights.items()))
        except (ValueError, OSError) as exc:
            st.error(str(exc))
    if "inspection" in st.session_state:
        row, simulated, saved_weights = st.session_state["inspection"]
        if saved_weights != tuple(weights.items()):
            st.warning("Signal weights changed. Inspect the domain again to update its saved result.")
        if simulated:
            st.info("Timing comes from a simulated history of 12 queries, not captured network activity.")
        render_evidence(row)

else:
    st.subheader("Method")
    st.markdown("""The detector combines seven heuristic signals: character entropy, bigram divergence from the bundled English reference, query timing regularity, a local TLD risk table, label length, encoding structure, and dictionary concatenation. CDN suffixes and known names provide context rather than blanket trust.

Features use fixed scales so a domain receives the same score in isolation and in a batch with the same history. Scores above 0.60 are flagged for review. A separate mean-plus-z-standard-deviations marker identifies relative batch outliers.

The TLD table and English reference are project heuristics, not a live reputation service. Encoded labels, dictionary words, and periodic activity can all be legitimate. The spectral helper is experimental and is not used in the production score.

PCAP ingestion processes decoded plaintext DNS requests on UDP/TCP port 53 and joins available responses. TCP stream reassembly, DNS over HTTPS/TLS, packet loss recovery, and full tunnel reconstruction are outside the current scope.
""")
    st.latex(r"H(X)=-\sum_c p(c)\log_2 p(c)")
    st.latex(r"D_{KL}(P\parallel Q)=\sum_x P(x)\ln(P(x)/Q(x))")
    st.latex(r"T=1/(1+\sigma_{\Delta t}/\mu_{\Delta t})")
    st.subheader("Project team")
    st.table(pd.DataFrame([
        ["Drishti Khurana", "24BCE2153"], ["Shreya Sundli", "24BCE2546"],
        ["Pranakshay Aggarwal", "24BCE2163"], ["Shreya Kumari", "24BCE2881"],
        ["Pardhav Maradani", "24BCE2123"]], columns=["Name", "Registration number"]))
