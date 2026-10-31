"""One analysis path for the command line and Streamlit dashboard."""
import pandas as pd
from src.dns_parser import prepare_traffic
from src.features.entropy import compute_entropy_score
from src.features.bigram_kl import load_reference_bigrams, kl_divergence
from src.features.timing import compute_timing_features
from src.features.tld_reputation import compute_tld_scores
from src.features.label_length import compute_label_length_scores
from src.features.tunnel_inspector import inspect_tunneling_features
from src.features.adversarial_defense import compute_adversarial_scores
from src.features.cdn_profiler import compute_cdn_features
from src.features.nxdomain import compute_nxdomain_rates
from src.scorer import compute_scores


def analyze_traffic(df, z_threshold=2.0, weights=None):
    df = prepare_traffic(df)
    derived = {"subdomain_label", "entropy", "label_length", "kl_divergence", "timing_score", "cv",
               "tld_score", "tld", "is_whitelisted", "length_score", "label_length_raw", "tunnel_score",
               "encoding_scheme", "estimated_payload_bytes", "decoded_sample", "dict_dga_score",
               "is_dict_dga", "dict_words_found", "is_cdn", "cdn_provider", "cdn_attenuation",
               "norm_entropy", "norm_kl", "norm_timing", "norm_length", "anomaly_score", "threshold",
               "batch_threshold", "is_anomaly", "severity", "is_statistical_outlier", "query_count",
               "mean_interval_sec", "std_interval_sec"}
    df = df.drop(columns=list(derived.intersection(df.columns)))
    ref = load_reference_bigrams()
    features = []
    for domain in df["domain"].unique():
        e = compute_entropy_score(domain)
        features.append({"domain": domain, "subdomain_label": e["subdomain_label"],
                         "entropy": e["entropy"], "label_length": e["label_length"],
                         "kl_divergence": kl_divergence(e["subdomain_label"], ref)})
    feature_df = pd.DataFrame(features)
    df = df.drop(columns=[c for c in feature_df.columns if c != "domain" and c in df])
    df = df.merge(feature_df, on="domain", validate="many_to_one")
    timing = compute_timing_features(df)
    tunnel = inspect_tunneling_features(df)
    adv = compute_adversarial_scores(df)
    cdn = compute_cdn_features(df)
    scored = compute_scores(df, weights, z_threshold, timing, compute_tld_scores(df),
                            compute_label_length_scores(feature_df), tunnel, adv, cdn)
    scored = scored.merge(timing.drop(columns="timing_score"), on=["src_ip", "registered_domain"], validate="many_to_one")
    return scored, timing, compute_nxdomain_rates(df), tunnel, adv, cdn


def inspect_domain(domain, beacon=False, weights=None):
    # Timing evidence exists only when an explicit simulation is requested.
    count = 12 if beacon else 1
    df = pd.DataFrame({"domain": [domain]*count, "src_ip": ["127.0.0.1"]*count,
                       "timestamp": pd.date_range("2024-01-01", periods=count, freq="30s", tz="UTC")})
    return analyze_traffic(df, weights=weights)[0].iloc[0].to_dict()
