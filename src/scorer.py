"""Deterministic heuristic scoring with a separate batch outlier diagnostic."""
import numpy as np
import pandas as pd
from typing import Tuple

# Default signal weights (must sum to 1.0)
DEFAULT_WEIGHTS = {
    "entropy": 0.25, "kl_divergence": 0.25, "timing": 0.15,
    "tld": 0.15, "length": 0.10, "tunneling": 0.05, "adversarial": 0.05,
}
DEFAULT_Z_THRESHOLD = 2.0


def _min_max_normalize(series: pd.Series) -> pd.Series:
    """
    Apply min-max normalization to a pandas Series.
    Returns values in [0, 1]. Returns zeros if all values are equal.
    """
    mn, mx = series.min(), series.max()
    if mx == mn:
        return pd.Series(np.zeros(len(series)), index=series.index)
    return (series - mn) / (mx - mn)


def severity_label(score: float, threshold: float, sigma: float) -> str:
    """
    Map a composite anomaly score to a human-readable severity tier.

    Tiers:
        CRITICAL : score > threshold + 2*sigma
        HIGH     : score > threshold + 1*sigma
        MEDIUM   : score > threshold
        LOW      : score <= threshold  (clean)
    """
    if score > threshold + 2 * sigma:
        return "CRITICAL"
    elif score > threshold + sigma:
        return "HIGH"
    elif score > threshold:
        return "MEDIUM"
    else:
        return "LOW"


def compute_scores(
    df: pd.DataFrame,
    weights: dict = None,
    z_threshold: float = DEFAULT_Z_THRESHOLD,
    timing_df: pd.DataFrame = None,
    tld_df: pd.DataFrame = None,
    length_df: pd.DataFrame = None,
    tunnel_df: pd.DataFrame = None,
    adv_df: pd.DataFrame = None,
    cdn_df: pd.DataFrame = None,
) -> pd.DataFrame:
    """
    Compute per-domain anomaly scores from a feature DataFrame.

    Parameters
    ----------
    df : pd.DataFrame
        Must contain columns: [domain, entropy, kl_divergence]
        Optionally includes: [src_ip, registered_domain] for timing merge.
    weights : dict
        Signal weights. Defaults to DEFAULT_WEIGHTS.
    z_threshold : float
        Number of standard deviations above mean to flag anomaly.
    timing_df : pd.DataFrame or None
        Per (src_ip, registered_domain) timing features from timing.py.
    tld_df : pd.DataFrame or None
        Per-domain TLD reputation scores from tld_reputation.py.
    length_df : pd.DataFrame or None
        Per-domain label length scores from label_length.py.
    tunnel_df : pd.DataFrame or None
        Per-domain tunneling features from tunnel_inspector.py.
    adv_df : pd.DataFrame or None
        Per-domain adversarial features from adversarial_defense.py.
    cdn_df : pd.DataFrame or None
        Per-domain CDN profiling features from cdn_profiler.py.

    Returns
    -------
    pd.DataFrame with added columns:
        norm_entropy, norm_kl, norm_timing, tld_score, norm_length,
        anomaly_score, is_anomaly, threshold, severity
    """
    if weights is None:
        weights = DEFAULT_WEIGHTS

    if not np.isfinite(z_threshold) or z_threshold < 0:
        raise ValueError("Z threshold must be finite and non-negative.")
    if any(not np.isfinite(v) or v < 0 for v in weights.values()) or sum(weights.values()) <= 0:
        raise ValueError("Signal weights must be finite, non-negative, and have a positive total.")
    unknown = set(weights) - set(DEFAULT_WEIGHTS)
    if unknown:
        raise ValueError(f"Unknown signal weights: {sorted(unknown)}")
    weights = {key: weights.get(key, 0.0) for key in DEFAULT_WEIGHTS}
    result = df.copy()

    # --- Signal 1: Normalise entropy ---
    result["norm_entropy"] = (result["entropy"].fillna(0) / 4.5).clip(0, 1)

    # --- Signal 2: Normalise KL divergence ---
    result["norm_kl"] = (result["kl_divergence"].fillna(0) / 18.0).clip(0, 1)

    # --- Signal 3: Merge timing score if available ---
    if timing_df is not None and not timing_df.empty:
        merge_cols = ["src_ip", "registered_domain", "timing_score"]
        available = [c for c in merge_cols if c in timing_df.columns]
        if "src_ip" in result.columns and "registered_domain" in result.columns:
            result = result.merge(
                timing_df[available].drop_duplicates(),
                on=["src_ip", "registered_domain"],
                how="left",
            )
        else:
            result["timing_score"] = np.nan

    if "timing_score" not in result.columns:
        result["timing_score"] = np.nan

    result["norm_timing"] = result["timing_score"].fillna(0).clip(0, 1)

    # --- Signal 4: TLD reputation score ---
    if tld_df is not None and not tld_df.empty:
        result = result.merge(
            tld_df[["domain", "tld_score", "is_whitelisted", "tld"]].drop_duplicates("domain"),
            on="domain", how="left"
        )
    if "tld_score" not in result.columns:
        result["tld_score"] = 0.15
    if "is_whitelisted" not in result.columns:
        result["is_whitelisted"] = False
    result["tld_score"] = result["tld_score"].fillna(0.15)

    # --- Signal 5: Label length score ---
    if length_df is not None and not length_df.empty:
        result = result.merge(
            length_df[["domain", "length_score", "label_length_raw"]].drop_duplicates("domain"),
            on="domain", how="left"
        )
    if "length_score" not in result.columns:
        result["length_score"] = 0.20
    result["length_score"] = result["length_score"].fillna(0.20)
    result["norm_length"] = result["length_score"].clip(0, 1)

    # --- Signal 6: DNS Tunneling Inspection ---
    if tunnel_df is not None and not tunnel_df.empty:
        t_cols = [c for c in ["domain", "tunnel_score", "encoding_scheme", "estimated_payload_bytes", "decoded_sample"] if c in tunnel_df.columns]
        result = result.merge(tunnel_df[t_cols].drop_duplicates("domain"), on="domain", how="left")
    if "tunnel_score" not in result.columns:
        result["tunnel_score"] = 0.0

    # --- Signal 7: Adversarial Dictionary DGA ---
    if adv_df is not None and not adv_df.empty:
        a_cols = [c for c in ["domain", "dict_dga_score", "is_dict_dga", "dict_words_found"] if c in adv_df.columns]
        result = result.merge(adv_df[a_cols].drop_duplicates("domain"), on="domain", how="left")
    if "dict_dga_score" not in result.columns:
        result["dict_dga_score"] = 0.0

    # --- Signal 8: CDN Profiling ---
    if cdn_df is not None and not cdn_df.empty:
        c_cols = [c for c in ["domain", "is_cdn", "cdn_provider", "cdn_attenuation"] if c in cdn_df.columns]
        result = result.merge(cdn_df[c_cols].drop_duplicates("domain"), on="domain", how="left")
    if "cdn_attenuation" not in result.columns:
        result["cdn_attenuation"] = 1.0

    # --- Composite score ---
    w1 = weights.get("entropy",       0.30)
    w2 = weights.get("kl_divergence", 0.30)
    w3 = weights.get("timing",        0.15)
    w4 = weights.get("tld",           0.15)
    w5 = weights.get("length",        0.10)
    w6 = weights.get("tunneling",     0.0)
    w7 = weights.get("adversarial",   0.0)

    # Normalize weights if custom sum != 1
    w_sum = w1 + w2 + w3 + w4 + w5 + w6 + w7
    if w_sum > 0:
        w1, w2, w3, w4, w5, w6, w7 = w1/w_sum, w2/w_sum, w3/w_sum, w4/w_sum, w5/w_sum, w6/w_sum, w7/w_sum

    base_score = (
        w1 * result["norm_entropy"]
        + w2 * result["norm_kl"]
        + w3 * result["norm_timing"]
        + w4 * result["tld_score"]
        + w5 * result["norm_length"]
        + w6 * result["tunnel_score"].fillna(0)
        + w7 * result["dict_dga_score"].fillna(0)
    )

    # If domain is a high-confidence dictionary DGA or Tunneling, boost score
    if "dict_dga_score" in result.columns:
        dict_boost = result["dict_dga_score"].fillna(0).apply(lambda s: 0.35 if s >= 0.70 else 0.0)
        base_score = base_score + dict_boost

    if "tunnel_score" in result.columns:
        tunnel_boost = result["tunnel_score"].fillna(0).apply(lambda s: 0.30 if s >= 0.50 else 0.0)
        base_score = base_score + tunnel_boost

    # Apply CDN false-positive attenuation
    if "cdn_attenuation" in result.columns:
        # Provider membership is context, never proof that a tenant is safe.
        strong_evidence = (result["tunnel_score"] >= 0.50) | (result["dict_dga_score"] >= 0.70)
        attenuation = result["cdn_attenuation"].fillna(1.0).clip(lower=0.75)
        base_score = base_score * attenuation.where(~strong_evidence, 1.0)

    result["anomaly_score"] = base_score.clip(0.0, 1.0).round(6)

    # Whitelisted domains always get score 0
    # Known names reduce weak lexical noise; suspicious subdomains remain visible.
    weak = (result["tunnel_score"] < 0.50) & (result["dict_dga_score"] < 0.70)
    result.loc[result["is_whitelisted"].fillna(False) & weak, "anomaly_score"] *= 0.75

    # --- Statistical threshold (z-score based) ---
    mu = result["anomaly_score"].mean()
    sigma = result["anomaly_score"].std()
    if sigma == 0 or pd.isna(sigma):
        sigma = 0.01
    threshold = mu + z_threshold * sigma
    result["batch_threshold"] = round(threshold, 6)
    result["is_statistical_outlier"] = result["anomaly_score"] > threshold
    # Absolute heuristic cutoff works for a single query and homogeneous batches.
    result["threshold"] = 0.60
    result["is_anomaly"] = result["anomaly_score"] > 0.60
    result["severity"] = result["anomaly_score"].map(
        lambda s: "CRITICAL" if s > 0.85 else "HIGH" if s > 0.75 else "MEDIUM" if s > 0.60 else "LOW")

    return result


def evaluate(df: pd.DataFrame) -> dict:
    """
    Compute precision, recall, F1, accuracy, and ROC data vs ground-truth labels.

    Parameters
    ----------
    df : pd.DataFrame
        Must contain [label, is_anomaly, anomaly_score] columns.
        label: 'benign' or 'malicious'

    Returns
    -------
    dict with precision, recall, f1, accuracy, tp, fp, tn, fn,
    plus roc_fpr and roc_tpr lists for plotting.
    """
    label_col = None
    for c in ["label", "label_x"]:
        if c in df.columns and df[c].notna().any():
            label_col = c
            break

    if label_col is None:
        return {}

    valid = df[label_col].isin(["benign", "malicious"])
    df = df.loc[valid].copy()
    if df.empty:
        return {}
    y_true = (df[label_col] == "malicious").astype(int)
    y_pred = df["is_anomaly"].astype(int)
    y_score = df["anomaly_score"].values

    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy  = (tp + tn) / len(df) if len(df) > 0 else 0.0

    # Sweep exact observed scores, retaining tied scores in one step.
    positives = int(y_true.sum())
    negatives = len(y_true) - positives
    roc_fpr, roc_tpr = [0.0], [0.0]
    auc = None
    if positives and negatives:
        ordered = pd.DataFrame({"score": y_score, "truth": y_true.to_numpy()})
        groups = ordered.groupby("score")["truth"].agg(["sum", "count"]).sort_index(ascending=False)
        roc_tpr += (groups["sum"].cumsum() / positives).tolist()
        roc_fpr += ((groups["count"] - groups["sum"]).cumsum() / negatives).tolist()
        auc = float(sum((roc_fpr[i] - roc_fpr[i-1]) * (roc_tpr[i] + roc_tpr[i-1]) / 2
                        for i in range(1, len(roc_fpr))))

    return {
        "evaluated_rows": len(df),
        "precision": round(precision, 4),
        "recall":    round(recall,    4),
        "f1":        round(f1,        4),
        "accuracy":  round(accuracy,  4),
        "auc":       round(auc, 4) if auc is not None else None,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "roc_fpr": roc_fpr,
        "roc_tpr": roc_tpr,
    }
