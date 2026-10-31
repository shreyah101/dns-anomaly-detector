"""NXDOMAIN rates from observed responses only; unknown is not success."""
import pandas as pd


def compute_nxdomain_rates(df):
    records = []
    for host, group in df.groupby("src_ip"):
        codes = group.get("response_code", group.get("rcode", pd.Series(index=group.index, dtype="object")))
        codes = codes.astype("string").str.strip().str.upper()
        observed = codes.notna() & codes.ne("")
        count = int(codes.isin(["NXDOMAIN", "3"]).sum())
        total = int(observed.sum())
        rate = count / total if total else float("nan")
        records.append({"src_ip": host, "total_queries": len(group), "observed_responses": total,
                        "nxdomain_count": count, "nxdomain_rate": rate,
                        "nxdomain_score": min(rate / 0.30, 1.0) if total else float("nan")})
    return pd.DataFrame(records)
