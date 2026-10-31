# Dashboard screenshots

Captured from the running localhost dashboard in its dark theme. PNGs show actual UI results using the bundled synthetic CSV, a generated synthetic PCAP, and a sample domain; no metrics or results have been edited.

| File | Demonstrates |
|---|---|
| 01_traffic_overview.png | 500-query CSV analysis, score distribution and traffic timeline |
| 02_query_evidence.png | Flagged queries and the feature-level explanation for a selected finding |
| 03_pcap_host_activity.png | 120 queries extracted from a generated PCAP, ranked clients, timing and payload candidates |
| 04_detection_evaluation.png | Precision, recall, F1, accuracy, confusion matrix and ROC curve on the synthetic labeled sample |
| 05_rule_export.png | Suricata draft rule for a selected flagged domain and the configuration download control |
| 06_domain_inspector.png | Hex-encoded sample inspection and the per-signal evidence report |

The benchmark shows 66% recall; the capture intentionally retains the measured result rather than presenting it as perfect detection. Unknown NXDOMAIN rates in the query-only PCAP correctly indicate that no responses were observed.
