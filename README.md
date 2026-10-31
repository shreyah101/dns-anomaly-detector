# Statistical DNS Anomaly Detector

Computer Networks course project, BCSE308L / BCSE308P.

A Python tool for reviewing DNS queries using statistical and structural heuristics. Supports CSV traffic logs, plaintext DNS from PCAP/PCAPNG, a domain inspector, evidence reports, and downloadable rule drafts. No trained machine learning model is used.

## Run locally

Run these commands from the directory containing `main.py` and `requirements.txt`:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run dashboard/app.py
```

The included CSV and bigram reference work without setup. To rebuild demonstration data:

```powershell
python main.py --setup
python main.py --report --top 10
python main.py --pcap data/sample_traffic.pcap
python main.py --domain elephantwindoworange.com
python main.py --domain c2-server.example.biz --beacon
python main.py --export-rules rules/
python -m pytest -q
```

`--beacon` explicitly simulates 12 requests at 30-second intervals. It is not observed network evidence. `--sniff` performs passive port-53 capture; on Windows it requires Npcap and suitable capture privileges. It never silently switches to synthetic traffic.

## Input format

Required CSV columns: `timestamp`, `src_ip`, `domain`.

```csv
timestamp,src_ip,domain,qtype,response_code,label
2026-01-01T10:00:00Z,192.168.1.10,mail.google.com,A,NOERROR,benign
2026-01-01T10:00:30Z,192.168.1.20,qxa3e3u61mpzga8d3.dga.tk,A,NXDOMAIN,malicious
```

Timestamps accept ISO datetimes or Unix seconds. Naive datetimes are interpreted as UTC. Domains are normalized and validated, and registered domains are derived using the bundled public suffix snapshot without network calls. Optional columns, including `qtype`, `rcode`, and `response_code`, are retained. Unknown labels are excluded from evaluation.

PCAP analysis counts requests, joins observed responses by client/resolver, client port, transaction ID, name and question type, and attributes response failures to the requesting client. Captures with no DNS requests produce a readable error.

## Scoring

CLI and dashboard use `src/pipeline.py`. Seven signals contribute:

| Signal | Scale / interpretation |
|---|---|
| Character entropy | H / 4.5, clipped to [0, 1] |
| Bigram divergence | KL / 18, clipped to [0, 1] |
| Timing | 1 / (1 + CV), requiring at least three queries per client/base-domain pair |
| TLD | Static project risk table; not a live reputation feed |
| Label length | Logistic transform around the configured baseline |
| Encoding structure | Hex, Base32, and constrained Base64 candidate inspection |
| Dictionary concatenation | Small local word-list heuristic |

Default weights are 0.25, 0.25, 0.15, 0.15, 0.10, 0.05, and 0.05 respectively. Weights are normalized. Dictionary scores >= 0.70 add 0.35 and tunnel scores >= 0.50 add 0.30 before contextual attenuation and clipping. Known-name and CDN membership reduce weak evidence but do not zero the score or suppress strong encoding/dictionary evidence. Provider membership does not verify individual tenants.

A score above **0.60** is flagged for review; above 0.75 is HIGH and above 0.85 is CRITICAL. These are heuristic priorities, not probabilities. Fixed scales preserve scores across different batches when the query history is the same. Missing timing contributes no evidence.

The separate batch outlier diagnostic uses mean + z * standard deviation (`--z`). It does not replace the fixed review cutoff. A batch-relative threshold alone can miss homogeneous suspicious traffic.

## Interpretation and limits

- Encoding, periodic queries, long names, and dictionary compounds can be legitimate. A flag calls for investigation, not a confirmed attack diagnosis.
- Estimated decoded bytes include repeated requests and do not prove theft or unique transferred volume.
- NXDOMAIN rates use actual response codes only. Missing responses are unknown, not successful lookups.
- The English reference and TLD table are illustrative; no current external threat intelligence is fetched.
- PCAP parsing handles decoded plaintext port-53 UDP/TCP DNS packets. TCP stream reassembly, encrypted DNS, and full tunnel reconstruction are outside scope.
- The spectral helper is experimental and excluded from scoring. An FFT of inter-arrival gaps does not establish a C2 channel.
- Evaluation reports only available labeled rows; ROC AUC is undefined for a single class. Included data is synthetic and is not evidence of real-world accuracy or a comparison against other detectors.
- Rule exports are drafts: Suricata syntax is not guaranteed to work in Snort, Linux filters cover plaintext UDP only, and the Windows script edits hosts rather than Defender Firewall. No configurations are applied automatically.

## Files and submission notes

- `src/`: parser, shared pipeline, feature extraction, scorer, explanation, packet capture and rule export.
- `dashboard/app.py`: Streamlit application with explicit analysis runs, persistent results, filters, evidence, evaluation, and export previews.
- `tests/`: component and regression tests.
- `Project_Report_BCSE308P.md`: current implementation report.
- Historical PDF/DOCX reports, slide decks, and report-generation scripts from earlier local drafts are excluded from this repository. Their hard-coded benchmark claims were not validated. Use the current Markdown report and measured CLI results for the final submission.

## Team

| Name | Registration number |
|---|---|
| Drishti Khurana | 24BCE2153 |
| Shreya Sundli | 24BCE2546 |
| Pranakshay Aggarwal | 24BCE2163 |
| Shreya Kumari | 24BCE2881 |
| Pardhav Maradani | 24BCE2123 |
