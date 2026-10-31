# Implementation review

- Replaced duplicated CLI/dashboard computations with one validated pipeline.
- Replaced per-batch min/max score scaling with fixed feature scales and a fixed review cutoff; retained z-score outliers as a separate diagnostic.
- Preserved real response codes and removed inferred NXDOMAIN statistics.
- Counted packet requests once and matched observed responses to the requesting client.
- Fixed datetime unit handling and disabled public-suffix network fetches.
- Removed unconditional known-domain score bypasses and limited provider attenuation.
- Replaced the misleading socket listener/simulated fallback with actual passive capture.
- Corrected STIX UUIDs and UTC times, Windows hosts path expansion, DNS wire-format matching, duplicate export entries, and Suricata exact-name matching.
- Rebuilt Streamlit navigation, input/run workflow, persistent results, filters, evidence views, charts and export previews without emojis.
- Added end-to-end pipeline and Streamlit regression tests.
- Rewrote README and the current Markdown report to remove unsupported benchmark and product claims. Historical binary reports and their generators are excluded from the repository; see README before submission.

Known limits: no TCP stream reassembly or encrypted DNS inspection; small lexical reference and dictionary; synthetic benchmark only; no live-capture driver validation in this review. Configuration exports have not been integration-tested on external firewalls/resolvers.
