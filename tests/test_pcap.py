"""
tests/test_pcap.py
Automated Unit Tests for PCAP / PCAPNG Network Packet Capture Parser
"""

import os
import tempfile
import pytest
import pandas as pd
from src.pcap_analyzer import generate_synthetic_pcap, load_pcap_traffic


def test_synthetic_pcap_generation_and_loading():
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_pcap = tmp.name

    try:
        # Generate synthetic PCAP with 40 packets
        out_path = generate_synthetic_pcap(tmp_pcap, n_records=40)
        assert os.path.exists(out_path)
        assert os.path.getsize(out_path) > 100

        # Load into DataFrame
        df = load_pcap_traffic(tmp_pcap)
        assert isinstance(df, pd.DataFrame)
        assert len(df) > 0

        # Verify mandatory columns
        expected_cols = {"timestamp", "src_ip", "dst_ip", "domain", "qtype", "qr"}
        assert expected_cols.issubset(set(df.columns))

        # Check domain string cleanliness (no trailing dots or uppercase)
        for dom in df["domain"]:
            assert not dom.endswith(".")
            assert dom == dom.lower()

    finally:
        if os.path.exists(tmp_pcap):
            os.remove(tmp_pcap)


def test_load_pcap_missing_file_raises_error():
    with pytest.raises(FileNotFoundError):
        load_pcap_traffic("non_existent_packet_capture_file.pcap")
