"""Passive plaintext DNS capture. Capture errors never fall back to invented traffic."""
import datetime


def live_sniff_dns(callback, duration_sec=30, max_packets=100, interface=None):
    try:
        from scapy.all import sniff, DNS, IP, IPv6, UDP, TCP
    except ImportError as exc:
        raise ImportError("Live capture requires Scapy and, on Windows, Npcap.") from exc
    def handle(packet):
        dns = packet[DNS]
        layer = packet[IP] if IP in packet else packet[IPv6]
        if dns.qr or not dns.qd:
            return
        callback({"timestamp": datetime.datetime.fromtimestamp(float(packet.time), datetime.timezone.utc),
                  "src_ip": layer.src, "domain": dns.qd[0].qname.decode("ascii", errors="replace").rstrip("."),
                  "qtype": str(dns.qd[0].qtype)})
    def is_query(packet):
        return (DNS in packet and (IP in packet or IPv6 in packet) and
                (UDP in packet or TCP in packet) and packet[DNS].qr == 0 and bool(packet[DNS].qd))
    try:
        sniff(iface=interface, filter="port 53", lfilter=is_query, prn=handle,
              timeout=duration_sec, count=max_packets, store=False)
    except Exception as exc:
        raise RuntimeError(f"Live capture failed: {exc}. Check capture privileges, interface, and Npcap installation.") from exc
