"""
generator.py -- Synthetic DNS Traffic Generator

Generates realistic benign and malicious DNS traffic for testing
the anomaly detector without needing real network captures.

Benign traffic:
    - Domain names drawn from common English-word patterns
    - Poisson-distributed inter-query times (mimics human browsing)
    - Multiple source IPs

Malicious traffic:
    - DGA (Domain Generation Algorithm) style: random character strings
    - DNS tunneling style: long base32/hex-like subdomains
    - Beacon timing: fixed intervals with tiny jitter (mimics malware)

Output: CSV with columns [timestamp, src_ip, domain, label]
  label: 'benign' or 'malicious'
"""

import csv
import json
import math
import os
import random
import string
from collections import Counter
from datetime import datetime, timedelta

import numpy as np

# ------------------------------------------------------------------
# English word list for benign domain generation
# ------------------------------------------------------------------
BENIGN_WORDS = [
    "mail", "www", "news", "shop", "blog", "api", "cdn", "static",
    "media", "images", "files", "docs", "help", "support", "login",
    "account", "secure", "auth", "portal", "dashboard", "home",
    "search", "video", "stream", "data", "cloud", "app", "mobile",
    "download", "update", "admin", "webmail", "smtp", "pop", "imap",
]

BENIGN_TLDS = [
    "google.com", "microsoft.com", "amazon.com", "youtube.com",
    "facebook.com", "twitter.com", "github.com", "reddit.com",
    "wikipedia.org", "cloudflare.com", "akamai.net", "netflix.com",
    "apple.com", "linkedin.com", "yahoo.com", "office365.com",
    "slack.com", "dropbox.com", "zoom.us", "adobe.com",
]

MALICIOUS_TLDS = [
    "badsite.com", "evil.net", "malware.org", "c2server.ru",
    "darkweb.biz", "phishing.cn", "tunnel.io", "dga.tk",
    "botnet.pw", "exfil.top",
]

# Characters used by DGA and tunneling payloads
DGA_CHARS = string.ascii_lowercase + string.digits
HEX_CHARS = string.hexdigits[:16]  # 0-9 a-f
B32_CHARS = string.ascii_uppercase[:26] + "234567"


def _random_dga_label(min_len: int = 8, max_len: int = 20) -> str:
    """Generate a pseudo-random DGA-style domain label."""
    length = random.randint(min_len, max_len)
    return "".join(random.choices(DGA_CHARS, k=length))


def _random_hex_label(min_len: int = 10, max_len: int = 24) -> str:
    """Generate a hex-encoded-looking label (DNS tunneling style)."""
    length = random.randint(min_len, max_len)
    return "".join(random.choices(HEX_CHARS, k=length))


def _random_benign_label() -> str:
    """Generate a realistic-looking benign subdomain label."""
    style = random.choice(["word", "word_num", "double_word"])
    if style == "word":
        return random.choice(BENIGN_WORDS)
    elif style == "word_num":
        return random.choice(BENIGN_WORDS) + str(random.randint(1, 99))
    else:
        return random.choice(BENIGN_WORDS) + "." + random.choice(BENIGN_WORDS)


def generate_benign_traffic(
    n_queries: int = 300,
    n_hosts: int = 10,
    start_time: datetime = None,
    seed: int = 42,
) -> list:
    """
    Generate benign DNS traffic records.

    Parameters
    ----------
    n_queries : int -- Total number of DNS queries to generate.
    n_hosts   : int -- Number of simulated source IP addresses.
    start_time: datetime -- Start of the time window.
    seed      : int -- Random seed for reproducibility.

    Returns
    -------
    list of dicts: [timestamp, src_ip, domain, registered_domain, label]
    """
    random.seed(seed)
    np.random.seed(seed)
    if start_time is None:
        start_time = datetime(2024, 6, 1, 8, 0, 0)

    hosts = [f"192.168.1.{i}" for i in range(1, n_hosts + 1)]
    records = []
    current_time = start_time

    for _ in range(n_queries):
        src_ip = random.choice(hosts)
        tld = random.choice(BENIGN_TLDS)
        label = _random_benign_label()
        domain = f"{label}.{tld}"
        # Poisson inter-arrival: exponential waiting times
        gap_sec = np.random.exponential(scale=30.0)
        current_time += timedelta(seconds=gap_sec)
        records.append({
            "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "domain": domain,
            "registered_domain": tld,
            "label": "benign",
        })

    return records


def generate_malicious_traffic(
    n_queries: int = 100,
    n_hosts: int = 3,
    start_time: datetime = None,
    beacon_interval_sec: float = 60.0,
    jitter_sec: float = 2.0,
    seed: int = 99,
    attack_type: str = "mixed",
) -> list:
    """
    Generate malicious DNS traffic records (DGA + DNS tunneling + beaconing).

    Parameters
    ----------
    n_queries           : int   -- Total malicious queries.
    n_hosts             : int   -- Number of infected source IPs.
    beacon_interval_sec : float -- Mean interval for beaconing queries.
    jitter_sec          : float -- Small timing jitter (std dev in seconds).
    attack_type         : str   -- 'dga', 'tunnel', or 'mixed'.

    Returns
    -------
    list of dicts
    """
    random.seed(seed)
    np.random.seed(seed)
    if start_time is None:
        start_time = datetime(2024, 6, 1, 8, 5, 0)

    hosts = [f"10.0.0.{i}" for i in range(1, n_hosts + 1)]
    records = []
    # Each host gets its own beacon clock
    host_times = {h: start_time for h in hosts}

    for i in range(n_queries):
        src_ip = random.choice(hosts)
        tld = random.choice(MALICIOUS_TLDS)

        if attack_type == "dga" or (attack_type == "mixed" and i % 2 == 0):
            label = _random_dga_label()
        else:
            label = _random_hex_label()

        domain = f"{label}.{tld}"

        # Beaconing: near-fixed interval with tiny jitter
        jitter = np.random.normal(0, jitter_sec)
        host_times[src_ip] += timedelta(seconds=beacon_interval_sec + jitter)

        records.append({
            "timestamp": host_times[src_ip].strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "domain": domain,
            "registered_domain": tld,
            "label": "malicious",
        })

    return records


def build_bigram_table(output_path: str) -> None:
    """
    Build an English bigram frequency table and save it as JSON.

    Uses a built-in word list so no external corpus download is needed.
    """
    # Large set of common English words covering diverse bigrams
    english_words = [
        "the","of","and","a","to","in","is","it","you","that","he","was","for",
        "on","are","with","as","his","they","at","be","this","have","from","or",
        "one","had","by","word","but","not","what","all","were","we","when","your",
        "can","said","there","use","an","each","which","she","do","how","their",
        "time","if","will","way","about","many","then","them","write","would","like",
        "so","these","her","long","make","thing","see","him","two","has","look",
        "more","day","could","go","come","did","number","sound","no","most","people",
        "my","over","know","water","than","call","first","who","may","down","side",
        "been","now","find","any","new","work","part","take","get","place","made",
        "live","where","after","back","little","only","round","man","year","came",
        "show","every","good","me","give","our","under","name","very","through",
        "just","form","sentence","great","think","say","help","low","line","differ",
        "turn","cause","much","mean","before","move","right","boy","old","too","same",
        "tell","does","set","three","want","air","well","also","play","small","end",
        "put","home","read","hand","port","large","spell","add","even","land","here",
        "must","big","high","such","follow","act","why","ask","men","change","went",
        "light","kind","off","need","house","picture","try","again","animal","point",
        "mother","world","near","build","self","earth","father","head","stand","own",
        "page","found","still","learn","should","america","country","food","letter",
        "between","school","never","start","city","body","music","family","direct",
        "pose","leave","song","measure","door","product","black","short","numeral",
        "class","wind","question","happen","complete","ship","area","half","rock",
        "order","fire","south","problem","piece","told","knew","pass","since","top",
        "whole","king","space","heard","best","hour","better","during","hundred",
        "five","remember","step","early","hold","west","ground","interest","reach",
        "fast","verb","sing","listen","six","table","travel","less","morning","ten",
        "simple","several","vowel","toward","war","lay","against","pattern","slow",
        "center","love","person","money","serve","appear","road","map","rain","rule",
        "govern","pull","cold","notice","voice","energy","hunt","probable","bed",
        "brother","egg","ride","cell","believe","fraction","forest","sit","race",
        "window","store","summer","train","sleep","prove","lone","leg","exercise",
        "wall","catch","mount","wish","sky","board","joy","winter","sat","written",
        "wild","instrument","kept","glass","grass","cow","job","edge","sign","visit",
        "past","soft","fun","bright","gas","weather","month","million","bear","finish",
        "happy","hope","flower","clothe","strange","gone","jump","baby","eight","village",
        "meet","root","buy","raise","solve","metal","whether","push","seven","paragraph",
        "third","shall","held","hair","describe","cook","floor","either","result","burn",
        "hill","safe","cat","century","consider","type","law","bit","coast","copy",
        "phrase","silent","tall","sand","soil","roll","temperature","finger","industry",
        "value","fight","false","wait","mix","complete","power","town","fine","drive",
        "print","fall","stay","gold","science","plain","lesson","ready","yet","govern",
        "winter","difficult","stretch","thousand","river","thick","smile","weight",
        "material","view","captain","science","choose","possible","natural","discuss",
        "history","human","plant","among","check","common","heart","stop","since",
        "bring","explain","clean","total","condition","basic","smell","valley","nor",
        "double","seat","continue","block","chart","hat","sell","success","company",
        "subtract","particular","deal","swim","term","opposite","wife","shoe","shoulder",
        "spread","arrange","camp","invent","cotton","born","determine","quart","nine",
        "truck","noise","level","chance","gather","shop","stretch","threw","shine",
        "decide","single","original","mark","moment","gone","supply","corner","electric",
        "insects","crop","tone","sugar","death","pretty","skill","women","season",
        "solution","magnet","silver","thank","branch","match","suffix","especially",
        "fig","afraid","huge","sister","steel","discuss","forward","similar","guide",
        "experience","score","apple","bought","led","pitch","coat","mass","card","band",
        "rope","slip","win","dream","evening","condition","feed","tool","total","basic",
        "smell","valley","nor","double","seat","contain","front","teach","week","final",
        "gave","green","oh","quick","develop","ocean","warm","free","minute","strong"
    ]

    counts: Counter = Counter()
    total = 0
    for word in english_words:
        word = word.lower()
        for i in range(len(word) - 1):
            bigram = word[i : i + 2]
            if bigram.isalpha():
                counts[bigram] += 1
                total += 1

    if total == 0:
        raise ValueError("No valid bigrams found in word list.")

    bigram_probs = {bg: count / total for bg, count in counts.items()}

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(bigram_probs, f, indent=2, sort_keys=True)

    print(f"[+] Bigram table written: {len(bigram_probs)} bigrams -> {output_path}")


def save_traffic_csv(records: list, output_path: str) -> None:
    """Save a list of traffic record dicts to a CSV file."""
    if not records:
        return
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    fieldnames = ["timestamp", "src_ip", "domain", "registered_domain", "label"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)
    print(f"[+] Traffic CSV written: {len(records)} records -> {output_path}")


if __name__ == "__main__":
    base_dir = os.path.join(os.path.dirname(__file__), "..")
    build_bigram_table(os.path.join(base_dir, "data", "bigram_english.json"))

    benign = generate_benign_traffic(n_queries=400)
    malicious = generate_malicious_traffic(n_queries=100)
    all_records = benign + malicious
    random.shuffle(all_records)

    save_traffic_csv(all_records, os.path.join(base_dir, "data", "synthetic_traffic.csv"))
    print("[+] Synthetic traffic generation complete.")
