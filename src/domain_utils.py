"""Shared domain parsing using the bundled public suffix snapshot (no network)."""
import re
import tldextract

extract_domain = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

def normalize_domain(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Domain must be a non-empty DNS name.")
    name = value.strip().rstrip(".")
    try:
        name = name.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid international domain name.") from exc
    if len(name) > 253 or any(not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", part) for part in name.split(".")):
        raise ValueError(f"Invalid DNS name: {value!r}")
    return name

def registered_domain(name):
    ext = extract_domain(name)
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else name
