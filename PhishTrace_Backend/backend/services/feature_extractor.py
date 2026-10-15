"""Extract descriptive URL features; these are not a phishing verdict."""
from __future__ import annotations

import ipaddress
from urllib.parse import parse_qsl, urlsplit


def extract_url_features(normalized_url: str) -> dict[str, int | bool]:
    parts = urlsplit(normalized_url)
    hostname = parts.hostname or ""
    hostname_without_dot = hostname.rstrip(".")
    labels = hostname_without_dot.split(".") if hostname_without_dot else []

    try:
        ipaddress.ip_address(hostname)
        host_is_ip = True
    except ValueError:
        host_is_ip = False

    try:
        port = parts.port
    except ValueError:
        port = None  # Normally excluded by URL validation; defensive fallback.

    query_parameters = parse_qsl(parts.query, keep_blank_values=True)
    return {
        "url_length": len(normalized_url),
        "hostname_length": len(hostname),
        "dot_count": normalized_url.count("."),
        "hyphen_count": normalized_url.count("-"),
        "digit_count": sum(char.isdigit() for char in normalized_url),
        "subdomain_count": max(0, len(labels) - 2),
        "uses_https": parts.scheme.lower() == "https",
        "hostname_is_ip_address": host_is_ip,
        "has_at_symbol": "@" in parts.netloc,
        "has_punycode_label": any(label.lower().startswith("xn--") for label in labels),
        "uses_nonstandard_port": port is not None and port not in {80, 443},
        "query_parameter_count": len(query_parameters),
        "path_segment_count": len([segment for segment in parts.path.split("/") if segment]),
        "has_percent_encoding": "%" in normalized_url,
        "has_fragment": bool(parts.fragment),
    }
