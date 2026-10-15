"""Strict structural URL validation. No network access is performed."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

DEFAULT_MAX_URL_LENGTH = 2048
_CONTROL_CHARS = re.compile(r"[\x00-\x20\x7f]")
_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
_HOST_PORT = re.compile(r"^(?:\[[^\]]+\]|[^/:?#]+):(\d+)(?:[/?#]|$)")
_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")


def _valid_hostname(hostname: str) -> bool:
    if not hostname or hostname.endswith(".."):
        return False

    if ":" in hostname:
        try:
            ipaddress.IPv6Address(hostname)
            return True
        except ipaddress.AddressValueError:
            return False

    try:
        ascii_host = hostname.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        return False

    if not ascii_host or len(ascii_host) > 253:
        return False

    # Accept IPv4 literals and ordinary DNS names, including localhost.
    try:
        ipaddress.IPv4Address(ascii_host)
        return True
    except ipaddress.AddressValueError:
        pass

    labels = ascii_host.split(".")
    return all(0 < len(label) <= 63 and _LABEL.fullmatch(label) for label in labels)


def validate_and_normalize_url(
    value: object, *, max_length: int = DEFAULT_MAX_URL_LENGTH
) -> str:
    """Validate URL syntax and normalize a missing scheme to HTTPS.

    This function does not resolve DNS, open sockets, make HTTP requests,
    follow redirects, or infer that a URL is safe.
    """
    if not isinstance(value, str):
        raise ValueError("The 'url' field must be a string.")

    candidate = value.strip()
    if not candidate:
        raise ValueError("Please enter a URL.")
    if len(candidate) > max_length:
        raise ValueError(f"The URL must be {max_length} characters or fewer.")
    if _CONTROL_CHARS.search(candidate) or "\\" in candidate:
        raise ValueError("The URL must not contain spaces, control characters, or backslashes.")

    if candidate.startswith("//"):
        candidate = "https:" + candidate
    elif not candidate.lower().startswith(("http://", "https://")):
        scheme_match = _SCHEME.match(candidate)
        if scheme_match:
            scheme = scheme_match.group(1).lower()
            is_host_port = bool(_HOST_PORT.match(candidate))
            if scheme not in {"http", "https"} and not is_host_port:
                raise ValueError("Only HTTP and HTTPS URLs are supported.")
            if scheme in {"http", "https"}:
                raise ValueError("Enter a complete URL, such as https://example.com.")
        candidate = "https://" + candidate

    try:
        parts = urlsplit(candidate)
        hostname = parts.hostname
        port = parts.port  # Access validates the numeric port range.
    except ValueError as exc:
        raise ValueError("The URL has an invalid hostname or port.") from exc

    if parts.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not parts.netloc or not hostname:
        raise ValueError("The URL must include a hostname.")
    if parts.username is not None or parts.password is not None:
        raise ValueError("URLs containing embedded credentials are not supported.")
    if not _valid_hostname(hostname):
        raise ValueError("The hostname format is invalid.")

    # Preserve the original path/query/fragment and netloc, while normalizing scheme.
    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path, parts.query, parts.fragment))
