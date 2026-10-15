"""Minimal request schema validation without another dependency."""
from __future__ import annotations
from typing import Any


def validate_scan_payload(payload: Any) -> str:
    if not isinstance(payload, dict):
        raise ValueError("Send a JSON object containing a 'url' field.")
    if "url" not in payload:
        raise ValueError("The required 'url' field is missing.")
    value = payload["url"]
    if not isinstance(value, str):
        raise ValueError("The 'url' field must be a string.")
    return value
