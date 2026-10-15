"""Typed representation of one feature-extraction operation."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from typing import Any


@dataclass(frozen=True)
class ScanResult:
    url_sha256: str
    created_at: str
    features: dict[str, Any]
    assessment: str = "not_assessed"

    @classmethod
    def from_url(cls, normalized_url: str, features: dict[str, Any]) -> "ScanResult":
        fingerprint = hashlib.sha256(normalized_url.encode("utf-8")).hexdigest()
        created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return cls(
            url_sha256=fingerprint,
            created_at=created_at,
            features=features,
            assessment="not_assessed",
        )
