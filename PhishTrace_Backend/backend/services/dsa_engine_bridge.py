"""Python-to-C++ Subprocess Bridge for PhishTrace DSA Detection Engine.

This module communicates with the isolated C++ DSA detection engine over
standard input/output using the protocol defined in docs/DSA_ENGINE_INTERFACE.md.

Security mandates:
- Subprocess execution uses an argument list with shell=False.
- Standard input receives exactly one JSON request; standard output returns exactly one JSON response.
- Diagnostic logs and error traces are captured via stderr and kept separate from JSON payloads.
- Submissions are never opened, fetched, or resolved via network requests.
- No sensitive query strings or credentials are logged.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import logging
import os
from pathlib import Path
import subprocess
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

DEFAULT_SCHEMA_VERSION = "1.0"
DEFAULT_TIMEOUT_SECONDS = 1.5
DEFAULT_ENGINE_PATH = "engine/bin/phishtrace_engine"


class DSAEngineBridgeError(Exception):
    """Base exception for DSA engine bridge errors."""


class DSAEngineNotFoundError(DSAEngineBridgeError):
    """Raised when the C++ engine binary does not exist."""


class DSAEngineTimeoutError(DSAEngineBridgeError):
    """Raised when the C++ engine exceeds its execution deadline."""


class DSAEngineSchemaError(DSAEngineBridgeError):
    """Raised when a request or response fails protocol schema validation."""


@dataclass(frozen=True)
class EngineResult:
    """Standardized result returned by the DSA engine bridge.

    Attributes:
        available: True if the engine executed cleanly and produced valid evidence;
                   False if the engine failed, timed out, or was missing.
        status: "ok", "error", or "unavailable".
        assessment_label: High-level assessment policy hint (always "not_assessed"
                          on bridge failures; never a fabricated verdict).
        evidence: Algorithmic findings (Trie matches, Hash Table lookup, Levenshtein distance).
        engine_metadata: Name, version, build, and execution time from the engine.
        warnings: Non-fatal diagnostic warnings reported by the engine.
        error: Error details if status is "error" or "unavailable".
        request_id: Echoed correlation identifier, if one was provided in the request.
    """

    available: bool
    status: str
    assessment_label: str = "not_assessed"
    evidence: dict[str, Any] | None = None
    engine_metadata: dict[str, Any] | None = None
    warnings: list[str] = field(default_factory=list)
    error: dict[str, Any] | None = None
    request_id: str | None = None

    @classmethod
    def unavailable(
        cls,
        code: str,
        message: str,
        *,
        request_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> "EngineResult":
        """Factory for unavailable / failure results."""
        err_dict: dict[str, Any] = {"code": code, "message": message}
        if details:
            err_dict["details"] = details
        return cls(
            available=False,
            status="unavailable",
            assessment_label="not_assessed",
            evidence=None,
            engine_metadata=None,
            warnings=[],
            error=err_dict,
            request_id=request_id,
        )


def resolve_engine_path(configured_path: str | Path | None = None) -> Path:
    """Resolve the path to the C++ engine executable.

    Precedence:
    1. Explicit configured_path argument (if provided).
    2. PHISHTRACE_ENGINE_PATH environment variable (if set).
    3. Default relative path: engine/bin/phishtrace_engine.
    """
    if configured_path:
        return Path(configured_path).resolve()

    env_path = os.getenv("PHISHTRACE_ENGINE_PATH")
    if env_path:
        return Path(env_path).resolve()

    # Search common project locations
    module_dir = Path(__file__).resolve().parent
    candidates = [
        module_dir.parent.parent / "engine" / "bin" / "phishtrace_engine",
        module_dir.parent.parent.parent / "engine" / "bin" / "phishtrace_engine",
        Path.cwd() / "engine" / "bin" / "phishtrace_engine",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()

    # Fall back to root candidate for error reporting
    return candidates[0]


def build_engine_request(
    url: str,
    *,
    hostname: str | None = None,
    path: str | None = None,
    query: str | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    request_id: str | None = None,
) -> dict[str, Any]:
    """Construct and validate a phish_request_v1 payload."""
    if not isinstance(url, str) or not url.strip():
        raise DSAEngineSchemaError("URL must be a non-empty string.")

    if hostname is None or path is None or query is None:
        parts = urlsplit(url)
        extracted_host = parts.hostname or ""
        extracted_path = parts.path or ""
        extracted_query = parts.query or ""
    else:
        extracted_host = hostname
        extracted_path = path
        extracted_query = query

    if not extracted_host:
        raise DSAEngineSchemaError("URL must include a valid hostname.")

    timeout_ms = max(10, min(10000, int(timeout_seconds * 1000)))

    return {
        "schema_version": DEFAULT_SCHEMA_VERSION,
        "request_id": request_id,
        "url": url,
        "hostname": extracted_host.lower().rstrip("."),
        "path": extracted_path,
        "query": extracted_query,
        "timeout_ms": timeout_ms,
    }


def validate_engine_response(
    response: Any,
    *,
    expected_request_id: str | None = None,
) -> dict[str, Any]:
    """Validate that the engine's response conforms to phish_response_v1.

    Raises:
        DSAEngineSchemaError: If any required structure or type is invalid.
    """
    if not isinstance(response, dict):
        raise DSAEngineSchemaError("Engine response must be a JSON object.")

    version = response.get("schema_version")
    if version != DEFAULT_SCHEMA_VERSION:
        raise DSAEngineSchemaError(
            f"Unsupported engine schema_version: {version!r}. Expected {DEFAULT_SCHEMA_VERSION!r}."
        )

    status = response.get("status")
    if status not in {"ok", "error"}:
        raise DSAEngineSchemaError(f"Engine status must be 'ok' or 'error', got {status!r}.")

    # Validate request_id correlation
    resp_request_id = response.get("request_id")
    if expected_request_id is not None and resp_request_id != expected_request_id:
        raise DSAEngineSchemaError(
            f"Correlation error: engine echoed request_id {resp_request_id!r}, "
            f"expected {expected_request_id!r}."
        )

    # Engine metadata is required
    metadata = response.get("engine_metadata")
    if not isinstance(metadata, dict):
        raise DSAEngineSchemaError("Engine response must include 'engine_metadata' object.")
    for req_key in ("name", "version", "execution_time_ms"):
        if req_key not in metadata:
            raise DSAEngineSchemaError(f"engine_metadata missing required field: {req_key!r}.")

    # If status is error, validate the error object
    if status == "error":
        err = response.get("error")
        if not isinstance(err, dict) or "message" not in err:
            raise DSAEngineSchemaError("Engine returned status='error' without a valid 'error' object.")
        return response

    # If status is ok, validate evidence structure
    evidence = response.get("evidence")
    if not isinstance(evidence, dict):
        raise DSAEngineSchemaError("Engine response must include an 'evidence' object on status='ok'.")

    # 1. Trie matches
    trie_matches = evidence.get("trie_matches")
    if not isinstance(trie_matches, list):
        raise DSAEngineSchemaError("'evidence.trie_matches' must be an array.")
    for item in trie_matches:
        if not isinstance(item, dict):
            raise DSAEngineSchemaError("Each item in 'trie_matches' must be an object.")
        for field_name in ("pattern", "category", "matched_in", "start_index", "length"):
            if field_name not in item:
                raise DSAEngineSchemaError(f"Item in 'trie_matches' missing field: {field_name!r}.")
        if item["matched_in"] not in {"hostname", "path", "query"}:
            raise DSAEngineSchemaError(f"Invalid 'matched_in' target: {item['matched_in']!r}.")

    # 2. Hash table lookup
    hash_lookup = evidence.get("hash_table_lookup")
    if not isinstance(hash_lookup, dict):
        raise DSAEngineSchemaError("'evidence.hash_table_lookup' must be an object.")
    if not isinstance(hash_lookup.get("matched"), bool):
        raise DSAEngineSchemaError("'hash_table_lookup.matched' must be a boolean.")
    for field_name in ("target_type", "dataset_category"):
        if field_name not in hash_lookup:
            raise DSAEngineSchemaError(f"'hash_table_lookup' missing field: {field_name!r}.")

    # 3. Levenshtein analysis
    lev_analysis = evidence.get("levenshtein_analysis")
    if not isinstance(lev_analysis, dict):
        raise DSAEngineSchemaError("'evidence.levenshtein_analysis' must be an object.")
    for field_name in (
        "analyzed_domain",
        "closest_candidate",
        "edit_distance",
        "similarity_ratio",
        "threshold_used",
        "is_typosquat_candidate",
    ):
        if field_name not in lev_analysis:
            raise DSAEngineSchemaError(f"'levenshtein_analysis' missing field: {field_name!r}.")
    if not isinstance(lev_analysis.get("is_typosquat_candidate"), bool):
        raise DSAEngineSchemaError("'is_typosquat_candidate' must be a boolean.")

    return response


def invoke_dsa_engine(
    url: str,
    *,
    hostname: str | None = None,
    path: str | None = None,
    query: str | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    engine_path: str | Path | None = None,
    request_id: str | None = None,
) -> EngineResult:
    """Execute the C++ DSA detection engine via a safe child process.

    Arguments:
        url: Validated canonical URL.
        hostname: Optional pre-extracted lowercase domain.
        path: Optional pre-extracted URL path.
        query: Optional pre-extracted URL query.
        timeout_seconds: Subprocess execution deadline in seconds.
        engine_path: Optional path to C++ binary (overrides environment/defaults).
        request_id: Optional correlation ID to echo.

    Returns:
        EngineResult: Guaranteed result object. If the engine fails, times out,
                      or is not yet compiled, available is False with status="unavailable"
                      and assessment_label="not_assessed".
    """
    executable = resolve_engine_path(engine_path)

    # 1. Verify binary existence without shell invocation
    if not executable.is_file():
        logger.debug("DSA engine binary not found at %s", executable)
        return EngineResult.unavailable(
            code="ENGINE_NOT_FOUND",
            message=f"Detection engine executable not found at '{executable}'.",
            request_id=request_id,
        )

    # 2. Build and validate request payload
    try:
        request_payload = build_engine_request(
            url=url,
            hostname=hostname,
            path=path,
            query=query,
            timeout_seconds=timeout_seconds,
            request_id=request_id,
        )
    except DSAEngineSchemaError as exc:
        return EngineResult.unavailable(
            code="INVALID_REQUEST",
            message=str(exc),
            request_id=request_id,
        )

    # 3. Serialize JSON for standard input
    request_bytes = json.dumps(request_payload, ensure_ascii=True).encode("utf-8")

    # 4. Execute child process with non-shell argument list
    try:
        process = subprocess.run(
            [str(executable)],
            input=request_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
            shell=False,  # Enforce direct execve to avoid shell injection
        )
    except PermissionError as exc:
        logger.warning("Permission denied executing DSA engine: %s", exc)
        return EngineResult.unavailable(
            code="PERMISSION_DENIED",
            message=f"Permission denied executing engine at '{executable}'.",
            request_id=request_id,
        )
    except subprocess.TimeoutExpired:
        logger.warning(
            "DSA engine timed out after %.2fs for hostname=%s",
            timeout_seconds,
            request_payload.get("hostname"),
        )
        return EngineResult.unavailable(
            code="TIMEOUT",
            message=f"Engine exceeded execution deadline of {timeout_seconds}s.",
            request_id=request_id,
        )
    except OSError as exc:
        logger.warning("OS error launching DSA engine: %s", exc)
        return EngineResult.unavailable(
            code="OS_ERROR",
            message=f"System error executing engine: {exc}",
            request_id=request_id,
        )

    # 5. Check exit code
    if process.returncode != 0:
        stderr_sample = process.stderr.decode("utf-8", errors="replace")[:300].strip()
        logger.warning(
            "DSA engine non-zero exit code %d: %s",
            process.returncode,
            stderr_sample,
        )
        return EngineResult.unavailable(
            code="PROCESS_CRASHED",
            message=f"Engine exited with non-zero status {process.returncode}.",
            request_id=request_id,
            details={"returncode": process.returncode, "stderr": stderr_sample},
        )

    # 6. Parse standard output as JSON
    stdout_raw = process.stdout.decode("utf-8", errors="replace").strip()
    try:
        response_data = json.loads(stdout_raw)
    except json.JSONDecodeError as exc:
        logger.warning("DSA engine produced invalid JSON on stdout")
        return EngineResult.unavailable(
            code="INVALID_JSON",
            message=f"Engine output could not be parsed as JSON: {exc}",
            request_id=request_id,
        )

    # 7. Validate response schema and request_id correlation
    try:
        validated = validate_engine_response(
            response_data,
            expected_request_id=request_id,
        )
    except DSAEngineSchemaError as exc:
        logger.warning("DSA engine response schema validation failed: %s", exc)
        return EngineResult.unavailable(
            code="SCHEMA_MISMATCH",
            message=str(exc),
            request_id=request_id,
        )

    # 8. Handle engine-reported error
    if validated["status"] == "error":
        return EngineResult(
            available=False,
            status="error",
            assessment_label="not_assessed",
            evidence=None,
            engine_metadata=validated.get("engine_metadata"),
            warnings=validated.get("warnings", []),
            error=validated.get("error"),
            request_id=validated.get("request_id"),
        )

    # 9. Clean success with algorithmic evidence
    return EngineResult(
        available=True,
        status="ok",
        assessment_label="not_assessed",  # Route layer remains responsible for policy
        evidence=validated.get("evidence"),
        engine_metadata=validated.get("engine_metadata"),
        warnings=validated.get("warnings", []),
        error=None,
        request_id=validated.get("request_id"),
    )
