"""Automated unit tests for the Python-to-C++ DSA engine subprocess bridge.

All subprocess calls in this module are mocked to verify bridge behavior,
schema validation, failure handling, and request-id correlation independently
without requiring the compiled C++ engine executable.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from backend.services.dsa_engine_bridge import (
    DSAEngineSchemaError,
    EngineResult,
    build_engine_request,
    invoke_dsa_engine,
    resolve_engine_path,
    validate_engine_response,
)


def _make_mock_process(
    returncode: int = 0,
    stdout: str | bytes = "",
    stderr: str | bytes = "",
) -> subprocess.CompletedProcess:
    stdout_bytes = stdout.encode("utf-8") if isinstance(stdout, str) else stdout
    stderr_bytes = stderr.encode("utf-8") if isinstance(stderr, str) else stderr
    return subprocess.CompletedProcess(
        args=["phishtrace_engine"],
        returncode=returncode,
        stdout=stdout_bytes,
        stderr=stderr_bytes,
    )


SAMPLE_FINDINGS_RESPONSE = {
    "schema_version": "1.0",
    "request_id": "req-findings-01",
    "status": "ok",
    "engine_metadata": {
        "name": "PhishTrace-DSA-Core",
        "version": "0.1.0",
        "build": "mock-build",
        "execution_time_ms": 1.45,
    },
    "evidence": {
        "trie_matches": [
            {
                "pattern": "paypal",
                "category": "brand_name",
                "matched_in": "hostname",
                "start_index": 0,
                "length": 6,
            },
            {
                "pattern": "login",
                "category": "credential_action",
                "matched_in": "path",
                "start_index": 1,
                "length": 5,
            },
        ],
        "hash_table_lookup": {
            "matched": False,
            "target_type": None,
            "dataset_category": None,
            "matched_key": None,
        },
        "levenshtein_analysis": {
            "analyzed_domain": "paypa1.com",
            "closest_candidate": "paypal.com",
            "edit_distance": 1,
            "similarity_ratio": 0.90,
            "threshold_used": 2,
            "is_typosquat_candidate": True,
        },
    },
    "warnings": [],
    "error": None,
}

SAMPLE_CLEAN_RESPONSE = {
    "schema_version": "1.0",
    "request_id": None,
    "status": "ok",
    "engine_metadata": {
        "name": "PhishTrace-DSA-Core",
        "version": "0.1.0",
        "build": "mock-build",
        "execution_time_ms": 0.52,
    },
    "evidence": {
        "trie_matches": [],
        "hash_table_lookup": {
            "matched": False,
            "target_type": None,
            "dataset_category": None,
            "matched_key": None,
        },
        "levenshtein_analysis": {
            "analyzed_domain": "example.com",
            "closest_candidate": None,
            "edit_distance": None,
            "similarity_ratio": None,
            "threshold_used": 2,
            "is_typosquat_candidate": False,
        },
    },
    "warnings": [],
    "error": None,
}


# ============================================================================
# 1. Successful Response with Findings
# ============================================================================

def test_bridge_successful_response_with_findings(tmp_path):
    fake_exe = tmp_path / "phishtrace_engine"
    fake_exe.touch()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _make_mock_process(
            returncode=0,
            stdout=json.dumps(SAMPLE_FINDINGS_RESPONSE),
        )

        result = invoke_dsa_engine(
            url="https://paypa1.com/login",
            engine_path=fake_exe,
            request_id="req-findings-01",
        )

    assert result.available is True
    assert result.status == "ok"
    assert result.assessment_label == "not_assessed"
    assert result.request_id == "req-findings-01"
    assert result.evidence is not None
    assert len(result.evidence["trie_matches"]) == 2
    assert result.evidence["levenshtein_analysis"]["is_typosquat_candidate"] is True
    assert result.evidence["levenshtein_analysis"]["closest_candidate"] == "paypal.com"
    assert result.error is None

    # Verify subprocess was called with shell=False and argument list
    mock_run.assert_called_once()
    call_kwargs = mock_run.call_args[1]
    assert call_kwargs.get("shell") is False
    assert mock_run.call_args[0][0] == [str(fake_exe)]


# ============================================================================
# 2. Successful Response with No Findings (Clean Scan)
# ============================================================================

def test_bridge_successful_response_with_no_findings(tmp_path):
    fake_exe = tmp_path / "phishtrace_engine"
    fake_exe.touch()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _make_mock_process(
            returncode=0,
            stdout=json.dumps(SAMPLE_CLEAN_RESPONSE),
        )

        result = invoke_dsa_engine(
            url="https://example.com/about",
            engine_path=fake_exe,
        )

    assert result.available is True
    assert result.status == "ok"
    assert result.evidence is not None
    assert result.evidence["trie_matches"] == []
    assert result.evidence["hash_table_lookup"]["matched"] is False
    assert result.evidence["levenshtein_analysis"]["is_typosquat_candidate"] is False
    assert result.error is None


# ============================================================================
# 3. Request ID Correlation
# ============================================================================

def test_bridge_request_id_correlation(tmp_path):
    fake_exe = tmp_path / "phishtrace_engine"
    fake_exe.touch()

    req_id = "corr-unique-987"
    response_copy = dict(SAMPLE_FINDINGS_RESPONSE)
    response_copy["request_id"] = req_id

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _make_mock_process(
            returncode=0,
            stdout=json.dumps(response_copy),
        )

        result = invoke_dsa_engine(
            url="https://paypa1.com/login",
            engine_path=fake_exe,
            request_id=req_id,
        )

    assert result.request_id == req_id

    # Verify the JSON passed on stdin had the matching request_id
    stdin_payload = json.loads(mock_run.call_args[1]["input"].decode("utf-8"))
    assert stdin_payload["request_id"] == req_id
    assert stdin_payload["schema_version"] == "1.0"
    assert stdin_payload["hostname"] == "paypa1.com"


# ============================================================================
# 4. Timeout Handling
# ============================================================================

def test_bridge_timeout_handling(tmp_path):
    fake_exe = tmp_path / "phishtrace_engine"
    fake_exe.touch()

    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=[str(fake_exe)],
            timeout=1.5,
        )

        result = invoke_dsa_engine(
            url="https://slow-engine.example.com",
            engine_path=fake_exe,
            timeout_seconds=1.5,
            request_id="timeout-req-1",
        )

    assert result.available is False
    assert result.status == "unavailable"
    assert result.assessment_label == "not_assessed"
    assert result.evidence is None
    assert result.error is not None
    assert result.error["code"] == "TIMEOUT"
    assert "exceeded execution deadline" in result.error["message"]
    assert result.request_id == "timeout-req-1"


# ============================================================================
# 5. Executable Missing or Unable to Start
# ============================================================================

def test_bridge_executable_missing(tmp_path):
    missing_exe = tmp_path / "nonexistent" / "phishtrace_engine"

    result = invoke_dsa_engine(
        url="https://example.com",
        engine_path=missing_exe,
    )

    assert result.available is False
    assert result.status == "unavailable"
    assert result.assessment_label == "not_assessed"
    assert result.error is not None
    assert result.error["code"] == "ENGINE_NOT_FOUND"


def test_bridge_permission_error(tmp_path):
    fake_exe = tmp_path / "phishtrace_engine"
    fake_exe.touch()

    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = PermissionError("Permission denied: cannot execute")

        result = invoke_dsa_engine(
            url="https://example.com",
            engine_path=fake_exe,
        )

    assert result.available is False
    assert result.status == "unavailable"
    assert result.assessment_label == "not_assessed"
    assert result.error is not None
    assert result.error["code"] == "PERMISSION_DENIED"


# ============================================================================
# 6. Non-Zero Process Exit
# ============================================================================

def test_bridge_nonzero_process_exit(tmp_path):
    fake_exe = tmp_path / "phishtrace_engine"
    fake_exe.touch()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _make_mock_process(
            returncode=139,  # SIGSEGV
            stderr="Segmentation fault: core dumped at 0xdeadbeef",
        )

        result = invoke_dsa_engine(
            url="https://crash-test.example.com",
            engine_path=fake_exe,
        )

    assert result.available is False
    assert result.status == "unavailable"
    assert result.assessment_label == "not_assessed"
    assert result.error is not None
    assert result.error["code"] == "PROCESS_CRASHED"
    assert result.error["details"]["returncode"] == 139
    assert "Segmentation fault" in result.error["details"]["stderr"]


# ============================================================================
# 7. Invalid JSON Output
# ============================================================================

def test_bridge_invalid_json_output(tmp_path):
    fake_exe = tmp_path / "phishtrace_engine"
    fake_exe.touch()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _make_mock_process(
            returncode=0,
            stdout="Starting engine... [CRITICAL ERROR] corrupted heap\n",
        )

        result = invoke_dsa_engine(
            url="https://example.com",
            engine_path=fake_exe,
        )

    assert result.available is False
    assert result.status == "unavailable"
    assert result.assessment_label == "not_assessed"
    assert result.error is not None
    assert result.error["code"] == "INVALID_JSON"


# ============================================================================
# 8. Invalid Response Schema
# ============================================================================

def test_bridge_invalid_response_schema_missing_evidence(tmp_path):
    fake_exe = tmp_path / "phishtrace_engine"
    fake_exe.touch()

    malformed = {
        "schema_version": "1.0",
        "status": "ok",
        "engine_metadata": {
            "name": "PhishTrace",
            "version": "1.0",
            "execution_time_ms": 1.0,
        },
        # Missing 'evidence' key entirely
    }

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _make_mock_process(
            returncode=0,
            stdout=json.dumps(malformed),
        )

        result = invoke_dsa_engine(
            url="https://example.com",
            engine_path=fake_exe,
        )

    assert result.available is False
    assert result.status == "unavailable"
    assert result.error is not None
    assert result.error["code"] == "SCHEMA_MISMATCH"
    assert "evidence" in result.error["message"]


def test_bridge_unsupported_schema_version(tmp_path):
    fake_exe = tmp_path / "phishtrace_engine"
    fake_exe.touch()

    future_schema = dict(SAMPLE_CLEAN_RESPONSE)
    future_schema["schema_version"] = "2.0"

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _make_mock_process(
            returncode=0,
            stdout=json.dumps(future_schema),
        )

        result = invoke_dsa_engine(
            url="https://example.com",
            engine_path=fake_exe,
        )

    assert result.available is False
    assert result.status == "unavailable"
    assert result.error is not None
    assert result.error["code"] == "SCHEMA_MISMATCH"
    assert "2.0" in result.error["message"]


# ============================================================================
# 9. Response Request ID Mismatch
# ============================================================================

def test_bridge_request_id_mismatch(tmp_path):
    fake_exe = tmp_path / "phishtrace_engine"
    fake_exe.touch()

    mismatched = dict(SAMPLE_FINDINGS_RESPONSE)
    mismatched["request_id"] = "different-id-xyz"

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _make_mock_process(
            returncode=0,
            stdout=json.dumps(mismatched),
        )

        result = invoke_dsa_engine(
            url="https://example.com",
            engine_path=fake_exe,
            request_id="expected-id-abc",
        )

    assert result.available is False
    assert result.status == "unavailable"
    assert result.error is not None
    assert result.error["code"] == "SCHEMA_MISMATCH"
    assert "Correlation error" in result.error["message"]


# ============================================================================
# 10. Engine-Reported Error
# ============================================================================

def test_bridge_engine_reported_error(tmp_path):
    fake_exe = tmp_path / "phishtrace_engine"
    fake_exe.touch()

    error_response = {
        "schema_version": "1.0",
        "request_id": "req-err-01",
        "status": "error",
        "engine_metadata": {
            "name": "PhishTrace-DSA-Core",
            "version": "0.1.0",
            "build": "mock-build",
            "execution_time_ms": 0.05,
        },
        "evidence": None,
        "warnings": [],
        "error": {
            "code": "CORRUPTED_CANDIDATE_DATASET",
            "message": "Candidate domains dataset could not be opened or parsed.",
        },
    }

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _make_mock_process(
            returncode=0,
            stdout=json.dumps(error_response),
        )

        result = invoke_dsa_engine(
            url="https://example.com",
            engine_path=fake_exe,
            request_id="req-err-01",
        )

    assert result.available is False
    assert result.status == "error"
    assert result.assessment_label == "not_assessed"
    assert result.evidence is None
    assert result.error == {
        "code": "CORRUPTED_CANDIDATE_DATASET",
        "message": "Candidate domains dataset could not be opened or parsed.",
    }
    assert result.request_id == "req-err-01"


# ============================================================================
# 11. Request Builder and Response Validator Unit Tests
# ============================================================================

def test_build_engine_request_validates_inputs():
    with pytest.raises(DSAEngineSchemaError, match="non-empty string"):
        build_engine_request("")

    with pytest.raises(DSAEngineSchemaError, match="valid hostname"):
        build_engine_request("https://")

    req = build_engine_request(
        "https://sub.evil-bank.com:8080/path/test?q=1#frag",
        request_id="req-build-1",
        timeout_seconds=2.0,
    )
    assert req["schema_version"] == "1.0"
    assert req["hostname"] == "sub.evil-bank.com"
    assert req["path"] == "/path/test"
    assert req["query"] == "q=1"
    assert req["timeout_ms"] == 2000
    assert req["request_id"] == "req-build-1"


def test_validate_engine_response_rejects_non_dict():
    with pytest.raises(DSAEngineSchemaError, match="JSON object"):
        validate_engine_response("not a dict")
