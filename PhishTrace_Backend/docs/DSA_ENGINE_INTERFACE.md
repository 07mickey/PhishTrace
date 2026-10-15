# PhishTrace — Python/C++ Detection Engine Interface Contract

**Document Version:** 1.1.0  
**Status:** Agreed Baseline & Interface Specification  
**Decisions Pending Team Confirmation:** Dataset Provenance (Database Teammate), Suffix Parsing Strategy (Member 4)  
**Target Components:** Python Subprocess Bridge (`backend/services/`) & C++ DSA Detection Engine (`engine/`)

---

## 1. Overview & Architectural Boundaries

PhishTrace couples a **Python/Flask Web Backend** with an isolated, high-performance **C++ Data Structures and Algorithms (DSA) Engine**. This document establishes the versioned communication contract, data schemas, algorithmic specifications, and governance rules between the two subsystems.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        Python / Flask Backend                          │
│  - Receives client HTTP POST /api/scan requests                        │
│  - Validates and normalizes URL syntax (url_validator.py)              │
│  - Extracts URL structural/lexical features (feature_extractor.py)     │
│  - Invokes C++ engine as an isolated child process via argument vector │
│  - Writes single JSON request to engine stdin; reads JSON from stdout  │
│  - Maps deterministic algorithmic evidence to public API responses     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ stdin: 1 JSON Request (phish_request_v1)
                                    │ stdout: 1 JSON Response (phish_response_v1)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        C++ DSA Detection Engine                        │
│  - Implemented in modern C++17 with nlohmann/json                      │
│  - Reads single JSON request from stdin; parses parameters             │
│  - Evaluates three primary DSA structures:                              │
│      1. Prefix Tree (Trie): Suspicious pattern & keyword matching      │
│      2. Hash Table: Exact lookup of known domains / URL fingerprints   │
│      3. Damerau–Levenshtein (OSA): Typosquatting against brand corpus   │
│  - Writes single JSON response containing structured evidence to stdout│
│  - Emits diagnostics exclusively to stderr                             │
│  - Exits with status 0 on clean analysis (even if zero matches found)  │
└────────────────────────────────────────────────────────────────────────┘
```

### Core Principles

1. **Separation of Evidence and Policy**:
   - The C++ engine reports deterministic algorithmic observations (e.g., token hits in Trie, hash table presence, string distance from a brand label).
   - The engine **never** invents confidence percentages, safety probabilities, or policy verdicts.
   - The Python backend evaluates the engine's evidence, enforces security policies, and generates the final client response.
2. **Absence of Evidence is Not Proof of Safety**:
   - Zero matches across Trie, Hash Table, and Damerau–Levenshtein means only that no known signatures or lookalike patterns were detected.
   - An unknown or newly registered phishing site will have no hash table entry.
   - Zero matches **must never** cause the backend to classify a URL as "safe". The appropriate label is `unclassified` or `no_evidence_detected`.
3. **Known-Benign Membership is Not Absolute Safety**:
   - Subdomains or open redirects on popular benign domains can be compromised. Presence in a known-benign domain list is an algorithmic observation, not an unconditional safety guarantee.

---

## 2. Process Communication & Execution Protocol

### Subprocess Invocation Strategy

- **Command Invocation**: Executed via standard argument list with `shell=False`. User input is **never** interpolated, concatenated, or passed to a shell interpreter.
- **Process Lifecycle**: The executable is launched per scan request.
- **Standard Input (`stdin`)**: Exactly one compact, valid JSON document (`phish_request_v1`) followed by EOF or newline.
- **Standard Output (`stdout`)**: Exactly one valid JSON document (`phish_response_v1`). Must contain **only** JSON; no banners, progress indicators, or debugging text.
- **Standard Error (`stderr`)**: Reserved exclusively for diagnostic logs, stack traces, and internal debugging. Captured by Python on failure for logging, but never parsed for business logic.

### Python Invocation Pattern (Reference Specification)

```python
import json
import subprocess
from pathlib import Path

def invoke_dsa_engine(
    engine_path: str,
    request_data: dict,
    timeout_seconds: float = 1.5,
) -> dict:
    executable = Path(engine_path).resolve()
    if not executable.is_file():
        raise FileNotFoundError(f"Engine binary not found: {executable}")

    input_bytes = json.dumps(request_data, ensure_ascii=True).encode("utf-8")

    try:
        process = subprocess.run(
            [str(executable)],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
            shell=False,  # Mandatory: prevent command injection
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Detection engine timed out") from exc

    if process.returncode != 0:
        stderr_sample = process.stderr.decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"Engine crashed (code {process.returncode}): {stderr_sample}")

    try:
        return json.loads(process.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("Engine produced malformed JSON on stdout") from exc
```

### Process Resilience & Failure Matrix

| Failure Mode | Detection in Python | Backend Handling | API Client Response |
| :--- | :--- | :--- | :--- |
| **Missing Binary** | `FileNotFoundError` | Log error; flag engine unintegrated | HTTP 200, `assessment.label="not_assessed"`, `detection_engine.integrated=false` |
| **Permission Denied** | `PermissionError` | Log executable permission fault | HTTP 200, `assessment.label="not_assessed"` |
| **Subprocess Timeout** | `subprocess.TimeoutExpired` | Terminate process cleanly; log timeout | HTTP 200, `assessment.label="not_assessed"`, warning logged |
| **Crash / SIGSEGV** | `process.returncode != 0` | Log return code and stderr sample | HTTP 200, `assessment.label="not_assessed"` |
| **Malformed stdout** | `json.JSONDecodeError` | Log raw stdout excerpt | HTTP 200, `assessment.label="not_assessed"` |
| **Schema Violation** | Missing required JSON keys | Log schema mismatch details | HTTP 200, `assessment.label="not_assessed"` |

---

## 3. Request Specification (`phish_request_v1`)

The Python backend pre-validates and normalizes the URL syntax using [`url_validator.py`](../backend/services/url_validator.py). The C++ engine receives clean, canonical input.

### Request JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "PhishTraceEngineRequest",
  "type": "object",
  "required": ["schema_version", "url", "hostname"],
  "properties": {
    "schema_version": {
      "type": "string",
      "enum": ["1.0"]
    },
    "request_id": {
      "type": ["string", "null"],
      "description": "Optional correlation identifier (UUID or integer). If supplied, the engine must echo it in the response."
    },
    "url": {
      "type": "string",
      "minLength": 1,
      "maxLength": 2048,
      "description": "Pre-normalized canonical URL with scheme and host."
    },
    "hostname": {
      "type": "string",
      "minLength": 1,
      "maxLength": 253,
      "description": "Extracted lowercase hostname or IP literal without trailing dots or port numbers."
    },
    "path": {
      "type": "string",
      "description": "Decoded URL path component (empty string if absent)."
    },
    "query": {
      "type": "string",
      "description": "Raw URL query string (empty string if absent)."
    },
    "timeout_ms": {
      "type": "integer",
      "minimum": 10,
      "maximum": 10000,
      "default": 1500,
      "description": "Cooperative deadline hint for internal loops in the engine."
    }
  },
  "additionalProperties": false
}
```

### Input Field Definitions & Rules

- `schema_version` (*string, required*): Must be `"1.0"`. Rejection with `"status": "error"` if unsupported.
- `request_id` (*string or null, optional*): Client or backend tracing ID. If provided, the C++ engine **must** echo this exact string in its response.
- `url` (*string, required*): Complete normalized URL.
- `hostname` (*string, required*): Lowercase hostname without port (e.g., `paypa1.sub.evil.com`). Provided to eliminate C++ URL re-parsing.
- `path` (*string, optional, default `""`*): Extracted path component.
- `query` (*string, optional, default `""`*): Extracted query component.
- `timeout_ms` (*integer, optional, default `1500`*): Cooperative execution deadline.

---

## 4. Response Specification (`phish_response_v1`)

### Response JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "PhishTraceEngineResponse",
  "type": "object",
  "required": ["schema_version", "status", "engine_metadata", "evidence"],
  "properties": {
    "schema_version": {
      "type": "string",
      "enum": ["1.0"]
    },
    "request_id": {
      "type": ["string", "null"],
      "description": "Echoed correlation identifier matching the request, or null if omitted in request."
    },
    "status": {
      "type": "string",
      "enum": ["ok", "error"]
    },
    "engine_metadata": {
      "type": "object",
      "required": ["name", "version", "build", "execution_time_ms"],
      "properties": {
        "name": { "type": "string" },
        "version": { "type": "string" },
        "build": { "type": "string" },
        "execution_time_ms": { "type": "number", "minimum": 0 }
      }
    },
    "evidence": {
      "type": "object",
      "required": [
        "trie_matches",
        "hash_table_lookup",
        "levenshtein_analysis"
      ],
      "properties": {
        "trie_matches": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["pattern", "category", "matched_in", "start_index", "length"],
            "properties": {
              "pattern": { "type": "string" },
              "category": {
                "type": "string",
                "enum": ["brand_name", "credential_action", "urgency_keyword", "security_token", "generic"]
              },
              "matched_in": {
                "type": "string",
                "enum": ["hostname", "path", "query"]
              },
              "start_index": { "type": "integer", "minimum": 0 },
              "length": { "type": "integer", "minimum": 1 }
            }
          }
        },
        "hash_table_lookup": {
          "type": "object",
          "required": ["matched", "target_type", "dataset_category"],
          "properties": {
            "matched": { "type": "boolean" },
            "target_type": {
              "type": ["string", "null"],
              "enum": ["url_exact", "domain_exact", null]
            },
            "dataset_category": {
              "type": ["string", "null"],
              "enum": ["known_phishing", "known_benign", null]
            },
            "matched_key": {
              "type": ["string", "null"],
              "description": "Identifier or hash representation matched (never raw credentials)."
            }
          }
        },
        "levenshtein_analysis": {
          "type": "object",
          "required": [
            "analyzed_domain",
            "closest_candidate",
            "edit_distance",
            "similarity_ratio",
            "threshold_used",
            "is_typosquat_candidate"
          ],
          "properties": {
            "analyzed_domain": { "type": "string" },
            "closest_candidate": { "type": ["string", "null"] },
            "edit_distance": { "type": ["integer", "null"], "minimum": 0 },
            "similarity_ratio": { "type": ["number", "null"], "minimum": 0.0, "maximum": 1.0 },
            "threshold_used": { "type": "integer", "minimum": 1 },
            "is_typosquat_candidate": { "type": "boolean" }
          }
        }
      }
    },
    "warnings": {
      "type": "array",
      "items": { "type": "string" }
    },
    "error": {
      "type": ["object", "null"],
      "properties": {
        "code": { "type": "string" },
        "message": { "type": "string" }
      }
    }
  }
}
```

---

## 5. Algorithm Semantics & Implementation Specifics

### 1. Trie Pattern Matching (`trie_matches`)

- **DSA Structure**: Multi-pattern Prefix Tree (Trie) with keyword termination nodes.
- **Tokenization Rules**:
  - Scanning raw substrings across the entire URL produces severe false positives (e.g. `"in"` inside `"domain"`, or `"pay"` inside `"company"`).
  - The C++ engine splits `hostname`, `path`, and `query` on standard URL delimiters: `.`, `-`, `_`, `/`, `?`, `=`, `&`, `@`.
  - Matching is **token-exact** against the Trie vocabulary.
  - In addition to exact token matching, for hyphenated or underscore compound tokens (e.g. `paypal-login`), the engine evaluates prefix and suffix sub-tokens against the Trie.
- **Normalization**: All input strings are lowercased (ASCII) before token evaluation.
- **Categories**:
  - `brand_name`: Targeted legitimate brands (`paypal`, `microsoft`, `apple`, `netflix`, `chase`).
  - `credential_action`: High-risk verbs (`login`, `signin`, `auth`, `password`, `authenticate`).
  - `urgency_keyword`: Social engineering urgency (`verify`, `suspended`, `action-required`, `urgent`, `locked`).
  - `security_token`: High-trust security indicators (`security`, `account`, `billing`, `wallet`, `kyc`).

### 2. Hash Table Lookup (`hash_table_lookup`)

- **DSA Structure**: Hash table with $O(1)$ expected lookup (e.g. `std::unordered_set<std::string>` or custom closed-addressing hash table).
- **Lookup Sequence**:
  1. Primary: Exact match on canonical URL string (or SHA-256 digest).
  2. Secondary: Exact match on normalized hostname.
- **Distinction Between Result States**:
  - `matched: true, dataset_category: "known_phishing"`: Exact match against verified malicious dataset.
  - `matched: true, dataset_category: "known_benign"`: Exact match against verified benign/allowlist dataset.
  - `matched: false`: Target not found. **Does not mean the URL is safe.**

### 3. Damerau–Levenshtein Distance (`levenshtein_analysis`)

- **Algorithm Variant**: **Restricted Damerau–Levenshtein distance (Optimal String Alignment / OSA)**.
  - Computes minimum cost of insertions, deletions, substitutions, and **adjacent character transpositions** (e.g. `paypla` $\leftrightarrow$ `paypal` costs 1 edit instead of 2 under classical Levenshtein).
  - Enforces the OSA condition that no substring is edited more than once.
- **Proposed Threshold**:
  - Maximum edit distance: $k = 2$.
  - Distance $k = 0$: Exact match with approved domain (not typosquatting).
  - Distance $1 \le k \le 2$: Flagged as `is_typosquat_candidate = true`.
  - Distance $k \ge 3$: Not considered a candidate typosquat (avoids spurious associations for short domains).
- **Candidate Pruning**:
  - Length filter: Immediately skip candidate $C$ if $|\text{len}(D) - \text{len}(C)| > 2$.
  - First-character filter: Optional optimization when evaluated over large candidate sets.

### 4. Domain Comparison & Registrable Domain Parsing (MVP vs. Future)

- **The Multi-Label Public Suffix Problem**:
  - Naively stripping `.com`, `.net`, and `.org` fails for multi-label country code public suffixes such as `.co.uk`, `.com.au`, `.edu.in`, and `.org.uk`.
  - Under naive stripping, `evil-bank.co.uk` would be parsed as domain `co` with subdomain `evil-bank`, corrupting Levenshtein comparisons.
- **Chosen MVP Approach**:
  - The engine will maintain a small hardcoded lookup table of common two-label public suffixes (`co.uk`, `com.au`, `co.jp`, `gov.uk`, `edu.in`).
  - For hostnames ending in a known two-label suffix, the engine extracts the label immediately preceding the suffix as the registrable second-level label.
  - For single-label TLDs (`.com`, `.net`, `.org`), it extracts the immediate preceding label.
- **Documented MVP Limitations**:
  - The hardcoded suffix table does not cover the complete Mozilla Public Suffix List (PSL). Private suffixes or uncommon regional ccTLDs may be incorrectly segmented.
- **Required Verification Tests**:
  - Test `paypal.com` $\rightarrow$ registrable label `paypal`.
  - Test `paypal.co.uk` $\rightarrow$ registrable label `paypal`.
  - Test `paypa1.com.au` $\rightarrow$ registrable label `paypa1` (identified as typosquat of `paypal`).
- **Future Roadmap**: Transition to a Trie-based Public Suffix List parser once the database teammate provides the reference suffix dataset.

---

## 6. Dataset Governance, Provenance & Build Reproducibility

### Dataset Coordination with Database Teammate

> **MANDATE:** Member 4 and the Python team must **not** independently create ad-hoc, competing datasets. All datasets used by the C++ engine must be coordinated with the database/dataset teammate.

1. **Dataset Sources & Provenance**:
   - **Known Phishing Feed**: Curated from vetted feeds (e.g., PhishTank, OpenPhish) agreed upon by the database teammate.
   - **Approved Brand Corpus**: Curated list of high-value brands (e.g., Alexa/Tranco top financial, e-commerce, and cloud authentication domains).
   - **Trie Lexicon**: Curated list of social engineering and credential keywords.
2. **Versioning & Ownership**:
   - The database teammate owns the canonical source data files (stored in a shared repository directory, e.g., `data/`).
   - Every dataset export must carry a version/timestamp identifier (e.g. `2026-10-dataset-v1`).
3. **Compiled Lookup Data & Rebuild Requirements**:
   - For sub-millisecond execution, datasets can be compiled directly into the C++ binary via static arrays/headers.
   - **Generation Process**: Must be 100% reproducible via an automated script (e.g., `scripts/generate_engine_datasets.py`) that reads canonical CSV/JSON from `data/` and generates C++ header files (`engine/include/generated_datasets.hpp`).
   - **Update Trade-off**: Updating compiled datasets requires re-running the generation script and recompiling the C++ binary. This trade-off is accepted for the initial milestone.

### Build Reproducibility & Toolchain Specification

- **C++ Standard**: C++17 (compiled with `-O3 -Wall -Wextra -std=c++17`).
- **Target Executable Location**: `engine/bin/phishtrace_engine`.
- **JSON Library Provisioning**:
  - CMake uses `FetchContent` to retrieve `nlohmann/json` (v3.11.3) during build configuration, or links against a vendored single-header file in `engine/include/nlohmann/json.hpp`.
- **Explicit CMake Output Configuration**:
  ```cmake
  cmake_minimum_required(VERSION 3.16)
  project(PhishTraceEngine LANGUAGES CXX)

  set(CMAKE_CXX_STANDARD 17)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)

  # Explicitly establish output directory so binary always lands at documented path
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

  include(FetchContent)
  FetchContent_Declare(
      nlohmann_json
      URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
  )
  FetchContent_MakeAvailable(nlohmann_json)

  add_executable(phishtrace_engine
      src/main.cpp
      src/trie.cpp
      src/hash_table.cpp
      src/levenshtein.cpp
  )

  target_link_libraries(phishtrace_engine PRIVATE nlohmann_json::nlohmann_json)
  ```
- **Build Execution**:
  ```bash
  cd engine
  mkdir -p build && cd build
  cmake -DCMAKE_BUILD_TYPE=Release ..
  cmake --build .
  # Confirmed binary created at: engine/bin/phishtrace_engine
  ```

---

## 7. Performance Targets & Benchmarking Protocol

> **NOTE:** All latency figures in this document represent **engineering targets**, not verified results. Actual performance must be measured empirically after Member 4 builds the engine.

### Engineering Targets

- **Engine Internal Execution Time (`execution_time_ms`)**: Target $\le 2.0\text{ ms}$ for typical URLs ($\le 100$ characters).
- **Subprocess Roundtrip Latency (Python $\rightarrow$ C++ $\rightarrow$ Python)**: Target $\le 20.0\text{ ms}$ wall-clock time on modern macOS/Linux hardware.
- **Engine Process Memory Footprint**: Target $\le 16\text{ MB}$ RSS.

### Benchmarking Protocol

Once the initial binary is delivered, the backend team will run an automated benchmark suite (`scripts/benchmark_engine.py`):

1. **Cold Start Test**: Execute engine on a single URL immediately after system boot / cache drop. Measure process creation overhead.
2. **Warm Invocations Test**: Execute 1,000 consecutive scans. Record minimum, median (P50), 95th percentile (P95), and maximum latency.
3. **Worst-Case Payload Test**: Execute scans with maximum URL length (2,048 chars), deeply nested paths, and 50+ query parameters to verify that Damerau–Levenshtein candidate filtering prevents quadratic blowup.
4. **Discrepancy Comparison**: Compare Python's measured wall-clock time against the engine's self-reported `execution_time_ms` to isolate subprocess spawn overhead from algorithmic execution time.

---

## 8. Assessment Semantics & Safety Verdicts

The Python backend applies the following strict interpretation rules when transforming C++ evidence into public API responses:

```text
┌───────────────────────────────────────┬────────────────────────────────────────┬────────────────────────────────────────┐
│ C++ Engine Evidence                   │ API assessment.label                   │ Client Message                         │
├───────────────────────────────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
│ Hash Table match on known_phishing    │ "phishing"                             │ "Known phishing domain/URL confirmed." │
│ Typosquat match + Credential keyword  │ "suspicious"                           │ "Likely brand impersonation detected." │
│ Clean scan (zero evidence matches)    │ "unclassified"                         │ "No known patterns detected; not verified safe." │
│ Process timeout / crash / missing bin │ "not_assessed"                         │ "Detection engine currently unavailable." │
└───────────────────────────────────────┴────────────────────────────────────────┴────────────────────────────────────────┘
```

1. **Distinction Between Clean Scan and Execution Error**:
   - `status == "ok"` with empty evidence means the algorithms executed successfully and found no matches.
   - `status == "error"` or non-zero exit code means the analysis failed or was aborted.
2. **Never Claim Safe on Clean Scan**:
   - If `status == "ok"` and all evidence lists are empty, the backend sets `assessment.label = "unclassified"` (or `"no_evidence_detected"`).
   - The response must explicitly clarify: *"Absence of detected patterns does not verify that a URL is safe."*
3. **Never Overwrite with Fabricated Metrics**:
   - The backend will never assign synthetic confidence percentages (e.g. `"92% safe"`). Assessments must cite concrete algorithm evidence.

---

## 9. Illustrative Contract Examples

> **DISCLAIMER:** The following examples are synthetic schema illustrations to demonstrate JSON structure and field types. They do not represent real engine execution results or live detection decisions.

### Example A: Typosquatting and Suspicious Keyword Match (with `request_id`)

#### Request (Python $\rightarrow$ C++ stdin)
```json
{
  "schema_version": "1.0",
  "request_id": "req-8f4b2a1c",
  "url": "https://paypa1-security.com/signin/verify",
  "hostname": "paypa1-security.com",
  "path": "/signin/verify",
  "query": "",
  "timeout_ms": 1500
}
```

#### Response (C++ $\rightarrow$ Python stdout)
```json
{
  "schema_version": "1.0",
  "request_id": "req-8f4b2a1c",
  "status": "ok",
  "engine_metadata": {
    "name": "PhishTrace-DSA-Core",
    "version": "0.1.0",
    "build": "20261015-arm64",
    "execution_time_ms": 1.42
  },
  "evidence": {
    "trie_matches": [
      {
        "pattern": "security",
        "category": "security_token",
        "matched_in": "hostname",
        "start_index": 7,
        "length": 8
      },
      {
        "pattern": "signin",
        "category": "credential_action",
        "matched_in": "path",
        "start_index": 1,
        "length": 6
      },
      {
        "pattern": "verify",
        "category": "urgency_keyword",
        "matched_in": "path",
        "start_index": 8,
        "length": 6
      }
    ],
    "hash_table_lookup": {
      "matched": false,
      "target_type": null,
      "dataset_category": null,
      "matched_key": null
    },
    "levenshtein_analysis": {
      "analyzed_domain": "paypa1-security.com",
      "closest_candidate": "paypal.com",
      "edit_distance": 1,
      "similarity_ratio": 0.88,
      "threshold_used": 2,
      "is_typosquat_candidate": true
    }
  },
  "warnings": [],
  "error": null
}
```

---

### Example B: Exact Known Phishing Match (Hash Table)

#### Request (Python $\rightarrow$ C++ stdin)
```json
{
  "schema_version": "1.0",
  "request_id": "req-002",
  "url": "https://malicious-update-portal.net/update.exe",
  "hostname": "malicious-update-portal.net",
  "path": "/update.exe",
  "query": "",
  "timeout_ms": 1500
}
```

#### Response (C++ $\rightarrow$ Python stdout)
```json
{
  "schema_version": "1.0",
  "request_id": "req-002",
  "status": "ok",
  "engine_metadata": {
    "name": "PhishTrace-DSA-Core",
    "version": "0.1.0",
    "build": "20261015-arm64",
    "execution_time_ms": 0.35
  },
  "evidence": {
    "trie_matches": [
      {
        "pattern": "update",
        "category": "generic",
        "matched_in": "hostname",
        "start_index": 10,
        "length": 6
      }
    ],
    "hash_table_lookup": {
      "matched": true,
      "target_type": "domain_exact",
      "dataset_category": "known_phishing",
      "matched_key": "malicious-update-portal.net"
    },
    "levenshtein_analysis": {
      "analyzed_domain": "malicious-update-portal.net",
      "closest_candidate": null,
      "edit_distance": null,
      "similarity_ratio": null,
      "threshold_used": 2,
      "is_typosquat_candidate": false
    }
  },
  "warnings": [],
  "error": null
}
```

---

### Example C: Clean Scan (Zero Evidence Matches)

#### Request (Python $\rightarrow$ C++ stdin)
```json
{
  "schema_version": "1.0",
  "request_id": null,
  "url": "https://unfamiliar-local-bakery.org/menu",
  "hostname": "unfamiliar-local-bakery.org",
  "path": "/menu",
  "query": "",
  "timeout_ms": 1500
}
```

#### Response (C++ $\rightarrow$ Python stdout)
```json
{
  "schema_version": "1.0",
  "request_id": null,
  "status": "ok",
  "engine_metadata": {
    "name": "PhishTrace-DSA-Core",
    "version": "0.1.0",
    "build": "20261015-arm64",
    "execution_time_ms": 0.81
  },
  "evidence": {
    "trie_matches": [],
    "hash_table_lookup": {
      "matched": false,
      "target_type": null,
      "dataset_category": null,
      "matched_key": null
    },
    "levenshtein_analysis": {
      "analyzed_domain": "unfamiliar-local-bakery.org",
      "closest_candidate": null,
      "edit_distance": null,
      "similarity_ratio": null,
      "threshold_used": 2,
      "is_typosquat_candidate": false
    }
  },
  "warnings": [],
  "error": null
}
```
*Backend Outcome:* `assessment.label = "unclassified"`. The API explicitly clarifies that no suspicious patterns were found, but the URL is not certified safe.

---

### Example D: Engine Internal Error

#### Response (C++ $\rightarrow$ Python stdout)
```json
{
  "schema_version": "1.0",
  "request_id": "req-999",
  "status": "error",
  "engine_metadata": {
    "name": "PhishTrace-DSA-Core",
    "version": "0.1.0",
    "build": "20261015-arm64",
    "execution_time_ms": 0.05
  },
  "evidence": {
    "trie_matches": [],
    "hash_table_lookup": {
      "matched": false,
      "target_type": null,
      "dataset_category": null,
      "matched_key": null
    },
    "levenshtein_analysis": {
      "analyzed_domain": "",
      "closest_candidate": null,
      "edit_distance": null,
      "similarity_ratio": null,
      "threshold_used": 2,
      "is_typosquat_candidate": false
    }
  },
  "warnings": [],
  "error": {
    "code": "DATASET_CORRUPTED",
    "message": "Engine initialization failed due to corrupted static dataset tables."
  }
}
```
*Backend Outcome:* Handled as an engine failure; returns HTTP 200 with `assessment.label = "not_assessed"`.

---

## 10. Team Alignment & Pending Decisions Checklist

The following items are categorized by team ownership and must be formally confirmed before code integration starts:

### Decisions for Member 4 (C++ Engine Developer)
- [ ] **Target Build Output**: Confirm that CMake build configuration explicitly outputs to `engine/bin/phishtrace_engine`.
- [ ] **Damerau–Levenshtein OSA Confirmation**: Confirm implementation of the Optimal String Alignment variant with max threshold $k = 2$.
- [ ] **Delimiter Set for Trie Tokenization**: Agree on standard delimiter set (`.`, `-`, `_`, `/`, `?`, `=`, `&`, `@`).
- [ ] **Echo Request ID**: Confirm that the optional `request_id` from the request JSON is echoed in the response JSON.
- [ ] **Diagnostics on stderr**: Confirm that all debug prints, logging, or timing messages are sent strictly to `stderr`, leaving `stdout` as pristine JSON.

### Decisions for Database / Dataset Teammate
- [ ] **Dataset Source & Provenance Agreement**: Agree on official feeds and sources for known phishing URLs/domains and the approved brand domain corpus. Avoid creating uncoordinated duplicate datasets.
- [ ] **Dataset Export Pipeline**: Establish the reproducible automated export format (CSV/JSON) and directory location (`data/`) for C++ code generation.
- [ ] **Multi-Label Public Suffix Dataset**: Coordinate on providing a canonical reference list of multi-label public suffixes (`.co.uk`, `.com.au`, etc.) to replace the MVP hardcoded table in future milestones.
- [ ] **Dataset Versioning & Update Cadence**: Define how often the dataset is refreshed and the protocol for triggering C++ binary rebuilds when compiled datasets change.
