# PhishTrace 🔍
### Explainable Phishing URL Detection and Robustness Testing

PhishTrace is a web-based project designed to analyze URLs for potential phishing indicators, explain suspicious patterns, and evaluate how detection algorithms handle lookalike URLs and other variations.

The goal is to make phishing detection more **transparent, understandable, and measurable** instead of simply returning a result without explaining why.

> **Project status:** Under development. The Flask backend foundation and Python–C++ bridge foundation are implemented. Integration with the actual C++ detection engine and the complete end-to-end detection workflow are pending.

---

## 🎯 Problem Statement

Phishing URLs are often designed to imitate legitimate websites using misleading words, suspicious URL structures, and lookalike domain names. Basic detection methods can miss these patterns or provide little explanation for their decisions.

PhishTrace aims to address this problem by combining data structures and algorithms with an explainable web interface and a reproducible evaluation process.

## 💡 Proposed Solution

PhishTrace is designed to:

- Accept and validate a URL submitted by the user.
- Normalize the URL and extract relevant lexical features.
- Analyze suspicious patterns using a C++ detection engine.
- Use a **Trie** for pattern matching.
- Use hash-table lookups for known, verified URL or domain entries.
- Apply restricted Damerau–Levenshtein (Optimal String Alignment) distance to identify potential lookalike strings.
- Display evidence explaining why a URL received a particular assessment.
- Evaluate detection performance using metrics such as precision, recall, F1-score, false-positive rate, and execution time.
- Test detection robustness against URL variations.

These are the intended capabilities; individual features will be marked complete only after implementation and testing.

## ⚙️ Technology Stack

| Component | Technology |
|---|---|
| Backend API | Python, Flask |
| Detection engine | C++17 |
| Data structures and algorithms | Trie, hash tables, string-distance matching |
| Database | SQLite |
| Frontend | HTML, CSS, JavaScript |
| Data exchange | JSON over standard input/output and HTTP APIs |
| Testing | pytest |
| Build system for C++ | CMake |
| JSON library for C++ | nlohmann/json |

The project is designed to use free and open-source tools wherever practical.

## 🔄 How It Works

1. **URL submission:** The user submits a URL through the web interface.
2. **Validation:** The backend validates and normalizes the input.
3. **Feature extraction:** Relevant lexical features are extracted without opening the submitted website.
4. **Algorithmic analysis:** The Python backend is intended to pass a structured JSON request to the C++ detection engine.
5. **Evidence collection:** The engine returns matching patterns, known-entry lookup results, and lookalike analysis.
6. **Assessment:** The backend combines the available evidence and reports an appropriate result.
7. **Explanation:** The frontend presents the assessment and its supporting evidence.
8. **Evaluation:** A separate evaluation workflow measures performance against a labeled dataset.

**Important:** A URL with no detected indicators is not automatically considered safe. If the engine fails or cannot assess the URL, the system should report that the result is unavailable rather than inventing a classification.

## 🧠 Data Structures and Algorithms

### 1. Trie-based pattern matching
A Trie stores patterns in a prefix-based structure and supports efficient matching of relevant URL tokens.

### 2. Hash-table lookup
Hash tables support efficient exact lookups against known, verified entries in the project's reference data.

### 3. Damerau–Levenshtein / OSA distance
String-distance analysis helps identify potential lookalike names, such as small character changes that may imitate a legitimate domain.

These algorithms provide complementary evidence. A matching pattern or similar string alone does not prove that a URL is malicious.

## 🛡️ Security and Responsible Analysis

PhishTrace is designed with the following principles:

- Never automatically visit submitted URLs during lexical analysis.
- Do not make DNS or HTTP requests to submitted URLs as part of the scanning workflow.
- Validate inputs and handle malformed URLs safely.
- Execute the C++ engine using a controlled subprocess interface without shell command concatenation.
- Apply execution timeouts and handle engine failures gracefully.
- Keep sensitive information out of logs.
- Preserve dataset provenance and document labeling limitations.
- Never claim a URL is safe solely because no known indicator matched.
- Do not fabricate detection results, benchmark scores, or dataset statistics.

PhishTrace is an educational and research project. Its assessments should not be treated as a guarantee that a URL is safe or malicious.

## 📊 Evaluation

The planned evaluation will use a labeled dataset and report relevant classification metrics:

- **Precision:** How often predicted phishing URLs are actually phishing.
- **Recall:** How many phishing URLs are correctly identified.
- **F1-score:** The harmonic mean of precision and recall.
- **False-positive rate:** How often legitimate URLs are incorrectly flagged.
- **Execution time:** The time required to process a request under documented test conditions.

Actual values will be reported only after the evaluation has been implemented and run. Dataset composition, labeling methods, and limitations should accompany the results.

## 🏗️ Project Structure

The repository is organized around the following components. The exact structure may evolve as implementation progresses.

```text
PhishTrace/
├── PhishTrace_Backend/
│   ├── backend/
│   │   ├── routes/
│   │   ├── services/
│   │   ├── tests/
│   │   └── ...
│   ├── docs/
│   │   └── DSA_ENGINE_INTERFACE.md
│   ├── requirements.txt
│   ├── .env.example
│   └── ...
└── README.md
```

The frontend, dataset pipeline, and C++ engine will be integrated as their respective components are developed. Consult the current repository for the latest file layout.

## 🚀 Getting Started

### Prerequisites

- Python and `pip`
- Git
- A C++17-compatible compiler and CMake when building the detection engine
- A modern web browser

### 1. Clone the repository

```bash
git clone https://github.com/07mickey/PhishTrace.git
cd PhishTrace
```

### 2. Navigate to the backend

```bash
cd PhishTrace_Backend
```

### 3. Create a virtual environment

**macOS / Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows PowerShell:**

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 5. Configure environment variables

Review `.env.example` and configure any required settings using the project's documented configuration process. Never commit secrets or a local `.env` file.

### 6. Run the tests

```bash
python -m pytest
```

### 7. Run the backend

Use the Flask application entry point and startup instructions documented in the current backend files. The exact command may depend on the configured entry point and environment.

**Current limitation:** The Python–C++ bridge foundation is implemented, but the actual C++ detection executable is not yet integrated into the scanning workflow. Until that integration is complete, a successful backend startup does not mean full phishing detection is operational.

## 👥 Team Contributions

PhishTrace is being developed collaboratively by four members.

| Member | Responsibility |
|---|---|
| Member 1 | Frontend development and integration with backend APIs |
| Member 2 | Flask backend, input validation, feature extraction, Python–C++ integration, API testing, and security |
| Member 3 | Dataset research, data cleaning, database support, provenance, and data validation |
| Member 4 | C++ detection algorithms, Trie and hash-table implementation, lookalike matching, and algorithm evaluation |

Responsibilities may be adjusted as the team coordinates component interfaces and integration.

## 🗺️ Development Roadmap

- [x] Initialize the GitHub repository and backend foundation.
- [x] Implement initial Flask API structure and URL-processing services.
- [x] Add backend tests and error handling.
- [x] Define the Python–C++ engine interface.
- [x] Implement the Python–C++ bridge foundation and mocked failure-handling tests.
- [ ] Implement the C++ detection engine.
- [ ] Build and validate the dataset pipeline.
- [ ] Complete database and evaluation-data integration.
- [ ] Connect the actual engine to the scanning API.
- [ ] Integrate the frontend with the backend.
- [ ] Run end-to-end tests and evaluate detection performance.
- [ ] Document limitations and prepare the final demonstration.

## ⚠️ Limitations

- Known-entry detection depends on the quality, freshness, and coverage of the reference data.
- Lexical analysis cannot establish the real-time reputation or behavior of a website.
- Lookalike similarity can produce false positives and false negatives.
- Domain parsing and public-suffix handling have limitations that must be documented.
- Detection performance cannot be established until the engine and evaluation workflow are operational.
- The absence of a match does not establish that a URL is legitimate.

## 🔮 Future Improvements

Potential future improvements include better dataset refresh workflows, expanded domain parsing, additional explainable features, larger reproducible evaluation sets, and carefully validated detection methods beyond the initial algorithmic MVP.

Any future addition will depend on project scope, evidence of usefulness, and available development time.

## 📚 Documentation

Refer to the backend documentation for implementation details, configuration, testing, and the C++ integration contract.

- [Repository](https://github.com/07mickey/PhishTrace)
- `PhishTrace_Backend/docs/DSA_ENGINE_INTERFACE.md` — Python–C++ interface contract
- `PhishTrace_Backend/` — Backend source code and tests

## 🤝 Contributing

This is a collaborative academic project. Contributors should:

1. Work on feature branches rather than directly on `main`.
2. Follow the agreed API and data contracts.
3. Add or update tests when changing behavior.
4. Run the test suite before opening a pull request.
5. Review staged changes and avoid committing secrets, virtual environments, local databases, or generated artifacts.
6. Document known limitations and avoid unsupported performance claims.

## 📄 Disclaimer

PhishTrace is intended for educational and research purposes. It is not a substitute for professional security tools, browser protections, or independent verification of a website.

---

**PhishTrace — Detect patterns. Explain evidence. Test robustness.**
