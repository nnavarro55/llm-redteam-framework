# LLM Red‑Team Framework

This is an automated security‑testing and auditing framework for large language models (LLMs). The tool sends adversarial payloads to a target LLM, evaluates the responses using a dual‑judge system (deterministic regex heuristics **plus** an LLM‑as‑a‑Judge), and maps any discovered vulnerabilities to the **OWASP Top 10 for LLM Applications**.

---

## 📚 Overview

- **Purpose:** Quickly discover prompt‑injection, information‑disclosure, agency‑escalation, XSS, and system‑prompt leakage bugs in LLM deployments.
- **Workflow:**
  1. Load a suite of adversarial payloads.
  2. Send each payload to the configured target model.
  3. Evaluate the response with two independent judges.
  4. Record results and map them to OWASP categories.

---

## ✨ Key Improvements (v2.0)

1. **Robust block‑reason handling** – `GeminiTarget.query` now inspects the enum name (`block_reason.name`) so every non‑`NONE`/`UNSPECIFIED` block reason (including `BLOCKED_REASON_UNSPECIFIED`) is correctly recognised.
2. **Centralised canary detection** – All secret canaries live in a single `ALL_CANARIES` list (defined in `constants.py`). The list is used both to inject canary values into the system prompt and to scan every model response before the regex heuristics. Any leak is reported with the appropriate OWASP category.

---

## ✅ Features

- **Dual‑judge evaluation** – deterministic regex + LLM‑as‑a‑Judge for high confidence.
- **OWASP Top 10 mapping** – each vulnerability is tied to a specific OWASP LLM category.
- **Mock mode** – run the full suite offline without an API key.
- **Strict CI mode** – exit with a non‑zero code when any vulnerability is found.
- **Extensible payload library** – easy to add new adversarial tests.

---

## 🚀 Installation

```powershell
# 1. Clone the repository (if you haven't already)
git clone https://github.com/nnavarro55/llm-redteam-framework.git
cd llm-redteam-framework

# 2. Create a virtual environment
python -m venv venv

# 3. Allow script execution for this PowerShell session (required on Windows)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# 4. Activate the environment
.\venv\Scripts\Activate.ps1

# 5. Install Python dependencies
pip install -r requirements.txt
```
> `requirements.txt` includes `python-dotenv`, `google‑genai`, `pydantic`, `rich`, and testing utilities.

---

## 🔧 Configuration

Create a `.env` file at the project root (copy from the example) and supply your Gemini API key:

```bash
cp .env.example .env
```

Edit `.env`:

```env
GEMINI_API_KEY=your_real_gemini_api_key_here
TARGET_MODEL=gemini-3.5-flash   # optional – defaults to the same value as JUDGE_MODEL
JUDGE_MODEL=gemini-3.5-flash    # optional – defaults to the same value as TARGET_MODEL
```

---

## 📖 Quick‑Start Guide

```powershell
# Run the full audit against the live Gemini API (requires .env)
python main.py

# Run offline using mock responses (no API key needed)
python main.py --mock

# Simulate vulnerable responses to see detection in action
python main.py --mock --simulate-vulnerable

# CI‑friendly mode – fails with exit code 1 on any vulnerability
python main.py --mock --simulate-vulnerable --strict
```

---

## 🛠️ Usage Details

| Option | Description |
|--------|-------------|
| `--mock` | Use built‑in mock responses – useful for CI and offline development. |
| `--simulate-vulnerable` | Force payloads to return clearly vulnerable responses (for testing error handling). |
| `--strict` | Exit with a non‑zero status if any payload is flagged as vulnerable or an error occurs. |
| `--category <OWASP_ID>` | Run only the payloads that map to the specified OWASP category (e.g., `LLM01`). |
| `--target-model <MODEL>` | Override the target model name.
| `--judge-model <MODEL>` | Override the judge model name.
| `--output <FILE>` | Write the audit report to a custom JSON file (default: `security_report.json`). |

---

## 🏗️ Project Architecture

- `schema.py` – Pydantic models for OWASP categories, payload definitions, test results, and the final audit report.
- `targets.py` – Abstract target interface and the concrete `GeminiTarget` implementation with safety‑guard interception.
- `payloads.py` – Library of adversarial test cases (prompt injection, data leakage, agency escalation, etc.).
- `evaluator.py` – Implements the dual‑judge evaluation pipeline.
- `main.py` – CLI entry point, orchestrates the audit, renders a Rich dashboard, and writes the JSON report.
- `constants.py` – Central location for canary tokens and other global constants.

---

## 🤝 Contributing

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/awesome‑feature`).
3. Install the development dependencies (`pip install -r requirements-dev.txt`).
4. Run the test suite (`pytest`).
5. Submit a Pull Request with a clear description of the change.

Please ensure new code follows the existing style and updates the documentation where appropriate.