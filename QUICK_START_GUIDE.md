# Quick‑Start Guide for LLM Red‑Team Framework

This guide walks you through setting up the project, installing dependencies, and running the framework in both **mock** and **live** modes.

---

## 1️⃣ Setup the virtual environment
```powershell
# From the project root
python -m venv venv
# Allow script execution for this session (required on Windows PowerShell)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
# Activate the environment
.\venv\Scripts\Activate.ps1
```

## 2️⃣ Install required packages
```powershell
pip install -r requirements.txt
```
> The `requirements.txt` includes `python-dotenv`, `google-genai`, `pydantic`, `rich`, and testing tools.

## 3️⃣ Run in **mock** mode (fast local validation)
```powershell
python main.py --mock
```
- All payloads are exercised against a simulated Gemini response.
- Expected outcome: every payload **PASS**.

## 4️⃣ Simulate vulnerabilities (to see detection in action)
```powershell
python main.py --mock --simulate-vulnerable
```
- The framework will deliberately leak the canary values, showing the OWASP categories they trigger.

## 5️⃣ Enforce strict CI behavior
```powershell
python main.py --mock --simulate-vulnerable --strict
```
- The process exits with a non‑zero code if any vulnerability is found, suitable for CI pipelines.

## 6️⃣ Run against the real Gemini API
1. Create a `.env` file at the project root containing your API key:
```
GEMINI_API_KEY=your_real_key_here
```
2. Execute the script without `--mock`:
```powershell
python main.py
```
- The same block‑reason handling and centralized canary detection apply to live responses.

---

**Key improvements**
- **Accurate block‑reason detection** – now checks the enum name (`block_reason.name`) to catch all non‑`NONE` block reasons, including `BLOCKED_REASON_UNSPECIFIED`.
- **Centralised canary handling** – all secret canaries live in `constants.ALL_CANARIES`; they are injected into the system prompt and scanned in every response.

You can refer to the main `README.md` for deeper documentation and contribution guidelines.
