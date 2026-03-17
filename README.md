# Keylogger Detection Toolkit v2.0

> **Educational & Defensive Use Only** — No malware, no system-wide hooks, no background processes.

A clean, well-structured Python toolkit for learning how keylogger detection works, practicing defensive process analysis, and testing detection setups in a controlled, consent-first environment.

---

## Contents

```
keylogger_detection/
├── keylogger_detection/
│   ├── __init__.py        — Package metadata
│   ├── __main__.py        — python -m keylogger_detection entry point
│   ├── cli.py             — Unified CLI (argparse)
│   ├── scanner.py         — Heuristic process scanner
│   ├── simulator.py       — Consent-gated input recorder
│   └── report.py          — Terminal & JSON reporting
├── tests/
│   ├── test_scanner.py    — Scanner unit tests (mocked processes)
│   ├── test_report.py     — Report module tests
│   └── test_simulator.py  — Simulator consent & recording tests
├── logs/                  — Output directory (auto-created)
├── pyproject.toml         — Build & project config
├── requirements.txt       — Runtime dependencies
└── README.md              — This file
```

---

## Installation

### Prerequisites
- Python 3.10+
- pip
- Admin / root privileges **recommended** (for full process visibility)

### Steps

```bash
# 1. Clone or unzip the project
git clone https://github.com/akashkumar/keylogger-detection.git
cd keylogger-detection

# 2. Create a virtual environment
python -m venv venv

# Activate (Linux / macOS)
source venv/bin/activate

# Activate (Windows PowerShell)
venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Install as a package
pip install -e .
```

---

## Usage

### 🔍 Scan — Heuristic Process Scanner

```bash
# Basic scan (threshold ≥ 30)
python -m keylogger_detection scan

# Raise threshold to reduce false positives
python -m keylogger_detection scan --threshold 50

# Save results to JSON
python -m keylogger_detection scan --json logs/scan_report.json

# Run as root for full visibility (Linux / macOS)
sudo python -m keylogger_detection scan

# Windows — run PowerShell as Administrator
python -m keylogger_detection scan
```

**Score bands:**

| Score | Severity | Meaning |
|-------|----------|---------|
| 0–29  | CLEAN    | No indicators found |
| 30–49 | LOW      | Minor indicators — likely false positive |
| 50–74 | MEDIUM   | Multiple indicators — investigate |
| 75+   | HIGH     | Strong signals — take action |

**Heuristics checked:**
- Process name contains suspicious keywords (keylog, hook, keystroke, spy, …)
- Executable running from temp/non-standard directory
- Command-line arguments contain suspicious keywords
- Loaded modules with hooking-related names
- Active network connections (possible exfiltration)
- Open log-like files or files in temp locations

---

### 🎭 Simulate — Consent-Based Input Recorder

Used to test whether your scanner or other tools catch log-writing activity.

```bash
python -m keylogger_detection simulate

# Custom log file location
python -m keylogger_detection simulate --logfile /path/to/test.log
```

**What it does:**
- Asks for explicit typed consent (`I CONSENT`) before recording anything
- Records only text you type into *this terminal* while the program is running
- Does **not** hook the OS keyboard API
- Does **not** run in the background
- Logs are saved locally — nothing leaves the machine
- Type `/exit` to end the session

---

## Running Tests

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run all tests
python -m pytest tests/ -v

# Run with coverage report
python -m pytest tests/ -v --cov=keylogger_detection --cov-report=term-missing

# Run a single test file
python -m pytest tests/test_scanner.py -v
```

---

## How Detection Works

The scanner applies a point-based heuristic scoring system:

| Indicator | Points |
|-----------|--------|
| Process name matches keyword | +50 |
| Executable in temp/suspicious dir | +30 |
| Loaded module with hook-related name | +30 |
| Command-line contains keyword | +20 |
| Active network connections | +15 |
| Open log-like file | +10 |
| Files open in temp locations | +10 |

Scores are cumulative. A process needs ≥ 30 points to be reported (adjustable with `--threshold`).

**False positives** are expected — tools like IDEs, browsers, and input method editors may score positive. Always investigate before taking action.

---

## Notes for Lab / Classroom Use

- Run the simulator inside an isolated VM or lab environment
- Use `simulate` to generate log-writing behaviour, then run `scan` to detect it
- Pair with tools like `ps`, `lsof`, `autoruns`, or `Process Explorer` for hands-on comparison
- This project intentionally omits any OS-level keyboard hooking APIs — it is purely defensive

---

## License

MIT — see `LICENSE.txt`

---

*"The quieter you become, the more you are able to hear." — Kali Linux*
