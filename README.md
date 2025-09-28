Safe Educational Project: Keylogger Detection + Consent-based Simulator
=======================================================================

IMPORTANT: This project is for **educational and defensive** purposes only.
It does NOT contain any malware or system-wide keylogging code. The included
"simulator" explicitly requires user consent and records only text you type
into the program while it runs — it does NOT hook into the OS or run in the background.

Contents:
- anti_keylogger_scan.py    : Defensive process-scanning tool (uses psutil).
- consensual_simulator.py   : A consent-first input monitor used to test detection.
- requirements.txt          : Python packages needed.
- LICENSE.txt               : Simple permissive license.
- README.md                 : This file.

Installation Guide
==================

## Prerequisites
- Python 3.7 or higher
- Administrator/root privileges (recommended for full scanner functionality)
- Windows, macOS, or Linux operating system

## Step-by-Step Installation

### Step 1: Download/Clone the Project
```bash
# If using git:
git clone https://github.com/KingAtomic7/keylogger_detection_safe_project.git
cd keylogger_detection_safe_project

# Or download and extract the ZIP file to your desired location
```

### Step 2: Navigate to Project Directory
```bash
cd keylogger_detection_safe_project
```

### Step 3: Create Python Virtual Environment
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows (PowerShell):
venv\Scripts\Activate.ps1

# On Windows (Command Prompt):
venv\Scripts\activate.bat

# On macOS/Linux:
source venv/bin/activate
```

### Step 4: Upgrade pip (Recommended)
```bash
python -m pip install --upgrade pip
```

### Step 5: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 6: Verify Installation
```bash
python --version
pip list
```

## Usage Instructions

### Running the Defensive Scanner
```bash
# Run as regular user (limited visibility)
python anti_keylogger_scan.py

# Run as administrator/root for full visibility (recommended)
# Windows: Right-click PowerShell/CMD → "Run as administrator"
# Linux/macOS: sudo python anti_keylogger_scan.py
```

### Running the Consent-Based Simulator (Optional)
```bash
python consensual_simulator.py
# Type 'I CONSENT' when prompted to begin simulation
# Type '/exit' to stop the simulator
```

## Troubleshooting

### Common Issues:
- **Permission Denied**: Run as administrator/root for full process visibility
- **Module Not Found**: Ensure virtual environment is activated
- **psutil Installation Failed**: Try `pip install --upgrade pip` first

### Deactivating Virtual Environment
```bash
deactivate
```

Notes for instructors / lab creators
----------------------------------
- Use the simulator inside isolated VMs or lab environments when teaching.
- The goal of this project is to let students practice detection, triage, and
  forensic collection in a controlled, ethical manner.

