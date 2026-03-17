"""
scanner.py — Heuristic keylogger detection via process analysis.

Defensive use only. Analyses running processes for behavioural
indicators associated with keylogging activity.
"""

import os
import sys
import platform
import pathlib
import datetime
import psutil

# ── Heuristic keyword sets ────────────────────────────────────────────────────

SUSPICIOUS_NAME_KEYWORDS = [
    "keylog", "keylogger", "keystroke", "hook", "keyboard",
    "logger", "klgr", "kgrab", "spy", "monitor", "sniff",
    "capture", "record", "inputcap",
]

SUSPICIOUS_PATH_DIRS = [
    os.getenv("TEMP") or "/tmp",
    "/tmp",
    os.path.expanduser("~/.cache"),
]
if platform.system() == "Windows":
    SUSPICIOUS_PATH_DIRS += [
        str(pathlib.Path.home() / "AppData" / "Local" / "Temp"),
        str(pathlib.Path.home() / "AppData" / "Roaming"),
        "C:\\Windows\\Temp",
    ]

# Known hook / injection DLLs (Windows-specific)
SUSPICIOUS_MODULES = [
    "setwindowshookex", "keybd_event", "sendinput",
    "hookkeyboard", "pynput", "keyboard.py",
]

# ── Process info gathering ────────────────────────────────────────────────────

def gather_process_info(proc: psutil.Process) -> dict:
    """Collect all available attributes for a process, suppressing errors."""
    info = {
        "pid":        proc.pid,
        "name":       None,
        "exe":        None,
        "cmdline":    None,
        "username":   None,
        "ppid":       None,
        "status":     None,
        "create_time": None,
        "open_files": [],
        "connections": [],
        "modules":    [],
        "environ_keys": [],
    }

    def _get(attr, *args, **kwargs):
        try:
            return getattr(proc, attr)(*args, **kwargs)
        except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError,
                NotImplementedError, Exception):
            return None

    info["name"]    = _get("name")
    info["exe"]     = _get("exe")
    info["status"]  = _get("status")
    info["username"] = _get("username")
    info["ppid"]    = _get("ppid")

    ct = _get("create_time")
    if ct:
        info["create_time"] = datetime.datetime.fromtimestamp(ct).isoformat(timespec="seconds")

    cmdline = _get("cmdline")
    info["cmdline"] = " ".join(cmdline) if cmdline else None

    files = _get("open_files")
    info["open_files"] = [f.path for f in files] if files else []

    conns = _get("connections", kind="inet")
    if conns:
        info["connections"] = [
            {"laddr": str(c.laddr), "raddr": str(c.raddr), "status": c.status}
            for c in conns
        ]

    maps = _get("memory_maps")
    if maps:
        info["modules"] = [m.path for m in maps if m.path]

    env = _get("environ")
    if env:
        info["environ_keys"] = list(env.keys())

    return info


# ── Scoring ───────────────────────────────────────────────────────────────────

def _name_hit(name: str | None) -> bool:
    if not name:
        return False
    lower = name.lower()
    return any(kw in lower for kw in SUSPICIOUS_NAME_KEYWORDS)


def _path_suspicious(path: str | None) -> bool:
    if not path:
        return False
    lower = path.lower()
    return any(d and d.lower() in lower for d in SUSPICIOUS_PATH_DIRS)


def score_process(info: dict) -> tuple[int, list[str]]:
    """
    Return (risk_score, [reason, ...]).

    Score bands:
      0–29   : Clean
      30–49  : Low suspicion
      50–74  : Medium suspicion  ← default report threshold
      75+    : High suspicion
    """
    score   = 0
    reasons = []

    name    = (info.get("name")    or "").lower()
    exe     = (info.get("exe")     or "").lower()
    cmdline = (info.get("cmdline") or "").lower()
    modules = [m.lower() for m in (info.get("modules") or []) if m]
    files   = [f.lower() for f in (info.get("open_files") or []) if f]
    conns   = info.get("connections") or []

    # ── Name match (strong indicator)
    if _name_hit(name):
        score += 50
        reasons.append(f"Process name matches suspicious keyword: '{name}'")

    # ── Executable in suspicious dir
    if _path_suspicious(exe):
        score += 30
        reasons.append(f"Executable located in suspicious directory: {exe}")

    # ── Command-line keyword
    if any(kw in cmdline for kw in SUSPICIOUS_NAME_KEYWORDS):
        score += 20
        reasons.append("Command-line arguments contain suspicious keyword")

    # ── Loaded module with hook-related name
    bad_mods = [m for m in modules if any(kw in m for kw in SUSPICIOUS_MODULES + SUSPICIOUS_NAME_KEYWORDS)]
    if bad_mods:
        score += 30
        reasons.append(f"Loaded {len(bad_mods)} suspicious module(s): {bad_mods[:2]}")

    # ── Outbound network connection (data exfil signal)
    if conns:
        score += 15
        reasons.append(f"Has {len(conns)} active network connection(s) — possible exfiltration")

    # ── Writing to temp/hidden file
    temp_files = [f for f in files if "/tmp" in f or "temp" in f or "\\tmp" in f]
    if temp_files:
        score += 10
        reasons.append(f"Writing to temp location(s): {temp_files[:2]}")

    # ── Log-file-like open file names
    log_files = [f for f in files if f.endswith(".log") or f.endswith(".txt") or "log" in f.split("/")[-1]]
    if log_files:
        score += 10
        reasons.append(f"Has open log-like file(s): {log_files[:2]}")

    return score, reasons


# ── Main scan ─────────────────────────────────────────────────────────────────

def scan(threshold: int = 30) -> list[dict]:
    """
    Enumerate all running processes and return those whose risk score
    meets or exceeds *threshold*.

    Returns a list of dicts sorted by score descending:
      { "info": {...}, "score": int, "reasons": [...], "severity": str }
    """
    results = []

    for proc in psutil.process_iter():
        try:
            info           = gather_process_info(proc)
            score, reasons = score_process(info)
            if score >= threshold:
                results.append({
                    "info":     info,
                    "score":    score,
                    "reasons":  reasons,
                    "severity": _severity(score),
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    results.sort(key=lambda x: x["score"], reverse=True)
    return results


def _severity(score: int) -> str:
    if score >= 75:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    if score >= 30:
        return "LOW"
    return "CLEAN"
