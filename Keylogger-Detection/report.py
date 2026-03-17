"""
report.py — Terminal and JSON reporting for scan results.
"""

import json
import datetime
import platform
import pathlib
import sys

# ── Colour helpers (no external deps) ────────────────────────────────────────

_ANSI = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _ANSI else text

def red(t):     return _c("31;1", t)
def yellow(t):  return _c("33;1", t)
def green(t):   return _c("32;1", t)
def cyan(t):    return _c("36;1", t)
def white(t):   return _c("97;1", t)
def dim(t):     return _c("2",    t)
def bold(t):    return _c("1",    t)

SEV_COLOUR = {
    "HIGH":   red,
    "MEDIUM": yellow,
    "LOW":    cyan,
    "CLEAN":  green,
}

SEV_ICON = {
    "HIGH":   "🔴",
    "MEDIUM": "🟡",
    "LOW":    "🔵",
    "CLEAN":  "🟢",
}

# ── Terminal report ───────────────────────────────────────────────────────────

HEADER = r"""
  ██╗  ██╗███████╗██╗   ██╗██╗      ██████╗  ██████╗  ██████╗ ███████╗██████╗
  ██║ ██╔╝██╔════╝╚██╗ ██╔╝██║     ██╔═══██╗██╔════╝ ██╔════╝ ██╔════╝██╔══██╗
  █████╔╝ █████╗   ╚████╔╝ ██║     ██║   ██║██║  ███╗██║  ███╗█████╗  ██████╔╝
  ██╔═██╗ ██╔══╝    ╚██╔╝  ██║     ██║   ██║██║   ██║██║   ██║██╔══╝  ██╔══██╗
  ██║  ██╗███████╗   ██║   ███████╗╚██████╔╝╚██████╔╝╚██████╔╝███████╗██║  ██║
  ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝
            DETECTION TOOLKIT  v2.0  //  Educational & Defensive Use Only
"""

def _divider(char="─", width=68):
    return dim(char * width)


def print_header():
    print(red(HEADER))


def print_scan_header(threshold: int):
    now = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    os_  = platform.system()
    node = platform.node()
    print(_divider("═"))
    print(f"  {bold('SCAN START')}   {dim(now)}")
    print(f"  Platform  :  {os_} / {node}")
    print(f"  Threshold :  score ≥ {threshold}")
    print(_divider("═"))
    print()


def print_result(entry: dict, index: int):
    info     = entry["info"]
    score    = entry["score"]
    severity = entry["severity"]
    reasons  = entry["reasons"]
    colour   = SEV_COLOUR.get(severity, white)
    icon     = SEV_ICON.get(severity, "⚪")

    pid  = info.get("pid",  "?")
    name = info.get("name", "unknown")
    exe  = info.get("exe")  or dim("(exe unavailable)")
    cmd  = info.get("cmdline") or dim("(cmdline unavailable)")
    user = info.get("username") or dim("(unknown user)")
    ppid = info.get("ppid") or "?"
    ct   = info.get("create_time") or "?"

    print(f"  {icon}  {colour(f'[{severity}]')}  {white(name)}  {dim(f'PID {pid}')}  score={colour(str(score))}")
    print(f"     exe     : {exe}")
    print(f"     cmdline : {cmd}")
    print(f"     user    : {user}  │  ppid: {ppid}  │  started: {ct}")

    if info.get("open_files"):
        sample = info["open_files"][:3]
        more   = len(info["open_files"]) - 3
        print(f"     files   : {sample}" + (f"  …+{more}" if more > 0 else ""))

    if info.get("connections"):
        print(f"     network : {info['connections'][:2]}")

    print(f"     {bold('reasons')} :")
    for r in reasons:
        print(f"       {red('▸')} {r}")

    print(_divider())


def print_scan_summary(results: list[dict], elapsed: float):
    high   = sum(1 for r in results if r["severity"] == "HIGH")
    medium = sum(1 for r in results if r["severity"] == "MEDIUM")
    low    = sum(1 for r in results if r["severity"] == "LOW")

    print()
    print(_divider("═"))
    print(f"  {bold('SCAN COMPLETE')}  ({elapsed:.2f}s)")
    print(_divider())
    if not results:
        print(f"  {green('✔')}  No suspicious processes found above threshold.")
    else:
        print(f"  Total flagged : {white(str(len(results)))}")
        if high:   print(f"    {red('HIGH')}   : {high}")
        if medium: print(f"    {yellow('MEDIUM')} : {medium}")
        if low:    print(f"    {cyan('LOW')}    : {low}")
    print()
    print(f"  {dim('NOTE: Heuristic scanning may produce false positives.')}")
    print(f"  {dim('Always investigate before taking action.')}")
    print(_divider("═"))
    print()


def save_json(results: list[dict], path: pathlib.Path) -> None:
    """Write results to a JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "scan_time": datetime.datetime.now().isoformat(),
        "platform":  platform.system(),
        "results":   results,
    }
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    print(f"  {green('✔')}  JSON report saved → {path}")
