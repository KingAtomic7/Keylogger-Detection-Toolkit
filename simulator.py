"""
simulator.py — Consent-gated input recorder.

This is NOT a system-wide keylogger.
It records only text the user explicitly types into this program
while it is running and ONLY after they give informed, typed consent.

Use case: test that the scanner actually detects log-writing activity.
"""

import time
import pathlib
import sys

DEFAULT_LOGFILE = pathlib.Path(__file__).parent.parent / "logs" / "consensual_simulator_log.txt"

CONSENT_PHRASE = "I CONSENT"
EXIT_COMMAND   = "/exit"
HELP_COMMAND   = "/help"

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║          CONSENT-BASED INPUT SIMULATOR  v2.0                ║
║          For educational / detection-testing use only        ║
╠══════════════════════════════════════════════════════════════╣
║  • This program records text YOU type into THIS terminal.    ║
║  • It does NOT capture system-wide keystrokes.               ║
║  • It does NOT run in the background.                        ║
║  • Logs are saved locally; nothing leaves this machine.      ║
╚══════════════════════════════════════════════════════════════╝
"""

CONSENT_PROMPT = (
    "\nThis simulator will record lines you type after consent.\n"
    "It is purely for testing detection tools in a controlled environment.\n\n"
    f"  Type '{CONSENT_PHRASE}' (exactly) to proceed.\n"
    "  Type anything else to abort safely.\n\n"
    "Your choice: "
)


def _prompt_consent() -> bool:
    print(BANNER)
    response = input(CONSENT_PROMPT).strip()
    return response == CONSENT_PHRASE


def run(logfile: pathlib.Path | None = None, quiet: bool = False) -> None:
    """
    Interactive consent-first simulator.

    Args:
        logfile: Path to write log entries. Defaults to DEFAULT_LOGFILE.
        quiet:   Suppress most print output (used in tests).
    """
    if not _prompt_consent():
        print("\nConsent not given. Exiting safely — no data recorded.")
        return

    logfile = logfile or DEFAULT_LOGFILE
    logfile.parent.mkdir(parents=True, exist_ok=True)

    if not quiet:
        print(f"\n✔  Consent received.")
        print(f"   Log file : {logfile}")
        print(f"   Commands : '{EXIT_COMMAND}' to quit | '{HELP_COMMAND}' for help\n")
        print("─" * 62)

    session_start = time.asctime()
    line_count    = 0

    with logfile.open("a", encoding="utf-8") as fh:
        fh.write(f"\n{'─'*60}\n")
        fh.write(f"SESSION START: {session_start}\n")
        fh.write(f"{'─'*60}\n")

        while True:
            try:
                line = input("sim> ")
            except (EOFError, KeyboardInterrupt):
                if not quiet:
                    print("\nInterrupted. Ending session.")
                break

            stripped = line.strip()

            if stripped == EXIT_COMMAND:
                if not quiet:
                    print("Session ended by user.")
                break

            if stripped == HELP_COMMAND:
                if not quiet:
                    print(f"  {EXIT_COMMAND}  — end the session")
                    print(f"  {HELP_COMMAND}  — show this message")
                continue

            # Record the line
            timestamp = time.strftime("%H:%M:%S")
            fh.write(f"[{timestamp}] {line}\n")
            fh.flush()
            line_count += 1

            if not quiet:
                print(f"  (recorded — line {line_count})")

        fh.write(f"SESSION END  : {time.asctime()}  |  {line_count} line(s)\n")

    if not quiet:
        print(f"\n─" * 62)
        print(f"  {line_count} line(s) recorded → {logfile}")
