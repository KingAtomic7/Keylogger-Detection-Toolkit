"""
cli.py — Unified command-line interface for the Keylogger Detection Toolkit.

Usage:
    python -m keylogger_detection scan    [--threshold N] [--json PATH] [--all]
    python -m keylogger_detection simulate [--logfile PATH] [--quiet]
    python -m keylogger_detection --version
    python -m keylogger_detection --help
"""

import argparse
import sys
import time
import pathlib

from keylogger_detection import __version__
from keylogger_detection import scanner, report


def cmd_scan(args: argparse.Namespace) -> None:
    threshold = args.threshold

    report.print_header()
    report.print_scan_header(threshold)

    t0 = time.perf_counter()
    results = scanner.scan(threshold=threshold)
    elapsed = time.perf_counter() - t0

    if not results:
        report.print_scan_summary([], elapsed)
        return

    print(f"  Found {len(results)} process(es) above threshold:\n")
    for i, entry in enumerate(results, 1):
        report.print_result(entry, i)

    report.print_scan_summary(results, elapsed)

    if args.json:
        json_path = pathlib.Path(args.json)
        report.save_json(results, json_path)


def cmd_simulate(args: argparse.Namespace) -> None:
    from keylogger_detection import simulator

    logfile = pathlib.Path(args.logfile) if args.logfile else None
    simulator.run(logfile=logfile, quiet=args.quiet)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keylogger_detection",
        description=(
            "Keylogger Detection Toolkit v{} — Educational & Defensive Use Only\n"
            "Scan running processes for keylogger-like behaviour, or run a\n"
            "consent-based simulator to test your detection setup."
        ).format(__version__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m keylogger_detection scan\n"
            "  python -m keylogger_detection scan --threshold 50 --json logs/report.json\n"
            "  python -m keylogger_detection simulate\n"
            "  sudo python -m keylogger_detection scan   # full visibility on Linux/macOS\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # ── scan ──────────────────────────────────────────────────────────────────
    p_scan = sub.add_parser(
        "scan",
        help="Run the heuristic process scanner",
        description="Scan all running processes for keylogger indicators.",
    )
    p_scan.add_argument(
        "--threshold", "-t",
        type=int,
        default=30,
        metavar="N",
        help="Minimum risk score to report (default: 30). Use 50+ for fewer false positives.",
    )
    p_scan.add_argument(
        "--json", "-j",
        metavar="PATH",
        help="Save results to a JSON file at PATH (e.g. logs/scan.json).",
    )
    p_scan.add_argument(
        "--all", "-a",
        action="store_true",
        help="Show all processes including those with score=0 (very verbose).",
    )
    p_scan.set_defaults(func=cmd_scan)

    # ── simulate ──────────────────────────────────────────────────────────────
    p_sim = sub.add_parser(
        "simulate",
        help="Run the consent-based input simulator",
        description=(
            "Runs a consent-gated input recorder for testing detection.\n"
            "This is NOT a system keylogger — it only records text you type\n"
            "into this terminal after you explicitly give consent."
        ),
    )
    p_sim.add_argument(
        "--logfile", "-l",
        metavar="PATH",
        help="Path to write simulated log (default: logs/consensual_simulator_log.txt).",
    )
    p_sim.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress informational output (for automated testing).",
    )
    p_sim.set_defaults(func=cmd_simulate)

    return parser


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n\nAborted by user.")
        sys.exit(0)
    except PermissionError:
        print(
            "\n[ERROR] Permission denied. Try running with administrator / root privileges:\n"
            "  sudo python -m keylogger_detection scan\n"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
