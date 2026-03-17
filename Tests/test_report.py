"""
tests/test_report.py — Unit tests for the report module.
"""

import sys
import json
import pathlib
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from keylogger_detection import report


class TestReportHelpers(unittest.TestCase):

    def test_severity_colours_all_keys_present(self):
        for sev in ("HIGH", "MEDIUM", "LOW", "CLEAN"):
            self.assertIn(sev, report.SEV_COLOUR)
            self.assertIn(sev, report.SEV_ICON)

    def test_save_json_creates_file(self):
        results = [
            {
                "info":     {"pid": 1, "name": "test", "exe": "/bin/test",
                             "cmdline": None, "username": "u", "ppid": 0,
                             "status": "running", "create_time": None,
                             "open_files": [], "connections": [], "modules": [],
                             "environ_keys": []},
                "score":    55,
                "reasons":  ["Test reason"],
                "severity": "MEDIUM",
            }
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "test_report.json"
            report.save_json(results, path)
            self.assertTrue(path.exists())
            data = json.loads(path.read_text())
            self.assertIn("scan_time", data)
            self.assertIn("results", data)
            self.assertEqual(len(data["results"]), 1)

    def test_print_functions_dont_crash(self):
        """Smoke-test that all print functions run without exceptions."""
        entry = {
            "info": {
                "pid": 999, "name": "suspicious_proc",
                "exe": "/tmp/suspicious_proc",
                "cmdline": "/tmp/suspicious_proc --run",
                "username": "testuser", "ppid": 1,
                "status": "running", "create_time": "2025-01-01T00:00:00",
                "open_files": ["/tmp/keys.log"],
                "connections": [{"laddr": "0.0.0.0:0", "raddr": "1.2.3.4:80", "status": "ESTABLISHED"}],
                "modules": [],
                "environ_keys": [],
            },
            "score":    80,
            "reasons":  ["name matches keyword", "runs from /tmp"],
            "severity": "HIGH",
        }
        try:
            report.print_result(entry, 1)
            report.print_scan_summary([entry], elapsed=0.123)
        except Exception as e:
            self.fail(f"print function raised: {e}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
