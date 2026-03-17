"""
tests/test_scanner.py — Unit tests for the scanner module.

Run with:  python -m pytest tests/ -v
       or: python -m pytest tests/ -v --tb=short
"""

import sys
import pathlib
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

# Ensure the package root is importable when running tests directly
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import psutil
from keylogger_detection import scanner


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_info(**kwargs) -> dict:
    """Return a minimal process-info dict, overridable with kwargs."""
    base = {
        "pid": 1234,
        "name": "normal_process",
        "exe": "/usr/bin/normal_process",
        "cmdline": "/usr/bin/normal_process --flag",
        "username": "user",
        "ppid": 1,
        "status": "running",
        "create_time": "2025-01-01T00:00:00",
        "open_files": [],
        "connections": [],
        "modules": [],
        "environ_keys": [],
    }
    base.update(kwargs)
    return base


# ── score_process tests ───────────────────────────────────────────────────────

class TestScoreProcess(unittest.TestCase):

    def test_clean_process_scores_zero(self):
        info = _make_info()
        score, reasons = scanner.score_process(info)
        self.assertEqual(score, 0)
        self.assertEqual(reasons, [])

    def test_name_keyword_keylogger_adds_50(self):
        info = _make_info(name="keylogger.exe")
        score, reasons = scanner.score_process(info)
        self.assertGreaterEqual(score, 50)
        self.assertTrue(any("name matches" in r.lower() for r in reasons))

    def test_name_keyword_keystroke(self):
        info = _make_info(name="keystroke_capture")
        score, _ = scanner.score_process(info)
        self.assertGreaterEqual(score, 50)

    def test_suspicious_exe_path_adds_score(self):
        info = _make_info(exe="/tmp/legit_looking_process")
        score, reasons = scanner.score_process(info)
        self.assertGreaterEqual(score, 30)
        self.assertTrue(any("directory" in r.lower() for r in reasons))

    def test_cmdline_keyword_adds_score(self):
        info = _make_info(cmdline="/usr/bin/python capture_keystrokes.py")
        score, reasons = scanner.score_process(info)
        self.assertGreaterEqual(score, 20)
        self.assertTrue(any("command-line" in r.lower() or "cmdline" in r.lower() for r in reasons))

    def test_network_connections_add_score(self):
        info = _make_info(connections=[
            {"laddr": "127.0.0.1:54321", "raddr": "1.2.3.4:443", "status": "ESTABLISHED"}
        ])
        score, reasons = scanner.score_process(info)
        self.assertGreaterEqual(score, 15)
        self.assertTrue(any("network" in r.lower() for r in reasons))

    def test_log_file_open_adds_score(self):
        info = _make_info(open_files=["/home/user/.config/output.log"])
        score, reasons = scanner.score_process(info)
        self.assertGreaterEqual(score, 10)
        self.assertTrue(any("log" in r.lower() for r in reasons))

    def test_temp_file_adds_score(self):
        info = _make_info(open_files=["/tmp/data.bin"])
        score, reasons = scanner.score_process(info)
        self.assertGreaterEqual(score, 10)

    def test_multiple_indicators_cumulative(self):
        info = _make_info(
            name="keylogger",
            exe="/tmp/keylogger",
            connections=[{"laddr": "x", "raddr": "y", "status": "ESTABLISHED"}],
        )
        score, _ = scanner.score_process(info)
        self.assertGreaterEqual(score, 75)  # HIGH tier

    def test_none_fields_dont_crash(self):
        info = _make_info(name=None, exe=None, cmdline=None, modules=None,
                          open_files=None, connections=None)
        score, reasons = scanner.score_process(info)
        self.assertIsInstance(score, int)
        self.assertIsInstance(reasons, list)


# ── severity tests ────────────────────────────────────────────────────────────

class TestSeverity(unittest.TestCase):

    def test_clean(self):
        self.assertEqual(scanner._severity(0), "CLEAN")
        self.assertEqual(scanner._severity(29), "CLEAN")

    def test_low(self):
        self.assertEqual(scanner._severity(30), "LOW")
        self.assertEqual(scanner._severity(49), "LOW")

    def test_medium(self):
        self.assertEqual(scanner._severity(50), "MEDIUM")
        self.assertEqual(scanner._severity(74), "MEDIUM")

    def test_high(self):
        self.assertEqual(scanner._severity(75), "HIGH")
        self.assertEqual(scanner._severity(200), "HIGH")


# ── gather_process_info tests ─────────────────────────────────────────────────

class TestGatherProcessInfo(unittest.TestCase):

    def _mock_proc(self, **overrides):
        proc = MagicMock(spec=psutil.Process)
        proc.pid = overrides.get("pid", 999)
        proc.name.return_value = overrides.get("name", "test_proc")
        proc.exe.return_value  = overrides.get("exe", "/usr/bin/test_proc")
        proc.cmdline.return_value = overrides.get("cmdline", ["/usr/bin/test_proc"])
        proc.username.return_value = overrides.get("username", "testuser")
        proc.ppid.return_value  = overrides.get("ppid", 1)
        proc.status.return_value = overrides.get("status", "running")
        proc.create_time.return_value = 1700000000.0
        proc.open_files.return_value  = []
        proc.connections.return_value = []
        proc.memory_maps.return_value = []
        proc.environ.return_value = {}
        return proc

    def test_basic_fields_populated(self):
        proc = self._mock_proc(name="myproc", pid=42)
        info = scanner.gather_process_info(proc)
        self.assertEqual(info["pid"],  42)
        self.assertEqual(info["name"], "myproc")

    def test_access_denied_returns_none_fields(self):
        proc = MagicMock(spec=psutil.Process)
        proc.pid = 1
        for attr in ("name", "exe", "cmdline", "username", "ppid",
                     "status", "create_time", "open_files",
                     "connections", "memory_maps", "environ"):
            getattr(proc, attr).side_effect = psutil.AccessDenied(pid=1)
        info = scanner.gather_process_info(proc)
        self.assertIsNone(info["name"])
        self.assertEqual(info["open_files"], [])


# ── scan integration test (mocked process list) ───────────────────────────────

class TestScanIntegration(unittest.TestCase):

    @patch("keylogger_detection.scanner.psutil.process_iter")
    def test_scan_returns_flagged_process(self, mock_iter):
        proc = MagicMock(spec=psutil.Process)
        proc.pid = 666
        proc.name.return_value    = "keylogger_evil"
        proc.exe.return_value     = "/tmp/keylogger_evil"
        proc.cmdline.return_value = ["/tmp/keylogger_evil"]
        proc.username.return_value = "hacker"
        proc.ppid.return_value    = 1
        proc.status.return_value  = "running"
        proc.create_time.return_value = 1700000000.0
        proc.open_files.return_value  = []
        proc.connections.return_value = []
        proc.memory_maps.return_value = []
        proc.environ.return_value = {}
        mock_iter.return_value = [proc]

        results = scanner.scan(threshold=30)
        self.assertGreaterEqual(len(results), 1)
        self.assertEqual(results[0]["info"]["name"], "keylogger_evil")
        self.assertGreaterEqual(results[0]["score"], 50)

    @patch("keylogger_detection.scanner.psutil.process_iter")
    def test_scan_skips_clean_process(self, mock_iter):
        proc = MagicMock(spec=psutil.Process)
        proc.pid = 100
        proc.name.return_value    = "systemd"
        proc.exe.return_value     = "/usr/lib/systemd/systemd"
        proc.cmdline.return_value = ["/usr/lib/systemd/systemd"]
        proc.username.return_value = "root"
        proc.ppid.return_value    = 0
        proc.status.return_value  = "running"
        proc.create_time.return_value = 1700000000.0
        proc.open_files.return_value  = []
        proc.connections.return_value = []
        proc.memory_maps.return_value = []
        proc.environ.return_value = {}
        mock_iter.return_value = [proc]

        results = scanner.scan(threshold=30)
        self.assertEqual(results, [])

    @patch("keylogger_detection.scanner.psutil.process_iter")
    def test_scan_handles_no_such_process(self, mock_iter):
        proc = MagicMock(spec=psutil.Process)
        proc.pid = 200
        proc.name.side_effect = psutil.NoSuchProcess(pid=200)
        mock_iter.return_value = [proc]
        # Should not raise
        results = scanner.scan(threshold=30)
        self.assertIsInstance(results, list)

    @patch("keylogger_detection.scanner.psutil.process_iter")
    def test_scan_results_sorted_by_score_desc(self, mock_iter):
        def _make(pid, name, exe):
            p = MagicMock(spec=psutil.Process)
            p.pid = pid
            p.name.return_value = name
            p.exe.return_value  = exe
            p.cmdline.return_value = [exe]
            p.username.return_value = "u"
            p.ppid.return_value = 1
            p.status.return_value = "running"
            p.create_time.return_value = 1700000000.0
            p.open_files.return_value  = []
            p.connections.return_value = []
            p.memory_maps.return_value = []
            p.environ.return_value = {}
            return p

        mock_iter.return_value = [
            _make(1, "hook_tool", "/tmp/hook_tool"),   # high score: name + path
            _make(2, "keylogger", "/usr/bin/keylogger"), # high score: name only
        ]
        results = scanner.scan(threshold=30)
        scores = [r["score"] for r in results]
        self.assertEqual(scores, sorted(scores, reverse=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
