"""
tests/test_simulator.py — Unit tests for the simulator module.

The simulator is interactive (requires stdin), so tests use mock inputs.
"""

import sys
import pathlib
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from keylogger_detection import simulator


class TestSimulatorConsent(unittest.TestCase):

    def test_no_consent_aborts(self):
        """Typing anything other than the consent phrase should abort."""
        with patch("builtins.input", return_value="no"):
            with tempfile.TemporaryDirectory() as tmpdir:
                logfile = pathlib.Path(tmpdir) / "sim.log"
                simulator.run(logfile=logfile, quiet=True)
                self.assertFalse(logfile.exists(), "Log should NOT be created if consent refused")

    def test_wrong_phrase_aborts(self):
        """Partial or differently-cased consent phrase must not pass."""
        for phrase in ("i consent", "I Consent", "CONSENT", "yes", ""):
            with patch("builtins.input", return_value=phrase):
                with tempfile.TemporaryDirectory() as tmpdir:
                    logfile = pathlib.Path(tmpdir) / "sim.log"
                    simulator.run(logfile=logfile, quiet=True)
                    self.assertFalse(logfile.exists(),
                                     f"Phrase '{phrase}' should not grant consent")

    def test_consent_creates_logfile(self):
        """Correct consent phrase + /exit should create the log file."""
        inputs = iter(["I CONSENT", "/exit"])
        with patch("builtins.input", side_effect=inputs):
            with tempfile.TemporaryDirectory() as tmpdir:
                logfile = pathlib.Path(tmpdir) / "sim.log"
                simulator.run(logfile=logfile, quiet=True)
                self.assertTrue(logfile.exists(), "Log file should be created after consent")

    def test_typed_lines_recorded(self):
        """Lines typed after consent should appear in the log."""
        inputs = iter(["I CONSENT", "hello world", "test line 2", "/exit"])
        with patch("builtins.input", side_effect=inputs):
            with tempfile.TemporaryDirectory() as tmpdir:
                logfile = pathlib.Path(tmpdir) / "sim.log"
                simulator.run(logfile=logfile, quiet=True)
                content = logfile.read_text(encoding="utf-8")
                self.assertIn("hello world", content)
                self.assertIn("test line 2", content)

    def test_exit_command_not_recorded(self):
        """/exit command itself should not appear as a recorded line."""
        inputs = iter(["I CONSENT", "real data", "/exit"])
        with patch("builtins.input", side_effect=inputs):
            with tempfile.TemporaryDirectory() as tmpdir:
                logfile = pathlib.Path(tmpdir) / "sim.log"
                simulator.run(logfile=logfile, quiet=True)
                content = logfile.read_text(encoding="utf-8")
                self.assertNotIn("/exit", content)

    def test_eof_ends_session_gracefully(self):
        """EOFError on input (e.g., piped empty stdin) should end cleanly."""
        def _inputs(prompt=""):
            if prompt == simulator.CONSENT_PROMPT:
                return "I CONSENT"
            raise EOFError

        with patch("builtins.input", side_effect=_inputs):
            with tempfile.TemporaryDirectory() as tmpdir:
                logfile = pathlib.Path(tmpdir) / "sim.log"
                try:
                    simulator.run(logfile=logfile, quiet=True)
                except EOFError:
                    self.fail("EOFError should be handled inside simulator.run()")


if __name__ == "__main__":
    unittest.main(verbosity=2)
