from __future__ import annotations

import io
import unittest

from netscan.progress import ProgressReporter
from netscan.progress_state import ProgressState


class ProgressTests(unittest.TestCase):
    def test_progress_reporter_prints_phase_and_counts(self) -> None:
        stream = io.StringIO()
        reporter = ProgressReporter(stream=stream, interval=0.001)
        reporter.start_phase("testing", 3, found=0)
        reporter.advance(found=1)
        reporter.finish_phase(found=1)
        output = stream.getvalue()
        self.assertIn("testing", output)
        self.assertIn("3/3", output)
        self.assertIn("found=1", output)

    def test_progress_state_serializes_snapshot(self) -> None:
        state = ProgressState()
        state.start_phase("phase", 2, live=0)
        state.advance(live=1)
        snapshot = state.to_dict()
        self.assertEqual(snapshot["phase"], "phase")
        self.assertEqual(snapshot["done"], 1)
        self.assertEqual(snapshot["details"]["live"], 1)
