import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sast_triage.cli.main import choose_result_name, timestamped_result_name, unique_result_name, validate_result_name


class NamingTests(unittest.TestCase):
    def test_timestamp_is_readable_and_portable(self):
        dt = datetime(2026, 10, 13, 9, 14, 30)
        self.assertEqual(timestamped_result_name('triage-result-ai', dt), 'triage-result-ai-13.10.2026-09-14-30')

    def test_collision_checks_all_three_files(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root)
            (p / 'report.trace.jsonl').write_text('')
            (p / 'report-01.md').write_text('')
            self.assertEqual(unique_result_name(p, 'report'), 'report-02')

    def test_reject_nonportable_names(self):
        for bad in ['bad:name', 'bad/name', 'bad\\name', 'result.json', 'result.trace.jsonl', 'CON<foo', '../secret', 'bad.']:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                validate_result_name(bad)

    def test_flag_overrides_default(self):
        with tempfile.TemporaryDirectory() as root:
            args = SimpleNamespace(resultName='my-review', name=None)
            self.assertEqual(choose_result_name(args, {'RESULT_NAME': 'triage-result-ai'}, Path(root)), 'my-review')

    def test_automatic_noninteractive(self):
        with tempfile.TemporaryDirectory() as root, patch('sast_triage.cli.main.sys.stdin.isatty', return_value=False):
            args = SimpleNamespace(resultName=None, name=None)
            self.assertRegex(choose_result_name(args, {'RESULT_NAME': 'triage-result-ai'}, Path(root)), r'^triage-result-ai-\d{2}\.\d{2}\.\d{4}-\d{2}-\d{2}-\d{2}$')

    def test_interactive_custom(self):
        with tempfile.TemporaryDirectory() as root, patch('sast_triage.cli.main.sys.stdin.isatty', return_value=True), patch('sast_triage.cli.main.ask_value', side_effect=['y', 'team-report']):
            args = SimpleNamespace(resultName=None, name=None)
            self.assertEqual(choose_result_name(args, {'RESULT_NAME': 'triage-result-ai'}, Path(root)), 'team-report')


if __name__ == '__main__':
    unittest.main()
