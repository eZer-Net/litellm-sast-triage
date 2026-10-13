import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sast_triage.cli.main import resolve_project, select_range, ask_value

class CliTests(unittest.TestCase):
    def test_explicit_project(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.assertEqual(resolve_project(root, str(root)), root.resolve())
    def test_project_required(self):
        with self.assertRaisesRegex(ValueError,'Specify project'):
            resolve_project(Path.cwd(), '')
    def test_scan_relative_to_project(self):
        from sast_triage.cli.main import resolve_scan
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve()
            self.assertEqual(resolve_scan(root,'scan-all.json'),root/'scan-all.json')
            self.assertEqual(resolve_scan(root,'results/sast.json'),root/'results/sast.json')
            with self.assertRaises(ValueError):resolve_scan(root,'../outside.json')
            with self.assertRaises(ValueError):resolve_scan(root,'/tmp/outside.json')
    def test_noninteractive_default_range(self):
        with patch('sys.stdin.isatty',return_value=False):
            self.assertEqual(select_range(21,None,None),(1,21))
            self.assertEqual(ask_value('Name','triage-result'),'triage-result')
    def test_explicit_range_and_validation(self):
        self.assertEqual(select_range(21,3,8),(3,8))
        with self.assertRaises(ValueError):select_range(21,9,2)
    def test_interactive_flow(self):
        with patch('sys.stdin.isatty',return_value=True),patch('builtins.input',side_effect=['2','3','7']):
            self.assertEqual(select_range(21,None,None),(3,7))

if __name__=='__main__':unittest.main()
