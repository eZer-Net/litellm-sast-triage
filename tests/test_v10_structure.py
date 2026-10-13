import unittest
from pathlib import Path
from sast_triage.providers.parsers import parse_command

class StructureTests(unittest.TestCase):
    def test_marked_tool_call(self):
        msg={"role":"assistant","content":"<|tool_call>call:read{\"arguments\":{\"path\":\"src/x.py\",\"line\":10}}<tool_call|>"}
        self.assertEqual(parse_command(msg)["action"],"read")
    def test_no_forced_fp(self):
        s=(Path(__file__).resolve().parents[1]/"src/sast_triage/core/triage.py").read_text()
        self.assertNotIn("Finalize FP only",s)

if __name__=='__main__':unittest.main()
