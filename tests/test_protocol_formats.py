import json
import unittest
from sast_triage.providers.parsers import parse_command, ProtocolError
from sast_triage.providers.request import build_payload
from sast_triage.providers.response import extract_message

class Formats(unittest.TestCase):
    def test_wrapped_read_from_real_log(self):
        text='<|tool_call>call:read{"arguments":{"line":204,"path":"scripts/audit-n8n-workflows.py","scope":"auto"},"purpose":"Read main"}<tool_call|>'
        a=parse_command({'content':text})
        self.assertEqual((a['action'],a['arguments']['line'],a['purpose']),('read',204,'Read main'))
    def test_other_terminator(self):
        a=parse_command({'content':'<|tool_call>call:find{"arguments":{"pattern":"run_psql"}}<|/tool_call|>'})
        self.assertEqual(a['action'],'find')
    def test_json(self):
        self.assertEqual(parse_command({'content':'{"action":"final","status":"FP","reason":"No data flow"}'})['status'],'FP')
    def test_native(self):
        a=parse_command({'tool_calls':[{'function':{'name':'read','arguments':'{"path":"a.py","line":1}'}}]})
        self.assertEqual(a['arguments']['line'],1)
    def test_malformed(self):
        with self.assertRaises(ProtocolError):parse_command({'content':'<|tool_call> nonsense'})
    def test_envelope(self):
        self.assertEqual(extract_message({'choices':[{'message':{'content':'hi'}}]})['content'],'hi')
    def test_body(self):
        c={'AI_MODEL':'m','AI_TEMPERATURE':0,'AI_PROTOCOL':'json'}
        self.assertEqual(json.loads(build_payload(c,[]))['model'],'m')
