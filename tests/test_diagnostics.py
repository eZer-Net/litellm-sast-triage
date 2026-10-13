import json
import tempfile
import unittest
from pathlib import Path
from sast_triage.core.trace import Trace
from sast_triage.core.triage import triage

class TraceTests(unittest.TestCase):
    def test_trace_events_and_redaction(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'run.trace.jsonl'
            log=Trace(p)
            log.emit('llm_request', alert_id=2, messages=[{'role':'user','content':'read a.py:1'}], authorization='Bearer sensitive', api_key='hello')
            log.emit('llm_response', alert_id=2, message={'content':'<|tool_call>call:read{"arguments":{}}<tool_call|>'})
            log.emit('parse_result',alert_id=2,ok=False,error_type='ProtocolError',error='invalid')
            events=[json.loads(x) for x in p.read_text().splitlines()]
            self.assertEqual([x['event'] for x in events],['llm_request','llm_response','parse_result'])
            self.assertEqual(events[0]['api_key'],'[REDACTED]')
            self.assertEqual(events[-1]['error_type'],'ProtocolError')

    def test_trace_without_text(self):
        with tempfile.TemporaryDirectory() as d:
            log=Trace(Path(d)/'t.jsonl',include_content=False)
            log.emit('llm_response',message={'content':'internal code'})
            self.assertIn('CONTENT HIDDEN',(Path(d)/'t.jsonl').read_text())

if __name__ == '__main__': unittest.main()
