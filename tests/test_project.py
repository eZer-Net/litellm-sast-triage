import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sast_triage.source.explorer import SourceExplorer, highlighted, markdown
from sast_triage.providers.litellm import parse_command
from sast_triage.cli.main import triage

CFG={'TAINT_DEPTH':3,'MAX_TOTAL_TURNS':12,'MAX_TOOL_ERRORS':4,'MAX_PROTOCOL_ERRORS':4,'CONTEXT_MODE':'window','CONTEXT_BEFORE':1,'CONTEXT_AFTER':1,'MAX_BLOCK_LINES':20,'MAX_SYMBOL_LINES':20,'MAX_FIND_MATCHES':30,'MAX_FIND_BLOCKS':6}
ALERT={'check_id':'demo.test','path':'a.py','start':{'line':2,'col':1},'end':{'line':2,'col':4},'extra':{'message':'demo','metadata':{'cwe':['CWE-89']}}}
class MockClient:
    def __init__(self,commands):self.commands=iter(commands)
    def ask(self,messages):return {'content':next(self.commands)}

def obj(x):return json.dumps(x)

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        (self.root/'a.py').write_text('def foo(x):\n    dangerous(x)\n    return x\n\ndef bar():\n    return foo(3)\n')
    def tearDown(self):self.tmp.cleanup()
    def test_exact_fragment(self):
        self.assertEqual(highlighted(['abcd','xyz'],{'line':1,'col':2},{'line':1,'col':4}),'bc')
    def test_ast_symbol(self):
        c={**CFG,'CONTEXT_MODE':'smart'};e=SourceExplorer(self.root,c)
        b=e.code('a.py',2)
        self.assertEqual((b['start_line'],b['end_line']),(1,3))
    def test_read_duplicate(self):
        e=SourceExplorer(self.root,CFG);a=e.tool('read',{'path':'a.py','line':2});b=e.tool('read',{'path':'a.py','line':2})
        self.assertTrue(a['code_blocks']);self.assertTrue(b['already_available'])
    def test_find_blocks(self):
        e=SourceExplorer(self.root,CFG);a=e.tool('find',{'mode':'references','pattern':'foo'})
        self.assertTrue(a['code_blocks']);self.assertIn('\n',a['code_blocks'][0]['code'])
    def test_parser(self):
        self.assertEqual(parse_command({'content':'```json\n{"action":"final","status":"FP"}\n```'})['status'],'FP')
        self.assertEqual(parse_command({'tool_calls':[{'function':{'name':'read','arguments':'{"path":"a.py","line":2}'}}]})['action'],'read')
    def test_protocol_correction_and_final(self):
        client=MockClient(['{oops',obj({'action':'final','status':'FP','reason':'No untrusted path: a.py:2 only'})])
        r=triage(ALERT,1,self.root,CFG,client,'prompt')
        self.assertEqual(r['ai']['status'],'FP')
        self.assertEqual(r['ai']['steps_used'],0)
    def test_no_progress_produces_unknown(self):
        client=MockClient([obj({'action':'read','arguments':{'path':'a.py','line':2}})]*4)
        r=triage(ALERT,1,self.root,CFG,client,'prompt')
        self.assertEqual(r['ai']['status'],'UNKNOWN')
    def test_needs_review_guard(self):
        commands=[obj({'action':'final','status':'NEEDS_REVIEW','reason':'Not sufficient sources a.py:2'}),obj({'action':'final','status':'FP','reason':'Proved unreachable a.py:2 by guard'})]
        r=triage(ALERT,1,self.root,CFG,MockClient(commands),'prompt')
        self.assertEqual(r['ai']['status'],'FP')
    def test_md_preserves_raw_code(self):
        result={'alerts':[{'id':1,'semgrep':{'name':'n','cwe':'c','message':'m','path':'p','start':{},'end':{}},'ai':{'status':'FP','reason':'r','taint_flow':[{'purpose':'init','code_blocks':[{'path':'p','start_line':1,'end_line':2,'code':'a = "x"\n  return a'}]}]}}]}
        md=markdown(result);self.assertIn('a = "x"\n  return a',md)

if __name__=='__main__':unittest.main()
