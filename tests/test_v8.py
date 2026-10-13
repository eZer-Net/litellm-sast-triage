import sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sast_triage.source.explorer import SourceExplorer
from sast_triage.providers.litellm import parse_command
CFG={'CONTEXT_MODE':'smart','CONTEXT_BEFORE':12,'CONTEXT_AFTER':12,'MAX_SYMBOL_LINES':120,'MAX_BLOCK_LINES':200,'MAX_WHOLE_FILE_LINES':350,'MAX_FIND_MATCHES':30,'MAX_FIND_BLOCKS':4}
class V8Tests(unittest.TestCase):
 def test_whole_file_and_outline(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp); (p/'x.py').write_text('def foo():\n    return 1\n\ndef bar():\n    return foo()\n')
   e=SourceExplorer(p,CFG)
   names={v['name'] for v in e.outline('x.py')['symbols']}
   self.assertEqual(names,{'foo','bar'})
   b=e.tool('read',{'path':'x.py','line':1})['code_blocks'][0]
   self.assertEqual((b['start_line'],b['end_line']),(1,5))
   self.assertTrue(e.tool('read',{'path':'x.py','line':1})['already_available'])
 def test_find_no_new_blocks(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp); (p/'x.py').write_text('def foo():\n    return foo()\n')
   e=SourceExplorer(p,CFG);e.tool('read',{'path':'x.py','line':1})
   self.assertTrue(e.tool('find',{'pattern':'foo'})['already_available'])
