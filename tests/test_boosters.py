import tempfile
import unittest
from pathlib import Path
from sast_triage.source.explorer import SourceExplorer
from sast_triage.core.triage import _evidence_location_supported

CFG = dict(CONTEXT_BEFORE=2, CONTEXT_AFTER=2, CONTEXT_MODE='window',MAX_SYMBOL_LINES=60,MAX_BLOCK_LINES=100,MAX_WHOLE_FILE_LINES=350,MAX_FIND_MATCHES=30,MAX_FIND_BLOCKS=2)

class BoosterTests(unittest.TestCase):
 def test_location_needs_supplied_code(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);(root/'example.py').write_text('a=1\nb=2\nc=3\n')
   ex=SourceExplorer(root,CFG);ex.tool('read',{'path':'example.py','line':2,'scope':'window'})
   self.assertTrue(_evidence_location_supported('example.py:2',ex))
   self.assertFalse(_evidence_location_supported('example.py:99',ex))
   self.assertFalse(_evidence_location_supported('missing.py:2',ex))
 def test_find_prefers_alert_file(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);(root/'aaa.py').write_text('run_psql()\n');(root/'zzz.py').write_text('run_psql()\n')
   ex=SourceExplorer(root,CFG);ex.focus_path='zzz.py'
   result=ex.tool('find',{'pattern':'run_psql'})
   self.assertEqual(result['code_blocks'][0]['path'],'zzz.py')

if __name__=='__main__':unittest.main()
