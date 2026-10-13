import json
import tempfile
import unittest
from pathlib import Path
from sast_triage.source.explorer import SourceExplorer, markdown
from sast_triage.providers.litellm import parse_command
from sast_triage.parsers.sast import normalize_alert, parse_scan

CFG={'CONTEXT_MODE':'window','CONTEXT_BEFORE':2,'CONTEXT_AFTER':2,'MAX_SYMBOL_LINES':40,'MAX_BLOCK_LINES':100,'MAX_FIND_MATCHES':20,'MAX_FIND_BLOCKS':4}

class VNextTests(unittest.TestCase):
    def test_parser_contract(self):
        raw={'check_id':'x','path':'f.py','start':{'line':2,'col':1},'end':{'line':2,'col':3},'extra':{'message':'m','metadata':{'cwe':['CWE-89']}}}
        n=normalize_alert(raw)
        self.assertEqual(set(n),{'name','cwe','message','path','start','end'})
        with tempfile.TemporaryDirectory() as tmp:
            f=Path(tmp)/'scan.json';f.write_text(json.dumps({'results':[raw]}))
            self.assertEqual(parse_scan(f),[raw])
    def test_coverage_merges_adjacent_ranges(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'f.py').write_text('\n'.join('x' for _ in range(20)))
            e=SourceExplorer(root,CFG);e.coverage['f.py']=[(1,5),(6,9)]
            self.assertTrue(e.covered({'path':'f.py','start_line':2,'end_line':8}))
    def test_find_gives_multiline_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'f.py').write_text('first\nsecond\nimportant_needle\nfourth\nfifth')
            e=SourceExplorer(root,CFG)
            result=e.tool('find',{'mode':'text','pattern':'important_needle'})
            self.assertEqual(len(result['code_blocks']),1)
            self.assertIn('first\nsecond\nimportant_needle',result['code_blocks'][0]['code'])
            self.assertEqual(result['code_blocks'][0]['start_line'],1)
    def test_parser_enclosed_json(self):
        self.assertEqual(parse_command({'content':'Answer: {"action":"final","status":"FP"}.'})['status'],'FP')
    def test_markdown_fences(self):
        data={'alerts':[{'id':1,'semgrep':{'name':'r','cwe':'c','message':'m','path':'f','start':{},'end':{}},'ai':{'status':'FP','reason':'x','taint_flow':[{'code_blocks':[{'path':'f','start_line':1,'end_line':2,'code':'a\n```\nb'}]}]}}]}
        rendered=markdown(data)
        self.assertIn('a\n```\nb',rendered)
        self.assertIn('````',rendered)

if __name__=='__main__':unittest.main()
