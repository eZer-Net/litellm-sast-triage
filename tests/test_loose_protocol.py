import unittest
from sast_triage.providers.parsers import parse_command, ProtocolError

class LooseParserTests(unittest.TestCase):
    def test_unquoted_keys_wrapped(self):
        x=parse_command({'content':'<|tool_call>call:read{arguments:{line:1,path:"a.py"},purpose:"inspect"}<tool_call|>'})
        self.assertEqual((x['action'],x['arguments']['line']),("read",1))
    def test_invalid_escape_recovered(self):
        x=parse_command({'content':'{"action":"final","status":"FP","reason":"text \\! xyz"}'})
        self.assertEqual(x['reason'],r'text \! xyz')
    def test_native(self):
        x=parse_command({'tool_calls':[{'function':{'name':'read','arguments':'{path:"a.py",line:12}'}}]})
        self.assertEqual(x['arguments']['line'],12)
    def test_missing_args_not_invented(self):
        with self.assertRaises(ProtocolError):parse_command({'content':'{action:"read",arguments:{path:"a.py"}}'})
    def test_no_eval(self):
        with self.assertRaises(ProtocolError):parse_command({'content':'{action:__import__("os").system("id")}'})
    def test_ambiguous(self):
        with self.assertRaises(ProtocolError):parse_command({'content':'{"action":"final","status":"FP"} {"action":"final","status":"TP"}'})

if __name__=='__main__':unittest.main()
