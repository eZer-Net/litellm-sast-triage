"""Change outbound OpenAI-compatible requests here; no triage logic."""
import json

def build_payload(cfg, messages):
    body={'model':cfg['AI_MODEL'],'messages':messages,'temperature':cfg['AI_TEMPERATURE']}
    if cfg['AI_PROTOCOL']=='native':
        body['tools']=[{'type':'function','function':{'name':name,'description':desc,'parameters':{'type':'object','properties':{'path':{'type':'string'},'line':{'type':'integer'},'pattern':{'type':'string'},'mode':{'type':'string'},'purpose':{'type':'string'}},'additionalProperties':True}}} for name,desc in [('read','Read source block'),('find','Search source code')]]
        body['tool_choice']='auto'
    return json.dumps(body,ensure_ascii=False).encode('utf-8')
