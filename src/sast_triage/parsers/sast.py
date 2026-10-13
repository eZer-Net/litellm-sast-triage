"""SAST format adapter. REQUIRED normalized fields: name, path,
start {line,col}, end {line,col}. Optional: cwe, message. Coordinates are 1-based and end-exclusive.
Modify normalize_alert() and parse_scan() for another scanner's schema.
"""
import json

def parse_scan(path):
    data=json.loads(path.read_text(encoding='utf-8'))
    findings=data['results']
    if not isinstance(findings,list):raise ValueError('results must be list')
    return findings

def normalize_alert(raw):
    extra=raw.get('extra') or {}; meta=extra.get('metadata') or {}
    cwe=meta.get('cwe') or []
    if not raw.get('check_id') or not raw.get('path'):
        raise ValueError('SAST finding needs name/check_id and path')
    if not isinstance(raw.get('start'),dict) or not isinstance(raw.get('end'),dict) or not all(isinstance(raw[k].get('line'),int) and raw[k]['line']>0 for k in ('start','end')):
        raise ValueError('SAST finding needs positive start.line and end.line')
    return {'name':raw.get('check_id',''), 'cwe':', '.join(map(str,cwe)) if isinstance(cwe,list) else str(cwe),
            'message':extra.get('message',''), 'path':raw.get('path',''),
            'start':raw.get('start',{}), 'end':raw.get('end',{})}
