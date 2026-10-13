#!/usr/bin/env python3
"""Minimal CLI orchestration for Semgrep -> LiteLLM -> JSON/Markdown."""
from __future__ import annotations
import argparse
import copy
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from sast_triage.source.explorer import SourceExplorer, highlighted, markdown
from sast_triage.providers.litellm import LiteLLM
from sast_triage.core.triage import triage
from sast_triage.core.trace import Trace
from sast_triage.parsers.sast import parse_scan, normalize_alert

BASE = Path(__file__).resolve().parents[3]

def config():
    p=BASE/'.env'
    if not p.is_file(): raise RuntimeError('Missing .env')
    values={}
    for line in p.read_text(encoding='utf-8').splitlines():
        line=line.strip()
        if not line or line.startswith('#') or '=' not in line: continue
        k,v=line.split('=',1)
        values[k.strip()]=v.strip().strip('"').strip("'")
    defaults={'AI_PROTOCOL':'json','AI_TIMEOUT_SECONDS':'120','AI_MAX_RETRIES':'3','AI_RETRY_BACKOFF_SECONDS':'3','AI_TEMPERATURE':'0','AI_REQUEST_PAUSE_SECONDS':'2','ALERT_PAUSE_SECONDS':'60','TAINT_DEPTH':'5','CONTEXT_MODE':'smart','CONTEXT_BEFORE':'12','CONTEXT_AFTER':'12','MAX_SYMBOL_LINES':'120','MAX_BLOCK_LINES':'200','MAX_FIND_MATCHES':'30','MAX_FIND_BLOCKS':'6','MAX_TOOL_ERRORS':'4','MAX_PROTOCOL_ERRORS':'4','MAX_TOTAL_TURNS':'30','MAX_WHOLE_FILE_LINES':'350','PROMPT_FILE':'prompt.txt','PROJECT_DIR':'','SCAN_FILE':'scan-all.json','RESULT_NAME':'triage-result-ai','TRACE_ENABLED':'true','TRACE_INCLUDE_CONTENT':'true','TRACE_MAX_CHARS':'100000'}
    c={**defaults,**values}
    for key in ('AI_TIMEOUT_SECONDS','AI_MAX_RETRIES','AI_RETRY_BACKOFF_SECONDS','AI_REQUEST_PAUSE_SECONDS','ALERT_PAUSE_SECONDS','TAINT_DEPTH','CONTEXT_BEFORE','CONTEXT_AFTER','MAX_SYMBOL_LINES','MAX_BLOCK_LINES','MAX_FIND_MATCHES','MAX_FIND_BLOCKS','MAX_TOOL_ERRORS','MAX_PROTOCOL_ERRORS','MAX_TOTAL_TURNS','MAX_WHOLE_FILE_LINES'):
        c[key]=int(c[key]) if key not in ('AI_REQUEST_PAUSE_SECONDS','ALERT_PAUSE_SECONDS','AI_RETRY_BACKOFF_SECONDS') else float(c[key])
        if c[key]<0: raise ValueError(f'{key} must not be negative')
    c['AI_TEMPERATURE']=float(c['AI_TEMPERATURE'])
    c['TRACE_ENABLED']=str(c['TRACE_ENABLED']).lower() in ('1','true','yes','on')
    c['TRACE_INCLUDE_CONTENT']=str(c['TRACE_INCLUDE_CONTENT']).lower() in ('1','true','yes','on')
    c['TRACE_MAX_CHARS']=int(c['TRACE_MAX_CHARS'])
    if c['CONTEXT_MODE'] not in ('window','smart','symbol'):raise ValueError('CONTEXT_MODE must be window/smart/symbol')
    if c['TAINT_DEPTH']<1 or c['MAX_BLOCK_LINES']<1:raise ValueError('Invalid depth/block limits')
    for key in ('AI_BASE_URL','AI_API_KEY','AI_MODEL'):
        if not c.get(key) or c[key] in ('YOUR_API_KEY','https://your-litellm-host/v1'):raise ValueError(f'Configure {key} in .env')
    return c


def alert_fields(raw):
    return normalize_alert(raw)



def resolve_project(base, setting):
    """Resolve an explicit project path; never discover workspace children."""
    if not setting or str(setting).strip().lower() == 'auto':
        raise ValueError('Specify project via --project, PROJECT_DIR in .env, or the interactive prompt')
    path = Path(setting).expanduser()
    return path.resolve() if path.is_absolute() else (Path.cwd() / path).resolve()


def resolve_scan(project, filename):
    """Resolve the scan report inside the selected project, never in workspace/."""
    if not filename or not str(filename).strip():
        raise ValueError('Specify --scan or SCAN_FILE')
    path = Path(filename).expanduser()
    if path.is_absolute():
        raise ValueError('SCAN_FILE / --scan must be a filename or a relative path inside the project')
    result = (project / path).resolve()
    if not result.is_relative_to(project.resolve()):
        raise ValueError('SCAN_FILE / --scan must remain inside the project directory')
    return result


def ask_value(label, default):
    if not sys.stdin.isatty(): return str(default)
    try: return input(f'{label} [{default}]: ').strip() or str(default)
    except EOFError: return str(default)


def validate_result_name(name):
    """Use a portable filename stem shared by JSON, Markdown and trace."""
    name = str(name).strip()
    if (not name or name in ('.', '..') or name != Path(name).name
            or any(ch in name for ch in '/\\<>:"|?*')
            or any(ord(ch) < 32 for ch in name)
            or name.endswith(('.', ' '))
            or name.lower().endswith(('.json', '.md', '.jsonl'))):
        raise ValueError('Result name must be a portable filename stem without extension')
    return name


def timestamped_result_name(prefix, now=None):
    """Local timestamp; hyphens in time keep names valid on Windows."""
    moment = now if now is not None else datetime.now()
    return validate_result_name(f'{validate_result_name(prefix)}-{moment:%d.%m.%Y-%H-%M-%S}')


def unique_result_name(outdir, name):
    """Do not overwrite a previous JSON/Markdown/trace trio, even within one second."""
    base = validate_result_name(name)
    stem = base
    n = 1
    while any((outdir / (stem + ext)).exists() for ext in ('.json', '.md', '.trace.jsonl')):
        stem = f'{base}-{n:02d}'
        n += 1
    return stem


def choose_result_name(args, cfg, outdir):
    """CLI override > interactive custom name > timestamped default."""
    requested = args.resultName or args.name
    if requested:
        return unique_result_name(outdir, requested)
    automatic = timestamped_result_name(cfg['RESULT_NAME'])
    if sys.stdin.isatty():
        print(f'\nSuggested report name: {automatic}')
        choice = ask_value('Use your own name? (y/N)', 'N').lower()
        if choice in ('y', 'yes'):
            automatic = ask_value('Report name (without extension)', automatic)
        elif choice not in ('n', 'no'):
            raise ValueError('Please answer y or n')
    return unique_result_name(outdir, automatic)


def select_range(total, begin, finish):
    if begin is not None or finish is not None:
        start=begin if begin is not None else 1
        end=finish if finish is not None else total
    elif sys.stdin.isatty():
        print('\nSelect alert range:')
        print('  1. Start from selected ID through end')
        print('  2. Specify start and end IDs')
        mode=ask_value('Choice 1/2','1')
        if mode not in ('1','2'):raise ValueError('Choice must be 1 or 2')
        start=int(ask_value(f'Start ID (1-{total})',1))
        end=int(ask_value(f'End ID ({start}-{total})',total)) if mode=='2' else total
    else: start,end=1,total
    if not 1<=start<=end<=total:raise ValueError(f'Invalid range: {start}-{end}; total alerts: {total}')
    return start,end


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',help='Project source directory (overrides PROJECT_DIR)')
    parser.add_argument('--scan',help='SAST report filename or relative path inside the project (overrides SCAN_FILE)')
    parser.add_argument('--resultName',help='Custom report name without extension; default uses local timestamp')
    parser.add_argument('--name',help=argparse.SUPPRESS)
    parser.add_argument('--start',type=int,help='Starting alert ID (1-based)')
    parser.add_argument('--end',type=int,help='Final alert ID (inclusive)')
    args=parser.parse_args();cfg=config()
    project_setting = args.project or cfg['PROJECT_DIR']
    if not project_setting or str(project_setting).lower() == 'auto':
        project_setting = ask_value('Project directory', '')
    project=resolve_project(BASE,project_setting)
    scan=resolve_scan(project,args.scan or cfg['SCAN_FILE'])
    if not project.is_dir():raise ValueError(f'Project not found: {project}')
    if not scan.is_file():raise ValueError(f'Semgrep scan not found: {scan}')
    alerts=parse_scan(scan)
    if not isinstance(alerts,list):raise ValueError('Semgrep results must be an array')
    print('\nLiteLLM SAST Triage\n===================')
    print(f'Model:       {cfg["AI_MODEL"]}')
    print(f'Project:     {project}')
    print(f'Semgrep:     {scan}')
    print(f'Alerts:      {len(alerts)}')
    outdir=BASE/'output';outdir.mkdir(exist_ok=True)
    basename=choose_result_name(args,cfg,outdir)
    print(f'Report name: {basename}')
    if not alerts: print('No alerts in Semgrep report');return
    start,end=select_range(len(alerts),args.start,args.end)
    prompt=(BASE/cfg['PROMPT_FILE']).read_text(encoding='utf-8')
    client=LiteLLM(cfg)
    chosen=list(enumerate(alerts,1))[start-1:end]
    print('\nRun configuration\n-----------------')
    print(f'Report:       {basename}.json / {basename}.md')
    print(f'Alert range:  {start} -> {end} ({len(chosen)} findings)')
    print(f'Taint depth:  {cfg["TAINT_DEPTH"]}')
    print(f'API pause:    {cfg["AI_REQUEST_PAUSE_SECONDS"]} seconds')
    print(f'Alert pause:  {cfg["ALERT_PAUSE_SECONDS"]} seconds\n')
    trace=Trace(outdir/(basename+'.trace.jsonl'),cfg['TRACE_ENABLED'],cfg['TRACE_INCLUDE_CONTENT'],cfg['TRACE_MAX_CHARS'])
    print(f'Diagnostic trace: {trace.path if cfg["TRACE_ENABLED"] else "disabled"}')
    result={'alerts':[]}
    for offset,(idx,alert) in enumerate(chosen):
        sem=alert_fields(alert)
        print('\n' + '═' * 78)
        print(f'[ID {idx} | {offset+1}/{len(chosen)}] {sem["name"]}')
        print(f'    {sem["path"]}:{sem["start"].get("line","?")}:{sem["start"].get("col","?")}')
        item=triage(alert,idx,project,cfg,client,prompt,trace=trace)
        result['alerts'].append(item)
        print('\n    ' + '-' * 60)
        print(f'    AI report: {item["ai"]["status"]}')
        print(f'    Reason: {item["ai"]["reason"]}')
        (outdir/(basename+'.json')).write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        (outdir/(basename+'.md')).write_text(markdown(result),encoding='utf-8')
        if offset<len(chosen)-1 and cfg['ALERT_PAUSE_SECONDS']>0:
            print(f'\n    Waiting {cfg["ALERT_PAUSE_SECONDS"]} second(s) before next alert...\n',flush=True)
            time.sleep(cfg['ALERT_PAUSE_SECONDS'])
    print('\nTriage completed')
    for status in ('TP','FP','NEEDS_REVIEW','UNKNOWN'):
        print(f'  {status:14} {sum(a["ai"]["status"]==status for a in result["alerts"])}')
    print(f'JSON: {outdir/(basename+".json")}')
    print(f'MD:   {outdir/(basename+".md")}')
    if cfg['TRACE_ENABLED']:print(f'Trace: {trace.path}')

if __name__=='__main__':
    try: main()
    except (ValueError,RuntimeError,FileNotFoundError,KeyError) as exc:
        print(f'ERROR: {exc}',file=sys.stderr);sys.exit(1)
