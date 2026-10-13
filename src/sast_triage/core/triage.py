"""Triage state machine: model commands -> source tools -> validated verdict."""
import json
from ..source.explorer import SourceExplorer, highlighted
from ..providers.parsers import parse_command
from ..source.tools import execute
from ..parsers.sast import normalize_alert

def _evidence_location_supported(value, explorer):
    """Only verify source/sink coordinates actually provided to the model."""
    import re
    if not isinstance(value, str):
        return False
    for path, spans in explorer.coverage.items():
        for match in re.finditer(re.escape(path) + r':(\d+)(?!\d)', value):
            line = int(match.group(1))
            if any(a <= line <= b for a, b in spans):
                return True
    return False


def _rule_family(sem):
    label=(str(sem.get('name',''))+' '+str(sem.get('cwe',''))+' '+str(sem.get('message',''))).lower()
    if 'cwe-78' in label or 'subprocess' in label or 'command injection' in label:
        return 'os_command'
    if 'regexp' in label or 'redos' in label:
        return 'regex'
    if 'html-in-template' in label or 'cwe-79' in label:
        return 'html'
    if 'sql' in label or 'sqli' in label:
        return 'sql'
    return 'other'


def _flow_review(sem, cmd, explorer):
    """Return targeted missing-proof diagnostics without choosing TP/FP for the model."""
    if cmd.get('status') != 'TP':
        return None
    family=_rule_family(sem)
    if family=='other':
        return None
    source=cmd.get('source'); sink=cmd.get('sink')
    if not source or not sink:
        return 'EVIDENCE_GAP: TP needs observed source and sink file:line, or a precise rule-specific direct condition. Investigate definitions/callers and return evidence.'
    if not _evidence_location_supported(source,explorer) or not _evidence_location_supported(sink,explorer):
        return 'EVIDENCE_GAP: cited source/sink lines were not supplied. Read actual cited functions and verify reachability.'
    text=str(cmd.get('reason','')).lower()
    if family=='os_command' and ('sql injection' in text or 'sql commands' in text) and not any(x in text for x in ('shell=true','shell injection','remote shell','argument injection','option injection')):
        return 'CWE_MISMATCH: this alert concerns OS commands, not SQL injection. Establish OS command execution mechanism or reconsider verdict.'
    if family=='regex' and not any(x in text for x in ('guard','validat','allowlist','config','restriction','filter','escape')):
        return 'GUARD_UNCHECKED: inspect regex interpolation constraints and any allowlist/validation before claiming ReDoS.'
    if family=='html' and not any(x in text for x in ('render','parsemode','html sink','markup','escape','encoding')):
        return 'SINK_UNCHECKED: establish that this exact interpolated variable reaches HTML rendering or a markup consumer.'
    if 'if an attacker can' in text or 'if it were' in text:
        return 'SPECULATIVE_TP: verify attacker control in current code, not hypothetical conditions.'
    return None


def alert_fields(raw):
    return normalize_alert(raw)

def triage(raw,index,root,cfg,client,prompt,trace=None):
    sem=alert_fields(raw); explorer=SourceExplorer(root,cfg)
    explorer.focus_path = sem['path']
    def log(event, **fields):
        if trace: trace.emit(event,alert_id=index,**fields)
    ai={'evidence_check': {'source': 'not_checked', 'sink': 'not_checked'}, 'status':'UNKNOWN','reason':'Not analyzed','source':None,'sink':None,'sanitizer':None,'taint_flow':[],'steps_used':0}
    try:
        lines=explorer.lines(sem['path'])
        exact=highlighted(lines,sem['start'],sem['end'])
        start=int(sem['start']['line']); end=int(sem['end'].get('line',start))
        # Semgrep coordinates are authoritative; never trim the matched span.
        excerpt=explorer.code(sem['path'],start,forced=(start,end))
        if excerpt['end_line'] < end:
            raise ValueError('Semgrep alert exceeds MAX_BLOCK_LINES, raise limit')
        explorer.coverage.setdefault(excerpt['path'],[]).append((excerpt['start_line'],excerpt['end_line']))
        surrounding=explorer.code(sem['path'],start,track=False)
        initial=[excerpt]
        if not explorer.covered(surrounding):
            initial.append(surrounding)
            explorer.coverage.setdefault(surrounding['path'],[]).append((surrounding['start_line'],surrounding['end_line']))
        ai['taint_flow'].append({'purpose':'Semgrep finding (exact range) + initial surrounding code','code_blocks':initial})
        print(f'\n    -> AI initial: {sem["path"]}:{start}-{end} [Semgrep exact]')
        for b in initial: print(f'    -> AI context: {b["path"]}:{b["start_line"]}-{b["end_line"]} ({len(b["code"].splitlines())} lines)')
        initial_message={'file_outline':explorer.outline(sem['path']),'semgrep':sem,'highlighted_match':exact,'source_blocks':initial,'tool_budget':cfg['TAINT_DEPTH'],'analysis_checklist':{'rule_family':_rule_family(sem),'inspect':['attacker-controlled source','data propagation/callers','exact sink for this rule','guards/sanitizers and reachability'],'note':'Confirm current-code facts; a dynamic pattern is not by itself a TP'},'available_ranges':explorer.coverage_map()}
        messages=[{'role':'system','content':prompt},{'role':'user','content':json.dumps(initial_message,ensure_ascii=False)}]
        log('initial_evidence', semgrep=sem, highlighted_match=exact, source_blocks=initial, outline=initial_message['file_outline'])
        errors=0; protocol_errors=0; consecutive_no_progress=0; fallback_requested=False
        for turn in range(cfg['MAX_TOTAL_TURNS']):
            try:
                log('llm_request', turn=turn+1, messages=messages)
                message=client.ask(messages)
                log('llm_response', turn=turn+1, message=message)
            except Exception as exc:
                log('api_error', turn=turn+1, error_type=type(exc).__name__, reason=str(exc))
                ai['reason']='API failure: '+str(exc)
                break
            try:
                cmd=parse_command(message)
            except (ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
                protocol_errors+=1
                log('parse_result', turn=turn+1, ok=False, error_type=type(exc).__name__, error=str(exc), content=message)
                messages.append({'role':'assistant','content':str(message.get('content') or '')[:1600]})
                messages.append({'role':'user','content':f'FORMAT_ERROR ({type(exc).__name__}). Reply as exactly one compact JSON object. You may FINALIZE now if evidence suffices. Already available: '+json.dumps(explorer.coverage_map())})
                print(f'\n    protocol correction {protocol_errors}/{cfg["MAX_PROTOCOL_ERRORS"]}: {type(exc).__name__}')
                print(f"    Parser error: {exc}")
                # Do not print raw model output: it may contain secrets or source code.
                # Enable restricted diagnostic logging separately if needed.
                if protocol_errors>=cfg['MAX_PROTOCOL_ERRORS']:
                    ai['reason']='Repeated invalid model protocol responses'; break
                continue
            log('parse_result', turn=turn+1, ok=True, command=cmd)
            action=cmd.get('action'); args=cmd.get('arguments') or {}
            if action=='final':
                status=cmd.get('status'); reason=cmd.get('reason')
                if status not in ('TP','FP','NEEDS_REVIEW') or not isinstance(reason,str) or len(reason.strip())<15:
                    why='Final requires TP/FP/NEEDS_REVIEW with an evidence-based reason (15+ chars).'
                elif status=='NEEDS_REVIEW' and ai['steps_used']<cfg['TAINT_DEPTH'] and not fallback_requested:
                    why=f'NEEDS_REVIEW requires more investigation or exhausted options. Request new code; final TP/FP if established.'
                elif status in ('TP','FP') and ('false positive' in reason.lower() if status=='TP' else 'true positive' in reason.lower()):
                    why='STATUS_REASON_CONFLICT: verdict contradicts narrative. Correct status or explanation using source evidence.'
                elif not fallback_requested and _flow_review(sem,cmd,explorer):
                    why=_flow_review(sem,cmd,explorer)
                else:
                    log('final_accepted', turn=turn+1, verdict=cmd)
                    ai.update(status=status,reason=reason.strip(),source=cmd.get('source'),sink=cmd.get('sink'),sanitizer=cmd.get('sanitizer'))
                    ai['evidence_check']={key: ('verified_in_supplied_code' if _evidence_location_supported(cmd.get(key), explorer) else 'unverified') for key in ('source','sink')}
                    break
                log('action_rejected', turn=turn+1, command=cmd, reason=why)
                errors+=1
                messages.append({'role':'user','content':why+' Available ranges: '+json.dumps(explorer.coverage_map())})
            elif action in ('read','find'):
                if fallback_requested:
                    messages.append({'role':'user','content':'FINAL_ONLY: no tools accepted. Return final JSON action now.'})
                    errors+=1
                    if errors>=cfg['MAX_TOOL_ERRORS']:
                        ai['reason']='Final-only protocol exhausted';break
                    continue
                if not isinstance(args,dict): args={}
                key=json.dumps({'action':action,'args':args},sort_keys=True,ensure_ascii=False)
                if ai['steps_used']>=cfg['TAINT_DEPTH']:
                    why='Tool budget exhausted. Return final verdict TP/FP/NEEDS_REVIEW now.'
                elif key in explorer.requests:
                    why='ALREADY_EXECUTED: identical search/read already returned. Do not ask again. Cite existing evidence or request DIFFERENT symbol/path. If evidence permits, FINAL now.'
                else:
                    explorer.requests.add(key)
                    try:
                        result=execute(explorer,action,args)
                    except (ValueError,OSError) as exc:
                        result={'error':str(exc),'code_blocks':[]}
                    if result.get('error'):
                        why=result['error']+'. Request NEW code or make evidence-based final decision.'
                    elif not result.get('code_blocks'):
                        # No new evidence: return an informative cached result, not a blind refusal.
                        why='CACHED_TOOL_RESULT: no new source; prior evidence already in conversation. '+json.dumps({'matches':result.get('matches',[])[:12],'reference':result.get('reference'),'outline':explorer.outline(sem['path'])},ensure_ascii=False)+' Choose another symbol/line, or finalize based on evidence.'
                    else:
                        log('tool_result', turn=turn+1, action=action, arguments=args, result=result, useful=True)
                        ai['steps_used']+=1
                        step={'purpose':str(cmd.get('purpose') or '')[:500],'action':action,'request':args,**result}
                        ai['taint_flow'].append(step)
                        print(f'\n    step {ai["steps_used"]}/{cfg["TAINT_DEPTH"]}: {action} {json.dumps(args,ensure_ascii=False)}; {len(result["code_blocks"])} new block(s)')
                        for b in result['code_blocks']: print(f'      -> AI code: {b["path"]}:{b["start_line"]}-{b["end_line"]} ({len(b["code"].splitlines())} lines)')
                        messages.append({'role':'assistant','content':json.dumps(cmd,ensure_ascii=False)})
                        messages.append({'role':'user','content':json.dumps({'tool_result':result,'remaining_steps':cfg['TAINT_DEPTH']-ai['steps_used'],'available_ranges':explorer.coverage_map()},ensure_ascii=False)})
                        errors=0;consecutive_no_progress=0
                        continue
                log('action_rejected', turn=turn+1, command=cmd, reason=why)
                errors+=1
                messages.append({'role':'user','content':why+' Available ranges: '+json.dumps(explorer.coverage_map())})
            else:
                errors+=1
                messages.append({'role':'user','content':'Unknown action. Return JSON action read/find/final only.'})
            log('action_rejected', turn=turn+1, command=cmd, reason=messages[-1]['content'])
            consecutive_no_progress+=1
            print(f'\n    rejected action {errors}/{cfg["MAX_TOOL_ERRORS"]}: {messages[-1]["content"][:110]}')
            if errors>=cfg['MAX_TOOL_ERRORS'] or consecutive_no_progress>=cfg['MAX_TOOL_ERRORS']:
                if not fallback_requested:
                    fallback_requested=True; errors=0; consecutive_no_progress=0
                    messages.append({'role':'user','content':'FINAL_ONLY STATE: tools are unavailable. Return action=final with TP or FP only if proven by existing code. Otherwise NEEDS_REVIEW with exact missing evidence. Never return read/find.'})
                    print('\n    recovery: request evidence-based final verdict; no more duplicate tools')
                else:
                    ai['reason']='Protocol/tool recovery exhausted; cannot trust model verdict';break
        else: ai['reason']='Maximum conversation turns reached without a valid verdict'
    except (ValueError,OSError,KeyError,TypeError) as exc:
        ai['reason']='Source processing failed: '+str(exc)
    ai['evidence_quality']='incomplete' if ai['status']=='TP' and (not ai.get('source') or not ai.get('sink')) else 'provided' if ai['status']=='TP' else 'not_applicable'
    log('alert_finished', evidence_quality=ai['evidence_quality'], status=ai['status'], reason=ai['reason'], steps_used=ai['steps_used'])
    return {'id':index,'semgrep':sem,'ai':ai}


