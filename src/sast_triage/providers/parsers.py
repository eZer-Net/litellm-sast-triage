"""Untrusted-model response adapter: strict JSON, native calls and bounded loose syntax.

No eval, execution, or guessing missing action/required arguments. Loose syntax
is a compatibility layer, not permission to invent evidence or fix semantics.
"""
import ast
import json
import re

class ProtocolError(ValueError):
    pass

ACTIONS = ('read', 'find', 'final')
MAX_RESPONSE = 200_000


def _normalize(obj):
    if not isinstance(obj, dict):
        raise ProtocolError('Expected command object')
    obj = dict(obj)
    if 'action' not in obj and 'name' in obj:
        obj['action'] = obj['name']
    action = str(obj.get('action', '')).lower()
    if action not in ACTIONS:
        raise ProtocolError('Missing or unknown action')
    args = obj.get('arguments', {})
    if isinstance(args, str):
        args = _decode_object(args)
    if not isinstance(args, dict):
        raise ProtocolError('arguments must be an object')
    if action == 'final':
        for key in ('status', 'reason', 'source', 'sink', 'sanitizer'):
            if key not in obj and key in args:
                obj[key] = args[key]
    elif action == 'read':
        if not isinstance(args.get('path'), str) or not isinstance(args.get('line'), int):
            raise ProtocolError('Read requires path string and line integer')
    elif action == 'find':
        if not isinstance(args.get('pattern', args.get('query')), str):
            raise ProtocolError('Find requires a pattern')
    obj['action'] = action
    obj['arguments'] = args
    if 'purpose' not in obj and 'purpose' in args:
        obj['purpose'] = args['purpose']
    return obj


def _quote_unquoted_keys(text):
    # Lexically quote property identifiers only outside string literals.
    out=[]; i=0; quote=None; escaped=False
    while i<len(text):
        ch=text[i]
        if quote:
            if ch=='\\':
                if i+1<len(text): out.extend((ch,text[i+1]));i+=2;continue
            if ch==quote: quote=None
            out.append(ch); i+=1;continue
        if ch in ('"', "'"):
            quote=ch;out.append(ch);i+=1;continue
        if (ch.isalpha() or ch=='_') and (not out or out[-1] in ('{',',') or ''.join(out).rstrip().endswith(('{',','))):
            j=i+1
            while j<len(text) and (text[j].isalnum() or text[j]=='_'):j+=1
            k=j
            while k<len(text) and text[k].isspace():k+=1
            if k<len(text) and text[k]==':':
                out.extend(('"',text[i:j],'"')); i=j;continue
        out.append(ch);i+=1
    return ''.join(out)


def _fix_invalid_escapes(text):
    # Escape only non-JSON escapes INSIDE quoted strings, preserving valid escapes.
    out=[]; i=0; quote=False
    while i<len(text):
        ch=text[i]
        if ch=='"':quote=not quote;out.append(ch);i+=1;continue
        if quote and ch=='\\' and i+1<len(text):
            nxt=text[i+1]
            if nxt not in '"\\/bfnrtu':out.append('\\\\');i+=1;continue
            if nxt=='u' and not re.match(r'[0-9a-fA-F]{4}',text[i+2:i+6]):
                out.append('\\\\');i+=1;continue
            out.extend((ch,nxt));i+=2;continue
        out.append(ch);i+=1
    return ''.join(out)


def _decode_object(text):
    text=text.strip()
    try:return json.loads(text)
    except (ValueError, TypeError):pass
    repaired=_fix_invalid_escapes(_quote_unquoted_keys(text))
    try:return json.loads(repaired)
    except (ValueError,TypeError):pass
    # Safely decode Python-style literal strings/dicts; size and depth restricted.
    if len(text)>40_000:raise ProtocolError('Loose object exceeds size limit')
    try:
        obj=ast.literal_eval(text)
        if isinstance(obj, dict):return obj
    except (SyntaxError,ValueError,MemoryError,RecursionError):pass
    raise ProtocolError('Cannot decode command object as JSON or supported loose syntax')


def _balanced_object(text, start):
    depth=0;quote=None;escaped=False
    for i in range(start,len(text)):
        ch=text[i]
        if quote:
            if escaped:escaped=False
            elif ch=='\\':escaped=True
            elif ch==quote:quote=None
        elif ch in ('"',"'"):quote=ch
        elif ch=='{':depth+=1
        elif ch=='}':
            depth-=1
            if depth==0:return text[start:i+1]
    raise ProtocolError('Truncated command object')


def _unwrap_text(content):
    if isinstance(content,list):content='\n'.join(x.get('text','') for x in content if isinstance(x,dict))
    if not isinstance(content,str):raise ProtocolError('No textual response')
    text=content.strip()
    if len(text)>MAX_RESPONSE:raise ProtocolError('Model response exceeds limit')
    if text.startswith('```'):
        text=re.sub(r'^```(?:json|json5)?\s*','',text,flags=re.I)
        text=re.sub(r'\s*```$','',text).strip()
    wrapped=re.search(r'<\|tool_call>\s*call:(read|find|final)\s*',text,re.I)
    if wrapped:
        pos=text.find('{',wrapped.end())
        if pos<0:raise ProtocolError('Tool call missing argument object')
        obj=_decode_object(_balanced_object(text,pos))
        if not isinstance(obj,dict):raise ProtocolError('Tool call requires argument object')
        return _normalize({'action':wrapped.group(1).lower(),**obj})
    try:return _normalize(_decode_object(text))
    except ProtocolError as primary:
        # Extract a single embedded object, never merge competing commands.
        found=[]
        for m in re.finditer(r'\{',text):
            try:
                obj=_normalize(_decode_object(_balanced_object(text,m.start())))
                found.append(obj)
            except (ValueError,TypeError):continue
        if len(found)==1:return found[0]
        raise ProtocolError(str(primary) if not found else 'Multiple commands in response') from primary


def parse_command(message):
    if not isinstance(message,dict):raise ProtocolError('Message must be an object')
    calls=message.get('tool_calls') or []
    if calls:
        if len(calls)!=1:raise ProtocolError('Exactly one tool call supported')
        fn=calls[0].get('function') or {}
        args=fn.get('arguments',{})
        if isinstance(args,str):args=_decode_object(args)
        return _normalize({'action':fn.get('name'),'arguments':args})
    return _unwrap_text(message.get('content'))
