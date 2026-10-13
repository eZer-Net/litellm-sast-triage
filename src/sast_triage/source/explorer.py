"""Bounded, read-only source exploration and report rendering."""
from __future__ import annotations
import ast
import json
import re
from pathlib import Path

SKIP_DIRS = {'.git', 'node_modules', '.venv', 'venv', 'dist', 'build', '__pycache__'}


def highlighted(lines, start, end):
    sl, sc = int(start.get('line', 1)), int(start.get('col', 1))
    el, ec = int(end.get('line', sl)), int(end.get('col', sc))
    if sl < 1 or el < sl or el > len(lines):
        return ''
    if sl == el:
        return lines[sl-1][max(sc-1, 0):max(ec-1, 0)]
    return '\n'.join([lines[sl-1][max(sc-1, 0):], *lines[sl:el-1], lines[el-1][:max(ec-1,0)]])


def symbol_span(path, lines, line, max_symbol):
    """AST for Python; conservative brace matching for JS/TS, window fallback."""
    if path.suffix == '.py':
        try:
            tree = ast.parse('\n'.join(lines))
            nodes = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and getattr(n, 'lineno', 10**9) <= line <= getattr(n, 'end_lineno', 0)]
            if nodes:
                n = min(nodes, key=lambda n: n.end_lineno - n.lineno)
                if n.end_lineno - n.lineno + 1 <= max_symbol:
                    return n.lineno, n.end_lineno
        except SyntaxError:
            pass
    if path.suffix in {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}:
        # Only recognizable declarations, balanced braces ignoring quoted strings/comments.
        pat = re.compile(r'\b(?:export\s+)?(?:async\s+)?function\s+\w+|\bclass\s+\w+|\b(?:const|let|var)\s+\w+\s*=.*(?:=>|function\s*\()')
        for begin in range(line-1, max(-1,line-max_symbol-1), -1):
            if not pat.search(lines[begin]):
                continue
            snippet = '\n'.join(lines[begin:begin+max_symbol])
            depth = 0; start_found = False; quote = None; escaped = False; comment = None
            for i, ch in enumerate(snippet):
                nxt = snippet[i:i+2]
                if comment == 'line':
                    if ch == '\n': comment = None
                    continue
                if comment == 'block':
                    if nxt == '*/': comment = None
                    continue
                if quote:
                    if escaped: escaped = False
                    elif ch == '\\': escaped = True
                    elif ch == quote: quote = None
                    continue
                if nxt == '//': comment = 'line'; continue
                if nxt == '/*': comment = 'block'; continue
                if ch in ('"', "'", '`'): quote = ch; continue
                if ch == '{': depth += 1; start_found = True
                elif ch == '}' and start_found:
                    depth -= 1
                    if depth == 0:
                        finish = begin+snippet[:i+1].count('\n')+1
                        if begin+1 <= line <= finish and finish-begin <= max_symbol:
                            return begin+1, finish
                        break
            # JS templates are complex: if ambiguous, window is safer.
    return None


class SourceExplorer:
    def __init__(self, root: Path, cfg: dict):
        self.root = root.resolve()
        self.cfg = cfg
        self.coverage: dict[str, list[tuple[int,int]]] = {}
        self.requests: set[str] = set()
        self.focus_path: str | None = None

    def file(self, rel):
        if not isinstance(rel, str) or not rel or '\x00' in rel:
            raise ValueError('invalid path')
        path = (self.root / rel).resolve()
        if not path.is_relative_to(self.root) or not path.is_file() or path.is_symlink():
            raise ValueError('file not available inside project')
        if any(part in SKIP_DIRS for part in path.relative_to(self.root).parts):
            raise ValueError('excluded path')
        if path.stat().st_size > 2_000_000:
            raise ValueError('file over 2 MB safety limit')
        return path

    def lines(self, rel):
        return self.file(rel).read_text(encoding='utf-8',errors='replace').splitlines()

    def code(self, rel, line, forced=None, track=True):
        path = self.file(rel)
        lines = self.lines(rel)
        if not lines: raise ValueError('empty source file')
        line = max(1, min(int(line),len(lines)))
        if forced is None:
            start = max(1,line-self.cfg['CONTEXT_BEFORE'])
            end = min(len(lines),line+self.cfg['CONTEXT_AFTER'])
            if self.cfg['CONTEXT_MODE'] in ('smart','symbol'):
                sym = symbol_span(path, lines, line, self.cfg['MAX_SYMBOL_LINES'])
                if sym: start, end = sym
        else:
            start, end = forced
            start = max(1,int(start)); end = min(len(lines),int(end))
        cap = max(self.cfg['MAX_BLOCK_LINES'], self.cfg.get('MAX_WHOLE_FILE_LINES', 350)) if forced and start==1 and end==len(lines) else self.cfg['MAX_BLOCK_LINES']
        if end-start+1 > cap:
            start = max(start,line-cap//2)
            end = min(end,start+cap-1)
            start = max(1,end-cap+1)
        key = path.relative_to(self.root).as_posix()
        block = {'path':key,'start_line':start,'end_line':end,'code':'\n'.join(lines[start-1:end])}
        if track: self.coverage.setdefault(key, []).append((start,end))
        return block

    def covered(self, b):
        spans=sorted(self.coverage.get(b['path'],[]))
        pos=b['start_line']
        for a,z in spans:
            if a>pos: break
            pos=max(pos,z+1)
            if pos>b['end_line']: return True
        return False

    def tool(self, action, args):
        if action == 'read':
            rel = args.get('path'); line = args.get('line')
            if line is None: line = args.get('start_line')
            if line is None: raise ValueError('read needs line')
            line = int(line)
            # A read at line 1 normally indicates a desire to inspect the file.
            # Avoid spending five calls scanning heavily overlapping 25-line windows.
            whole_limit = self.cfg.get('MAX_WHOLE_FILE_LINES', 350)
            if line == 1 and len(self.lines(rel)) <= whole_limit and args.get('scope','auto') != 'window':
                block = self.code(rel,1,forced=(1,len(self.lines(rel))),track=False)
            elif args.get('scope') == 'file' and len(self.lines(rel)) <= whole_limit:
                block = self.code(rel,line,forced=(1,len(self.lines(rel))),track=False)
            else:
                block = self.code(rel,line,track=False)
            if self.covered(block): return {'already_available':True, 'reference': {'path':block['path'],'start_line':block['start_line'],'end_line':block['end_line']}, 'code_blocks':[]}
            self.coverage.setdefault(block['path'],[]).append((block['start_line'],block['end_line']))
            return {'code_blocks':[block]}
        if action != 'find': raise ValueError('unsupported action')
        pattern = args.get('pattern') or args.get('query')
        mode = args.get('mode','references')
        if mode not in ('references','definition','text') or not isinstance(pattern,str) or not pattern or len(pattern)>150:
            raise ValueError('invalid find pattern or mode')
        matches = []; seen=set(); blocks=[]
        for path in sorted(self.root.rglob('*'), key=lambda p: (0 if self.focus_path and p.relative_to(self.root).as_posix() == self.focus_path else 1, p.as_posix())):
            if len(matches) >= self.cfg['MAX_FIND_MATCHES']: break
            if not path.is_file() or path.is_symlink() or any(x in SKIP_DIRS for x in path.relative_to(self.root).parts) or path.suffix.lower() not in {'.py','.js','.jsx','.ts','.tsx','.mjs','.cjs','.go','.java','.rb','.php','.rs','.sql'}:
                continue
            try: lines = self.lines(path.relative_to(self.root).as_posix())
            except (ValueError,OSError): continue
            for i,line in enumerate(lines,1):
                if pattern not in line: continue
                if mode == 'definition' and not re.search(r'\b(?:def|class|function|const|let|var|export|async)\b',line): continue
                rel = path.relative_to(self.root).as_posix()
                matches.append({'path':rel,'line':i})
                if len(blocks) < self.cfg['MAX_FIND_BLOCKS']:
                    b = self.code(rel,i,track=False)
                    k=(b['path'],b['start_line'],b['end_line'])
                    if k not in seen and not self.covered(b) and not any(x['path'] == b['path'] and not (x['end_line'] < b['start_line'] or b['end_line'] < x['start_line']) for x in blocks):
                        seen.add(k); blocks.append(b)
                        self.coverage.setdefault(rel,[]).append((b['start_line'],b['end_line']))
                if len(matches)>=self.cfg['MAX_FIND_MATCHES']: break
        return {'matches':matches,'code_blocks':blocks,'matches_truncated':len(matches)>=self.cfg['MAX_FIND_MATCHES'], 'already_available': bool(matches and not blocks)}

    def outline(self, rel):
        """Lightweight line map, not source evidence; helps LLM select precise reads."""
        lines = self.lines(rel)
        items = []
        path = self.file(rel)
        if path.suffix == '.py':
            try:
                tree = ast.parse('\n'.join(lines))
                for n in tree.body:
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        items.append({'name': n.name, 'kind': type(n).__name__, 'start_line': n.lineno, 'end_line': n.end_lineno})
            except SyntaxError: pass
        else:
            rx = re.compile(r'\b(?:function\s+([A-Za-z_$][\w$]*)|class\s+([A-Za-z_$][\w$]*)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=.*(?:=>|function))')
            for i, line in enumerate(lines, 1):
                m = rx.search(line)
                if m: items.append({'name': next((v for v in m.groups() if v), ''), 'start_line': i})
        return {'path':rel, 'total_lines':len(lines), 'symbols':items[:100]}

    def coverage_map(self):
        return {k:[{'start_line':a,'end_line':b} for a,b in spans] for k,spans in self.coverage.items()}


def markdown(report):
    out=['# Semgrep AI Triage Report','']
    for item in report['alerts']:
        s=item['semgrep']; ai=item['ai']; t=ai['taint_flow']
        out += [f"## Alert {item['id']}", '', '### Semgrep', '',f"- **Name:** `{s['name']}`",f"- **CWE:** {s['cwe']}",f"- **Message:** {s['message']}",f"- **Path:** `{s['path']}`",f"- **Start:** {s['start']}",f"- **End:** {s['end']}",'', '### AI', '',f"- **Status:** **{ai['status']}**",f"- **Reason:** {ai['reason']}",f"- **Source:** {ai.get('source')}",f"- **Sink:** {ai.get('sink')}",f"- **Sanitizer:** {ai.get('sanitizer')}",f"- **Steps used:** {ai.get('steps_used',0)}",f"- **Evidence quality:** {ai.get('evidence_quality', 'not_recorded')}",'', '### Evidence / taint flow', '']
        for index, step in enumerate(t):
            out += [f"#### {'Semgrep source' if index==0 else 'Step '+str(index)}", '',f"**Purpose:** {step.get('purpose') or '—'}",'']
            for b in step.get('code_blocks',[]):
                code=b['code']; fence='`'*max(3,max((len(m.group(0)) for m in re.finditer(r'`+',code)),default=0)+1)
                out += [f"**{b['path']}:{b['start_line']}-{b['end_line']}**",'', fence,code,fence,'']
            if step.get('matches'): out += [f"**Matches:** {len(step['matches'])} (paths/lines in JSON)",'']
            if step.get('error'): out += [f"**Tool error:** {step['error']}",'']
        out += ['---','']
    return '\n'.join(out)
