"""Append-only, per-run provider/protocol trace. Never writes authorization headers."""
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

class Trace:
    def __init__(self, path, enabled=True, include_content=True, max_chars=100000):
        self.path=Path(path)
        self.enabled=enabled
        self.include_content=include_content
        self.max_chars=max_chars
        if enabled:
            self.path.parent.mkdir(parents=True,exist_ok=True)
            fd=os.open(str(self.path),os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
            os.close(fd)
            try: os.chmod(self.path,0o600)
            except OSError: pass

    def _clean(self, obj):
        if isinstance(obj,dict):
            return {str(k): ('[REDACTED]' if re.search(r'api.?key|authorization|password|secret|token',str(k),re.I) else self._clean(v)) for k,v in obj.items()}
        if isinstance(obj,list):return [self._clean(v) for v in obj]
        if isinstance(obj,str):
            if not self.include_content: return f'[CONTENT HIDDEN, chars={len(obj)}]'
            value=obj[:self.max_chars]
            return re.sub(r'(?i)(sk-[A-Za-z0-9_-]{12,})','[REDACTED_API_KEY]',value)
        return obj

    def emit(self, event, alert_id=None, **fields):
        if not self.enabled:return
        record={'timestamp':datetime.now(timezone.utc).isoformat(), 'event':event,'alert_id':alert_id,**self._clean(fields)}
        with self.path.open('a',encoding='utf-8') as f:
            f.write(json.dumps(record,ensure_ascii=False,default=str)+'\n')
