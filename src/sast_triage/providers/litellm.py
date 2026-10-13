"""Edit this file to change provider request/response transport only."""
import json
import re
import time
import urllib.error
import urllib.request


from .parsers import parse_command
from .request import build_payload
from .response import extract_message


class LiteLLM:
    def __init__(self, cfg):
        self.cfg=cfg
        self.last_call=0.0

    def ask(self,messages):
        c=self.cfg
        url=c['AI_BASE_URL'].rstrip('/')
        if not url.endswith('/chat/completions'): url += '/chat/completions'
        data=build_payload(c,messages)
        headers={'Content-Type':'application/json','Authorization':'Bearer '+c['AI_API_KEY']}
        retries=c['AI_MAX_RETRIES']
        for attempt in range(retries+1):
            remaining=c['AI_REQUEST_PAUSE_SECONDS']-(time.monotonic()-self.last_call)
            if remaining>0: time.sleep(remaining)
            req=urllib.request.Request(url,data=data,headers=headers,method='POST')
            self.last_call=time.monotonic()
            try:
                with urllib.request.urlopen(req,timeout=c['AI_TIMEOUT_SECONDS']) as resp:
                    obj=json.load(resp)
                return extract_message(obj)
            except urllib.error.HTTPError as exc:
                # Never include full headers/request or credentials in exception strings.
                if exc.code not in (429,500,502,503,504) or attempt==retries:
                    raise RuntimeError(f'LiteLLM HTTP {exc.code}') from exc
                retry=exc.headers.get('Retry-After')
                try: wait=min(120,max(float(retry),0)) if retry else c['AI_RETRY_BACKOFF_SECONDS']*2**attempt
                except ValueError: wait=c['AI_RETRY_BACKOFF_SECONDS']*2**attempt
                time.sleep(wait)
            except (TimeoutError,urllib.error.URLError) as exc:
                if attempt==retries: raise RuntimeError('LiteLLM network/timeout failure') from exc
                time.sleep(c['AI_RETRY_BACKOFF_SECONDS']*2**attempt)
