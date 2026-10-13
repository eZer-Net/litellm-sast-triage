# LLM integration and response decoding

The provider layer is independent of scanner parsing and evidence collection.

| File | Responsibility | Typical modification |
|---|---|---|
| `providers/litellm.py` | HTTP endpoint, credentials, retry and timeout | Change HTTP client / authentication |
| `providers/request.py` | Serialize chat messages and optional native tools | Add provider-specific request properties |
| `providers/response.py` | Extract assistant message from API envelope | Adapt `choices[0].message` for another provider |
| `providers/parsers.py` | Decode assistant command into `{action, arguments, ...}` | Add another syntax/marker format |
| `prompt.txt` | Analyst instructions and accepted action examples | Tune taint-flow rules without changing transport |

**Message lifecycle:** `triage` creates messages → `build_payload` → `LiteLLM.ask()` → `extract_message` → `parse_command` → dispatch `read`/`find` or validate `final` → append trace.

**Supported command forms:** strict JSON, Markdown-fenced JSON, OpenAI `tool_calls`, model-specific `<|tool_call>` wrappers, and a constrained JSON-like format (unquoted keys and selected invalid string escapes). The tolerant parser extracts known fields; it does **not** evaluate scripts, infer missing paths, or execute source code. Unknown or ambiguous commands are rejected and logged to the JSONL trace.

**Safe customization:** add a parser branch and regression fixture containing a real model response; retain clear failures for ambiguous commands. When changing `request.py`, update protocol examples in `prompt.txt` and keep `response.py` aligned with the gateway envelope. Avoid logging secrets in bug reports.
