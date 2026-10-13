# Diagnostics and AI exchange trace

Each run writes `output/<report-name>.trace.jsonl` when `TRACE_ENABLED=true`. Each line is a standalone JSON event with UTC timestamp, alert ID and event type:

| Event | Contents |
| --- | --- |
| `initial_evidence` | Normalized SAST alert, exact match, source blocks and outline provided to the model |
| `llm_request` | Complete messages sent to LiteLLM (no authorization header) |
| `llm_response` | Actual assistant message returned by the provider |
| `parse_result` | Success flag and normalized command, or parser error type and reason |
| `tool_result` | Executed read/find arguments and code blocks returned |
| `action_rejected` | Invalid/duplicated action and reason |
| `final_accepted` | Accepted final model verdict |
| `alert_finished` | Final recorded status, reason and number of useful source requests |
| `api_error` | Transport failure without credentials |

## Debugging a ProtocolError

Open the `.trace.jsonl`, filter on `alert_id` and inspect successive `llm_response` and `parse_result` entries. Change the model response parser in `src/sast_triage/providers/parsers.py` if your provider uses a different wrapper. Change extraction of the HTTP response in `providers/response.py`; request schema lives in `providers/request.py`.

## Sensitive data

The trace can include proprietary source code and model answers. It is stored locally with restrictive file permissions (0600 on POSIX). It is ignored by git and never bundled in released archives. `TRACE_INCLUDE_CONTENT=false` keeps event structure but masks textual payloads; `TRACE_ENABLED=false` disables it. Do not share traces without reviewing embedded code and identifiers. API key fields and common `sk-...` tokens are redacted, but this is not comprehensive secret scanning.
