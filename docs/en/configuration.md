# Configuration

Configure a single `.env` file in the application root. The CLI flags `--project`, `--scan`, `--resultName` override their corresponding `.env` settings. The SAST report is resolved **inside the selected source project**; the result files are written to application `output/`. `AI_API_KEY` must not be committed.

| Variable | Example/default | Purpose |
|---|---|---|
| `AI_BASE_URL` | `https://llm.example.com/v1/chat/completions` | LiteLLM/OpenAI-compatible chat-completions endpoint |
| `AI_API_KEY` | `<secret>` | Authentication token; never commit this value |
| `AI_MODEL` | `your-model-id` | Model identifier served by the gateway |
| `AI_PROTOCOL` | `json` | `json` for text commands, `native` for provider function calling |
| `AI_TEMPERATURE` | `0` | Generation temperature; 0 recommended for repeatability |
| `AI_TIMEOUT_SECONDS` | `120` | Per-request HTTP timeout, seconds |
| `AI_MAX_RETRIES` | `3` | Retries for transport/API failures |
| `AI_RETRY_BACKOFF_SECONDS` | `3` | Delay before retrying a failed API call, seconds |
| `AI_REQUEST_PAUSE_SECONDS` | `2` | Minimum pause between model API requests, seconds |
| `ALERT_PAUSE_SECONDS` | `60` | Pause between findings, seconds |
| `PROJECT_DIR` | `` | Source project directory; empty prompts in interactive mode; `--project` overrides |
| `SCAN_FILE` | `scan-all.json` | SAST result filename/path relative to project; `--scan` overrides |
| `RESULT_NAME` | `triage-result-ai` | Prefix for the timestamped output name (`dd.mm.yyyy-HH-MM-SS`); `--resultName` replaces the generated name |
| `PROMPT_FILE` | `prompt.txt` | Agent instructions file, relative to application root |
| `TAINT_DEPTH` | `5` | Maximum useful source-inspection tool steps per finding |
| `MAX_WHOLE_FILE_LINES` | `350` | Maximum file length eligible for whole-file read |
| `CONTEXT_MODE` | `smart` | Initial/source reading strategy: `window`, `smart`, `symbol` |
| `CONTEXT_BEFORE` | `12` | Context lines before matched range |
| `CONTEXT_AFTER` | `12` | Context lines after matched range |
| `MAX_SYMBOL_LINES` | `120` | Maximum lines in an extracted function/class |
| `MAX_BLOCK_LINES` | `200` | Maximum lines returned by a source block |
| `MAX_FIND_MATCHES` | `30` | Maximum raw search matches |
| `MAX_FIND_BLOCKS` | `4` | Maximum code blocks returned by a search |
| `MAX_TOOL_ERRORS` | `4` | Maximum rejected/invalid tool operations before recovery |
| `MAX_PROTOCOL_ERRORS` | `4` | Maximum unparseable assistant messages |
| `MAX_TOTAL_TURNS` | `25` | Upper bound for requests per finding |
| `TRACE_ENABLED` | `true` | Write a per-request JSONL diagnostic trace |
| `TRACE_INCLUDE_CONTENT` | `true` | Include model messages and source in trace; confidential |
| `TRACE_MAX_CHARS` | `100000` | Maximum logged string length in trace |

**Example:** `python3 agent.py --project /repos/app --scan reports/findings.json --resultName audit`.

Without `--resultName`, the CLI generates one local-time name per run (for example `triage-result-ai-13.10.2026-09-14-30`), and uses it for `.json`, `.md`, and `.trace.jsonl`. Interactive mode asks whether to use a custom name. Existing outputs are never overwritten; a `-01` suffix is added on collision. Colons are deliberately avoided for Windows compatibility.
