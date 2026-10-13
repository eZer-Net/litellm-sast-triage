# Architecture

The project separates terminal orchestration, source access, provider transport, response parsing and SAST normalization. No fixed `workspace/` directory is required.

```text
litellm-sast-triage/
├── agent.py                         # Stable Python entry point
├── .env.example                     # Documented configuration template
├── prompt.txt                       # Editable security-analysis instructions
├── install.sh                       # Python and environment bootstrap
├── Dockerfile / compose.yaml        # Container deployment
├── README.md / LICENSE              # Entry documentation and MIT license
├── output/                          # Generated JSON, Markdown, trace JSONL
├── src/sast_triage/
│   ├── cli/main.py                  # CLI flags, interactive project input, reports
│   ├── core/triage.py               # Analysis loop, evidence checks, budgets
│   ├── core/trace.py                # Per-turn diagnostic logging
│   ├── source/explorer.py           # Read/find, source outlines, evidence cache
│   ├── source/tools.py              # Read-only tool dispatch
│   ├── parsers/sast.py              # Input SAST adapter and normalization
│   └── providers/
│       ├── litellm.py               # HTTP client, retry, timing
│       ├── request.py               # Provider request envelope
│       ├── response.py              # Provider response envelope
│       └── parsers.py               # Tolerant model-command decoder
├── docs/en/ + docs/ru/             # Developer and operator guides
└── tests/                            # Unit and regression tests
```

**Extension boundaries:** scanner-specific changes stay in `parsers/sast.py`; provider envelope changes stay in `providers/{request,response}.py`; new command syntax stays in `providers/parsers.py`. `core/triage.py` does not know the upstream scanner JSON layout.
