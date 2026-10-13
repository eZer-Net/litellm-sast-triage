# Triage engine: evidence controls

The CLI is intended to make small or protocol-inconsistent models more useful in SAST triage. These mechanisms improve auditability; **they do not guarantee accurate classifications or formally prove exploitability**.

| Mechanism | Effect |
|---|---|
| Exact scanner coordinates | Always supplies the actual flagged source line and surrounding code |
| Python-aware source outline | Lists nearby functions/classes so the model can request relevant definitions |
| Adaptive `read` / `find` | Reads whole small files; otherwise supplies bounded code regions |
| Same-file-first search | Prioritizes matches in the finding's file over similarly named symbols elsewhere |
| Evidence cache | Rejects repeated reads and overlaps that contain no new source |
| Bounded search and turn budgets | Avoids endless calls and forces an explicit final state |
| Tolerant response adapter | Decodes common provider-specific and JSON-like commands; reports ambiguity |
| Source/sink location checks | Ensures referenced `file:line` ranges were actually shown to the model |
| CWE-specific TP review | Challenges conflated vulnerability classes and missing guards/propagation |
| Neutral recovery | Requests missing evidence without forcing `FP` after a rejected `TP` |
| Diagnostic JSONL | Records prompts, responses, parsing outcomes and tool results for debugging |
| Incremental reports | Saves JSON and Markdown after each finding |

**Evidence boundary:** a verified `file:line` reference is only a location check, not a validated data-flow edge. For difficult paths the correct outcome may remain `NEEDS_REVIEW`.
