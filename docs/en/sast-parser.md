# SAST adapter: adding a scanner

**Files:** `src/sast_triage/parsers/sast.py`. Two public functions form the integration boundary: `parse_scan(path)` reads a report and returns a list of raw findings; `normalize_alert(raw)` converts one finding into the stable internal schema.

| Normalized field | Required | Contract |
|---|---|---|
| `name` | Yes | Non-empty rule/finding identifier |
| `path` | Yes | Source file path **relative to the selected project** |
| `start.line` | Yes | Positive integer, 1-based |
| `end.line` | Yes | Positive integer, 1-based, not before start |
| `start.col`, `end.col` | No | Columns when available |
| `cwe` | No | CWE identifier or description; default empty string |
| `message` | No | Scanner description; default empty string |

**Steps:** (1) Change `parse_scan()` to locate the source scanner's findings array. (2) Map fields in `normalize_alert()` to the above contract. (3) Add one fixture/test for the new schema. Do not edit the LLM loop or report writer. The original finding is preserved as input and transformed before the agent reads its exact source range.

```python
return {
    'name': raw['rule_id'], 'path': raw['location']['file'],
    'start': {'line': raw['location']['start_line']},
    'end': {'line': raw['location']['end_line']},
    'cwe': raw.get('cwe', ''), 'message': raw.get('description', ''),
}
```

**Safety:** project files are read-only and must remain inside the selected root. Coordinates should refer to the source revision that was scanned.
