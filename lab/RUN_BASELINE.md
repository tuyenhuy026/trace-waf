# Local baseline runner

Run from the project root with the existing `.venv`. This runner never calls an
LLM, edits rules or starts containers. Only 127.0.0.1:18080 and :18081 receive
requests. Chrome renders captured responses with subsequent networking blocked.

## Commands

```bash
.venv/bin/python lab/run_baseline.py --check --include-llm
.venv/bin/python lab/run_baseline.py --split dev --include-llm
```

The first command validates the frozen corpus, checks health and browser controls,
and snapshots the environment. It does not execute corpus cases. The second runs
the dev corpus and eligible saved GPT candidates. It does not query an API.
Do not open the test split until candidate policies and selection are frozen.

Requirements: `requests`, `playwright`, Docker services already running. On this
Mac, Google Chrome is detected automatically. Else use `--browser-path PATH` or
install Playwright Chromium with `.venv/bin/python -m playwright install chromium`.

## Outputs

Every invocation creates a new directory under `results/checkpoint/baseline/`.
No earlier run is overwritten. `summary.json` only appears after the request loop
completes. An interrupted run retains a partial observations journal.

- `input-audit.json`: frozen hash, cross-split exact overlap, rejected model rows.
- `cases.json`: exact selected input snapshot, provenance and duplicate markers.
- `manifest.json`: software and container identity, hashes and measurement limits.
- `observations.jsonl`: request ID, direct/WAF responses, timing and oracle result.
- `summary.json`: case-weighted and within-source-deduplicated counts/metrics.
- `backend-logs.json`, `waf-logs.json`: commands and captured service logs.
- `dev-baseline.json`: dev observations only, for subsequent reviewed rule prompts.

Share only the terminal aggregate summary or `summary.json` for initial review.
The observations and logs contain raw test inputs and stay in the project.

## Interpretation

HTTP 200 is not an attack oracle. SQL requires the fixture marker in parsed rows;
traversal requires the exact file marker; XSS requires the browser flag within
750 ms. A missing marker means not observed in this fixture, not universally safe.
Encoded strings are sent as literal q values via normal HTTP parameter encoding;
the resulting extra encoding is recorded in the request, not silently removed.

Only candidates effective directly and evaluable through WAF enter attack recall.
Invalid samples and infrastructure/oracle failures are separately counted. WAF
blocking is inferred from 403 without the backend request-ID echo and must be
corroborated against saved WAF logs. Benign response mismatches are regressions,
not true negatives. N/A rates have a null denominator, never an invented zero.

The existing corpus has related grammars and repeated benign fixtures across
splits. Identifier separation is not independent-family generalization. Exact
deduplication does not remove semantic dependence. The model and heuristic
candidate budgets are unequal here: this is a baseline pilot, not a budget-matched
generator superiority claim. No CVE verification, policy approval or uncertainty
interval is inferred by this script.

Saved GPT calls with readable JSON but no cases are not successful generation.
Missing or mismatched parent IDs are rejected rather than repaired. Other models
are excluded. All generated descendants stay in dev.
