# GPT-only rule validation study

## Compiler correction replay

Compiler v2 represents literal quote tokens as PCRE hex escapes instead of
rejecting every expression containing a double quote. It retains control-character,
size and scope restrictions; quoted PCRE regions needing special handling are
rejected explicitly. Apache remains the authoritative syntax check before loading.

Replay saved proposals in a new study without API calls:

```bash
.venv/bin/python lab/run_rule_study.py --replay-study results/checkpoint/rule-study/20261016T170028748633Z
```

The original study and raw responses are preserved. Replaying these responses
does not constitute new independent generations. Proxy settings and validation
data stay unchanged so the replay isolates the compiler correction. Unit tests
cover quote/backslash semantics and prevention of configuration injection.

## Original generation workflow

From the project root, after the completed dev baseline:

```bash
.venv/bin/python lab/run_rule_study.py
```

The runner uses the most recent completed dev baseline. To select it explicitly:

```bash
.venv/bin/python lab/run_rule_study.py --dev-run results/checkpoint/baseline/20261016T165121499202Z-dev
```

It performs five sequential calls to gpt-6-luna, using only dev evidence; stores
raw requests, responses and failures; validates the proposed JSON; freezes all
candidates; then evaluates B0 (stock CRS), B1 (fixed scoped tuning), and accepted
GPT candidates on validation. It never accesses test requests or calls other
models. Expect several minutes and five API calls. No silent repair/retry is used.

The constrained policy can exclude q from selected CRS attack tags on verified
escaping routes /docs and /search, and add up to three scoped blocking patterns.
It cannot disable the engine, exempt vulnerable routes, execute commands, or
inject arbitrary ModSecurity directives. This constrained policy space limits
the scientific claim: it is not unrestricted autonomous rule synthesis.

Apache checks candidate configuration syntax before activation. WAF alone is
recreated for each candidate; a response header verifies the active policy. The
same backend stays running. Direct oracle outcomes are compared against B0 to
detect measurement drift. Configuration syntax errors are recorded as rejected.

The runner restores the original rules and recreates WAF in a finally block.
`rollback.json` records both byte equality and the health/header check. A killed
process or machine shutdown cannot guarantee finally; inspect the original
snapshot and rollback evidence before resuming an interrupted run. Do not run a
baseline experiment concurrently with this study.

Outputs are in a new `results/checkpoint/rule-study/<UTC>/` directory. Send the
last terminal summary and path, or `study-summary.json`, for review. Do not paste
raw prompts, observations or rule contents into chat unnecessarily.

To separate API generation from local validation:

```bash
.venv/bin/python lab/run_rule_study.py --prepare-only
.venv/bin/python lab/run_rule_study.py --evaluate-prepared results/checkpoint/rule-study/REPLACE_WITH_PRINTED_DIRECTORY
```

The second command makes no API calls. Completed or interrupted studies cannot
be silently overwritten. Keep their evidence and create a new study if needed.

## Interpretation

The measured dev pilot has 17 blocked effective attacks, 37 candidates without
observed effect, five false positives, ten true negatives and one benign content
regression. The regression coincides with the stock proxy's
`PROXY_ERROR_OVERRIDE=on`; it is not relabeled or silently fixed between branches.
This setting and the exact-response criterion may prevent every candidate from
passing the functional gate. NO_GO is a valid research result.

The non-LLM control is explicitly a fixed policy chosen using dev semantics; it
is not claimed to represent all expert tuning methods. Five model calls assess
within-alias variation, not differences between model families. Requests through
the custom gateway identify a service alias, not independently verified weights.

The existing validation corpus is small and shares some benign cases and
traversal semantics with dev. Treat this as a lab pilot, not independent exploit
family generalization or evidence of CVE protection. Final test, CVE reproduction,
controlled drift, and report generation remain separate subsequent stages.
