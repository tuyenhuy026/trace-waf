# TRACE-WAF checkpoint protocol

Protocol established before new endpoint measurements. Legacy results remain in
`results/`; new evidence is under `results/checkpoint/`.

## Questions and scope

RQ1: Do model-generated variants remain effective on a real backend and evade
CRS more often than deterministic mutations, under the same candidate budget?
RQ2: Do model-proposed rule changes improve the coverage/FPR trade-off relative
to stock CRS and documented non-LLM tuning?
RQ3: Can evidence-linked approval, staged replay and rollback be executed?

SQLi, browser-confirmed XSS and filesystem traversal are all included. CVE
reproductions are separate from purpose-built CWE fixtures: do not label a toy
fixture as a CVE reproduction. No production-readiness claim is permitted.

## Controls

- Bind published vulnerable services only to localhost; use synthetic data.
- Record image digests, software versions, UTC timestamps and API aliases.
- Keep dev, validation and test families separate. Generated descendants inherit
  their parent's split. Only dev observations may enter model prompts.
- Freeze corpus and candidate rules before final test. Never tune on test errors.
- All attack candidates first require an application oracle without WAF.
  Invalid or uncertain candidates are reported, not counted as WAF bypasses.
- Block means WAF rejection; protection additionally requires absence of the
  oracle effect. HTTP 200 alone is not exploit success.
- Compare stock CRS, documented heuristic tuning and gpt-6-luna only (user
  scope amendment before endpoint evaluation). Prior other-model API probes are
  retained as infrastructure records, excluded from the main experiment.
- Five independent generation attempts per model and role, fixed prompt schema,
  maximum 12 payload candidates per attempt and one rule proposal per attempt.
  Preserve failures and raw responses. No silent retries or hand-repaired output.
- Select rules on validation only: coverage >= 0.90, FPR <= 0.05, transformed
  valid-attack recall >= 0.85. These are illustrative lab gates, not industry
  deployment thresholds. Rank passing rules by FPR, then coverage, then ID.
- Rule proposals use a constrained declarative schema compiled to ModSecurity;
  arbitrary model-written configuration is never executed. Report this restriction.
- Before the validation study, add a functional gate: no uncertain measurements,
  benign response regressions or missing CWE strata. Preserve the stock proxy
  error-page override in all branches and report its observed dev regression.
  The rule study freezes all candidates before measuring validation. No automatic
  test execution occurs even if a candidate passes validation.
- Report per-CWE counts, validity, deduplication, latency and token use; no
  significance claim with a small number of independent families.
- Drift is controlled replay, not a claim about temporal production drift.
- Single-researcher approval is simulated governance, not independent review.

## Completion

Separate implementation completion, evidence quality, and deployment approval.
Missing API/model/CVE evidence must appear explicitly in the report checklist.
Replaying saved API responses reproduces evaluation, not model generation.
