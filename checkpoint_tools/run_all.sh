#!/usr/bin/env bash
# TRACE-WAF explicit local lab checkpoint orchestration. No GPT by default.
set -u
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$HERE/.." || exit 3

if [ "${1:-}" != "--i-own-local-lab" ]; then
  echo 'Usage: bash checkpoint_tools/run_all.sh --i-own-local-lab [--with-llm]'
  echo 'Only run on YOUR authorized Docker localhost lab. GPT calls are OFF by default.'
  exit 2
fi
WITH_LLM=0
if [ "${2:-}" = "--with-llm" ]; then WITH_LLM=1; fi
if [ -x .venv/bin/python ]; then PY=.venv/bin/python; else PY=python3; fi

printf '\n[1/6] Unit tests (never invoke Docker or GPT)\n'
"$PY" -m unittest discover -s checkpoint_tools/tests -v || exit 2
printf '\n[2/6] Docker localhost lab\n'
docker compose -f lab/compose.yaml up -d || exit 2
printf '\n[3/6] Frozen final test one-shot continuation\n'
"$PY" checkpoint_tools/final_test.py --preflight || exit 2
if [ -d results/checkpoint/final-test-continuation/20261016T170642475819Z ]; then
  "$PY" checkpoint_tools/final_test.py --resume
else
  "$PY" checkpoint_tools/final_test.py --run
fi
FINAL_RC=$?
if [ "$FINAL_RC" -ne 0 ]; then
  echo "Final test did not complete cleanly (code $FINAL_RC). Preserve evidence; no test retries."
fi

printf '\n[4/6] Isolated aiohttp CVE-2024-23334 proof/control\n'
"$PY" checkpoint_tools/cve_2024_23334.py --run
CVE_RC=$?
if [ "$CVE_RC" -ne 0 ]; then echo "CVE case status incomplete: $CVE_RC"; fi

printf '\n[5/6] Controlled drift replay with explicit lab-canary approval\n'
if [ "$FINAL_RC" -eq 0 ]; then
  "$PY" checkpoint_tools/drift_replay.py --run --approve-canary
  DRIFT_RC=$?
else
  echo 'SKIPPED: held-out final test needs audit/continuation first.'
  DRIFT_RC=9
fi
if [ "$WITH_LLM" -eq 1 ]; then
  printf '\n[optional] One bounded DEV-only gpt-6-luna call\n'
  "$PY" checkpoint_tools/optional_llm_dev.py --run --reps 1 || true
fi

printf '\n[6/6] Evidence ZIP for report update\n'
"$PY" checkpoint_tools/bundle_evidence.py
BUNDLE_RC=$?
echo 'Note: report conclusions remain NO-GO; upload the evidence ZIP for review.'
if [ "$BUNDLE_RC" -ne 0 ]; then exit "$BUNDLE_RC"; fi
if [ "$FINAL_RC" -ne 0 ] || [ "$CVE_RC" -ne 0 ] || [ "$DRIFT_RC" -ne 0 ]; then
  echo 'Some studies remain incomplete; see the evidence manifest for details.'
  exit 4
fi
echo 'All three collection stages finished; verify evidence before claiming scientific completion.'
