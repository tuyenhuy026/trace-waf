"""One-shot descriptive held-out evaluation; no API calls or policy selection."""
import fcntl
import json
from pathlib import Path
import shutil

from run_baseline import EVIDENCE, ROOT, digest, save, load_cases
from run_rule_study import evaluate

SOURCE = EVIDENCE/'rule-study/20261016T170642475819Z'
OUTPUT = EVIDENCE/'final-test'


def main():
    with (EVIDENCE/'rule-study.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        raw=(SOURCE/'frozen-plan.json').read_bytes()
        if digest(raw)!=(SOURCE/'frozen-plan.sha256').read_text().strip():
            raise ValueError('Source plan mismatch')
        plan=json.loads(raw)
        prior=json.loads((SOURCE/'study-summary.json').read_text())
        if not prior['rollback']['restored'] or len(prior['results'])!=7:
            raise ValueError('Completed seven-policy validation required')
        load_cases('test',False)
        for candidate in plan['candidates']:
            config=(SOURCE/f"{candidate['id']}.conf").read_bytes()
            if digest(config)!=candidate['rule_sha256']:
                raise ValueError('Frozen candidate mismatch')
        OUTPUT.mkdir(exist_ok=False)
        for candidate in plan['candidates']:
            shutil.copyfile(SOURCE/f"{candidate['id']}.conf", OUTPUT/f"{candidate['id']}.conf")
        save(OUTPUT/'test-protocol.json',{
            'source_plan_sha256':digest(raw),'candidate_hashes':plan['candidates'],
            'corpus_sha256':plan['corpus_sha256'], 'api_calls':0,
            'selection_allowed':False, 'validation_decision':prior['decision'],
            'purpose':'One descriptive test pass per frozen policy; no tuning or deployment approval',
            'runner_sha256':digest((ROOT/'lab/run_baseline.py').read_bytes()),
            'orchestrator_sha256':digest((ROOT/'lab/run_rule_study.py').read_bytes())})
        evaluate(OUTPUT,plan,split='test')


if __name__=='__main__':
    main()
