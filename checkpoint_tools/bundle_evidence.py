"""Create a source-hashed evidence ZIP for later academic report updates.

No secrets or whole-repository snapshots. Default excludes optional raw model
prompts/replies; include only when user knowingly opts in.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import json
from pathlib import Path
import sys
import zipfile
import common as c


def selected_files(include_llm_raw=False):
    roots=[c.RECOVERY,c.CP/'cve-2024-23334',c.CP/'drift-replay',
           c.CP/'llm-exploratory-dev-20261017']
    result=[]
    for root in roots:
        if root.exists():
            for p in root.rglob('*'):
                if not p.is_file() or p.is_symlink(): continue
                if not include_llm_raw and 'responses' in p.parts:
                    continue
                if p.stat().st_size>20_000_000:
                    continue
                result.append(p)
    for path in (c.STUDY/'frozen-plan.json',c.STUDY/'frozen-plan.sha256',
                 c.STUDY/'study-summary.json',c.PRIOR/'test-protocol.json'):
        if path.exists(): result.append(path)
    return sorted(set(result))


def completion():
    final=c.RECOVERY/'test-summary.json'
    f=c.read_json(final) if final.exists() else {}
    cves=sorted((c.CP/'cve-2024-23334').glob('*/cve-summary.json')) if (c.CP/'cve-2024-23334').exists() else []
    cve=c.read_json(cves[-1]) if cves else {}
    drifts=sorted((c.CP/'drift-replay').glob('*/drift-summary.json')) if (c.CP/'drift-replay').exists() else []
    drift=c.read_json(drifts[-1]) if drifts else {}
    llmp=c.CP/'llm-exploratory-dev-20261017'/'exploratory-summary.json'
    llm=c.read_json(llmp) if llmp.exists() else {}
    return {'final_7_candidates_complete':bool(f.get('all_seven_complete')),
        'final_rollback_verified':bool(f.get('rollback_verified')),
        'cve_product_version_control_confirmed':bool(cve.get('cve_reproduction_confirmed')),
        'cve_has_conclusive_waf_evidence':bool(cve.get('conclusive_waf_probes')),
        'cve_latest_status':cve.get('status','NOT_RUN'),
        'drift_live_replay_finished':drift.get('status')=='REPLAY_FINISHED',
        'drift_canary_evaluated':bool(drift.get('lab_canary_evaluated')),
        'drift_rollback_verified':bool(drift.get('rollback',{}).get('restored')),
        'autonomous_adaptation_proven':False,
        'extra_luna_dev_status':llm.get('status','NOT_RUN'),
        'checkpoint_gate':'NO_GO'}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,help='Optional local .zip destination.')
    ap.add_argument('--include-llm-raw',action='store_true',help='Include raw dev-only prompts and model replies (review before sharing).')
    args=ap.parse_args()
    files=selected_files(args.include_llm_raw)
    summary=completion()
    out=args.output or c.CP/('TRACE_WAF_EVIDENCE_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.zip')
    out=out.expanduser().resolve()
    out.parent.mkdir(parents=True,exist_ok=True)
    manifest={'created_utc':c.now(),'repo':'tuyenhuy026/trace-waf',
              'checkpoint':'20261016T170642475819Z',
              'checks':summary,'files':[],'raw_llm_included':args.include_llm_raw,
              'limitations':['The ZIP contains measured outputs, not proof of independently reproduced infrastructure.',
                'No payloads or candidate rules were altered for scoring.',
                'No CVE success claim without direct vulnerable-versus-patched oracle.',
                'NO-GO remains; additional test data never changes policy selection.']}
    with zipfile.ZipFile(out,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=7) as archive:
        for p in files:
            rel=p.relative_to(c.ROOT).as_posix()
            archive.write(p,arcname=rel)
            manifest['files'].append({'path':rel,'bytes':p.stat().st_size,'sha256':c.digest_path(p)})
        archive.writestr('EVIDENCE_MANIFEST.json',json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
        archive.writestr('README_EVIDENCE.txt',
            'TRACE-WAF locally collected checkpoint evidence.\n'
            'Inspect EVIDENCE_MANIFEST.json for status and all SHA-256 hashes.\n'
            'Send this ZIP to the assistant for report updates. NO-GO remains unchanged.\n'
            'This archive does not contain the entire Git repository or all old historical logs.\n')
    print(json.dumps({'zip':str(out),'size_bytes':out.stat().st_size,
                     'files':len(files),'checks':summary},ensure_ascii=False,indent=2))


if __name__=='__main__':
    try: main()
    except Exception as exc:
        print('BUNDLE FAILED: '+str(exc),file=sys.stderr);sys.exit(2)
