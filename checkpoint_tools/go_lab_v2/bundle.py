"""Export integrity-hashed GO-lab-v2 evidence only, without .env/API secrets.

Output is the only file to send for report updates. It makes NO GO claim by
itself; read the separate gate decision and the detailed measurement journals.
"""
from pathlib import Path
import argparse,datetime,hashlib,json,zipfile
ROOT=Path(__file__).resolve().parents[2]
EXP=ROOT/'results'/'checkpoint'/'go-lab-v2'

def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--output',type=Path,default=None)
 args=parser.parse_args()
 assert EXP.exists(),f'No new go-lab-v2 evidence in {EXP}'
 files=[]
 for p in sorted(EXP.rglob('*')):
  if p.is_file() and not p.is_symlink() and p.stat().st_size<20_000_000:
   files.append(p)
 for name in ['checkpoint_tools/go_lab_v2/cve_compose.yaml','checkpoint_tools/go_lab_v2/lab_override.yaml']:
  p=ROOT/name
  if p.exists():files.append(p)
 assert files,'No evidence found'
 utc=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
 dest=(args.output or (ROOT/'results'/'checkpoint'/f'TRACE_WAF_GO_LAB_V2_EVIDENCE_{utc}.zip')).resolve()
 manifest={'created_utc':utc,'gate_conclusion':'READ go_gate.py output; not implied by zip',
           'no_production_approval':True,
           'files':[{'path':str(p.relative_to(ROOT)),'size':p.stat().st_size,'sha256':digest(p)} for p in files]}
 with zipfile.ZipFile(dest,'x',zipfile.ZIP_DEFLATED,compresslevel=8) as z:
  for p in files:z.write(p,str(p.relative_to(ROOT)))
  z.writestr('EVIDENCE_MANIFEST.json',json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'zip':str(dest),'files':len(files),'size':dest.stat().st_size},ensure_ascii=False,indent=2))
if __name__=='__main__':main()
