"""One prospective local-only LLM-vs-heuristic WAF rule trial (NOT a retest).

--prepare: freezes a fresh corpus and gate; calls a local LLM once; compiles
whitelisted JSON policy as G2 and hashes it. Model actual response metadata is
preserved, and a mismatched model name aborts the LLM-origin assertion.
--evaluate: one run of both B1 and G2 on the frozen cohort, same proxy settings;
no generation or tuning allowed during evaluation. Preserves any interruption.
A second --evaluate cannot overwrite its own observations.
"""
from __future__ import annotations
import argparse,contextlib,datetime,fcntl,hashlib,html,json,os,subprocess,sys,time
from pathlib import Path
import urllib.request,urllib.error

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
CHECK=ROOT/"results"/"checkpoint"
STUDY=CHECK/"rule-study"/"20261016T170642475819Z"
ACTIVE=ROOT/"lab"/"active-rules.conf"
COMPOSE=["docker","compose","-f","lab/compose.yaml","-f","checkpoint_tools/go_lab_v2/lab_override.yaml"]
BASE_COMPOSE=["docker","compose","-f","lab/compose.yaml"]
FROZEN_PLAN_SHA="80897b18898c5e90285e47de12f5de3acd4f14cf620cf802380537a2f592f5a3"
GATE={"coverage_min":.9,"fpr_max":.05,"robustness_min":.85,"min_valid_families_per_cwe":2,"min_benign":40,"zero_uncertain":True,"zero_regressions":True}

def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(data):return hashlib.sha256(data).hexdigest()
def dsha(path):return sha(path.read_bytes())
def save(p,o):
 p.parent.mkdir(parents=True,exist_ok=True)
 with p.with_suffix(p.suffix+".new").open('w',encoding='utf-8') as fh:
  json.dump(o,fh,ensure_ascii=False,indent=2);fh.write("\n");fh.flush();os.fsync(fh.fileno())
 os.replace(p.with_suffix(p.suffix+".new"),p)
def load(p):return json.loads(p.read_text(encoding='utf-8'))
def ck(cond,msg):
 if not cond:raise RuntimeError(msg)
def command(args,out=None,timeout=160):
 try:
  c=subprocess.run(args,cwd=ROOT,capture_output=True,text=True,timeout=timeout)
  r={"args":args,"returncode":c.returncode,"stdout":c.stdout[-200000:],"stderr":c.stderr[-40000:],"utc":now()}
 except (OSError,subprocess.TimeoutExpired) as e:r={"args":args,"error":str(e),"utc":now()}
 if out:save(out,r)
 return r

def baseline_module():
 sys.path.insert(0,str(ROOT/"lab"))
 import run_baseline as rb
 return rb

def policy_compiler():
 sys.path.insert(0,str(ROOT/"lab"))
 from run_rule_study import compile_policy
 return compile_policy

def llm_prompt():
 return """You are reviewing one authorized localhost-only TRACE-WAF training lab.
Propose ONE conservative JSON rule policy; no shell commands, raw ModSecurity directives or control of deployment.
The schema MUST be exactly {\"exempt_routes\": [\"/docs\",\"/search\"], \"patterns\": [{\"route\":\"/sql\",\"regex\":\"...\"}, {\"route\":\"/xss\",\"regex\":\"...\"}, {\"route\":\"/file\",\"regex\":\"...\"}], \"rationale\":\"...\", \"risks\":\"...\"}.
Route semantics: /sql is a deliberately vulnerable SQLite concat query, /xss renders an unsafe HTML fragment, /file reads a synthetic canary if traversal is effective; /docs and /search HTML-escape q. A policy must preserve benign functionality and avoid false positives, not merely block more attacks. Report risks of regex on SQL comments and legitimate strings. Only dev-side observations are supplied: CRS stock FP is high, a fixed non-LLM route-level adjustment helps but benign false positives persist. Heuristic control and all LLM proposals must be tested at the same CRS paranoia level. Restrict to 2 route exemptions and at most 3 regex patterns each <=512 chars, compiled by a separate restricted compiler. DO NOT change anomaly threshold or disable WAF globally. The /sql regex must NOT reject standalone punctuation `--` in a benign string. The /file rules must distinguish permissible public-readme paths from traversal to the synthetic secret. Do not mention any held-out test cases or their results. Return the JSON object only.
"""

def do_prepare(model,endpoint,new_round_rationale=None):
 ck(model in {"gpt-5.6-sol","gpt-6-luna"},"Only explicitly named model IDs supported")
 ck(endpoint=="http://127.0.0.1:20128/v1/chat/completions", "Model gateway must be the fixed localhost address")
 ck((STUDY/"frozen-plan.json").exists() and dsha(STUDY/"frozen-plan.json")==FROZEN_PLAN_SHA,
    "Original checkpoint plan mismatch")
 prior=sorted((CHECK/"go-lab-v2").glob("*/rule-trial/preregistration.json"))
 if prior and not new_round_rationale:
  raise RuntimeError("A prior LLM rule trial already exists. Provide --new-round-rationale to explicitly document why another preregistered round is necessary; never cherry-pick attempts.")
 if new_round_rationale and len(new_round_rationale.strip())<25:
  raise RuntimeError("New-round rationale must explain the technical or scientific reason (minimum 25 characters).")
 # Before any LLM request, write and hash the new test cohort and the gate.
 from cohort import build
 cases=build()
 stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
 trial=CHECK/"go-lab-v2"/stamp/"rule-trial"
 trial.mkdir(parents=True,exist_ok=False)
 save(trial/"frozen_cohort.json",cases)
 manifest={"utc":now(),"experiment":"prospective_demo_lab", "freeze_before_model_request":True,
   "corpus_sha256":dsha(trial/"frozen_cohort.json"),"case_count":len(cases),
   "model_requested":model,"gateway":endpoint,"api_call_budget":1,
   "thresholds":GATE,"candidate":"G2","baseline":"B1","selection_after_test":False,
   "old_checkpoint_untouched":True,"model_prompt_excludes_heldout_cases":True,
   "new_round_rationale":new_round_rationale,
   "previous_registered_rounds":[str(p.relative_to(ROOT)) for p in prior],
   "proxy_override_sha256":dsha(HERE/"lab_override.yaml"),
   "baseline_runner_sha256":dsha(ROOT/"lab"/"run_baseline.py"),
   "policy_compiler_sha256":dsha(ROOT/"lab"/"run_rule_study.py"),
   "backend_source_sha256":dsha(ROOT/"lab"/"backend.py"),
   "limitations":["Fixed new fixture cohort is not a population-random sample.",
                  "Authors know old checkpoint findings; no statistical independence from prior design decisions.",
                  "The returned model alias is provider metadata, not cryptographic model weights."]}
 save(trial/"preregistration.json",manifest)
 prompt=llm_prompt()
 request={"model":model,"messages":[{"role":"user","content":prompt}],
          "temperature":0.2,"max_tokens":2500,"stream":False}
 save(trial/"llm-call-intent.json",{"utc":now(),"request_sha256":sha(json.dumps(request,sort_keys=True).encode()),"model":model})
 record={"requested_model":model,"utc":now(),"request":request}
 try:
  raw=json.dumps(request).encode()
  req=urllib.request.Request(endpoint,data=raw,headers={"Content-Type":"application/json"},method="POST")
  with urllib.request.urlopen(req,timeout=150) as res:
   obj=json.loads(res.read(1500000))
  record["response"]=obj
  actual=obj.get("model")
  record["response_model"]=actual
  if actual!=model:raise RuntimeError(f"model alias mismatch: requested={model} returned={actual}")
  text=obj["choices"][0]["message"]["content"].strip()
  if text.startswith("```"):text=text.split("\n",1)[1].rsplit("```",1)[0]
  policy=json.loads(text)
  if isinstance(policy,dict) and "policy" in policy:policy=policy["policy"]
  compiler=policy_compiler()
  rule=compiler(policy,"G2")  # whitelist compiler, not raw LLM shell/config text
  save(trial/"candidate_policy.json",policy)
  (trial/"G2.conf").write_text(rule,encoding='utf-8')
  (trial/"B1.conf").write_bytes((STUDY/"B1.conf").read_bytes())
  manifest.update({"status":"FROZEN","model_response":actual,
                   "model_response_file_sha256":None,
                   "G2_sha256":dsha(trial/"G2.conf"),"B1_sha256":dsha(trial/"B1.conf")})
  record["status"]="POLICY_COMPILED"
 except Exception as e:
  record["status"]="CALL_OR_COMPILATION_FAILED";record["error"]=f"{type(e).__name__}: {e}"
  manifest["status"]="INCOMPLETE_MODEL_CALL"
 finally:
  save(trial/"llm-response.json",record)
  manifest["model_response_file_sha256"]=dsha(trial/"llm-response.json")
  save(trial/"preregistration.json",manifest)
 print(json.dumps({"trial_dir":str(trial),"status":manifest["status"],"model_response":manifest.get("model_response"),
                   "candidate_hash":manifest.get("G2_sha256")},ensure_ascii=False,indent=2))
 return 0 if manifest["status"]=="FROZEN" else 2

@contextlib.contextmanager
def lock():
 l=CHECK/"rule-study.lock";l.parent.mkdir(parents=True,exist_ok=True)
 with l.open('a+b') as f:
  try:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError as e:raise RuntimeError("Another WAF experiment is using the lab") from e
  yield

def activate(policy_id,policy_bytes,out):
 ACTIVE.write_bytes(policy_bytes)
 r=command(COMPOSE+["exec","-T","waf","httpd","-t"],out/(policy_id+"-syntax.json"),timeout=45)
 # Syntax test in the old container might be stale if override not yet created; recreate follows, then test again.
 r=command(COMPOSE+["up","-d","--no-deps","--force-recreate","waf"],out/(policy_id+"-activate.json"),timeout=170)
 ck(r.get("returncode")==0,"WAF activation failure for "+policy_id)
 r=command(COMPOSE+["exec","-T","waf","httpd","-t"],out/(policy_id+"-syntax-after.json"),timeout=40)
 ck(r.get("returncode")==0,"ModSecurity/Apache syntax invalid for "+policy_id)
 import requests
 deadline=time.monotonic()+65
 while time.monotonic()<deadline:
  try:
   res=requests.get("http://127.0.0.1:18081/health",timeout=2)
   if res.status_code==200 and res.text=="ok" and res.headers.get("X-Trace-Policy")==policy_id:return
  except requests.RequestException:pass
  time.sleep(1)
 raise RuntimeError("WAF did not identify policy "+policy_id)

def measure_case(rb,case,idx,policy,sess,oracle):
 rid=f"trace-go-v2-{policy}-{idx}"
 direct=rb.fetch(sess,case,rb.DIRECT,rid+'-direct');direct['effect']=rb.effect(case,direct,oracle)
 waf=rb.fetch(sess,case,rb.WAF,rid+'-waf');waf['effect']=rb.effect(case,waf,oracle)
 if direct['effect'] is None or waf['effect'] is None:
  outcome="uncertain_oracle_or_infrastructure"
 elif case['intended_attack']:
  if not direct['effect']:outcome="invalid_attack"
  elif waf['effect']:outcome="bypass"
  elif waf.get('status')==403 and waf.get('backend_request_id')!=rid+'-waf':outcome="blocked_attack"
  else:outcome="uncertain_not_waf_block"
 else:
  if direct['effect']:outcome="invalid_benign"
  elif waf.get('status')==403 and waf.get('backend_request_id')!=rid+'-waf':outcome="false_positive"
  elif direct.get('status')!=waf.get('status') or direct.get('body_sha256')!=waf.get('body_sha256'):
   outcome="benign_regression"
  else:outcome="true_negative"
 return {"case":case,"rid":rid,"direct":direct,"waf":waf,"outcome":outcome}

def score(rows):
 from collections import Counter
 atk=[r for r in rows if r['case']['intended_attack']]
 benign=[r for r in rows if not r['case']['intended_attack']]
 valid=[r for r in atk if r['direct'].get('effect') is True]
 transformed=[r for r in valid if r['case']['variant']!='raw']
 total_benign=len(benign)
 n_block=sum(r['outcome']=="blocked_attack" for r in valid)
 n_b_trans=sum(r['outcome']=="blocked_attack" for r in transformed)
 fp=sum(r['outcome']=="false_positive" for r in benign)
 uncertain=sum('uncertain' in r['outcome'] or r['outcome']=="invalid_benign" for r in rows)
 family_counts={cwe:len({r['case']['family'] for r in valid if r['case']['cwe']==cwe}) for cwe in ("CWE-89","CWE-79","CWE-22")}
 return {"coverage":n_block/len(valid) if valid else None,
 "robustness":n_b_trans/len(transformed) if transformed else None,
 "fpr":fp/total_benign if total_benign else None,"benign_n":total_benign,
 "valid_attack_n":len(valid),"valid_transformed_n":len(transformed),
 "valid_families_per_cwe":family_counts,"functional_regressions":sum(r['outcome']=="benign_regression" for r in benign),
 "uncertain_n":uncertain,"outcomes":dict(Counter(r['outcome'] for r in rows))}

def do_evaluate(trial):
 ck(trial.is_dir(),"Trial directory not found")
 pre=load(trial/"preregistration.json")
 ck(pre.get("status")=="FROZEN","Policy was not frozen after a verified model response")
 ck(pre.get("model_requested")==pre.get("model_response"),"Actual LLM model mismatch")
 ck(dsha(trial/"frozen_cohort.json")==pre.get("corpus_sha256"),"Frozen holdout cohort mutated")
 ck(pre.get("thresholds")==GATE,"Pre-registered gate was changed")
 for key,p in [("proxy_override_sha256",HERE/"lab_override.yaml"),
                ("baseline_runner_sha256",ROOT/"lab"/"run_baseline.py"),
                ("policy_compiler_sha256",ROOT/"lab"/"run_rule_study.py"),
                ("backend_source_sha256",ROOT/"lab"/"backend.py")]:
  ck(pre.get(key)==dsha(p),key+" changed since registration")
 ck(dsha(trial/"G2.conf")==pre.get("G2_sha256"),"LLM candidate changed after freeze")
 ck(dsha(trial/"B1.conf")==pre.get("B1_sha256"),"Heuristic baseline changed after freeze")
 ck(dsha(trial/"llm-response.json")==pre.get("model_response_file_sha256"),"Model evidence changed")
 ck(not (trial/"evaluation-started.json").exists(),"This trial has already been started; do NOT rerun after observing test results")
 ck(dsha(STUDY/"frozen-plan.json")==FROZEN_PLAN_SHA,"Historic checkpoint unexpectedly changed")
 rb=baseline_module();cases=load(trial/"frozen_cohort.json")
 ck(len(cases)==92,"Unknown trial corpus; refusing")
 original=(STUDY/"original-rules.conf").read_bytes()
 ck(ACTIVE.read_bytes()==original,"Current WAF configuration is not the original state; stop and inspect")
 lockfile=trial/"evaluation-started.json"
 report={"status":"INCOMPLETE","utc":now(),"frozen_before_test":True,"no_test_tuning":True,
         "corpus_sha256":pre["corpus_sha256"],"model_requested":pre["model_requested"],"model_response":pre["model_response"],
         "run_counts":{},"rollback_verified":False,"direct_oracle_stable":False}
 from playwright.sync_api import sync_playwright
 import requests
 with lock():
  save(lockfile,{"started":now(),"note":"Do not repeat; incomplete trial remains scientific evidence"})
  try:
   info=command(["docker","info","--format","{{.ServerVersion}}"],trial/"docker_info.json",timeout=20)
   ck(info.get("returncode")==0,"Docker daemon unavailable")
   cfg=command(COMPOSE+["config","--quiet"],trial/"compose_config.json",timeout=20)
   ck(cfg.get("returncode")==0,"Compose config invalid")
   command(COMPOSE+["images"],trial/"docker_images.json",timeout=30)
   for policy in ("B1","G2"):
    activate(policy,(trial/(policy+".conf")).read_bytes(),trial)
    pw=sync_playwright().start();browser=pw.chromium.launch(headless=True)
    try:
     oracle=rb.BrowserOracle(browser,750)
     with requests.Session() as sess:
      sess.trust_env=False
      path=trial/(policy+"-observations.jsonl")
      with path.open('x',encoding='utf-8') as f:
       for i,case in enumerate(cases):
        # One write-ahead marker before network; interruptions are not silently retried.
        save(trial/"inflight.json",{"policy":policy,"index":i,"case_id":case["id"],"utc":now()})
        row=measure_case(rb,case,i,policy,sess,oracle)
        f.write(json.dumps(row,ensure_ascii=False)+"\n");f.flush();os.fsync(f.fileno())
        (trial/"inflight.json").unlink()
    finally:
     browser.close();pw.stop()
    report["run_counts"][policy]=len(cases)
    with (trial/(policy+"-observations.jsonl")).open() as f:rows=[json.loads(l) for l in f if l.strip()]
    report["baseline" if policy=="B1" else "candidate"]=score(rows)
    report[(policy+"_observations_sha256")]=dsha(trial/(policy+"-observations.jsonl"))
    l=command(COMPOSE+["logs","--no-color","waf"],timeout=55)
    save(trial/(policy+"-waf-logs.json"),l)
   with (trial/"B1-observations.jsonl").open() as f:base=[json.loads(l) for l in f if l.strip()]
   with (trial/"G2-observations.jsonl").open() as f:comp=[json.loads(l) for l in f if l.strip()]
   compare=lambda x:(x["case"]["id"],x["direct"].get("status"),x["direct"].get("effect"),x["direct"].get("body_sha256"))
   report["direct_oracle_stable"]=([compare(x) for x in base]==[compare(x) for x in comp])
   report["status"]="EVALUATED"
  except Exception as e:
   report["status"]="INCOMPLETE";report["error"]=f"{type(e).__name__}: {e}"
  finally:
   ACTIVE.write_bytes(original)
   res=command(BASE_COMPOSE+["up","-d","--no-deps","--force-recreate","waf"],trial/"rollback-command.json",timeout=170)
   report["rollback_verified"]=res.get("returncode")==0 and ACTIVE.read_bytes()==original
   try:
    r=requests.get("http://127.0.0.1:18081/health",timeout=8)
    report["rollback_verified"]=bool(report["rollback_verified"] and r.status_code==200 and r.text=="ok" and not r.headers.get("X-Trace-Policy"))
   except Exception as e:report["rollback_verified"]=False;report["rollback_error"]=str(e)
   save(trial/"confirmatory-summary.json",report)
 print(json.dumps({"trial":str(trial),"status":report["status"],"rollback":report["rollback_verified"],
      "candidate":report.get("candidate"),"baseline":report.get("baseline"),"error":report.get("error")},ensure_ascii=False,indent=2))
 return 0 if report["status"]=="EVALUATED" and report["rollback_verified"] else 2

if __name__=="__main__":
 parser=argparse.ArgumentParser(description=__doc__)
 actions=parser.add_mutually_exclusive_group(required=True)
 actions.add_argument("--prepare",action="store_true")
 actions.add_argument("--evaluate",type=Path,metavar="TRIAL_DIR")
 parser.add_argument("--model",choices=["gpt-5.6-sol","gpt-6-luna"],default="gpt-5.6-sol")
 parser.add_argument("--new-round-rationale",default=None,help="Required if another trial has already been preregistered; previous evidence is never deleted")
 a=parser.parse_args()
 rc=do_prepare(a.model,"http://127.0.0.1:20128/v1/chat/completions",a.new_round_rationale) if a.prepare else do_evaluate(a.evaluate.resolve())
 raise SystemExit(rc)
