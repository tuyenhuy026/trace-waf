"""One strict, fixed GO/NO-GO evaluator. Never edits evidence or thresholds.

LAB_GO requires independent prospective trial evidence, conservative metrics,
zero regressions/uncertainties, verified rollback AND CVE direct+patched+CRS.
No output of this program is a production deployment authorization.
"""
from __future__ import annotations
import argparse,json
from pathlib import Path

THRESHOLDS={"coverage_min":.90,"fpr_max":.05,"robustness_min":.85,
            "min_valid_families_per_cwe":2,"min_benign":40,
            "max_uncertain":0,"max_benign_regression":0}

def assess(trial,cve):
 reasons=[]
 if trial.get("status")!="EVALUATED":reasons.append("trial_incomplete")
 if not trial.get("frozen_before_test"):reasons.append("not_pre_registered")
 if not trial.get("rollback_verified"):reasons.append("rule_rollback_unverified")
 if not trial.get("no_test_tuning"):reasons.append("test_contamination")
 if trial.get("direct_oracle_stable") is not True:reasons.append("direct_oracle_drift")
 if trial.get("run_counts",{}).get("B1")!=92 or trial.get("run_counts",{}).get("G2")!=92:
  reasons.append("incomplete_confirmatory_trial")
 if trial.get("model_requested")!=trial.get("model_response"):
  reasons.append("unverified_model_identity_metadata")
 cand=trial.get("candidate",{})
 for name,minval in (("coverage",.9),("robustness",.85)):
  if not isinstance(cand.get(name),(int,float)) or cand[name]<minval:reasons.append(name)
 if not isinstance(cand.get("fpr"),(int,float)) or cand["fpr"]>.05:reasons.append("fpr")
 if int(cand.get("benign_n",0))<40:reasons.append("benign_sample_too_small")
 if int(cand.get("valid_attack_n",0))<10:reasons.append("too_few_valid_attacks")
 if int(cand.get("valid_transformed_n",0))<5:reasons.append("too_few_valid_transformed")
 base=trial.get("baseline",{})
 if any(not isinstance(base.get(k),(int,float)) for k in ("coverage","fpr","robustness")):
  reasons.append("baseline_metrics_missing")
 else:
  if (not isinstance(cand.get("coverage"),(int,float)) or
      not isinstance(cand.get("robustness"),(int,float)) or
      not isinstance(cand.get("fpr"),(int,float))):
   reasons.append("candidate_metrics_missing")
  else:
   if (cand["coverage"]+1e-8<base["coverage"] or cand["robustness"]+1e-8<base["robustness"]
       or cand["fpr"]>base["fpr"]+1e-8):reasons.append("not_noninferior_to_nonLLM_control")
   if not (cand["coverage"]>base["coverage"]+1e-8 or
           cand["robustness"]>base["robustness"]+1e-8 or cand["fpr"]<base["fpr"]-1e-8):
    reasons.append("no_measured_advantage_vs_nonLLM")
 if int(cand.get("uncertain_n",999))>0:reasons.append("uncertain_results")
 if int(cand.get("functional_regressions",999))>0:reasons.append("functional_regression")
 by_cwe=cand.get("valid_families_per_cwe",{})
 for cwe in ("CWE-89","CWE-79","CWE-22"):
  if int(by_cwe.get(cwe,0))<2:reasons.append("insufficient_families_"+cwe)
 if not cve.get("cve_confirmed"):reasons.append("CVE_direct_and_patched_not_confirmed")
 if not cve.get("waf_protection_confirmed"):reasons.append("CVE_WAF_not_correlated")
 if cve.get("status")!="CVE_AND_WAF_CONFIRMED":reasons.append("CVE_experiment_incomplete")
 return {"decision":"LAB_GO" if not reasons else "NO_GO",
         "production_deployment_approval":False,
         "scope":"two distinct lab demonstrations (LLM rule on TRACE-WAF fixture; CRS on aiohttp CVE). This is not proof that the LLM rule mitigates that CVE or approval for production.",
         "reasons":reasons,"thresholds":THRESHOLDS}

if __name__=="__main__":
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument("--trial",type=Path,required=True,help="confirmatory-summary.json")
 p.add_argument("--cve",type=Path,required=True,help="cve_v2_summary.json")
 args=p.parse_args()
 r=assess(json.loads(args.trial.read_text()),json.loads(args.cve.read_text()))
 print(json.dumps(r,ensure_ascii=False,indent=2))
 raise SystemExit(0 if r["decision"]=="LAB_GO" else 2)
