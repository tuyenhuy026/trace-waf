#!/usr/bin/env python3
"""Optional figure recreation: pip install matplotlib; run from package root."""
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

ROOT = Path(__file__).resolve().parents[1]
DATA = json.loads((ROOT / "results/metrics.json").read_text(encoding="utf-8"))
OUT = ROOT / "assets"
OUT.mkdir(exist_ok=True)
COLORS = ["#335170", "#18a49c", "#e59a55"]
plt.rcParams.update({"font.family":"DejaVu Sans", "font.size":11, "axes.spines.top":False, "axes.spines.right":False,
                     "figure.facecolor":"white", "savefig.facecolor":"white"})

rows = [x for x in DATA["metrics"] if x["cwe"] == "ALL"]
names = ["Signature gốc", "Signature chuẩn hóa", "TRACE-Policy"]
labels = [("attack_coverage", "Coverage"), ("fpr", "False-positive rate"), ("evasion_robustness", "Evasion robustness")]
fig, ax = plt.subplots(figsize=(9.8, 4.7), dpi=160)
for i, (metric, label) in enumerate(labels):
    x = [j+(i-1)*.24 for j in range(3)]
    vals = [100*rows[j][metric] for j in range(3)]
    ax.bar(x, vals, width=.22, color=COLORS[i], label=label)
    for xx,v in zip(x,vals):
        ax.text(xx, v+1.4, f"{v:.1f}%", ha="center", va="bottom", fontsize=9.4)
ax.set_xticks(range(3), names)
ax.set_ylim(0,114)
ax.set_ylabel("Tỷ lệ (%)")
ax.set_title("Ba trục đánh giá trên tập synthetic test (n = 570)", loc="left", pad=18, color="#20334d", weight="bold")
ax.grid(axis="y", alpha=.16)
ax.legend(loc="upper center", ncol=3, bbox_to_anchor=(.5, 1.13), frameon=False, fontsize=9.6)
fig.subplots_adjust(left=.08, right=.98, top=.76, bottom=.17)
fig.savefig(OUT / "metrics.png", dpi=180, bbox_inches="tight")
plt.close(fig)

periods = ["A: raw + case", "B: encoded + transform"]
fig, ax = plt.subplots(figsize=(9.2, 4.25), dpi=160)
for j, s in enumerate(("raw_signature", "canonical_signature", "trace_policy")):
    vals = [next(x["recall"] for x in DATA["synthetic_drift"] if x["strategy"]==s and x["period"]==p)*100 for p in ("A_raw_case", "B_encoded")]
    xp=[i+(j-1)*.24 for i in range(2)]
    ax.bar(xp,vals,width=.22,label=names[j],color=COLORS[j])
    for x,v in zip(xp, vals):
        ax.text(x,v+1.1,f"{v:.1f}%",ha="center",fontsize=9.6)
ax.set_xticks(range(2),periods)
ax.set_ylim(0,116)
ax.set_ylabel("Attack recall (%)")
ax.set_title("Mô phỏng dịch chuyển tỷ trọng biến đổi đầu vào",loc="left",pad=15,color="#20334d",weight="bold")
ax.grid(axis="y",alpha=.16)
ax.legend(loc="lower center",bbox_to_anchor=(.5,-.31),ncol=3,frameon=False)
fig.subplots_adjust(left=.1,right=.98,top=.83,bottom=.22)
fig.savefig(OUT / "drift.png", dpi=180, bbox_inches="tight")
plt.close(fig)

fig, ax=plt.subplots(figsize=(11.4, 4.9),dpi=160)
ax.set_xlim(0,12); ax.set_ylim(0,5.2); ax.axis('off')
def card(x,y,w,h,heading,sub,fill="#f1f6fa",stroke="#9fb6c8"):
    patch=FancyBboxPatch((x,y),w,h,boxstyle="round,pad=0.13,rounding_size=.18",facecolor=fill,edgecolor=stroke,lw=1.5)
    ax.add_patch(patch)
    ax.text(x+.2,y+h-.36,heading,fontsize=12,color="#20334d",weight="bold",va="top")
    ax.text(x+.2,y+h-.92,sub,fontsize=9,color="#485a69",va="top",linespacing=1.35)
def arrow(x,y,x2,y2):
    ax.add_patch(FancyArrowPatch((x,y),(x2,y2),arrowstyle='-|>',mutation_scale=15,lw=1.6,color="#66859e"))
card(.3,2.2,2.25,1.6,"NGỮ CẢNH","CWE/CVE có nguồn\nLưu lượng hợp lệ\nPhạm vi ứng dụng")
card(3.0,2.2,2.35,1.6,"SINH ỨNG VIÊN","Payload biến đổi\nLLM: nhánh mở rộng\nLọc, kiểm tra nhãn")
card(5.85,2.2,2.3,1.6,"POLICY & RULE","Chuẩn hóa đầu vào\nLuật theo tuyến tin cậy\nProvenance từng rule")
card(8.65,2.2,2.95,1.6,"BENCHMARK 3 TRỤC","Coverage × False positives\n× Evasion robustness\nBáo cáo theo CWE/biến đổi")
for a,b in ((2.57,2.88),(5.37,5.74),(8.17,8.54)):
    arrow(a,3,b,3)
card(3.0,.23,6.15,1.05,"CỔNG QUẢN TRỊ","Review AppSec  →  Canary  →  Theo dõi drift  →  Rollback",fill="#eaf7f5",stroke="#68b9ac")
arrow(10.05,2.07,8.95,1.35)
arrow(4.1,1.45,4.1,2.02)
ax.text(.3,4.85,"TRACE-WAF  |  Luồng thiết kế và đánh giá có truy vết",size=15,weight="bold",color="#20334d")
fig.subplots_adjust(left=.01,right=.99,top=.97,bottom=.02)
fig.savefig(OUT / "architecture.png",dpi=180,bbox_inches="tight")
plt.close(fig)
print("Created", [p.name for p in OUT.glob("*.png")])
