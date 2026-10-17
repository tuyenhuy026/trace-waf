# TRACE-WAF report figures regenerated from code

This package regenerates the report figures **entirely from Python code** and then overwrites the image assets used by `BAO_CAO_TRACE_WAF.md` / `BAO_CAO_TRACE_WAF.tex`.

## Files

- `scripts/generate_report_figures.py` — creates four PNG figures from code:
  - `architecture.png`
  - `validation.png`
  - `final_test.png`
  - `drift.png`
- `scripts/replace_report_images.py` — scans the report for `assets/*.png` references and overwrites them with the generated figures.
- `scripts/rebuild_report.sh` — end-to-end helper: generate figures, replace assets, rebuild DOCX/TEX/PDF.

## Usage

From the repository root (the folder that contains `BAO_CAO_TRACE_WAF.md`):

```bash
bash /path/to/rebuild_report.sh .
```

Or step by step:

```bash
python scripts/generate_report_figures.py --out-dir assets_codegen
python scripts/replace_report_images.py --repo-root . --generated-dir assets_codegen
pandoc BAO_CAO_TRACE_WAF.md -o BAO_CAO_TRACE_WAF.docx
pandoc BAO_CAO_TRACE_WAF.md -o BAO_CAO_TRACE_WAF.tex
xelatex BAO_CAO_TRACE_WAF.tex
xelatex BAO_CAO_TRACE_WAF.tex
```

## Data used in the code

The plots encode the latest confirmed values used in the report:

- Validation: B0 FPR 31.25%; B1 and L1–L5 FPR 6.25%; all policies block 14/14 valid attacks.
- Final test: L3 reaches 100% coverage and 100% robustness; FPR is 11.36% for B1 and L1–L5, 25.00% for B0.
- Drift replay: B0/B1 windows A/B with composition shift from 0.0 to 1.0 and canary decision `LAB_NO_GO_ROLLBACK`.

If you later revise the paper numbers, update the constant arrays in `generate_report_figures.py` and rerun.
