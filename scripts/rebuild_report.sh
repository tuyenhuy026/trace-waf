#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GEN_DIR="$ROOT/assets_codegen"

echo "[1/3] Generate code-based figures"
python "$SCRIPT_DIR/generate_report_figures.py" --out-dir "$GEN_DIR"

echo "[2/3] Replace report image assets"
python "$SCRIPT_DIR/replace_report_images.py" --repo-root "$ROOT" --generated-dir "$GEN_DIR"

echo "[3/3] Rebuild report files"
if command -v pandoc >/dev/null 2>&1; then
  pandoc "$ROOT/BAO_CAO_TRACE_WAF.md" --from markdown+tex_math_dollars --resource-path="$ROOT" --standalone -o "$ROOT/BAO_CAO_TRACE_WAF.docx"
  pandoc "$ROOT/BAO_CAO_TRACE_WAF.md" --from markdown+tex_math_dollars --resource-path="$ROOT" --standalone -o "$ROOT/BAO_CAO_TRACE_WAF.tex"
fi
if command -v xelatex >/dev/null 2>&1 && [[ -f "$ROOT/BAO_CAO_TRACE_WAF.tex" ]]; then
  (cd "$ROOT" && xelatex -interaction=nonstopmode -halt-on-error BAO_CAO_TRACE_WAF.tex >/dev/null && xelatex -interaction=nonstopmode -halt-on-error BAO_CAO_TRACE_WAF.tex >/dev/null)
fi

echo "Done. Review $ROOT/assets and rebuilt report outputs."
