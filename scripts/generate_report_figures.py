from pathlib import Path
import math
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle, FancyArrowPatch

OUT_DEFAULT = Path('generated')

# Fixed data from the latest confirmed report state.
VALIDATION_POLICIES = ['B0', 'B1', 'L1', 'L2', 'L3', 'L4', 'L5']
VALIDATION_COVERAGE = [100, 100, 100, 100, 100, 100, 100]
VALIDATION_FPR = [31.25, 6.25, 6.25, 6.25, 6.25, 6.25, 6.25]
VALIDATION_ROBUSTNESS = [100, 100, 100, 100, 100, 100, 100]

FINAL_POLICIES = ['B0', 'B1', 'L1', 'L2', 'L3', 'L4', 'L5']
FINAL_COVERAGE = [87.50, 87.50, 87.50, 87.50, 100.00, 95.83, 87.50]
FINAL_FPR = [25.00, 11.36, 11.36, 11.36, 11.36, 11.36, 11.36]
FINAL_ROBUSTNESS = [83.33, 83.33, 83.33, 83.33, 100.00, 91.67, 83.33]

DRIFT_WINDOWS = [
    ('B0', 'A: raw-weighted', 6, 6, 0, 31.25, 1),
    ('B0', 'B: transformed-weighted', 8, 8, 16, 31.25, 1),
    ('B1', 'A: raw-weighted', 6, 6, 0, 6.25, 1),
    ('B1', 'B: transformed-weighted', 8, 8, 16, 6.25, 1),
]


def save(fig, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=220, bbox_inches='tight', facecolor='white')
    plt.close(fig)


def add_rounded_box(ax, x, y, w, h, text, fc='#EEF4F8', ec='#C9D7E1', title=False, fontsize=12):
    box = FancyBboxPatch((x, y), w, h, boxstyle='round,pad=0.012,rounding_size=0.03',
                         facecolor=fc, edgecolor=ec, linewidth=1.2)
    ax.add_patch(box)
    ax.text(x + w/2, y + h/2, text, ha='center', va='center', fontsize=fontsize,
            fontweight='bold' if title else 'normal', color='#17334D', wrap=True)
    return box


def add_arrow(ax, x1, y1, x2, y2):
    arrow = FancyArrowPatch((x1, y1), (x2, y2), arrowstyle='-|>', mutation_scale=18,
                            linewidth=1.6, color='#148F8A')
    ax.add_patch(arrow)


def figure_architecture(out_dir: Path):
    fig, ax = plt.subplots(figsize=(15, 8))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis('off')

    ax.text(0.02, 0.96, 'TRACE-WAF architecture and evidence flow', fontsize=20, fontweight='bold', color='#17334D')
    ax.text(0.02, 0.92, 'Code-generated overview for the report: inputs, oracle, WAF evaluation, governance, and rollback.', fontsize=11.5, color='#556B7B')

    add_rounded_box(ax, 0.03, 0.70, 0.18, 0.14, 'CWE / CVE\nknowledge sources', fc='#E9F4FA', fontsize=13)
    add_rounded_box(ax, 0.26, 0.70, 0.18, 0.14, 'Payload sources\nHeuristic / LLM', fc='#EAF8F6', fontsize=13)
    add_rounded_box(ax, 0.49, 0.70, 0.20, 0.14, 'Oracle backend\nSQLi / XSS / traversal', fc='#FFF5EA', fontsize=13)
    add_rounded_box(ax, 0.74, 0.70, 0.20, 0.14, 'ModSecurity + CRS\npolicy under test', fc='#EEF4F8', fontsize=13)

    add_arrow(ax, 0.21, 0.77, 0.26, 0.77)
    add_arrow(ax, 0.44, 0.77, 0.49, 0.77)
    add_arrow(ax, 0.69, 0.77, 0.74, 0.77)

    add_rounded_box(ax, 0.08, 0.42, 0.22, 0.14, 'Frozen validation / final corpora\n(hash-locked before evaluation)', fc='#F5F8FA', fontsize=13)
    add_rounded_box(ax, 0.39, 0.42, 0.22, 0.14, 'Metrics\nCoverage · FPR · Robustness', fc='#E9F4FA', fontsize=13)
    add_rounded_box(ax, 0.70, 0.42, 0.20, 0.14, 'Gate\nGO / NO-GO', fc='#FDEEEF', ec='#E6C4C8', fontsize=13)

    add_arrow(ax, 0.30, 0.49, 0.39, 0.49)
    add_arrow(ax, 0.61, 0.49, 0.70, 0.49)
    add_arrow(ax, 0.84, 0.42, 0.84, 0.29)

    add_rounded_box(ax, 0.71, 0.16, 0.25, 0.14, 'Rollback + audit trail\nrule hash, transaction logs,\nevidence bundle', fc='#EAF8F6', fontsize=11.8)

    # Notes panel
    note = Rectangle((0.03, 0.05), 0.62, 0.27, facecolor='#FAFBFC', edgecolor='#D9E2EA', linewidth=1.0)
    ax.add_patch(note)
    lines = [
        'Scope: SQLi, XSS, and path traversal in a controlled Docker lab.',
        'Rule study: L1–L5 from gpt-6-luna; B0/B1 kept as baselines.',
        'Governance: freeze, validation, final test, drift replay, canary, rollback.',
        'CVE-2024-23334 is still incomplete pending service preflight and proof runs.'
    ]
    y = 0.27
    for line in lines:
        ax.text(0.05, y, '\u2022 ' + line, fontsize=10.8, color='#42596B', va='top')
        y -= 0.05

    save(fig, out_dir / 'architecture.png')


def figure_validation(out_dir: Path):
    fig, axes = plt.subplots(1, 3, figsize=(15.5, 4.7))
    series = [VALIDATION_COVERAGE, VALIDATION_FPR, VALIDATION_ROBUSTNESS]
    titles = ['Validation coverage', 'Validation FPR', 'Validation robustness']
    ylims = [(0, 110), (0, 36), (0, 110)]
    for ax, vals, title, ylim in zip(axes, series, titles, ylims):
        ax.bar(VALIDATION_POLICIES, vals)
        ax.set_title(title, fontsize=13, fontweight='bold')
        ax.set_ylim(*ylim)
        ax.grid(axis='y', linestyle='--', linewidth=0.7)
        ax.set_axisbelow(True)
        for i, v in enumerate(vals):
            ax.text(i, v + (1.5 if title != 'Validation FPR' else 0.7), f'{v:.2f}%', ha='center', va='bottom', fontsize=9)
    axes[1].axhline(5, linestyle='--', linewidth=1.2)
    axes[1].text(6.4, 5.7, 'Gate: 5%', ha='right', fontsize=8.8)
    fig.suptitle('Frozen validation on the same corpus (14 valid attacks, 16 benign)', fontsize=15, fontweight='bold')
    fig.text(0.5, -0.02, 'All 7 policies blocked 14/14 valid attacks; all remained NO-GO because FPR stayed above the deployment gate.', ha='center', fontsize=10)
    save(fig, out_dir / 'validation.png')


def figure_final_test(out_dir: Path):
    fig, axes = plt.subplots(1, 3, figsize=(15.5, 4.8))
    series = [FINAL_COVERAGE, FINAL_FPR, FINAL_ROBUSTNESS]
    titles = ['Final-test coverage', 'Final-test FPR', 'Final-test robustness']
    ylims = [(0, 110), (0, 30), (0, 110)]
    for ax, vals, title, ylim in zip(axes, series, titles, ylims):
        ax.bar(FINAL_POLICIES, vals)
        ax.set_title(title, fontsize=13, fontweight='bold')
        ax.set_ylim(*ylim)
        ax.grid(axis='y', linestyle='--', linewidth=0.7)
        ax.set_axisbelow(True)
        for i, v in enumerate(vals):
            ax.text(i, v + (1.5 if title != 'Final-test FPR' else 0.6), f'{v:.2f}%', ha='center', va='bottom', fontsize=9)
    axes[1].axhline(5, linestyle='--', linewidth=1.2)
    axes[1].text(6.4, 5.7, 'Gate: 5%', ha='right', fontsize=8.8)
    fig.suptitle('Frozen final test: 7 policies on the same held-out corpus', fontsize=15, fontweight='bold')
    fig.text(0.5, -0.03, 'Coverage / robustness use deduplicated valid attacks (n=24). FPR uses evaluable benign traffic (n=44).', ha='center', fontsize=10)
    save(fig, out_dir / 'final_test.png')


def figure_drift(out_dir: Path):
    fig = plt.figure(figsize=(15.2, 6.6))
    gs = fig.add_gridspec(1, 2, width_ratios=[1.05, 1.55])
    ax1 = fig.add_subplot(gs[0, 0])
    ax2 = fig.add_subplot(gs[0, 1])

    # left: composition shift
    ax1.barh(['Window A', 'Window B'], [0, 1.0])
    ax1.set_xlim(0, 1.05)
    ax1.set_xlabel('Transformed-attack share')
    ax1.set_title('Controlled composition shift', fontsize=13, fontweight='bold')
    ax1.grid(axis='x', linestyle='--', linewidth=0.7)
    for y, v in enumerate([0, 1.0]):
        ax1.text(v + 0.02, y, f'{v:.1f}', va='center', fontsize=10)

    # right: compact table-like visualization
    ax2.axis('off')
    ax2.set_title('Replay outcomes (per policy and window)', fontsize=13, fontweight='bold', pad=14)
    columns = ['Policy', 'Window', 'Blocked', 'Valid', 'Invalid', 'FPR', 'Regression']
    widths = [0.13, 0.27, 0.12, 0.10, 0.10, 0.10, 0.12]
    x0, y0, row_h = 0.02, 0.82, 0.12
    x = x0
    for c, w in zip(columns, widths):
        ax2.add_patch(Rectangle((x, y0), w, row_h, facecolor='#17334D', edgecolor='white'))
        ax2.text(x + w/2, y0 + row_h/2, c, ha='center', va='center', color='white', fontsize=10, fontweight='bold')
        x += w
    yy = y0 - row_h
    for idx, row in enumerate(DRIFT_WINDOWS):
        bg = '#F5F8FA' if idx % 2 == 0 else '#FFFFFF'
        x = x0
        vals = [row[0], row[1], f'{row[2]}', f'{row[3]}', f'{row[4]}', f'{row[5]:.2f}%', f'{row[6]}']
        for v, w in zip(vals, widths):
            ax2.add_patch(Rectangle((x, yy), w, row_h, facecolor=bg, edgecolor='#D8E2EA'))
            ax2.text(x + w/2, yy + row_h/2, v, ha='center', va='center', fontsize=10, color='#17334D')
            x += w
        yy -= row_h

    ax2.text(0.02, 0.12,
             'Decision: canary B1 remained LAB_NO_GO_ROLLBACK in both replay runs.\n'
             'Interpretation: replay demonstrates the evaluation / rollback process in the lab,\n'
             'not autonomous adaptation or real-world temporal drift.',
             fontsize=11, color='#42596B', va='bottom')

    fig.suptitle('Drift replay and canary evaluation', fontsize=16, fontweight='bold')
    save(fig, out_dir / 'drift.png')


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Generate code-based TRACE-WAF report figures.')
    parser.add_argument('--out-dir', default=str(OUT_DEFAULT), help='Output directory for PNG figures.')
    args = parser.parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    figure_architecture(out_dir)
    figure_validation(out_dir)
    figure_final_test(out_dir)
    figure_drift(out_dir)
    print('Generated figures in', out_dir.resolve())
    for p in sorted(out_dir.glob('*.png')):
        print('-', p.name)

if __name__ == '__main__':
    main()
