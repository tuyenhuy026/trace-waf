from pathlib import Path
import shutil
import re

KEYWORDS = {
    'architecture': ('arch', 'pipeline', 'overview', 'framework', 'system', 'trace'),
    'validation': ('validation', 'rule_study', 'study', 'candidate'),
    'final_test': ('final', 'test'),
    'drift': ('drift', 'replay', 'shift'),
}


def classify(name: str):
    n = name.lower()
    for target, kws in KEYWORDS.items():
        if all(k in n for k in kws if target == 'final_test'):
            return target
    for target, kws in KEYWORDS.items():
        if target == 'final_test':
            continue
        if any(k in n for k in kws):
            return target
    # special handling
    if 'final' in n:
        return 'final_test'
    return None


def extract_image_paths(text: str):
    paths = set()
    for m in re.finditer(r'assets/([^\)\}\s]+\.png)', text):
        paths.add(m.group(1))
    return sorted(paths)


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Overwrite report image assets with code-generated TRACE-WAF figures.')
    parser.add_argument('--repo-root', default='.', help='Root directory containing BAO_CAO_TRACE_WAF.md and assets/.')
    parser.add_argument('--generated-dir', default='generated', help='Directory containing generated PNGs.')
    args = parser.parse_args()

    root = Path(args.repo_root).resolve()
    generated = Path(args.generated_dir).resolve()
    md = root / 'BAO_CAO_TRACE_WAF.md'
    tex = root / 'BAO_CAO_TRACE_WAF.tex'
    if not md.exists() and not tex.exists():
        raise SystemExit('Cannot find BAO_CAO_TRACE_WAF.md or BAO_CAO_TRACE_WAF.tex under repo root')

    text = ''
    if md.exists():
        text += md.read_text(encoding='utf-8', errors='ignore') + '\n'
    if tex.exists():
        text += tex.read_text(encoding='utf-8', errors='ignore') + '\n'
    image_names = extract_image_paths(text)
    if not image_names:
        raise SystemExit('No assets/*.png references found in report files.')

    src_map = {
        'architecture': generated / 'architecture.png',
        'validation': generated / 'validation.png',
        'final_test': generated / 'final_test.png',
        'drift': generated / 'drift.png',
    }

    assets_dir = root / 'assets'
    assets_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    unresolved = []
    for name in image_names:
        kind = classify(name)
        if kind and src_map[kind].exists():
            dst = assets_dir / name
            shutil.copyfile(src_map[kind], dst)
            copied.append((name, kind))
        else:
            unresolved.append(name)

    print('Copied:')
    for name, kind in copied:
        print(f'  {name} <- {src_map[kind].name}')
    if unresolved:
        print('\nUnresolved image names (assign manually if needed):')
        for name in unresolved:
            print('  ', name)

if __name__ == '__main__':
    main()
