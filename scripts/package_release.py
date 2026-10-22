#!/usr/bin/env python3
"""Build a reviewed source bundle; exclude research originals, logs and credentials."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile

DIRECTORIES = ('damascus_a','tests','docs','configs','schemas','fixtures','scripts','licenses')
ROOT_FILES = ('README.md','pyproject.toml','requirements-plot.lock','.python-version',
              '.gitignore','THIRD_PARTY_NOTICES.md','sources/paper/manifest.json')
SECRET_PATTERNS = (
    r'https://drive\.google\.com/(?:file/d/|drive/folders/)',
    r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    r'\bgh[pousr]_[A-Za-z0-9]{20,}\b',
    r'\bgithub_pat_[A-Za-z0-9_]{20,}\b',
    r'\bAKIA[A-Z0-9]{16}\b',
    r'https://[^\s"\x27]+[?&](?:sig|token|access_token)=[^\s"\x27]+',
)


def collect_files(root):
    root = Path(root).resolve()
    candidates = [root/name for name in ROOT_FILES if (root/name).exists()]
    for directory in DIRECTORIES:
        location = root/directory
        if location.is_symlink():
            raise ValueError(f'symlink rejected: {directory}')
        if location.exists():
            candidates.extend(location.rglob('*'))
    selected = []
    for path in sorted(set(candidates)):
        relative = path.relative_to(root)
        # A regular leaf can still escape via a symlinked parent. Check the
        # entire path beneath the explicitly selected root before reading it.
        current = root
        for component in relative.parts:
            current = current/component
            if current.is_symlink():
                raise ValueError(f'symlink rejected: {relative}')
        if not path.resolve().is_relative_to(root):
            raise ValueError(f'outside-root path rejected: {relative}')
        if not path.is_file():
            continue
        if any(part == '__pycache__' or part.startswith('.env') for part in relative.parts):
            continue
        if str(relative) == 'docs/progress.md':
            continue  # Internal execution/authorization ledger stays local.
        if path.suffix.lower() in ('.pyc','.pem','.key','.p12','.pfx') or path.name.endswith('.local.json'):
            continue
        selected.append(path)
    return selected


def scan_files(files):
    for path in files:
        raw = path.read_bytes()
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError(f'non-text source upload requires separate review: {path.name}')
        for pattern in SECRET_PATTERNS:
            if re.search(pattern, text):
                # Never echo the matching credential.
                raise ValueError(f'credential-like or private-locator content in {path.name}')


def manifest_for(root, files):
    return [{'path':str(path.relative_to(root)), 'bytes':path.stat().st_size,
             'sha256':hashlib.sha256(path.read_bytes()).hexdigest()} for path in files]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--manifest',type=Path)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    files=collect_files(root); scan_files(files)
    manifest=manifest_for(root, files)
    if args.manifest:
        args.manifest.parent.mkdir(parents=True,exist_ok=True)
        args.manifest.write_text(json.dumps(manifest,indent=2)+'\n')
    if args.output:
        if args.output.exists():
            raise SystemExit('refusing to overwrite existing archive')
        args.output.parent.mkdir(parents=True,exist_ok=True)
        with tarfile.open(args.output,'w:gz') as archive:
            for path in files:
                info=archive.gettarinfo(str(path),arcname='damascus-fold-audit/'+str(path.relative_to(root)))
                info.uid=info.gid=0;info.uname=info.gname='';info.mtime=0
                with path.open('rb') as stream: archive.addfile(info,stream)
    print(json.dumps({'reviewed_file_count':len(files),'reviewed_bytes':sum(x['bytes'] for x in manifest),
                      'credential_scan':'no_matching_patterns','manual_review_required':True,
                      'output':str(args.output) if args.output else None},indent=2))


if __name__=='__main__': main()
