#!/usr/bin/env python3
"""Check original paper bytes locally; never fetch or publish them."""
from pathlib import Path
import hashlib
import json
import sys

root=Path(__file__).resolve().parents[1]/'sources/paper'
manifest=json.loads((root/'manifest.json').read_text())
results=[]
for entry in manifest['files']:
    name=entry['name']
    if name not in ('main.tex','main.pdf'):
        raise SystemExit('unexpected manifest target')
    path=root/name
    if not path.is_file():
        results.append({'name':name,'status':'not_materialized'});continue
    digest=hashlib.sha256(path.read_bytes()).hexdigest()
    results.append({'name':name,'status':'verified' if digest==entry['sha256'] and path.stat().st_size==entry['size'] else 'MISMATCH','sha256':digest})
print(json.dumps(results,indent=2))
sys.exit(0 if all(item['status']=='verified' for item in results) else 1)
