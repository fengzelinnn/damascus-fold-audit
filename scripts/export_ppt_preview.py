#!/usr/bin/env python3
"""Export marked empty/fixture PPTX previews to PDF and reject rasterized output.

Requires locally installed LibreOffice and Poppler pdfimages. This is the preview
path; final publication typography and data approval remain separate gates.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def check_preview(manifest):
    banner=manifest.get('banner','')
    if manifest.get('publication') is not False or not any(marker in banner for marker in ('EMPTY LAYOUT','NON-PAPER')):
        raise ValueError('only explicitly marked empty or NON-PAPER preview decks are enabled')


def check_vector_inventory(output):
    lines=[line for line in output.splitlines() if line.strip()]
    if len(lines)<2 or not lines[0].lstrip().startswith('page') or not set(lines[1].strip())=={'-'}:
        raise ValueError('unrecognized pdfimages inventory; cannot certify vector-only output')
    if len(lines)>2:
        raise ValueError('PDF contains raster image objects; preview vector export rejected')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pptx',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        pptx=args.pptx.resolve(strict=True)
        if pptx.suffix.lower()!='.pptx':raise ValueError('PPTX required')
        check_preview(json.loads(pptx.with_name('manifest.json').read_text()))
        if args.output.exists():raise ValueError('refusing to overwrite an existing PDF')
        for command in ('soffice','pdfimages'):
            if shutil.which(command) is None:raise ValueError(command+' is required')
        with tempfile.TemporaryDirectory(prefix='damascus-ppt-export-') as temporary:
            temp=Path(temporary);profile=temp/'profile';profile.mkdir()
            subprocess.run(['soffice','-env:UserInstallation='+profile.as_uri(),'--headless',
                            '--convert-to','pdf','--outdir',str(temp),str(pptx)],
                           capture_output=True,text=True,check=True,timeout=60)
            pdf=temp/(pptx.stem+'.pdf')
            if not pdf.is_file() or not pdf.read_bytes().startswith(b'%PDF'):
                raise ValueError('LibreOffice did not produce a PDF')
            inventory=subprocess.run(['pdfimages','-list',str(pdf)],capture_output=True,text=True,check=True,timeout=15)
            check_vector_inventory(inventory.stdout)
            args.output.parent.mkdir(parents=True,exist_ok=True)
            with args.output.open('xb') as target, pdf.open('rb') as source:
                shutil.copyfileobj(source,target)
        print(json.dumps({'output':str(args.output),'mode':'marked_preview','raster_image_objects':0,
                          'publication_typography_verified':False},indent=2))
    except (ValueError,OSError,subprocess.SubprocessError) as exc:
        parser.exit(2,'PPT preview export rejected: '+str(exc)+'\n')


if __name__=='__main__':main()
