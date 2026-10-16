#!/usr/bin/env python3
"""Package operator-supplied Nuclei templates and/or Trivy data; never downloads or scans."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--version',required=True)
parser.add_argument('--nuclei-dir',type=Path)
parser.add_argument('--trivy-dir',type=Path)
parser.add_argument('--output',required=True,type=Path)
args=parser.parse_args()
if not re.fullmatch(r'[0-9]{8}\.[0-9]{2,8}',args.version):parser.error('Version must be YYYYMMDD.NN')
def file_hash(stream):
    digest=hashlib.sha256()
    for data in iter(lambda:stream.read(1024*1024),b''):digest.update(data)
    return digest.hexdigest()

files={};engines=[]
for engine,root in [('nuclei',args.nuclei_dir),('trivy',args.trivy_dir)]:
    if root is None:continue
    if not root.is_dir() or root.is_symlink():parser.error('Input must be a real local directory')
    engines.append(engine)
    for source in sorted(root.rglob('*')):
        if source.is_symlink():parser.error('Symbolic links are not supported')
        if source.is_file():
            name=engine+'/'+source.relative_to(root).as_posix()
            if len(name)>240 or ':' in name or '\\' in name:parser.error('Unsupported file path')
            files[name]=source
if not files:parser.error('Provide at least one non-empty engine directory')
if len(files)>50000:parser.error('At most 50000 files per package')
manifest={'version':args.version,'engines':engines,'files':{}}
for name,source in files.items():
    with source.open('rb') as stream:manifest['files'][name]=file_hash(stream)
args.output.parent.mkdir(parents=True,exist_ok=True)
with zipfile.ZipFile(args.output,'x',zipfile.ZIP_DEFLATED) as archive:
    archive.writestr('manifest.json',json.dumps(manifest,ensure_ascii=False,sort_keys=True))
    for name,source in files.items():archive.write(source,name)
with args.output.open('rb') as stream:digest=file_hash(stream)
print('Package:',args.output)
print('SHA-256:',digest)
