#!/usr/bin/env python3
"""Package operator-supplied Nuclei templates and/or Trivy data; never downloads or scans."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--version',required=True)
parser.add_argument('--nuclei-dir',type=Path)
parser.add_argument('--trivy-dir',type=Path)
parser.add_argument('--output',required=True,type=Path)
parser.add_argument('--signing-private-key',required=True,type=Path,help='External Ed25519 private PEM file; never included in the archive')
args=parser.parse_args()
if not re.fullmatch(r'[0-9]{8}\.[0-9]{2,8}',args.version):parser.error('Version must be YYYYMMDD.NN')
def file_hash(stream):
    digest=hashlib.sha256()
    for data in iter(lambda:stream.read(1024*1024),b''):digest.update(data)
    return digest.hexdigest()

def openssl(arguments):
    try:
        result=subprocess.run(['openssl',*arguments],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
    except OSError:
        parser.error('An installed OpenSSL with Ed25519 support is required')
    if result.returncode:
        parser.error('OpenSSL signing failed; verify the Ed25519 private key and OpenSSL support')
    return result.stdout

if (not args.signing_private_key.is_file() or args.signing_private_key.is_symlink()
        or args.signing_private_key.stat().st_size>4096):
    parser.error('Signing private key must be a regular non-symlink file of at most 4 KiB')
# A DER SubjectPublicKeyInfo Ed25519 key is exactly this prefix plus 32 bytes.
derived=openssl(['pkey','-in',str(args.signing_private_key),'-passin','pass:','-pubout','-outform','DER'])
if len(derived)!=44 or derived[:12]!=bytes.fromhex('302a300506032b6570032100'):
    parser.error('Signing private key must be Ed25519')

files={};engines=[]
for engine,root in [('nuclei',args.nuclei_dir),('trivy',args.trivy_dir)]:
    if root is None:continue
    if not root.is_dir() or root.is_symlink():parser.error('Input must be a real local directory')
    try:
        args.signing_private_key.resolve().relative_to(root.resolve())
    except ValueError:
        pass
    else:
        parser.error('Signing private key must be outside engine input directories')
    engines.append(engine)
    for source in sorted(root.rglob('*')):
        if source.is_symlink():parser.error('Symbolic links are not supported')
        if source.is_file():
            if source.samefile(args.signing_private_key):parser.error('Signing private key must be outside packaged content')
            name=engine+'/'+source.relative_to(root).as_posix()
            if len(name)>240 or ':' in name or '\\' in name:parser.error('Unsupported file path')
            files[name]=source
if not files:parser.error('Provide at least one non-empty engine directory')
if len(files)>50000:parser.error('At most 50000 files per package')
manifest={'version':args.version,'engines':engines,'files':{}}
for name,source in files.items():
    with source.open('rb') as stream:manifest['files'][name]=file_hash(stream)
manifest_data=json.dumps(manifest,ensure_ascii=False,sort_keys=True).encode('utf-8')
with tempfile.TemporaryDirectory(prefix='scanner-rule-sign-') as temporary:
    directory=Path(temporary)
    manifest_path=directory/'manifest.json';manifest_path.write_bytes(manifest_data)
    signature_path=directory/'manifest.json.sig'
    public_path=directory/'public.der';public_path.write_bytes(derived)
    openssl(['pkeyutl','-sign','-rawin','-inkey',str(args.signing_private_key),'-passin','pass:',
             '-in',str(manifest_path),'-out',str(signature_path)])
    signature=signature_path.read_bytes()
    if len(signature)!=64:parser.error('OpenSSL did not produce a raw 64-byte Ed25519 signature')
    openssl(['pkeyutl','-verify','-rawin','-pubin','-keyform','DER','-inkey',str(public_path),
             '-in',str(manifest_path),'-sigfile',str(signature_path)])
args.output.parent.mkdir(parents=True,exist_ok=True)
with zipfile.ZipFile(args.output,'x',zipfile.ZIP_DEFLATED) as archive:
    archive.writestr('manifest.json',manifest_data)
    archive.writestr('manifest.json.sig',signature)
    for name,source in files.items():archive.write(source,name)
with args.output.open('rb') as stream:digest=file_hash(stream)
print('Package:',args.output)
print('SHA-256:',digest)
