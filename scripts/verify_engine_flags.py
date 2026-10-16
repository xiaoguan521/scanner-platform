#!/usr/bin/env python3
"""Verify flags against installed, pinned engines without accessing scan targets."""
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
lock = json.loads((ROOT / 'config/engines.lock.json').read_text())
source = (ROOT / 'internal/executor/engineflags/args.go').read_text()
extension = '.exe' if os.name == 'nt' else ''

with tempfile.TemporaryDirectory(prefix='scanner-flags-') as temp:
    env = {key: value for key, value in os.environ.items() if key in ['PATH', 'SYSTEMROOT', 'WINDIR', 'JAVA_HOME']}
    env.update(HOME=temp, USERPROFILE=temp, XDG_CONFIG_HOME=temp, XDG_CACHE_HOME=temp, XDG_DATA_HOME=temp,
               DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD='true')
    for name in ['nuclei', 'trivy', 'zap']:
        if name == 'zap':
            command = ['java', '-jar', str(ROOT / f'bin/zap/zap-{lock[name]["version"]}.jar')]
            version = subprocess.check_output(command + ['-version'], env=env, cwd=temp, stderr=subprocess.STDOUT, timeout=30).decode()
            help_text = subprocess.check_output(command + ['-silent', '-dir', temp + '/zap', '-h'], env=env, cwd=temp, stderr=subprocess.STDOUT, timeout=60).decode()
            function = 'ZAPArgs'
        else:
            command = [str(ROOT / ('bin/' + name + extension))]
            version = subprocess.check_output(command + ['-version' if name == 'nuclei' else '--version'], env=env, cwd=temp, stderr=subprocess.STDOUT, timeout=30).decode()
            commands = [['-h']] if name == 'nuclei' else [['filesystem', '--help'], ['image', '--help']]
            help_text = '\n'.join(subprocess.check_output(command + args, env=env, cwd=temp, stderr=subprocess.STDOUT, timeout=30).decode() for args in commands)
            function = 'NucleiArgs' if name == 'nuclei' else 'TrivyArgs'
        assert lock[name]['version'] in version, f'{name}: installed version differs from lock'
        body = source.split('func ' + function + '(')[1].split('\nfunc ')[0]
        if name == 'trivy':
            body += source.split('func TrivyDownloadArgs(')[1]
        flags = set(re.findall(r'"(-[-a-z0-9]+)"', body)) - {'-jar'}
        for flag in flags:
            assert re.search(r'(?<![\w-])' + re.escape(flag) + r'(?![\w-])', help_text), f'{name}: missing flag {flag}'
        print(f'PASS {name} {lock[name]["version"]}: {len(flags)} flags verified; no scan executed')
