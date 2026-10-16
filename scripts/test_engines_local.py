#!/usr/bin/env python3
"""Real engines against a disposable loopback fixture and local dependency lock only."""
import http.server
import hashlib
import io
import tarfile
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading

from test_local import API, PASSWORD, ROOT, until


def main():
    if os.environ.get('LAB_ENV') != 'isolated':
        raise SystemExit('Set LAB_ENV=isolated; this script creates its own loopback fixture.')
    directory = Path(tempfile.mkdtemp(prefix='scanner-engines-local-'))
    (directory / 'inputs/deps').mkdir(parents=True)
    lock = {'name': 'local-fixture', 'version': '1.0.0', 'lockfileVersion': 2, 'requires': True,
            'packages': {'': {'name': 'local-fixture', 'version': '1.0.0', 'dependencies': {'lodash': '4.17.20'}},
                         'node_modules/lodash': {'version': '4.17.20'}},
            'dependencies': {'lodash': {'version': '4.17.20'}}}
    (directory / 'inputs/deps/package-lock.json').write_text(json.dumps(lock))
    # Build a tiny Docker-save archive from local metadata; no image pull or daemon.
    layer_buffer=io.BytesIO()
    with tarfile.open(fileobj=layer_buffer,mode='w') as layer:
        for name,body in {'etc/debian_version': b'12.0\n', 'etc/os-release': b'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12"\n',
                          'var/lib/dpkg/status': b'Package: openssl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.0.11-1~deb12u2\n\n'}.items():
            entry=tarfile.TarInfo(name);entry.size=len(body);entry.mode=0o644;layer.addfile(entry,io.BytesIO(body))
    layer_data=layer_buffer.getvalue()
    config=json.dumps({'architecture':'amd64','os':'linux','config':{},'rootfs':{'type':'layers','diff_ids':['sha256:'+hashlib.sha256(layer_data).hexdigest()]}}).encode()
    config_name=hashlib.sha256(config).hexdigest()+'.json'
    image_manifest=json.dumps([{'Config':config_name,'RepoTags':['fixture:local'],'Layers':['layer.tar']}]).encode()
    with tarfile.open(directory/'inputs/image.tar','w') as image:
        for name,body in {'manifest.json':image_manifest,config_name:config,'layer.tar':layer_data}.items():
            entry=tarfile.TarInfo(name);entry.size=len(body);entry.mode=0o644;image.addfile(entry,io.BytesIO(body))
    requests = []

    class Fixture(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            assert self.path == '/'
            body = b'<html><title>Local fixture</title><body>baseline fixture</body></html>'
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    fixture = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
    threading.Thread(target=fixture.serve_forever, daemon=True).start()
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    api = API(base)
    processes = []
    logs = []

    def start(name, args):
        log = (directory / (name + '.log')).open('ab')
        logs.append(log)
        process = subprocess.Popen([str(ROOT / ('dist/sec-' + name))] + args,
                                   cwd=ROOT, stdout=log, stderr=log)
        processes.append(process)
        return process

    def ready():
        try:
            return api.call('GET', '/readyz')
        except (OSError, AssertionError):
            return False

    def completed(task):
        item = next(t for t in api.call('GET', '/api/v1/tasks')['items'] if t['id'] == task['id'])
        assert item['status'] != 'FAILED', item
        return item if item['status'] == 'COMPLETED' else False

    try:
        start('server', ['--listen', f'127.0.0.1:{port}', '--db', str(directory / 'platform.db'),
                         '--ui-dir', str(ROOT / 'web/dist')])
        until(ready)
        api.call('POST', '/api/v1/auth/setup', {'username': 'localadmin', 'password': PASSWORD}, expect=201)
        api.login('localadmin')
        start('updater', ['--server', base, '--rules-dir', str(ROOT / 'vuln-data')])
        start('worker', ['--server', base, '--bin-dir', str(ROOT / 'bin'), '--rules-dir', str(ROOT / 'vuln-data'),
                         '--runtime-dir', str(directory / 'worker'), '--inputs-dir', str(directory / 'inputs')])
        until(lambda: any(r['isCurrent'] for r in api.call('GET', '/api/v1/rules')['items']), timeout=60)
        target = f'127.0.0.1:{fixture.server_port}'
        api.call('POST', '/api/v1/assets', {'kind': 'host', 'address': '127.0.0.1',
                  'requestedPorts': [fixture.server_port, 1], 'skippedPorts': [1],
                  'businessGroup': 'Local fixture', 'owner': 'Example owner'}, expect=201)
        counts = {}
        for engine in ['nuclei', 'zap']:
            before = len(requests)
            task = api.call('POST', '/api/v1/tasks', {'synthetic': False, 'engine': engine, 'scheme': 'http',
                            'targets': [target, '127.0.0.1:1'], 'timeWindows': []}, expect=201)
            done = until(lambda: completed(task), timeout=150)
            assert done['skippedTargets'] == ['127.0.0.1:1']
            findings = [f for f in api.call('GET', '/api/v1/findings')['items'] if f['taskId'] == task['id']]
            assert findings and all(not f['synthetic'] for f in findings)
            counts[engine] = len(findings)
            if engine == 'zap':
                assert len(requests) - before == 1, 'ZAP must only analyze one recorded root response'
            print(f'PASS {engine}: real process -> HTTP report -> SQLite -> {len(findings)} findings; skipped port excluded', flush=True)
        input_body = {'synthetic': False, 'engine': 'trivy', 'inputKind': 'filesystem',
                      'inputPath': 'deps', 'targets': [], 'timeWindows': []}
        for iteration in range(2):
            task = api.call('POST', '/api/v1/tasks', input_body, expect=201)
            until(lambda: completed(task), timeout=150)
            findings = [f for f in api.call('GET', '/api/v1/findings')['items'] if f['engine'] == 'trivy']
            assert findings
            if iteration == 0:
                ids = {f['id'] for f in findings}
            else:
                assert ids == {f['id'] for f in findings}, 'repeat scan duplicated stable findings'
        counts['trivy'] = len(findings)
        image_task=api.call('POST','/api/v1/tasks',{**input_body,'inputKind':'image-archive','inputPath':'image.tar'},expect=201)
        until(lambda: completed(image_task),timeout=150)
        image_findings=[f for f in api.call('GET','/api/v1/findings')['items'] if f['taskId']==image_task['id']]
        assert image_findings and all(f.get('artifactId','').startswith('sha256:') for f in image_findings)
        print('PASS Trivy Docker-save archive: offline scan and immutable image identity',flush=True)
        print(f'PASS trivy: offline DB + local dependency lock -> {len(findings)} findings; repeat scan deduplicated', flush=True)
        task = api.call('POST', '/api/v1/tasks', {**input_body, 'inputPath': 'missing'}, expect=201)
        failed = until(lambda: next((t for t in api.call('GET', '/api/v1/tasks')['items']
                                    if t['id'] == task['id'] and t['status'] == 'FAILED'), None))
        assert failed['error']
        print('PASS missing input: task FAILED without manufactured success findings', flush=True)
        result = {'state': 'PASS', 'realServersContacted': False, 'fixturePaths': sorted(set(requests)),
                  'engineFindingCounts': counts, 'imageArchiveFindingCount':len(image_findings), 'checks': ['real process/report/persistence', 'skip ports',
                  'ZAP offline passive analysis', 'Trivy offline scan', 'stable dedup', 'failure reporting']}
        (directory / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print('Evidence:', directory, flush=True)
    finally:
        for process in reversed(processes):
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for log in logs:
            log.close()
        fixture.shutdown()
        fixture.server_close()


if __name__ == '__main__':
    main()
