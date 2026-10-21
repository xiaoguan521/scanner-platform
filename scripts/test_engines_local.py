#!/usr/bin/env python3
"""Real engines against a disposable loopback fixture and local dependency lock only."""
import http.server
import hashlib
import io
import tarfile
import json
import os
import shutil
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import zipfile

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
    current = (ROOT / 'vuln-data/CURRENT').read_text().strip()
    java_available = (ROOT / 'vuln-data/releases' / current / 'trivy/java-db/trivy-java.db').is_file()
    if os.environ.get('SCANNER_EXPECT_JAVA_DB') == '1' and not java_available:
        raise SystemExit('Run make engines-java first; Java regression was explicitly requested.')
    zap_jar = ROOT / 'bin/zap/zap-2.17.0.jar'
    zap_available = zap_jar.is_file() and shutil.which('java') is not None
    if os.environ.get('SCANNER_EXPECT_ZAP') == '1' and not zap_available:
        raise SystemExit('Run make engines-zap and install Java 17+; ZAP regression was explicitly requested.')
    http_engines = ['nuclei']
    if zap_available:
        http_engines.append('zap')
    else:
        print('SKIP ZAP: optional passive engine is not installed (set SCANNER_EXPECT_ZAP=1 to require it)', flush=True)
    collector_apps = []
    if java_available:
        java = directory / 'java-fixture'
        java.mkdir()
        # Metadata-only fixture. No vulnerable library bytecode is downloaded,
        # executed or used to attack anything.
        with zipfile.ZipFile(java / 'log4j-core-2.14.1.jar', 'w') as jar:
            jar.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\nImplementation-Title: log4j-core\nImplementation-Version: 2.14.1\n\n')
            jar.writestr('META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties',
                         'groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n')
        collector_apps += ['--app', 'java=' + str(java)]
    go_source = directory / 'fixture.go'
    go_source.write_text('package main\nfunc main() {}\n')
    for arch in ['amd64', 'arm64']:
        output = directory / ('go-' + arch)
        environment = dict(os.environ, GOOS='linux', GOARCH=arch, CGO_ENABLED='0', GOPROXY='off', GOTOOLCHAIN='local')
        subprocess.run(['go', 'build', '-trimpath', '-o', str(output), str(go_source)], env=environment, check=True)
        collector_apps += ['--app', 'go-' + arch + '=' + str(output)]
    # Build a tiny Docker-save archive from local metadata; no image pull or daemon.
    layer_buffer=io.BytesIO()
    linux_files = {'etc/debian_version': b'12.0\n', 'etc/os-release': b'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12"\n',
                   'var/lib/dpkg/status': b'Package: openssl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.0.11-1~deb12u2\n\n'}
    if java_available:
        linux_files['opt/app/log4j-core-2.14.1.jar'] = (java / 'log4j-core-2.14.1.jar').read_bytes()
    with tarfile.open(fileobj=layer_buffer,mode='w') as layer:
        for name,body in linux_files.items():
            entry=tarfile.TarInfo(name);entry.size=len(body);entry.mode=0o644;layer.addfile(entry,io.BytesIO(body))
            fixture_file = directory / 'linux-fixture' / name
            fixture_file.parent.mkdir(parents=True, exist_ok=True)
            fixture_file.write_bytes(body)
    layer_data=layer_buffer.getvalue()
    config=json.dumps({'architecture':'amd64','os':'linux','config':{},'rootfs':{'type':'layers','diff_ids':['sha256:'+hashlib.sha256(layer_data).hexdigest()]}}).encode()
    config_name=hashlib.sha256(config).hexdigest()+'.json'
    image_manifest=json.dumps([{'Config':config_name,'RepoTags':['fixture:local'],'Layers':['layer.tar']}]).encode()
    with tarfile.open(directory/'inputs/image.tar','w') as image:
        for name,body in {'manifest.json':image_manifest,config_name:config,'layer.tar':layer_data}.items():
            entry=tarfile.TarInfo(name);entry.size=len(body);entry.mode=0o644;image.addfile(entry,io.BytesIO(body))
    # The same local image in OCI layout, as exported by a containerd operator.
    layer_digest = hashlib.sha256(layer_data).hexdigest()
    config_digest = hashlib.sha256(config).hexdigest()
    oci_manifest = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                              'config': {'mediaType': 'application/vnd.oci.image.config.v1+json', 'digest': 'sha256:' + config_digest, 'size': len(config)},
                              'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar', 'digest': 'sha256:' + layer_digest, 'size': len(layer_data)}]}).encode()
    manifest_digest = hashlib.sha256(oci_manifest).hexdigest()
    oci_index = json.dumps({'schemaVersion': 2, 'manifests': [{'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                            'digest': 'sha256:' + manifest_digest, 'size': len(oci_manifest), 'platform': {'os': 'linux', 'architecture': 'amd64'}}]}).encode()
    with tarfile.open(directory / 'oci-fixture.tar', 'w') as image:
        for name, body in {'oci-layout': b'{"imageLayoutVersion":"1.0.0"}', 'index.json': oci_index,
                           'blobs/sha256/' + manifest_digest: oci_manifest, 'blobs/sha256/' + config_digest: config,
                           'blobs/sha256/' + layer_digest: layer_data}.items():
            entry = tarfile.TarInfo(name); entry.size = len(body); entry.mode = 0o600; image.addfile(entry, io.BytesIO(body))
    subprocess.run([sys.executable, str(ROOT / 'scripts/collect_linux_inputs.py'), '--source', 'lab-a',
                    '--rootfs', str(directory / 'linux-fixture'), '--output', str(directory / 'inputs/lab-a'),
                    '--app', 'web=' + str(directory / 'inputs/deps'), '--image-archive', 'middleware=' + str(directory / 'oci-fixture.tar'), *collector_apps], check=True)
    shutil.copytree(directory / 'linux-fixture', directory / 'kylin-fixture')
    (directory / 'kylin-fixture/etc/os-release').write_text('ID=kylin\nID_LIKE=centos\nVERSION_ID=V10\n')
    subprocess.run([sys.executable, str(ROOT / 'scripts/collect_linux_inputs.py'), '--source', 'lab-kylin',
                    '--rootfs', str(directory / 'kylin-fixture'), '--output', str(directory / 'inputs/lab-kylin')], check=True)
    requests = []

    class Fixture(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            assert self.path in ['/', '/actuator/env', '/server-status?auto']
            if self.path != '/':
                self.send_response(404); self.end_headers(); return
            body = b'<html><title>Local fixture</title><body>baseline fixture</body></html>'
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):
            requests.append(self.path)
            assert self.path == '/'
            self.send_response(204)
            self.send_header('Allow', 'GET, HEAD, OPTIONS')
            self.end_headers()

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
        asset = api.call('POST', '/api/v1/assets', {'kind': 'host', 'address': '127.0.0.1',
                  'requestedPorts': [fixture.server_port, 1], 'skippedPorts': [1],
                  'businessGroup': 'Local fixture', 'owner': 'Example owner'}, expect=201)
        api.call('POST','/api/v1/users',{'username':'localops','password':PASSWORD,'role':'ops_approver'},expect=201)
        ops=API(base);ops.login('localops')
        ops.call('POST',f'/api/v1/port-requests/{asset["id"]}/{fixture.server_port}/review',
                 {'decision':'APPROVE','approvalTicket':'LOCAL-ENGINE-FIXTURE','note':'Isolated loopback fixture','kind':'WEB'})
        counts = {}
        for engine in http_engines:
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
        rootfs_input = {**input_body, 'inputKind': 'rootfs', 'inputPath': 'lab-a/os'}
        for iteration in range(2):
            task = api.call('POST', '/api/v1/tasks', rootfs_input, expect=201)
            until(lambda: completed(task), timeout=150)
            os_findings = [f for f in api.call('GET', '/api/v1/findings')['items'] if f['target'] == 'lab-a/os']
            assert os_findings and all(f['package'] == 'openssl' and 'lab-a' in f['description'] for f in os_findings)
            if iteration == 0:
                os_ids = {f['id'] for f in os_findings}
            else:
                assert os_ids == {f['id'] for f in os_findings}, 'repeat OS scan duplicated findings'
        app_task = api.call('POST', '/api/v1/tasks', {**input_body, 'inputPath': 'lab-a/apps/web'}, expect=201)
        until(lambda: completed(app_task), timeout=150)
        app_findings = [f for f in api.call('GET', '/api/v1/findings')['items'] if f['taskId'] == app_task['id']]
        assert app_findings and all('lab-a' in f['description'] for f in app_findings)
        print(f'PASS Linux collector -> rootfs -> {len(os_findings)} OS findings; selected application -> {len(app_findings)} findings; stable dedup', flush=True)
        java_findings = []
        if java_available:
            java_task = api.call('POST', '/api/v1/tasks', {**input_body, 'inputKind': 'artifact', 'inputPath': 'lab-a/apps/java'}, expect=201)
            until(lambda: completed(java_task), timeout=180)
            java_findings = [f for f in api.call('GET', '/api/v1/findings')['items'] if f['taskId'] == java_task['id']]
            assert any(f['templateOrCve'] == 'CVE-2021-44228' and f['installedVersion'] == '2.14.1' for f in java_findings)
            print(f'PASS Java metadata fixture: offline Java index and main DB -> {len(java_findings)} findings including expected CVE; no library executed', flush=True)
        else:
            print('SKIP Java fixture: active bundle has no Java index; use make engines-java', flush=True)
        for arch in ['amd64', 'arm64']:
            go_task = api.call('POST', '/api/v1/tasks', {**input_body, 'inputKind': 'artifact', 'inputPath': 'lab-a/apps/go-' + arch}, expect=201)
            until(lambda: completed(go_task), timeout=150)
            report = max((directory / 'worker').glob('scan-*/trivy.json'), key=lambda p: p.stat().st_mtime_ns)
            analyzed = json.loads(report.read_text())
            assert any(item.get('Type') == 'gobinary' for item in analyzed.get('Results', [])), 'Go build information was not analyzed'
        print('PASS Go Linux amd64/arm64 ELF inputs: build metadata analyzed without executing either binary', flush=True)
        # A changed copy must fail before launching a scan, without new findings.
        (directory / 'inputs/lab-a/os/var/lib/dpkg/status').write_text('changed fixture')
        changed = api.call('POST', '/api/v1/tasks', rootfs_input, expect=201)
        failed = until(lambda: next((t for t in api.call('GET', '/api/v1/tasks')['items']
                                    if t['id'] == changed['id'] and t['status'] == 'FAILED'), None))
        assert failed['error'] and not any(f['taskId'] == changed['id'] for f in api.call('GET', '/api/v1/findings')['items'])
        print('PASS changed OS snapshot: rejected without success findings', flush=True)
        image_task=api.call('POST','/api/v1/tasks',{**input_body,'inputKind':'image-archive','inputPath':'image.tar'},expect=201)
        until(lambda: completed(image_task),timeout=150)
        image_findings=[f for f in api.call('GET','/api/v1/findings')['items'] if f['taskId']==image_task['id']]
        assert image_findings and all(f.get('artifactId','').startswith('sha256:') for f in image_findings)
        print('PASS Trivy Docker-save archive: offline scan and immutable image identity',flush=True)
        oci_task = api.call('POST', '/api/v1/tasks', {**input_body, 'inputKind': 'image-archive', 'inputPath': 'lab-a/images/middleware.tar'}, expect=201)
        until(lambda: completed(oci_task), timeout=150)
        oci_findings = [f for f in api.call('GET', '/api/v1/findings')['items'] if f['taskId'] == oci_task['id']]
        assert {f['id'] for f in oci_findings} == {f['id'] for f in image_findings}, 'OCI and Docker image identity must agree'
        assert all('lab-a' in f.get('description', '') for f in oci_findings)
        print('PASS preexported OCI archive: same immutable image findings; no Docker/containerd/Kubernetes access', flush=True)
        unsupported = api.call('POST', '/api/v1/tasks', {**rootfs_input, 'inputPath': 'lab-kylin/os'}, expect=201)
        failed = until(lambda: next((t for t in api.call('GET', '/api/v1/tasks')['items']
                                    if t['id'] == unsupported['id'] and t['status'] == 'FAILED'), None))
        assert '尚未适配' in failed['error'] and not any(f['taskId'] == unsupported['id'] for f in api.call('GET', '/api/v1/findings')['items'])
        print('PASS unsupported Kylin fixture: explicit coverage failure; no CentOS substitution', flush=True)
        print(f'PASS trivy: offline DB + local dependency lock -> {len(findings)} findings; repeat scan deduplicated', flush=True)
        task = api.call('POST', '/api/v1/tasks', {**input_body, 'inputPath': 'missing'}, expect=201)
        failed = until(lambda: next((t for t in api.call('GET', '/api/v1/tasks')['items']
                                    if t['id'] == task['id'] and t['status'] == 'FAILED'), None))
        assert failed['error']
        print('PASS missing input: task FAILED without manufactured success findings', flush=True)
        result = {'state': 'PASS', 'realServersContacted': False, 'fixturePaths': sorted(set(requests)),
                  'engineFindingCounts': counts, 'imageArchiveFindingCount':len(image_findings), 'linuxOSFindingCount': len(os_findings),
                  'collectedAppFindingCount': len(app_findings), 'ociArchiveFindingCount': len(oci_findings),
                  'javaIndexTested': java_available, 'javaFixtureFindingCount': len(java_findings), 'goFixtureArchitectures': ['amd64', 'arm64'],
                  'zapTested': zap_available,
                  'unsupportedDistributionRejected': True, 'checks': ['Linux rootfs collector', 'snapshot integrity', 'real process/report/persistence', 'skip ports',
                  *(['ZAP offline passive analysis'] if zap_available else []), 'Trivy offline scan', 'stable dedup', 'failure reporting']}
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
        # Preserve reports/database/logs as evidence, not a second 1.5+ GiB DB cache.
        for cache in (directory / 'worker').glob('trivy-cache-*'):
            shutil.rmtree(cache)


if __name__ == '__main__':
    main()
