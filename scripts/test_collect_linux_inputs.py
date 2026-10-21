#!/usr/bin/env python3
"""Collector tests use synthetic Linux files only; no host inventory or daemon."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

import collect_linux_inputs as collector


class CollectorTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='scanner-collect-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.linux = self.root / 'linux'
        self.put('etc/os-release', 'ID=debian\nVERSION_ID="12"\n')
        self.put('var/lib/dpkg/status', 'Package: fixture\nStatus: install ok installed\nVersion: 1.0\n\n')

    def put(self, name, body):
        path = self.linux / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
        return path

    def run_collect(self, extra=(), output='lab-a'):
        path = self.root / output
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            collector.main(['--source', 'lab-a', '--rootfs', str(self.linux), '--output', str(path), *extra])
        return path

    def test_os_application_selection_and_hashes(self):
        app = self.root / 'app'
        app.mkdir()
        (app / 'package-lock.json').write_text('{"lockfileVersion": 2}')
        (app / '.env').write_text('EXAMPLE_ONLY=not-a-real-key')
        (app / 'config.yaml').write_text('fixture: true')
        (app / '.git').mkdir()
        (app / '.git/package-lock.json').write_text('excluded')
        output = self.run_collect(['--app', 'web=' + str(app)])
        self.assertEqual((output / '.gitignore').read_text(), '*\n')
        self.assertFalse((output / 'apps/web/.env').exists())
        self.assertFalse((output / 'apps/web/config.yaml').exists())
        self.assertFalse((output / 'apps/web/.git').exists())
        receipt = json.loads((output / 'collection.json').read_text())
        self.assertEqual([c['kind'] for c in receipt['components']], ['rootfs', 'filesystem'])
        for relative in ['os', 'apps/web']:
            directory = output / relative
            manifest = json.loads((directory / collector.SNAPSHOT).read_text())
            self.assertEqual(manifest['source'], 'lab-a')
            for name, digest in manifest['files'].items():
                file = directory / name
                self.assertEqual(hashlib.sha256(file.read_bytes()).hexdigest(), digest)
                self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(SystemExit):
            self.run_collect()

    def test_absolute_os_symlink_stays_inside_fixture(self):
        (self.linux / 'etc/os-release').unlink()
        target = self.put('usr/lib/os-release', 'ID=debian\nVERSION_ID=12\n')
        (self.linux / 'etc/os-release').symlink_to('/usr/lib/os-release')
        output = self.run_collect()
        self.assertEqual((output / 'os/etc/os-release').read_bytes(), target.read_bytes())
        self.assertFalse((output / 'os/etc/os-release').is_symlink())

    def test_runtime_service_inventory_is_bounded_and_read_only(self):
        self.put('etc/systemd/system/apache2.service', '[Unit]\nDescription=fixture\n')
        self.put('etc/init.d/redis-server', '#!/bin/sh\n')
        self.put('proc/101/comm', 'java\n')
        self.put('proc/102/comm', 'java\n')
        self.put('proc/103/comm', 'bad name\n')
        (self.linux / 'etc/systemd/system/tomcat.service').symlink_to('/does/not/matter')
        self.put('proc/101/cmdline', 'secret-args\x00must-not-be-collected')
        output = self.run_collect()
        inventory = json.loads((output / 'runtime-services.json').read_text())
        self.assertEqual(inventory['schemaVersion'], 1)
        self.assertEqual(inventory['services'], [
            {'name': 'redis-server', 'manager': 'init', 'state': 'installed'},
            {'name': 'java', 'manager': 'process', 'state': 'running'},
            {'name': 'apache2', 'manager': 'systemd', 'state': 'installed'},
            {'name': 'tomcat', 'manager': 'systemd', 'state': 'installed'},
        ])
        self.assertEqual((output / 'runtime-services.json').stat().st_mode & 0o777, 0o600)
        self.assertNotIn('cmdline', (output / 'runtime-services.json').read_text())

    def test_escaping_symlink_and_missing_package_db_fail_atomically(self):
        (self.linux / 'etc/os-release').unlink()
        (self.linux / 'etc/os-release').symlink_to('../../elsewhere')
        with self.assertRaises(SystemExit):
            self.run_collect()
        self.assertFalse((self.root / 'lab-a').exists())
        self.assertEqual(list(self.root.glob('.scanner-collect-*')), [])
        (self.linux / 'etc/os-release').unlink()
        self.put('etc/os-release', 'ID=debian\n')
        (self.linux / 'var/lib/dpkg/status').unlink()
        with self.assertRaises(SystemExit):
            self.run_collect()
        self.assertFalse((self.root / 'lab-a').exists())

    def test_sqlite_rpm_backup_includes_committed_wal(self):
        (self.linux / 'var/lib/dpkg/status').unlink()
        database = self.linux / 'usr/lib/sysimage/rpm/rpmdb.sqlite'
        database.parent.mkdir(parents=True)
        connection = sqlite3.connect(database)
        self.addCleanup(connection.close)
        connection.execute('PRAGMA journal_mode=WAL')
        connection.execute('CREATE TABLE fixture (package TEXT)')
        connection.execute("INSERT INTO fixture VALUES ('fixture-rpm')")
        connection.commit()
        self.assertTrue(Path(str(database) + '-wal').exists())
        output = self.run_collect()
        with sqlite3.connect(output / 'os/usr/lib/sysimage/rpm/rpmdb.sqlite') as backup:
            self.assertEqual(backup.execute('SELECT package FROM fixture').fetchone()[0], 'fixture-rpm')

    def test_application_symlink_and_unselected_config_file_fail(self):
        app = self.root / 'app'
        app.mkdir()
        (app / 'package-lock.json').symlink_to(self.linux / 'etc/os-release')
        with self.assertRaises(SystemExit):
            self.run_collect(['--app', 'web=' + str(app)])
        config = self.root / 'config.env'
        config.write_text('EXAMPLE_ONLY=fixture')
        with self.assertRaises(SystemExit):
            self.run_collect(['--app', 'web=' + str(config)])

    def test_docker_only_exports_explicit_image_to_local_socket(self):
        commands = []

        def save(command, **kwargs):
            commands.append(command)
            self.assertEqual(command[0:3], ['docker', '--host', 'unix:///var/run/docker.sock'])
            self.assertEqual(command[5:7], ['image', 'save'])
            self.assertEqual(command[-2:], ['--', 'fixture:local'])
            self.assertNotIn('DOCKER_HOST', kwargs['env'])
            Path(command[command.index('--output') + 1]).write_bytes(b'local-image-fixture')

        with mock.patch.object(collector.subprocess, 'run', side_effect=save), mock.patch.dict(
                os.environ, {'DOCKER_HOST': 'tcp://192.0.2.1:2375'}):
            output = self.run_collect(['--image', 'web=fixture:local'])
        self.assertEqual(len(commands), 1)
        image = output / 'images/web.tar'
        manifest = json.loads(Path(str(image) + collector.SNAPSHOT).read_text())
        self.assertEqual(list(manifest['files']), ['web.tar'])
        self.assertEqual(manifest['kind'], 'image-archive')

    def test_duplicate_names_are_rejected_before_collection(self):
        with self.assertRaises(SystemExit):
            self.run_collect(['--app', 'web=/example', '--app', 'web=/other'])
        self.assertFalse((self.root / 'lab-a').exists())

    def test_preexported_image_does_not_need_docker_or_kubernetes_access(self):
        archive = self.root / 'fixture.tar'
        archive.write_bytes(b'operator-exported-fixture')
        with mock.patch.object(collector.subprocess, 'run', side_effect=AssertionError('no daemon access')):
            output = self.run_collect(['--image-archive', 'web=' + str(archive)])
        self.assertEqual((output / 'images/web.tar').read_bytes(), archive.read_bytes())
        self.assertTrue((output / 'images/web.tar.scanner-input.json').exists())
        with self.assertRaises(SystemExit):
            self.run_collect(['--image', 'web=fixture:local', '--image-archive', 'web=' + str(archive)], output='other')

    def test_mixed_application_splits_lockfiles_and_deployed_artifacts(self):
        app = self.root / 'app'
        app.mkdir()
        (app / 'package-lock.json').write_text('{}')
        (app / 'fixture.jar').write_bytes(b'Java metadata fixture')
        output = self.run_collect(['--app', 'web=' + str(app)])
        receipt = json.loads((output / 'collection.json').read_text())
        self.assertEqual([c['kind'] for c in receipt['components']], ['rootfs', 'filesystem', 'artifact'])
        self.assertTrue((output / 'apps/web/dependencies/package-lock.json').is_file())
        self.assertTrue((output / 'apps/web/artifacts/fixture.jar').is_file())
        for relative, kind in [('dependencies', 'filesystem'), ('artifacts', 'artifact')]:
            manifest = json.loads((output / 'apps/web' / relative / collector.SNAPSHOT).read_text())
            self.assertEqual(manifest['kind'], kind)

    def test_mixed_application_preserves_overlapping_component_paths(self):
        app = self.root / 'app'
        files = {
            'fixture.jar': b'root Java fixture',
            'artifacts/fixture.jar': b'nested Java fixture',
            'package-lock.json': b'{"name":"root-fixture"}',
            'dependencies/package-lock.json': b'{"name":"nested-fixture"}',
        }
        for name, body in files.items():
            path = app / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        output = self.run_collect(['--app', 'web=' + str(app)])
        for sub, kind in [('artifacts', 'artifact'), ('dependencies', 'filesystem')]:
            directory = output / 'apps/web' / sub
            expected = {name: body for name, body in files.items()
                        if collector.deployed_file(name) == (kind == 'artifact')}
            manifest = json.loads((directory / collector.SNAPSHOT).read_text())
            self.assertEqual(manifest['kind'], kind)
            self.assertEqual(set(manifest['files']), set(expected))
            self.assertEqual({str(path.relative_to(directory)) for path in directory.rglob('*')
                              if path.is_file() and path.name != collector.SNAPSHOT}, set(expected))
            for name, body in expected.items():
                self.assertEqual((directory / name).read_bytes(), body)
                self.assertEqual(manifest['files'][name], hashlib.sha256(body).hexdigest())
        self.assertEqual(list(output.glob('.app-split-*')), [])

    def test_mixed_application_split_failure_cleans_unpublished_output(self):
        app = self.root / 'app'
        (app / 'artifacts').mkdir(parents=True)
        (app / 'fixture.jar').write_bytes(b'root Java fixture')
        (app / 'artifacts/fixture.jar').write_bytes(b'nested Java fixture')
        (app / 'package-lock.json').write_text('{}')
        original_rename = Path.rename
        moved = 0

        def fail_during_split(path, target):
            nonlocal moved
            if path.name == 'fixture.jar':
                moved += 1
                if moved == 2:
                    raise OSError('synthetic storage failure')
            return original_rename(path, target)

        with mock.patch.object(Path, 'rename', autospec=True, side_effect=fail_during_split):
            with self.assertRaises(SystemExit):
                self.run_collect(['--app', 'web=' + str(app)])
        self.assertEqual(moved, 2)
        self.assertFalse((self.root / 'lab-a').exists())
        self.assertEqual(list(self.root.glob('.scanner-collect-*')), [])



class SSHApplicationCollectorTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='scanner-app-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.linux = self.root / 'fixture'
        self.appdir = self.linux / 'opt/demo'
        self.appdir.mkdir(parents=True)
        self.apps = [{'alias': 'demo', 'directory': '/opt/demo', 'includeJava': True, 'includeGo': False}]

    def token(self):
        import base64
        return 'x' + base64.urlsafe_b64encode(json.dumps(self.apps, separators=(',', ':')).encode()).decode().rstrip('=')

    def collect(self):
        output = self.root / 'output'
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            collector.main(['--source', 'target-fixture', '--rootfs', str(self.linux), '--output', str(output), '--ssh-apps-b64=' + self.token()])
        return output

    def test_ssh_selects_only_explicit_deployment_and_enabled_types(self):
        (self.appdir / 'service.jar').write_bytes(b'fixture-jar')
        (self.appdir / 'settings.yaml').write_text('fixture: true')
        (self.appdir / 'native').write_bytes(b'\x7fELFfixture')
        other = self.linux / 'opt/other'
        other.mkdir()
        (other / 'other.jar').write_bytes(b'excluded')
        output = self.collect()
        files = sorted(p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file())
        self.assertEqual(files, ['apps/demo/0000/.scanner-input.json', 'apps/demo/0000/artifact.jar'])
        manifest = json.loads((output / files[0]).read_text())
        self.assertEqual(manifest['kind'], 'artifact')
        self.assertEqual(manifest['files'], {'artifact.jar': hashlib.sha256(b'fixture-jar').hexdigest()})
        self.assertEqual((output / files[1]).stat().st_mode & 0o777, 0o600)

    def test_ssh_rejects_symlink_and_excess_depth_without_publishing(self):
        for kind in ('file-link', 'directory-link', 'ancestor-link', 'depth'):
            with self.subTest(kind=kind):
                path = self.appdir / 'service.jar'
                path.write_bytes(b'fixture')
                if kind == 'file-link':
                    path.unlink()
                    path.symlink_to(self.root / 'not-read')
                elif kind == 'directory-link':
                    (self.appdir / 'link').symlink_to(self.root, target_is_directory=True)
                elif kind == 'ancestor-link':
                    path.unlink()
                    self.appdir.rmdir()
                    self.appdir.symlink_to(self.root, target_is_directory=True)
                else:
                    (self.appdir / 'one/two/three/four').mkdir(parents=True)
                with self.assertRaises(SystemExit):
                    self.collect()
                self.assertFalse((self.root / 'output').exists())
                if self.appdir.is_symlink():
                    self.appdir.unlink()
                    self.appdir.mkdir()
                else:
                    import shutil
                    shutil.rmtree(self.appdir)
                    self.appdir.mkdir()

    def test_ssh_limits_fail_instead_of_truncating(self):
        (self.appdir / 'service.jar').write_bytes(b'fixture')
        with mock.patch.dict(collector.collect_ssh_apps.__globals__, {'SSH_APP_MAX_FILE': 2}):
            with self.assertRaises(SystemExit):
                self.collect()
        (self.appdir / 'service.jar').unlink()
        for n in range(17):
            (self.appdir / ('%02d.jar' % n)).write_bytes(b'fixture')
        with self.assertRaises(SystemExit):
            self.collect()
        self.assertFalse((self.root / 'output').exists())

    def test_ssh_no_matching_files_is_failure(self):
        (self.appdir / 'settings.yaml').write_text('fixture: true')
        with self.assertRaises(SystemExit):
            self.collect()
        self.assertFalse((self.root / 'output').exists())

    def test_ssh_revalidates_payload_paths_types_and_count(self):
        for directory in ('/', '/opt', '/var/lib', '/opt/../etc', '/opt//demo', '/proc/demo', '/mnt/demo', '/opt/demo\n', '/opt/demo\u0085'):
            self.apps[0]['directory'] = directory
            with self.assertRaises(ValueError):
                collector.decode_ssh_apps(self.token())
        self.apps[0]['directory'] = '/opt/demo'
        self.apps[0]['includeJava'] = 'yes'
        with self.assertRaises(ValueError):
            collector.decode_ssh_apps(self.token())


    def test_ssh_file_mutation_is_rejected(self):
        path = self.appdir / 'service.jar'
        path.write_bytes(b'fixture-java')
        original = collector.ssh_file_identity
        checks = [0]
        def changed(info):
            checks[0] += 1
            value = original(info)
            # Simulate a descriptor changing after its contents were copied.
            if checks[0] == 3:
                return value[:-1] + (value[-1] + 1,)
            return value
        with mock.patch.dict(collector.collect_ssh_apps.__globals__, {'ssh_file_identity': changed}):
            with self.assertRaises(SystemExit):
                self.collect()
        self.assertFalse((self.root / 'output').exists())

    def test_ssh_entry_limit_fails_without_truncating(self):
        (self.appdir / 'service.jar').write_bytes(b'fixture')
        for n in range(4096):
            (self.appdir / ('entry-%04d.txt' % n)).write_text('fixture')
        with self.assertRaises(SystemExit):
            self.collect()
        self.assertFalse((self.root / 'output').exists())


if __name__ == '__main__':
    unittest.main()
