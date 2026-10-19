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


if __name__ == '__main__':
    unittest.main()
