#!/usr/bin/env python3
"""Collect explicit local Linux inputs for offline Trivy tasks; never run a scan."""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse

SNAPSHOT = '.scanner-input.json'
MAX_FILE = 16 << 30
MAX_TOTAL = 32 << 30
MAX_FILES = 10000
ALIAS = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\Z')
LOCKS = {'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml',
         'poetry.lock', 'Pipfile.lock', 'uv.lock', 'requirements.txt', 'Gemfile.lock',
         'composer.lock', 'packages.lock.json', 'packages.config', 'go.mod', 'go.sum', 'Cargo.lock'}
EXCLUDE = {'.git', '.svn', 'node_modules', '.venv', 'venv', '__pycache__', '.cache', '.npm', '.m2', '.gradle'}
OS_FILES = ['etc/os-release', 'usr/lib/os-release', 'etc/debian_version', 'etc/redhat-release', 'etc/centos-release', 'etc/system-release-cpe',
            'etc/alpine-release', 'var/lib/dpkg/status', 'lib/apk/db/installed',
            'var/lib/rpm/Packages', 'var/lib/rpm/Packages.db', 'var/lib/rpm/rpmdb.sqlite',
            'usr/lib/sysimage/rpm/Packages', 'usr/lib/sysimage/rpm/Packages.db', 'usr/lib/sysimage/rpm/rpmdb.sqlite']


def root_file(root, name):
    """Resolve Linux absolute symlinks within the selected root, never the host root."""
    parts, pending, links = [], list(PurePosixPath(name).parts), 0
    while pending:
        part = pending.pop(0)
        if part in ('', '.', '/'):
            continue
        if part == '..':
            if not parts:
                raise ValueError('OS metadata symlink escapes the selected root')
            parts.pop()
            continue
        path = root.joinpath(*parts, part)
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(mode):
            links += 1
            if links > 20:
                raise ValueError('OS metadata has a symlink loop')
            target = PurePosixPath(os.readlink(path))
            if target.is_absolute():
                parts = []
            pending = list(target.parts) + pending
        else:
            parts.append(part)
    path = root.joinpath(*parts)
    if not path.is_file():
        raise ValueError('OS metadata must be a regular file')
    return path


def copy_stable(source, destination):
    before = source.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE:
        raise ValueError('Input is not a regular file or exceeds 16 GiB')
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with source.open('rb') as src, destination.open('xb') as dst:
        copied = 0
        while True:
            chunk = src.read(128 << 10)
            if not chunk:
                break
            copied += len(chunk)
            if copied > before.st_size:
                raise ValueError('Input changed during collection; retry when it is stable')
            dst.write(chunk)
    after = source.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or copied != before.st_size:
        raise ValueError('Input changed during collection; retry when it is stable')
    destination.chmod(0o600)


def snapshot(root, source, kind, collected, image=None):
    files = [image] if image else sorted(p for p in root.rglob('*') if p.is_file())
    if not files or len(files) > MAX_FILES:
        raise ValueError('No supported files found, or more than 10000 files selected')
    hashes, total = {}, 0
    for path in files:
        size = path.stat().st_size
        total += size
        if size > MAX_FILE or total > MAX_TOTAL:
            raise ValueError('Collection exceeds 16 GiB per file / 32 GiB per component')
        with path.open('rb') as stream:
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(128 << 10), b''):
                digest.update(chunk)
        hashes[path.relative_to(root).as_posix()] = digest.hexdigest()
    data = {'schemaVersion': 1, 'source': source, 'kind': kind,
            'collectedAt': collected, 'files': hashes}
    path = Path(str(image) + SNAPSHOT) if image else root / SNAPSHOT
    encoded = json.dumps(data, ensure_ascii=False, indent=2) + '\n'
    if len(encoded.encode()) > 2 << 20:
        raise ValueError('Collection metadata exceeds 2 MiB')
    path.write_text(encoded)
    path.chmod(0o600)


def collect_os(root, destination):
    copied = []
    for name in OS_FILES:
        source = root_file(root, name)
        if source is None:
            continue
        target = destination / name
        if name.endswith('rpmdb.sqlite'):
            if not hasattr(sqlite3.Connection, 'backup'):
                raise ValueError('SQLite RPM snapshots require Python 3.7+; Python 3.6 supports dpkg/apk/legacy RPM files')
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # SQLite backup includes a committed WAL without modifying the source.
            uri = 'file:' + urllib.parse.quote(str(source), safe='/') + '?mode=ro'
            deadline = time.monotonic() + 60

            def progress(status, remaining, total):
                if time.monotonic() > deadline:
                    raise ValueError('RPM database backup timed out; retry when package changes have stopped')

            with sqlite3.connect(uri, uri=True, timeout=5) as src, sqlite3.connect(target) as dst:
                src.backup(dst, pages=256, progress=progress)
            target.chmod(0o600)
        else:
            copy_stable(source, target)
        copied.append(name)
    if not any(name.endswith('os-release') for name in copied) or not any(
            name.endswith(('dpkg/status', 'apk/db/installed', '/Packages', '/Packages.db', '/rpmdb.sqlite')) for name in copied):
        raise ValueError('A Linux os-release file and supported dpkg/apk/rpm package database are required')


def deployed_file(name):
    return name.lower().endswith(('.jar', '.war', '.ear', '.par'))


def application_file(name):
    return name in LOCKS or deployed_file(name) or name.endswith('.deps.json') or (
        name.startswith('requirements') and name.endswith('.txt'))


def collect_application(source, destination):
    if source.is_symlink():
        raise ValueError('Application input must not be a symlink')
    if source.is_file():
        with source.open('rb') as stream:
            elf = stream.read(4) == b'\x7fELF'
        if not application_file(source.name) and not elf:
            raise ValueError('Select a dependency manifest, JAR/WAR/EAR or an ELF executable')
        copy_stable(source, destination / source.name)
        return {'artifact' if deployed_file(source.name) or elf else 'filesystem'}
    if not source.is_dir():
        raise ValueError('Application input is missing')
    count, total, kinds = 0, 0, set()
    for current, dirs, names in os.walk(source, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name not in EXCLUDE)
        if any((Path(current) / name).is_symlink() for name in dirs):
            raise ValueError('Application contains a symlink directory; select a concrete dependency directory')
        for name in sorted(names):
            if not application_file(name):
                continue
            path = Path(current) / name
            if path.is_symlink():
                raise ValueError('Selected dependency file is a symlink')
            count += 1
            total += path.stat().st_size
            if count > MAX_FILES or total > MAX_TOTAL:
                raise ValueError('Application input is too large; split it into separate components')
            copy_stable(path, destination / path.relative_to(source))
            kinds.add('artifact' if deployed_file(name) else 'filesystem')
    return kinds


def named(value):
    name, separator, target = value.partition('=')
    if not separator or not ALIAS.fullmatch(name) or not target or '\x00' in target:
        raise argparse.ArgumentTypeError('Use alias=path or alias=image with a short alphanumeric alias')
    return name, target



SSH_APP_MAX_FILE = 512 << 20
SSH_APP_MAX_TOTAL = 2 << 30


def ssh_app_directory(value):
    if not isinstance(value, str) or len(value.encode()) > 512 or not value.startswith('/') or value == '/':
        return False
    if any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in value) or any(part in ('', '.', '..') for part in value.split('/')[1:]):
        return False
    denied = ('/proc', '/sys', '/dev', '/run', '/tmp', '/net', '/mnt', '/media')
    if any(value == root or value.startswith(root + '/') for root in denied):
        return False
    return value not in ('/opt', '/srv', '/home', '/root', '/etc', '/usr', '/usr/local', '/var', '/var/lib', '/var/www', '/var/opt', '/var/local', '/bin', '/sbin', '/lib', '/lib64', '/boot')


def decode_ssh_apps(token):
    if sys.version_info < (3, 7):
        raise ValueError('SSH application collection requires Python 3.7+')
    if len(token) > 8192 or not re.fullmatch(r'x[A-Za-z0-9_-]+', token):
        raise ValueError('Invalid SSH application token')
    encoded = token[1:]
    raw = base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True)
    if base64.urlsafe_b64encode(raw).decode().rstrip('=') != encoded:
        raise ValueError('Noncanonical application token')
    apps = json.loads(raw)
    if not isinstance(apps, list) or not 1 <= len(apps) <= 8:
        raise ValueError('Invalid SSH application count')
    seen = set()
    for app in apps:
        if not isinstance(app, dict) or set(app) != {'alias', 'directory', 'includeJava', 'includeGo'}:
            raise ValueError('Invalid SSH application shape')
        alias = app['alias']
        if not isinstance(alias, str) or not ALIAS.fullmatch(alias) or alias in seen or not ssh_app_directory(app['directory']):
            raise ValueError('Invalid SSH application alias or deployment directory')
        if type(app['includeJava']) is not bool or type(app['includeGo']) is not bool or not (app['includeJava'] or app['includeGo']):
            raise ValueError('Select Java or Go application artifacts')
        seen.add(alias)
    return apps


def ssh_file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def collect_ssh_apps(root, staging, apps, source, collected):
    # Directory descriptors keep every lookup beneath the explicitly selected
    # fixture/root. O_NOFOLLOW rejects symlinks at every path component.
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root_fd = os.open(str(root), flags)
    total = [0, 0, 0]  # bytes, selected artifacts, examined entries
    try:
        root_dev = os.fstat(root_fd).st_dev
        for app in apps:
            app_fd = os.dup(root_fd)
            try:
                for part in app['directory'].split('/')[1:]:
                    next_fd = os.open(part, flags, dir_fd=app_fd)
                    os.close(app_fd)
                    app_fd = next_fd
                    if os.fstat(app_fd).st_dev != root_dev:
                        raise ValueError('Application directory crosses a filesystem boundary')
                count = [0]
                def walk(fd, depth):
                    before_dir = os.fstat(fd)
                    with os.scandir(fd) as iterator:
                        entries = []
                        for entry in iterator:
                            total[2] += 1
                            if total[2] > 4096:
                                raise ValueError('SSH application entry limit exceeded')
                            entries.append(entry.name)
                    for name in sorted(entries):
                        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
                        if before.st_dev != root_dev or stat.S_ISLNK(before.st_mode):
                            raise ValueError('Application contains a symlink or filesystem boundary')
                        if stat.S_ISDIR(before.st_mode):
                            if depth >= 3:
                                raise ValueError('Application directory depth exceeds 3')
                            child = os.open(name, flags, dir_fd=fd)
                            try:
                                if ssh_file_identity(before) != ssh_file_identity(os.fstat(child)):
                                    raise ValueError('Application directory changed')
                                walk(child, depth + 1)
                            finally:
                                os.close(child)
                            continue
                        if not stat.S_ISREG(before.st_mode):
                            raise ValueError('Application contains a special file')
                        selected_java = app['includeJava'] and deployed_file(name)
                        # Read only explicitly enabled artifact candidates.
                        if not selected_java and not app['includeGo']:
                            continue
                        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                        with os.fdopen(file_fd, 'rb') as stream:
                            if ssh_file_identity(before) != ssh_file_identity(os.fstat(stream.fileno())):
                                raise ValueError('Application artifact changed before reading')
                            elf = stream.read(4) == b'\x7fELF'
                            if not selected_java and not (app['includeGo'] and elf):
                                continue
                            if before.st_size > SSH_APP_MAX_FILE or count[0] >= 16 or total[1] >= 32 or total[0] + before.st_size > SSH_APP_MAX_TOTAL:
                                raise ValueError('SSH application artifact limit exceeded')
                            # Fixed output names never expose deployment filenames.
                            suffix = Path(name).suffix.lower() if selected_java else '.elf'
                            destination = staging / 'apps' / app['alias'] / ('%04d' % count[0]) / ('artifact' + suffix)
                            destination.parent.mkdir(parents=True, mode=0o700)
                            stream.seek(0)
                            copied = 0
                            with destination.open('xb') as output:
                                while True:
                                    chunk = stream.read(128 << 10)
                                    if not chunk:
                                        break
                                    copied += len(chunk)
                                    if copied > before.st_size:
                                        raise ValueError('Application artifact grew')
                                    output.write(chunk)
                            if copied != before.st_size or ssh_file_identity(before) != ssh_file_identity(os.fstat(stream.fileno())) or ssh_file_identity(before) != ssh_file_identity(os.stat(name, dir_fd=fd, follow_symlinks=False)):
                                raise ValueError('Application artifact changed during collection')
                            destination.chmod(0o600)
                            stable_source = 'app-' + hashlib.sha256((source + '\x00' + app['alias'] + '\x00' + app['directory']).encode()).hexdigest()[:32]
                            snapshot(destination.parent, stable_source, 'artifact', collected)
                            count[0] += 1
                            total[0] += copied
                            total[1] += 1
                    if ssh_file_identity(before_dir) != ssh_file_identity(os.fstat(fd)):
                        raise ValueError('Application directory changed during collection')
                walk(app_fd, 0)
                if not count[0]:
                    raise ValueError('Application directory has no enabled Java or Go artifact')
            finally:
                os.close(app_fd)
    finally:
        os.close(root_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, help='Stable private host alias, e.g. lab-a (no auto-discovery)')
    parser.add_argument('--output', required=True, type=Path, help='NEW private output directory; never overwritten')
    parser.add_argument('--rootfs', type=Path, default=Path('/'), help='Linux root filesystem; defaults to / on Linux only')
    parser.add_argument('--app', action='append', type=named, default=[], help='Explicit alias=directory (manifests/JAR only), lockfile, JAR, or single ELF')
    parser.add_argument('--image', action='append', type=named, default=[], help='Explicit alias=LOCAL image ID/tag; docker image save only')
    parser.add_argument('--image-archive', action='append', type=named, default=[], help='Explicit alias=previously exported Docker/OCI tar, including containerd exports')
    parser.add_argument('--docker-socket', type=Path, default=Path('/var/run/docker.sock'), help='Explicit local Unix socket; no remote Docker contexts')
    parser.add_argument('--archive-stdout', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--ssh-apps-b64', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    ssh_apps = decode_ssh_apps(args.ssh_apps_b64) if args.ssh_apps_b64 else None
    if ssh_apps and (args.app or args.image or args.image_archive):
        parser.error('SSH application mode cannot combine other collection modes')
    if not ALIAS.fullmatch(args.source):
        parser.error('--source must be an alphanumeric alias (hyphen/underscore allowed, maximum 64 characters)')
    if args.rootfs == Path('/') and platform.system() != 'Linux':
        parser.error('Default / collection is Linux-only; --rootfs may select an isolated Linux fixture')
    for group in (args.app, args.image + args.image_archive):
        if len({name for name, _ in group}) != len(group):
            parser.error('Duplicate component aliases are not allowed')
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        parser.error('--output already exists; choose a new directory')
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = Path(tempfile.mkdtemp(prefix='.scanner-collect-', dir=output.parent))
    old_umask = os.umask(0o077)
    try:
        collected = dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')
        components = []
        if ssh_apps:
            collect_ssh_apps(args.rootfs, staging, ssh_apps, args.source, collected)
        else:
            components = [{'name': 'os', 'kind': 'rootfs', 'path': 'os'}]
            collect_os(args.rootfs.resolve(strict=True), staging / 'os')
            snapshot(staging / 'os', args.source, 'rootfs', collected)
        for name, path in args.app:
            destination = staging / 'apps' / name
            kinds = collect_application(Path(path).absolute(), destination)
            if not kinds:
                raise ValueError('Application has no supported dependency files or deployed artifacts')
            if len(kinds) == 1:
                kind = next(iter(kinds))
                snapshot(destination, args.source, kind, collected)
                components.append({'name': name, 'kind': kind, 'path': 'apps/' + name})
            else:
                # Trivy fs scans lockfiles; rootfs --pkg-types library scans
                # deployed JAR/Go artifacts. Keep explicit, disjoint tasks.
                # Split outside the source tree so existing artifacts/ and
                # dependencies/ paths cannot collide with their destinations.
                split = Path(tempfile.mkdtemp(prefix='.app-split-', dir=staging))
                for file in list(destination.rglob('*')):
                    if not file.is_file():
                        continue
                    sub = 'artifacts' if deployed_file(file.name) else 'dependencies'
                    target = split / sub / file.relative_to(destination)
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    file.rename(target)
                shutil.rmtree(destination)
                split.rename(destination)
                for sub, kind in [('dependencies', 'filesystem'), ('artifacts', 'artifact')]:
                    snapshot(destination / sub, args.source, kind, collected)
                    components.append({'name': name + '-' + sub, 'kind': kind, 'path': 'apps/' + name + '/' + sub})
        for name, reference in args.image:
            if reference.startswith('-') or len(reference) > 500 or not args.docker_socket.is_absolute():
                raise ValueError('Invalid image reference or local Docker socket path')
            destination = staging / 'images' / (name + '.tar')
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            env = {key: value for key, value in os.environ.items() if key == 'PATH'}
            # Isolate Docker configuration so inherited contexts/credentials do not
            # select another daemon. Save never pulls or starts an image/container.
            with tempfile.TemporaryDirectory(prefix='scanner-docker-config-') as config:
                subprocess.run(['docker', '--host', 'unix://' + str(args.docker_socket), '--config', config,
                                'image', 'save', '--output', str(destination), '--', reference],
                               env=env, stdout=subprocess.DEVNULL, check=True, timeout=1800)
            destination.chmod(0o600)
            snapshot(destination.parent, args.source, 'image-archive', collected, destination)
            components.append({'name': name, 'kind': 'image-archive', 'path': 'images/' + name + '.tar'})
        for name, path in args.image_archive:
            source = Path(path).absolute()
            if source.is_symlink() or source.suffix != '.tar':
                raise ValueError('Select a concrete Docker/OCI .tar archive')
            destination = staging / 'images' / (name + '.tar')
            copy_stable(source, destination)
            snapshot(destination.parent, args.source, 'image-archive', collected, destination)
            components.append({'name': name, 'kind': 'image-archive', 'path': 'images/' + name + '.tar'})
        receipt = {'source': args.source, 'collectedAt': collected, 'components': components,
                   'coverage': ['OS package database snapshot; not live kernel or process verification',
                                'Only explicitly selected application dependency files and image archives',
                                'Image writable layers, volumes and unregistered native binaries are not covered']}
        if not ssh_apps:
            (staging / 'collection.json').write_text(json.dumps(receipt, indent=2) + '\n')
            (staging / 'collection.json').chmod(0o600)
        # Keep the private inventory out of Git even if the operator selects an
        # output directory beneath a checkout instead of the usual runtime/.
        if not ssh_apps:
            (staging / '.gitignore').write_text('*\n')
            (staging / '.gitignore').chmod(0o600)
        # Recheck to avoid replacing an output created during collection.
        if output.exists():
            raise ValueError('Output appeared during collection; refusing to overwrite it')
        staging.rename(output)
        if args.archive_stdout:
            try:
                with tarfile.open(fileobj=sys.stdout.buffer, mode='w|gz') as archive:
                    for path in sorted(output.rglob('*')):
                        archive.add(path, arcname=path.relative_to(output).as_posix(), recursive=False)
                sys.stdout.buffer.flush()
            finally:
                shutil.rmtree(output, ignore_errors=True)
            return
        print('Collected private inputs:', output)
        for component in components:
            print(f'  Trivy {component["kind"]}: {output.name}/{component["path"]}')
        print('Copy this directory to the Worker inputs root. No scan has been started.')
    except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as error:
        parser.exit(1, f'Collection failed: {error}\nNo complete output was published.\n')
    finally:
        os.umask(old_umask)
        if staging.exists():
            shutil.rmtree(staging)
        if args.archive_stdout and output.exists():
            shutil.rmtree(output, ignore_errors=True)


if __name__ == '__main__':
    main()
