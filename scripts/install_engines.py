#!/usr/bin/env python3
"""Install pinned official scanner distributions; never execute a scan."""
import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
DOWNLOAD_ATTEMPTS = 3
DOWNLOAD_TIMEOUT_SECONDS = 120


def download_archive(url, archive):
    """Download one pinned archive with bounded retries and atomic replacement."""
    last_error = None
    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        partial = archive.with_suffix(archive.suffix + '.partial')
        partial.unlink(missing_ok=True)
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'scanner-platform-installer'})
            digest = hashlib.sha256()
            with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response, partial.open('wb') as output:
                size = 0
                while block := response.read(1024 * 1024):
                    size += len(block)
                    if size > 1024 * 1024 * 1024:
                        raise ValueError('download exceeds 1 GiB')
                    digest.update(block)
                    output.write(block)
            os.replace(partial, archive)
            return digest.hexdigest()
        except (OSError, urllib.error.URLError, TimeoutError) as error:
            last_error = error
            partial.unlink(missing_ok=True)
            if attempt == DOWNLOAD_ATTEMPTS:
                break
            delay = min(2 ** (attempt - 1), 8)
            print(f"Download attempt {attempt} failed ({error}); retrying in {delay}s", flush=True)
            time.sleep(delay)
    raise RuntimeError(f'download failed after {DOWNLOAD_ATTEMPTS} attempts: {last_error}') from last_error


def install(name, item, system, arch, destination):
    asset = item['assets'].get(system + '-' + arch, item['assets'].get('all'))
    if not asset:
        raise ValueError(f'{name}: unsupported platform {system}-{arch}')
    with tempfile.TemporaryDirectory(prefix='scanner-engine-') as temp:
        archive = Path(temp) / 'download'
        print(f"Downloading {name} {item['version']} from {asset['url']}", flush=True)
        digest = download_archive(asset['url'], archive)
        if digest != asset['sha256']:
            raise ValueError(f'{name}: SHA-256 mismatch; nothing installed')
        stage = Path(temp) / 'extracted'
        stage.mkdir()

        def save(member_name, source, mode=0o644):
            path = PurePosixPath(member_name)
            if path.is_absolute() or '..' in path.parts or '\\' in member_name or ':' in member_name:
                raise ValueError('unsafe archive path')
            target = stage.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as output:
                shutil.copyfileobj(source, output)
            target.chmod(mode & 0o777)

        if asset['url'].endswith('.zip'):
            with zipfile.ZipFile(archive) as source:
                for member in source.infolist():
                    if member.is_dir():
                        continue
                    mode = member.external_attr >> 16
                    if stat.S_ISLNK(mode):
                        raise ValueError('links are not allowed in distributions')
                    with source.open(member) as content:
                        save(member.filename, content, mode or 0o644)
        else:
            with tarfile.open(archive) as source:
                for member in source:
                    if member.isdir():
                        continue
                    if not member.isfile():
                        raise ValueError('links are not allowed in distributions')
                    with source.extractfile(member) as content:
                        save(member.name, content, member.mode)
        destination.mkdir(parents=True, exist_ok=True)
        if name == 'zap':
            package = next(stage.glob('ZAP_*'))
            target = destination / 'zap'
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(package, target)
            # Only ship the passive analysis pipeline used by this platform.
            keep = {'automation', 'commonlib', 'exim', 'network', 'pscan', 'pscanrules', 'reports', 'callhome'}
            for addon in (target / 'plugin').glob('*.zap'):
                if addon.name.split('-')[0] not in keep:
                    addon.unlink()
        else:
            executable = name + ('.exe' if system == 'windows' else '')
            source = next(stage.rglob(executable))
            temporary = destination / (executable + '.tmp')
            shutil.copy2(source, temporary)
            temporary.chmod(0o755)
            os.replace(temporary, destination / executable)
            license_dir = destination / 'licenses' / name
            license_dir.mkdir(parents=True, exist_ok=True)
            for source in stage.rglob('*'):
                if source.is_file() and source.name.lower().startswith(('license', 'notice')):
                    shutil.copy2(source, license_dir / source.name)
        (destination / (name + '.installed.json')).write_text(json.dumps({
            'version': item['version'], 'archiveSha256': asset['sha256'],
            'source': asset['url'], 'license': item['license'],
        }, indent=2) + '\n')
        print(f'Installed {name} {item["version"]} in {destination}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--engine',
        choices=['nuclei', 'trivy', 'zap', 'core', 'all'],
        default='all',
        help='engine to install; core installs Nuclei and Trivy, while ZAP is optional',
    )
    parser.add_argument('--platform', choices=['darwin', 'linux', 'windows'], default=platform.system().lower())
    parser.add_argument('--arch', choices=['arm64', 'amd64'], default={'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'amd64', 'AMD64': 'amd64'}.get(platform.machine()))
    parser.add_argument('--destination', type=Path, default=ROOT / 'bin')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'config/engines.lock.json').read_text())
    selected = {'nuclei', 'trivy'} if args.engine == 'core' else set(lock) if args.engine == 'all' else {args.engine}
    for name, item in lock.items():
        if name in selected:
            install(name, item, args.platform, args.arch, args.destination.resolve())


if __name__ == '__main__':
    main()
