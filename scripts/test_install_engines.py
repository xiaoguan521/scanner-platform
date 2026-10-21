import hashlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name('install_engines.py')
SPEC = importlib.util.spec_from_file_location('install_engines_under_test', MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class DownloadTest(unittest.TestCase):
    def test_retries_then_atomically_publishes_archive(self):
        payload = b'fixture archive bytes'
        response = io.BytesIO(payload)
        response.__enter__ = lambda self: self
        response.__exit__ = lambda self, exc_type, exc, tb: None
        calls = 0

        def open_url(request, timeout):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise TimeoutError('fixture timeout')
            return response

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'archive'
            with mock.patch.object(MODULE, 'DOWNLOAD_ATTEMPTS', 2), \
                    mock.patch.object(MODULE.time, 'sleep'), \
                    mock.patch.object(MODULE.urllib.request, 'urlopen', side_effect=open_url):
                digest = MODULE.download_archive('https://example.invalid/archive', archive)

            self.assertEqual(calls, 2)
            self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
            self.assertEqual(archive.read_bytes(), payload)
            self.assertFalse(archive.with_suffix('.partial').exists())

    def test_failed_attempt_does_not_leave_partial_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'archive'
            with mock.patch.object(MODULE, 'DOWNLOAD_ATTEMPTS', 1), \
                    mock.patch.object(MODULE.urllib.request, 'urlopen', side_effect=TimeoutError('fixture timeout')):
                with self.assertRaises(RuntimeError):
                    MODULE.download_archive('https://example.invalid/archive', archive)
            self.assertFalse(archive.exists())
            self.assertFalse(archive.with_suffix('.partial').exists())


if __name__ == '__main__':
    unittest.main()
