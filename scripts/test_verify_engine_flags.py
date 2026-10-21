import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_engine_flags


class VerifyEngineFlagsTest(unittest.TestCase):
    def test_missing_zap_is_optional_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            original = verify_engine_flags.ROOT
            try:
                verify_engine_flags.ROOT = Path(directory)
                self.assertFalse(verify_engine_flags.zap_jar_path().is_file())
            finally:
                verify_engine_flags.ROOT = original

    def test_pinned_zap_path_is_detected_when_present(self):
        with tempfile.TemporaryDirectory() as directory:
            original = verify_engine_flags.ROOT
            try:
                root = Path(directory)
                verify_engine_flags.ROOT = root
                path = root / 'bin/zap/zap-2.17.0.jar'
                path.parent.mkdir(parents=True)
                path.write_bytes(b'fixture')
                self.assertTrue(verify_engine_flags.zap_jar_path().is_file())
            finally:
                verify_engine_flags.ROOT = original


if __name__ == '__main__':
    unittest.main()
