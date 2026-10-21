#!/usr/bin/env python3
"""Static checks for release workflow contracts; no GitHub or network access."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WorkflowContractTest(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / ".github/workflows/build-artifacts.yml").read_text(
            encoding="utf-8"
        )
        self.package_doc = (ROOT / "docs/offline-package.md").read_text(
            encoding="utf-8"
        )

    def test_zap_is_an_explicit_manual_opt_in(self):
        self.assertIn("include_zap:", self.workflow)
        self.assertIn("type: boolean", self.workflow)
        self.assertIn("default: false", self.workflow)
        self.assertIn("--engine core", self.workflow)
        self.assertIn("--engine zap", self.workflow)
        self.assertIn("inputs.include_zap == true", self.workflow)
        self.assertIn("test ! -e build_output/bin/zap", self.workflow)
        self.assertIn("ZAP is included only when", self.workflow)

    def test_release_package_has_one_artifact_path_and_clear_engine_docs(self):
        self.assertEqual(self.workflow.count("path: dist_pkg/*"), 1)
        self.assertIn("Nuclei 和 Trivy", self.package_doc)
        self.assertIn("include_zap=true", self.package_doc)
        self.assertIn("Java 17", self.package_doc)


if __name__ == "__main__":
    unittest.main()
