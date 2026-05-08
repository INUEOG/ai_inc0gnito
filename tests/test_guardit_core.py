from __future__ import annotations

from pathlib import Path
import unittest

from guardit.config import load_config
from guardit.file_filter import is_candidate_path
from guardit.scanner import scan_source


class GuarditCoreTest(unittest.TestCase):
    def test_candidate_path_detects_required_files(self) -> None:
        self.assertTrue(is_candidate_path(".vscode/tasks.json")[0])
        self.assertTrue(is_candidate_path("package.json")[0])
        self.assertTrue(is_candidate_path("scripts/init.js")[0])
        self.assertTrue(is_candidate_path(".husky/pre-commit")[0])

    def test_malicious_demo_forces_malicious(self) -> None:
        config = load_config()
        config = config.__class__(llm_provider="off")
        report = scan_source(str(Path("demo_repos/malicious")), config)
        self.assertEqual(report.score.risk_level, "MALICIOUS")
        self.assertTrue(report.score.forced_malicious)
        self.assertTrue(any(item.type == "source_to_sink" for item in report.evidence))


if __name__ == "__main__":
    unittest.main()
