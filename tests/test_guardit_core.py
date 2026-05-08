from __future__ import annotations

from pathlib import Path
import unittest
from unittest.mock import patch

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

    def test_llm_required_allows_degraded_ai_after_provider_failure(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            config = load_config()
            config = config.__class__(llm_provider="gemini-api", llm_required=True, llm_backoff_seconds=0)
            report = scan_source(str(Path("demo_repos/benign")), config)
        self.assertNotEqual(report.score.risk_level, "UNKNOWN")
        self.assertTrue(report.llm.used)
        self.assertEqual(report.llm.status, "degraded")


if __name__ == "__main__":
    unittest.main()
