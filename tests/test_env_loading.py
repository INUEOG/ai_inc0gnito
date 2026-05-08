from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from guardit.ai.llm_judge import LLMJudge
from guardit.cli import _doctor
from guardit.config import load_config
from guardit.models import AuthorTrust, RepoMetadata


class EnvLoadingTest(unittest.TestCase):
    def test_load_config_reads_project_root_env_for_gemini_key(self) -> None:
        with tempfile.TemporaryDirectory(prefix="guardit_env_project_") as tmp:
            root = Path(tmp)
            (root / ".env").write_text("GEMINI_API_KEY=project-key\nGUARDIT_LLM_PROVIDER=gemini-api\n", encoding="utf-8")
            with patch.dict("os.environ", {}, clear=True), patch("guardit.config._project_root", return_value=root):
                config = load_config()
                self.assertEqual(config.llm_provider, "gemini-api")
                self.assertEqual(__import__("os").environ.get("GEMINI_API_KEY"), "project-key")

    def test_doctor_reports_env_and_gemini_key(self) -> None:
        with tempfile.TemporaryDirectory(prefix="guardit_env_doctor_") as tmp:
            root = Path(tmp)
            (root / ".env").write_text("GEMINI_API_KEY=doctor-key\n", encoding="utf-8")
            with patch.dict("os.environ", {}, clear=True), patch("guardit.config._project_root", return_value=root):
                config = load_config()
                output = io.StringIO()
                with redirect_stdout(output):
                    _doctor(config)
            text = output.getvalue()
            self.assertIn("GEMINI_API_KEY: 설정됨", text)
            self.assertIn("project .env: 설정됨", text)
            self.assertIn("Provider used:  gemini-api", text)

    def test_missing_gemini_key_message_is_actionable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="guardit_env_missing_") as tmp:
            root = Path(tmp)
            with patch.dict("os.environ", {}, clear=True), patch("guardit.config._project_root", return_value=root):
                result = LLMJudge(provider="gemini-api", model="gemini-test").judge(
                    suspicious_files=[],
                    evidence=[],
                    sandbox_logs=[],
                    metadata=RepoMetadata(source="local", author_trust=AuthorTrust()),
                    rule_score=0,
                )
        self.assertIn(".env 또는 환경변수에 API 키를 설정하세요", result.error or "")


if __name__ == "__main__":
    unittest.main()
