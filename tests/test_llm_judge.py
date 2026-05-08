from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from guardit.ai.llm_judge import LLMJudge
from guardit.models import AuthorTrust, Evidence, RepoMetadata


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class LLMJudgeTest(unittest.TestCase):
    def test_gemini_api_judgement_is_used_when_key_exists(self) -> None:
        response_payload = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": json.dumps(
                                    {
                                        "verdict": "SUSPICIOUS",
                                        "confidence": 0.8,
                                        "reason": "자동 실행 evidence가 있어 검토가 필요합니다.",
                                        "risk_adjustment": 7,
                                        "evidence": ["package.json postinstall"],
                                    },
                                    ensure_ascii=False,
                                )
                            }
                        ]
                    }
                }
            ]
        }

        with patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"}, clear=False), patch(
            "guardit.ai.llm_judge.urllib.request.urlopen", return_value=_FakeResponse(response_payload)
        ) as urlopen:
            result = LLMJudge(provider="gemini-api", model="gemini-test").judge(
                suspicious_files=["package.json"],
                evidence=[_evidence()],
                sandbox_logs=[],
                metadata=_metadata(),
                rule_score=22,
            )

        self.assertTrue(result.used)
        self.assertEqual(result.provider, "gemini-api")
        self.assertEqual(result.verdict, "SUSPICIOUS")
        self.assertEqual(result.risk_adjustment, 7)
        self.assertIn("자동 실행", result.reason)
        self.assertIn("gemini-test:generateContent", urlopen.call_args.args[0].full_url)

    def test_gemini_api_parses_markdown_fenced_json_response(self) -> None:
        response_payload = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": (
                                    "분석 결과입니다.\n"
                                    "```json\n"
                                    '{"verdict":"MALICIOUS","confidence":0.91,'
                                    '"reason":"postinstall에서 실행 파일을 호출합니다.",'
                                    '"risk_adjustment":10,"evidence":["loader.exe"]}'
                                    "\n```\n"
                                    "위 JSON을 참고하세요."
                                )
                            }
                        ]
                    }
                }
            ]
        }

        with patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"}, clear=False), patch(
            "guardit.ai.llm_judge.urllib.request.urlopen", return_value=_FakeResponse(response_payload)
        ):
            result = LLMJudge(provider="gemini-api", model="gemini-test").judge(
                suspicious_files=["package.json"],
                evidence=[_evidence()],
                sandbox_logs=[],
                metadata=_metadata(),
                rule_score=22,
            )

        self.assertTrue(result.used)
        self.assertEqual(result.provider, "gemini-api")
        self.assertEqual(result.verdict, "MALICIOUS")
        self.assertEqual(result.risk_adjustment, 10)
        self.assertIn("실행 파일", result.reason)

    def test_gemini_api_without_key_falls_back(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            result = LLMJudge(provider="gemini-api", model="gemini-test").judge(
                suspicious_files=["package.json"],
                evidence=[_evidence()],
                sandbox_logs=[],
                metadata=_metadata(),
                rule_score=22,
            )

        self.assertFalse(result.used)
        self.assertEqual(result.provider, "offline-fallback")
        self.assertIn("GEMINI_API_KEY", result.error or "")


def _metadata() -> RepoMetadata:
    return RepoMetadata(
        source="https://github.com/example/repo",
        author_trust=AuthorTrust(score=50, signals=["test"]),
    )


def _evidence() -> Evidence:
    return Evidence(
        file="package.json",
        line=1,
        type="auto_trigger",
        severity="medium",
        evidence="postinstall: node setup.js",
        score=20,
        category="auto_trigger",
        description="npm lifecycle에서 자동 실행될 수 있는 스크립트입니다.",
    )


if __name__ == "__main__":
    unittest.main()
