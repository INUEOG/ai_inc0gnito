from __future__ import annotations

import json
import unittest
import urllib.error
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
        self.assertEqual(result.status, "used")
        self.assertEqual(result.attempts, 1)

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

    def test_gemini_api_429_retries_with_backoff_then_degrades(self) -> None:
        def rate_limited(*args, **kwargs):
            raise urllib.error.HTTPError(
                url="https://generativelanguage.googleapis.com",
                code=429,
                msg="Too Many Requests",
                hdrs=None,
                fp=_FakeErrorBody('{"error":"quota exceeded"}'),
            )

        with patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"}, clear=False), patch(
            "guardit.ai.llm_judge.urllib.request.urlopen", side_effect=rate_limited
        ) as urlopen, patch("guardit.ai.llm_judge.time.sleep") as sleep:
            result = LLMJudge(provider="gemini-api", model="gemini-test", max_retries=3, backoff_seconds=0).judge(
                suspicious_files=["package.json"],
                evidence=[_evidence()],
                sandbox_logs=[],
                metadata=_metadata(),
                rule_score=22,
            )

        self.assertTrue(result.used)
        self.assertEqual(result.status, "degraded")
        self.assertEqual(result.attempts, 3)
        self.assertEqual(urlopen.call_count, 3)
        self.assertEqual(sleep.call_count, 0)
        self.assertIn("degraded AI analysis", result.notes[-1])
        self.assertIn("429", result.error or "")

    def test_gemini_429_retries_with_lightweight_payload(self) -> None:
        response_payload = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": json.dumps(
                                    {
                                        "verdict": "SAFE",
                                        "confidence": 0.6,
                                        "reason": "lightweight evidence 기준으로 외부 전송은 없습니다.",
                                        "risk_adjustment": 0,
                                        "evidence": ["lightweight"],
                                    },
                                    ensure_ascii=False,
                                )
                            }
                        ]
                    }
                }
            ]
        }

        calls = []

        def fake_urlopen(request, **kwargs):
            calls.append(json.loads(request.data.decode("utf-8")))
            if len(calls) == 1:
                raise urllib.error.HTTPError(
                    url=request.full_url,
                    code=429,
                    msg="Too Many Requests",
                    hdrs=None,
                    fp=_FakeErrorBody('{"error":"quota exceeded"}'),
                )
            return _FakeResponse(response_payload)

        with patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"}, clear=False), patch(
            "guardit.ai.llm_judge.urllib.request.urlopen", side_effect=fake_urlopen
        ), patch("guardit.ai.llm_judge.time.sleep"):
            result = LLMJudge(provider="gemini-api", model="gemini-test", max_retries=3, backoff_seconds=0).judge(
                suspicious_files=["package.json"],
                evidence=[_evidence()],
                sandbox_logs=[],
                metadata=_metadata(),
                rule_score=22,
            )

        self.assertTrue(result.used)
        self.assertEqual(result.status, "lightweight")
        second_prompt = calls[1]["contents"][0]["parts"][0]["text"]
        self.assertIn('"payload_mode": "lightweight"', second_prompt)

    def test_gemini_429_falls_back_to_openai_provider(self) -> None:
        openai_payload = {"choices": [{"message": {"content": json.dumps({"verdict": "SUSPICIOUS", "confidence": 0.7, "reason": "OpenAI fallback 판단", "risk_adjustment": 3, "evidence": ["fallback"]})}}]}

        def fake_urlopen(request, **kwargs):
            if "generativelanguage.googleapis.com" in request.full_url:
                raise urllib.error.HTTPError(
                    url=request.full_url,
                    code=429,
                    msg="Too Many Requests",
                    hdrs=None,
                    fp=_FakeErrorBody('{"error":"quota exceeded"}'),
                )
            return _FakeResponse(openai_payload)

        with patch.dict("os.environ", {"GEMINI_API_KEY": "test-key", "OPENAI_API_KEY": "openai-key"}, clear=False), patch(
            "guardit.ai.llm_judge.urllib.request.urlopen", side_effect=fake_urlopen
        ), patch("guardit.ai.llm_judge.time.sleep"):
            result = LLMJudge(provider="gemini-api", model="gemini-test", max_retries=3, backoff_seconds=0).judge(
                suspicious_files=["package.json"],
                evidence=[_evidence()],
                sandbox_logs=[],
                metadata=_metadata(),
                rule_score=22,
            )

        self.assertTrue(result.used)
        self.assertEqual(result.provider, "openai")
        self.assertEqual(result.verdict, "SUSPICIOUS")
        self.assertEqual(result.risk_adjustment, 3)

    def test_gemini_api_parses_text_wrapped_json_and_normalizes_schema(self) -> None:
        response_payload = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": (
                                    "여기 분석 결과입니다: "
                                    "{'verdict':'malicious','confidence':'90',"
                                    "'reason':['자동 실행 파일 존재','외부 전송 가능'],"
                                    "'risk_adjustment': 4,"
                                    "'evidence':['postinstall'],"
                                    "'leaked_data':['AWS credentials'],}"
                                    " 추가 설명입니다."
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
            result = LLMJudge(provider="gemini-api", model="gemini-test", backoff_seconds=0).judge(
                suspicious_files=["package.json"],
                evidence=[_evidence()],
                sandbox_logs=[],
                metadata=_metadata(),
                rule_score=22,
            )

        self.assertTrue(result.used)
        self.assertEqual(result.verdict, "MALICIOUS")
        self.assertEqual(result.confidence, 0.9)
        self.assertIn("자동 실행", result.reason)
        self.assertEqual(result.leaked_data, ["AWS credentials"])
        self.assertTrue(any("confidence normalized" in note for note in result.notes))

    def test_gemini_api_without_key_falls_back(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            result = LLMJudge(provider="gemini-api", model="gemini-test").judge(
                suspicious_files=["package.json"],
                evidence=[_evidence()],
                sandbox_logs=[],
                metadata=_metadata(),
                rule_score=22,
            )

        self.assertTrue(result.used)
        self.assertEqual(result.provider, "local-degraded-ai")
        self.assertEqual(result.status, "degraded")
        self.assertIn("GEMINI_API_KEY", result.error or "")
        self.assertIn("degraded AI analysis", result.reason)


class _FakeErrorBody:
    def __init__(self, text: str) -> None:
        self.text = text

    def read(self) -> bytes:
        return self.text.encode("utf-8")


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
