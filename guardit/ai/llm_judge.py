from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

from guardit.ai.redact import redact_obj, redact_sensitive_text
from guardit.models import Evidence, LLMJudgement, RepoMetadata, SandboxLog


@dataclass
class LLMJudge:
    provider: str = "off"
    model: str = "gpt-4.1-mini"

    def judge(
        self,
        suspicious_files: list[str],
        evidence: list[Evidence],
        sandbox_logs: list[SandboxLog],
        metadata: RepoMetadata,
        rule_score: int,
    ) -> LLMJudgement:
        fallback = _fallback_judgement(evidence, sandbox_logs, rule_score)
        if self.provider in {"off", "none", ""}:
            return fallback
        if self.provider == "openai":
            return self._judge_openai(suspicious_files, evidence, sandbox_logs, metadata, rule_score, fallback)
        return LLMJudgement("WATCH", 0.0, f"지원하지 않는 LLM provider입니다: {self.provider}", 0, provider="offline-fallback", used=False)

    def _judge_openai(
        self,
        suspicious_files: list[str],
        evidence: list[Evidence],
        sandbox_logs: list[SandboxLog],
        metadata: RepoMetadata,
        rule_score: int,
        fallback: LLMJudgement,
    ) -> LLMJudgement:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            fallback.error = "OPENAI_API_KEY가 없어 LLM fallback을 사용했습니다."
            return fallback

        payload = redact_obj(
            {
                "suspicious_files": suspicious_files[:20],
                "matched_rules": [item.__dict__ for item in evidence[:30]],
                "sandbox_logs": [item.__dict__ for item in sandbox_logs[:30]],
                "author_trust": metadata.author_trust.__dict__,
                "rule_score": rule_score,
            }
        )
        body = {
            "model": self.model,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Return only JSON with schema "
                        '{"verdict":"SAFE|SUSPICIOUS|MALICIOUS","confidence":0.0,'
                        '"reason":"","risk_adjustment":0,"evidence":[]}. '
                        "risk_adjustment must be -10..10. Use only supplied evidence."
                    ),
                },
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
            ],
            "temperature": 0.1,
        }
        request = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                result = json.loads(response.read().decode("utf-8"))
            content = result["choices"][0]["message"]["content"]
            parsed = json.loads(content)
        except (urllib.error.HTTPError, KeyError, IndexError, json.JSONDecodeError, TimeoutError, OSError) as exc:
            fallback.error = f"LLM 파싱/호출 실패: {exc}"
            return fallback

        verdict = str(parsed.get("verdict", "SUSPICIOUS"))
        if verdict not in {"SAFE", "SUSPICIOUS", "MALICIOUS"}:
            verdict = "SUSPICIOUS"
        adjustment = max(-10, min(10, int(parsed.get("risk_adjustment") or 0)))
        confidence = max(0.0, min(1.0, float(parsed.get("confidence") or 0.0)))
        llm_evidence = parsed.get("evidence") if isinstance(parsed.get("evidence"), list) else []
        return LLMJudgement(
            verdict=verdict,  # type: ignore[arg-type]
            confidence=confidence,
            reason=redact_sensitive_text(str(parsed.get("reason") or fallback.reason)),
            risk_adjustment=adjustment,
            evidence=[redact_sensitive_text(str(item)) for item in llm_evidence[:10]],
            provider="openai",
            used=True,
        )


def _fallback_judgement(evidence: list[Evidence], sandbox_logs: list[SandboxLog], rule_score: int) -> LLMJudgement:
    has_flow = any(item.category == "data_flow" for item in evidence)
    has_auto = any(item.category == "auto_trigger" for item in evidence)
    has_secret = any(item.category == "secret_access" for item in evidence)
    has_sink = any(item.category == "external_sink" for item in evidence)
    if has_auto and has_secret and has_sink:
        reason = "자동 실행 지점에서 민감정보 접근과 외부 전송 근거가 함께 나타납니다."
        verdict = "MALICIOUS"
    elif has_flow:
        reason = "민감정보 source가 sink로 이어지는 흐름이 관찰됩니다."
        verdict = "SUSPICIOUS"
    elif rule_score >= 50:
        reason = "자동 실행 또는 외부 전송 관련 정적/샌드박스 점수가 높습니다."
        verdict = "SUSPICIOUS"
    else:
        reason = "LLM 없이 룰 기반 근거만으로 판단했습니다."
        verdict = "SAFE" if rule_score < 30 else "SUSPICIOUS"
    if sandbox_logs:
        reason += " 샌드박스형 행동 추정 로그가 보조 근거로 사용되었습니다."
    return LLMJudgement(verdict=verdict, confidence=0.0, reason=reason, risk_adjustment=0, provider="offline-fallback", used=False)
