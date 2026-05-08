from __future__ import annotations

import ast
import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from guardit.ai.redact import redact_obj, redact_sensitive_text
from guardit.models import Evidence, LLMJudgement, RepoMetadata, SandboxLog


GEMINI_SYSTEM_PROMPT = (
    "JSON만 반환하세요. markdown 금지. 설명 금지. "
    "Return only a valid JSON object. Do not wrap it in markdown code fences. "
    "Do not include prose before or after JSON."
)
CODE_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.I | re.S)
JSON_OBJECT_RE = re.compile(r"\{.*\}", re.S)
RAW_RESPONSE_LOG = Path("logs") / "llm_raw_response.txt"


@dataclass
class LLMJudge:
    provider: str = "off"
    model: str = "gemini-2.5-flash"
    max_retries: int = 3
    backoff_seconds: float = 1.0
    strict_json: bool = False

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
            fallback.provider = "offline-fallback"
            fallback.status = "off"
            fallback.max_attempts = 0
            fallback.reason = "LLM provider가 off로 설정되어 정적 분석 근거 기반의 안전 판단을 적용했습니다."
            return fallback
        if self.provider == "gemini-api" or (self.provider in {"auto", "gemini"} and _gemini_api_key()):
            return self._judge_gemini_api(suspicious_files, evidence, sandbox_logs, metadata, rule_score, fallback)
        if self.provider in {"auto", "gemini"}:
            _mark_llm_fallback(
                fallback,
                provider="gemini-api",
                attempts=0,
                max_attempts=self.max_retries,
                notes=["Gemini API key missing"],
                error="GEMINI_API_KEY 또는 GOOGLE_API_KEY가 없어 LLM 호출을 수행하지 못했습니다.",
            )
            return fallback
        if self.provider == "openai":
            return self._judge_openai(suspicious_files, evidence, sandbox_logs, metadata, rule_score, fallback)
        return LLMJudgement("WATCH", 0.0, f"지원하지 않는 LLM provider입니다: {self.provider}", 0, provider="offline-fallback", used=False)

    def _judge_gemini_api(
        self,
        suspicious_files: list[str],
        evidence: list[Evidence],
        sandbox_logs: list[SandboxLog],
        metadata: RepoMetadata,
        rule_score: int,
        fallback: LLMJudgement,
    ) -> LLMJudgement:
        api_key = _gemini_api_key()
        if not api_key:
            _mark_llm_fallback(
                fallback,
                provider="gemini-api",
                attempts=0,
                max_attempts=self.max_retries,
                notes=["Gemini API key missing"],
                error="GEMINI_API_KEY 또는 GOOGLE_API_KEY가 없어 LLM 호출을 수행하지 못했습니다.",
            )
            return fallback

        payload = _build_evidence_payload(suspicious_files, evidence, sandbox_logs, metadata, rule_score)
        notes: list[str] = []
        max_attempts = max(1, self.max_retries)
        last_error = ""
        for attempt in range(1, max_attempts + 1):
            try:
                raw_api_response = self._call_gemini_api(api_key, payload)
                result = json.loads(raw_api_response)
                raw_model_text = _extract_gemini_text(result)
                parsed, parse_notes = _parse_jsonish(raw_model_text, strict=self.strict_json)
                notes.extend(f"attempt {attempt}: {note}" for note in parse_notes)
                if parsed:
                    judgement = _judgement_from_parsed(
                        parsed,
                        fallback,
                        provider="gemini-api",
                        model=self.model,
                        attempts=attempt,
                        max_attempts=max_attempts,
                        notes=notes,
                    )
                    return judgement
                _save_raw_response(raw_model_text)
                last_error = f"Gemini API 응답 JSON 파싱 실패. response preview: {_preview(raw_model_text)}"
                notes.append(f"attempt {attempt}: {last_error}")
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")[:400]
                last_error = f"Gemini API HTTP {exc.code}: {detail}"
                notes.append(f"attempt {attempt}: {last_error}")
                if not _retryable_http(exc.code):
                    break
            except json.JSONDecodeError as exc:
                raw = locals().get("raw_api_response", "")
                _save_raw_response(raw)
                last_error = f"Gemini API wrapper JSON 파싱 실패: {exc}. response preview: {_preview(raw)}"
                notes.append(f"attempt {attempt}: {last_error}")
            except (TimeoutError, urllib.error.URLError, OSError) as exc:
                last_error = f"Gemini API 일시 오류: {exc}"
                notes.append(f"attempt {attempt}: {last_error}")
            if attempt < max_attempts:
                delay = self.backoff_seconds * (2 ** (attempt - 1))
                notes.append(f"attempt {attempt}: retry after {delay:.2f}s")
                if delay > 0:
                    time.sleep(delay)

        _mark_llm_fallback(
            fallback,
            provider="gemini-api",
            attempts=max_attempts,
            max_attempts=max_attempts,
            notes=notes,
            error=last_error or "Gemini API LLM analysis failed after retries.",
        )
        return fallback

    def _call_gemini_api(self, api_key: str, payload: dict) -> str:
        body = {
            "systemInstruction": {"parts": [{"text": GEMINI_SYSTEM_PROMPT}]},
            "contents": [{"role": "user", "parts": [{"text": _build_gemini_prompt(payload)}]}],
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": 1024,
                "responseMimeType": "application/json",
            },
        }
        request = urllib.request.Request(
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "x-goog-api-key": api_key},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8", errors="replace")

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

        payload = _build_evidence_payload(suspicious_files, evidence, sandbox_logs, metadata, rule_score)
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

        return _judgement_from_parsed(parsed, fallback, provider="openai", model=self.model)


def _gemini_api_key() -> str | None:
    return os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")


def _build_evidence_payload(
    suspicious_files: list[str],
    evidence: list[Evidence],
    sandbox_logs: list[SandboxLog],
    metadata: RepoMetadata,
    rule_score: int,
) -> dict:
    return redact_obj(
        {
            "suspicious_files": suspicious_files[:20],
            "matched_rules": [item.__dict__ for item in evidence[:30]],
            "sandbox_logs": [item.__dict__ for item in sandbox_logs[:30]],
            "author_trust": metadata.author_trust.__dict__,
            "rule_score": rule_score,
        }
    )


def _build_gemini_prompt(payload: dict) -> str:
    return json.dumps(
        {
            "task": "pre-clone repo privacy exfiltration judgement",
            "instruction": (
                "Decide whether the supplied evidence indicates developer credential or personal-data theft. "
                "JSON만 반환, markdown 금지, 설명 금지. "
                "Return only valid compact JSON with schema "
                '{"verdict":"SAFE|SUSPICIOUS|MALICIOUS","confidence":0.0,'
                '"reason":"","risk_adjustment":0,"evidence":[]}. '
                "risk_adjustment must be an integer from -10 to 10. "
                "Use only supplied evidence. Do not invent facts. Do not use markdown."
            ),
            "evidence_payload": payload,
        },
        ensure_ascii=False,
    )


def _extract_gemini_text(payload: dict) -> str:
    try:
        parts = payload["candidates"][0]["content"]["parts"]
    except (KeyError, IndexError, TypeError):
        return json.dumps(payload, ensure_ascii=False)[:1000]
    return "".join(str(part.get("text", "")) for part in parts if isinstance(part, dict)).strip()


def _parse_jsonish(text: str, strict: bool = False) -> tuple[dict | None, list[str]]:
    notes: list[str] = []
    for label, candidate in _json_candidates(text, strict=strict):
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, str):
                parsed = json.loads(parsed)
            if isinstance(parsed, dict):
                notes.append(f"parsed via {label}")
                return parsed, notes
        except json.JSONDecodeError:
            notes.append(f"{label} json.loads failed")
            if not strict:
                repaired = _repair_json_candidate(candidate)
                if repaired != candidate:
                    try:
                        parsed = json.loads(repaired)
                        if isinstance(parsed, dict):
                            notes.append(f"parsed via repaired {label}")
                            return parsed, notes
                    except json.JSONDecodeError:
                        notes.append(f"repaired {label} json.loads failed")
                try:
                    parsed = ast.literal_eval(candidate)
                    if isinstance(parsed, dict):
                        notes.append(f"parsed via python literal {label}")
                        return parsed, notes
                except (SyntaxError, ValueError):
                    notes.append(f"python literal {label} failed")
    return None, notes


def _json_candidates(text: str, strict: bool = False) -> list[tuple[str, str]]:
    cleaned = text.strip()
    candidates: list[tuple[str, str]] = [("raw", cleaned)]
    for match in CODE_FENCE_RE.finditer(cleaned):
        fenced = match.group(1).strip()
        candidates.append(("code_fence", fenced))
        object_match = JSON_OBJECT_RE.search(fenced)
        if object_match:
            candidates.append(("code_fence_object", object_match.group(0)))
    if strict:
        return _unique_candidates(candidates)
    without_fences = CODE_FENCE_RE.sub(lambda match: match.group(1), cleaned).strip()
    candidates.append(("without_code_fence", without_fences))
    object_match = JSON_OBJECT_RE.search(without_fences)
    if object_match:
        candidates.append(("json_object", object_match.group(0)))
    return _unique_candidates(candidates)


def _repair_json_candidate(text: str) -> str:
    repaired = re.sub(r",\s*([}\]])", r"\1", text.strip())
    if "'" in repaired and '"' not in repaired:
        repaired = repaired.replace("'", '"')
    return repaired


def _save_raw_response(text: str) -> None:
    try:
        RAW_RESPONSE_LOG.parent.mkdir(parents=True, exist_ok=True)
        RAW_RESPONSE_LOG.write_text(text, encoding="utf-8")
    except OSError:
        pass


def _preview(text: str, limit: int = 300) -> str:
    compact = " ".join(text.split())
    return compact[:limit]


def _retryable_http(status_code: int) -> bool:
    return status_code in {408, 409, 425, 429, 500, 502, 503, 504}


def _mark_llm_fallback(
    fallback: LLMJudgement,
    provider: str,
    attempts: int,
    max_attempts: int,
    notes: list[str],
    error: str,
) -> None:
    fallback.provider = provider
    fallback.used = False
    fallback.status = "failed"
    fallback.attempts = attempts
    fallback.max_attempts = max_attempts
    fallback.notes = notes
    fallback.error = error
    if attempts == 0:
        fallback.reason = "LLM 호출 조건이 충족되지 않아 정적 분석 근거 기반의 안전 fallback을 적용했습니다."
    else:
        fallback.reason = (
            "LLM 분석을 재시도했으나 API 오류 또는 응답 파싱 문제로 실패하여, "
            "정적 분석 근거 기반의 안전 fallback을 적용했습니다."
        )


def _unique_candidates(values: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[str] = set()
    result: list[tuple[str, str]] = []
    for label, value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append((label, value))
    return result


def _judgement_from_parsed(
    parsed: dict,
    fallback: LLMJudgement,
    provider: str,
    model: str,
    attempts: int = 1,
    max_attempts: int = 1,
    notes: list[str] | None = None,
) -> LLMJudgement:
    result_notes = list(notes or [])
    verdict = str(parsed.get("verdict", "SUSPICIOUS")).upper()
    if verdict not in {"SAFE", "SUSPICIOUS", "MALICIOUS"}:
        result_notes.append(f"unknown verdict normalized to SUSPICIOUS: {verdict}")
        verdict = "SUSPICIOUS"
    try:
        adjustment = int(parsed.get("risk_adjustment") or 0)
    except (TypeError, ValueError):
        adjustment = 0
    try:
        confidence = float(parsed.get("confidence") or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    if confidence > 1.0:
        confidence = confidence / 100.0
        result_notes.append("confidence normalized from 0..100 to 0..1")
    llm_evidence = parsed.get("evidence") if isinstance(parsed.get("evidence"), list) else []
    leaked_data = parsed.get("leaked_data") if isinstance(parsed.get("leaked_data"), list) else []
    reason_value = parsed.get("reason") or fallback.reason
    if isinstance(reason_value, list):
        reason = " ".join(f"- {item}" for item in reason_value)
    else:
        reason = str(reason_value)
    return LLMJudgement(
        verdict=verdict,  # type: ignore[arg-type]
        confidence=max(0.0, min(1.0, confidence)),
        reason=redact_sensitive_text(reason),
        risk_adjustment=max(-10, min(10, adjustment)),
        evidence=[redact_sensitive_text(str(item)) for item in llm_evidence[:10]],
        leaked_data=[redact_sensitive_text(str(item)) for item in leaked_data[:10]],
        provider=provider,
        used=True,
        status="used",
        attempts=attempts,
        max_attempts=max_attempts,
        notes=result_notes,
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
        reason = "정적 분석 근거 기반의 안전 판단입니다."
        verdict = "SAFE" if rule_score < 30 else "SUSPICIOUS"
    if sandbox_logs:
        reason += " 샌드박스형 행동 추정 로그가 보조 근거로 사용되었습니다."
    return LLMJudgement(verdict=verdict, confidence=0.0, reason=reason, risk_adjustment=0, provider="offline-fallback", used=False)
