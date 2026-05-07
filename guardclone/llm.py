from __future__ import annotations

import json
import os
import shutil
import shlex
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass

from .models import Finding, RepoProfile, SandboxEvent


GEMINI_FALLBACK_MODELS = ["gemini-2.0-flash", "gemini-1.5-flash"]


@dataclass
class LlmResult:
    provider: str
    model: str
    used: bool
    judgement: str
    risk_adjustment: int = 0
    error: str | None = None


def judge_with_llm(
    provider: str,
    model: str,
    base_score: int,
    profile: RepoProfile,
    findings: list[Finding],
    sandbox_events: list[SandboxEvent],
    fallback_judgement: str,
    gemini_command: str | None = None,
) -> LlmResult:
    if provider == "off":
        return LlmResult("offline-heuristic", "rules+ast+sandbox", False, fallback_judgement)

    if provider == "gemini-api" or (provider in {"auto", "gemini"} and _gemini_api_key()):
        return _judge_with_gemini_api(model, base_score, profile, findings, sandbox_events, fallback_judgement)

    if provider in {"auto", "gemini"}:
        command_prefix = resolve_gemini_command(gemini_command)
        if command_prefix is None:
            error = (
                "Gemini CLI not found. Install official Google Gemini CLI with "
                "`npm install -g @google/gemini-cli`, or pass --gemini-command."
            )
            return LlmResult("offline-fallback", "rules+ast+sandbox", False, fallback_judgement, error=error)
        return _judge_with_gemini(command_prefix, model, base_score, profile, findings, sandbox_events, fallback_judgement)

    return LlmResult(provider, model, False, fallback_judgement, error=f"Unsupported LLM provider: {provider}")


def _judge_with_gemini_api(
    model: str,
    base_score: int,
    profile: RepoProfile,
    findings: list[Finding],
    sandbox_events: list[SandboxEvent],
    fallback_judgement: str,
) -> LlmResult:
    api_key = _gemini_api_key()
    if not api_key:
        return LlmResult("gemini-api", model, False, fallback_judgement, error="GEMINI_API_KEY or GOOGLE_API_KEY is not set.")

    prompt = _build_prompt(base_score, profile, findings, sandbox_events)
    errors: list[str] = []
    for candidate_model in _candidate_models(model):
        result = _call_gemini_api_model(candidate_model, api_key, prompt, fallback_judgement)
        if result.used:
            return result
        if result.error:
            errors.append(f"{candidate_model}: {result.error}")
        retryable = any(marker in result.error for marker in ["HTTP 503", "UNAVAILABLE", "HTTP 429", "quota"])
        if result.error and not retryable:
            return result
    return LlmResult("gemini-api", model, False, fallback_judgement, error="; ".join(errors)[:800])


def _call_gemini_api_model(model: str, api_key: str, prompt: str, fallback_judgement: str) -> LlmResult:
    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 1024,
            "responseMimeType": "application/json",
        },
    }
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:400]
        return LlmResult("gemini-api", model, False, fallback_judgement, error=f"Gemini API HTTP {exc.code}: {detail}")
    except Exception as exc:
        return LlmResult("gemini-api", model, False, fallback_judgement, error=str(exc))

    text = _extract_gemini_text(payload)
    parsed = _parse_jsonish(text)
    if not parsed:
        repaired = _repair_partial_json_text(text)
        if repaired:
            return LlmResult("gemini-api", model, True, repaired[:600])
        return LlmResult("gemini-api", model, False, fallback_judgement, error=f"Gemini API returned unparsable JSON: {text[:200]}")

    judgement = _format_llm_judgement(parsed, fallback_judgement)
    try:
        risk_adjustment = int(parsed.get("risk_adjustment", 0))
    except (TypeError, ValueError):
        risk_adjustment = 0
    return LlmResult("gemini-api", model, True, judgement[:600], max(-15, min(15, risk_adjustment)))


def _candidate_models(model: str) -> list[str]:
    models = [model]
    for fallback in GEMINI_FALLBACK_MODELS:
        if fallback not in models:
            models.append(fallback)
    return models


def _judge_with_gemini(
    command_prefix: list[str],
    model: str,
    base_score: int,
    profile: RepoProfile,
    findings: list[Finding],
    sandbox_events: list[SandboxEvent],
    fallback_judgement: str,
) -> LlmResult:
    prompt = _build_prompt(base_score, profile, findings, sandbox_events)
    command = [*command_prefix]
    if model:
        command.extend(["-m", model])
    command.extend(["-p", prompt])

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=90,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return LlmResult(
            "gemini",
            model,
            False,
            fallback_judgement,
            error="Gemini CLI timed out after 90 seconds. Run `gemini -p \"hello\"` once to finish login/authentication.",
        )
    except Exception as exc:
        return LlmResult("gemini", model, False, fallback_judgement, error=str(exc))

    if completed.returncode != 0:
        return LlmResult("gemini", model, False, fallback_judgement, error=completed.stderr.strip()[:300])

    text = completed.stdout.strip()
    parsed = _parse_jsonish(text)
    if not parsed:
        return LlmResult("gemini", model, True, text[:600] or fallback_judgement)

    judgement = str(parsed.get("judgement") or fallback_judgement)
    try:
        risk_adjustment = int(parsed.get("risk_adjustment", 0))
    except (TypeError, ValueError):
        risk_adjustment = 0
    risk_adjustment = max(-15, min(15, risk_adjustment))
    return LlmResult("gemini", model, True, judgement[:600], risk_adjustment)


def resolve_gemini_command(gemini_command: str | None = None) -> list[str] | None:
    configured = gemini_command or os.environ.get("GUARDCLONE_GEMINI_CMD")
    if configured:
        return shlex.split(configured, posix=False)
    detected = shutil.which("gemini")
    if detected:
        return [detected]
    return None


def gemini_diagnostics() -> dict[str, object]:
    command = resolve_gemini_command()
    return {
        "gemini_command": command,
        "gemini_on_path": shutil.which("gemini"),
        "npx_on_path": shutil.which("npx"),
        "gemini_api_key_set": bool(os.environ.get("GEMINI_API_KEY")),
        "google_api_key_set": bool(os.environ.get("GOOGLE_API_KEY")),
        "guardclone_gemini_cmd": os.environ.get("GUARDCLONE_GEMINI_CMD"),
        "preferred_llm_path": "gemini-api" if _gemini_api_key() else ("gemini-cli" if command else "offline-fallback"),
    }


def _gemini_api_key() -> str | None:
    return os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")


def _extract_gemini_text(payload: dict) -> str:
    try:
        parts = payload["candidates"][0]["content"]["parts"]
    except (KeyError, IndexError, TypeError):
        return json.dumps(payload, ensure_ascii=False)[:1000]
    return "".join(str(part.get("text", "")) for part in parts if isinstance(part, dict)).strip()


def _build_prompt(base_score: int, profile: RepoProfile, findings: list[Finding], events: list[SandboxEvent]) -> str:
    payload = {
        "task": "pre-clone repo privacy exfiltration judgement",
        "instruction": (
            "You are a security reviewer. Decide whether the evidence indicates credential or personal-data theft. "
            "Return only valid compact JSON. Schema: "
            "{\"judgement\":\"one Korean sentence\","
            "\"reason\":\"one Korean sentence grounded only in evidence\","
            "\"risk_adjustment\":0,"
            "\"confidence\":0.0}. "
            "risk_adjustment must be an integer from -15 to 15. confidence must be 0.0 to 1.0. "
            "Do not invent evidence. Do not use markdown."
        ),
        "base_score": base_score,
        "author_trust_score": profile.author_trust_score,
        "author_signals": profile.author_signals[:5],
        "auto_exec_files": profile.executable_files[:8],
        "findings": [
            {
                "rule_id": finding.rule_id,
                "file": finding.file,
                "line": finding.line,
                "category": finding.category,
                "evidence": finding.evidence[:90],
            }
            for finding in findings[:8]
        ],
        "sandbox_events": [
            {
                "kind": event.kind,
                "file": event.file,
                "line": event.line,
            }
            for event in events[:8]
        ],
    }
    return json.dumps(payload, ensure_ascii=False)


def _parse_jsonish(text: str) -> dict | None:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`").removeprefix("json").strip()
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        parsed = json.loads(cleaned[start : end + 1])
        if isinstance(parsed, str):
            parsed = json.loads(parsed)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


def _repair_partial_json_text(text: str) -> str | None:
    judgement = _extract_json_string_value(text, "judgement")
    reason = _extract_json_string_value(text, "reason")
    if not judgement and not reason:
        return None
    parts = []
    if judgement:
        parts.append(judgement)
    if reason:
        parts.append(f"근거: {reason}")
    return " ".join(parts)


def _extract_json_string_value(text: str, key: str) -> str | None:
    marker = f'"{key}"'
    start = text.find(marker)
    if start == -1:
        return None
    colon = text.find(":", start + len(marker))
    if colon == -1:
        return None
    quote = text.find('"', colon + 1)
    if quote == -1:
        return None
    chars: list[str] = []
    escaped = False
    for char in text[quote + 1 :]:
        if escaped:
            chars.append(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == '"':
            break
        chars.append(char)
    value = "".join(chars).strip()
    return value or None


def _format_llm_judgement(parsed: dict, fallback_judgement: str) -> str:
    judgement = str(parsed.get("judgement") or "").strip()
    reason = str(parsed.get("reason") or "").strip()
    confidence = parsed.get("confidence")

    parts = []
    if judgement:
        parts.append(judgement)
    if reason:
        parts.append(f"근거: {reason}")
    if confidence is not None:
        parts.append(f"신뢰도: {confidence}")
    return " ".join(parts) if parts else fallback_judgement
