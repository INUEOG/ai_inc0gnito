from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass

from .models import Finding, RepoProfile, SandboxEvent


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
) -> LlmResult:
    if provider == "off":
        return LlmResult("offline-heuristic", "rules+ast+sandbox", False, fallback_judgement)

    if provider in {"auto", "gemini"}:
        if shutil.which("gemini") is None:
            error = "Gemini CLI not found. Install the official Google Gemini CLI to enable LLM judgement."
            return LlmResult("offline-fallback", "rules+ast+sandbox", False, fallback_judgement, error=error)
        return _judge_with_gemini(model, base_score, profile, findings, sandbox_events, fallback_judgement)

    return LlmResult(provider, model, False, fallback_judgement, error=f"Unsupported LLM provider: {provider}")


def _judge_with_gemini(
    model: str,
    base_score: int,
    profile: RepoProfile,
    findings: list[Finding],
    sandbox_events: list[SandboxEvent],
    fallback_judgement: str,
) -> LlmResult:
    prompt = _build_prompt(base_score, profile, findings, sandbox_events)
    command = ["gemini", "-p", prompt]
    if model:
        command[1:1] = ["-m", model]

    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=40, check=False)
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


def _build_prompt(base_score: int, profile: RepoProfile, findings: list[Finding], events: list[SandboxEvent]) -> str:
    payload = {
        "task": "GitHub repository pre-clone privacy exfiltration risk judgement",
        "instruction": (
            "You are a security reviewer. Decide whether the evidence indicates credential or personal-data theft. "
            "Return only JSON with keys judgement and risk_adjustment. risk_adjustment must be an integer from -15 to 15. "
            "Do not invent evidence. Explain the intent in Korean."
        ),
        "base_score": base_score,
        "author_trust_score": profile.author_trust_score,
        "author_signals": profile.author_signals,
        "auto_exec_files": profile.executable_files[:20],
        "findings": [finding.__dict__ for finding in findings[:20]],
        "sandbox_events": [event.__dict__ for event in events[:20]],
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
        return json.loads(cleaned[start : end + 1])
    except json.JSONDecodeError:
        return None
