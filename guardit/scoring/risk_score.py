from __future__ import annotations

from guardit.models import Evidence, LLMJudgement, RepoMetadata, RiskLevel, SandboxLog, ScoreBreakdown


LEVELS: list[tuple[int, RiskLevel]] = [
    (70, "MALICIOUS"),
    (30, "SUSPICIOUS"),
    (20, "WATCH"),
    (0, "SAFE"),
]


def score_report(
    metadata: RepoMetadata,
    evidence: list[Evidence],
    sandbox_logs: list[SandboxLog],
    llm: LLMJudgement | None = None,
) -> ScoreBreakdown:
    has_auto_trigger = any(item.category == "auto_trigger" for item in evidence)
    has_secret_access = any(item.category == "secret_access" for item in evidence)
    has_external_sink = any(item.category == "external_sink" for item in evidence)
    has_flow = any(item.category == "data_flow" for item in evidence)
    has_command_execution = any(item.category in {"remote_execution", "process_execution", "binary_execution", "obfuscation"} for item in evidence)

    score = 0
    notes: list[str] = []
    for category, cap in {
        "auto_trigger": 30,
        "secret_access": 35,
        "external_sink": 35,
        "data_flow": 40,
        "obfuscation": 20,
        "remote_execution": 20,
        "process_execution": 20,
        "binary_execution": 20,
    }.items():
        category_score = min(cap, sum(item.score for item in evidence if item.category == category))
        if category_score:
            score += category_score
            notes.append(f"{category}: +{category_score}")

    if has_flow:
        notes.append("source -> sink 흐름 탐지")

    inferred_file = min(20, sum(log.score for log in sandbox_logs if log.origin == "inferred" and log.action == "dummy_credential_access"))
    observed_file = min(40, sum(log.score for log in sandbox_logs if log.origin == "observed" and log.action in {"dummy_credential_access", "dummy_credential_io"}))
    inferred_net = min(20, sum(log.score for log in sandbox_logs if log.origin == "inferred" and log.action == "network_connect_attempt"))
    observed_net = min(40, sum(log.score for log in sandbox_logs if log.origin == "observed" and log.action == "network_connect_attempt"))
    observed_proc = min(20, sum(log.score for log in sandbox_logs if log.origin == "observed" and log.action == "process_spawn"))
    if inferred_file:
        score += inferred_file
        notes.append(f"inferred credential access: +{inferred_file}")
    if observed_file:
        score += observed_file
        notes.append(f"observed credential access: +{observed_file}")
    if inferred_net:
        score += inferred_net
        notes.append(f"inferred network attempt: +{inferred_net}")
    if observed_net:
        score += observed_net
        notes.append(f"observed network attempt: +{observed_net}")
    if observed_proc:
        score += observed_proc
        notes.append(f"observed process execution: +{observed_proc}")

    multiplier = _trust_multiplier(metadata.author_trust.score)
    if score and multiplier != 1.0:
        before = score
        score = int(round(score * multiplier))
        notes.append(f"작성자 신뢰도 보조 multiplier: {multiplier:.2f} ({before} -> {score})")

    forced = has_auto_trigger and has_secret_access and has_external_sink
    if forced:
        score = max(score, 70)
        notes.append("강제 규칙 적용: 자동 실행 + 민감정보 접근 + 외부 전송")
    elif has_auto_trigger and has_secret_access and not has_external_sink and score > 69:
        score = 69
        notes.append("외부 전송 근거가 없어 credential access-only 상한을 적용")
    elif has_auto_trigger and has_command_execution and not has_secret_access and not has_external_sink and score > 29:
        score = 29
        notes.append("자동 실행 + benign command는 warning 상한을 적용")
    elif not has_secret_access and score > 69:
        score = 69
        notes.append("민감정보 접근 근거가 없어 MALICIOUS 상한을 적용")

    base_score = max(0, min(100, score))
    adjustment = _bounded_adjustment(llm.risk_adjustment if llm else 0)
    if llm:
        notes.append(f"LLM risk_adjustment: {adjustment:+d}")
    final_score = max(0, min(100, base_score + adjustment))
    if forced:
        final_score = max(final_score, 70)

    return ScoreBreakdown(
        base_score=base_score,
        final_score=final_score,
        risk_level=_level(final_score),
        forced_malicious=forced,
        has_auto_trigger=has_auto_trigger,
        has_secret_access=has_secret_access,
        has_external_sink=has_external_sink,
        has_command_execution=has_command_execution,
        notes=notes,
    )


def _trust_multiplier(score: int) -> float:
    if score <= 20:
        return 1.3
    if score <= 35:
        return 1.2
    if score <= 49:
        return 1.1
    if score >= 85:
        return 0.95
    return 1.0


def _bounded_adjustment(value: int) -> int:
    return max(-10, min(10, int(value or 0)))


def _level(score: int) -> RiskLevel:
    for threshold, level in LEVELS:
        if score >= threshold:
            return level
    return "SAFE"
