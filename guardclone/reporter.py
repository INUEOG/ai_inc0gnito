from __future__ import annotations

import json

from .models import ScanReport


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)


def render_text(report: ScanReport) -> str:
    lines = [
        "GuardClone 사전 검사 결과",
        "=" * 28,
        f"대상: {report.profile.source}",
        f"검사 파일 수: {report.profile.files_scanned}",
        f"자동 실행 후보: {len(report.profile.executable_files)}개",
        f"작성자 신뢰도: {report.profile.author_trust_score}/100",
    ]
    if report.profile.author_signals:
        lines.extend(["신뢰도 근거", *[f"- {signal}" for signal in report.profile.author_signals[:5]]])

    lines.extend([
        f"위험 점수: {report.risk_score}/100",
        f"판정: {report.verdict}",
        f"권장 조치: {report.recommendation}",
        "",
        f"판단 엔진: {report.ai_provider} / {report.ai_model} / {'LLM 사용' if report.ai_used else 'LLM 미사용'}",
        f"판단 요약: {report.ai_judgement}",
    ])
    if report.ai_error:
        lines.append(f"LLM 연동 참고: {report.ai_error}")

    if report.exfiltration_targets:
        lines.extend(["", "탈취 가능 정보"])
        lines.extend(f"- {target}" for target in report.exfiltration_targets)

    if report.findings:
        lines.extend(["", "주요 탐지 근거"])
        for finding in report.findings[:10]:
            lines.append(f"- [{finding.rule_id}] {finding.file}:{finding.line} {finding.title}")
            lines.append(f"  {finding.description}")

    if report.sandbox_events:
        lines.extend(["", "샌드박스형 행동 로그"])
        for event in report.sandbox_events[:10]:
            lines.append(f"- {event.kind} {event.file}:{event.line} - {event.detail}")

    lines.extend(["", f"처리 시간: {report.elapsed_ms:.2f}ms"])
    return "\n".join(lines)
