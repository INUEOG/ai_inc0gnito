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
        f"위험 점수: {report.risk_score}/100",
        f"판정: {report.verdict}",
        f"권장 조치: {report.recommendation}",
        "",
        f"AI 판단: {report.ai_judgement}",
    ]

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

    lines.extend(
        [
            "",
            "사용자 선택지",
            "1. clone 차단",
            "2. 위험 파일 제외 후 clone",
            "3. 위험 감수 후 진행",
            "",
            f"처리 시간: {report.elapsed_ms:.2f}ms",
        ]
    )
    return "\n".join(lines)
