from __future__ import annotations

import json
from pathlib import Path

from .ai.redact import redact_obj
from .models import ScanReport


def save_report(report: ScanReport, path: Path = Path("results/guardit-report.json")) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_json(report), encoding="utf-8")


def render_json(report: ScanReport) -> str:
    return json.dumps(redact_obj(report.to_dict()), ensure_ascii=False, indent=2)


def render_text(report: ScanReport) -> str:
    lines = [
        f"[{report.score.risk_level}]",
        f"위험도: {report.score.final_score}/100",
        "",
        f"대상: {report.metadata.source}",
        f"수집 방식: {report.metadata.collection_mode}",
        f"자동 실행 후보 파일: {len(report.candidates)}개",
        f"작성자 신뢰도: {report.metadata.author_trust.score}/100",
    ]
    if report.metadata.author_trust.signals:
        lines.append("작성자 신뢰도 근거:")
        lines.extend(f"- {signal}" for signal in report.metadata.author_trust.signals[:5])

    lines.extend(["", "탐지 근거:"])
    if report.evidence:
        for item in report.evidence[:15]:
            lines.append(f"- {item.file}:{item.line} [{item.type}] {item.description}")
            lines.append(f"  evidence: {item.evidence}")
    else:
        lines.append("- 위험 evidence 없음")

    if report.suspected_secrets:
        lines.extend(["", "탈취 가능 개인정보:"])
        lines.extend(f"- {item}" for item in report.suspected_secrets)

    if report.sandbox_logs:
        lines.extend(["", "샌드박스형 행동 추정:"])
        for log in report.sandbox_logs[:10]:
            lines.append(f"- {log.file}:{log.line} {log.action} - {log.detail}")

    lines.extend(
        [
            "",
            "AI 의도 분석:",
            f"- provider: {report.llm.provider}",
            f"- 사용 여부: {'사용' if report.llm.used else 'fallback'}",
            f"- 판단: {report.llm.verdict}",
            f"- 이유: {report.llm.reason}",
        ]
    )
    if report.llm.error:
        lines.append(f"- 참고: {report.llm.error}")

    lines.extend(["", "점수 근거:"])
    lines.extend(f"- {note}" for note in report.score.notes)
    lines.append(f"- 처리 시간: {report.elapsed_ms:.2f}ms")
    lines.append("")
    lines.append("JSON 리포트: results/guardit-report.json")
    return "\n".join(lines)
