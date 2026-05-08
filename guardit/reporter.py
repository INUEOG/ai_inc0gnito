from __future__ import annotations

import json
from pathlib import Path

from .ai.redact import redact_obj
from .models import ScanReport
from .terminal_ui import badge, bar, level_color, panel, secret_badge


def save_report(report: ScanReport, path: Path = Path("results/guardit-report.json")) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_json(report), encoding="utf-8")


def render_json(report: ScanReport) -> str:
    return json.dumps(redact_obj(report.to_dict()), ensure_ascii=False, indent=2)


def render_saved_report(path: Path) -> str:
    payload = json.loads(path.read_text(encoding="utf-8"))
    score = payload.get("score", {})
    metadata = payload.get("metadata", {})
    level = str(score.get("risk_level", "UNKNOWN"))
    final_score = int(score.get("final_score") or 0)
    summary = [
        f"Final Risk        {badge(level, level_color(level))}",
        f"Risk Score        {bar(final_score, 100, level_color(level))} {final_score}/100",
        f"- LLM 보정 전 점수: {score.get('base_score', '?')}/100",
        f"대상: {metadata.get('source', '-')}",
    ]
    sections = [panel("Final Risk Report", summary, border=level_color(level))]

    candidates = []
    for candidate in payload.get("candidates", [])[:20]:
        if isinstance(candidate, dict):
            candidates.append(f"- {candidate.get('path')} ({candidate.get('reason', '')})")
        else:
            candidates.append(f"- {candidate}")
    sections.append(panel("Suspicious Files", candidates or ["위험 후보 파일 없음"], border=level_color(level)))

    flows = []
    for flow in payload.get("execution_flows", [])[:10]:
        flows.append(f"- {flow.get('trigger_file')}")
        if flow.get("executed_file"):
            flows.append(f"  -> {flow.get('executed_file')}")
        for source in flow.get("secret_sources", [])[:3]:
            flows.append(f"  -> 민감정보 접근: {source}")
        for sink in flow.get("external_sinks", [])[:3]:
            flows.append(f"  -> 외부 전송: {sink}")
        flows.append(f"  risk: {flow.get('risk')}")
    if flows:
        sections.append(panel("Execution Flow", flows, border=level_color(level)))

    warnings = payload.get("warnings", [])
    if warnings:
        warning_lines = []
        for warning in warnings[:10]:
            warning_lines.append(f"- {warning.get('file')}:{warning.get('line')} {warning.get('message')}")
        sections.append(panel("Warnings", warning_lines, border=level_color(level)))

    sandbox = payload.get("sandbox_summary", {})
    if sandbox:
        sandbox_lines = [
            f"- mode: {sandbox.get('mode')}",
            f"- real sandbox: {sandbox.get('is_real_sandbox')}",
            f"- fallback: {sandbox.get('fallback_used')}",
        ]
        if sandbox.get("fallback_reason"):
            sandbox_lines.append(f"- fallback reason: {sandbox.get('fallback_reason')}")
        sections.append(panel("Sandbox Behavior", sandbox_lines, border=level_color(level)))

    evidence_lines = []
    for item in payload.get("evidence", [])[:15]:
        evidence_lines.append(f"- {item.get('file')}:{item.get('line')} [{item.get('type')}] {item.get('description')}")
    if payload.get("suspected_secrets"):
        evidence_lines.append("")
        evidence_lines.append(" ".join(secret_badge(item) for item in payload.get("suspected_secrets", [])))
    sections.append(panel("Evidence", evidence_lines or ["위험 evidence 없음"], border=level_color(level)))

    llm = payload.get("llm", {})
    if llm:
        sections.append(
            panel(
                "AI Security Analysis",
            [
                "",
                f"- provider: {llm.get('provider')}",
                f"- 사용 여부: {'사용' if llm.get('used') else 'fallback'}",
                f"- AI 판단: {llm.get('verdict')}",
                f"- risk_adjustment: {int(llm.get('risk_adjustment') or 0):+d}",
                f"- 이유: {llm.get('reason')}",
            ],
                border=level_color(str(llm.get("verdict", level))),
            )
        )
    return "\n\n".join(sections)


def render_text(report: ScanReport) -> str:
    lines = [
        "최종 판정:",
        f"- 등급: {report.score.risk_level}",
        f"- 위험도: {report.score.final_score}/100",
        f"- LLM 보정 전 점수: {report.score.base_score}/100",
        "",
        f"대상: {report.metadata.source}",
        f"수집 방식: {report.metadata.collection_mode}",
        f"자동 실행 후보 파일: {len(report.candidates)}개",
        f"작성자 신뢰도: {report.metadata.author_trust.score}/100",
    ]
    if report.metadata.author_trust.signals:
        lines.append("작성자 신뢰도 근거:")
        lines.extend(f"- {signal}" for signal in report.metadata.author_trust.signals[:5])

    if report.candidates:
        lines.extend(["", "위험 후보 파일:"])
        for candidate in report.candidates[:15]:
            lines.append(f"- {candidate.path} ({candidate.reason}, {candidate.size} bytes)")

    if report.execution_flows:
        lines.extend(["", "위험 흐름:"])
        for flow in report.execution_flows[:8]:
            lines.append(f"- {flow.trigger_file}")
            if flow.executed_file:
                lines.append(f"  -> {flow.executed_file}")
            for source in flow.secret_sources[:3]:
                lines.append(f"  -> 민감정보 접근: {source}")
            for sink in flow.external_sinks[:3]:
                lines.append(f"  -> 외부 전송: {sink}")
            for process in flow.process_steps[:3]:
                lines.append(f"  -> 실행/우회: {process}")
            lines.append(f"  risk: {flow.risk}")

    if report.warnings:
        lines.extend(["", "[주의]"])
        for warning in report.warnings[:10]:
            lines.append(f"- {warning.file}:{warning.line} {warning.message}")

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
        lines.extend(["", "Sandbox Mode:"])
        lines.append(f"- mode: {report.sandbox_summary.mode}")
        lines.append(f"- real sandbox: {report.sandbox_summary.is_real_sandbox}")
        lines.append(f"- fallback used: {report.sandbox_summary.fallback_used}")
        if report.sandbox_summary.fallback_reason:
            lines.append(f"- fallback reason: {report.sandbox_summary.fallback_reason}")
        lines.append(f"- dummy credential accessed: {report.sandbox_summary.dummy_credentials_accessed}")
        inferred = [log for log in report.sandbox_logs if log.origin == "inferred"]
        observed = [log for log in report.sandbox_logs if log.origin == "observed"]
        if inferred:
            lines.append("")
            lines.append("[inferred]")
            for log in inferred[:10]:
                lines.append(f"- {log.file}:{log.line} {log.action} - {log.detail}")
        if observed:
            lines.append("")
            lines.append("[observed]")
            for log in observed[:10]:
                syscall = f" ({log.syscall})" if log.syscall else ""
                lines.append(f"- {log.file}:{log.line} {log.action}{syscall} - {log.detail}")
    elif report.sandbox_summary.mode in {"off", "docker-sandbox-skipped"}:
        lines.extend(["", "Sandbox Mode:"])
        lines.append(f"- mode: {report.sandbox_summary.mode}")
        if report.sandbox_summary.fallback_reason:
            lines.append(f"- reason: {report.sandbox_summary.fallback_reason}")

    lines.extend(
        [
            "",
            "AI 보조 판단:",
            f"- provider: {report.llm.provider}",
            f"- 사용 여부: {'사용' if report.llm.used else 'fallback'}",
            f"- AI 판단: {report.llm.verdict}",
            f"- risk_adjustment: {report.llm.risk_adjustment:+d}",
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
