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


def render_saved_report(path: Path) -> str:
    payload = json.loads(path.read_text(encoding="utf-8"))
    score = payload.get("score", {})
    metadata = payload.get("metadata", {})
    lines = [
        f"[{score.get('risk_level', 'UNKNOWN')}]",
        f"위험도: {score.get('final_score', '?')}/100",
        f"대상: {metadata.get('source', '-')}",
        "",
        "위험 후보 파일:",
    ]
    for candidate in payload.get("candidates", [])[:20]:
        if isinstance(candidate, dict):
            lines.append(f"- {candidate.get('path')} ({candidate.get('reason', '')})")
        else:
            lines.append(f"- {candidate}")
    lines.append("")
    lines.append("위험 흐름:")
    for flow in payload.get("execution_flows", [])[:10]:
        lines.append(f"- {flow.get('trigger_file')}")
        if flow.get("executed_file"):
            lines.append(f"  -> {flow.get('executed_file')}")
        for source in flow.get("secret_sources", [])[:3]:
            lines.append(f"  -> 민감정보 접근: {source}")
        for sink in flow.get("external_sinks", [])[:3]:
            lines.append(f"  -> 외부 전송: {sink}")
        lines.append(f"  risk: {flow.get('risk')}")
    lines.append("")
    warnings = payload.get("warnings", [])
    if warnings:
        lines.append("주의:")
        for warning in warnings[:10]:
            lines.append(f"- {warning.get('file')}:{warning.get('line')} {warning.get('message')}")
        lines.append("")
    sandbox = payload.get("sandbox_summary", {})
    if sandbox:
        lines.append("Sandbox Mode:")
        lines.append(f"- mode: {sandbox.get('mode')}")
        lines.append(f"- real sandbox: {sandbox.get('is_real_sandbox')}")
        lines.append(f"- fallback: {sandbox.get('fallback_used')}")
        if sandbox.get("fallback_reason"):
            lines.append(f"- fallback reason: {sandbox.get('fallback_reason')}")
        lines.append("")
    lines.append("주요 evidence:")
    for item in payload.get("evidence", [])[:15]:
        lines.append(f"- {item.get('file')}:{item.get('line')} [{item.get('type')}] {item.get('description')}")
    return "\n".join(lines)


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
