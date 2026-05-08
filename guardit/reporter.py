from __future__ import annotations

import json
from pathlib import Path

from .ai.redact import redact_obj
from .models import ScanReport
from .terminal_ui import (
    BOLD,
    DIM,
    FG_GREEN,
    FG_RED,
    FG_YELLOW,
    badge,
    bar,
    color,
    level_color,
    panel,
    section_header,
    secret_badge,
    terminal_width,
    _short,
)


def save_report(report: ScanReport, path: Path = Path("results/guardit-report.json")) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_json(report), encoding="utf-8")


def render_json(report: ScanReport) -> str:
    return json.dumps(redact_obj(report.to_dict()), ensure_ascii=False, indent=2)


def render_saved_report(path: Path) -> str:
    """저장된 JSON 리포트를 사람이 읽기 쉬운 형태로 출력."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    score = payload.get("score", {})
    metadata = payload.get("metadata", {})
    level = str(score.get("risk_level", "UNKNOWN"))
    final_score = int(score.get("final_score") or 0)
    base_score = score.get("base_score", "?")
    style = level_color(level)

    lines: list[str] = []

    # 최종 판정
    lines.append(section_header("최종 판정"))
    lines.append("")
    lines.append(f"  판정     {color(level, f'{BOLD}{style}')}")
    lines.append(f"  위험도   {bar(final_score, 100, style)} {color(f'{final_score}/100', style)}")
    lines.append(f"  LLM 보정 전  {base_score}/100")
    lines.append(f"  대상     {metadata.get('source', '-')}")
    lines.append("")

    # 의심 파일
    candidates = payload.get("candidates", [])[:10]
    if candidates:
        lines.append(section_header("탐지 요약"))
        lines.append("")
        lines.append(f"  {color('의심 파일', BOLD)} {len(candidates)}개")
        for c in candidates:
            if isinstance(c, dict):
                reason = c.get('reason', '')
                dot = color('·', DIM)
                reason_text = color('(' + reason + ')', DIM)
                lines.append(f"  {dot} {c.get('path')} {reason_text}")
            else:
                lines.append(f"  {color('·', DIM)} {c}")
        lines.append("")

    # 위험 흐름
    flows = payload.get("execution_flows", [])[:5]
    if flows:
        lines.append(f"  {color('위험 흐름', BOLD)}")
        for flow in flows:
            trigger = flow.get("trigger_file", "")
            executed = flow.get("executed_file")
            if executed and executed != trigger:
                lines.append(f"  {color('·', DIM)} {trigger} → {executed}")
            else:
                lines.append(f"  {color('·', DIM)} {trigger}")
            for source in flow.get("secret_sources", [])[:2]:
                lines.append(f"    → {color('민감정보 접근', FG_YELLOW)}: {source}")
            for sink in flow.get("external_sinks", [])[:2]:
                lines.append(f"    → {color('외부 전송', FG_RED)}: {sink}")
        lines.append("")

    # Evidence
    evidence_items = payload.get("evidence", [])[:8]
    if evidence_items:
        lines.append(f"  {color('핵심 탐지 근거', BOLD)}")
        for item in evidence_items:
            lines.append(f"  {color('·', DIM)} {item.get('file')}:{item.get('line')} {item.get('type')} — {_short(str(item.get('evidence', '')), 50)}")
        lines.append("")

    # 탈취 가능 정보
    secrets = payload.get("suspected_secrets", [])
    if secrets:
        labels = ", ".join(secrets[:5])
        lines.append(f"  {color('탈취 가능 정보', BOLD)}  {color(labels, FG_RED)}")
        lines.append("")

    # Sandbox
    sandbox = payload.get("sandbox_summary", {})
    if sandbox:
        lines.append(f"  {color('Sandbox Behavior', BOLD)}")
        lines.append(f"  {color('·', DIM)} Mode: {sandbox.get('mode', '-')}")
        lines.append(f"  {color('·', DIM)} Real sandbox: {'yes' if sandbox.get('is_real_sandbox') else 'no'}")
        if sandbox.get("fallback_reason"):
            lines.append(f"  {color('·', FG_YELLOW)} Sandbox status: failed")
            lines.append(f"    Reason: {sandbox.get('fallback_reason')}")
        if not sandbox.get("observed_opened_files") and not sandbox.get("observed_network_attempts") and not sandbox.get("observed_processes"):
            lines.append(f"  {color('✓', FG_GREEN)} suspicious behavior not observed")
            lines.append(f"  {color('✓', FG_GREEN)} credential access not observed")
            lines.append(f"  {color('✓', FG_GREEN)} external network attempt not observed")
        lines.append("")

    # Warnings
    warnings = payload.get("warnings", [])
    if warnings:
        lines.append(f"  {color('주의 사항', BOLD)}")
        for w in warnings[:5]:
            lines.append(f"  {color('·', FG_YELLOW)} {w.get('file')}:{w.get('line')} {w.get('message')}")
        lines.append("")

    # AI 분석
    llm = payload.get("llm", {})
    if llm:
        lines.append(section_header("AI 분석"))
        lines.append("")
        verdict = str(llm.get("verdict", level))
        v_style = level_color(verdict)
        confidence = int(round(float(llm.get("confidence") or 0) * 100))
        lines.append(f"  판정     {color(verdict, f'{BOLD}{v_style}')}")
        if llm.get("used"):
            lines.append(f"  신뢰도   {bar(confidence, 100, v_style)} {color(f'{confidence}%', v_style)}")
        else:
            lines.append(f"  {color('AI 미사용 — 규칙 기반 안전 판정', DIM)}")
        if llm.get("reason"):
            lines.append("")
            lines.append(f"  {color('근거', BOLD)}")
            lines.append(f"  - {llm.get('reason')}")
        if llm.get("error"):
            err = llm.get('error')
            lines.append(f"  {color('참고: ' + str(err), DIM)}")
        lines.append("")

    return "\n".join(lines)


def render_text(report: ScanReport) -> str:
    """플레인 텍스트 요약 (JSON이 아닌 사람 읽기용)."""
    lines = [
        "──── 최종 판정 ────",
        f"판정: {report.score.risk_level}",
        f"위험도: {report.score.final_score}/100",
        f"LLM 보정 전: {report.score.base_score}/100",
        "",
        f"대상: {report.metadata.source}",
        f"수집 방식: {report.metadata.collection_mode}",
        f"자동 실행 후보 파일: {len(report.candidates)}개",
        f"작성자 신뢰도: {report.metadata.author_trust.score}/100",
    ]
    if report.metadata.author_trust.signals:
        lines.append("신뢰도 근거:")
        lines.extend(f"- {signal}" for signal in report.metadata.author_trust.signals[:5])

    if report.candidates:
        lines.extend(["", "──── 의심 파일 ────"])
        for candidate in report.candidates[:10]:
            lines.append(f"- {candidate.path} ({candidate.reason}, {candidate.size} bytes)")

    if report.execution_flows:
        lines.extend(["", "──── 위험 흐름 ────"])
        for flow in report.execution_flows[:5]:
            lines.append(f"- {flow.trigger_file}")
            if flow.executed_file:
                lines.append(f"  → {flow.executed_file}")
            for source in flow.secret_sources[:3]:
                lines.append(f"  → 민감정보 접근: {source}")
            for sink in flow.external_sinks[:3]:
                lines.append(f"  → 외부 전송: {sink}")
            for process in flow.process_steps[:3]:
                lines.append(f"  → 실행/우회: {process}")
            lines.append(f"  risk: {flow.risk}")

    if report.evidence:
        lines.extend(["", "──── 탐지 근거 ────"])
        for item in report.evidence[:10]:
            lines.append(f"- {item.file}:{item.line} [{item.type}] {item.description}")
            lines.append(f"  evidence: {item.evidence}")
    else:
        lines.extend(["", "탐지 근거 없음"])

    if report.suspected_secrets:
        lines.extend(["", "탈취 가능 개인정보:"])
        lines.extend(f"- {item}" for item in report.suspected_secrets)

    if report.warnings:
        lines.extend(["", "──── 주의 사항 ────"])
        for warning in report.warnings[:10]:
            lines.append(f"- {warning.file}:{warning.line} {warning.message}")

    lines.extend(["", "──── sandbox 분석 ────"])
    lines.append(f"모드: {report.sandbox_summary.mode}")
    lines.append(f"Real sandbox: {'yes' if report.sandbox_summary.is_real_sandbox else 'no'}")
    if report.sandbox_summary.fallback_reason:
        lines.append("Sandbox status: failed")
        lines.append(f"Reason: {report.sandbox_summary.fallback_reason}")
    inferred = [log for log in report.sandbox_logs if log.origin == "inferred"]
    observed = [log for log in report.sandbox_logs if log.origin == "observed"]
    if report.sandbox_logs:
        if inferred:
            lines.append("")
            lines.append("[inferred] 정적 추론")
            for log in inferred[:8]:
                lines.append(f"- {log.file}:{log.line} {log.action} — {log.detail}")
        if observed:
            lines.append("")
            lines.append("[observed] 실제 행위")
            for log in observed[:8]:
                syscall = f" ({log.syscall})" if log.syscall else ""
                lines.append(f"- {log.file}:{log.line} {log.action}{syscall} — {log.detail}")
    if not observed:
        lines.append("")
        lines.append("[observed] 실제 행위")
        lines.append("- suspicious behavior not observed")
        lines.append("- credential access not observed")
        lines.append("- external network attempt not observed")

    lines.extend([
        "",
        "──── AI 분석 ────",
        f"AI 판단: {report.llm.verdict}",
        f"신뢰도: {report.llm.confidence:.2f}",
        f"이유: {report.llm.reason}",
    ])
    if not report.llm.used:
        lines.append("참고: AI 미사용 — 규칙 기반 안전 판정")
    if report.llm.error:
        lines.append(f"참고: {report.llm.error}")

    lines.extend(["", "점수 근거:"])
    lines.extend(f"- {note}" for note in report.score.notes)
    lines.append(f"처리 시간: {report.elapsed_ms:.0f}ms")
    lines.append("")
    lines.append("JSON 리포트: results/guardit-report.json")
    return "\n".join(lines)
