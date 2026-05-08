from __future__ import annotations

import os
import re
import shutil
import sys
import threading
import time
import unicodedata
from dataclasses import dataclass
from textwrap import shorten
from typing import Callable

from .models import Evidence, RiskLevel, SandboxLog, ScanReport


# ── 색상 정책: 녹/노/적 + 흰/회 ──────────────────────────────────────────────
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
FG_RED = "\033[31m"
FG_GREEN = "\033[32m"
FG_YELLOW = "\033[33m"
FG_WHITE = "\033[37m"
FG_BRIGHT_RED = "\033[91m"
FG_BRIGHT_BLACK = "\033[90m"
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def color(text: str, style: str) -> str:
    if os.environ.get("NO_COLOR"):
        return text
    return f"{style}{text}{RESET}"


def terminal_width() -> int:
    return max(60, min(100, shutil.get_terminal_size((80, 24)).columns))


# ── 진행 단계 ─────────────────────────────────────────────────────────────────

@dataclass
class Step:
    index: int
    title: str


STEPS = [
    Step(1, "GitHub/로컬 정보 수집"),
    Step(2, "자동 실행 파일 탐지"),
    Step(3, "정적 개인정보 유출 분석"),
    Step(4, "샌드박스 행동 분석"),
    Step(5, "AI 판단"),
]


class SecurityConsole:
    def __init__(self, stream=None) -> None:
        self.stream = stream or sys.stdout
        self._spinner_stop: threading.Event | None = None
        self._spinner_thread: threading.Thread | None = None
        self._spinner_label = ""

    def banner(self, source: str, mode: str) -> None:
        width = terminal_width()
        self.print("")
        self.print(color("  guardit", BOLD) + color(f"  ·  분석 대상: {_short(source, width - 24)}", DIM))
        self.print(color(f"  sandbox={mode}", DIM))
        self.print("")

    def progress_callback(self, quiet: bool = False) -> Callable[[str, int, str], None] | None:
        if quiet:
            return None

        def callback(event: str, index: int, title: str) -> None:
            if event == "start":
                self.start_step(index, title)
            elif event == "done":
                self.complete_step(index, title)
            elif event == "fail":
                self.fail_step(index, title)

        return callback

    def start_step(self, index: int, title: str) -> None:
        self._stop_spinner(clear=True)
        self._spinner_label = f"[{index}/5] {title}"
        stop = threading.Event()
        self._spinner_stop = stop

        def spin() -> None:
            frames = ["·", "··", "···"]
            frame_index = 0
            while not stop.is_set():
                frame = color(frames[frame_index % len(frames)], DIM)
                label = self._spinner_label
                self.stream.write(f"\r  {label} {frame}  ")
                self.stream.flush()
                frame_index += 1
                time.sleep(0.25)

        self._spinner_thread = threading.Thread(target=spin, daemon=True)
        self._spinner_thread.start()

    def complete_step(self, index: int, title: str) -> None:
        self._stop_spinner(clear=True)
        self.print(f"  {color('✓', FG_GREEN)} [{index}/5] {title}")

    def fail_step(self, index: int, title: str) -> None:
        self._stop_spinner(clear=True)
        self.print(f"  {color('✗', FG_RED)} [{index}/5] {title}")

    def action_menu(self, report: ScanReport) -> None:
        self.print("")
        self.print(section_header("사용자 조치 선택"))
        self.print(f"  [1] {color('Clone 차단', FG_RED)}  {color('(권장)', FG_YELLOW) if report.score.risk_level in {'WATCH', 'SUSPICIOUS', 'MALICIOUS'} else ''}")
        self.print(f"      clone 전 차단하여 로컬 credential 노출을 방지합니다.")
        self.print(f"  [2] {color('위험 파일 제외 Clone', FG_YELLOW)}")
        self.print(f"      위험 후보 파일을 제외한 clean clone을 수행합니다.")
        self.print(f"  [3] {color('위험 감수 후 Clone', DIM)}")
        self.print(f"      위험을 인지하고 원본 clone을 진행합니다.")
        self.print("")

    def action_result(self, title: str, lines: list[str], severity: RiskLevel | str = "SAFE") -> None:
        self.print("")
        style = level_color(str(severity))
        self.print(f"  {color(title, f'{BOLD}{style}')}")
        for line in lines:
            self.print(f"  {line}")
        self.print("")

    def print(self, value: str = "") -> None:
        self.stream.write(f"{value}\n")
        self.stream.flush()

    def _stop_spinner(self, clear: bool = False) -> None:
        if self._spinner_stop:
            self._spinner_stop.set()
        if self._spinner_thread:
            self._spinner_thread.join(timeout=0.3)
        self._spinner_stop = None
        self._spinner_thread = None
        if clear:
            self.stream.write("\r" + " " * (terminal_width() - 1) + "\r")
            self.stream.flush()


# ── 메인 리포트 렌더링 ───────────────────────────────────────────────────────

def render_security_report(report: ScanReport, output_path: str = "results/guardit-report.json") -> str:
    sections: list[str] = []

    # 1. 최종 판정 (최상단)
    sections.append(_verdict_section(report))

    # 2. 탐지 요약
    detection = _detection_section(report)
    if detection:
        sections.append(detection)

    # 3. AI 분석
    sections.append(_ai_section(report))

    # 4. 상세 정보
    sections.append(_detail_section(report, output_path))

    return "\n".join(sections)


# ── 섹션 헬퍼 ─────────────────────────────────────────────────────────────────

def section_header(title: str) -> str:
    width = terminal_width()
    dashes = "─" * max(4, width - len(title) - 8)
    return color(f"  ──── {title} {dashes}", DIM)


def level_color(level: str) -> str:
    return {
        "SAFE": FG_GREEN,
        "WATCH": FG_YELLOW,
        "SUSPICIOUS": FG_RED,
        "MALICIOUS": FG_BRIGHT_RED,
        "LOW": FG_GREEN,
        "MEDIUM": FG_YELLOW,
        "HIGH": FG_RED,
        "CRITICAL": FG_BRIGHT_RED,
    }.get(level, FG_WHITE)


def bar(value: int, total: int = 100, style: str = FG_GREEN, width: int = 10) -> str:
    value = max(0, min(total, int(value)))
    filled = int(round((value / total) * width)) if total else 0
    return color("█" * filled, style) + color("░" * (width - filled), DIM)


def badge(text: str, style: str) -> str:
    return color(text, f"{BOLD}{style}")


# ── 최종 판정 섹션 ────────────────────────────────────────────────────────────

def _verdict_section(report: ScanReport) -> str:
    level = report.score.risk_level
    style = level_color(level)
    lines = [""]
    lines.append(section_header("최종 판정"))
    lines.append("")
    lines.append(f"  판정     {color(level, f'{BOLD}{style}')}")
    lines.append(f"  위험도   {bar(report.score.final_score, 100, style)} {color(f'{report.score.final_score}/100', style)}")

    if level == "SAFE":
        lines.append("")
        lines.extend(_safe_checklist(report))
    elif report.suspected_secrets:
        targets = ", ".join(report.suspected_secrets[:5])
        lines.append(f"  탈취 대상 {color(targets, style)}")

    lines.append("")
    return "\n".join(lines)


def _safe_checklist(report: ScanReport) -> list[str]:
    lines: list[str] = []
    has_auto = any(item.category == "auto_trigger" for item in report.evidence)
    has_secret = any(item.category == "secret_access" for item in report.evidence)
    has_sink = any(item.category == "external_sink" for item in report.evidence)

    lines.append(f"  {color('✓', FG_GREEN)} 자동 실행 파일 {'탐지됨 (위험도 낮음)' if has_auto else '없음'}")
    lines.append(f"  {color('✓', FG_GREEN)} 개인정보 접근 패턴 {'탐지됨 (위험도 낮음)' if has_secret else '없음'}")
    lines.append(f"  {color('✓', FG_GREEN)} 외부 전송 시도 {'탐지됨 (위험도 낮음)' if has_sink else '없음'}")
    return lines


# ── 탐지 요약 섹션 ────────────────────────────────────────────────────────────

def _detection_section(report: ScanReport) -> str | None:
    has_candidates = bool(report.candidates)
    has_evidence = bool(report.evidence)
    has_sandbox = bool(report.sandbox_logs) or bool(report.sandbox_summary.mode)
    has_flows = bool(report.execution_flows)

    if not has_candidates and not has_evidence and not has_sandbox:
        return None

    lines = [section_header("탐지 요약"), ""]

    # 의심 파일
    if has_candidates:
        lines.append(f"  {color('의심 파일', BOLD)} {len(report.candidates)}개")
        for candidate in report.candidates[:5]:
            lines.append(f"  {color('·', DIM)} {candidate.path} {color(f'({candidate.reason})', DIM)}")
        if len(report.candidates) > 5:
            lines.append(color(f"    ... 외 {len(report.candidates) - 5}개 (JSON 리포트 참조)", DIM))
        lines.append("")

    # 위험 흐름
    if has_flows:
        lines.append(f"  {color('위험 흐름', BOLD)}")
        for flow in report.execution_flows[:3]:
            trigger = flow.trigger_file
            target = flow.executed_file
            if target and target != trigger:
                lines.append(f"  {color('·', DIM)} {trigger} → {target}")
            else:
                lines.append(f"  {color('·', DIM)} {trigger}")
            for source in flow.secret_sources[:2]:
                lines.append(f"    → {color('민감정보 접근', FG_YELLOW)}: {source}")
            for sink in flow.external_sinks[:2]:
                lines.append(f"    → {color('외부 전송', FG_RED)}: {sink}")
        lines.append("")

    # 핵심 evidence
    if has_evidence:
        critical = sorted(report.evidence, key=lambda e: e.score, reverse=True)[:5]
        lines.append(f"  {color('핵심 탐지 근거', BOLD)}")
        for item in critical:
            sev_style = level_color(_severity_to_level(item.severity))
            lines.append(f"  {color('·', sev_style)} {item.file}:{item.line} {color(item.type, sev_style)} {_short(item.evidence, 50)}")
        if len(report.evidence) > 5:
            lines.append(color(f"    ... 외 {len(report.evidence) - 5}개 (JSON 리포트 참조)", DIM))
        lines.append("")

    # 탈취 가능 개인정보 뱃지
    if report.suspected_secrets:
        labels = "  ".join(color(s, f"{BOLD}{FG_RED}") for s in report.suspected_secrets)
        lines.append(f"  {color('탈취 가능 정보', BOLD)}  {labels}")
        lines.append("")

    # sandbox 상태
    summary = report.sandbox_summary
    lines.append(f"  {color('Sandbox Behavior', BOLD)}")
    lines.append(f"  {color('·', DIM)} Mode: {summary.mode}")
    lines.append(f"  {color('·', DIM)} Real sandbox: {'yes' if summary.is_real_sandbox else 'no'}")
    if summary.fallback_reason:
        lines.append(f"  {color('·', FG_YELLOW)} Sandbox status: failed")
        lines.append(f"    Reason: {summary.fallback_reason}")
    lines.append("")

    # inferred / observed
    inferred = [log for log in report.sandbox_logs if log.origin == "inferred"]
    observed = [log for log in report.sandbox_logs if log.origin == "observed"]

    if inferred:
        lines.append(f"  {color('[inferred]', FG_YELLOW)} {color('정적 추론', DIM)}")
        for log in inferred[:4]:
            lines.append(f"  {color('·', FG_YELLOW)} {log.file}:{log.line} {log.action} — {_short(log.detail, 50)}")
        lines.append("")

    if observed:
        lines.append(f"  {color('[observed]', FG_RED)} {color('실제 행위', DIM)}")
        for log in observed[:4]:
            syscall = f" ({log.syscall})" if log.syscall else ""
            lines.append(f"  {color('·', FG_RED)} {log.file}:{log.line} {log.action}{syscall} — {_short(log.detail, 50)}")
        lines.append("")

    if summary.is_real_sandbox and not observed:
        lines.append(f"  {color('[observed]', FG_GREEN)} {color('실제 행위', DIM)}")
        lines.append(f"  {color('✓', FG_GREEN)} suspicious behavior not observed")
        lines.append(f"  {color('✓', FG_GREEN)} credential access not observed")
        lines.append(f"  {color('✓', FG_GREEN)} external network attempt not observed")
        lines.append("")

    return "\n".join(lines)


# ── AI 분석 섹션 ──────────────────────────────────────────────────────────────

def _ai_section(report: ScanReport) -> str:
    llm = report.llm
    confidence = int(round(llm.confidence * 100))
    verdict_style = level_color(llm.verdict)

    lines = [section_header("AI 분석"), ""]

    if not llm.used:
        lines.append(f"  판정     {color(llm.verdict, f'{BOLD}{verdict_style}')}")
        lines.append(f"  {color('AI provider disabled — local safety analysis', DIM)}")
        if llm.error:
            lines.append(f"  {color(f'참고: {llm.error}', DIM)}")
        lines.append("")
        return "\n".join(lines)

    lines.append(f"  판정     {color(llm.verdict, f'{BOLD}{verdict_style}')}")
    lines.append(f"  상태     {color(llm.status, FG_YELLOW if llm.status == 'degraded' else DIM)}")
    lines.append(f"  provider {llm.provider}")
    lines.append(f"  신뢰도   {bar(confidence, 100, verdict_style)} {color(f'{confidence}%', verdict_style)}")

    if llm.risk_adjustment:
        lines.append(f"  점수 보정 {color(f'{llm.risk_adjustment:+d}', FG_YELLOW)}")

    lines.append("")
    lines.append(f"  {color('근거', BOLD)}")
    reason_items = _reason_lines(llm.reason, llm.evidence)
    for item in reason_items:
        lines.append(f"  {item}")

    if llm.leaked_data:
        lines.append("")
        labels = ", ".join(llm.leaked_data[:5])
        lines.append(f"  {color('유출 데이터 후보', BOLD)}  {color(labels, FG_RED)}")

    if llm.error:
        lines.append(f"  {color(f'참고: {llm.error}', DIM)}")

    lines.append("")
    return "\n".join(lines)


# ── 상세 정보 섹션 ────────────────────────────────────────────────────────────

def _detail_section(report: ScanReport, output_path: str) -> str:
    lines = [section_header("상세 정보"), ""]

    lines.append(f"  대상           {_short(report.metadata.source, terminal_width() - 20)}")
    lines.append(f"  수집 방식       {report.metadata.collection_mode}")

    trust = report.metadata.author_trust.score
    trust_style = FG_GREEN if trust >= 70 else FG_YELLOW if trust >= 40 else FG_RED
    lines.append(f"  작성자 신뢰도   {bar(trust, 100, trust_style)} {color(f'{trust}/100', trust_style)}")

    lines.append(f"  LLM 보정 전     {report.score.base_score}/100")
    lines.append(f"  처리 시간       {report.elapsed_ms:.0f}ms")
    lines.append(f"  JSON 리포트     {output_path}")

    # Clone Gate 권장 조치
    lines.append("")
    action = _recommended_action(report)
    lines.append(f"  {color('권장 조치', BOLD)}  {action}")

    # 점수 근거 (상위 5개)
    if report.score.notes:
        lines.append("")
        lines.append(f"  {color('점수 근거', DIM)}")
        for note in report.score.notes[:5]:
            lines.append(f"  {color('·', DIM)} {note}")

    lines.append("")
    return "\n".join(lines)


# ── 유틸리티 ──────────────────────────────────────────────────────────────────

def _severity_to_level(severity: str) -> str:
    return {"low": "SAFE", "medium": "WATCH", "high": "SUSPICIOUS", "critical": "MALICIOUS"}.get(severity, "WATCH")


def _reason_lines(reason: str, evidence: list[str]) -> list[str]:
    items = [item.strip(" -") for item in reason.replace("。", ".").split(".") if item.strip()]
    lines = [f"- {item}" for item in items[:4]] or ["- AI 판단 사유 없음"]
    lines.extend(f"- {item}" for item in evidence[:3])
    return lines


def _recommended_action(report: ScanReport) -> str:
    level = report.score.risk_level
    if level == "UNKNOWN":
        return color("보류: LLM 분석 실패로 최종 판정을 보류했습니다.", FG_YELLOW)
    if level == "MALICIOUS":
        return color("차단 권장: 자동 실행 + 개인정보 탈취 흐름 탐지", FG_BRIGHT_RED)
    if level in {"WATCH", "SUSPICIOUS"}:
        return color("위험 파일 제외 clone 권장", FG_YELLOW)
    return color("진행 가능: clone 전 차단 조건 없음", FG_GREEN)


def secret_badge(value: str) -> str:
    label = value
    upper = value.upper()
    if "AWS" in upper:
        label = "AWS"
    elif "SSH" in upper:
        label = "SSH"
    elif "BROWSER" in upper:
        label = "BROWSER"
    elif "GITHUB" in upper:
        label = "GITHUB"
    elif "NPM" in upper:
        label = "NPM"
    elif ".ENV" in upper or "ENV" in upper:
        label = "ENV"
    return color(label, f"{BOLD}{FG_RED}")


def _short(value: str, width: int) -> str:
    return shorten(str(value).replace("\n", " "), width=max(10, width), placeholder="...")


# ── 레거시 호환: reporter.py에서 사용하는 panel / fit_ansi ─────────────────────

def panel(title: str, lines: list[str], border: str = DIM) -> str:
    """레거시 호환용. render_saved_report에서 사용."""
    width = terminal_width()
    divider = color("─" * (width - 4), DIM)
    header = f"  {color(title, BOLD)}"
    body = [f"  {line}" for line in lines]
    return "\n".join(["", divider, header, ""] + body + [""])


def fit_ansi(text: str, width: int) -> str:
    visible = ANSI_RE.sub("", text)
    visible_width = display_width(visible)
    if visible_width > width:
        clipped = clip_display(visible, width)
        return clipped + " " * max(0, width - display_width(clipped))
    return text + " " * (width - visible_width)


def display_width(text: str) -> int:
    total = 0
    for char in text:
        if unicodedata.combining(char):
            continue
        total += 2 if unicodedata.east_asian_width(char) in {"F", "W"} else 1
    return total


def clip_display(text: str, width: int) -> str:
    if width <= 3:
        return "." * max(0, width)
    result: list[str] = []
    total = 0
    limit = width - 3
    for char in text:
        char_width = 2 if unicodedata.east_asian_width(char) in {"F", "W"} else 1
        if total + char_width > limit:
            break
        result.append(char)
        total += char_width
    return "".join(result) + "..."


def short(value: str, width: int) -> str:
    """레거시 호환."""
    return _short(value, width)
