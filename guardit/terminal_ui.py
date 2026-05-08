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


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
FG_RED = "\033[31m"
FG_GREEN = "\033[32m"
FG_YELLOW = "\033[33m"
FG_BLUE = "\033[34m"
FG_MAGENTA = "\033[35m"
FG_CYAN = "\033[36m"
FG_WHITE = "\033[37m"
FG_BRIGHT_RED = "\033[91m"
FG_BRIGHT_BLACK = "\033[90m"
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def color(text: str, style: str) -> str:
    if os.environ.get("NO_COLOR"):
        return text
    return f"{style}{text}{RESET}"


def terminal_width() -> int:
    return max(82, min(118, shutil.get_terminal_size((100, 24)).columns))


@dataclass
class Step:
    index: int
    title: str


STEPS = [
    Step(1, "GitHub/로컬 정보 수집"),
    Step(2, "자동 실행 파일 탐지"),
    Step(3, "정적 개인정보 유출 분석"),
    Step(4, "샌드박스 행동 분석"),
    Step(5, "AI 보조 판단"),
]


class SecurityConsole:
    def __init__(self, stream=None) -> None:
        self.stream = stream or sys.stdout
        self._spinner_stop: threading.Event | None = None
        self._spinner_thread: threading.Thread | None = None
        self._spinner_label = ""

    def banner(self, source: str, mode: str) -> None:
        width = terminal_width()
        title = "GUARDIT AI SECURITY GATE"
        subtitle = "Pre-clone privacy exfiltration defense"
        lines = [
            color(title, f"{BOLD}{FG_CYAN}"),
            color(subtitle, FG_BRIGHT_BLACK),
            "",
            f"Target : {short(source, width - 12)}",
            f"Mode   : sandbox={mode}",
        ]
        self.print(panel("AI 기반 GitHub 레포지토리 사전 개인정보 유출 차단", lines, border=FG_CYAN))

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
            frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
            frame_index = 0
            while not stop.is_set():
                frame = color(frames[frame_index % len(frames)], FG_CYAN)
                label = color(self._spinner_label, BOLD)
                self.stream.write(f"\r{frame} {label} {color('analyzing...', FG_BRIGHT_BLACK)}")
                self.stream.flush()
                frame_index += 1
                time.sleep(0.08)

        self._spinner_thread = threading.Thread(target=spin, daemon=True)
        self._spinner_thread.start()

    def complete_step(self, index: int, title: str) -> None:
        self._stop_spinner(clear=True)
        self.print(f"{color('✓', FG_GREEN)} [{index}/5] {title} {color('complete', FG_BRIGHT_BLACK)}")

    def fail_step(self, index: int, title: str) -> None:
        self._stop_spinner(clear=True)
        self.print(f"{color('!', FG_RED)} [{index}/5] {title} {color('failed', FG_RED)}")

    def action_menu(self, report: ScanReport) -> None:
        recommendation = "Recommended" if report.score.risk_level in {"WATCH", "SUSPICIOUS", "MALICIOUS"} else ""
        cards = [
            f"[1] {color('Block Clone', FG_BRIGHT_RED)} {color(recommendation, FG_YELLOW) if recommendation else ''}\n"
            "    clone 전 차단하여 로컬 credential 노출을 방지합니다.",
            f"[2] {color('Clone Without Risky Files', FG_YELLOW)}\n"
            "    위험 후보 파일을 제외한 clean clone을 수행합니다.",
            f"[3] {color('Continue Anyway', FG_BRIGHT_BLACK)}\n"
            "    위험을 인지하고 원본 clone을 진행합니다.",
        ]
        self.print(panel("사용자 조치 선택", cards, border=FG_YELLOW))

    def action_result(self, title: str, lines: list[str], severity: RiskLevel | str = "SAFE") -> None:
        self.print("")
        self.print(panel(title, lines, border=level_color(str(severity))))

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


def render_security_report(report: ScanReport, output_path: str = "results/guardit-report.json") -> str:
    sections = [
        _repository_panel(report),
        _suspicious_files_panel(report),
        _evidence_panel(report),
        _sandbox_panel(report),
        _ai_panel(report),
        _final_panel(report, output_path),
    ]
    return "\n\n".join(section for section in sections if section)


def _repository_panel(report: ScanReport) -> str:
    trust = report.metadata.author_trust.score
    trust_style = FG_GREEN if trust >= 70 else FG_YELLOW if trust >= 40 else FG_RED
    lines = [
        f"Target             {short(report.metadata.source, terminal_width() - 30)}",
        f"Collection         {badge(report.metadata.collection_mode, FG_CYAN)}",
        f"Auto-run files     {badge(str(len(report.candidates)), FG_MAGENTA)}",
        f"Author trust       {bar(trust, 100, trust_style)} {color(str(trust) + '/100', trust_style)}",
    ]
    if report.metadata.author_trust.signals:
        lines.append("")
        lines.append(color("Trust signals", BOLD))
        lines.extend(f"- {signal}" for signal in report.metadata.author_trust.signals[:4])
    return panel("Repository Summary", lines, border=FG_CYAN)


def _suspicious_files_panel(report: ScanReport) -> str:
    if not report.candidates:
        return panel("Suspicious Files", [color("✓ 자동 실행 후보 파일 없음", FG_GREEN)], border=FG_GREEN)
    lines = []
    for candidate in report.candidates[:10]:
        lines.append(f"{color('!', FG_YELLOW)} {candidate.path} {color(str(candidate.size) + ' bytes', FG_BRIGHT_BLACK)}")
        lines.append(f"  {candidate.reason}")
    if len(report.candidates) > 10:
        lines.append(color(f"... {len(report.candidates) - 10}개 후보는 JSON 리포트에 저장됨", FG_BRIGHT_BLACK))
    return panel("Suspicious Files", lines, border=FG_YELLOW)


def _evidence_panel(report: ScanReport) -> str:
    if not report.evidence:
        return panel("Evidence", [color("✓ 위험 evidence 없음", FG_GREEN)], border=FG_GREEN)
    lines = []
    for item in sorted(report.evidence, key=lambda ev: ev.score, reverse=True)[:12]:
        lines.append(_format_evidence(item))
    if len(report.evidence) > 12:
        lines.append(color(f"... lower priority evidence {len(report.evidence) - 12}개 collapse됨. 전체는 JSON export 확인.", FG_BRIGHT_BLACK))
    if report.suspected_secrets:
        lines.append("")
        lines.append(color("Detected Privacy Targets", BOLD))
        lines.append(" ".join(secret_badge(item) for item in report.suspected_secrets))
    return panel("Evidence", lines, border=FG_MAGENTA)


def _sandbox_panel(report: ScanReport) -> str:
    summary = report.sandbox_summary
    lines = [
        f"Mode              {badge(summary.mode, FG_CYAN)}",
        f"Real sandbox      {badge('yes' if summary.is_real_sandbox else 'no', FG_GREEN if summary.is_real_sandbox else FG_BRIGHT_BLACK)}",
    ]
    if summary.fallback_reason:
        lines.append(f"Skip/Fallback     {color(summary.fallback_reason, FG_YELLOW)}")

    inferred = [log for log in report.sandbox_logs if log.origin == "inferred"]
    observed = [log for log in report.sandbox_logs if log.origin == "observed"]
    if inferred:
        lines.append("")
        lines.append(color("[Inferred]", f"{BOLD}{FG_YELLOW}"))
        lines.extend(_format_sandbox_log(log) for log in inferred[:8])
    if observed:
        lines.append("")
        lines.append(color("[Observed]", f"{BOLD}{FG_BRIGHT_RED}"))
        lines.extend(_format_sandbox_log(log) for log in observed[:8])
    if not inferred and not observed:
        lines.append(color("샌드박스 행동 로그 없음", FG_BRIGHT_BLACK))
    return panel("Sandbox Behavior", lines, border=FG_BLUE)


def _ai_panel(report: ScanReport) -> str:
    confidence = int(round(report.llm.confidence * 100))
    verdict_color = level_color(report.llm.verdict)
    lines = [
        f"Provider          {badge(report.llm.provider, FG_CYAN)}",
        f"Usage             {badge('used' if report.llm.used else 'fallback', FG_GREEN if report.llm.used else FG_YELLOW)}",
        f"AI Verdict        {badge(report.llm.verdict, verdict_color)}",
        f"Confidence        {bar(confidence, 100, verdict_color)} {color(str(confidence) + '%', verdict_color)}",
        f"Risk adjustment   {color(f'{report.llm.risk_adjustment:+d}', FG_YELLOW if report.llm.risk_adjustment else FG_BRIGHT_BLACK)}",
        "",
        color("Reason", BOLD),
    ]
    lines.extend(_reason_lines(report.llm.reason, report.llm.evidence))
    if report.llm.error:
        lines.append("")
        lines.append(color(f"LLM note: {report.llm.error}", FG_YELLOW))
    return panel("AI Security Analysis", lines, border=verdict_color)


def _final_panel(report: ScanReport, output_path: str) -> str:
    level = report.score.risk_level
    style = level_color(level)
    action = _recommended_action(report)
    lines = [
        f"Final Risk        {badge(level, style)}",
        f"Risk Score        {bar(report.score.final_score, 100, style)} {color(str(report.score.final_score) + '/100', style)}",
        f"Before LLM        {report.score.base_score}/100",
        f"Elapsed           {report.elapsed_ms:.2f}ms",
        f"JSON Export       {output_path}",
        "",
        color("Clone Gate Decision", BOLD),
        action,
    ]
    if report.score.notes:
        lines.append("")
        lines.append(color("Score drivers", BOLD))
        lines.extend(f"- {note}" for note in report.score.notes[:8])
    return panel("Final Risk Report", lines, border=style)


def panel(title: str, lines: list[str], border: str = FG_CYAN) -> str:
    width = terminal_width()
    inner = width - 4
    top = color("┌" + "─" * (width - 2) + "┐", border)
    header_text = f" {title} "
    header = color("│", border) + color(header_text.ljust(inner), BOLD) + color("│", border)
    separator = color("├" + "─" * (width - 2) + "┤", border)
    body = []
    for raw in lines:
        split_lines = str(raw).splitlines() or [""]
        for line in split_lines:
            body.append(color("│", border) + fit_ansi(line, inner) + color("│", border))
    bottom = color("└" + "─" * (width - 2) + "┘", border)
    return "\n".join([top, header, separator, *body, bottom])


def badge(text: str, style: str) -> str:
    return color(f"[ {text} ]", f"{BOLD}{style}")


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


def bar(value: int, total: int = 100, style: str = FG_GREEN, width: int = 24) -> str:
    value = max(0, min(total, int(value)))
    filled = int(round((value / total) * width)) if total else 0
    return color("█" * filled, style) + color("░" * (width - filled), FG_BRIGHT_BLACK)


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
    }.get(level, FG_CYAN)


def _format_evidence(item: Evidence) -> str:
    style = level_color(_severity_to_level(item.severity))
    return (
        f"{color('✓', style)} {item.file}:{item.line} "
        f"{badge(item.category, style)} {badge(item.type, FG_CYAN)} "
        f"{short(item.evidence, 58)}"
    )


def _format_sandbox_log(log: SandboxLog) -> str:
    style = FG_BRIGHT_RED if log.origin == "observed" else FG_YELLOW
    syscall = f" {badge(log.syscall, FG_BRIGHT_BLACK)}" if log.syscall else ""
    return f"- {log.file}:{log.line} {badge(log.action, style)}{syscall} {short(log.detail, 72)}"


def _severity_to_level(severity: str) -> str:
    return {"low": "SAFE", "medium": "WATCH", "high": "SUSPICIOUS", "critical": "MALICIOUS"}.get(severity, "WATCH")


def _reason_lines(reason: str, evidence: list[str]) -> list[str]:
    items = [item.strip(" -") for item in reason.replace("。", ".").split(".") if item.strip()]
    lines = [f"- {item}" for item in items[:4]] or ["- AI 판단 사유 없음"]
    lines.extend(f"- {item}" for item in evidence[:4])
    return lines


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
    return badge(label, FG_MAGENTA)


def _recommended_action(report: ScanReport) -> str:
    if report.score.risk_level == "MALICIOUS":
        return color("Block Clone recommended: 자동 실행 + 개인정보 탈취 흐름 차단", FG_BRIGHT_RED)
    if report.score.risk_level in {"WATCH", "SUSPICIOUS"}:
        return color("Clean Clone recommended: 위험 후보 파일 제외 후 검토", FG_YELLOW)
    return color("Proceed: clone 전 차단 조건 없음", FG_GREEN)


def short(value: str, width: int) -> str:
    return shorten(str(value).replace("\n", " "), width=max(10, width), placeholder="...")
