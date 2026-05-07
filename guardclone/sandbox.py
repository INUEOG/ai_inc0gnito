from __future__ import annotations

import re
from pathlib import Path

from .models import SandboxEvent


NETWORK_RE = re.compile(r"\b(curl|wget|Invoke-WebRequest|iwr|fetch|axios|requests\.post|http://|https://)\b", re.I)
FILE_RE = re.compile(r"(\.aws|\.ssh|Login Data|Cookies|wallet\.dat|\.env|API_KEY|TOKEN)", re.I)
PROC_RE = re.compile(r"\b(sh|bash|python|node|powershell|pwsh|subprocess|child_process|os\.system)\b", re.I)


def infer_sandbox_events(root: Path, executable_files: list[Path]) -> list[SandboxEvent]:
    events: list[SandboxEvent] = []
    for path in executable_files:
        rel = path.relative_to(root).as_posix()
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for index, line in enumerate(lines, start=1):
            if FILE_RE.search(line):
                events.append(SandboxEvent("file-read", rel, index, "민감 파일 또는 환경변수 접근 시도", 12))
            if NETWORK_RE.search(line):
                events.append(SandboxEvent("network-attempt", rel, index, "외부 네트워크 연결 또는 전송 시도", 14))
            if PROC_RE.search(line):
                events.append(SandboxEvent("process-spawn", rel, index, "추가 프로세스 실행 시도", 8))
    return events
