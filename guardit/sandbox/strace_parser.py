from __future__ import annotations

import re

from guardit.models import SandboxLog


PATH_RE = re.compile(r'"([^"]+)"')


def parse_strace(text: str, file_hint: str = "sandbox") -> list[SandboxLog]:
    logs: list[SandboxLog] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if ("open(" in line or "openat(" in line) and any(marker in line for marker in [".aws/credentials", ".ssh/id_rsa", ".env"]):
            logs.append(SandboxLog(file_hint, line_no, "dummy_credential_access", _first_path(line) or line.strip()[:220], 40, origin="observed", syscall=_syscall(line)))
        if any(syscall in line for syscall in ["connect(", "sendto("]):
            logs.append(SandboxLog(file_hint, line_no, "network_connect_attempt", line.strip()[:220], 35, origin="observed", syscall=_syscall(line)))
        if "execve(" in line:
            logs.append(SandboxLog(file_hint, line_no, "process_spawn", _first_path(line) or line.strip()[:220], 20, origin="observed", syscall="execve"))
        if ("read(" in line or "write(" in line) and any(marker in line for marker in ["FAKE_AWS_KEY", "FAKE_SSH_KEY", "FAKE_TOKEN"]):
            logs.append(SandboxLog(file_hint, line_no, "dummy_credential_io", line.strip()[:220], 20, origin="observed", syscall=_syscall(line)))
    return logs


def _first_path(line: str) -> str | None:
    match = PATH_RE.search(line)
    return match.group(1) if match else None


def _syscall(line: str) -> str | None:
    match = re.match(r"(?:\[[^\]]+\]\s*)?([a-zA-Z_][a-zA-Z0-9_]*)\(", line.strip())
    return match.group(1) if match else None
