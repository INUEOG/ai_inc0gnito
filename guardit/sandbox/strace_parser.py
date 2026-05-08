from __future__ import annotations

from guardit.models import SandboxLog


def parse_strace(text: str, file_hint: str = "sandbox") -> list[SandboxLog]:
    logs: list[SandboxLog] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if "openat(" in line and any(marker in line for marker in [".aws/credentials", ".ssh/id_rsa", ".env"]):
            logs.append(SandboxLog(file_hint, line_no, "dummy_credential_access", line.strip()[:220], 30))
        if any(syscall in line for syscall in ["connect(", "sendto("]):
            logs.append(SandboxLog(file_hint, line_no, "network_connect_attempt", line.strip()[:220], 25))
        if "execve(" in line:
            logs.append(SandboxLog(file_hint, line_no, "process_spawn", line.strip()[:220], 8))
    return logs
