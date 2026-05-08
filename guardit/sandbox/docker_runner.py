from __future__ import annotations

import re
from dataclasses import dataclass

from guardit.models import CandidateFile, Evidence, SandboxLog


SECRET_RE = re.compile(r"(\.aws[/\\]credentials|\.ssh[/\\]id_rsa|\.env|NPM_TOKEN|GITHUB_TOKEN|ghp_|github_pat_)", re.I)
NETWORK_RE = re.compile(r"(https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)|curl|wget|fetch|axios\.post|requests\.post|nc\s+)", re.I)
PROCESS_RE = re.compile(r"(child_process|subprocess|os\.system|bash\s+-c|node\s+-e|eval|exec)", re.I)


@dataclass
class SandboxRunner:
    """행동 추정 기반 sandbox skeleton.

    실제 Docker 실행은 향후 이 클래스에 추가한다. 기본 구현은 악성 코드를 실행하지 않고
    정적 evidence와 후보 파일 라인을 기반으로 dummy credential 접근/네트워크 시도를 추정한다.
    """

    network_none: bool = True
    read_only: bool = True
    memory_limit: str = "256m"
    cpu_limit: str = "0.5"

    def analyze(self, candidates: list[CandidateFile], evidence: list[Evidence]) -> list[SandboxLog]:
        logs: list[SandboxLog] = []
        for candidate in candidates:
            for line_no, line in enumerate(candidate.content.splitlines(), start=1):
                stripped = line.strip()
                if SECRET_RE.search(line):
                    logs.append(SandboxLog(candidate.path, line_no, "dummy_credential_access", stripped[:220], 30))
                if NETWORK_RE.search(line):
                    logs.append(SandboxLog(candidate.path, line_no, "network_connect_attempt", stripped[:220], 25))
                if PROCESS_RE.search(line):
                    logs.append(SandboxLog(candidate.path, line_no, "process_spawn", stripped[:220], 8))
        return _dedupe(logs)

    def docker_security_profile(self) -> list[str]:
        return [
            "--network=none",
            "--read-only",
            f"--memory={self.memory_limit}",
            f"--cpus={self.cpu_limit}",
            "--security-opt=no-new-privileges",
        ]


def _dedupe(logs: list[SandboxLog]) -> list[SandboxLog]:
    seen: set[tuple[str, int, str]] = set()
    result: list[SandboxLog] = []
    for log in logs:
        key = (log.file, log.line, log.action)
        if key in seen:
            continue
        seen.add(key)
        result.append(log)
    return result
