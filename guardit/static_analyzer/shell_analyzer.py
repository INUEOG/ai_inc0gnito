from __future__ import annotations

import re

from guardit.models import CandidateFile, Evidence


READ_RE = re.compile(r"(cat|grep|awk|sed|read)\s+.*(\.aws|\.ssh|\.env|id_rsa|credentials)", re.I)
POST_RE = re.compile(r"(curl|wget)\b.*(--data|-d|--post-data|--method=POST|https?://)", re.I)
PIPE_EXEC_RE = re.compile(r"(curl|wget)\b.*\|\s*(sh|bash|python|node)", re.I)
SOURCE_ASSIGN_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=\$?\((cat|grep|awk|sed).*(\.aws|\.ssh|\.env|id_rsa|credentials).*\)", re.I)


def analyze_shell(candidate: CandidateFile) -> list[Evidence]:
    evidence: list[Evidence] = []
    source_vars: set[str] = set()
    for line_no, line in enumerate(candidate.content.splitlines(), start=1):
        if ".env.example" in line:
            continue
        assign = SOURCE_ASSIGN_RE.search(line)
        if assign:
            source_vars.add(assign.group(1))
            evidence.append(_ev(candidate.path, line_no, "sh_secret_source", "high", line.strip()[:220], 20, "secret_access", "Shell 변수에 민감 파일 내용이 저장됩니다."))
        if READ_RE.search(line):
            evidence.append(_ev(candidate.path, line_no, "sh_secret_access", "high", line.strip()[:220], 25, "secret_access", "Shell 명령으로 민감 파일을 읽습니다."))
        if POST_RE.search(line):
            evidence.append(_ev(candidate.path, line_no, "sh_external_sink", "high", line.strip()[:220], 25, "external_sink", "Shell에서 외부 전송 명령을 실행합니다."))
            if any(f"${name}" in line or name in line for name in source_vars):
                evidence.append(_ev(candidate.path, line_no, "source_to_sink", "critical", line.strip()[:220], 20, "data_flow", "민감정보 source 변수가 외부 전송 sink로 전달됩니다."))
        if PIPE_EXEC_RE.search(line):
            evidence.append(_ev(candidate.path, line_no, "remote_script_execution", "high", line.strip()[:220], 20, "remote_execution", "다운로드한 원격 스크립트를 즉시 실행합니다."))
    return evidence


def _ev(path: str, line: int, type_: str, severity: str, evidence: str, score: int, category: str, description: str) -> Evidence:
    return Evidence(path, line, type_, severity, evidence, score, category, description)
