from __future__ import annotations

import re

from guardit.models import CandidateFile, Evidence


SOURCE_RE = re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+)")
SECRET_SOURCE_RE = re.compile(r"(fs\.readFileSync|fs\.readFile|process\.env|os\.homedir|path\.join).*(\.aws|\.ssh|\.env|TOKEN|SECRET|credentials|id_rsa)?", re.I)
SINK_RE = re.compile(r"\b(fetch|axios\.post|child_process\.(exec|spawn)|eval|Function)\b", re.I)
BASE64_RE = re.compile(r"(Buffer\.from|atob)\s*\(.+base64", re.I)


def analyze_javascript(candidate: CandidateFile) -> list[Evidence]:
    evidence: list[Evidence] = []
    source_vars: set[str] = set()
    lines = candidate.content.splitlines()

    for line_no, line in enumerate(lines, start=1):
        assign = SOURCE_RE.search(line)
        if assign and SECRET_SOURCE_RE.search(assign.group(2)):
            source_vars.add(assign.group(1))
            evidence.append(_ev(candidate.path, line_no, "js_secret_source", "high", line.strip()[:220], 20, "secret_access", "JavaScript에서 민감정보 source로 볼 수 있는 값을 변수에 저장합니다."))

        if re.search(r"\bfs\.(readFileSync|readFile)\b", line):
            score = 25 if re.search(r"(\.aws|\.ssh|\.env|credentials|id_rsa)", line, re.I) else 12
            evidence.append(_ev(candidate.path, line_no, "js_fs_read", "high", line.strip()[:220], score, "secret_access", "fs API로 로컬 파일을 읽습니다."))

        if re.search(r"\bprocess\.env\b", line):
            evidence.append(_ev(candidate.path, line_no, "js_env_access", "medium", line.strip()[:220], 12, "secret_access", "환경변수 접근은 token 수집에 사용될 수 있습니다."))

        if SINK_RE.search(line):
            if _localhost_only(line) and re.search(r"\b(fetch|axios\.post)\b", line):
                continue
            evidence.append(_ev(candidate.path, line_no, "js_sink", "high", line.strip()[:220], 15, "external_sink", "JavaScript sink 또는 동적 실행 API 호출입니다."))
            if _line_mentions_source(line, source_vars):
                evidence.append(_ev(candidate.path, line_no, "source_to_sink", "critical", line.strip()[:220], 20, "data_flow", "민감정보 source 변수가 외부 전송 또는 실행 sink로 전달됩니다."))

        if BASE64_RE.search(line):
            evidence.append(_ev(candidate.path, line_no, "base64_decode", "medium", line.strip()[:220], 10, "obfuscation", "base64 디코딩은 payload 은닉에 사용될 수 있습니다."))

    joined = "\n".join(lines)
    for var_name in source_vars:
        if re.search(rf"(fetch|axios\.post)\s*\([^)]*{re.escape(var_name)}", joined, re.S):
            evidence.append(_ev(candidate.path, 1, "source_to_sink", "critical", var_name, 20, "data_flow", "파일 전체 흐름에서 source 변수가 network sink로 전달됩니다."))
    return evidence


def _line_mentions_source(line: str, source_vars: set[str]) -> bool:
    return any(re.search(rf"\b{re.escape(name)}\b", line) for name in source_vars)


def _localhost_only(line: str) -> bool:
    urls = re.findall(r"https?://([^/\s'\"`:]+)", line, flags=re.I)
    return bool(urls) and all(host in {"localhost", "127.0.0.1", "0.0.0.0"} for host in urls)


def _ev(path: str, line: int, type_: str, severity: str, evidence: str, score: int, category: str, description: str) -> Evidence:
    return Evidence(path, line, type_, severity, evidence, score, category, description)
