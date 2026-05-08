from __future__ import annotations

import json
import re

from guardit.models import CandidateFile, Evidence
from guardit.static_analyzer.js_analyzer import analyze_javascript
from guardit.static_analyzer.python_analyzer import analyze_python
from guardit.static_analyzer.shell_analyzer import analyze_shell


SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("aws_credentials", "AWS credentials", re.compile(r"(\.aws[/\\]credentials|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)", re.I)),
    ("ssh_private_key", "SSH private key", re.compile(r"(\.ssh[/\\](id_rsa|id_ed25519)|BEGIN OPENSSH PRIVATE KEY)", re.I)),
    ("dotenv_access", ".env token", re.compile(r"(^|[^A-Za-z0-9_])\.env(?!\.example)([^A-Za-z0-9_]|$)|dotenv", re.I)),
    ("github_token", "GitHub token", re.compile(r"(GITHUB_TOKEN|ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]+)", re.I)),
    ("npm_token", "npm token", re.compile(r"(NPM_TOKEN|npm_[A-Za-z0-9_]+|//registry\.npmjs\.org/:_authToken)", re.I)),
    ("cloud_credentials", "cloud credential", re.compile(r"(GOOGLE_APPLICATION_CREDENTIALS|\.config[/\\]gcloud|AZURE_CLIENT_SECRET|client_secret|access_key)", re.I)),
    ("browser_credentials", "browser credential", re.compile(r"(Login Data|Local State|Cookies|Chrome[/\\]User Data|Edge[/\\]User Data)", re.I)),
    ("keychain_access", "keychain credential", re.compile(r"\b(security\s+find-generic-password|cmdkey|keyring|get-credential)\b", re.I)),
]

NETWORK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("external_post", re.compile(r"\b(curl|fetch|axios\.post|requests\.post|Invoke-RestMethod|Invoke-WebRequest)\b.*\b(POST|--data|-d|body\s*:|http://|https://)", re.I)),
    ("wget_transfer", re.compile(r"\bwget\b.*(http://|https://|--post-data|--method=POST)", re.I)),
    ("scp_transfer", re.compile(r"\bscp\b\s+.+:.+", re.I)),
    ("nc_transfer", re.compile(r"\b(nc|netcat)\b\s+[\w.-]+\s+\d+", re.I)),
    ("external_url", re.compile(r"https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^\s'\"`]+", re.I)),
    ("external_ip", re.compile(r"\b(?!(127|10|192\.168|172\.(1[6-9]|2\d|3[0-1]))\.)(\d{1,3}\.){3}\d{1,3}\b")),
]

DANGEROUS_EXEC_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("remote_script_execution", re.compile(r"\b(curl|wget)\b.+\|\s*(sh|bash|python|node)", re.I)),
    ("node_eval", re.compile(r"\bnode\s+-e\b", re.I)),
    ("bash_command", re.compile(r"\bbash\s+-c\b", re.I)),
    ("script_command_execution", re.compile(r"\b(node|python|python3|bash|sh|pwsh|powershell)\s+[\w./-]+\.(js|mjs|cjs|py|sh|ps1)\b", re.I)),
    ("dynamic_execution", re.compile(r"\b(eval|exec|Function|child_process|subprocess|os\.system)\b", re.I)),
    ("base64_execution", re.compile(r"(base64\s+-d|atob\(|Buffer\.from\(|b64decode).*?(eval|exec|sh|bash|node|python)?", re.I)),
    ("string_split_obfuscation", re.compile(r"(['\"]\.[a-z]+['\"]\s*\+\s*['\"]|join\(\s*['\"]\s*['\"]\s*\)|path\.join|os\.path\.join)", re.I)),
]


def analyze_candidate(candidate: CandidateFile) -> list[Evidence]:
    evidence: list[Evidence] = []
    evidence.extend(_analyze_special_files(candidate))
    evidence.extend(_analyze_lines(candidate))

    suffix = _suffix(candidate.path)
    if suffix in {".js", ".mjs", ".cjs"}:
        evidence.extend(analyze_javascript(candidate))
    elif suffix == ".py" or candidate.path == "setup.py":
        evidence.extend(analyze_python(candidate))
    elif suffix in {".sh", ".bash", ".zsh"} or candidate.path.startswith((".husky/", ".githooks/")):
        evidence.extend(analyze_shell(candidate))
    return _dedupe(evidence)


def _analyze_special_files(candidate: CandidateFile) -> list[Evidence]:
    if candidate.path == ".vscode/tasks.json":
        return _analyze_tasks_json(candidate)
    if candidate.path == "package.json":
        return _analyze_package_json(candidate)
    return []


def _analyze_tasks_json(candidate: CandidateFile) -> list[Evidence]:
    evidence: list[Evidence] = []
    try:
        payload = json.loads(candidate.content)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        tasks = payload.get("tasks", [])
        if isinstance(tasks, list):
            for task in tasks:
                if not isinstance(task, dict):
                    continue
                run_options = task.get("runOptions", {})
                run_on = run_options.get("runOn") if isinstance(run_options, dict) else None
                if run_on == "folderOpen":
                    evidence.append(_ev(candidate.path, 1, "auto_trigger", "critical", "runOn: folderOpen", 20, "auto_trigger", "VSCode/Cursor에서 폴더를 열 때 자동 실행될 수 있습니다."))
                command = str(task.get("command", ""))
                if command:
                    evidence.extend(_scan_virtual_line(candidate.path, 1, command))
    else:
        for idx, line in enumerate(candidate.content.splitlines(), start=1):
            if re.search(r'"runOn"\s*:\s*"folderOpen"', line):
                evidence.append(_ev(candidate.path, idx, "auto_trigger", "critical", line.strip(), 20, "auto_trigger", "VSCode/Cursor folderOpen 자동 실행 트리거입니다."))
    return evidence


def _analyze_package_json(candidate: CandidateFile) -> list[Evidence]:
    evidence: list[Evidence] = []
    try:
        payload = json.loads(candidate.content)
    except json.JSONDecodeError:
        return evidence
    scripts = payload.get("scripts", {})
    if not isinstance(scripts, dict):
        return evidence
    for name, command in scripts.items():
        if name in {"preinstall", "install", "postinstall", "prepare"}:
            evidence.append(_ev(candidate.path, 1, "auto_trigger", "high", f"{name}: {command}", 20, "auto_trigger", "npm lifecycle에서 자동 실행될 수 있는 스크립트입니다."))
            evidence.extend(_scan_virtual_line(candidate.path, 1, str(command)))
    return evidence


def _analyze_lines(candidate: CandidateFile) -> list[Evidence]:
    evidence: list[Evidence] = []
    for idx, line in enumerate(candidate.content.splitlines(), start=1):
        evidence.extend(_scan_virtual_line(candidate.path, idx, line))
    if candidate.path.startswith((".husky/", ".githooks/")):
        evidence.append(_ev(candidate.path, 1, "auto_trigger", "medium", candidate.path, 15, "auto_trigger", "custom hook 경로의 실행 후보 파일입니다."))
    if candidate.path in {"Makefile", "makefile", "setup.py", "pyproject.toml", "pre-commit-config.yaml", ".devcontainer/devcontainer.json", ".vscode/launch.json"}:
        evidence.append(_ev(candidate.path, 1, "auto_trigger", "medium", candidate.path, 10, "auto_trigger", "개발 workflow에서 자동 또는 반자동 실행될 수 있는 파일입니다."))
    return evidence


def _scan_virtual_line(path: str, line_no: int, line: str) -> list[Evidence]:
    result: list[Evidence] = []
    stripped = line.strip()
    for evidence_type, label, pattern in SECRET_PATTERNS:
        if pattern.search(line):
            result.append(_ev(path, line_no, "secret_file_access", "high", stripped[:220], 25, "secret_access", f"{label} 접근 정황입니다."))
    for evidence_type, pattern in NETWORK_PATTERNS:
        if pattern.search(line):
            if _localhost_only(line):
                continue
            score = 25 if evidence_type in {"external_post", "wget_transfer"} else 15
            result.append(_ev(path, line_no, evidence_type, "high", stripped[:220], score, "external_sink", "외부 전송 또는 외부 endpoint 접근 정황입니다."))
    for evidence_type, pattern in DANGEROUS_EXEC_PATTERNS:
        if pattern.search(line):
            score = 20 if evidence_type == "remote_script_execution" else 10
            if evidence_type in {"remote_script_execution", "script_command_execution"}:
                category = "remote_execution" if evidence_type == "remote_script_execution" else "process_execution"
            else:
                category = "obfuscation"
            result.append(_ev(path, line_no, evidence_type, "high", stripped[:220], score, category, "동적 실행, 난독화, 원격 스크립트 실행 패턴입니다."))
    return result


def _localhost_only(line: str) -> bool:
    urls = re.findall(r"https?://([^/\s'\"`:]+)", line, flags=re.I)
    return bool(urls) and all(host in {"localhost", "127.0.0.1", "0.0.0.0"} for host in urls)


def _ev(path: str, line: int, type_: str, severity: str, evidence: str, score: int, category: str, description: str) -> Evidence:
    return Evidence(path, line, type_, severity, evidence, score, category, description)


def _suffix(path: str) -> str:
    index = path.rfind(".")
    return path[index:] if index >= 0 else ""


def _dedupe(items: list[Evidence]) -> list[Evidence]:
    seen: set[tuple[str, int, str, str]] = set()
    result: list[Evidence] = []
    for item in items:
        key = (item.file, item.line, item.type, item.evidence)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result
