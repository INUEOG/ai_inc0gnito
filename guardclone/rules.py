from __future__ import annotations

import re
from dataclasses import dataclass


AUTO_EXEC_PATTERNS = (
    ".vscode/tasks.json",
    ".vscode/launch.json",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Makefile",
    "makefile",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".git/hooks/",
    ".husky/",
    "scripts/",
)

SCRIPT_SUFFIXES = {".sh", ".bash", ".zsh", ".ps1", ".py", ".js", ".mjs", ".cjs", ".ts"}

SENSITIVE_TARGETS = {
    "AWS credentials": [r"\.aws[/\\]credentials", r"\.aws[/\\]config", r"AWS_ACCESS_KEY_ID"],
    "SSH keys": [r"\.ssh[/\\]id_rsa", r"\.ssh[/\\]id_ed25519", r"\.ssh[/\\]config"],
    "GitHub tokens": [r"GITHUB_TOKEN", r"ghp_[A-Za-z0-9_]{20,}", r"\.config[/\\]gh"],
    "Browser passwords": [r"Login Data", r"Local State", r"Cookies", r"Chrome[/\\]User Data", r"Edge[/\\]User Data"],
    "Crypto wallets": [r"wallet\.dat", r"metamask", r"Electrum", r"Exodus"],
    "Environment secrets": [r"\.env", r"SECRET_KEY", r"API_KEY", r"TOKEN"],
}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    category: str
    severity: int
    pattern: re.Pattern[str]
    description: str


RULES = [
    Rule(
        "NET001",
        "외부 서버로 데이터 전송",
        "network",
        25,
        re.compile(r"\b(curl|wget|Invoke-WebRequest|iwr|fetch|axios|requests\.post)\b.*\b(POST|--data|-d|upload|http)", re.I),
        "외부 주소로 데이터를 전송하는 명령이 포함되어 있습니다.",
    ),
    Rule(
        "NET002",
        "원격 스크립트 즉시 실행",
        "network",
        22,
        re.compile(r"(curl|wget|iwr|Invoke-WebRequest).*(\||;).*(sh|bash|python|powershell|pwsh|node)", re.I),
        "다운로드한 원격 코드를 즉시 실행하는 패턴입니다.",
    ),
    Rule(
        "FS001",
        "민감 파일 경로 접근",
        "filesystem",
        24,
        re.compile(r"(\~|%USERPROFILE%|\$HOME|/home/|C:\\Users).*(\.aws|\.ssh|Login Data|Cookies|wallet\.dat|\.env)", re.I),
        "사용자 홈 디렉터리의 민감 정보 경로에 접근합니다.",
    ),
    Rule(
        "OBF001",
        "난독화 또는 동적 실행",
        "obfuscation",
        18,
        re.compile(r"\b(eval|exec|Function|fromCharCode|base64\s+-d|b64decode|EncodedCommand)\b", re.I),
        "실행 의도를 숨기거나 문자열을 동적으로 실행할 수 있습니다.",
    ),
    Rule(
        "PROC001",
        "외부 프로세스 실행",
        "process",
        12,
        re.compile(r"\b(subprocess|child_process|os\.system|Start-Process|spawn|execFile)\b", re.I),
        "추가 프로세스를 실행해 분석 회피 또는 정보 수집을 할 수 있습니다.",
    ),
    Rule(
        "HOOK001",
        "Git hook 자동 실행 지점",
        "auto-exec",
        15,
        re.compile(r"(.+)", re.I),
        "Git hook은 clone 이후 개발 작업 중 자동 실행될 수 있습니다.",
    ),
    Rule(
        "PKG001",
        "패키지 설치/실행 스크립트",
        "auto-exec",
        16,
        re.compile(r'"(preinstall|postinstall|prepare|prestart|postinstall)"\s*:', re.I),
        "패키지 매니저 동작 중 자동 실행되는 스크립트입니다.",
    ),
]


def is_auto_exec_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    if any(normalized == pattern or normalized.startswith(pattern) for pattern in AUTO_EXEC_PATTERNS):
        return True
    filename = normalized.rsplit("/", 1)[-1].lower()
    script_like = any(normalized.endswith(suffix) for suffix in SCRIPT_SUFFIXES)
    likely_entrypoint = filename in {
        "install.sh",
        "setup.sh",
        "bootstrap.sh",
        "postinstall.sh",
        "preinstall.sh",
        "setup.ps1",
    }
    return script_like and likely_entrypoint
