from __future__ import annotations

from pathlib import PurePosixPath

from .models import RepoFile


EXACT_RISK_FILES = {
    ".vscode/tasks.json": "VSCode folderOpen 자동 실행 후보",
    ".vscode/launch.json": "IDE launch 설정 후보",
    ".devcontainer/devcontainer.json": "devcontainer lifecycle 후보",
    "package.json": "npm lifecycle script 후보",
    "setup.py": "Python setup 실행 후보",
    "pyproject.toml": "Python build 설정 후보",
    "Makefile": "make 자동화 후보",
    "makefile": "make 자동화 후보",
    "pre-commit-config.yaml": "pre-commit hook 후보",
}

PREFIX_RISK_FILES = {
    ".husky/": "Husky git hook 후보",
    ".githooks/": "custom git hook 후보",
}

SCRIPT_SUFFIXES = {".js", ".mjs", ".cjs", ".sh", ".bash", ".zsh", ".py"}
SCRIPT_DIRS = {"scripts"}


def is_candidate_path(path: str) -> tuple[bool, str]:
    normalized = path.replace("\\", "/").lstrip("/")
    if normalized in EXACT_RISK_FILES:
        return True, EXACT_RISK_FILES[normalized]
    for prefix, reason in PREFIX_RISK_FILES.items():
        if normalized.startswith(prefix) and not normalized.endswith("/"):
            return True, reason

    parts = PurePosixPath(normalized).parts
    if parts and parts[0] in SCRIPT_DIRS and PurePosixPath(normalized).suffix in SCRIPT_SUFFIXES:
        return True, "scripts 디렉터리 실행 스크립트 후보"

    filename = parts[-1] if parts else normalized
    if filename in {"install.sh", "setup.sh", "bootstrap.sh", "postinstall.sh", "preinstall.sh"}:
        return True, "설치/부트스트랩 스크립트 후보"
    return False, ""


def filter_candidate_files(files: list[RepoFile], max_file_bytes: int, max_candidates: int) -> list[RepoFile]:
    result: list[RepoFile] = []
    for file in files:
        matched, _ = is_candidate_path(file.path)
        if not matched:
            continue
        if file.size and file.size > max_file_bytes:
            continue
        result.append(file)
        if len(result) >= max_candidates:
            break
    return result


def looks_binary(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data[:4096]:
        return True
    sample = data[:4096]
    text_chars = sum(1 for byte in sample if byte in b"\n\r\t" or 32 <= byte <= 126 or byte >= 128)
    return text_chars / max(1, len(sample)) < 0.75
