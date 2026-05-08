from __future__ import annotations

import shutil
import subprocess
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlparse

from guardit.github_client import GitHubClient
from guardit.models import ScanReport
from guardit.reporter import render_json


def clean_clone(source: str, destination: Path, report: ScanReport, token: str | None = None) -> None:
    if destination.exists():
        raise FileExistsError(f"대상 경로가 이미 존재합니다: {destination}")
    risky = set(report.candidates)
    risky.update(item.file for item in report.evidence)
    if _is_github_url(source):
        _clean_clone_github(source, destination, report, risky, token)
    else:
        _copy_without_risky(Path(source).resolve(), destination, risky)
        _write_warning(destination, report)


def force_clone_or_copy(source: str, destination: Path) -> None:
    if destination.exists():
        raise FileExistsError(f"대상 경로가 이미 존재합니다: {destination}")
    if Path(source).exists():
        shutil.copytree(Path(source).resolve(), destination)
        return
    subprocess.run(["git", "clone", source, str(destination)], check=True)


def _clean_clone_github(source: str, destination: Path, report: ScanReport, risky: set[str], token: str | None) -> None:
    client = GitHubClient(token=token)
    ref = client.parse_repo_url(source)
    url = client.zipball_url(ref, report.metadata.default_branch or "main")
    with tempfile.TemporaryDirectory(prefix="guardit_zip_") as tmp:
        zip_path = Path(tmp) / "repo.zip"
        request = urllib.request.Request(url, headers=client._headers())  # noqa: SLF001 - header reuse is intentional.
        with urllib.request.urlopen(request, timeout=60) as response:
            zip_path.write_bytes(response.read())
        destination.mkdir(parents=True)
        with zipfile.ZipFile(zip_path) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                parts = Path(member.filename).parts
                rel = Path(*parts[1:]).as_posix() if len(parts) > 1 else member.filename
                if _is_risky(rel, risky):
                    continue
                target = destination / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
        _write_warning(destination, report)


def _copy_without_risky(source: Path, destination: Path, risky: set[str]) -> None:
    def ignore(directory: str, names: list[str]) -> set[str]:
        ignored: set[str] = set()
        base = Path(directory)
        for name in names:
            rel = (base / name).relative_to(source).as_posix()
            if _is_risky(rel, risky):
                ignored.add(name)
        return ignored

    shutil.copytree(source, destination, ignore=ignore)


def _is_risky(path: str, risky: set[str]) -> bool:
    normalized = path.rstrip("/")
    return normalized in risky or any(item.startswith(normalized + "/") for item in risky)


def _write_warning(destination: Path, report: ScanReport) -> None:
    (destination / "guardit-report.json").write_text(render_json(report), encoding="utf-8")
    (destination / "README_GUARDIT_WARNING.md").write_text(
        "# Guardit Clean Clone Warning\n\n"
        "이 폴더는 Guardit이 위험 후보 파일을 제외하고 생성한 clean clone 결과입니다.\n\n"
        "- zipball 기반 추출은 git history를 보존하지 않을 수 있습니다.\n"
        "- 제외된 파일과 근거는 `guardit-report.json`을 확인하세요.\n",
        encoding="utf-8",
    )


def _is_github_url(source: str) -> bool:
    parsed = urlparse(source)
    return parsed.scheme in {"http", "https"} and parsed.netloc in {"github.com", "www.github.com"}
