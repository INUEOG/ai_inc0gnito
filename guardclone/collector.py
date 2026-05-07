from __future__ import annotations

import json
import shutil
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .models import RepoProfile


def collect_source(source: str) -> RepoProfile:
    path = Path(source)
    if path.exists():
        return RepoProfile(source=source, local_path=path.resolve(), author_trust_score=65, author_signals=["로컬 경로 분석"])

    if "github.com" in source:
        temp_dir = Path(tempfile.mkdtemp(prefix="guardclone_"))
        try:
            return _collect_github_archive(source, temp_dir)
        except Exception as exc:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise RuntimeError(f"GitHub 레포지토리를 가져오지 못했습니다: {exc}") from exc

    raise FileNotFoundError(f"분석할 경로나 GitHub URL을 찾을 수 없습니다: {source}")


def _collect_github_archive(source: str, temp_dir: Path) -> RepoProfile:
    parsed = urlparse(source)
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        raise ValueError("GitHub URL은 owner/repo 형식이어야 합니다.")

    owner, repo = parts[0], parts[1].removesuffix(".git")
    api = f"https://api.github.com/repos/{owner}/{repo}"
    with urllib.request.urlopen(api, timeout=15) as response:
        metadata = json.loads(response.read().decode("utf-8"))

    branch = metadata.get("default_branch", "main")
    archive_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
    zip_path = temp_dir / "repo.zip"
    urllib.request.urlretrieve(archive_url, zip_path)
    shutil.unpack_archive(zip_path, temp_dir)
    roots = [p for p in temp_dir.iterdir() if p.is_dir()]
    if not roots:
        raise RuntimeError("압축 해제된 레포지토리 폴더를 찾지 못했습니다.")

    owner_metadata = _fetch_json(f"https://api.github.com/users/{owner}")
    trust, signals = _score_github_author(metadata, owner_metadata)
    return RepoProfile(source=source, local_path=roots[0], author_trust_score=trust, author_signals=signals)


def _fetch_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def _score_github_author(metadata: dict, owner_metadata: dict | None = None) -> tuple[int, list[str]]:
    score = 50
    signals: list[str] = []

    stargazers = int(metadata.get("stargazers_count") or 0)
    forks = int(metadata.get("forks_count") or 0)
    open_issues = int(metadata.get("open_issues_count") or 0)
    watchers = int(metadata.get("watchers_count") or 0)

    if stargazers >= 100:
        score += 15
        signals.append("스타 수 100개 이상")
    elif stargazers == 0:
        score -= 8
        signals.append("스타 수 0개")

    if forks >= 20:
        score += 8
        signals.append("포크 수 20개 이상")
    if watchers == 0:
        score -= 5
        signals.append("감시자 수 0개")
    if open_issues > stargazers + 20:
        score -= 7
        signals.append("이슈 수가 평판 대비 높음")
    if metadata.get("archived"):
        score -= 5
        signals.append("아카이브된 저장소")

    if owner_metadata:
        followers = int(owner_metadata.get("followers") or 0)
        public_repos = int(owner_metadata.get("public_repos") or 0)
        created_at = owner_metadata.get("created_at")

        if followers >= 100:
            score += 10
            signals.append("작성자 팔로워 100명 이상")
        elif followers <= 1:
            score -= 8
            signals.append("작성자 팔로워 1명 이하")

        if public_repos >= 10:
            score += 5
            signals.append("작성자 공개 레포 10개 이상")
        elif public_repos <= 1:
            score -= 5
            signals.append("작성자 공개 레포 1개 이하")

        account_age_days = _account_age_days(created_at)
        if account_age_days is not None:
            if account_age_days >= 365:
                score += 8
                signals.append("작성자 계정 생성 1년 이상")
            elif account_age_days <= 30:
                score -= 15
                signals.append("작성자 계정 생성 30일 이하")

    return max(0, min(100, score)), signals or ["공개 GitHub 메타데이터 기반 기본 신뢰도"]


def _account_age_days(created_at: str | None) -> int | None:
    if not created_at:
        return None
    try:
        created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - created).days
