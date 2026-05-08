from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

from .file_filter import looks_binary
from .models import AuthorTrust, CandidateFile, RepoFile, RepoMetadata, RepositoryRef


GITHUB_API = "https://api.github.com"


@dataclass
class GitHubClient:
    token: str | None = None
    timeout: int = 20

    def parse_repo_url(self, url: str) -> RepositoryRef:
        parsed = urllib.parse.urlparse(url)
        if parsed.netloc not in {"github.com", "www.github.com"}:
            raise ValueError("GitHub URL만 지원합니다.")
        parts = [part for part in parsed.path.strip("/").split("/") if part]
        if len(parts) < 2:
            raise ValueError("GitHub URL은 owner/repo 형식이어야 합니다.")
        owner, repo = parts[0], parts[1].removesuffix(".git")
        return RepositoryRef(owner=owner, repo=repo, url=f"https://github.com/{owner}/{repo}")

    def fetch_metadata(self, ref: RepositoryRef) -> RepoMetadata:
        repo_payload = self._get_json(f"/repos/{ref.owner}/{ref.repo}")
        owner_payload = self._get_json(f"/users/{ref.owner}")
        trust = self._score_author(repo_payload, owner_payload)
        return RepoMetadata(
            source=ref.url,
            owner=ref.owner,
            repo=ref.repo,
            default_branch=repo_payload.get("default_branch") or "main",
            stars=int(repo_payload.get("stargazers_count") or 0),
            forks=int(repo_payload.get("forks_count") or 0),
            created_at=repo_payload.get("created_at"),
            pushed_at=repo_payload.get("pushed_at"),
            owner_created_at=owner_payload.get("created_at"),
            owner_public_repos=int(owner_payload.get("public_repos") or 0),
            owner_followers=int(owner_payload.get("followers") or 0),
            author_trust=trust,
            collection_mode="github-api",
        )

    def fetch_tree(self, ref: RepositoryRef, branch: str) -> list[RepoFile]:
        payload = self._get_json(f"/repos/{ref.owner}/{ref.repo}/git/trees/{urllib.parse.quote(branch)}?recursive=1")
        if payload.get("truncated"):
            # GitHub truncates very large trees. The candidate filter still works on returned entries.
            pass
        files: list[RepoFile] = []
        for item in payload.get("tree", []):
            if item.get("type") != "blob":
                continue
            files.append(RepoFile(path=item["path"], size=int(item.get("size") or 0), sha=item.get("sha")))
        return files

    def fetch_blob(self, ref: RepositoryRef, file: RepoFile) -> CandidateFile | None:
        if not file.sha:
            return None
        payload = self._get_json(f"/repos/{ref.owner}/{ref.repo}/git/blobs/{file.sha}")
        if payload.get("encoding") != "base64":
            return None
        raw = base64.b64decode(str(payload.get("content", "")).encode("ascii"), validate=False)
        if looks_binary(raw):
            return None
        return CandidateFile(
            path=file.path,
            content=raw.decode("utf-8", errors="replace"),
            size=len(raw),
            sha=file.sha,
        )

    def zipball_url(self, ref: RepositoryRef, branch: str) -> str:
        return f"{GITHUB_API}/repos/{ref.owner}/{ref.repo}/zipball/{urllib.parse.quote(branch)}"

    def _get_json(self, path: str) -> dict:
        request = urllib.request.Request(f"{GITHUB_API}{path}", headers=self._headers())
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            raise RuntimeError(f"GitHub API HTTP {exc.code}: {detail}") from exc

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "guardit-preclone-scanner",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _score_author(self, repo_payload: dict, owner_payload: dict) -> AuthorTrust:
        score = 50
        signals: list[str] = []
        stars = int(repo_payload.get("stargazers_count") or 0)
        forks = int(repo_payload.get("forks_count") or 0)
        followers = int(owner_payload.get("followers") or 0)
        public_repos = int(owner_payload.get("public_repos") or 0)

        if stars >= 100:
            score += 12
            signals.append("스타 수 100개 이상")
        elif stars == 0:
            score -= 6
            signals.append("스타 수 0개")
        if forks >= 20:
            score += 6
            signals.append("포크 수 20개 이상")
        if followers <= 1:
            score -= 8
            signals.append("작성자 팔로워 1명 이하")
        elif followers >= 100:
            score += 8
            signals.append("작성자 팔로워 100명 이상")
        if public_repos <= 1:
            score -= 5
            signals.append("작성자 공개 레포 1개 이하")
        elif public_repos >= 10:
            score += 5
            signals.append("작성자 공개 레포 10개 이상")

        age = _days_since(owner_payload.get("created_at"))
        if age is not None and age <= 30:
            score -= 12
            signals.append("작성자 계정 생성 30일 이하")
        elif age is not None and age >= 365:
            score += 6
            signals.append("작성자 계정 생성 1년 이상")
        return AuthorTrust(score=max(0, min(100, score)), signals=signals or ["공개 GitHub 메타데이터 기반 기본 신뢰도"])


def _days_since(value: str | None) -> int | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - parsed).days
