from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path

from .analyzer import scan_profile
from .collector import collect_source
from .demo import create_demo_repos
from .evaluator import evaluate_dataset
from .reporter import render_json, render_text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardclone", description="clone 전 GitHub 개인정보 탈취 위험 검사 CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="로컬 경로 또는 GitHub URL 검사")
    scan.add_argument("source", help="검사할 로컬 경로 또는 GitHub URL")
    scan.add_argument("--json", action="store_true", help="JSON 리포트 출력")

    clone = sub.add_parser("clone", help="검사 후 정책에 따라 clone 또는 격리 clone 수행")
    clone.add_argument("source", help="clone할 로컬 경로 또는 GitHub URL")
    clone.add_argument("destination", help="결과를 받을 폴더")
    clone.add_argument(
        "--choice",
        choices=["auto", "block", "clean", "force"],
        default="auto",
        help="auto는 판정에 따라 차단/격리/진행을 자동 선택",
    )
    clone.add_argument("--json", action="store_true", help="JSON 리포트 출력")

    demo = sub.add_parser("demo", help="심사용 데모 레포지토리 생성")
    demo.add_argument("--base", default=".", help="데모 폴더를 만들 위치")

    eval_cmd = sub.add_parser("eval", help="라벨이 있는 데이터셋으로 정량 지표 평가")
    eval_cmd.add_argument("dataset", help="labels.json이 있는 데이터셋 경로")

    args = parser.parse_args(argv)

    if args.command == "demo":
        root = create_demo_repos(Path(args.base).resolve())
        print(f"데모 데이터셋 생성 완료: {root}")
        print(f"악성 시나리오 검사: py -m guardclone scan {root / 'malicious_repo'}")
        print(f"지표 평가: py -m guardclone eval {root}")
        return 0

    if args.command == "scan":
        report = scan_profile(collect_source(args.source))
        print(render_json(report) if args.json else render_text(report))
        return 1 if report.verdict == "BLOCK" else 0

    if args.command == "clone":
        report = scan_profile(collect_source(args.source))
        action = _resolve_action(report.verdict, args.choice)
        if action == "block":
            print(render_json(report) if args.json else render_text(report))
            print("\n결과: 위험도가 높아 clone을 차단했습니다.")
            return 1
        destination = Path(args.destination).resolve()
        if action == "clean":
            _copy_without_risky_files(report.profile.local_path, destination, _risky_files(report))
            suffix = "위험 파일을 제외하고 격리 clone을 완료했습니다."
        else:
            _clone_or_copy(args.source, report.profile.local_path, destination)
            suffix = "검사 후 clone을 완료했습니다."
        print(render_json(report) if args.json else render_text(report))
        print(f"\n결과: {suffix}")
        print(f"위치: {destination}")
        return 0

    if args.command == "eval":
        result = evaluate_dataset(Path(args.dataset).resolve())
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    return 2


def _resolve_action(verdict: str, choice: str) -> str:
    if choice != "auto":
        return {"block": "block", "clean": "clean", "force": "force"}[choice]
    if verdict == "BLOCK":
        return "block"
    if verdict == "QUARANTINE":
        return "clean"
    return "force"


def _risky_files(report) -> set[str]:
    files = {finding.file for finding in report.findings}
    files.update(event.file for event in report.sandbox_events)
    return files


def _copy_without_risky_files(source: Path, destination: Path, risky_files: set[str]) -> None:
    if destination.exists():
        raise FileExistsError(f"대상 폴더가 이미 존재합니다: {destination}")

    def ignore(directory: str, names: list[str]) -> set[str]:
        ignored = set()
        base = Path(directory)
        for name in names:
            rel = (base / name).relative_to(source).as_posix()
            if rel in risky_files or any(item.startswith(rel.rstrip("/") + "/") for item in risky_files):
                ignored.add(name)
        return ignored

    shutil.copytree(source, destination, ignore=ignore)


def _clone_or_copy(original_source: str, collected_path: Path, destination: Path) -> None:
    if destination.exists():
        raise FileExistsError(f"대상 폴더가 이미 존재합니다: {destination}")
    if Path(original_source).exists():
        shutil.copytree(Path(original_source).resolve(), destination)
        return
    subprocess.run(["git", "clone", original_source, str(destination)], check=True)
