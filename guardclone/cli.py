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
from .llm import gemini_diagnostics
from .reporter import render_json, render_text


RISKY_VERDICTS = {"WARN", "QUARANTINE", "BLOCK"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardclone", description="clone 전 GitHub 개인정보 탈취 위험 검사 CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="로컬 경로 또는 GitHub URL 검사")
    scan.add_argument("source", help="검사할 로컬 경로 또는 GitHub URL")
    scan.add_argument("--json", action="store_true", help="JSON 리포트 출력")
    scan.add_argument("--ai", choices=["off", "auto", "gemini", "gemini-api"], default="gemini", help="LLM 판단 사용 방식")
    scan.add_argument("--gemini-model", default="gemini-2.5-flash", help="Gemini에서 사용할 모델")
    scan.add_argument("--gemini-command", help="Gemini CLI 실행 명령 직접 지정")

    clone = sub.add_parser("clone", help="검사 후 사용자 선택에 따라 clone 수행")
    clone.add_argument("source", help="clone할 로컬 경로 또는 GitHub URL")
    clone.add_argument("destination", help="결과를 받을 폴더")
    clone.add_argument(
        "--choice",
        choices=["ask", "auto", "block", "clean", "force"],
        default="ask",
        help="ask는 위험 판정 시 사용자에게 3가지 선택지를 묻습니다.",
    )
    clone.add_argument("--json", action="store_true", help="JSON 리포트 출력")
    clone.add_argument("--ai", choices=["off", "auto", "gemini", "gemini-api"], default="gemini", help="LLM 판단 사용 방식")
    clone.add_argument("--gemini-model", default="gemini-2.5-flash", help="Gemini에서 사용할 모델")
    clone.add_argument("--gemini-command", help="Gemini CLI 실행 명령 직접 지정")

    demo = sub.add_parser("demo", help="심사용 데모 레포지토리 생성")
    demo.add_argument("--base", default=".", help="데모 폴더를 만들 위치")

    eval_cmd = sub.add_parser("eval", help="라벨이 있는 데이터셋으로 정량 지표 평가")
    eval_cmd.add_argument("dataset", help="labels.json이 있는 데이터셋 경로")

    sub.add_parser("doctor", help="Gemini 연동 상태 진단")

    args = parser.parse_args(argv)

    if args.command == "demo":
        root = create_demo_repos(Path(args.base).resolve())
        print(f"데모 데이터셋 생성 완료: {root}")
        print(f"악성 시나리오 검사: py -m guardclone scan {root / 'malicious_repo'}")
        print(f"인터랙티브 clone 데모: py -m guardclone clone {root / 'suspicious_repo'} safe-copy")
        print(f"지표 평가: py -m guardclone eval {root}")
        return 0

    if args.command == "scan":
        report = _scan(args)
        print(render_json(report) if args.json else render_text(report))
        return 1 if report.verdict == "BLOCK" else 0

    if args.command == "clone":
        report = _scan(args)
        print(render_json(report) if args.json else render_text(report))
        action = _resolve_action(report.verdict, args.choice)
        return _perform_clone_action(args.source, args.destination, report, action)

    if args.command == "doctor":
        return _print_doctor()

    if args.command == "eval":
        result = evaluate_dataset(Path(args.dataset).resolve())
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    return 2


def _scan(args):
    return scan_profile(
        collect_source(args.source),
        ai_provider=args.ai,
        ai_model=args.gemini_model,
        gemini_command=args.gemini_command,
    )


def _print_doctor() -> int:
    diagnostics = gemini_diagnostics()
    print("GuardClone Gemini 진단")
    print("======================")
    print(f"gemini PATH 감지: {diagnostics['gemini_on_path'] or '없음'}")
    print(f"npx PATH 감지: {diagnostics['npx_on_path'] or '없음'}")
    print(f"GEMINI_API_KEY 설정: {'예' if diagnostics['gemini_api_key_set'] else '아니오'}")
    print(f"GOOGLE_API_KEY 설정: {'예' if diagnostics['google_api_key_set'] else '아니오'}")
    print(f"GUARDCLONE_GEMINI_CMD: {diagnostics['guardclone_gemini_cmd'] or '없음'}")
    print(f"GuardClone이 사용할 명령: {diagnostics['gemini_command'] or '없음'}")
    print(f"우선 사용할 LLM 경로: {diagnostics['preferred_llm_path']}")
    if diagnostics["gemini_api_key_set"] or diagnostics["google_api_key_set"]:
        print("\n상태: Gemini API를 직접 호출할 준비가 되어 있습니다.")
        return 0
    if diagnostics["gemini_command"]:
        print("\n상태: Gemini CLI를 호출할 준비가 되어 있습니다.")
        return 0
    print("\n상태: Gemini를 찾지 못했습니다.")
    print("설치: npm install -g @google/gemini-cli")
    print("인증: gemini 실행 후 Google 로그인 또는 GEMINI_API_KEY 설정")
    print('대안: py -m guardclone scan <repo> --gemini-command "npx -y @google/gemini-cli"')
    return 1


def _resolve_action(verdict: str, choice: str) -> str:
    if choice == "ask":
        if verdict in RISKY_VERDICTS:
            return _ask_user_action(verdict)
        return "force"
    if choice == "auto":
        if verdict == "BLOCK":
            return "block"
        if verdict in {"WARN", "QUARANTINE"}:
            return "clean"
        return "force"
    return {"block": "block", "clean": "clean", "force": "force"}[choice]


def _ask_user_action(verdict: str) -> str:
    print("\n위험이 감지되었습니다.")
    print(f"현재 판정: {verdict}")
    print("원하는 조치를 선택하세요.")
    print("1. clone 차단")
    print("2. 위험 파일 제외 후 clone")
    print("3. 위험 감수 후 진행")

    while True:
        selected = input("> ").strip()
        if selected == "1":
            return "block"
        if selected == "2":
            return "clean"
        if selected == "3":
            return "force"
        print("1, 2, 3 중 하나를 입력하세요.")


def _perform_clone_action(source: str, destination: str, report, action: str) -> int:
    if action == "block":
        print("\n결과: 위험도가 높아 clone을 차단했습니다.")
        return 1

    target = Path(destination).resolve()
    try:
        if action == "clean":
            _copy_without_risky_files(report.profile.local_path, target, _risky_files(report))
            suffix = "위험 파일을 제외하고 격리 clone을 완료했습니다."
        else:
            _clone_or_copy(source, report.profile.local_path, target)
            suffix = "검사 후 clone을 완료했습니다."
    except FileExistsError as exc:
        print(f"\n결과: 실패 - {exc}")
        return 1

    print(f"\n결과: {suffix}")
    print(f"위치: {target}")
    return 0


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
