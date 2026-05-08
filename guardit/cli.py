from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .clone import clean_clone, force_clone_or_copy
from .config import load_config
from .evaluation import evaluate_dataset
from .reporter import render_json, render_saved_report, render_text, save_report
from .scanner import scan_source


RISKY_LEVELS = {"WATCH", "SUSPICIOUS", "MALICIOUS"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardit", description="GitHub 레포지토리 pre-clone 개인정보 탈취 위험 차단 CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="GitHub URL 또는 로컬 경로를 분석합니다.")
    scan.add_argument("source")
    scan.add_argument("--json", action="store_true", help="JSON만 출력합니다.")
    scan.add_argument("--output", default="results/guardit-report.json", help="분석 리포트 저장 경로")
    scan.add_argument("--llm", choices=["off", "openai"], default=None, help="LLM provider 단축 옵션")
    scan.add_argument("--llm-provider", choices=["off", "openai"], default=None)
    scan.add_argument("--llm-model", default=None)
    scan.add_argument("--threshold", type=int, default=70, help="위험 종료 코드 기준 점수")
    scan.add_argument("--sandbox", choices=["off", "static", "docker"], default=None, help="sandbox 분석 방식")

    clone = sub.add_parser("clone", help="분석 후 사용자 선택에 따라 clone을 진행합니다.")
    clone.add_argument("repo_url")
    clone.add_argument("destination", nargs="?", help="생략 시 레포 이름을 사용합니다.")
    clone.add_argument("--choice", choices=["ask", "block", "clean", "force", "auto"], default="ask")
    clone.add_argument("--clean-clone", action="store_true", help="위험 파일 제외 clean clone을 즉시 선택합니다.")
    clone.add_argument("--allow-risk", action="store_true", help="위험을 감수하고 clone을 진행합니다.")
    clone.add_argument("--output", default="results/guardit-report.json", help="분석 리포트 저장 경로")
    clone.add_argument("--llm", choices=["off", "openai"], default=None, help="LLM provider 단축 옵션")
    clone.add_argument("--llm-provider", choices=["off", "openai"], default=None)
    clone.add_argument("--llm-model", default=None)
    clone.add_argument("--threshold", type=int, default=70, help="auto 선택 시 차단 기준 점수")
    clone.add_argument("--sandbox", choices=["off", "static", "docker"], default=None, help="sandbox 분석 방식")

    eval_cmd = sub.add_parser("eval", help="라벨 기반 정량 평가를 실행합니다.")
    eval_cmd.add_argument("dataset", nargs="?", default="demo_repos")
    eval_cmd.add_argument("--output", default="results/eval_result.json", help="평가 JSON 저장 경로")
    eval_cmd.add_argument("--sandbox", choices=["off", "static", "docker"], default=None, help="평가 시 sandbox 분석 방식")

    report_cmd = sub.add_parser("report", help="저장된 JSON 리포트를 사람이 읽기 쉽게 출력합니다.")
    report_cmd.add_argument("result", nargs="?", default="results/guardit-report.json")

    sub.add_parser("doctor", help="환경 설정을 점검합니다.")

    args = parser.parse_args(argv)
    config = _config_from_args(args)

    if args.command == "scan":
        report = _run_scan(args.source, config, quiet=args.json)
        save_report(report, Path(args.output))
        print(render_json(report) if args.json else render_text(report))
        return 1 if report.score.final_score >= args.threshold else 0

    if args.command == "clone":
        report = _run_clone_scan(args.repo_url, config)
        save_report(report, Path(args.output))
        print(render_text(report))
        choice = _clone_choice_from_flags(args)
        action = _resolve_action(report.score.risk_level, choice, report.score.final_score, args.threshold)
        return _perform_action(args.repo_url, args.destination, action, report, config.github_token)

    if args.command == "eval":
        result = evaluate_dataset(Path(args.dataset).resolve(), Path(args.output), sandbox_mode=args.sandbox)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        print(f"평가 JSON: {args.output}")
        print("평가 Markdown: results/eval_report.md")
        return 0

    if args.command == "report":
        print(render_saved_report(Path(args.result)))
        return 0

    if args.command == "doctor":
        return _doctor(config)

    return 2


def _run_scan(source: str, config, quiet: bool = False) -> object:
    _progress("[1/5] GitHub/로컬 레포 정보 수집 시작", quiet)
    report = scan_source(source, config)
    _progress("[2/5] 자동 실행 후보 파일 탐지 완료", quiet)
    _progress("[3/5] 정적 분석 완료", quiet)
    _progress(f"[4/5] sandbox mode={config.sandbox_mode} 분석 완료", quiet)
    _progress("[5/5] AI 의도 분석 완료", quiet)
    return report


def _run_clone_scan(source: str, config) -> object:
    print(f"guardit clone {source}")
    return _run_scan(source, config)


def _progress(message: str, quiet: bool) -> None:
    print(message, file=sys.stderr if quiet else sys.stdout)


def _resolve_action(level: str, choice: str, score: int = 0, threshold: int = 70) -> str:
    if choice == "auto":
        if score >= threshold or level == "MALICIOUS":
            return "block"
        if level in RISKY_LEVELS:
            return "clean"
        return "force"
    if choice != "ask":
        return choice
    if level not in RISKY_LEVELS:
        return "force"
    print("")
    print("선택:")
    print("1. clone 차단")
    print("2. 위험 파일 제외 후 clean clone")
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


def _perform_action(source: str, destination: str | None, action: str, report, token: str | None) -> int:
    target = Path(destination or _default_destination(source)).resolve()
    if action == "block":
        print("")
        print("결과: clone을 차단했습니다.")
        return 1
    try:
        if action == "clean":
            clean_clone(source, target, report, token=token)
            print("")
            print("결과: 위험 파일 제외 후 clean clone을 완료했습니다.")
        else:
            force_clone_or_copy(source, target)
            print("")
            print("결과: 위험을 감수하고 clone/copy를 완료했습니다.")
    except Exception as exc:
        print(f"결과: 실패 - {exc}")
        return 1
    print(f"위치: {target}")
    return 0


def _default_destination(source: str) -> str:
    stripped = source.rstrip("/").removesuffix(".git")
    name = stripped.rsplit("/", 1)[-1] or "guardit-clone"
    return name


def _config_from_args(args):
    config = load_config()
    provider = getattr(args, "llm", None) or getattr(args, "llm_provider", None) or config.llm_provider
    model = getattr(args, "llm_model", None) or config.llm_model
    sandbox_mode = getattr(args, "sandbox", None) or config.sandbox_mode
    return config.__class__(
        max_candidate_files=config.max_candidate_files,
        max_file_bytes=config.max_file_bytes,
        sandbox_threshold=config.sandbox_threshold,
        sandbox_mode=sandbox_mode,
        sandbox_timeout_sec=config.sandbox_timeout_sec,
        sandbox_image=config.sandbox_image,
        results_dir=config.results_dir,
        logs_dir=config.logs_dir,
        github_token=config.github_token,
        llm_provider=provider,
        llm_model=model,
    )


def _clone_choice_from_flags(args) -> str:
    if args.clean_clone:
        return "clean"
    if args.allow_risk:
        return "force"
    return args.choice


def _doctor(config) -> int:
    print("Guardit 환경 점검")
    print("================")
    print(f"GITHUB_TOKEN 설정: {'예' if config.github_token else '아니오'}")
    print(f"LLM provider: {config.llm_provider}")
    print(f"LLM model: {config.llm_model}")
    print(f"Sandbox mode: {config.sandbox_mode}")
    print(f"Sandbox image: {config.sandbox_image}")
    print(f"Sandbox timeout: {config.sandbox_timeout_sec}s")
    print(f"max file bytes: {config.max_file_bytes}")
    print("OPENAI_API_KEY 설정 시 --llm-provider openai를 사용할 수 있습니다.")
    return 0
