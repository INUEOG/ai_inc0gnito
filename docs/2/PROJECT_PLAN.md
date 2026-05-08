# Guardit 2차 구현 계획서

## 프로젝트 목적

Guardit은 GitHub 레포지토리를 `git clone`하기 전에 자동 실행 파일과 스크립트를 선별 분석해, 개발자 로컬 환경의 AWS key, SSH key, `.env`, browser credential, 인증 토큰이 탈취될 가능성을 evidence 기반으로 판단하는 CLI 보안 도구다.

핵심 목적은 단순 악성코드 탐지가 아니라 “clone 이전 단계에서 개인정보 탈취 위험을 차단하는 것”이다. 사용자는 분석 결과에 따라 clone 차단, 위험 파일 제외 후 clone, 위험 감수 진행을 선택할 수 있어야 한다.

## 문제 정의

개발자는 외부 레포를 clone한 뒤 IDE로 열거나 `npm install`, `make`, hook 도구를 실행한다. 공격자는 이 흐름에 `.vscode/tasks.json`, `package.json`, `setup.py`, `.husky/*`, `scripts/*.sh` 같은 자동 실행 또는 반자동 실행 지점을 넣고, 홈 디렉터리의 credential을 읽어 외부 서버로 보낼 수 있다.

기존 백신이나 SAST는 개별 위험 문자열 탐지에는 강하지만 “자동 실행 → 민감정보 접근 → 외부 전송”이라는 개발자 공급망 공격 흐름을 clone 이전 UX로 연결하는 데 한계가 있다.

## 서비스 핵심 흐름

1. CLI에서 `guardit scan <repo>` 또는 `guardit clone <repo>` 입력
2. GitHub URL이면 metadata와 recursive tree를 GitHub API로 수집
3. 전체 clone 없이 위험 후보 파일만 선별
4. 후보 blob만 다운로드
5. 후보가 없으면 빠른 SAFE 판정
6. 후보가 있으면 정규식, 경량 AST/source-to-sink, sandbox-like 분석 수행
7. repo/user 신뢰도는 보조 신호로만 반영
8. evidence 조합으로 0~100 위험 점수 계산
9. LLM 또는 fallback은 evidence 해석과 reason 생성만 보조
10. 결과 리포트 출력 및 JSON/Markdown 저장
11. clone 차단, clean clone, allow-risk clone 처리

## 현재 구현 상태

- CLI 진입점: `guardit/cli.py`, `python -m guardit`와 `guardit` entrypoint 구조가 있다.
- 명령어: `scan`, `clone`, `eval`, `doctor`가 구현되어 있다.
- GitHub 수집: `github_client.py`가 repo URL 파싱, metadata, owner metadata, tree, blob, zipball URL을 처리한다.
- 위험 파일 필터: `file_filter.py`가 `.vscode/tasks.json`, `package.json`, `.husky/*`, `.githooks/*`, `scripts/*.js|*.py|*.sh` 등을 선별한다.
- 정적 분석: `static_analyzer/regex_rules.py`, `js_analyzer.py`, `python_analyzer.py`, `shell_analyzer.py`가 evidence를 생성한다.
- sandbox-like: `sandbox/docker_runner.py`가 실제 실행 없이 dummy credential 접근, 네트워크 시도, 프로세스 실행을 추정한다.
- LLM/fallback: `ai/llm_judge.py`가 OpenAI 선택 연동과 offline fallback을 제공한다.
- risk score: `scoring/risk_score.py`가 점수와 판정을 계산한다.
- reporter: `reporter.py`가 텍스트/JSON 리포트를 생성한다.
- safe clone: `clone/safe_clone.py`가 GitHub zipball 또는 로컬 copy에서 위험 파일을 제외한다.
- 테스트/데이터셋: `tests/`와 `demo_repos`가 있으나 데이터셋은 3개 샘플 중심이라 객관성 평가용으로 부족하다.

## 추가 구현 목표

1. `/docs/2` 문서 세트 작성
2. CLI 옵션 개선: `--output`, `--llm`, `--threshold`, `--clean-clone`, `--allow-risk`, `report`
3. 후보 파일 정보를 path 문자열이 아니라 reason 포함 객체로 리포트
4. 자동 실행 파일에서 호출하는 script 경로 추적
5. 실행 흐름 리포트 추가: trigger → script → secret/source → sink
6. sandbox-like 로그를 요약 구조로 추가: opened_files, network_attempts, executed_processes, dummy_credentials_accessed
7. 점수 체계를 0~29 SAFE, 30~69 SUSPICIOUS, 70~100 MALICIOUS 기준으로 단순화
8. 평가 데이터셋을 benign/suspicious/malicious 각 5개 이상으로 확장
9. eval 결과에 TPR, FPR, precision, recall, confusion matrix, evidence count, 처리 시간 저장
10. `results/eval_result.json`, `results/eval_report.md` 생성
11. README와 구현 보고서에 LLM 보조 역할과 한계를 명확히 문서화

## 구현 우선순위

1. 심사 지표 객관성: 데이터셋 확장, confusion matrix, TPR/FPR, evidence count
2. 발표력: 실행 흐름과 위험 이유를 사람이 이해하기 쉽게 출력
3. 실제 사용성: CLI 옵션과 clean clone 흐름 개선
4. 현실성: 후보 파일 필터 후 필요한 파일에만 분석 수행
5. 확장성: Docker/strace, GitHub App, CI/CD, DLP 연동 지점을 문서화

## 심사 기준 대응 전략

- 구현 20점: scan → 판단 → 리포트 → clone 선택 흐름을 실제 CLI에서 동작시킨다.
- 지표 객관성 40점: 유리한 단일 수치가 아니라 confusion matrix, TPR/FPR, evidence count, 시간 지표, 한계를 함께 출력한다.
- 현실성 15점: 모든 파일을 LLM이나 Docker로 보내지 않고 위험 후보 파일에만 분석을 집중한다.
- 영향력 15점: 개인 개발자 보호에서 기업 DLP/GitHub App/CI 연동으로 확장 가능한 구조를 유지한다.
- 발표력 10점: 점수뿐 아니라 어떤 파일과 어떤 흐름 때문에 위험한지 evidence 기반으로 설명한다.

## 구현 범위

- public GitHub repo와 로컬 demo dataset 분석
- 위험 후보 파일 선별
- 정규식 기반 evidence 탐지
- JS/Python/Shell 경량 source-to-sink 분석
- tasks/package에서 실행 script 경로 추적
- sandbox-like 행동 추정
- LLM optional fallback
- safe clone
- 정량 평가 리포트

## 구현하지 않을 범위

- 실제 악성코드 실행
- 사용자 홈 디렉터리 실제 credential 접근
- 모든 파일에 대한 AST 분석
- 모든 레포 Docker 실행
- private repo 권한 UX 완성
- production-grade malware sandbox
- 악성 여부를 LLM 단독으로 결정하는 구조

## 기술 선택 이유

Python 표준 라이브러리 중심으로 구현한다. CLI, GitHub API 호출, zipball 처리, JSON/Markdown 리포트, 경량 분석은 외부 의존성 없이 구현 가능하다. 이는 데모와 심사 환경에서 설치 실패 가능성을 줄이고, LLM API key가 없어도 핵심 기능이 동작하게 만든다.

GitHub API tree/blob 방식은 전체 clone보다 pre-clone 목적에 맞다. 위험 후보 파일만 다운로드하면 대형 레포 비용과 시간을 줄일 수 있다.

Evidence 기반 구조는 오탐과 한계를 설명할 수 있게 한다. 점수만 출력하면 왜 차단됐는지 설득하기 어렵고, LLM 설명만 쓰면 재현성과 개인정보 보호가 약해진다.

Sandbox-like 방식은 MVP에서 실제 실행 위험을 피하기 위한 절충이다. 실제 Docker/strace는 향후 확장하되, 현재는 “추정 로그”임을 명확히 표시한다.

## 현실성과 구현 난이도 고려 사항

source-to-sink 분석은 완전한 프로그램 분석이 아니라 경량 추적이다. 단일 파일과 단순 변수 전달, 자동 실행 파일에서 호출한 script 연결을 우선한다. 여러 파일에 분산된 고도 난독화 payload는 한계로 문서화한다.

정상 프로젝트도 curl, env, script를 사용할 수 있으므로 단일 패턴으로 MALICIOUS를 만들지 않는다. 최소 차단 조건은 자동 실행, 민감정보 접근, 외부 전송 또는 명령 실행의 결합이다.

LLM은 API 비용과 개인정보 전송 위험이 있으므로 기본 off이며, 입력 전 마스킹하고 `risk_adjustment` 범위를 제한한다.
