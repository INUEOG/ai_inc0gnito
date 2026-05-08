# Guardit 2차 구현 보고서

## 요약

이번 구현은 Guardit을 “pre-clone 개인정보 탈취 위험 차단 CLI”로 설명 가능하게 만드는 데 집중했다. 단순히 점수를 출력하는 도구가 아니라, 어떤 자동 실행 파일이 어떤 script를 호출하고, 그 script가 어떤 민감정보에 접근하며, 어떤 외부 전송 또는 명령 실행으로 이어지는지 evidence와 흐름으로 보여준다.

## 왜 현재 구조를 선택했는가

Guardit은 GitHub API에서 tree를 먼저 받고 위험 후보 파일만 blob으로 다운로드한다. 전체 clone 후 분석하면 이미 신뢰하지 않는 코드가 로컬에 내려온 뒤이므로 pre-clone 서비스의 의미가 약해진다. 반대로 모든 파일을 분석하면 대형 레포에서 비용과 시간이 커진다. 따라서 후보 파일 필터링을 첫 단계로 두었다.

핵심 판단은 LLM이 아니라 evidence와 score가 담당한다. LLM은 Gemini API를 기본 보조 판단기로 사용하되, 비용, 개인정보 전송, 재현성 문제가 있으므로 fallback 판단으로도 서비스가 동작한다.

## 왜 evidence 기반 구조를 선택했는가

보안 도구가 “위험함”만 출력하면 사용자는 오탐인지 실제 위험인지 판단하기 어렵다. Guardit은 모든 탐지를 `Evidence` 객체로 만든다.

- 입력: 후보 파일 path, line, content
- 처리: 정규식/경량 AST/source-to-sink 분석
- 출력: file, line, type, severity, evidence, score, category, description

이 구조 덕분에 점수, 리포트, LLM 입력, 평가 지표가 같은 근거를 공유한다.

## 왜 LLM을 보조 판단기로 제한했는가

LLM은 코드 의도를 자연어로 요약하는 데 유용하지만, 모든 파일을 LLM에 보내면 비용과 개인정보 노출 위험이 커진다. 또한 같은 입력에서도 응답이 달라질 수 있다. Guardit은 LLM 없이도 파일 필터링, 정규식 탐지, source-to-sink 분석, scoring이 동작한다. LLM은 Gemini API 기반 evidence 해석, reason 생성, 제한된 `risk_adjustment`만 담당한다.

## 왜 sandbox-like 구조를 먼저 구현했는가

실제 Docker/strace sandbox는 구현 비용과 실행 위험이 있다. MVP에서는 악성코드를 실행하지 않고, 정적 evidence에서 “만약 실행된다면 어떤 파일 접근/네트워크/프로세스가 발생할 가능성이 있는지”를 구조화된 로그로 추정한다. 리포트에는 `sandbox-like-static-inference`로 명확히 표시해 실제 실행 로그처럼 과장하지 않는다.

## 왜 source-to-sink 분석이 필요한가

정상 프로젝트도 curl, fetch, env, script를 사용할 수 있다. 단일 패턴만으로 악성 판정을 내리면 오탐이 높아진다. Guardit은 다음 연결을 더 강하게 본다.

- 자동 실행 → script 실행
- 민감 파일 read → 외부 POST
- env token read → 외부 전송
- 난독화 해제 → 명령 실행

이 흐름이 있어야 MALICIOUS에 가까워진다.

## 왜 clean clone 기능이 필요한가

분석 도구가 차단만 제공하면 개발자가 업무를 위해 우회할 수 있다. clean clone은 위험 파일을 제외한 상태로 코드를 받아볼 수 있게 해 생산성과 보안을 절충한다. GitHub URL에서는 zipball을 받아 위험 후보 파일을 제외하고 압축 해제한다. 이 방식은 git history를 보존하지 못할 수 있어 warning 파일에 한계를 기록한다.

## 핵심 모듈별 설명

### `guardit/cli.py`

- 입력: CLI 인자
- 처리 흐름: scan/clone/eval/report/doctor 분기, 옵션 처리, 사용자 선택
- 출력: 터미널 결과, JSON/Markdown 리포트, clone 결과
- 핵심 로직: `--clean-clone`, `--allow-risk`, `--output`, `--llm`, `--threshold`, `report` 명령
- 한계점: interactive UX는 기본 터미널 입력 중심이며 TUI는 없다.

### `guardit/github_client.py`

- 입력: GitHub URL
- 처리 흐름: owner/repo 파싱, metadata 수집, owner metadata 수집, tree 수집, 후보 blob 다운로드
- 출력: `RepoMetadata`, `RepoFile`, `CandidateFile`
- 핵심 로직: 전체 clone 없이 tree/blob API 사용
- 한계점: GitHub API rate limit과 private repo 권한 UX는 환경변수 token 수준이다.

### `guardit/file_filter.py`

- 입력: 파일 tree
- 처리 흐름: 자동 실행 가능 파일과 scripts 파일 선별, 크기 제한, binary skip
- 출력: 위험 후보 파일 목록과 reason
- 핵심 로직: `.vscode`, `package.json`, `.devcontainer`, `.husky`, `.githooks`, `scripts/*` 우선
- 한계점: 후보 밖 파일에 숨어 있는 payload는 자동 실행 파일에서 참조되지 않으면 놓칠 수 있다.

### `guardit/static_analyzer/*`

- 입력: 후보 파일 content
- 처리 흐름: 정규식, JS/Python/Shell 경량 분석, source-to-sink evidence 생성
- 출력: `Evidence`
- 핵심 로직: 민감정보 접근, 외부 전송, 난독화, 동적 실행, 원격 스크립트 실행 탐지
- 한계점: 완전한 AST/CFG/데이터 흐름 분석은 아니며 고도 난독화는 한계가 있다.

### `guardit/flow.py`

- 입력: 후보 파일과 evidence
- 처리 흐름: tasks.json/package.json/shell에서 script reference 추출 후 관련 evidence 연결
- 출력: `ExecutionFlow`
- 핵심 로직: trigger → executed file → secret source → external sink 흐름 생성
- 한계점: 동적 문자열로 만든 파일명이나 여러 단계 import 체인은 제한적으로만 추적한다.

### `guardit/sandbox/docker_runner.py`

- 입력: 후보 파일과 evidence
- 처리 흐름: 실제 실행 없이 파일 접근, 네트워크 시도, 프로세스 실행을 추정
- 출력: `SandboxLog`, `SandboxSummary`
- 핵심 로직: opened_files, network_attempts, executed_processes, dummy_credentials_accessed
- 한계점: 실제 Docker/strace 결과가 아니라 sandbox-like 추정이다.

### `guardit/scoring/risk_score.py`

- 입력: metadata, evidence, sandbox logs, LLM judgement
- 처리 흐름: category별 점수 cap, 신뢰도 multiplier, 강제 MALICIOUS 규칙, LLM 보정 제한
- 출력: `ScoreBreakdown`
- 핵심 로직: 자동 실행 + 민감정보 접근 + 외부 전송/명령 실행이면 MALICIOUS
- 한계점: 점수는 MVP 기준의 휴리스틱이며 운영 전 대규모 데이터셋으로 보정해야 한다.

### `guardit/evaluation/metrics.py`

- 입력: `demo_repos/labels.json`
- 처리 흐름: 각 샘플 scan, expected/actual 비교, confusion matrix와 시간/evidence count 계산
- 출력: `results/eval_result.json`, `results/eval_report.md`
- 핵심 로직: accuracy, TPR, FPR, precision, recall, evidence count, p95 elapsed time
- 한계점: 현재 demo dataset은 교육용 mock 샘플이며 실제 성능 수치로 과장하면 안 된다.

## MVP 범위 선택 이유

MVP는 개발자 clone 흐름에서 실제로 자동 실행될 가능성이 높은 파일에 집중했다. 모든 파일 분석이나 실제 sandbox 실행보다, clone 이전에 빠르게 판단하고 사용자가 행동을 선택하게 하는 UX가 더 중요하다.

## 실제 구현과 향후 구현 구분

현재 구현됨:

- CLI scan/clone/eval/report
- GitHub API 기반 pre-clone 수집
- 후보 파일 필터링
- evidence 기반 정적 분석
- 경량 source-to-sink
- sandbox-like 추정
- LLM fallback
- clean clone
- 15개 demo dataset 평가

향후 구현 예정:

- 실제 Docker/strace sandbox 실행
- GitHub App 연동
- CI/CD policy gate
- private repo OAuth UX
- 더 정교한 JS AST 파서 연동
- 대규모 정상/악성 benchmark dataset
