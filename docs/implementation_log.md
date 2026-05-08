# Guardit 구현 로그

## 2026-05-08

### 1. docs 문서 초안 생성

요구사항에서 문서를 구현보다 먼저 작성하도록 명시했기 때문에 `docs/` 폴더와 핵심 설계 문서를 먼저 생성했다. 목적은 구현 중 의사결정이 흔들리지 않도록 “pre-clone”, “자동 실행 + 민감정보 접근 + 외부 전송”, “LLM 보조 역할”을 고정하는 것이다.

### 2. 기본 프로젝트 구조 생성

`guardit/` 패키지와 하위 모듈 디렉터리, `tests/fixtures`, `results`, `logs`를 생성했다. 기존 `guardclone` 구현은 참고 대상으로 두고, 요청된 구조에 맞춘 새 패키지로 구현한다.

### 3. CLI 기본 명령 구현

`python -m guardit scan`, `clone`, `eval`, `doctor`를 구현했다. clone 명령은 위험 판정 시 차단, 위험 파일 제외 clean clone, 위험 감수 진행의 3가지 선택지를 제공한다. 이 UX는 분석 결과가 단순 경고에 머물지 않고 clone 전 의사결정으로 이어지게 하기 위한 것이다.

### 4~7. GitHub 수집 및 후보 blob 다운로드

`github_client.py`에서 GitHub URL을 `owner/repo`로 파싱하고 repo metadata, owner metadata, recursive tree를 GitHub API로 수집한다. 전체 clone을 하지 않고 `file_filter.py`가 선별한 위험 후보 파일 blob만 다운로드한다. 대형 레포와 binary 파일은 크기 제한과 binary heuristic으로 줄인다.

### 8. 정규식 기반 evidence 탐지

`static_analyzer/regex_rules.py`는 모든 탐지 결과를 `Evidence` 객체로 만든다. 민감정보 접근, 외부 전송, 원격 스크립트 실행, 난독화, 자동 실행 트리거를 분리해 저장한다. 리포트와 점수화가 동일 evidence를 사용하도록 해 설명 가능성을 높였다.

### 9. 위험 점수 계산

`scoring/risk_score.py`는 0~100 점수와 `SAFE/WATCH/SUSPICIOUS/MALICIOUS` 판정을 계산한다. 작성자 신뢰도는 최대 +10 보조 점수로 제한하고, `자동 실행 + 민감정보 접근 + 외부 전송` 조합은 MALICIOUS 강제 규칙으로 반영했다.

### 10~13. 리포트, 전용 룰, JS/Python/Shell 분석

`reporter.py`는 터미널 출력과 `results/guardit-report.json` 저장을 담당한다. `package.json` lifecycle script와 `.vscode/tasks.json`의 `runOn: folderOpen`을 전용 룰로 탐지한다. JS/Python/Shell 분석기는 경량 source -> sink 흐름을 추적한다.

### 14. 샌드박스 skeleton

`sandbox/docker_runner.py`는 실제 악성 코드를 실행하지 않고 행동 추정 로그를 생성한다. Docker 확장을 위해 `--network=none`, `--read-only`, `--memory`, `--cpus`, `no-new-privileges` 보안 옵션을 별도 메서드로 노출했다.

### 15~16. LLM judge fallback 및 마스킹

`ai/llm_judge.py`는 OpenAI JSON 응답 구조를 붙일 수 있게 만들었고, API key가 없으면 offline fallback을 사용한다. `ai/redact.py`는 AWS key, GitHub token, npm token, private key, bearer token, password/secret 계열 문자열을 `[REDACTED]`로 치환한다.

### 17. safe clone 구현

GitHub URL은 zipball을 다운로드해 위험 파일을 제외하고 압축 해제한다. 로컬 fixture는 copytree ignore 방식으로 처리한다. 결과 폴더에는 `guardit-report.json`과 `README_GUARDIT_WARNING.md`를 생성해 history 미보존 한계를 알린다.

### 18~20. 데모, 평가, README 업데이트

`demo_repos/benign`, `suspicious`, `malicious`와 라벨 파일을 작성했다. `evaluation/metrics.py`는 accuracy, precision, recall, false positive/negative rate, 평균/p95 처리 시간을 계산하고 `results/evaluation-report.json`에 저장한다. README는 실행법과 한계를 현재 구현 기준으로 갱신했다.
