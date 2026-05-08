# Guardit 3차 구현 보고서

## 요약

이번 구현은 기존 `sandbox-like` 구조를 실제 sandbox처럼 과장하지 않도록 정리하고, 선택 기능으로 Docker/strace 기반 observed evidence 수집을 추가했다. 기본값은 여전히 빠르고 안전한 `static`이다.

## 왜 static inference를 유지했는가

pre-clone 도구는 빠르게 판단해야 한다. 모든 레포에서 Docker를 실행하면 느리고, Docker daemon 권한과 image 준비가 필요하다. 따라서 기본은 정적 추정으로 유지했다.

## 왜 실제 sandbox를 옵션으로 만들었는가

실제 실행 관찰은 더 강한 근거가 되지만 비용과 위험이 있다. Docker/strace는 사용자가 명시적으로 `--sandbox docker`를 선택하거나 운영 환경에서 policy로 선택할 때 쓰는 기능으로 두는 것이 현실적이다.

## 왜 auto-run 단독을 차단하지 않는가

`runOn: folderOpen`, `postinstall`, devcontainer command는 정상 프로젝트에서도 사용된다. 자동 실행 단독으로 MALICIOUS 처리하면 오탐률이 높다. 대신 `WATCH`와 warning을 출력해 사용자가 검토하게 한다.

## 왜 warning 구조를 추가했는가

자동 실행은 위험 조합이 없더라도 사용자가 알아야 하는 신호다. warning은 차단과 구분되는 낮은 강도의 보안 메시지다.

## 왜 inferred와 observed를 분리했는가

정적 추정과 실제 strace 관찰은 신뢰도가 다르다. 같은 “credential access”라도 inferred는 가능성이고 observed는 sandbox 내부에서 관찰된 syscall이다. 리포트와 점수에서 이를 구분해야 과장 없이 설명할 수 있다.

## 모듈별 설명

### `guardit/config.py`

- 입력: 환경변수
- 처리: sandbox mode, timeout, image 설정
- 출력: `GuarditConfig`
- 한계: Docker image 자동 빌드는 하지 않는다.

### `guardit/cli.py`

- 입력: `--sandbox off|static|docker`
- 처리: scan/clone/eval에서 sandbox mode를 config에 반영
- 출력: sandbox mode가 반영된 분석 결과
- 한계: Docker 권한 문제 해결은 사용자 환경 설정에 맡긴다.

### `guardit/sandbox/docker_runner.py`

- 입력: 후보 파일, evidence, execution flow
- 처리: static inference 또는 Docker sandbox 실행
- 출력: `SandboxLog`, `SandboxSummary`
- 핵심: Docker unavailable/failure 시 fallback
- 한계: Docker image에 strace가 없으면 fallback된다.

### `guardit/sandbox/strace_parser.py`

- 입력: strace text
- 처리: `open/openat`, `connect/sendto`, `execve`, 일부 read/write 로그 파싱
- 출력: observed `SandboxLog`
- 한계: fd 기반 read/write taint tracking은 하지 않는다.

### `guardit/scoring/risk_score.py`

- 입력: evidence, sandbox logs
- 처리: inferred와 observed 가중치 분리
- 출력: 0~100 점수와 verdict
- 핵심: observed credential/network는 inferred보다 높은 가중치
- 한계: 휴리스틱 점수이며 대규모 데이터셋 보정이 필요하다.

### `guardit/reporter.py`

- 입력: `ScanReport`
- 처리: warnings, sandbox mode, fallback, inferred, observed 구분 출력
- 출력: 텍스트/JSON 리포트
- 한계: JSON schema versioning은 아직 없다.

## 실제 구현된 것

- `--sandbox off|static|docker`
- `StaticBehaviorAnalyzer`
- `DockerSandboxRunner`
- dummy HOME/credential 생성
- Docker 제한 옵션
- strace 로그 파싱
- inferred/observed 구분
- Docker fallback
- auto-run warning
- 테스트 10개

## 구현하지 않은 것

- production-grade malware sandbox
- 모든 파일 실행
- 실제 외부 네트워크 허용
- 실제 credential 사용
- Docker image 자동 빌드
- 완전한 동적 taint tracking

## 현재 한계

Docker sandbox는 환경 의존성이 있다. Docker daemon 권한이 없거나 `guardit-sandbox:latest` image가 없으면 fallback된다. 이 fallback은 의도된 안전 동작이다.
