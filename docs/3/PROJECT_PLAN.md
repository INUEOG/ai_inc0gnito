# Guardit 3차 구현 계획서

## 목적

이번 작업의 목적은 기존 Guardit의 빠른 `static behavior inference` 구조를 유지하면서, 사용자가 명시적으로 요청하거나 위험도가 높은 경우 선택적으로 실제 Docker/strace 기반 sandbox를 실행할 수 있게 만드는 것이다. 동시에 자동 실행 단독 탐지를 `MALICIOUS`로 과장하지 않되, 사용자가 놓치지 않도록 warning으로 명확히 표시한다.

## 현재 sandbox-like 구조 분석

현재 `guardit/sandbox/docker_runner.py`의 `SandboxRunner`는 실제 Docker runner가 아니다. 후보 파일의 각 라인을 정규식으로 확인해 다음 로그를 추정한다.

- `dummy_credential_access`
- `network_connect_attempt`
- `process_spawn`

`models.py`의 `SandboxSummary.mode`도 `sandbox-like-static-inference`로 되어 있다. 즉 현재 구현은 악성코드를 실행하지 않고, 정적 evidence를 바탕으로 “실행된다면 이런 행동이 있을 수 있다”를 추정하는 구조다.

## 실제 Docker/strace sandbox와의 차이

static inference는 파일 내용을 읽고 패턴을 추정한다. 실제 Docker/strace sandbox는 격리된 컨테이너 안에서 제한된 명령을 실행하고, strace로 `openat`, `connect`, `execve`, `sendto` 같은 시스템콜을 관찰한다.

차이점:

- static inference: 빠르고 안전하지만 실제 실행 관찰이 아니다.
- Docker sandbox: 실제 실행 관찰에 가깝지만 Docker/strace 의존성, 실행 비용, timeout, 격리 실패 위험이 있다.

## 왜 기존 구조가 static behavior inference인가

현재 코드에는 컨테이너 실행, 임시 HOME 마운트, dummy credential 생성, strace 실행, timeout 종료가 없다. `docker_security_profile()`은 Docker 옵션 문자열을 반환할 뿐 실제 실행에 사용되지 않는다. 따라서 현재 구조를 “sandbox”라고 단독 표현하면 과장이다. 정확한 명칭은 `static behavior inference`다.

## 왜 실제 sandbox를 옵션 기능으로 구현하는가

모든 레포에서 Docker sandbox를 실행하면 느리고 운영 비용이 크다. 또한 실행 대상 선정이 잘못되면 악성코드를 불필요하게 실행하는 문제가 생긴다. Guardit의 기본 목표는 clone 이전에 빠르게 위험을 판단하는 것이므로 기본값은 static inference로 두고, 사용자가 `--sandbox docker`를 지정하거나 위험 점수가 threshold 이상일 때만 Docker sandbox를 선택적으로 실행한다.

## 자동 실행 단독 탐지 정책 분석

현재 자동 실행 단독은 낮은 점수로 끝날 수 있다. 예를 들어 `.vscode/tasks.json`에 `runOn: folderOpen`과 `echo hello`만 있으면 개인정보 접근이나 외부 전송이 없으므로 MALICIOUS가 아니다.

하지만 자동 실행은 개발자가 폴더를 열기만 해도 코드가 실행될 수 있다는 보안상 중요한 신호다. 따라서 `MALICIOUS`로 차단하지는 않되 `WATCH` 또는 warning으로 표시해야 한다.

## 왜 단순 auto-run만으로 MALICIOUS 판정하지 않는가

정상 프로젝트도 빌드, 테스트, devcontainer 초기화, 포맷터 실행을 위해 자동 실행 설정을 사용할 수 있다. 자동 실행 단독으로 차단하면 오탐률이 올라가고 개발자가 도구를 우회할 가능성이 커진다.

Guardit의 핵심 차단 조건은 다음 결합이다.

```text
자동 실행 + 민감정보 접근 + 외부 전송/명령 실행 = MALICIOUS
```

단순 auto-run은 warning, auto-run + 외부 POST 또는 민감정보 접근은 SUSPICIOUS, 세 조건이 결합되면 MALICIOUS로 둔다.

## 오탐률 문제

자동 실행, curl, env 접근은 정상 개발 환경에서도 흔하다. 따라서 단일 신호에 높은 점수를 주기보다 evidence 조합과 source-to-sink 흐름을 기준으로 점수를 높인다. 특히 Docker observed evidence는 inferred evidence보다 높은 가중치를 주되, network=none 환경에서 실제 외부 통신은 차단한다.

## 구현 목표

1. `--sandbox off|static|docker` CLI 옵션 추가
2. 기본값은 `static`
3. 기존 static inference는 유지하되 명칭과 리포트를 명확히 정리
4. `DockerSandboxRunner` 추가
5. 임시 repo 복사, dummy HOME 생성, dummy credential 생성
6. Docker `--network=none`, `--read-only`, memory/cpu/no-new-privileges 적용
7. strace `trace=file,network,process` 수집
8. observed evidence와 inferred evidence 분리
9. Docker unavailable/failure 시 graceful fallback
10. auto-run only warning 정책 추가
11. reporter에 sandbox mode, fallback 여부, inferred/observed/warnings 구분 출력
12. 테스트와 문서 보강

## 구현 우선순위

1. 모델 확장: inferred/observed/warning/fallback 구분
2. CLI 옵션: sandbox mode 설정
3. static inference 명칭 정리
4. Docker runner 안전 설계 및 구현
5. strace parser 보완
6. scoring에서 observed evidence 가중치 분리
7. reporter 출력 개선
8. 테스트 추가
9. README와 docs/3 정리

## 현실성 고려 사항

Docker와 strace는 실행 환경에 없을 수 있다. 이 경우 서비스 전체가 실패하면 안 된다. `--sandbox docker`를 지정해도 Docker가 없으면 fallback 메시지를 기록하고 static inference로 돌아간다.

실제 sandbox는 모든 후보를 실행하지 않고 자동 실행 흐름에서 연결된 script, package lifecycle script, setup.py, shell script 등 제한된 대상만 실행한다. timeout은 5~10초로 제한한다.

## 보안 고려 사항

- 실제 사용자 HOME 마운트 금지
- 실제 credential 사용 금지
- dummy `.aws/credentials`, `.ssh/id_rsa`, `.env`만 생성
- `--network=none` 필수
- `--read-only` 적용
- writable tmp 최소화
- `--security-opt no-new-privileges`
- timeout으로 무한 실행 방지
- 실패 시 전체 CLI 중단 금지

## 발표/Q&A 대응 전략

Q: 기존 sandbox는 가짜 아닌가?

A: 기존 구현은 실제 sandbox가 아니라 `static behavior inference`라고 명확히 구분한다. 이번 구현에서 실제 Docker/strace 기반 observed evidence를 선택 기능으로 추가한다.

Q: 왜 Docker sandbox를 기본값으로 하지 않는가?

A: 속도, 비용, 실행 위험, 환경 의존성 때문이다. 기본은 빠른 static inference이고, 필요할 때만 docker sandbox를 실행한다.

Q: 단순 자동 실행은 왜 차단하지 않는가?

A: 정상 프로젝트도 자동 실행을 쓸 수 있기 때문에 차단하면 오탐률이 높다. 대신 WATCH/warning으로 사용자에게 명확히 알린다.

## 심사 기준 대응 전략

- 구현: 실제 Docker/strace runner를 옵션 기능으로 추가
- 지표 객관성: inferred와 observed evidence를 분리해 리포트
- 현실성: 기본 static, 선택 docker 구조
- 영향력: 실제 공급망 공격 흐름을 격리 환경에서 일부 관찰
- 발표력: warning, inferred, observed, fallback을 명확히 보여줌

## 구현 범위

- CLI `--sandbox off|static|docker`
- `StaticBehaviorAnalyzer`와 `DockerSandboxRunner` 공존
- dummy credential home 구성
- Docker command 생성 및 실행
- strace 로그 파싱
- observed/inferred summary 분리
- auto-run warning
- 테스트와 문서

## 구현하지 않을 범위

- production-grade malware sandbox
- 모든 파일 실행
- 실제 외부 네트워크 허용
- 실제 사용자 credential 접근
- Docker image 자동 빌드/배포
- 복잡한 multi-language dependency install
- 완전한 동적 taint tracking

## 기술 선택 이유

Python 표준 라이브러리의 `tempfile`, `shutil`, `subprocess`만으로 Docker CLI를 호출한다. 추가 의존성을 늘리지 않으면 심사 환경에서 설치 실패 위험이 줄어든다. strace parser는 기존 `strace_parser.py`를 보완해 사용한다. Docker가 없는 환경에서도 fallback을 통해 핵심 분석이 동작하게 한다.
