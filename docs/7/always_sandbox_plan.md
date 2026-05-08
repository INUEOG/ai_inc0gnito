# Always Sandbox Plan

## 1. 현재 sandbox skip 구조 분석

기존 `guardit/scanner.py`는 정적 분석 직후 `provisional = score_report(...)`를 먼저 계산하고, `config.sandbox_threshold` 이상일 때만 Docker sandbox를 실행했다.

- `config.sandbox_mode == "docker" and provisional.final_score >= config.sandbox_threshold`: Docker 실행
- `config.sandbox_mode == "docker"` 이지만 점수 미달: `docker-sandbox-skipped`
- `config.sandbox_mode == "static"` 이고 점수 미달: static behavior inference도 생략
- `config.sandbox_mode == "off"`: sandbox 단계 비활성화

`guardit/sandbox/docker_runner.py`에도 추가 skip 경로가 있었다. `execution_commands(flows)`가 비어 있으면 Docker를 실행하지 않고 static fallback으로 내려갔다. 즉 safe repo나 낮은 점수 repo는 observed evidence를 확보하지 못했다.

## 2. threshold 정책 문제점

Guardit의 핵심 가치는 정적 추론(inferred)과 실제 행위 관찰(observed)을 같이 보여주는 것이다. threshold gating은 이 흐름을 깨뜨린다.

- 낮은 점수 repo에서 실제 credential 접근이 뒤늦게 드러날 수 있다.
- 자동 실행 파일만 있는 repo도 실제 실행에서 child process, shell execution, network attempt가 발생할 수 있다.
- 점수 산정 전에 observed evidence가 없으므로 점수가 observed 기반으로 보정될 기회가 사라진다.

## 3. inferred only 분석의 한계

정적 분석은 코드 문자열과 패턴을 기반으로 가능성을 추정한다. 그러나 다음 행위는 실제 실행 관찰 없이는 신뢰도가 낮다.

- runtime 분기 뒤 credential 접근
- subprocess를 통한 우회 실행
- shell script 내부 network attempt
- obfuscated command 실행
- install lifecycle 중 실제 호출되는 script

## 4. observed evidence 필요성

Docker/strace 기반 observed evidence는 syscall 단위의 근거를 제공한다.

- `openat`: dummy credential 접근 관찰
- `connect`, `sendto`: 네트워크 연결 시도 관찰
- `execve`: process execution, shell execution 관찰
- child process: 자동 실행 흐름의 실제 실행 여부 확인

## 5. 왜 항상 sandbox가 필요한가

Guardit은 clone 이전 보안 게이트다. 낮은 점수 repo도 사용자가 clone 또는 install을 수행하기 전에는 실제 행위가 확인되지 않는다. 따라서 sandbox는 위험 repo만 대상으로 하는 부가 기능이 아니라 기본 분석 단계여야 한다.

## 6. 성능 영향 분석

항상 Docker를 실행하면 비용이 증가한다. 대신 다음 방식으로 제한한다.

- `sandbox_timeout_sec`로 짧은 timeout 유지
- 실행 command가 없으면 `true` probe만 수행
- 자동 실행 command는 기존 제한 command만 최대 3개 실행
- Docker network는 `--network=none`으로 유지
- workspace와 dummy home은 read-only mount 유지

## 7. 수정 대상 파일

- `guardit/scanner.py`
- `guardit/sandbox/docker_runner.py`
- `guardit/config.py`
- `guardit/cli.py`
- `guardit/evaluation/metrics.py`
- `guardit/reporter.py`
- `guardit/terminal_ui.py`
- `tests/test_sandbox_policy.py`
- `docs/7/*`

## 8. 구현 전략

1. `scanner.py`에서 `sandbox_threshold` 기반 분기를 제거한다.
2. 모든 분석에서 `DockerSandboxRunner.analyze(...)`를 호출한다.
3. Docker runner에서 실행 command가 없어도 lightweight probe를 실행한다.
4. Docker 실패 시에만 static fallback을 허용한다.
5. fallback mode는 `static-fallback`으로 명확히 표시한다.
6. 성공 mode는 `docker`로 단순화한다.

## 9. reporter 변경 방향

Reporter는 더 이상 threshold 미달 skip을 출력하지 않는다.

성공 시:

- `Mode docker`
- `Real sandbox yes`
- `[observed]` 실제 행위 또는 무탐지 요약

실패 시:

- `Mode static-fallback`
- `Real sandbox no`
- `Sandbox status failed`
- `Reason Docker CLI unavailable` 같은 명확한 실패 이유

## 10. fallback 정책

fallback은 sandbox를 실행하지 않기로 결정한 경우가 아니라, 실행을 시도했지만 환경 또는 런타임 문제로 실패한 경우에만 허용한다.

- Docker CLI unavailable
- Docker daemon unavailable 또는 permission denied
- strace log 미생성
- sandbox timeout
- subprocess runtime error

## 11. 안전성 고려사항

- 실제 사용자 HOME 또는 credential은 mount하지 않는다.
- `/sandbox-home`에는 dummy credential만 둔다.
- 네트워크는 `--network=none`으로 차단한다.
- read-only root filesystem과 read-only workspace mount를 유지한다.
- container user는 non-root `65534:65534`를 유지한다.
- 실행 대상은 lifecycle/자동 실행 흐름에서 제한적으로 추출한 command로 제한한다.
