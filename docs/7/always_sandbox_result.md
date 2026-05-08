# Always Sandbox Result

## 수정 파일

- `guardit/scanner.py`
- `guardit/sandbox/docker_runner.py`
- `guardit/config.py`
- `guardit/cli.py`
- `guardit/evaluation/metrics.py`
- `guardit/reporter.py`
- `guardit/terminal_ui.py`
- `tests/test_sandbox_policy.py`
- `docs/7/always_sandbox_plan.md`
- `docs/7/always_sandbox_checklist.md`
- `docs/7/always_sandbox_result.md`

## threshold 제거 이유

기존 구조는 LLM 보정 전 점수가 `sandbox_threshold` 미만이면 Docker sandbox를 실행하지 않았다. 이 정책은 observed evidence 확보 전에 실행 여부를 결정하므로 Guardit의 핵심 흐름인 inferred + observed 결합을 약화시켰다.

이번 변경으로 `scanner.py`는 점수와 관계없이 항상 `DockerSandboxRunner`를 호출한다. `sandbox_threshold` config와 `GUARDIT_SANDBOX_THRESHOLD` env 설정도 제거했다.

## skip policy 제거 이유

다음 skip 경로를 제거하거나 비활성화했다.

- `docker-sandbox-skipped`
- threshold 미만 Docker skip
- static mode threshold 미만 shortcut
- 실행 command 없음으로 인한 static fallback
- CLI의 `off`/`static` sandbox 선택지

실행 command가 없는 safe repo도 Docker에서 짧은 `true` probe를 수행한다.

## observed evidence 개선점

Docker/strace 성공 시 mode는 `docker`, `is_real_sandbox`는 `true`다. strace parser는 기존처럼 다음 observed evidence를 수집한다.

- credential access: `open`, `openat`
- network attempt: `connect`, `sendto`
- process execution: `execve`
- dummy credential IO: `read`, `write`

safe repo나 실행 command가 없는 repo는 probe용 process_spawn을 점수에 반영하지 않도록 필터링한다.

## reporter 개선점

Reporter와 terminal UI에서 threshold 미달 skip 문구를 제거했다.

성공했지만 suspicious observed behavior가 없으면 다음처럼 출력한다.

- suspicious behavior not observed
- credential access not observed
- external network attempt not observed

Docker 실행 실패 시에는 skip이 아니라 실패 상태로 표시한다.

- `Sandbox status: failed`
- `Reason: Docker CLI unavailable`

## fallback 정책

fallback은 Docker 실행을 시도했지만 환경 또는 런타임 문제로 실패한 경우에만 허용한다.

- Docker CLI unavailable
- Docker daemon permission/runtime error
- timeout
- sandbox command failure with no strace logs

fallback mode는 `static-fallback`이다.

## 성능 영향

항상 sandbox를 실행하므로 Docker startup 비용은 추가된다. 대신 다음 제한을 유지했다.

- timeout 기반 짧은 관찰
- command 없을 때 lightweight probe만 수행
- 자동 실행 command 최대 3개 실행
- `--network=none`
- read-only workspace/home mount
- non-root user

## 테스트 결과

실행 대상:

```bash
python -m unittest tests.test_sandbox_policy
python -m unittest tests.test_guardit_core
python -m unittest tests.test_llm_judge
```

검증 항목:

- low score repo도 `docker` mode로 real sandbox 수행
- safe repo도 Docker probe 수행
- Docker unavailable 시 `static-fallback`
- strace observed evidence 파싱 유지
- reporter에 threshold skip 문구 대신 observed 무탐지 출력

결과:

- `tests.test_sandbox_policy`: 10 tests OK
- `tests.test_guardit_core`: 3 tests OK
- `tests.test_llm_judge`: 5 tests OK
