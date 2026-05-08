# Guardit Sandbox 설계

## 모드

Guardit은 세 가지 sandbox mode를 제공한다.

- `off`: sandbox 관련 분석을 수행하지 않는다.
- `static`: 기본값. 실행 없이 정적 행동 추정을 수행한다.
- `docker`: Docker 컨테이너에서 제한된 command를 strace로 관찰한다.

## Static Behavior Inference

`static` 모드는 후보 파일 문자열과 정적 evidence를 기반으로 다음 행동 가능성을 추정한다.

- inferred credential access
- inferred network attempt
- inferred process spawn

이 모드는 실제 실행이 아니다. 빠르고 안전하지만 observed evidence가 아니다.

## Docker Sandbox

`docker` 모드는 제한된 실행 대상만 컨테이너에서 실행한다.

실행 대상:

- `tasks.json`에서 연결된 script
- `package.json` lifecycle script
- shell script
- Python/JS script

실행하지 않는 것:

- 전체 레포
- 임의 binary
- dependency install
- 실제 사용자 HOME
- 실제 credential

## Dummy Home

Docker sandbox는 임시 HOME을 생성한다.

```text
/sandbox-home/.aws/credentials
/sandbox-home/.ssh/id_rsa
/sandbox-home/.env
```

내용은 모두 dummy 값이다.

```text
FAKE_AWS_KEY
FAKE_SSH_KEY
FAKE_TOKEN
```

## Docker 제한

Docker 실행 시 다음 제한을 적용한다.

- `--network=none`
- `--read-only`
- `--memory=256m`
- `--cpus=0.5`
- `--cap-drop=ALL`
- `--security-opt no-new-privileges`
- non-root user
- timeout
- writable `/tmp` 최소화

## strace

컨테이너 내부에서 다음 형태로 strace를 실행한다.

```bash
strace -f -qq -e trace=file,network,process -o /trace/strace.log ...
```

수집 후 `strace_parser.py`가 다음 observed log를 만든다.

- observed opened files
- observed network attempts
- observed processes
- dummy credential access

## Fallback

Docker CLI가 없거나 Docker daemon 권한이 없거나 image에 strace가 없으면 전체 scan을 실패시키지 않는다. fallback reason을 기록하고 static behavior inference로 돌아간다.

## Docker Image

기본 image는 `guardit-sandbox:latest`다. 예시는 `docker/sandbox.Dockerfile`에 있다.

```bash
docker build -f docker/sandbox.Dockerfile -t guardit-sandbox:latest .
```

이 image는 strace, bash, curl, nodejs, python을 포함한다. 실제 외부 통신은 `--network=none`으로 차단된다.
