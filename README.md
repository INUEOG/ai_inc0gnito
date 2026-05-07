# GuardClone

AI 기반 GitHub 레포지토리 사전 개인정보 유출 차단 CLI 프로토타입입니다.

`git clone` 전에 레포지토리 파일 트리와 자동 실행 가능 파일을 먼저 검사하고,
정적 분석, 샌드박스형 행동 추정, 작성자 신뢰도, AI 의도 판단을 합산해
clone 진행 여부를 결정합니다.

## 빠른 실행

```powershell
py -m guardclone demo
py -m guardclone scan .\demo_repos\malicious_repo --json
py -m guardclone eval .\demo_repos
py -m guardclone clone .\demo_repos\suspicious_repo .\safe-copy --choice auto
```

## 주요 기능

- `.vscode/tasks.json`, `package.json`, `.git/hooks`, `Makefile`, 셸/파이썬 스크립트 등 자동 실행 위험 파일 우선 검사
- `curl`, `Invoke-WebRequest`, `~/.aws`, `~/.ssh`, 브라우저 프로필, `eval`, `exec`, base64 난독화 등 개인정보 탈취 지표 탐지
- Python AST 기반 변수 흐름 추적
- 실행 없이 위험 행동을 모델링하는 샌드박스형 분석
- 위험 점수, 탈취 가능 정보, 악성 위치, 권장 조치 출력
- 검사 결과에 따라 차단/위험 파일 제외 clone/강제 진행 수행
- 데모 데이터셋 기반 정탐률/오탐률/처리 시간 평가

## 심사용 시나리오

1. 참가자가 의심스러운 GitHub 레포 URL 또는 로컬 경로를 입력합니다.
2. GuardClone이 자동 실행 파일을 먼저 찾습니다.
3. 위험 파일이 없으면 빠르게 안전 판정을 반환합니다.
4. 위험 파일이 있으면 개인정보 접근, 외부 전송, 난독화, 프로세스 실행을 분석합니다.
5. 최종 위험 점수와 근거를 보여주고 다음 선택지를 제공합니다.
   - clone 차단
   - 위험 파일 제외 후 clone
   - 위험 감수 후 진행

## 한계

본 프로토타입은 심사용으로 안전하게 설계되어 실제 악성 코드를 실행하지 않습니다.
Docker/strace가 있는 운영 환경에서는 `sandbox.py`의 행동 모델을 실제 컨테이너 실행 로그로 교체할 수 있습니다.
