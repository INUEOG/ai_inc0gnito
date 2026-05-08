# 위협 모델

## 핵심 공격 시나리오

1. 공격자가 정상 AI 툴처럼 보이는 GitHub 레포를 만든다.
2. 개발자가 레포를 clone한다.
3. VSCode/Cursor로 폴더를 열거나 npm install을 실행한다.
4. `.vscode/tasks.json`의 `runOn: folderOpen` 또는 `package.json`의 `postinstall`/`prepare`가 실행된다.
5. 스크립트가 `~/.aws/credentials`, `~/.ssh/id_rsa`, `.env`, GitHub token, npm token 등을 읽는다.
6. `fetch`, `axios.post`, `curl -d`, `requests.post` 등으로 외부 서버에 전송한다.

## 주요 자산

- AWS/GCP/Azure credential
- SSH private key
- GitHub token
- npm token
- `.env` 파일
- browser credential database
- 개발자 로컬 환경 정보

## 우선 탐지 지점

자동 실행 지점은 피해자가 명시적으로 코드를 실행하지 않아도 트리거될 수 있으므로 가장 높은 우선순위로 본다. `.git/hooks`는 일반 clone에 포함되지 않으므로 `.husky/*`, `.githooks/*`, `core.hooksPath` 계열 구조를 더 중요하게 본다.

## 비목표

Guardit MVP는 모든 악성코드 탐지를 목표로 하지 않는다. 런타임 exploit, kernel exploit, 바이너리 malware 분석은 범위 밖이다. 목표는 개발자 개인정보 탈취 공급망 공격을 clone 이전에 줄이는 것이다.

## 한계

난독화된 다단계 payload, 외부 서버에서 받은 2차 payload, 암호화된 문자열 조합은 완전 탐지가 어렵다. 이 경우 난독화와 원격 실행 근거를 점수화하고 사용자가 위험 파일 제외 clone을 선택할 수 있게 한다.
