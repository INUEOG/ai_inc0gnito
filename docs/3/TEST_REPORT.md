# Guardit 3차 테스트 리포트

## 실행 명령

```bash
python3 -m unittest discover -s tests -q
python3 -m compileall -q guardit tests
python3 -m guardit eval demo_repos --output results/eval_result.json --sandbox static
python3 -m guardit scan demo_repos/malicious --sandbox docker --threshold 101
```

## 단위 테스트

추가 테스트:

1. auto-run only
2. auto-run + benign build script
3. auto-run + credential access
4. auto-run + external POST
5. auto-run + credential access + external POST
6. docker sandbox unavailable fallback
7. docker sandbox success
8. strace parser

결과:

```text
Ran 10 tests
OK
```

## 평가 결과

`demo_repos` 15개 샘플 기준:

- accuracy: 1.0
- blocking accuracy: 1.0
- true positive rate: 1.0
- precision: 1.0
- recall: 1.0
- false positive rate: 0.0
- false negative rate: 0.0

주의: 이 수치는 교육용 mock dataset 기준이다. 실제 운영 성능으로 과장하면 안 된다.

## Docker Smoke 결과

현재 실행 환경에서는 Docker daemon 권한 문제로 실제 컨테이너 실행이 fallback되었다.

```text
fallback reason: permission denied while trying to connect to the docker API
```

서비스는 실패하지 않고 static behavior inference로 fallback했다. 이는 요구한 graceful fallback 동작이다.
