# Guardit 평가 계획

## 평가 목적

Guardit의 평가는 “위험해 보인다”는 주관적 설명이 아니라, 라벨이 있는 데이터셋에서 정탐률과 오탐률을 계산할 수 있는 구조를 검증하는 것이다.

## 데이터셋 구성

현재 `demo_repos`는 15개 mock 샘플을 포함한다.

- benign 5개
- suspicious 5개
- malicious 5개

각 샘플은 실제 credential을 포함하지 않는다. 민감 경로와 외부 endpoint는 교육용 문자열 또는 example domain을 사용한다.

## 측정 지표

- accuracy
- blocking accuracy
- true positive rate
- precision
- recall
- false positive rate
- false negative rate
- confusion matrix
- average evidence count
- average elapsed time
- p95 elapsed time

## 실행 방법

```bash
python3 -m guardit eval demo_repos --output results/eval_result.json
```

결과 파일:

- `results/eval_result.json`
- `results/eval_report.md`

## 한계와 오탐 가능성

정상 프로젝트도 remote install, telemetry, local env, Makefile을 사용할 수 있다. Guardit은 민감정보 접근 근거가 없으면 MALICIOUS 상한을 적용하지만, 보수적인 SUSPICIOUS 판정은 여전히 발생할 수 있다.

현재 데이터셋은 교육용 mock이다. 실제 운영 지표로 쓰려면 정상 오픈소스, 공개 악성 샘플, 사내 정책 위반 샘플을 분리해 평가해야 한다.

## 분석 실패 케이스

- 동적으로 생성한 script path
- 암호화된 2차 payload
- 외부 서버에서 내려받은 payload
- 복잡한 JS bundler output
- native binary payload
- private repo rate limit 또는 권한 실패

## 성능 한계

전체 clone을 피하고 후보 blob만 받기 때문에 빠르지만, GitHub API tree가 truncated되는 초대형 레포에서는 일부 파일이 누락될 수 있다. 이 경우 리포트에 rate limit/truncation 신호를 추가하는 확장이 필요하다.
