# 정량 평가 지표

## 목적

심사와 운영 모두에서 “좋아 보이는 경고”가 아니라 측정 가능한 성능을 제공하기 위해 라벨 기반 평가 기능을 둔다.

## 산출 지표

- accuracy
- blocking accuracy
- precision
- recall
- false positive rate
- false negative rate
- average elapsed time
- p95 elapsed time

## 라벨 기준

평가 라벨은 `SAFE`, `WATCH`, `SUSPICIOUS`, `MALICIOUS`를 사용한다. 운영 의사결정에서는 `SUSPICIOUS`와 `MALICIOUS`를 차단 또는 clean clone 권장 그룹으로 본다.

`accuracy`는 라벨 정확 일치 기준이고, `blocking_accuracy`는 차단군/비차단군 의사결정이 맞았는지 보는 기준이다. 심사에서는 두 값을 함께 제시해 점수 분류 품질과 실제 차단 의사결정을 분리한다.

## 보안적 의도

개인정보 탈취 차단 서비스는 false negative를 특히 낮춰야 한다. 반면 개발자 도구 특성상 false positive가 높으면 사용자가 도구를 우회한다. 따라서 recall과 false positive rate를 함께 공개한다.

## 한계

데모 데이터셋은 지표 계산 구조 검증용이다. 실제 운영 전에는 정상 오픈소스, 사내 레포, 공개 악성 샘플, AI 툴 사칭 샘플을 분리해 평가해야 한다.
