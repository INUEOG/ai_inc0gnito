# 위험도 점수 시스템

## 점수 범위

Guardit은 0~100 정량 점수를 사용한다.

- `0~29`: SAFE
- `30~49`: WATCH
- `50~79`: SUSPICIOUS
- `80~100`: MALICIOUS

## 기본 점수

- 자동 실행 트리거: +20
- 민감정보 접근: +25
- 외부 POST 전송: +25
- source -> sink 연결: +20
- 난독화: +10
- 원격 스크립트 실행: +20
- sandbox에서 dummy credential 접근: +30
- sandbox에서 network connect 시도: +25
- 작성자 신뢰도 낮음: 최대 +10

## 핵심 강제 규칙

```python
if has_auto_trigger and has_secret_access and has_external_sink:
    risk_level = "MALICIOUS"
```

이 규칙은 점수가 80 미만이어도 최종 판정을 MALICIOUS로 올린다. 이유는 개발자 환경 자동 실행, credential 접근, 외부 전송이 동시에 있는 경우 목적이 정상 telemetry인지 여부와 관계없이 clone 전 차단해야 할 위험이 크기 때문이다.

## 작성자 신뢰도 제한

작성자 신뢰도는 보조 점수로만 사용한다. 낮은 신뢰도만으로 MALICIOUS를 만들지 않고, 높은 신뢰도만으로 명확한 탈취 흐름을 SAFE로 낮추지 않는다.

## LLM 보정 제한

LLM의 `risk_adjustment`는 `-10~+10`으로 제한한다. LLM confidence를 점수에 곱하지 않으며, LLM이 최종 점수를 직접 결정하지 않는다.
