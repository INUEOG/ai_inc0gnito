# Env Loading Result

## 변경 요약

Guardit CLI가 실행될 때 `load_config()`에서 `.env`를 자동 로드한다. 프로젝트 루트 `.env`를 먼저 확인하고, 현재 작업 디렉터리 `.env`도 확인한다.

## 수정 파일

- `pyproject.toml`
- `requirements.txt`
- `.env.example`
- `guardit/config.py`
- `guardit/cli.py`
- `guardit/ai/llm_judge.py`
- `tests/test_env_loading.py`

## 동작

- `.env`에 `GEMINI_API_KEY=` 또는 `GOOGLE_API_KEY=`를 넣으면 CLI가 자동 인식한다.
- `doctor`는 key 설정 여부와 `.env` 감지 여부를 출력한다.
- key가 없으면 다음 메시지를 출력한다.

```text
GEMINI_API_KEY 또는 GOOGLE_API_KEY가 없습니다. .env 또는 환경변수에 API 키를 설정하세요.
```

## 검증

- 프로젝트 루트 `.env`의 `GEMINI_API_KEY` 로딩
- `doctor`의 key 설정 상태 출력
- key 누락 시 명확한 안내 메시지 출력
