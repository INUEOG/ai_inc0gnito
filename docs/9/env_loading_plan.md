# Env Loading Plan

## 문제

Guardit은 `GEMINI_API_KEY`와 `GOOGLE_API_KEY`를 `os.environ`에서만 확인했다. 프로젝트 루트의 `.env`를 자동 로드하지 않아 사용자가 PowerShell에서 매번 `$env:GEMINI_API_KEY`를 직접 설정해야 했다.

## 구현 전략

- `python-dotenv` 의존성 추가
- `load_config()` 시작 시 프로젝트 루트 `.env`와 현재 작업 디렉터리 `.env` 자동 로드
- `python-dotenv`가 아직 설치되지 않은 환경에서도 동작하도록 간단한 fallback parser 제공
- `doctor`에서 `.env` 감지 여부와 Gemini/OpenAI key 상태 표시
- Gemini key 누락 메시지를 `.env` 또는 환경변수 설정 안내로 개선

## 수정 대상

- `pyproject.toml`
- `requirements.txt`
- `.env.example`
- `guardit/config.py`
- `guardit/cli.py`
- `guardit/ai/llm_judge.py`
- `tests/test_env_loading.py`
