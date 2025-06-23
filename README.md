## 🛡️ OSS Guard

- **OSS Guard**는 GitHub 오픈소스 프로젝트를 분석하여 보안 취약점과 패키지 위험성을 시각화하는 도구.
- React + FastAPI + Redis 기반으로 작동하며, Docker Compose로 손쉽게 실행 가능

## 🛠️ 기술 스택

- Frontend: React.js - 모던한 사용자 인터페이스
- Backend: FastAPI -  Python 웹 프레임워크
- Cache: Redis - 빠른 분석 결과 저장
- Deploy: Docker Compose - 원클릭 배포

## 🚀 실행 방법

### 1️⃣ 레포지토리 클론

```bash
git clone https://github.com/mu-pamang/OSSGuard.git
cd OSSGuard
```

### 2️⃣ Docker Compose로 빌드 및 실행

```bash
docker compose up --build
```

👉 **백그라운드 실행:**

```bash
docker compose up --build -d
```

### 3️⃣ 중지

```bash
docker compose down
```

## 🌐 서비스 주소

| 서비스 | 주소 |
|--------|------|
| 프론트엔드 | http://localhost:3000 |
| 백엔드 API | http://localhost:8003 |

## 📝 주요 기능

-  GitHub URL 기반 저장소 보안 분석
-  취약점, 패키지, 업데이트 권고 시각화
-  Typosquatting 및 의존성 혼동 탐지
-  YARA 기반 악성 코드 탐지 (예정)
-  React + FastAPI 모던 대시보드 UI
-  Redis 캐싱을 통한 분석 결과 저장

## ⚠️ 참고

- Docker, Docker Compose 필요
- 필요한 경우 `docker-compose.yml`과 `.env` 파일을 수정해 포트를 변경 가능
- API CORS 설정이 되어 있어 로컬 React 앱과 통신 가능

## 💡 기본 API 엔드포인트

| 엔드포인트 | 설명 |
|------------|------|
| `GET /health` | 서버 상태 확인 |
| `POST /store_analysis` | GitHub URL 보안 분석 요청 |
| `POST /g_dashboard` | 대시보드 데이터 조회 |
| `POST /vulnerabilities` | 취약점 데이터 조회 |
| `POST /packages` | 패키지 데이터 조회 |
| `POST /updates` | 업데이트 권고 조회 |
| `POST /reset_cache` | 특정 저장소 분석 데이터 초기화 |
