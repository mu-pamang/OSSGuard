## 경로 : ./backend/services/github_detection/Dockerfile

#  Python 3.9 기반 이미지 사용
FROM python:3.9

# (1) 작업 디렉토리 생성 (필수!)
WORKDIR /app

# (2) Docker Secrets에서 환경 변수 로드 (기존 .env 제거)
RUN if [ -f "/run/secrets/github_env" ]; then cp /run/secrets/github_env /app/.env; fi

# (3) Yara C 라이브러리 빌드에 필요한 패키지 설치: libyara-dev, gcc
RUN apt-get update && apt-get install -y --no-install-recommends \
    libyara-dev gcc \
    && rm -rf /var/lib/apt/lists/*

# (4) 가상환경 생성 및 활성화 : 패키지 설치
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# (5)) requirements.txt 먼저 복사
COPY requirements.txt /app/
RUN /app/venv/bin/pip install --no-cache-dir --force-reinstall -r /app/requirements.txt

#  `venv` 확인
RUN ls -l /app/venv/ || echo " venv 생성 실패!"


#  Celery가 정상 설치되었는지 확인
RUN /app/venv/bin/celery --version || echo "Celery 설치 실패!"
RUN ls -l /app/venv/bin/celery || echo "Celery 실행 파일 없음!"

#  보안 스캐너 설치 (Trivy, Syft)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

#  앱 소스 복사 (패키지 설치 후)
COPY . /app/

#  `venv` 패키지 설치 확인
RUN ls -l /app/venv/lib/python3.9/site-packages

#  환경 변수 설정
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH="/app/venv/lib/python3.9/site-packages:/app"

# FastAPI 실행 (가상환경 활성화 후 실행)
CMD ["/bin/sh", "-c", "export PYTHONPATH=/app/venv/lib/python3.9/site-packages:/app && exec /app/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000"]
