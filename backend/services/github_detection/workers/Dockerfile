## 경로 : backend/services/github_detection/workers/Dockerfile

#  Celery Worker 실행용 Dockerfile
FROM python:3.9

WORKDIR /app

#  Docker Secrets에서 환경 변수 로드 (기존 .env 파일 제거)
RUN if [ -f "/run/secrets/github_env" ]; then cp /run/secrets/github_env /app/.env; fi

# apt-get install git
RUN apt-get update && apt-get install -y git curl

#  부모 디렉토리의 코드도 포함하여 복사 (requirements.txt 먼저 복사)
COPY requirements.txt /app/

#  가상환경 생성 및 활성화
RUN python -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

#  패키지 설치
COPY requirements.txt /app/
RUN /app/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

# syft, trivy 설치
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

#  애플리케이션 코드 복사 (패키지 설치 후)
COPY . /app/

#  환경 변수 로드
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH="/app"

#  Celery Worker 실행 (venv 활성화 후 실행)
# CMD ["/bin/sh", "-c", "[ -f /app/venv/bin/python ] || python3 -m venv /app/venv && /app/venv/bin/python -m celery -A github_detection.worker worker --loglevel=info"]
# Celery Worker 실행 (venv 활성화 후 실행)
#CMD ["/bin/sh", "-c", "[ -f /app/venv/bin/python ] || python3 -m venv /app/venv && /app/venv/bin/python -m celery -A config.celery_app worker --loglevel=info"]
CMD ["/bin/sh", "-c", "exec /app/venv/bin/celery -A config.celery_app worker --loglevel=info -Q app_queue"]