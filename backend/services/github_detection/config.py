import os
import redis
from celery import Celery
from dotenv import load_dotenv

# `.env` 파일 로드 (app/secrets/github_env)
load_dotenv("/app/.env")
# env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "secrets", "github_env"))
# if os.path.exists(env_path):
#     load_dotenv(env_path)
# else:
#     print(" 환경 변수 파일을 찾을 수 없습니다:", env_path)


# 환경 변수 설정
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_DB = os.getenv("REDIS_DB", "0")

RABBITMQ_USER = os.getenv("RABBITMQ_USER", "myuser")
RABBITMQ_PASSWORD = os.getenv("RABBITMQ_PASSWORD", "mypassword")
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_PORT = os.getenv("RABBITMQ_PORT", "5672")

# Redis 클라이언트 설정
redis_client = redis.Redis(
    host=REDIS_HOST,
    port=int(REDIS_PORT),
    db=int(REDIS_DB),
    decode_responses=True
)

# Celery 인스턴스 생성
celery_app = Celery(
    "tasks",
    broker=f"amqp://{RABBITMQ_USER}:{RABBITMQ_PASSWORD}@{RABBITMQ_HOST}:{RABBITMQ_PORT}//",
    backend=f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"
)

# Celery 최적화 설정
celery_app.conf.update(
    include=["tasks"],
    task_routes={"github_detection.tasks.*": {"queue": "app_queue"}},
    worker_concurrency=os.cpu_count() or 4,  # CPU 코어 기반 설정
    task_acks_late=True,
    result_expires=3600,

    # RabbitMQ 연결 안정화 설정 추가
    broker_heartbeat=0,  # RabbitMQ와 지속적인 연결 유지 (60초마다 확인)
    broker_connection_retry=True,  # 연결 실패 시 자동 재연결
    broker_connection_max_retries=None,  # 무제한 재연결 시도
    broker_pool_limit=None,  # 연결 풀 제한 해제 (기본값: 10)
    worker_prefetch_multiplier=1,  # 한 번에 하나의 작업만 처리 (안정성 증가)
    
    # RabbitMQ 추가 설정 (타임아웃 및 QoS 설정)
    broker_transport_options={
        "visibility_timeout": 3600,  # 1시간 동안 작업이 실행되지 않으면 다시 큐에 넣음
        "retry_policy": {
            "max_retries": 5,  # 최대 재시도 횟수
            "interval_start": 0,  # 첫 재시도까지 대기 시간
            "interval_step": 2,  # 재시도 간격 증가 값
            "interval_max": 10,  # 최대 재시도 간격
        }
    }
)
