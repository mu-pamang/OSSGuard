## backend/services/github_detection/workers/workers.py
import os
import sys

# `github_detection/`을 Python 경로에 추가
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))  # 상위 디렉토리 (github_detection)
sys.path.append(BASE_DIR)

from config import celery_app
