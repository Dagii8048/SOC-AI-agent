"""
celery_app.py
Configures the Celery app: Redis as both the job broker (where tasks
are queued) and the result backend (where results are stored once
a task finishes). Reads connection details from the environment to
match the project's existing .env.example convention (REDIS_HOST,
REDIS_PORT).
"""

from dotenv import load_dotenv
load_dotenv()

import os

from celery import Celery

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = os.environ.get("REDIS_PORT", "6379")
REDIS_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/0"

celery_app = Celery(
    "soc_tasks",
    broker=REDIS_URL,
    backend=REDIS_URL,
)

# Import tasks so Celery discovers and registers them at startup.
import tasks  # noqa: E402,F401
