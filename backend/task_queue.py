import os

from celery import Celery


def _env_url(name: str, default: str) -> str:
    raw = (os.environ.get(name) or "").strip()
    return raw or default


_default_redis_url = _env_url("REDIS_URL", "redis://localhost:6379/0")
REDIS_BROKER_URL = _env_url("REDIS_BROKER_URL", _default_redis_url)
REDIS_RESULT_BACKEND = _env_url("REDIS_RESULT_BACKEND", REDIS_BROKER_URL)

celery_app = Celery(
    "exam_os_tasks",
    broker=REDIS_BROKER_URL,
    backend=REDIS_RESULT_BACKEND,
    include=[
        "tasks.exam_generation",
        "tasks.notifications",
        "tasks.analytics",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    broker_connection_retry_on_startup=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
)
