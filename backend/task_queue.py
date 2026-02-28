import os

from celery import Celery

REDIS_BROKER_URL = os.environ.get("REDIS_BROKER_URL", "redis://localhost:6379/0")
REDIS_RESULT_BACKEND = os.environ.get("REDIS_RESULT_BACKEND", REDIS_BROKER_URL)

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
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
)
