import logging
import os
import random
from datetime import datetime, timezone

from fastapi import HTTPException
from pymongo import ReturnDocument

from task_queue import celery_app
from tasks._async_runner import run_async
from server import (
    GenerationRequest,
    db,
    increment_usage_counter,
    record_metric,
    run_generation_pipeline,
)
from tasks.notifications import (
    send_first_exam_upgrade_nudge,
    send_generation_status_notification,
)

logger = logging.getLogger(__name__)

GENERATION_JOB_MAX_RETRIES = int(os.environ.get("GENERATION_JOB_MAX_RETRIES", "4"))
GENERATION_JOB_BACKOFF_BASE_SECONDS = int(os.environ.get("GENERATION_JOB_BACKOFF_BASE_SECONDS", "5"))
GENERATION_JOB_BACKOFF_MAX_SECONDS = int(os.environ.get("GENERATION_JOB_BACKOFF_MAX_SECONDS", "120"))


@celery_app.task(
    bind=True,
    name="tasks.exam_generation.process_generation_job",
    max_retries=GENERATION_JOB_MAX_RETRIES,
)
def process_generation_job(self, job_id: str) -> dict:
    return run_async(_process_generation_job_impl(self, job_id))


async def _process_generation_job_impl(self, job_id: str) -> dict:
    processing_job = await db.generation_jobs.find_one_and_update(
        {
            "job_id": job_id,
            "status": {"$in": ["queued", "retrying"]},
        },
        {
            "$set": {
                "status": "processing",
                "progress": 20,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "worker_task_id": self.request.id,
            },
            "$inc": {"attempt": 1},
        },
        return_document=ReturnDocument.AFTER,
        projection={"_id": 0},
    )
    if not processing_job:
        current = await db.generation_jobs.find_one({"job_id": job_id}, {"_id": 0, "status": 1})
        logger.info("generation_job_skip job_id=%s status=%s", job_id, (current or {}).get("status"))
        return {"job_id": job_id, "status": (current or {}).get("status", "missing")}

    user_id = processing_job["user_id"]
    request_payload = processing_job.get("request") or {}
    generation_type = processing_job.get("type", "unknown")
    result_reference = processing_job.get("result_reference") or job_id
    logger.info(
        "generation_job_processing_start user_id=%s job_id=%s type=%s attempt=%s",
        user_id,
        job_id,
        generation_type,
        processing_job.get("attempt"),
    )

    try:
        request_model = GenerationRequest(**request_payload)
        await db.generation_jobs.update_one(
            {"job_id": job_id},
            {"$set": {"progress": 45}},
        )
        generation = await run_generation_pipeline(
            user_id=user_id,
            request=request_model,
            generation_id=result_reference,
        )

        await increment_usage_counter(user_id, "generations_total", 1)
        if generation_type == "exam":
            await increment_usage_counter(user_id, "exam_generations_total", 1)
            counters = await db.user_usage_counters.find_one(
                {"user_id": user_id},
                {"_id": 0, "exam_generations_total": 1},
            )
            if int((counters or {}).get("exam_generations_total", 0)) == 1:
                send_first_exam_upgrade_nudge.delay(user_id=user_id)
        record_metric("generation_success", tags={"type": generation_type, "user_id": user_id})
        await db.generation_jobs.update_one(
            {"job_id": job_id},
            {
                "$set": {
                    "status": "completed",
                    "progress": 100,
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "result_reference": generation.id,
                    "error": None,
                }
            },
        )
        send_generation_status_notification.delay(
            user_id=user_id,
            job_id=job_id,
            status="completed",
            message="Your generation is complete.",
            result_reference=generation.id,
        )
        logger.info(
            "generation_job_processing_complete user_id=%s job_id=%s generation_id=%s type=%s",
            user_id,
            job_id,
            generation.id,
            generation_type,
        )
        return {"job_id": job_id, "status": "completed", "generation_id": generation.id}
    except HTTPException as exc:
        retryable = exc.status_code in {429, 500, 502, 503, 504}
        if retryable and self.request.retries < self.max_retries:
            delay = min(
                GENERATION_JOB_BACKOFF_BASE_SECONDS * (2 ** self.request.retries) + random.randint(0, 2),
                GENERATION_JOB_BACKOFF_MAX_SECONDS,
            )
            await db.generation_jobs.update_one(
                {"job_id": job_id},
                {
                    "$set": {
                        "status": "retrying",
                        "progress": 15,
                        "error": str(exc.detail),
                    },
                    "$push": {
                        "error_log": {
                            "at": datetime.now(timezone.utc).isoformat(),
                            "error": str(exc.detail),
                            "status_code": exc.status_code,
                            "retryable": True,
                        }
                    },
                },
            )
            logger.warning(
                "generation_job_retrying user_id=%s job_id=%s attempt=%s status_code=%s delay=%ss error=%s",
                user_id,
                job_id,
                self.request.retries + 1,
                exc.status_code,
                delay,
                exc.detail,
            )
            raise self.retry(exc=Exception(str(exc.detail)), countdown=delay)

        await _mark_job_failed(job_id, user_id, str(exc.detail), generation_type, exc.status_code)
        return {"job_id": job_id, "status": "failed"}
    except Exception as exc:
        if self.request.retries < self.max_retries:
            delay = min(
                GENERATION_JOB_BACKOFF_BASE_SECONDS * (2 ** self.request.retries) + random.randint(0, 2),
                GENERATION_JOB_BACKOFF_MAX_SECONDS,
            )
            await db.generation_jobs.update_one(
                {"job_id": job_id},
                {
                    "$set": {
                        "status": "retrying",
                        "progress": 15,
                        "error": str(exc),
                    },
                    "$push": {
                        "error_log": {
                            "at": datetime.now(timezone.utc).isoformat(),
                            "error": str(exc),
                            "retryable": True,
                        }
                    },
                },
            )
            logger.warning(
                "generation_job_retrying_unknown user_id=%s job_id=%s attempt=%s delay=%ss error=%s",
                user_id,
                job_id,
                self.request.retries + 1,
                delay,
                exc,
            )
            raise self.retry(exc=exc, countdown=delay)

        await _mark_job_failed(job_id, user_id, str(exc), generation_type, None)
        return {"job_id": job_id, "status": "failed"}


async def _mark_job_failed(
    job_id: str,
    user_id: str,
    error_text: str,
    generation_type: str,
    status_code: int | None,
) -> None:
    await db.generation_jobs.update_one(
        {"job_id": job_id},
        {
            "$set": {
                "status": "failed",
                "progress": 100,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "error": error_text,
            },
            "$push": {
                "error_log": {
                    "at": datetime.now(timezone.utc).isoformat(),
                    "error": error_text,
                    "status_code": status_code,
                    "retryable": False,
                }
            },
        },
    )
    send_generation_status_notification.delay(
        user_id=user_id,
        job_id=job_id,
        status="failed",
        message=f"Generation failed: {error_text}",
    )
    logger.error(
        "generation_job_failed user_id=%s job_id=%s type=%s status_code=%s error=%s",
        user_id,
        job_id,
        generation_type,
        status_code,
        error_text,
    )
