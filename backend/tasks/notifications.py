import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from pymongo import ReturnDocument

from task_queue import celery_app
from tasks._async_runner import run_async
from notification_service import send_push_to_user
from server import (
    BREVO_API_KEY2,
    BREVO_SENDER_EMAIL,
    BREVO_SENDER_NAME,
    RETENTION_EMAIL_BATCH_SIZE,
    RETENTION_EMAIL_DAILY_LIMIT,
    RETENTION_EMAIL_MIN_DAYS_BETWEEN_SENDS,
    RETENTION_INSIGHTS_ENABLED,
    current_runtime_settings,
    db,
    get_generation_entitlement,
    send_brevo_transactional_email,
)

logger = logging.getLogger(__name__)
RETENTION_TARGET_LOCK_MINUTES = 20
RETENTION_REQUEUE_SECONDS = 30


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


def _next_day_eta(now: Optional[datetime] = None) -> datetime:
    current = now or _utc_now()
    next_day = (current + timedelta(days=1)).date()
    return datetime(
        year=next_day.year,
        month=next_day.month,
        day=next_day.day,
        hour=0,
        minute=5,
        tzinfo=timezone.utc,
    )


def _daily_usage_key(now: Optional[datetime] = None) -> str:
    current = now or _utc_now()
    return current.strftime("%Y-%m-%d")


@celery_app.task(name="tasks.notifications.send_generation_status_notification")
def send_generation_status_notification(
    user_id: str,
    job_id: str,
    status: str,
    message: str,
    result_reference: Optional[str] = None,
) -> None:
    run_async(
        _persist_notification(
            user_id=user_id,
            job_id=job_id,
            status=status,
            message=message,
            result_reference=result_reference,
        )
    )


async def _persist_notification(
    user_id: str,
    job_id: str,
    status: str,
    message: str,
    result_reference: Optional[str] = None,
) -> None:
    now = _utc_now()
    doc = {
        "id": f"notif_{job_id}_{int(now.timestamp())}",
        "user_id": user_id,
        "job_id": job_id,
        "status": status,
        "message": message,
        "result_reference": result_reference,
        "read": False,
        "created_at": now.isoformat(),
    }
    await db.notifications.insert_one(doc)
    await send_push_to_user(
        db=db,
        user_id=user_id,
        title="Generation Update",
        body=message,
        data={
            "notification_id": doc["id"],
            "status": status,
            "job_id": job_id,
            "result_reference": result_reference or "",
        },
    )
    logger.info(
        "notification_saved user_id=%s job_id=%s status=%s result_reference=%s",
        user_id,
        job_id,
        status,
        result_reference,
    )


@celery_app.task(name="tasks.notifications.send_class_scheduled_push")
def send_class_scheduled_push(
    user_ids: list[str],
    class_id: str,
    title: str,
    teacher_name: str,
    meeting_link: str,
    scheduled_start_at: str,
) -> None:
    run_async(
        _send_class_scheduled_push(
            user_ids=user_ids,
            class_id=class_id,
            title=title,
            teacher_name=teacher_name,
            meeting_link=meeting_link,
            scheduled_start_at=scheduled_start_at,
        )
    )


async def _send_class_scheduled_push(
    user_ids: list[str],
    class_id: str,
    title: str,
    teacher_name: str,
    meeting_link: str,
    scheduled_start_at: str,
) -> None:
    body = f"{title} by {teacher_name} is scheduled."
    for user_id in user_ids:
        await send_push_to_user(
            db=db,
            user_id=user_id,
            title="New Class Scheduled",
            body=body,
            data={
                "class_id": class_id,
                "meeting_link": meeting_link,
                "scheduled_start_at": scheduled_start_at,
                "status": "class_scheduled",
            },
        )


@celery_app.task(bind=True, name="tasks.notifications.process_retention_insight_campaign")
def process_retention_insight_campaign(self, campaign_id: str) -> Dict[str, Any]:
    return run_async(_process_retention_campaign_impl(self.request.id or "", campaign_id))


async def _process_retention_campaign_impl(worker_task_id: str, campaign_id: str) -> Dict[str, Any]:
    if not RETENTION_INSIGHTS_ENABLED:
        await _mark_campaign_failed(campaign_id, "Retention insights are disabled")
        return {"campaign_id": campaign_id, "status": "failed", "reason": "disabled"}
    if not BREVO_API_KEY2 or not BREVO_SENDER_EMAIL:
        await _mark_campaign_failed(campaign_id, "BREVO_API_KEY2 or BREVO_SENDER_EMAIL missing")
        return {"campaign_id": campaign_id, "status": "failed", "reason": "brevo_config_missing"}

    campaign = await _claim_campaign(campaign_id=campaign_id, worker_task_id=worker_task_id)
    if not campaign:
        return {"campaign_id": campaign_id, "status": "skipped"}

    await _requeue_stale_targets(campaign_id)

    processed_this_run = 0
    quota_exhausted = False
    while processed_this_run < max(1, RETENTION_EMAIL_BATCH_SIZE):
        target = await _claim_next_target(campaign_id=campaign_id, worker_task_id=worker_task_id)
        if not target:
            break

        now = _utc_now()
        now_iso = now.isoformat()
        if not await _is_user_due_for_retention(target["user_id"], now):
            await _mark_target_skipped(campaign_id=campaign_id, target_id=target["id"], reason="cooldown")
            processed_this_run += 1
            continue

        slot_reserved, day_key = await _reserve_daily_slot(now=now)
        if not slot_reserved:
            await db.retention_email_targets.update_one(
                {"id": target["id"], "status": "processing"},
                {
                    "$set": {
                        "status": "pending",
                        "updated_at": now_iso,
                    },
                    "$unset": {"processing_started_at": "", "worker_task_id": ""},
                },
            )
            quota_exhausted = True
            break

        try:
            payload = await _build_retention_email_payload(target)
            result = await send_brevo_transactional_email(api_key=BREVO_API_KEY2, payload=payload)
            await db.retention_email_targets.update_one(
                {"id": target["id"], "status": "processing"},
                {
                    "$set": {
                        "status": "sent",
                        "sent_at": now_iso,
                        "updated_at": now_iso,
                        "brevo_message_id": str(result.get("messageId") or ""),
                    },
                    "$unset": {"processing_started_at": "", "worker_task_id": ""},
                },
            )
            await db.retention_email_campaigns.update_one(
                {"id": campaign_id},
                {
                    "$inc": {"sent_count": 1, "pending_count": -1},
                    "$set": {"updated_at": now_iso, "error": None},
                },
            )
            await db.retention_email_recipients.update_one(
                {"user_id": target["user_id"]},
                {
                    "$set": {
                        "user_id": target["user_id"],
                        "email": target["email"],
                        "last_sent_at": now_iso,
                        "last_campaign_id": campaign_id,
                        "updated_at": now_iso,
                    },
                    "$inc": {"sent_total": 1},
                    "$setOnInsert": {"created_at": now_iso},
                },
                upsert=True,
            )
            processed_this_run += 1
        except Exception as exc:
            logger.error(
                "retention_email_send_failed campaign_id=%s target_id=%s user_id=%s error=%s",
                campaign_id,
                target["id"],
                target["user_id"],
                exc,
            )
            await _release_daily_slot(day_key)
            await db.retention_email_targets.update_one(
                {"id": target["id"], "status": "processing"},
                {
                    "$set": {
                        "status": "failed",
                        "error": str(exc),
                        "updated_at": now_iso,
                    },
                    "$unset": {"processing_started_at": "", "worker_task_id": ""},
                },
            )
            await db.retention_email_campaigns.update_one(
                {"id": campaign_id},
                {
                    "$inc": {"failed_count": 1, "pending_count": -1},
                    "$set": {"updated_at": now_iso, "error": str(exc)},
                },
            )
            processed_this_run += 1

    remaining_pending = await db.retention_email_targets.count_documents(
        {"campaign_id": campaign_id, "status": "pending"}
    )
    if remaining_pending <= 0:
        now_iso = _utc_now_iso()
        await db.retention_email_campaigns.update_one(
            {"id": campaign_id},
            {
                "$set": {
                    "status": "completed",
                    "completed_at": now_iso,
                    "updated_at": now_iso,
                    "lock_expires_at": now_iso,
                    "next_run_at": None,
                    "error": None,
                }
            },
        )
        logger.info("retention_campaign_completed campaign_id=%s", campaign_id)
        return {"campaign_id": campaign_id, "status": "completed"}

    if quota_exhausted:
        now = _utc_now()
        eta = _next_day_eta(now)
        delay_seconds = max(60, int((eta - now).total_seconds()))
        await db.retention_email_campaigns.update_one(
            {"id": campaign_id},
            {
                "$set": {
                    "status": "queued",
                    "updated_at": now.isoformat(),
                    "next_run_at": eta.isoformat(),
                    "lock_expires_at": now.isoformat(),
                }
            },
        )
        process_retention_insight_campaign.apply_async(args=[campaign_id], countdown=delay_seconds)
        logger.info(
            "retention_campaign_quota_exhausted campaign_id=%s next_run_at=%s",
            campaign_id,
            eta.isoformat(),
        )
        return {"campaign_id": campaign_id, "status": "queued", "next_run_at": eta.isoformat()}

    now = _utc_now()
    eta = now + timedelta(seconds=RETENTION_REQUEUE_SECONDS)
    await db.retention_email_campaigns.update_one(
        {"id": campaign_id},
        {
            "$set": {
                "status": "queued",
                "updated_at": now.isoformat(),
                "next_run_at": eta.isoformat(),
                "lock_expires_at": now.isoformat(),
            }
        },
    )
    process_retention_insight_campaign.apply_async(args=[campaign_id], countdown=RETENTION_REQUEUE_SECONDS)
    return {"campaign_id": campaign_id, "status": "queued", "next_run_at": eta.isoformat()}


async def _claim_campaign(campaign_id: str, worker_task_id: str) -> Optional[Dict[str, Any]]:
    now = _utc_now()
    now_iso = now.isoformat()
    lock_until = (now + timedelta(minutes=RETENTION_TARGET_LOCK_MINUTES)).isoformat()
    campaign = await db.retention_email_campaigns.find_one_and_update(
        {
            "id": campaign_id,
            "status": {"$in": ["queued", "processing"]},
            "$or": [
                {"lock_expires_at": {"$exists": False}},
                {"lock_expires_at": {"$lte": now_iso}},
                {"worker_task_id": worker_task_id},
            ],
        },
        {
            "$set": {
                "status": "processing",
                "worker_task_id": worker_task_id,
                "updated_at": now_iso,
                "started_at": now_iso,
                "lock_expires_at": lock_until,
            },
            "$inc": {"run_count": 1},
        },
        projection={"_id": 0},
        return_document=ReturnDocument.AFTER,
    )
    return campaign


async def _requeue_stale_targets(campaign_id: str) -> None:
    cutoff_iso = (_utc_now() - timedelta(minutes=RETENTION_TARGET_LOCK_MINUTES)).isoformat()
    await db.retention_email_targets.update_many(
        {
            "campaign_id": campaign_id,
            "status": "processing",
            "processing_started_at": {"$lte": cutoff_iso},
        },
        {
            "$set": {"status": "pending", "updated_at": _utc_now_iso()},
            "$unset": {"processing_started_at": "", "worker_task_id": ""},
        },
    )


async def _claim_next_target(campaign_id: str, worker_task_id: str) -> Optional[Dict[str, Any]]:
    now_iso = _utc_now_iso()
    return await db.retention_email_targets.find_one_and_update(
        {"campaign_id": campaign_id, "status": "pending"},
        {
            "$set": {
                "status": "processing",
                "processing_started_at": now_iso,
                "updated_at": now_iso,
                "worker_task_id": worker_task_id,
            },
            "$inc": {"attempts": 1},
        },
        sort=[("created_at", 1)],
        projection={"_id": 0},
        return_document=ReturnDocument.AFTER,
    )


async def _is_user_due_for_retention(user_id: str, now: datetime) -> bool:
    if RETENTION_EMAIL_MIN_DAYS_BETWEEN_SENDS <= 0:
        return True
    recipient_state = await db.retention_email_recipients.find_one(
        {"user_id": user_id},
        {"_id": 0, "last_sent_at": 1},
    )
    last_sent_at_raw = (recipient_state or {}).get("last_sent_at")
    if not last_sent_at_raw:
        return True
    try:
        last_sent_at = datetime.fromisoformat(str(last_sent_at_raw))
    except Exception:
        return True
    return (now - last_sent_at) >= timedelta(days=RETENTION_EMAIL_MIN_DAYS_BETWEEN_SENDS)


async def _reserve_daily_slot(now: datetime) -> Tuple[bool, str]:
    day_key = _daily_usage_key(now)
    usage_doc = await db.retention_email_daily_usage.find_one_and_update(
        {"day_key": day_key, "count": {"$lt": RETENTION_EMAIL_DAILY_LIMIT}},
        {
            "$inc": {"count": 1},
            "$set": {"updated_at": now.isoformat()},
            "$setOnInsert": {"day_key": day_key, "count": 0, "created_at": now.isoformat()},
        },
        upsert=True,
        projection={"_id": 0, "count": 1},
        return_document=ReturnDocument.AFTER,
    )
    return usage_doc is not None, day_key


async def _release_daily_slot(day_key: str) -> None:
    await db.retention_email_daily_usage.update_one(
        {"day_key": day_key, "count": {"$gt": 0}},
        {"$inc": {"count": -1}, "$set": {"updated_at": _utc_now_iso()}},
    )


async def _mark_target_skipped(campaign_id: str, target_id: str, reason: str) -> None:
    now_iso = _utc_now_iso()
    await db.retention_email_targets.update_one(
        {"id": target_id, "status": "processing"},
        {
            "$set": {
                "status": "skipped",
                "skip_reason": reason,
                "updated_at": now_iso,
            },
            "$unset": {"processing_started_at": "", "worker_task_id": ""},
        },
    )
    await db.retention_email_campaigns.update_one(
        {"id": campaign_id},
        {"$inc": {"skipped_count": 1, "pending_count": -1}, "$set": {"updated_at": now_iso}},
    )


async def _build_retention_email_payload(target: Dict[str, Any]) -> Dict[str, Any]:
    user_id = str(target.get("user_id", ""))
    user_email = str(target.get("email", ""))
    full_name = str(target.get("full_name", "") or "").strip()
    first_name = (full_name.split(" ")[0] if full_name else "there").strip() or "there"
    entitlement = await get_generation_entitlement(user_id)
    runtime = current_runtime_settings()
    monthly_price = int(runtime.get("subscription_monthly_kes", 499))

    plan_name = entitlement.get("plan_name") or "Free"
    generation_used = int(entitlement.get("generation_used", 0))
    generation_limit = int(entitlement.get("generation_limit", 0))
    generation_remaining = int(entitlement.get("generation_remaining", 0))
    exam_limit = entitlement.get("exam_limit")
    exam_used = entitlement.get("exam_used")
    exam_remaining = entitlement.get("exam_remaining")
    is_free = bool(entitlement.get("is_free", True))

    if is_free and generation_remaining <= 0:
        headline = "Your free generation credits are fully used"
        next_step = f"Upgrade to Monthly (KES {monthly_price}) to unlock higher generation and exam quotas."
    elif is_free and generation_remaining <= 2:
        headline = "You are close to your free generation limit"
        next_step = f"Use your remaining {generation_remaining} generation(s) strategically, then upgrade when ready."
    elif (not is_free) and generation_remaining <= 5:
        headline = "You are nearing your current subscription limit"
        next_step = "Prioritize highest-impact exams this week and renew early to avoid downtime."
    else:
        headline = "Your Exam OS workflow is active and healthy"
        next_step = "Keep momentum by planning your next exam set and class sessions ahead."

    exam_line = ""
    if exam_limit is not None:
        exam_line = (
            f"<li><strong>Exam quota:</strong> {int(exam_used or 0)} used / {int(exam_limit)} total "
            f"(remaining: {int(exam_remaining or 0)})</li>"
        )

    subject = f"Exam OS Retention Insight: {headline}"
    html = (
        f"<p>Hi {first_name},</p>"
        f"<p>{headline}.</p>"
        "<p>Here is your current learning-ops snapshot:</p>"
        "<ul>"
        f"<li><strong>Plan:</strong> {plan_name}</li>"
        f"<li><strong>Generations:</strong> {generation_used} used / {generation_limit} total "
        f"(remaining: {generation_remaining})</li>"
        f"{exam_line}"
        "</ul>"
        "<p><strong>Recommended next step:</strong> "
        f"{next_step}</p>"
        "<p>Pro tip: combine Topic Board demand signals with Generation Lab prompts for faster exam planning.</p>"
        "<p>— Exam OS Team</p>"
    )

    return {
        "sender": {"email": BREVO_SENDER_EMAIL, "name": BREVO_SENDER_NAME},
        "to": [{"email": user_email, "name": full_name or user_email}],
        "subject": subject,
        "htmlContent": html,
    }


async def _mark_campaign_failed(campaign_id: str, error: str) -> None:
    now_iso = _utc_now_iso()
    await db.retention_email_campaigns.update_one(
        {"id": campaign_id},
        {
            "$set": {
                "status": "failed",
                "error": error,
                "updated_at": now_iso,
                "completed_at": now_iso,
            }
        },
    )
    logger.error("retention_campaign_failed campaign_id=%s error=%s", campaign_id, error)
