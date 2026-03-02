import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from pymongo import ReturnDocument

from task_queue import celery_app
from tasks._async_runner import run_async
from notification_service import send_push_to_user
from server import (
    BREVO_API_KEY2,
    BREVO_API_KEY,
    ENGAGEMENT_EMAILS_ENABLED,
    RETENTION_EMAIL_BATCH_SIZE,
    RETENTION_EMAIL_DAILY_LIMIT,
    RETENTION_EMAIL_MIN_DAYS_BETWEEN_SENDS,
    RETENTION_INSIGHTS_ENABLED,
    current_runtime_settings,
    db,
    get_generation_entitlement,
    resolve_brevo_sender_for_api_key,
    send_brevo_transactional_email,
)

logger = logging.getLogger(__name__)
RETENTION_TARGET_LOCK_MINUTES = 20
RETENTION_REQUEUE_SECONDS = 30
ENGAGEMENT_UPGRADE_SUBJECT = "You are already using your free Exam OS credits"
ENGAGEMENT_QUOTA_EXHAUSTED_SUBJECT = "Action needed: your Exam OS quota is exhausted"


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
    sent = await send_push_to_user(
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
    await db.notification_delivery_logs.insert_one(
        {
            "id": str(uuid.uuid4()),
            "channel": "push",
            "category": "generation_status",
            "user_id": user_id,
            "notification_id": doc["id"],
            "job_id": job_id,
            "status": "sent" if sent else "failed",
            "created_at": now.isoformat(),
        }
    )
    logger.info(
        "notification_saved user_id=%s job_id=%s status=%s result_reference=%s push_sent=%s",
        user_id,
        job_id,
        status,
        result_reference,
        sent,
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


@celery_app.task(
    bind=True,
    name="tasks.notifications.send_first_exam_upgrade_nudge",
    max_retries=3,
)
def send_first_exam_upgrade_nudge(self, user_id: str) -> None:
    try:
        run_async(_send_first_exam_upgrade_nudge_impl(user_id=user_id))
    except Exception as exc:
        delay = min(300, 30 * (2 ** self.request.retries))
        raise self.retry(exc=exc, countdown=delay)


async def _send_first_exam_upgrade_nudge_impl(user_id: str) -> None:
    if not ENGAGEMENT_EMAILS_ENABLED:
        return
    api_key = (BREVO_API_KEY2 or BREVO_API_KEY).strip()
    sender_email, sender_name = resolve_brevo_sender_for_api_key(api_key)
    if not api_key or not sender_email:
        logger.info("engagement_email_skip_missing_config user_id=%s", user_id)
        return

    user = await db.users.find_one({"id": user_id}, {"_id": 0, "email": 1, "full_name": 1})
    if not user or not str(user.get("email") or "").strip():
        logger.info("engagement_email_skip_missing_user user_id=%s", user_id)
        return

    now_iso = _utc_now_iso()
    claim = await db.user_usage_counters.find_one_and_update(
        {
            "user_id": user_id,
            "first_exam_upgrade_email_sent_at": {"$exists": False},
            "$or": [
                {"first_exam_upgrade_email_lock_until": {"$exists": False}},
                {"first_exam_upgrade_email_lock_until": {"$lte": now_iso}},
            ],
        },
        {
            "$set": {
                "first_exam_upgrade_email_lock_until": (
                    _utc_now() + timedelta(minutes=10)
                ).isoformat(),
                "updated_at": now_iso,
            }
        },
        upsert=True,
        projection={"_id": 0, "user_id": 1},
        return_document=ReturnDocument.AFTER,
    )
    if not claim:
        return

    try:
        entitlement = await get_generation_entitlement(user_id)
        if not bool(entitlement.get("is_free", True)):
            await db.user_usage_counters.update_one(
                {"user_id": user_id},
                {"$unset": {"first_exam_upgrade_email_lock_until": ""}},
            )
            return

        generation_used = int(entitlement.get("generation_used", 0))
        generation_limit = int(entitlement.get("generation_limit", 0))
        generation_remaining = int(entitlement.get("generation_remaining", 0))

        # Trigger the nudge right after the first exam generation.
        if generation_used < 1:
            await db.user_usage_counters.update_one(
                {"user_id": user_id},
                {"$unset": {"first_exam_upgrade_email_lock_until": ""}},
            )
            return

        full_name = str(user.get("full_name") or "").strip()
        first_name = (full_name.split(" ")[0] if full_name else "there").strip() or "there"
        monthly_price = int(current_runtime_settings().get("subscription_monthly_kes", 499))
        html = (
            f"<p>Hi {first_name},</p>"
            "<p>Great start. You have made your first exam generation on Exam OS.</p>"
            f"<p>Your current free credits: <strong>{generation_used}/{generation_limit}</strong> used "
            f"(remaining: <strong>{generation_remaining}</strong>).</p>"
            f"<p>To avoid interruption as your usage grows, consider upgrading to Monthly "
            f"(KES {monthly_price}) for higher generation and exam limits.</p>"
            "<p>Keep building great assessments.<br/>Exam OS Team</p>"
        )
        payload = {
            "sender": {"email": sender_email, "name": sender_name},
            "to": [{"email": str(user["email"]), "name": full_name or str(user["email"])}],
            "subject": ENGAGEMENT_UPGRADE_SUBJECT,
            "htmlContent": html,
        }
        await send_brevo_transactional_email(api_key=api_key, payload=payload)
        await db.user_usage_counters.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "first_exam_upgrade_email_sent_at": now_iso,
                    "updated_at": now_iso,
                },
                "$unset": {"first_exam_upgrade_email_lock_until": ""},
            },
            upsert=True,
        )
        logger.info(
            "engagement_email_sent type=first_exam_upgrade user_id=%s remaining=%s",
            user_id,
            generation_remaining,
        )
    except Exception as exc:
        await db.user_usage_counters.update_one(
            {"user_id": user_id},
            {"$unset": {"first_exam_upgrade_email_lock_until": ""}},
            upsert=True,
        )
        logger.error("engagement_email_failed user_id=%s error=%s", user_id, exc)
        raise


@celery_app.task(
    bind=True,
    name="tasks.notifications.send_quota_exhausted_nudge",
    max_retries=0,
)
def send_quota_exhausted_nudge(self, user_id: str, quota_type: str = "generation") -> None:
    try:
        run_async(_send_quota_exhausted_nudge_impl(user_id=user_id, quota_type=quota_type))
    except Exception as exc:
        logger.error(
            "engagement_quota_exhausted_email_failed user_id=%s quota_type=%s error=%s",
            user_id,
            quota_type,
            exc,
        )
        raise


async def _send_quota_exhausted_nudge_impl(user_id: str, quota_type: str) -> None:
    if not ENGAGEMENT_EMAILS_ENABLED:
        return

    normalized_type = "exam" if str(quota_type).strip().lower() == "exam" else "generation"
    api_key = (BREVO_API_KEY2 or BREVO_API_KEY).strip()
    sender_email, sender_name = resolve_brevo_sender_for_api_key(api_key)
    if not api_key or not sender_email:
        logger.info(
            "engagement_quota_exhausted_email_skip_missing_config user_id=%s quota_type=%s",
            user_id,
            normalized_type,
        )
        return

    user = await db.users.find_one({"id": user_id}, {"_id": 0, "email": 1, "full_name": 1})
    if not user or not str(user.get("email") or "").strip():
        logger.info(
            "engagement_quota_exhausted_email_skip_missing_user user_id=%s quota_type=%s",
            user_id,
            normalized_type,
        )
        return

    now = _utc_now()
    now_iso = now.isoformat()
    day_key = _daily_usage_key(now)
    lock_field = f"{normalized_type}_quota_exhausted_email_lock_until"
    day_field = f"{normalized_type}_quota_exhausted_email_day_key"
    sent_field = f"{normalized_type}_quota_exhausted_email_sent_at"

    claim = await db.user_usage_counters.find_one_and_update(
        {
            "user_id": user_id,
            day_field: {"$ne": day_key},
            "$or": [
                {lock_field: {"$exists": False}},
                {lock_field: {"$lte": now_iso}},
            ],
        },
        {
            "$set": {
                lock_field: (_utc_now() + timedelta(minutes=10)).isoformat(),
                "updated_at": now_iso,
            }
        },
        upsert=True,
        projection={"_id": 0, "user_id": 1},
        return_document=ReturnDocument.AFTER,
    )
    if not claim:
        return

    slot_reserved, reserved_day_key = await _reserve_daily_slot(now)
    if not slot_reserved:
        await db.user_usage_counters.update_one(
            {"user_id": user_id},
            {"$unset": {lock_field: ""}, "$set": {"updated_at": now_iso}},
            upsert=True,
        )
        logger.info(
            "engagement_quota_exhausted_email_skip_daily_limit user_id=%s quota_type=%s limit=%s",
            user_id,
            normalized_type,
            RETENTION_EMAIL_DAILY_LIMIT,
        )
        return

    try:
        entitlement = await get_generation_entitlement(user_id)
        runtime = current_runtime_settings()
        monthly_price = int(runtime.get("subscription_monthly_kes", 499))
        full_name = str(user.get("full_name") or "").strip()
        first_name = (full_name.split(" ")[0] if full_name else "there").strip() or "there"
        plan_name = str(entitlement.get("plan_name") or "Free")

        generation_used = int(entitlement.get("generation_used", 0))
        generation_limit = int(entitlement.get("generation_limit", 0))
        generation_remaining = int(entitlement.get("generation_remaining", 0))
        exam_limit = entitlement.get("exam_limit")
        exam_used = int(entitlement.get("exam_used") or 0) if exam_limit is not None else None
        exam_remaining = int(entitlement.get("exam_remaining") or 0) if exam_limit is not None else None

        if normalized_type == "exam":
            headline = "You have exhausted your exam generation quota"
            quota_line = (
                f"Exam quota: <strong>{exam_used or 0}/{int(exam_limit or 0)}</strong> used "
                f"(remaining: <strong>{exam_remaining or 0}</strong>)."
            )
            action_line = (
                f"Upgrade or renew your plan to continue generating exams without interruption "
                f"(Monthly starts at KES {monthly_price})."
            )
        else:
            headline = "You have exhausted your generation quota"
            quota_line = (
                f"Generation quota: <strong>{generation_used}/{generation_limit}</strong> used "
                f"(remaining: <strong>{generation_remaining}</strong>)."
            )
            action_line = (
                f"Upgrade to continue creating new outputs right away "
                f"(Monthly starts at KES {monthly_price})."
            )

        html = (
            f"<p>Hi {first_name},</p>"
            f"<p>{headline}.</p>"
            f"<p>Current plan: <strong>{plan_name}</strong>.</p>"
            f"<p>{quota_line}</p>"
            f"<p>{action_line}</p>"
            "<p>Need help choosing a plan? Reply to this email and our team will guide you.</p>"
            "<p>— Exam OS Team</p>"
        )
        payload = {
            "sender": {"email": sender_email, "name": sender_name},
            "to": [{"email": str(user["email"]), "name": full_name or str(user["email"])}],
            "subject": ENGAGEMENT_QUOTA_EXHAUSTED_SUBJECT,
            "htmlContent": html,
        }
        await send_brevo_transactional_email(api_key=api_key, payload=payload)
        await db.user_usage_counters.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    sent_field: now_iso,
                    day_field: day_key,
                    "updated_at": now_iso,
                },
                "$unset": {lock_field: ""},
            },
            upsert=True,
        )
        logger.info(
            "engagement_email_sent type=%s_quota_exhausted user_id=%s remaining_generation=%s remaining_exam=%s",
            normalized_type,
            user_id,
            generation_remaining,
            exam_remaining,
        )
    except Exception:
        await _release_daily_slot(reserved_day_key)
        await db.user_usage_counters.update_one(
            {"user_id": user_id},
            {"$unset": {lock_field: ""}, "$set": {"updated_at": _utc_now_iso()}},
            upsert=True,
        )
        raise


@celery_app.task(bind=True, name="tasks.notifications.process_retention_insight_campaign")
def process_retention_insight_campaign(self, campaign_id: str) -> Dict[str, Any]:
    return run_async(_process_retention_campaign_impl(self.request.id or "", campaign_id))


async def _process_retention_campaign_impl(worker_task_id: str, campaign_id: str) -> Dict[str, Any]:
    if not RETENTION_INSIGHTS_ENABLED:
        await _mark_campaign_failed(campaign_id, "Retention insights are disabled")
        return {"campaign_id": campaign_id, "status": "failed", "reason": "disabled"}
    sender_email2, _ = resolve_brevo_sender_for_api_key(BREVO_API_KEY2)
    if not BREVO_API_KEY2 or not sender_email2:
        await _mark_campaign_failed(campaign_id, "BREVO_API_KEY2 or sender for key2 missing")
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
    availability_line = "No active document retention timeline found yet."
    try:
        now = _utc_now()
        docs = await db.documents.find(
            {"user_id": user_id, "retention_expires_at": {"$exists": True}},
            {"_id": 0, "retention_expires_at": 1},
        ).to_list(200)
        parsed: list[datetime] = []
        for doc in docs:
            raw = str(doc.get("retention_expires_at") or "").strip()
            if not raw:
                continue
            dt = datetime.fromisoformat(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            parsed.append(dt)
        future = [dt for dt in parsed if dt > now]
        if future:
            next_expiry = min(future)
            expiring_soon = len([dt for dt in future if dt <= now + timedelta(days=3)])
            remaining = next_expiry - now
            if remaining.total_seconds() < 3600 * 24:
                remaining_label = f"{max(1, int(remaining.total_seconds() // 3600))} hour(s)"
            else:
                remaining_label = f"{max(1, remaining.days)} day(s)"
            availability_line = (
                f"Next document cleanup in about <strong>{remaining_label}</strong>"
                f" (expiring within 3 days: <strong>{expiring_soon}</strong>)."
            )
        elif parsed:
            availability_line = "Some document records are already at/after expiry and pending cleanup."
    except Exception as exc:
        logger.warning("retention_campaign_availability_compute_failed user_id=%s error=%s", user_id, exc)
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
        f"<p><strong>Document availability:</strong> {availability_line}</p>"
        "<p><strong>Recommended next step:</strong> "
        f"{next_step}</p>"
        "<p>Pro tip: combine Topic Board demand signals with Generation Lab prompts for faster exam planning.</p>"
        "<p>— Exam OS Team</p>"
    )

    sender_email, sender_name = resolve_brevo_sender_for_api_key(BREVO_API_KEY2)
    return {
        "sender": {"email": sender_email, "name": sender_name},
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
