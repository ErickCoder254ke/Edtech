import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Any

from task_queue import celery_app
from tasks._async_runner import run_async
from server import db

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="tasks.analytics.run_heavy_analytics")
def run_heavy_analytics(self, user_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    return run_async(_run_heavy_analytics_impl(user_id, payload))


async def _run_heavy_analytics_impl(user_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    # Reserved for future high-cost analytics workloads.
    # Keep this task idempotent by deriving a deterministic summary from payload.
    await asyncio.sleep(0.1)
    summary = {
        "user_id": user_id,
        "input_keys": sorted(list(payload.keys())),
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.analytics_runs.insert_one(
        {
            "user_id": user_id,
            "summary": summary,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    logger.info("analytics_task_completed user_id=%s keys=%s", user_id, summary["input_keys"])
    return summary
