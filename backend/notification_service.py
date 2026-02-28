import json
import logging
import os
from typing import Any, Dict, Optional

import firebase_admin
from firebase_admin import credentials, messaging

logger = logging.getLogger(__name__)

_firebase_initialized = False


def _is_firebase_enabled() -> bool:
    return os.environ.get("FIREBASE_ENABLED", "false").strip().lower() == "true"


def _resolve_credentials() -> Optional[credentials.Base]:
    service_account_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON", "").strip()
    if service_account_json:
        try:
            parsed = json.loads(service_account_json)
            return credentials.Certificate(parsed)
        except Exception as exc:
            logger.error("firebase_credentials_json_invalid error=%s", exc)
            return None

    service_account_path = os.environ.get("FIREBASE_SERVICE_ACCOUNT_PATH", "").strip()
    if service_account_path and os.path.exists(service_account_path):
        try:
            return credentials.Certificate(service_account_path)
        except Exception as exc:
            logger.error("firebase_credentials_file_invalid path=%s error=%s", service_account_path, exc)
            return None
    return None


def initialize_firebase() -> bool:
    global _firebase_initialized
    if _firebase_initialized:
        return True
    if not _is_firebase_enabled():
        logger.info("firebase_disabled")
        return False

    cred = _resolve_credentials()
    if cred is None:
        logger.warning("firebase_credentials_missing_or_invalid")
        return False
    try:
        firebase_admin.initialize_app(cred)
        _firebase_initialized = True
        logger.info("firebase_initialized")
        return True
    except Exception as exc:
        logger.error("firebase_init_failed error=%s", exc)
        return False


def send_push_notification(
    fcm_token: str,
    title: str,
    body: str,
    data: Optional[Dict[str, Any]] = None,
) -> bool:
    if not fcm_token:
        return False
    if not initialize_firebase():
        return False

    payload = {str(k): str(v) for k, v in (data or {}).items()}
    try:
        message = messaging.Message(
            notification=messaging.Notification(title=title, body=body),
            data=payload,
            token=fcm_token,
            android=messaging.AndroidConfig(
                priority="high",
                notification=messaging.AndroidNotification(
                    channel_id="exam_os_alerts",
                    sound="default",
                ),
            ),
            apns=messaging.APNSConfig(
                payload=messaging.APNSPayload(
                    aps=messaging.Aps(sound="default", badge=1),
                ),
            ),
        )
        messaging.send(message)
        return True
    except messaging.UnregisteredError:
        logger.warning("push_send_unregistered_token")
        return False
    except Exception as exc:
        logger.error("push_send_failed error=%s", exc)
        return False


async def send_push_to_user(
    db,
    user_id: str,
    title: str,
    body: str,
    data: Optional[Dict[str, Any]] = None,
) -> bool:
    user = await db.users.find_one({"id": user_id}, {"_id": 0, "id": 1, "fcm_token": 1})
    if not user:
        return False
    token = (user.get("fcm_token") or "").strip()
    if not token:
        return False

    sent = send_push_notification(token, title=title, body=body, data=data)
    if not sent:
        logger.info("push_not_sent user_id=%s", user_id)
    return sent
