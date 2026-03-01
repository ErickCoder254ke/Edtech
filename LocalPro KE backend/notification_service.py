from typing import List, Dict, Optional
import logging
import firebase_admin
from firebase_admin import credentials, messaging
import os

logger = logging.getLogger(__name__)

# Initialize Firebase Admin SDK
_firebase_initialized = False

def initialize_firebase():
    """Initialize Firebase Admin SDK with service account"""
    global _firebase_initialized

    if _firebase_initialized:
        logger.debug("Firebase Admin SDK already initialized, skipping...")
        return

    try:
        logger.info("🔧 Attempting to initialize Firebase Admin SDK...")

        # Try to get service account from environment variable (JSON string)
        service_account_json = os.getenv('FIREBASE_SERVICE_ACCOUNT_JSON')

        if service_account_json:
            # Use service account from environment variable (Render secret)
            logger.info("📋 Found FIREBASE_SERVICE_ACCOUNT_JSON environment variable")

            try:
                import json
                service_account_dict = json.loads(service_account_json)

                # Validate that the JSON has required fields
                required_fields = ['project_id', 'private_key', 'client_email']
                missing_fields = [field for field in required_fields if field not in service_account_dict]

                if missing_fields:
                    logger.error(f"❌ Service account JSON is missing required fields: {missing_fields}")
                    raise ValueError(f"Invalid service account JSON: missing {missing_fields}")

                cred = credentials.Certificate(service_account_dict)
                logger.info(f"✅ Using Firebase service account from environment variable")
                logger.info(f"   Project ID: {service_account_dict.get('project_id')}")
                logger.info(f"   Client Email: {service_account_dict.get('client_email')}")

            except json.JSONDecodeError as e:
                logger.error(f"❌ Failed to parse FIREBASE_SERVICE_ACCOUNT_JSON: {e}")
                logger.error("   Make sure the environment variable contains valid JSON")
                raise ValueError(f"Invalid JSON in FIREBASE_SERVICE_ACCOUNT_JSON: {e}")

        else:
            # Fall back to file path
            logger.warning("⚠️ FIREBASE_SERVICE_ACCOUNT_JSON not found, trying file path...")

            service_account_path = os.getenv(
                'FIREBASE_SERVICE_ACCOUNT_PATH',
                './churchapp-3efc3-firebase-adminsdk-fbsvc-383637106d.json'
            )

            logger.info(f"📁 Looking for service account file at: {service_account_path}")

            if not os.path.exists(service_account_path):
                logger.error(f"❌ Firebase service account file not found at: {service_account_path}")
                logger.error("❌ Please set FIREBASE_SERVICE_ACCOUNT_JSON environment variable")
                logger.error("   OR place the service account file in the backend directory")
                logger.error("   Deployment Guide: See DEPLOYMENT_GUIDE_RENDER.md or RENDER_DEPLOYMENT_CHECKLIST.md")
                raise FileNotFoundError(f"Firebase service account file not found: {service_account_path}")

            cred = credentials.Certificate(service_account_path)
            logger.info(f"✅ Using Firebase service account from file: {service_account_path}")

        # Initialize Firebase with the credentials
        firebase_admin.initialize_app(cred)
        _firebase_initialized = True
        logger.info("✅ Firebase Admin SDK initialized successfully")
        logger.info("🔔 Push notifications are now enabled")

    except ValueError as e:
        # Configuration error (invalid JSON, missing fields, etc.)
        logger.error(f"❌ Configuration error: {e}")
        logger.error("⚠️ Push notifications will NOT work until this is fixed")
        raise

    except FileNotFoundError as e:
        # Service account file not found
        logger.error(f"❌ File not found error: {e}")
        logger.error("⚠️ Push notifications will NOT work until this is fixed")
        raise

    except Exception as e:
        # Unexpected error
        logger.error(f"❌ Unexpected error initializing Firebase Admin SDK: {e}")
        logger.error(f"   Error type: {type(e).__name__}")
        import traceback
        logger.error(f"   Traceback: {traceback.format_exc()}")
        logger.error("⚠️ Push notifications will NOT work until this is fixed")
        raise


class NotificationService:
    """Service for sending push notifications via Firebase Cloud Messaging HTTP v1"""
    
    @staticmethod
    def send_push_notification(
        fcm_token: str,
        title: str,
        body: str,
        data: Optional[Dict] = None
    ) -> bool:
        """
        Send a push notification to a single device using FCM HTTP v1

        Args:
            fcm_token: Native FCM device token (NOT Expo push token)
            title: Notification title
            body: Notification body
            data: Additional data to send with notification

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Validate inputs
            if not fcm_token or not isinstance(fcm_token, str) or len(fcm_token) < 10:
                logger.error(f"🔔 [PUSH] ❌ Invalid FCM token: {fcm_token}")
                return False

            if not title or not body:
                logger.error(f"🔔 [PUSH] ❌ Title and body are required")
                return False

            # Ensure Firebase is initialized
            try:
                initialize_firebase()
            except Exception as init_error:
                logger.error(f"🔔 [PUSH] ❌ Firebase not initialized: {init_error}")
                logger.error("🔔 [PUSH] ❌ Cannot send push notification without Firebase")
                return False

            logger.info(f"🔔 [PUSH] Attempting to send FCM push notification")
            logger.info(f"🔔 [PUSH] Token: {fcm_token[:50]}..." if len(fcm_token) > 50 else f"🔔 [PUSH] Token: {fcm_token}")
            logger.info(f"🔔 [PUSH] Title: {title}")
            logger.info(f"🔔 [PUSH] Body: {body}")

            # Prepare notification data
            notification_data = data or {}
            
            # Convert all data values to strings (FCM requirement)
            notification_data = {k: str(v) for k, v in notification_data.items()}

            # Create FCM message
            message = messaging.Message(
                notification=messaging.Notification(
                    title=title,
                    body=body,
                ),
                data=notification_data,
                token=fcm_token,
                android=messaging.AndroidConfig(
                    priority='high',
                    notification=messaging.AndroidNotification(
                        sound='default',
                        channel_id='default',
                        color='#2196F3',  # LocalPro KE brand color (Blue)
                        default_sound=True,
                        default_vibrate_timings=True,
                    )
                ),
                apns=messaging.APNSConfig(
                    payload=messaging.APNSPayload(
                        aps=messaging.Aps(
                            sound='default',
                            badge=1,
                        )
                    )
                )
            )

            logger.info(f"🔔 [PUSH] Sending message via FCM HTTP v1...")
            response = messaging.send(message)
            
            logger.info(f"🔔 [PUSH] ✅ Push notification sent successfully!")
            logger.info(f"🔔 [PUSH] ✅ FCM Message ID: {response}")
            return True

        except messaging.UnregisteredError:
            logger.warning(f"🔔 [PUSH] ⚠️ FCM token no longer valid: {fcm_token[:20]}...")
            logger.warning(f"🔔 [PUSH] ⚠️ The app likely uninstalled or token expired")
            return False
        except messaging.SenderIdMismatchError:
            logger.error(f"🔔 [PUSH] ❌ Sender ID mismatch - token belongs to different Firebase project")
            return False
        except messaging.QuotaExceededError:
            logger.error(f"🔔 [PUSH] ❌ FCM quota exceeded - too many messages sent")
            return False
        except messaging.ApiCallError as e:
            logger.error(f"🔔 [PUSH] ❌ FCM API error: {e}")
            return False
        except Exception as e:
            logger.error(f"🔔 [PUSH] ❌ Unexpected error sending push: {e}")
            import traceback
            logger.error(f"🔔 [PUSH] ❌ Traceback: {traceback.format_exc()}")
            return False
    
    @staticmethod
    def send_batch_notifications(
        notifications: List[Dict]
    ) -> Dict[str, int]:
        """
        Send multiple push notifications at once using FCM HTTP v1
        
        Args:
            notifications: List of dicts with keys: fcm_token, title, body, data
            
        Returns:
            Dict with success and failure counts
        """
        try:
            # Ensure Firebase is initialized
            initialize_firebase()
            
            messages = []
            for notif in notifications:
                # Convert all data values to strings
                notification_data = notif.get('data', {})
                notification_data = {k: str(v) for k, v in notification_data.items()}
                
                messages.append(
                    messaging.Message(
                        notification=messaging.Notification(
                            title=notif['title'],
                            body=notif['body'],
                        ),
                        data=notification_data,
                        token=notif['fcm_token'],
                        android=messaging.AndroidConfig(
                            priority='high',
                            notification=messaging.AndroidNotification(
                                sound='default',
                                channel_id='default',
                                color='#FF6B6B',
                            )
                        ),
                    )
                )
            
            # Send all messages in batch
            response = messaging.send_all(messages)
            
            success_count = response.success_count
            failure_count = response.failure_count
            
            logger.info(f"🔔 [BATCH] Sent {success_count}/{len(messages)} notifications successfully")
            
            if failure_count > 0:
                for idx, resp in enumerate(response.responses):
                    if not resp.success:
                        logger.error(f"🔔 [BATCH] Failed to send notification {idx}: {resp.exception}")
            
            return {
                'success': success_count,
                'failed': failure_count,
                'total': len(messages)
            }
            
        except Exception as e:
            logger.error(f"🔔 [BATCH] Batch notification error: {e}")
            return {'success': 0, 'failed': len(notifications), 'total': len(notifications)}


class NotificationType:
    # Order notifications
    ORDER_CREATED = "order_created"  # Seller receives when buyer creates order
    ORDER_PLACED = "order_placed"  # Buyer receives confirmation of order placement
    ORDER_UPDATED = "order_updated"  # Generic order update
    ORDER_CONFIRMED = "order_confirmed"
    ORDER_CANCELLED = "order_cancelled"

    # Payment notifications
    PAYMENT_RECEIVED = "payment_received"
    PAYMENT_FAILED = "payment_failed"

    # Delivery fee notifications
    DELIVERY_FEE_REQUIRED = "delivery_fee_required"  # Seller needs to set delivery fee
    DELIVERY_FEE_SET = "delivery_fee_set"  # Seller has set delivery fee
    DELIVERY_FEE_PAID = "delivery_fee_paid"  # Buyer has paid delivery fee

    # Other notifications
    NEW_MESSAGE = "new_message"
    REVIEW_RECEIVED = "review_received"
    LISTING_APPROVED = "listing_approved"
    LISTING_REJECTED = "listing_rejected"
    WITHDRAWAL_PROCESSED = "withdrawal_processed"


async def create_notification(
    db,
    user_id: str,
    notification_type: str,
    title: str,
    message: str,
    data: Optional[Dict] = None,
    send_push: bool = True
) -> dict:
    """
    Create a notification and optionally send push notification via FCM HTTP v1

    Args:
        db: Database connection
        user_id: User to notify
        notification_type: Type of notification
        title: Notification title
        message: Notification message
        data: Additional data (order_id, pet_id, etc.)
        send_push: Whether to send push notification

    Returns:
        Created notification document
    """
    from datetime import datetime
    from bson import ObjectId

    logger.info(f"🔔 [NOTIF] Creating notification for user {user_id}")
    logger.info(f"🔔 [NOTIF] Type: {notification_type}, Title: {title}")

    notification_data = {
        'user_id': user_id,
        'type': notification_type,
        'title': title,
        'message': message,
        'data': data or {},
        'read': False,
        'created_at': datetime.utcnow()
    }

    result = await db.notifications.insert_one(notification_data)
    notification_data['_id'] = result.inserted_id
    logger.info(f"🔔 [NOTIF] ✅ Notification created in DB with ID: {result.inserted_id}")

    if send_push:
        logger.info(f"🔔 [NOTIF] send_push=True, checking for user's FCM token...")
        logger.info(f"🔔 [NOTIF] Looking up user with ID: {user_id} (type: {type(user_id).__name__})")

        try:
            # Convert user_id to ObjectId for lookup
            user_object_id = ObjectId(user_id)
            logger.info(f"🔔 [NOTIF] Converted to ObjectId: {user_object_id}")

            user = await db.users.find_one({'_id': user_object_id})

            if not user:
                logger.error(f"🔔 [NOTIF] ❌ User document not found for ID: {user_id}")
                logger.error(f"🔔 [NOTIF] ❌ Query used: {{'_id': {user_object_id}}}")
                return notification_data

            logger.info(f"🔔 [NOTIF] ✅ User document found: {user.get('name', 'Unknown')} (email: {user.get('email', 'N/A')})")

            fcm_token = user.get('fcm_token')
            if fcm_token:
                logger.info(f"🔔 [NOTIF] ✅ User has FCM token (length: {len(fcm_token)}), sending push notification...")
                success = NotificationService.send_push_notification(
                    fcm_token=fcm_token,
                    title=title,
                    body=message,
                    data=data
                )
                if success:
                    logger.info(f"🔔 [NOTIF] ✅ Push notification sent successfully to {user.get('name', 'Unknown')}")
                else:
                    logger.error(f"🔔 [NOTIF] ❌ Push notification failed to send to {user.get('name', 'Unknown')}")
            else:
                logger.warning(f"🔔 [NOTIF] ⚠️ User {user.get('name', 'Unknown')} has no FCM token - skipping push notification")
                logger.warning(f"🔔 [NOTIF] ⚠️ User needs to login on a physical device to register FCM token")

        except Exception as user_lookup_error:
            logger.error(f"🔔 [NOTIF] ❌ Error looking up user: {user_lookup_error}")
            import traceback
            logger.error(f"🔔 [NOTIF] ❌ Traceback: {traceback.format_exc()}")
    else:
        logger.info(f"🔔 [NOTIF] send_push=False, skipping push notification")

    return notification_data
