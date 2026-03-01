from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, UploadFile, File, WebSocket, Request
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr, validator
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from bson import ObjectId
import jwt
import html
from urllib.parse import quote, urlencode
import bcrypt
from enum import Enum
import cloudinary
import cloudinary.uploader
import base64
import io
import uuid
import socketio
from urllib import parse as urlparse
import httpx
import re
import secrets
import hashlib
import hmac
import json
import time
import asyncio
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.starlette import StarletteIntegration
try:
    import redis.asyncio as redis
    HAS_REDIS = True
except Exception:
    HAS_REDIS = False
from mpesa_service import mpesa_service
from moderation_service import moderation_service
from websocket_handler import websocket_endpoint
from notification_service import NotificationService, create_notification, NotificationType, initialize_firebase
from google_calendar_service import initialize_calendar_service

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Environment
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'development').lower()

# Sentry (optional): enable error monitoring when SENTRY_DSN is provided
SENTRY_DSN = os.environ.get('SENTRY_DSN', '').strip()
if SENTRY_DSN:
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        environment=os.environ.get('SENTRY_ENVIRONMENT', ENVIRONMENT),
        traces_sample_rate=float(os.environ.get('SENTRY_TRACES_SAMPLE_RATE', '0.2')),
        integrations=[
            FastApiIntegration(),
            StarletteIntegration(),
        ],
    )
    logger.info("✅ Sentry monitoring initialized")

# Validate required environment variables
REQUIRED_ENV_VARS = ['MONGO_URL', 'DB_NAME']
if ENVIRONMENT == 'production':
    REQUIRED_ENV_VARS.append('JWT_SECRET')

missing_vars = [var for var in REQUIRED_ENV_VARS if not os.environ.get(var)]

if missing_vars:
    error_msg = f"""
    ❌ CONFIGURATION ERROR: Missing required environment variables

    Missing variables: {', '.join(missing_vars)}

    Please set the following environment variables:
    - MONGO_URL: MongoDB connection string
    - DB_NAME: Database name

    For Railway deployment, add these in the Variables tab.
    See RAILWAY_ENV_SETUP.md for detailed instructions.
    """
    logger.error(error_msg)
    raise EnvironmentError(error_msg)

logger.info("✅ Required environment variables validated")

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]
logger.info(f"✅ MongoDB connection configured for database: {os.environ['DB_NAME']}")

# Cloudinary Configuration
cloudinary.config(
    cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME'),
    api_key=os.environ.get('CLOUDINARY_API_KEY'),
    api_secret=os.environ.get('CLOUDINARY_API_SECRET'),
    secure=True
)

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET')
if not JWT_SECRET:
    if ENVIRONMENT == 'production':
        raise EnvironmentError("❌ CONFIGURATION ERROR: JWT_SECRET must be set in production")
    JWT_SECRET = secrets.token_urlsafe(32)
    logger.warning("⚠️  JWT_SECRET not set. Generated a temporary dev secret; tokens will reset on restart.")
    # Make the dev secret available to websocket_handler (reads from env at runtime)
    os.environ['JWT_SECRET'] = JWT_SECRET
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = int(os.environ.get('ACCESS_TOKEN_TTL_HOURS', 1))  # 1 hour
REFRESH_TOKEN_TTL_DAYS = int(os.environ.get('REFRESH_TOKEN_TTL_DAYS', 30))
TRANSACTION_HASH_SECRET = os.environ.get('TRANSACTION_HASH_SECRET')
if ENVIRONMENT == 'production' and not TRANSACTION_HASH_SECRET:
    raise EnvironmentError("❌ CONFIGURATION ERROR: TRANSACTION_HASH_SECRET must be set in production")

security = HTTPBearer()

# Request limits and upload validation
MAX_REQUEST_BYTES = int(os.environ.get('MAX_REQUEST_BYTES', 10 * 1024 * 1024))  # 10 MB
MAX_IMAGE_BYTES = int(os.environ.get('MAX_IMAGE_BYTES', 5 * 1024 * 1024))  # 5 MB
ALLOWED_IMAGE_CONTENT_TYPES = {
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
}

# Rate limiting (basic in-memory)
RATE_LIMIT_REQUESTS = int(os.environ.get('RATE_LIMIT_REQUESTS', 300))
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get('RATE_LIMIT_WINDOW_SECONDS', 60))
REDIS_URL = os.environ.get('REDIS_URL')

# Safety limits for early-stage production (per Phase 1 remediation guide)
# These conservative limits protect against fraud until Phase 2 security measures are in place
MAX_WALLET_BALANCE = float(os.environ.get('MAX_WALLET_BALANCE', 10000))  # KES - Max balance per wallet
MAX_SINGLE_TRANSACTION = float(os.environ.get('MAX_SINGLE_TRANSACTION', 5000))  # KES - Max single transaction
WITHDRAWAL_DAILY_LIMIT = float(os.environ.get('WITHDRAWAL_DAILY_LIMIT', 10000))  # KES - Reduced from 50K for safety
WITHDRAWAL_DAILY_COUNT = int(os.environ.get('WITHDRAWAL_DAILY_COUNT', 3))
WITHDRAWAL_VELOCITY_WINDOW_MINUTES = int(os.environ.get('WITHDRAWAL_VELOCITY_WINDOW_MINUTES', 60))
WITHDRAWAL_VELOCITY_COUNT = int(os.environ.get('WITHDRAWAL_VELOCITY_COUNT', 2))
WITHDRAWAL_MANUAL_REVIEW_THRESHOLD = float(os.environ.get('WITHDRAWAL_MANUAL_REVIEW_THRESHOLD', 20000))  # Anything >20K needs admin approval
WITHDRAWAL_MIN_ACCOUNT_AGE_HOURS = int(os.environ.get('WITHDRAWAL_MIN_ACCOUNT_AGE_HOURS', 48))  # 48 hour cooling period
_rate_limit_store = {}
_rate_limit_rule_store = {}
reconciliation_task: Optional[asyncio.Task] = None
integrity_task: Optional[asyncio.Task] = None
chat_contact_cleanup_task: Optional[asyncio.Task] = None
redis_client = redis.from_url(REDIS_URL, decode_responses=True) if (HAS_REDIS and REDIS_URL) else None
CHAT_CONTACT_CLEANUP_INTERVAL_HOURS = int(os.environ.get('CHAT_CONTACT_CLEANUP_INTERVAL_HOURS', 6))

# Per-endpoint rate limits for high-risk routes (override global limits)
RATE_LIMIT_RULES = [
    {'name': 'auth_login', 'path': '/api/auth/login', 'method': 'POST', 'limit': 10, 'window': 60},
    {'name': 'auth_register', 'path': '/api/auth/register', 'method': 'POST', 'limit': 5, 'window': 60},
    {'name': 'auth_forgot', 'path': '/api/auth/forgot-password', 'method': 'POST', 'limit': 5, 'window': 60},
    {'name': 'auth_forgot_verify', 'path': '/api/auth/forgot-password/verify', 'method': 'POST', 'limit': 10, 'window': 60},
    {'name': 'auth_refresh', 'path': '/api/auth/refresh', 'method': 'POST', 'limit': 20, 'window': 60},
    {'name': 'auth_google', 'path': '/api/auth/google', 'method': 'POST', 'limit': 10, 'window': 60},
    {'name': 'auth_google_initiate', 'path': '/api/auth/google/initiate', 'method': 'POST', 'limit': 10, 'window': 60},
    {'name': 'auth_google_complete', 'path': '/api/auth/google/complete', 'method': 'POST', 'limit': 10, 'window': 60}
]

# Security event logging
SECURITY_EVENT_RETENTION_DAYS = int(os.environ.get('SECURITY_EVENT_RETENTION_DAYS', 365))
ALERT_ADMIN_SECURITY_EVENTS = os.environ.get('ALERT_ADMIN_SECURITY_EVENTS', 'true').lower() == 'true'

# Webhook security (optional)
MPESA_WEBHOOK_SECRET = os.environ.get('MPESA_WEBHOOK_SECRET')
MPESA_ENVIRONMENT = os.environ.get('MPESA_ENVIRONMENT', 'sandbox').lower()
MPESA_ALLOWED_IPS = [ip.strip() for ip in os.environ.get('MPESA_ALLOWED_IPS', '').split(',') if ip.strip()]

IDEMPOTENCY_TTL_SECONDS = int(os.environ.get('IDEMPOTENCY_TTL_SECONDS', 3600))

def _hash_request_payload(payload: dict) -> str:
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(payload_bytes).hexdigest()

async def _get_idempotency_response(
    key: str,
    scope: str,
    user_id: str,
    request_hash: str
) -> Optional[dict]:
    record = await db.idempotency_keys.find_one({
        'key': key,
        'scope': scope,
        'user_id': user_id
    })

    if not record:
        await db.idempotency_keys.insert_one({
            'key': key,
            'scope': scope,
            'user_id': user_id,
            'request_hash': request_hash,
            'status': 'in_progress',
            'created_at': datetime.utcnow(),
            'expires_at': datetime.utcnow() + timedelta(seconds=IDEMPOTENCY_TTL_SECONDS)
        })
        return None

    if record.get('request_hash') != request_hash:
        raise HTTPException(status_code=409, detail="Idempotency key reuse with different payload")

    if record.get('status') == 'completed' and record.get('response') is not None:
        return record.get('response')

    if record.get('status') == 'in_progress':
        raise HTTPException(status_code=409, detail="Request is already in progress")

    return None

async def _finalize_idempotency(
    key: str,
    scope: str,
    user_id: str,
    response: dict,
    status: str = 'completed'
) -> None:
    await db.idempotency_keys.update_one(
        {'key': key, 'scope': scope, 'user_id': user_id},
        {'$set': {'status': status, 'response': response, 'completed_at': datetime.utcnow()}}
    )

def _require_idempotency_key(request: Request) -> str:
    key = request.headers.get('Idempotency-Key')
    if not key:
        raise HTTPException(status_code=400, detail="Idempotency-Key header is required for payment operations")
    return key

def _round_payment_amount(amount: float) -> float:
    """Round amount to nearest whole based on 0.5 rule for production payments."""
    try:
        base = float(amount)
    except Exception:
        return amount
    fractional = base - int(base)
    if fractional < 0.5:
        return float(int(base))
    return float(int(base) + 1)


def _amount_matches(amount_paid: Optional[float], expected_amount: float) -> bool:
    try:
        if amount_paid is None:
            return False
        if MPESA_ENVIRONMENT == 'production':
            expected_amount = _round_payment_amount(expected_amount)
        tolerance = RECONCILIATION_TOLERANCE_PROD if MPESA_ENVIRONMENT == 'production' else RECONCILIATION_TOLERANCE_DEV
        return abs(float(amount_paid) - float(expected_amount)) <= tolerance
    except Exception:
        return False

def _verify_webhook_signature(payload: dict, signature: Optional[str]) -> None:
    # Daraja sandbox does not send signatures. Only enforce for live environment.
    if MPESA_ENVIRONMENT != 'production':
        if not signature:
            logger.warning("⚠️  Missing webhook signature (sandbox). Skipping verification.")
            return
        if not MPESA_WEBHOOK_SECRET:
            logger.warning("⚠️  MPESA_WEBHOOK_SECRET not set (sandbox). Skipping verification.")
            return
    else:
        if not MPESA_WEBHOOK_SECRET:
            raise HTTPException(
                status_code=500,
                detail="SECURITY ERROR: MPESA_WEBHOOK_SECRET not configured"
            )
        if not signature:
            raise HTTPException(status_code=401, detail="Missing webhook signature")
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
    digest = hmac.new(MPESA_WEBHOOK_SECRET.encode('utf-8'), payload_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(digest, signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

def _extract_request_ip(request: Request) -> Optional[str]:
    forwarded_for = request.headers.get('X-Forwarded-For') or request.headers.get('x-forwarded-for')
    if forwarded_for:
        # Use the left-most IP (original client)
        return forwarded_for.split(',')[0].strip()
    forwarded = request.headers.get('Forwarded') or request.headers.get('forwarded')
    if forwarded:
        # Example: Forwarded: for=203.0.113.43;proto=https;by=203.0.113.44
        parts = forwarded.split(';')
        for part in parts:
            if part.strip().lower().startswith('for='):
                return part.split('=', 1)[1].strip().strip('"')
    real_ip = request.headers.get('X-Real-IP') or request.headers.get('x-real-ip')
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else None

def _verify_webhook_ip(request: Request) -> None:
    if not MPESA_ALLOWED_IPS:
        if ENVIRONMENT == 'production':
            raise HTTPException(
                status_code=500,
                detail="SECURITY ERROR: MPESA_ALLOWED_IPS not configured"
            )
        logger.warning("⚠️  Webhook IP allowlist disabled (dev only)")
        return
    client_ip = _extract_request_ip(request)
    if not client_ip or client_ip not in MPESA_ALLOWED_IPS:
        raise HTTPException(status_code=403, detail="Webhook IP not allowed")

def _validate_mpesa_callback_schema(payload: dict) -> Optional[str]:
    """Basic schema validation for M-Pesa STK callback payload."""
    if not isinstance(payload, dict):
        return "Payload must be an object"
    body = payload.get('Body')
    if not isinstance(body, dict):
        return "Missing Body"
    stk_callback = body.get('stkCallback')
    if not isinstance(stk_callback, dict):
        return "Missing stkCallback"
    if stk_callback.get('CheckoutRequestID') is None:
        return "Missing CheckoutRequestID"
    if stk_callback.get('ResultCode') is None:
        return "Missing ResultCode"
    return None

async def _ensure_mpesa_callback_idempotent(checkout_request_id: str) -> bool:
    """Return True if already processed, otherwise mark as pending."""
    existing = await db.mpesa_callbacks.find_one({'checkout_request_id': checkout_request_id})
    if existing:
        return existing.get('status') == 'processed'
    await db.mpesa_callbacks.insert_one({
        'checkout_request_id': checkout_request_id,
        'status': 'pending',
        'created_at': datetime.utcnow(),
        'updated_at': datetime.utcnow()
    })
    return False

async def _mark_mpesa_callback_processed(checkout_request_id: str, status: str, details: dict):
    await db.mpesa_callbacks.update_one(
        {'checkout_request_id': checkout_request_id},
        {'$set': {
            'status': status,
            'details': details,
            'updated_at': datetime.utcnow()
        }},
        upsert=True
    )

def _match_rate_limit_rule(path: str, method: str) -> Optional[dict]:
    for rule in RATE_LIMIT_RULES:
        if rule['path'] == path and rule['method'] == method:
            return rule
    return None

def _is_rate_limited(store: dict, key: str, limit: int, window_seconds: int) -> bool:
    now = time.time()
    window_start = now - window_seconds
    timestamps = store.get(key, [])
    timestamps = [t for t in timestamps if t >= window_start]
    if len(timestamps) >= limit:
        store[key] = timestamps
        return True
    timestamps.append(now)
    store[key] = timestamps
    return False

async def _is_rate_limited_redis(key: str, limit: int, window_seconds: int) -> bool:
    """Redis-based sliding window rate limiter."""
    if not redis_client:
        return False
    now = time.time()
    window_start = now - window_seconds
    pipe = redis_client.pipeline()
    pipe.zremrangebyscore(key, 0, window_start)
    pipe.zcard(key)
    pipe.zadd(key, {str(now): now})
    pipe.expire(key, window_seconds)
    results = await pipe.execute()
    request_count = results[1]
    return request_count >= limit

# Security middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        if ENVIRONMENT == 'production':
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response

class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get('content-length')
        if content_length:
            try:
                if int(content_length) > MAX_REQUEST_BYTES:
                    return JSONResponse(
                        status_code=413,
                        content={'detail': 'Request size exceeds limit'}
                    )
            except ValueError:
                pass
        return await call_next(request)

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Only apply to API routes
        if not request.url.path.startswith('/api'):
            return await call_next(request)

        client_ip = request.client.host if request.client else 'unknown'
        path = request.url.path
        method = request.method.upper()

        rule = _match_rate_limit_rule(path, method)
        if rule:
            rule_key = f"{rule['name']}:{client_ip}"
            if (
                (await _is_rate_limited_redis(f"ratelimit:{rule_key}", rule['limit'], rule['window']))
                if redis_client else
                _is_rate_limited(_rate_limit_rule_store, rule_key, rule['limit'], rule['window'])
            ):
                await log_security_event(
                    event_type='rate_limit_exceeded',
                    severity='medium',
                    details={'path': path, 'rule': rule['name']},
                    user_id=None,
                    request=request
                )
                return JSONResponse(
                    status_code=429,
                    content={'detail': 'Rate limit exceeded. Please try again later.'}
                )
        else:
            global_key = f"global:{client_ip}"
            if (
                (await _is_rate_limited_redis(f"ratelimit:{global_key}", RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS))
                if redis_client else
                _is_rate_limited(_rate_limit_store, global_key, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS)
            ):
                await log_security_event(
                    event_type='rate_limit_exceeded',
                    severity='medium',
                    details={'path': path},
                    user_id=None,
                    request=request
                )
                return JSONResponse(
                    status_code=429,
                    content={'detail': 'Rate limit exceeded. Please try again later.'}
                )

        return await call_next(request)

class SafeHTTPSRedirectMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/health":
            return await call_next(request)
        forwarded_proto = request.headers.get('X-Forwarded-Proto') or request.headers.get('x-forwarded-proto')
        if forwarded_proto and forwarded_proto.lower() == 'https':
            return await call_next(request)
        if request.url.scheme == "http":
            return RedirectResponse(url=str(request.url.replace(scheme="https")))
        return await call_next(request)

# Create the main app
app = FastAPI(title="LocalPro KE API")
api_router = APIRouter(prefix="/api")

if ENVIRONMENT == 'production':
    app.add_middleware(SafeHTTPSRedirectMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestSizeLimitMiddleware)
app.add_middleware(RateLimitMiddleware)

# Socket.IO setup for real-time chat
WEBSOCKET_ALLOWED_ORIGINS = [o.strip() for o in os.environ.get('WEBSOCKET_ALLOWED_ORIGINS', '').split(',') if o.strip()]
socket_origins = WEBSOCKET_ALLOWED_ORIGINS if WEBSOCKET_ALLOWED_ORIGINS else '*'
sio = socketio.AsyncServer(
    async_mode='asgi',
    cors_allowed_origins=socket_origins,
    logger=True,
    engineio_logger=False
)

# Connected users store for Socket.IO
connected_users = {}

async def _get_socket_user(sid: str) -> Optional[str]:
    session = await sio.get_session(sid)
    return session.get('user_id') if session else None

async def _authenticate_socket(environ: dict) -> Optional[dict]:
    query_string = environ.get('QUERY_STRING', '')
    params = dict(urlparse.parse_qsl(query_string))
    token = params.get('token')
    if not token:
        return None

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get('user_id')
        if not user_id:
            return None
        user = await db.users.find_one({'_id': ObjectId(user_id)})
        if not user or user.get('suspended', False):
            return None
        return {'user_id': user_id, 'role': user.get('role')}
    except Exception:
        return None

# Enums
class UserRole(str, Enum):
    BUYER = "buyer"
    SELLER = "seller"
    ADMIN = "admin"

class KYCStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    VERIFIED = "verified"
    REJECTED = "rejected"

class ServiceCategory(str, Enum):
    PLUMBING = "plumbing"
    ELECTRICAL = "electrical"
    HOUSEKEEPING = "housekeeping"
    NANNY = "nanny"
    COOKING = "cooking"
    GARDENING = "gardening"
    CARPENTRY = "carpentry"
    PAINTING = "painting"
    TAILORING = "tailoring"
    CLEANING = "cleaning"
    SECURITY = "security"
    DRIVING = "driving"
    TUTORING = "tutoring"
    BEAUTY = "beauty"
    FITNESS = "fitness"
    MOVING = "moving"
    HANDYMAN = "handyman"
    TILING = "tiling"
    WELDING = "welding"
    COMPUTER_REPAIR = "computer_repair"
    IT_SUPPORT = "it_support"
    NETWORKING = "networking"
    CCTV_INSTALLATION = "cctv_installation"
    PHONE_REPAIR = "phone_repair"
    APPLIANCE_REPAIR = "appliance_repair"
    INTERIOR_DESIGN = "interior_design"
    EVENT_PLANNING = "event_planning"
    PHOTOGRAPHY = "photography"
    LAUNDRY = "laundry"
    GRAPHIC_DESIGN = "graphic_design"
    WEB_DESIGN = "web_design"
    VIDEO_EDITING = "video_editing"
    DIGITAL_MARKETING = "digital_marketing"
    SOFTWARE_DEVELOPMENT = "software_development"
    DATA_ENTRY = "data_entry"
    PRINTING_BRANDING = "printing_branding"
    OTHER = "other"

class ServiceType(str, Enum):
    ONE_TIME = "one-time"
    RECURRING = "recurring"
    PACKAGE = "package"

class ServiceLocationType(str, Enum):
    AT_CUSTOMER = "at_customer"
    AT_PROVIDER = "at_provider"
    MOBILE = "mobile"

class PriceUnit(str, Enum):
    PER_SESSION = "per_session"
    PER_HOUR = "per_hour"
    PER_DAY = "per_day"
    PER_WEEK = "per_week"
    PER_MONTH = "per_month"

class ListingStatus(str, Enum):
    DRAFT = "draft"
    PENDING = "pending"
    ACTIVE = "active"
    PAUSED = "paused"
    REMOVED = "removed"
    SOLD = "sold"

class SubscriptionTier(str, Enum):
    NONE = "none"
    BRONZE = "bronze"
    SILVER = "silver"
    GOLD = "gold"

class PaymentStatus(str, Enum):
    PENDING = "pending"
    PAID = "paid"
    PENDING_CASH_PAYMENT = "pending_cash_payment"
    FAILED = "failed"
    REFUNDED = "refunded"
    CANCELLED = "cancelled"

class DeliveryOption(str, Enum):
    PICKUP = "pickup"
    DELIVERY = "delivery"

class PaymentMethod(str, Enum):
    MPESA = "mpesa"
    CASH = "cash"
    WALLET = "wallet"

class DeliveryStatus(str, Enum):
    PENDING = "pending"
    DELIVERED = "delivered"
    CONFIRMED = "confirmed"

class DeliveryFeeStatus(str, Enum):
    NOT_SET = "not_set"
    SET_BY_SELLER = "set_by_seller"
    PAID_ONLINE = "paid_online"
    PAY_CASH_ON_DELIVERY = "pay_cash_on_delivery"
    CASH_RECEIVED = "cash_received"

class TransactionType(str, Enum):
    ORDER_PAYMENT = "order_payment"
    PLATFORM_FEE = "platform_fee"  # Generic platform fee (legacy)
    PLATFORM_FEE_BOOKING = "platform_fee_booking"  # Platform fee from service bookings
    PLATFORM_FEE_VERIFICATION = "platform_fee_verification"  # Verification fee
    PLATFORM_FEE_JOB_POSTING = "platform_fee_job_posting"  # Job posting fee
    PLATFORM_FEE_SUBSCRIPTION = "platform_fee_subscription"  # Seller subscription fee
    SELLER_EARNING = "seller_earning"
    DELIVERY_FEE_PAYMENT = "delivery_fee_payment"
    WITHDRAWAL = "withdrawal"
    REFUND = "refund"
    CANCELLATION_FEE_REFUND = "cancellation_fee_refund"
    CANCELLATION_RESTOCKING_FEE = "cancellation_restocking_fee"
    SELLER_CANCELLATION_PENALTY = "seller_cancellation_penalty"
    JOB_POSTING_FEE = "job_posting_fee"  # Debit from user for job posting (legacy)

class TransactionStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    REVERSED = "reversed"

class WithdrawalStatus(str, Enum):
    PENDING = "pending"
    PENDING_APPROVAL = "pending_approval"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

class MessageStatus(str, Enum):
    SENT = "sent"
    DELIVERED = "delivered"
    BLOCKED = "blocked"

# Pydantic Models
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    phone: str
    password: str
    role: UserRole = UserRole.BUYER
    security_question: str
    security_answer: str

    @validator('phone')
    def validate_phone(cls, v: str) -> str:
        # Accept E.164-like formats or local digits (7-15 digits)
        normalized = v.strip()
        if not re.fullmatch(r'^\+?\d{7,15}$', normalized):
            raise ValueError("Invalid phone number format")
        return normalized

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class GoogleAuthRequest(BaseModel):
    id_token: Optional[str] = None
    code: Optional[str] = None
    redirect_uri: Optional[str] = None
    code_verifier: Optional[str] = None
    role: UserRole = UserRole.BUYER


class GoogleAuthInitiateRequest(BaseModel):
    redirect_uri: str
    return_to: str
    role: UserRole = UserRole.BUYER


class GoogleAuthInitiateResponse(BaseModel):
    auth_url: str
    state: str


class GoogleAuthCompleteRequest(BaseModel):
    auth_code: str

class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    phone: str
    role: UserRole
    kyc_status: KYCStatus
    avatar: Optional[str] = None
    security_question_needs_setup: bool = False
    subscription_tier: Optional[SubscriptionTier] = SubscriptionTier.NONE
    subscription_expires_at: Optional[datetime] = None
    created_at: datetime

class LoginResponse(BaseModel):
    token: str
    refresh_token: Optional[str] = None
    user: UserResponse

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = None
    all_devices: bool = False

class RefreshResponse(BaseModel):
    token: str
    refresh_token: str


# In-memory state storage (use Redis in production)
google_auth_states = {}
google_auth_codes = {}

class SellerProfileCreate(BaseModel):
    business_name: Optional[str] = None
    license_file: Optional[str] = ''  # base64 (optional during free upgrade)
    bank_details: Dict[str, str] = Field(default_factory=dict)

class SellerProfile(BaseModel):
    user_id: str
    business_name: str
    license_file: str
    rating: float = 0.0
    bank_details: Dict[str, str]
    created_at: datetime

class Location(BaseModel):
    city: str
    region: Optional[str] = None
    lat: Optional[float] = None
    lng: Optional[float] = None

class Availability(BaseModel):
    days: List[str]
    hours: Dict[str, str]  # {"start": "09:00", "end": "18:00"}

class ServiceListingCreate(BaseModel):
    service_category: ServiceCategory
    service_name: str
    service_type: ServiceType
    duration_minutes: int
    price: float
    price_unit: PriceUnit
    description: str
    qualifications: Optional[str] = None
    certifications: List[str] = []  # base64 images
    experience_years: int
    services_included: List[str] = []
    pet_types_accepted: List[str] = []  # Legacy field for backwards compatibility
    location: Location
    service_location_type: ServiceLocationType
    photos: List[str] = []  # base64 images
    availability: Availability

class ServiceListingUpdate(BaseModel):
    service_category: Optional[ServiceCategory] = None
    service_name: Optional[str] = None
    service_type: Optional[ServiceType] = None
    duration_minutes: Optional[int] = None
    price: Optional[float] = None
    price_unit: Optional[PriceUnit] = None
    description: Optional[str] = None
    qualifications: Optional[str] = None
    certifications: Optional[List[str]] = None
    experience_years: Optional[int] = None
    services_included: Optional[List[str]] = None
    pet_types_accepted: Optional[List[str]] = None
    location: Optional[Location] = None
    service_location_type: Optional[ServiceLocationType] = None
    photos: Optional[List[str]] = None
    availability: Optional[Availability] = None
    status: Optional[ListingStatus] = None

class ServiceListing(BaseModel):
    id: str
    seller_id: str
    seller_name: Optional[str] = None
    seller_kyc_status: Optional[str] = None
    seller_subscription_tier: Optional[SubscriptionTier] = SubscriptionTier.NONE
    seller_subscription_badge: Optional[str] = None
    seller_visibility_boost: Optional[int] = 0
    seller_available_now: Optional[bool] = False
    seller_available_now_updated_at: Optional[datetime] = None
    service_category: ServiceCategory
    service_name: str
    service_type: ServiceType
    duration_minutes: int
    price: float
    price_unit: PriceUnit
    description: str
    qualifications: Optional[str] = None
    certifications: List[str]
    experience_years: int
    services_included: List[str]
    pet_types_accepted: List[str]
    location: Location
    service_location_type: ServiceLocationType
    photos: List[str]
    availability: Availability
    status: ListingStatus
    created_at: datetime
    updated_at: datetime

class ServiceRequirements(BaseModel):
    customer_name: str
    contact_phone: str
    service_details: Optional[str] = None
    number_of_people: Optional[int] = None
    special_instructions: Optional[str] = None

class OrderCreate(BaseModel):
    service_id: str
    booking_date: datetime
    booking_time: str
    service_location: ServiceLocationType
    service_address: str
    service_requirements: ServiceRequirements
    payment_method: PaymentMethod

class Order(BaseModel):
    id: str
    buyer_id: str
    seller_id: str
    service_id: str
    price: float
    platform_fee: float
    seller_amount: float
    service_fee: float = 0.0
    total_amount: float
    payment_method: PaymentMethod
    payment_status: PaymentStatus
    booking_date: datetime
    booking_time: str
    service_location: ServiceLocationType
    service_address: str
    service_requirements: ServiceRequirements
    service_status: str = "pending"
    service_fee_status: str = "not_set"
    service_fee_payment_method: Optional[str] = None
    service_fee_set_at: Optional[datetime] = None
    service_fee_paid_at: Optional[datetime] = None
    tracking_id: Optional[str] = None
    mpesa_checkout_request_id: Optional[str] = None
    provider_confirmed: Optional[bool] = None
    provider_confirmed_at: Optional[datetime] = None
    provider_declined_at: Optional[datetime] = None
    service_completed_by_customer: Optional[bool] = None
    service_completed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

class WalletResponse(BaseModel):
    user_id: str
    balance: float
    total_earned: float
    total_withdrawn: float
    pending_balance: float
    pending_deductions: float = 0.0
    created_at: datetime
    updated_at: datetime

class Transaction(BaseModel):
    id: str
    user_id: str
    order_id: Optional[str] = None
    amount: float
    transaction_type: TransactionType
    status: TransactionStatus
    description: str
    balance_before: float
    balance_after: float
    created_at: datetime
    updated_at: datetime

class InitiatePaymentRequest(BaseModel):
    order_id: str
    phone_number: str

class InitiatePaymentResponse(BaseModel):
    success: bool
    message: str
    checkout_request_id: Optional[str] = None
    merchant_request_id: Optional[str] = None

class WithdrawalRequest(BaseModel):
    amount: float
    phone_number: str

class WithdrawalResponse(BaseModel):
    id: str
    user_id: str
    amount: float
    phone_number: str
    status: WithdrawalStatus
    mpesa_conversation_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime

class ConversationCreate(BaseModel):
    buyer_id: str
    seller_id: str
    service_id: str

class Conversation(BaseModel):
    id: str
    buyer_id: str
    seller_id: str
    service_id: str
    created_at: datetime
    last_message: Optional[str] = None
    last_message_time: Optional[datetime] = None

class MessageCreate(BaseModel):
    conversation_id: str
    sender_id: str
    content: str

class Message(BaseModel):
    id: str
    conversation_id: str
    sender_id: str
    content_original: str
    content_filtered: str
    is_blocked: bool = False
    violation_type: Optional[str] = None
    timestamp: datetime
    status: MessageStatus = MessageStatus.SENT

class ConversationWithDetails(BaseModel):
    id: str
    buyer_id: str
    seller_id: str
    service_id: str
    created_at: datetime
    last_message: Optional[str] = None
    last_message_time: Optional[datetime] = None
    other_user_id: str
    other_user_name: str
    unread_count: int = 0

class ReviewCreate(BaseModel):
    order_id: str
    rating: int = Field(..., ge=1, le=5)
    comment: str = Field(..., min_length=10, max_length=500)

class ReviewUpdate(BaseModel):
    rating: int = Field(..., ge=1, le=5)
    comment: str = Field(..., min_length=10, max_length=500)

class SellerResponse(BaseModel):
    response: str = Field(..., min_length=10, max_length=500)

class Review(BaseModel):
    id: str
    seller_id: str
    buyer_id: str
    buyer_name: str
    order_id: str
    service_id: Optional[str] = None  # Unified field (was pet_id)
    rating: int
    comment: str
    created_at: datetime
    seller_response: Optional[str] = None
    seller_response_date: Optional[datetime] = None
    verified_purchase: bool = True

class SellerRatingResponse(BaseModel):
    seller_id: str
    average_rating: float
    total_reviews: int
    reviews: List[Review]
    rating_distribution: Optional[Dict[int, int]] = None

class PushTokenUpdate(BaseModel):
    fcm_token: str

class NotificationResponse(BaseModel):
    id: str
    type: str
    title: str
    message: str
    data: Dict[str, Any]
    read: bool
    created_at: str

class PlatformSettingsUpdate(BaseModel):
    # Financial Settings
    platform_fee_percentage: Optional[float] = None
    delivery_fee_escrow_hours: Optional[int] = None
    unpaid_order_cancellation_days: Optional[int] = None
    minimum_withdrawal: Optional[float] = None
    maximum_withdrawal: Optional[float] = None
    verification_fee: Optional[float] = None

    # Listing Settings
    max_images_per_listing: Optional[int] = None
    auto_approve_listings: Optional[bool] = None
    max_listing_duration_days: Optional[int] = None
    require_vet_certificate: Optional[bool] = None

    # Order Settings
    order_confirmation_hours: Optional[int] = None
    auto_complete_delivery_days: Optional[int] = None
    cancellation_refund_percentage: Optional[float] = None
    seller_cancellation_penalty_percentage: Optional[float] = None

    # Security Settings
    min_password_length: Optional[int] = None
    session_timeout_hours: Optional[int] = None
    max_login_attempts: Optional[int] = None
    require_email_verification: Optional[bool] = None

    # Moderation Settings
    auto_moderation_enabled: Optional[bool] = None
    flagged_content_threshold: Optional[int] = None
    review_approval_required: Optional[bool] = None

    # Communication Settings
    support_email: Optional[str] = None
    support_phone: Optional[str] = None
    system_announcement: Optional[str] = None
    announcement_active: Optional[bool] = None

    # Advertisement Settings
    ad_image_url: Optional[str] = None
    ad_link_url: Optional[str] = None
    ad_active: Optional[bool] = None
    ad_animation_style: Optional[str] = None
    ad_display_frequency: Optional[str] = None

    # Notification Settings
    enable_email_notifications: Optional[bool] = None
    enable_sms_notifications: Optional[bool] = None
    enable_push_notifications: Optional[bool] = None

    # Maintenance
    maintenance_mode: Optional[bool] = None
    api_rate_limit_per_minute: Optional[int] = None

    # Job Posting Settings
    jobPostingFee: Optional[float] = None
    jobPostingPromotionalMessage: Optional[str] = None

    # Seller Subscription Settings
    subscriptionBronzePrice: Optional[float] = None
    subscriptionSilverPrice: Optional[float] = None
    subscriptionGoldPrice: Optional[float] = None

    # Feature Toggles
    features: Optional[Dict[str, bool]] = None

class SellerSubscriptionActivateRequest(BaseModel):
    tier: SubscriptionTier
    payment_method: PaymentMethod
    phone_number: Optional[str] = None

class AdminSetSellerSubscriptionRequest(BaseModel):
    tier: SubscriptionTier
    duration_days: Optional[int] = 30

class SellerAvailabilityUpdateRequest(BaseModel):
    available_now: bool

class SuspendUserRequest(BaseModel):
    suspend: bool
    reason: Optional[str] = None

# Verification Models
class VerificationStatus(str, Enum):
    NOT_SUBMITTED = "not_submitted"
    PENDING = "pending"
    PAYMENT_PENDING = "payment_pending"
    UNDER_REVIEW = "under_review"
    VERIFIED = "verified"
    REJECTED = "rejected"

class VerificationDocumentCreate(BaseModel):
    national_id_front_url: str
    national_id_back_url: str
    business_license_url: Optional[str] = None
    proof_of_address_url: Optional[str] = None
    selfie_url: Optional[str] = None
    agree_to_terms: bool

class VerificationPaymentRequest(BaseModel):
    verification_id: str
    payment_method: PaymentMethod  # wallet or mpesa
    phone_number: Optional[str] = None  # Required if mpesa

class VerificationCancellationRequest(BaseModel):
    verification_id: str

class RejectVerificationRequest(BaseModel):
    reason: str

# Job Posting Enums (must be defined before models that use them)
class JobEmploymentType(str, Enum):
    FULL_TIME = "full_time"
    PART_TIME = "part_time"
    CONTRACT = "contract"
    INTERNSHIP = "internship"
    TEMPORARY = "temporary"

class JobStatus(str, Enum):
    DRAFT = "draft"
    PENDING_PAYMENT = "pending_payment"
    ACTIVE = "active"
    PAUSED = "paused"
    CLOSED = "closed"
    EXPIRED = "expired"

class JobExperienceLevel(str, Enum):
    ENTRY = "entry"
    INTERMEDIATE = "intermediate"
    SENIOR = "senior"
    EXECUTIVE = "executive"

# Job Posting Models
class JobPostingCreate(BaseModel):
    job_title: str
    company_name: str
    employment_type: JobEmploymentType
    experience_level: JobExperienceLevel
    location: str
    salary_range_min: Optional[float] = None
    salary_range_max: Optional[float] = None
    salary_currency: str = "KES"
    job_description: str
    requirements: List[str] = []
    responsibilities: List[str] = []
    benefits: List[str] = []
    application_deadline: Optional[datetime] = None
    application_email: Optional[str] = None
    application_url: Optional[str] = None
    contact_phone: Optional[str] = None

class JobPostingUpdate(BaseModel):
    job_title: Optional[str] = None
    employment_type: Optional[JobEmploymentType] = None
    experience_level: Optional[JobExperienceLevel] = None
    location: Optional[str] = None
    salary_range_min: Optional[float] = None
    salary_range_max: Optional[float] = None
    job_description: Optional[str] = None
    requirements: Optional[List[str]] = None
    responsibilities: Optional[List[str]] = None
    benefits: Optional[List[str]] = None
    application_deadline: Optional[datetime] = None
    application_email: Optional[str] = None
    application_url: Optional[str] = None
    contact_phone: Optional[str] = None
    status: Optional[JobStatus] = None

class JobPosting(BaseModel):
    id: str
    company_id: str
    company_name: str
    job_title: str
    employment_type: JobEmploymentType
    experience_level: JobExperienceLevel
    location: str
    salary_range_min: Optional[float] = None
    salary_range_max: Optional[float] = None
    salary_currency: str = "KES"
    job_description: str
    requirements: List[str] = []
    responsibilities: List[str] = []
    benefits: List[str] = []
    application_deadline: Optional[datetime] = None
    application_email: Optional[str] = None
    application_url: Optional[str] = None
    contact_phone: Optional[str] = None
    status: JobStatus
    payment_status: PaymentStatus
    posting_fee: float
    mpesa_checkout_request_id: Optional[str] = None
    posted_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

class JobPostingPaymentRequest(BaseModel):
    job_posting_id: str
    payment_method: PaymentMethod
    phone_number: Optional[str] = None

class JobPostingFeeUpdate(BaseModel):
    posting_fee: float
    promotional_message: Optional[str] = None

# Verification Constants
VERIFICATION_FEE = 100.0  # 100 KES verification fee

# Job Posting Constants
DEFAULT_JOB_POSTING_FEE = 300.0  # 300 KES default job posting fee

# Helper Functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, role: str) -> str:
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def _hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()

def _compute_transaction_hash(transaction_data: dict, prev_hash: Optional[str]) -> str:
    payload = {
        'user_id': transaction_data.get('user_id'),
        'order_id': transaction_data.get('order_id'),
        'amount': transaction_data.get('amount'),
        'transaction_type': transaction_data.get('transaction_type'),
        'status': transaction_data.get('status'),
        'created_at': transaction_data.get('created_at').isoformat() if transaction_data.get('created_at') else None,
        'prev_hash': prev_hash
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
    key = (TRANSACTION_HASH_SECRET or JWT_SECRET or 'dev-secret').encode('utf-8')
    return hmac.new(key, payload_bytes, hashlib.sha256).hexdigest()

async def _create_refresh_token(user_id: str, device_id: Optional[str] = None) -> str:
    raw_token = secrets.token_urlsafe(64)
    token_hash = _hash_refresh_token(raw_token)
    await db.refresh_tokens.insert_one({
        'user_id': user_id,
        'token_hash': token_hash,
        'device_id': device_id,
        'revoked': False,
        'created_at': datetime.utcnow(),
        'expires_at': datetime.utcnow() + timedelta(days=REFRESH_TOKEN_TTL_DAYS)
    })
    return raw_token

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get('user_id')
        if not user_id:
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication credentials"
            )

        user = await db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            raise HTTPException(
                status_code=401,
                detail="User not found or has been deleted"
            )

        # Check if user account is suspended
        if user.get('suspended', False):
            suspension_reason = user.get('suspension_reason', 'No reason provided')
            suspension_date = user.get('suspension_date')

            detail_msg = f"Your account has been suspended. Reason: {suspension_reason}"
            if suspension_date:
                detail_msg += f" (Suspended on: {suspension_date.strftime('%Y-%m-%d')})"
            detail_msg += " Please contact support for assistance."

            logger.warning(f"Suspended user attempted to access API: {user.get('email')} - {suspension_reason}")
            raise HTTPException(
                status_code=403,
                detail=detail_msg
            )

        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Authentication token has expired. Please log in again."
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token"
        )
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=401,
            detail="Authentication failed. Please log in again."
        )

async def require_admin(current_user: dict = Depends(get_current_user)):
    if current_user.get('role') != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

async def log_security_event(
    event_type: str,
    severity: str,
    details: dict,
    user_id: Optional[str] = None,
    request: Optional[Request] = None
):
    """Log a security event and optionally notify admins."""
    try:
        record = {
            'event_type': event_type,
            'severity': severity,
            'details': details,
            'user_id': user_id,
            'ip_address': request.client.host if request and request.client else None,
            'user_agent': request.headers.get('User-Agent') if request else None,
            'created_at': datetime.utcnow(),
            'expires_at': datetime.utcnow() + timedelta(days=SECURITY_EVENT_RETENTION_DAYS)
        }
        await db.security_events.insert_one(record)

        if ALERT_ADMIN_SECURITY_EVENTS and severity in ['high', 'critical']:
            admins = await db.users.find({'role': UserRole.ADMIN}).to_list(50)
            for admin in admins:
                try:
                    await create_notification(
                        db=db,
                        user_id=str(admin['_id']),
                        notification_type=NotificationType.ADMIN_ANNOUNCEMENT,
                        title=f"Security Event: {event_type}",
                        message=f"Severity: {severity}. Details: {details}",
                        data={'event_type': event_type, 'severity': severity}
                    )
                except Exception:
                    continue
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")

def _sanitize_audit_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _sanitize_audit_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_audit_value(v) for v in value]
    if isinstance(value, str):
        if len(value) > 500:
            return value[:500] + "...(truncated)"
        return value
    return value

def _sanitize_audit_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return _sanitize_audit_value(payload)
    redacted_keys = {'password', 'new_password', 'old_password', 'token', 'refresh_token', 'access_token', 'secret', 'api_key'}
    sanitized = {}
    for key, value in payload.items():
        key_lower = str(key).lower()
        if key_lower in redacted_keys or 'password' in key_lower or 'token' in key_lower or 'secret' in key_lower:
            sanitized[key] = '[redacted]'
        else:
            sanitized[key] = _sanitize_audit_value(value)
    return sanitized

def _compute_audit_diff(before: Optional[dict], after: Optional[dict]) -> Optional[dict]:
    if not isinstance(before, dict) or not isinstance(after, dict):
        return None
    diff = {}
    all_keys = set(before.keys()) | set(after.keys())
    for key in all_keys:
        if key not in before or key not in after:
            diff[key] = {
                'from': _sanitize_audit_value(before.get(key)),
                'to': _sanitize_audit_value(after.get(key))
            }
            continue
        if before.get(key) != after.get(key):
            diff[key] = {
                'from': _sanitize_audit_value(before.get(key)),
                'to': _sanitize_audit_value(after.get(key))
            }
    return diff or None

async def log_admin_audit(
    action: str,
    actor: dict,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    before: Optional[dict] = None,
    after: Optional[dict] = None,
    payload: Optional[Any] = None,
    request: Optional[Request] = None,
    extra: Optional[dict] = None
):
    try:
        record = {
            'action': action,
            'actor_id': str(actor.get('_id')) if actor else None,
            'actor_email': actor.get('email') if actor else None,
            'actor_name': actor.get('name') if actor else None,
            'target_type': target_type,
            'target_id': target_id,
            'payload': _sanitize_audit_payload(payload) if payload is not None else None,
            'before': _sanitize_audit_payload(before) if before is not None else None,
            'after': _sanitize_audit_payload(after) if after is not None else None,
            'diff': _compute_audit_diff(before, after),
            'extra': _sanitize_audit_payload(extra) if extra is not None else None,
            'ip_address': request.client.host if request and request.client else None,
            'user_agent': request.headers.get('User-Agent') if request else None,
            'path': request.url.path if request else None,
            'method': request.method if request else None,
            'created_at': datetime.utcnow()
        }
        await db.admin_audit_logs.insert_one(record)
    except Exception as e:
        logger.error(f"Failed to log admin audit: {e}")

# Wallet Helper Functions
PLATFORM_FEE_PERCENTAGE = 0.05  # 5% platform fee (DEPRECATED - use get_platform_settings())
PLATFORM_WALLET_ID = "platform_wallet"
CLEARING_WALLET_ID = "clearing_wallet"
MINIMUM_WITHDRAWAL_AMOUNT = 100  # KES 100 (DEPRECATED - use get_platform_settings())
RECONCILIATION_INTERVAL_HOURS = int(os.environ.get('RECONCILIATION_INTERVAL_HOURS', 24))
RECONCILIATION_TOLERANCE_PROD = float(os.environ.get('RECONCILIATION_TOLERANCE_PROD', 0.01))
RECONCILIATION_TOLERANCE_DEV = float(os.environ.get('RECONCILIATION_TOLERANCE_DEV', 1.0))
INTEGRITY_SCAN_INTERVAL_HOURS = int(os.environ.get('INTEGRITY_SCAN_INTERVAL_HOURS', 24))
INTEGRITY_SCAN_LIMIT = int(os.environ.get('INTEGRITY_SCAN_LIMIT', 1000))
SELLER_CANCELLATION_PENALTY_PERCENTAGE = 0.10  # 10% penalty on order value for seller-initiated cancellations (DEPRECATED - use get_platform_settings())
# DELIVERY_FEE constant removed - now seller sets custom delivery fee per order
MINIMUM_DELIVERY_FEE = 50.0  # KES 50 minimum delivery fee
MAXIMUM_DELIVERY_FEE = 5000.0  # KES 5000 maximum delivery fee
DEFAULT_SUBSCRIPTION_BRONZE_PRICE = 1000.0
DEFAULT_SUBSCRIPTION_SILVER_PRICE = 2500.0
DEFAULT_SUBSCRIPTION_GOLD_PRICE = 5000.0

# Settings Cache
_settings_cache = None
_settings_cache_time = None
SETTINGS_CACHE_TTL = 60  # Cache settings for 60 seconds

async def get_platform_settings():
    """
    Get platform settings with caching
    Returns settings from DB or defaults if not found
    """
    global _settings_cache, _settings_cache_time

    # Check if cache is valid
    now = datetime.utcnow()
    if _settings_cache and _settings_cache_time:
        if (now - _settings_cache_time).total_seconds() < SETTINGS_CACHE_TTL:
            return _settings_cache

    # Fetch from database
    try:
        settings = await db.settings.find_one({'key': 'platform_config'})

        if not settings:
            # Return defaults
            settings = {
                'platformFeePercentage': PLATFORM_FEE_PERCENTAGE * 100,
                'deliveryFeeEscrowHours': 24,
                'unpaidOrderCancellationDays': 7,
                'minimumWithdrawal': 100.0,
                'maximumWithdrawal': 100000.0,
                'verificationFee': VERIFICATION_FEE,
                'maxImagesPerListing': 10,
                'autoApproveListings': False,
                'maxListingDurationDays': 90,
                'requireVetCertificate': True,
                'orderConfirmationHours': 72,
                'autoCompleteDeliveryDays': 7,
                'cancellationRefundPercentage': 90.0,
                'sellerCancellationPenaltyPercentage': 10.0,
                'minPasswordLength': 8,
                'sessionTimeoutHours': 168,
                'maxLoginAttempts': 5,
                'requireEmailVerification': False,
                'autoModerationEnabled': True,
                'flaggedContentThreshold': 3,
                'reviewApprovalRequired': False,
                'supportEmail': 'support@petsoko.com',
                'supportPhone': '+254700000000',
                'systemAnnouncement': '',
                'announcementActive': False,
                'enableEmailNotifications': True,
                'enableSmsNotifications': False,
                'enablePushNotifications': True,
                'maintenanceMode': False,
                'apiRateLimitPerMinute': 60,
                'subscriptionBronzePrice': DEFAULT_SUBSCRIPTION_BRONZE_PRICE,
                'subscriptionSilverPrice': DEFAULT_SUBSCRIPTION_SILVER_PRICE,
                'subscriptionGoldPrice': DEFAULT_SUBSCRIPTION_GOLD_PRICE,
                'features': {
                    'enableMpesa': True,
                    'enableWallet': True,
                    'enableCashPayment': True,
                    'enableDelivery': True,
                    'enableReviews': True,
                    'enableChat': True
                }
            }

        # Update cache
        _settings_cache = settings
        _settings_cache_time = now

        return settings
    except Exception as e:
        logger.error(f"Error fetching platform settings: {e}")
        # Return cache if available, otherwise defaults
        if _settings_cache:
            return _settings_cache
        return {
            'platformFeePercentage': 5.0,
            'minimumWithdrawal': 100.0,
            'maximumWithdrawal': 100000.0,
            'verificationFee': VERIFICATION_FEE,
            'autoApproveListings': False,
            'sellerCancellationPenaltyPercentage': 10.0,
            'subscriptionBronzePrice': DEFAULT_SUBSCRIPTION_BRONZE_PRICE,
            'subscriptionSilverPrice': DEFAULT_SUBSCRIPTION_SILVER_PRICE,
            'subscriptionGoldPrice': DEFAULT_SUBSCRIPTION_GOLD_PRICE,
        }

def invalidate_settings_cache():
    """Invalidate the settings cache to force a fresh fetch"""
    global _settings_cache, _settings_cache_time
    _settings_cache = None
    _settings_cache_time = None

def get_subscription_visibility_boost(tier: Optional[str]) -> int:
    normalized = (tier or SubscriptionTier.NONE).lower()
    if normalized == SubscriptionTier.GOLD:
        return 3
    if normalized == SubscriptionTier.SILVER:
        return 2
    if normalized == SubscriptionTier.BRONZE:
        return 1
    return 0

def build_seller_subscription_payload(user: Optional[dict]) -> dict:
    now = datetime.utcnow()
    subscription = user.get('provider_subscription', {}) if user else {}
    tier = (subscription.get('tier') or SubscriptionTier.NONE).lower()
    if tier not in {SubscriptionTier.NONE, SubscriptionTier.BRONZE, SubscriptionTier.SILVER, SubscriptionTier.GOLD}:
        tier = SubscriptionTier.NONE
    expires_at = subscription.get('expires_at')
    if isinstance(expires_at, str):
        try:
            expires_at = datetime.fromisoformat(expires_at)
        except Exception:
            expires_at = None

    is_active = subscription.get('is_active', False)
    if not expires_at or expires_at < now:
        tier = SubscriptionTier.NONE
        is_active = False

    return {
        'seller_subscription_tier': tier,
        'seller_subscription_badge': tier.capitalize() if tier != SubscriptionTier.NONE else None,
        'seller_visibility_boost': get_subscription_visibility_boost(tier) if is_active else 0,
        'subscription_expires_at': expires_at
    }

def parse_seller_availability_payload(user: Optional[dict]) -> dict:
    available_now = bool(user.get('available_now', False)) if user else False
    updated_at = user.get('available_now_updated_at') if user else None
    if isinstance(updated_at, str):
        try:
            updated_at = datetime.fromisoformat(updated_at)
        except Exception:
            updated_at = None
    return {
        'seller_available_now': available_now,
        'seller_available_now_updated_at': updated_at
    }

def security_question_needs_setup(user: Optional[dict]) -> bool:
    if not user:
        return True
    question = str(user.get('security_question') or '').strip()
    if not question:
        return True
    return question.lower() == 'google oauth user'

async def activate_provider_subscription(user_id: str, tier: str, amount_paid: float):
    now = datetime.utcnow()
    user = await db.users.find_one({'_id': ObjectId(user_id)})
    current_sub = user.get('provider_subscription', {}) if user else {}
    current_expires = current_sub.get('expires_at')
    if isinstance(current_expires, str):
        try:
            current_expires = datetime.fromisoformat(current_expires)
        except Exception:
            current_expires = None

    base_start = current_expires if (current_expires and current_expires > now) else now
    new_expires = base_start + timedelta(days=30)

    await db.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {
            'provider_subscription': {
                'tier': tier,
                'is_active': True,
                'started_at': now,
                'expires_at': new_expires,
                'price_paid': amount_paid
            }
        }}
    )
    return {
        'started_at': now,
        'expires_at': new_expires
    }

async def get_job_posting_settings():
    """Get job posting fee and promotional message from platform settings"""
    try:
        settings = await db.settings.find_one({'key': 'platform_config'})
        if not settings:
            return {
                'jobPostingFee': DEFAULT_JOB_POSTING_FEE,
                'jobPostingPromotionalMessage': ''
            }
        return {
            'jobPostingFee': settings.get('jobPostingFee', DEFAULT_JOB_POSTING_FEE),
            'jobPostingPromotionalMessage': settings.get('jobPostingPromotionalMessage', '')
        }
    except Exception as e:
        logger.error(f"Error fetching job posting settings: {e}")
        return {
            'jobPostingFee': DEFAULT_JOB_POSTING_FEE,
            'jobPostingPromotionalMessage': ''
        }

async def get_or_create_wallet(user_id: str):
    """Get or create wallet for a user"""
    wallet = await db.wallets.find_one({'user_id': user_id})

    if not wallet:
        wallet_data = {
            'user_id': user_id,
            'balance': 0.0,
            'total_earned': 0.0,
            'total_withdrawn': 0.0,
            'pending_balance': 0.0,
            'pending_deductions': 0.0,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        await db.wallets.insert_one(wallet_data)
        wallet = wallet_data

    # Ensure pending_deductions field exists for existing wallets
    if 'pending_deductions' not in wallet:
        await db.wallets.update_one(
            {'user_id': user_id},
            {'$set': {'pending_deductions': 0.0}}
        )
        wallet['pending_deductions'] = 0.0

    return wallet

async def get_or_create_platform_wallet():
    """Get or create platform wallet"""
    wallet = await db.wallets.find_one({'user_id': PLATFORM_WALLET_ID})

    if not wallet:
        wallet_data = {
            'user_id': PLATFORM_WALLET_ID,
            'balance': 0.0,
            'total_earned': 0.0,
            'total_withdrawn': 0.0,
            'pending_balance': 0.0,
            'pending_deductions': 0.0,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        await db.wallets.insert_one(wallet_data)
        wallet = wallet_data

    # Ensure pending_deductions field exists for existing wallet
    if 'pending_deductions' not in wallet:
        await db.wallets.update_one(
            {'user_id': PLATFORM_WALLET_ID},
            {'$set': {'pending_deductions': 0.0}}
        )
        wallet['pending_deductions'] = 0.0

    return wallet

async def create_transaction(
    user_id: str,
    amount: float,
    transaction_type: TransactionType,
    status: TransactionStatus,
    description: str,
    order_id: Optional[str] = None,
    counterparty_id: Optional[str] = None
) -> dict:
    """Create a transaction record"""
    wallet = await get_or_create_wallet(user_id)

    prev_txn = await db.transactions.find_one({'user_id': user_id}, sort=[('created_at', -1)])
    prev_hash = prev_txn.get('integrity_hash') if prev_txn else None

    transaction_data = {
        'user_id': user_id,
        'order_id': order_id,
        'amount': amount,
        'transaction_type': transaction_type,
        'status': status,
        'description': description,
        'balance_before': wallet['balance'],
        'balance_after': wallet['balance'],
        'created_at': datetime.utcnow(),
        'updated_at': datetime.utcnow()
    }
    transaction_data['prev_integrity_hash'] = prev_hash
    transaction_data['integrity_hash'] = _compute_transaction_hash(transaction_data, prev_hash)

    result = await db.transactions.insert_one(transaction_data)
    transaction_data['_id'] = result.inserted_id

    # Ledger entry (append-only)
    ledger_entry = {
        'user_id': user_id,
        'transaction_id': str(transaction_data['_id']),
        'order_id': order_id,
        'amount': amount,
        'direction': 'credit' if amount >= 0 else 'debit',
        'transaction_type': transaction_type,
        'status': status,
        'description': description,
        'balance_before': wallet['balance'],
        'balance_after': wallet['balance'],
        'created_at': datetime.utcnow(),
        'prev_integrity_hash': prev_hash,
        'integrity_hash': transaction_data['integrity_hash']
    }
    await db.ledger_entries.insert_one(ledger_entry)

    # Double-entry ledger (audit trail)
    if amount != 0:
        cp_id = counterparty_id or CLEARING_WALLET_ID
        if amount < 0:
            await create_double_entry_ledger(
                from_user_id=user_id,
                to_user_id=cp_id,
                amount=abs(amount),
                transaction_type=transaction_type,
                description=description,
                order_id=order_id,
                reference_transaction_id=str(transaction_data['_id'])
            )
        else:
            await create_double_entry_ledger(
                from_user_id=cp_id,
                to_user_id=user_id,
                amount=abs(amount),
                transaction_type=transaction_type,
                description=description,
                order_id=order_id,
                reference_transaction_id=str(transaction_data['_id'])
            )

    return transaction_data

async def create_double_entry_ledger(
    from_user_id: str,
    to_user_id: str,
    amount: float,
    transaction_type: TransactionType,
    description: str,
    order_id: Optional[str] = None,
    reference_transaction_id: Optional[str] = None
) -> str:
    """
    Record a double-entry ledger pair for audit purposes.
    This does not change wallet balances; it creates immutable accounting entries.
    """
    if amount <= 0:
        raise ValueError("Amount must be positive for double-entry ledger")

    transaction_id = reference_transaction_id or str(ObjectId())
    timestamp = datetime.utcnow()

    entries = [
        {
            'transaction_id': transaction_id,
            'user_id': from_user_id,
            'counterparty_id': to_user_id,
            'order_id': order_id,
            'amount': -amount,
            'entry_type': 'debit',
            'transaction_type': transaction_type,
            'description': description,
            'created_at': timestamp
        },
        {
            'transaction_id': transaction_id,
            'user_id': to_user_id,
            'counterparty_id': from_user_id,
            'order_id': order_id,
            'amount': amount,
            'entry_type': 'credit',
            'transaction_type': transaction_type,
            'description': description,
            'created_at': timestamp
        }
    ]

    await db.double_entry_ledger.insert_many(entries)
    return transaction_id

async def update_wallet_balance(user_id: str, amount: float, transaction_id: str):
    """Update wallet balance and transaction record"""
    wallet = await get_or_create_wallet(user_id)

    new_balance = wallet['balance'] + amount

    # SAFETY LIMIT: Check maximum wallet balance (Phase 1 security)
    # Skip check for platform/clearing wallets and negative amounts (withdrawals)
    if amount > 0 and user_id not in [PLATFORM_WALLET_ID, CLEARING_WALLET_ID]:
        if new_balance > MAX_WALLET_BALANCE:
            logger.warning(
                f"Wallet balance limit exceeded for user {user_id}: "
                f"attempted={new_balance:.2f}, limit={MAX_WALLET_BALANCE}"
            )
            raise HTTPException(
                status_code=400,
                detail=f"Wallet balance limit reached (KES {MAX_WALLET_BALANCE}). Please withdraw funds before receiving more payments."
            )

    await db.wallets.update_one(
        {'user_id': user_id},
        {
            '$set': {
                'balance': new_balance,
                'updated_at': datetime.utcnow()
            }
        }
    )

    # Update transaction with new balance
    await db.transactions.update_one(
        {'_id': ObjectId(transaction_id)},
        {
            '$set': {
                'balance_after': new_balance,
                'updated_at': datetime.utcnow()
            }
        }
    )

    # Update ledger entry balance_after for this transaction
    await db.ledger_entries.update_one(
        {'transaction_id': transaction_id},
        {'$set': {'balance_after': new_balance}}
    )

    return new_balance

async def debit_wallet_balance(user_id: str, amount: float, transaction_id: str):
    """Atomically debit wallet balance (prevents negative balances)"""
    if amount <= 0:
        raise HTTPException(status_code=400, detail="Invalid debit amount")

    result = await db.wallets.update_one(
        {'user_id': user_id, 'balance': {'$gte': amount}},
        {
            '$inc': {'balance': -amount},
            '$set': {'updated_at': datetime.utcnow()}
        }
    )

    if result.modified_count == 0:
        raise HTTPException(status_code=400, detail="Insufficient wallet balance")

    wallet = await db.wallets.find_one({'user_id': user_id})
    new_balance = wallet['balance'] if wallet else 0.0

    # Update transaction with new balance
    await db.transactions.update_one(
        {'_id': ObjectId(transaction_id)},
        {
            '$set': {
                'balance_after': new_balance,
                'updated_at': datetime.utcnow()
            }
        }
    )

    # Update ledger entry balance_after for this transaction
    await db.ledger_entries.update_one(
        {'transaction_id': transaction_id},
        {'$set': {'balance_after': new_balance}}
    )

    return new_balance

async def split_payment(order_id: str, total_amount: float, seller_id: str):
    """
    Split payment between seller and platform
    Platform fee % is configurable via admin settings (default 5%)
    """
    # Get platform fee from settings
    settings = await _get_platform_settings_internal()
    platform_fee_percentage = settings.get('platformFeePercentage', 5.0) / 100.0  # Convert from percentage to decimal

    platform_fee = total_amount * platform_fee_percentage
    seller_amount = total_amount - platform_fee

    # Create transaction for platform fee (booking fee)
    platform_txn = await create_transaction(
        user_id=PLATFORM_WALLET_ID,
        amount=platform_fee,
        transaction_type=TransactionType.PLATFORM_FEE_BOOKING,
        status=TransactionStatus.COMPLETED,
        description=f"{platform_fee_percentage*100:.1f}% platform fee from service booking (Order {order_id})",
        order_id=order_id
    )

    # Update platform wallet
    platform_wallet = await get_or_create_platform_wallet()
    new_platform_balance = await update_wallet_balance(
        PLATFORM_WALLET_ID,
        platform_fee,
        str(platform_txn['_id'])
    )

    # Update platform total earned
    await db.wallets.update_one(
        {'user_id': PLATFORM_WALLET_ID},
        {'$inc': {'total_earned': platform_fee}}
    )

    # Check for pending deductions (e.g., from seller cancellation penalties)
    seller_wallet = await get_or_create_wallet(seller_id)
    pending_deductions = seller_wallet.get('pending_deductions', 0.0)

    # Calculate actual amount to credit to seller after pending deductions
    deduction_to_apply = min(pending_deductions, seller_amount)
    actual_seller_credit = seller_amount - deduction_to_apply

    # Create transaction for seller earning
    seller_txn = await create_transaction(
        user_id=seller_id,
        amount=seller_amount,
        transaction_type=TransactionType.SELLER_EARNING,
        status=TransactionStatus.COMPLETED,
        description=f"Payment for order {order_id} (after {platform_fee_percentage*100:.1f}% platform fee)",
        order_id=order_id
    )

    # Update seller wallet with actual amount (after pending deductions)
    new_seller_balance = await update_wallet_balance(
        seller_id,
        actual_seller_credit,
        str(seller_txn['_id'])
    )

    # Update seller total earned
    await db.wallets.update_one(
        {'user_id': seller_id},
        {'$inc': {'total_earned': seller_amount}}
    )

    # If there were pending deductions, apply them
    if deduction_to_apply > 0:
        # Reduce pending deductions
        await db.wallets.update_one(
            {'user_id': seller_id},
            {
                '$inc': {'pending_deductions': -deduction_to_apply},
                '$set': {'updated_at': datetime.utcnow()}
            }
        )

        # Create penalty deduction transaction
        penalty_deduction_txn = await create_transaction(
            user_id=seller_id,
            amount=-deduction_to_apply,
            transaction_type=TransactionType.SELLER_CANCELLATION_PENALTY,
            status=TransactionStatus.COMPLETED,
            description=f"Automatic deduction of pending cancellation penalty (KES {deduction_to_apply:.2f}) from earnings for order {order_id}",
            order_id=order_id
        )

        # Transfer deducted amount to platform
        platform_penalty_credit_txn = await create_transaction(
            user_id=PLATFORM_WALLET_ID,
            amount=deduction_to_apply,
            transaction_type=TransactionType.SELLER_CANCELLATION_PENALTY,
            status=TransactionStatus.COMPLETED,
            description=f"Seller penalty deduction from earnings (order {order_id})",
            order_id=order_id
        )

        await update_wallet_balance(
            PLATFORM_WALLET_ID,
            deduction_to_apply,
            str(platform_penalty_credit_txn['_id'])
        )

        logger.info(f"Applied pending deduction of KES {deduction_to_apply:.2f} from seller {seller_id} earnings. Remaining pending: KES {pending_deductions - deduction_to_apply:.2f}")

    logger.info(f"Payment split for order {order_id}: Platform fee={platform_fee}, Seller amount={seller_amount}, Actual seller credit={actual_seller_credit}")

    return {
        'platform_fee': platform_fee,
        'seller_amount': seller_amount,
        'platform_balance': new_platform_balance,
        'seller_balance': new_seller_balance
    }

async def hold_payment_pending(order_id: str, total_amount: float, seller_id: str):
    """
    Hold payment in seller's pending balance until buyer confirms receipt
    Used for MPesa payments to protect buyers
    Platform fee % is configurable via admin settings (default 5%)
    """
    # Get platform fee from settings
    settings = await _get_platform_settings_internal()
    platform_fee_percentage = settings.get('platformFeePercentage', 5.0) / 100.0  # Convert from percentage to decimal

    platform_fee = total_amount * platform_fee_percentage
    seller_amount = total_amount - platform_fee

    # Credit platform fee immediately (booking fee)
    platform_txn = await create_transaction(
        user_id=PLATFORM_WALLET_ID,
        amount=platform_fee,
        transaction_type=TransactionType.PLATFORM_FEE_BOOKING,
        status=TransactionStatus.COMPLETED,
        description=f"{platform_fee_percentage*100:.1f}% platform fee from service booking (Order {order_id})",
        order_id=order_id
    )

    await update_wallet_balance(
        PLATFORM_WALLET_ID,
        platform_fee,
        str(platform_txn['_id'])
    )

    await db.wallets.update_one(
        {'user_id': PLATFORM_WALLET_ID},
        {'$inc': {'total_earned': platform_fee}}
    )

    # Add seller amount to pending_balance (not available balance)
    seller_wallet = await get_or_create_wallet(seller_id)
    await db.wallets.update_one(
        {'user_id': seller_id},
        {
            '$inc': {'pending_balance': seller_amount},
            '$set': {'updated_at': datetime.utcnow()}
        }
    )

    # Create pending transaction for seller
    await create_transaction(
        user_id=seller_id,
        amount=seller_amount,
        transaction_type=TransactionType.SELLER_EARNING,
        status=TransactionStatus.PENDING,
        description=f"Pending payment for order {order_id} (awaiting buyer confirmation)",
        order_id=order_id
    )

    logger.info(f"Payment for order {order_id} held in pending. Seller amount: {seller_amount}, Platform fee: {platform_fee}")

async def release_pending_payment(order_id: str, seller_id: str):
    """
    Release pending payment to seller's available balance when buyer confirms receipt
    """
    # Get order to find transaction
    order = await db.orders.find_one({'_id': ObjectId(order_id)})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    # Find the pending transaction
    pending_txn = await db.transactions.find_one({
        'order_id': order_id,
        'user_id': seller_id,
        'transaction_type': TransactionType.SELLER_EARNING,
        'status': TransactionStatus.PENDING
    })

    if not pending_txn:
        logger.warning(f"No pending transaction found for order {order_id}")
        return

    seller_amount = pending_txn['amount']
    seller_wallet = await get_or_create_wallet(seller_id)

    # Check for pending deductions
    pending_deductions = seller_wallet.get('pending_deductions', 0.0)
    deduction_to_apply = min(pending_deductions, seller_amount)
    actual_seller_credit = seller_amount - deduction_to_apply

    # Move from pending_balance to balance
    await db.wallets.update_one(
        {'user_id': seller_id},
        {
            '$inc': {
                'pending_balance': -seller_amount,
                'balance': actual_seller_credit,
                'total_earned': seller_amount
            },
            '$set': {'updated_at': datetime.utcnow()}
        }
    )

    # Update transaction to completed
    current_balance = seller_wallet.get('balance', 0.0)
    await db.transactions.update_one(
        {'_id': pending_txn['_id']},
        {
            '$set': {
                'status': TransactionStatus.COMPLETED,
                'description': f"Payment released for order {order_id} (buyer confirmed receipt)",
                'balance_before': current_balance,
                'balance_after': current_balance + actual_seller_credit,
                'updated_at': datetime.utcnow()
            }
        }
    )

    # Handle pending deductions if any
    if deduction_to_apply > 0:
        await db.wallets.update_one(
            {'user_id': seller_id},
            {
                '$inc': {'pending_deductions': -deduction_to_apply},
                '$set': {'updated_at': datetime.utcnow()}
            }
        )

        await create_transaction(
            user_id=seller_id,
            amount=-deduction_to_apply,
            transaction_type=TransactionType.SELLER_CANCELLATION_PENALTY,
            status=TransactionStatus.COMPLETED,
            description=f"Automatic deduction of pending cancellation penalty (KES {deduction_to_apply:.2f})",
            order_id=order_id
        )

        platform_penalty_credit_txn = await create_transaction(
            user_id=PLATFORM_WALLET_ID,
            amount=deduction_to_apply,
            transaction_type=TransactionType.SELLER_CANCELLATION_PENALTY,
            status=TransactionStatus.COMPLETED,
            description=f"Seller penalty deduction from earnings (order {order_id})",
            order_id=order_id
        )

        await update_wallet_balance(
            PLATFORM_WALLET_ID,
            deduction_to_apply,
            str(platform_penalty_credit_txn['_id'])
        )

    logger.info(f"Released pending payment for order {order_id}. Amount: {actual_seller_credit}")

# Socket.IO Event Handlers
@sio.event
async def connect(sid, environ):
    auth = await _authenticate_socket(environ)
    if not auth:
        logger.warning(f"Socket connection rejected: {sid}")
        return False
    await sio.save_session(sid, {'user_id': auth['user_id'], 'role': auth['role']})
    connected_users[auth['user_id']] = sid
    logger.info(f"Socket connected and authenticated: {sid} user={auth['user_id']}")
    return True

@sio.event
async def disconnect(sid):
    # Remove user from connected users
    user_id = await _get_socket_user(sid)
    if user_id:
        connected_users.pop(user_id, None)
    logger.info(f"Client disconnected: {sid}")

@sio.event
async def register_user(sid, data):
    """Register user with their socket ID"""
    # Deprecated: socket auth is handled on connect
    user_id = await _get_socket_user(sid)
    if user_id:
        await sio.emit('registered', {'user_id': user_id}, room=sid)

@sio.event
async def send_message(sid, data):
    """Handle incoming chat messages"""
    try:
        sender_id = await _get_socket_user(sid)
        if not sender_id:
            await sio.emit('error', {'message': 'Unauthorized'}, room=sid)
            return

        conversation_id = data.get('conversation_id')
        content = data.get('content')

        if not all([conversation_id, content]):
            await sio.emit('error', {'message': 'Missing required fields'}, room=sid)
            return

        # Get conversation to find recipient
        conv = await db.conversations.find_one({'id': conversation_id})
        if not conv:
            await sio.emit('error', {'message': 'Conversation not found'}, room=sid)
            return
        if sender_id not in [str(conv.get('buyer_id')), str(conv.get('seller_id'))]:
            await sio.emit('error', {'message': 'Not authorized for this conversation'}, room=sid)
            return

        # Moderate message with enhanced detection
        moderation_result = await moderation_service.moderate_message(
            content=content,
            conversation_id=conversation_id,
            sender_id=sender_id,
            db=db
        )

        # If blocked, store flagged message for admin review and notify sender
        if moderation_result['is_blocked']:
            message_data = {
                'id': str(uuid.uuid4()),
                'conversation_id': conversation_id,
                'sender_id': sender_id,
                'content_original': content,
                'content_filtered': moderation_result.get('filtered_content', content),
                'is_blocked': True,
                'violation_type': moderation_result.get('violation_type'),
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'blocked'
            }

            try:
                await db.messages.insert_one(message_data)
            except Exception as save_error:
                logger.error(f"Failed to save blocked message: {save_error}", exc_info=True)

            warning_data = {
                'type': 'warning',
                'message': moderation_result['warning_message'],
                'violation_type': moderation_result['violation_type'],
                'order_paid': moderation_result.get('order_paid', False)
            }
            await sio.emit('message_blocked', warning_data, room=sid)
            return

        # Create message
        message_data = {
            'id': str(uuid.uuid4()),
            'conversation_id': conversation_id,
            'sender_id': sender_id,
            'content_original': content,
            'content_filtered': moderation_result['filtered_content'],
            'is_blocked': False,
            'violation_type': moderation_result.get('violation_type'),
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'sent'
        }

        # Save to DB
        await db.messages.insert_one(message_data)

        # Update conversation last message
        await db.conversations.update_one(
            {'id': conversation_id},
            {
                '$set': {
                    'last_message': moderation_result['filtered_content'][:50],
                    'last_message_time': datetime.utcnow().isoformat()
                }
            }
        )

        # Prepare message for sending
        send_data = {
            'id': message_data['id'],
            'conversation_id': conversation_id,
            'sender_id': sender_id,
            'content': moderation_result['filtered_content'],
            'timestamp': message_data['timestamp'],
            'status': 'delivered',
            'has_masked_content': moderation_result.get('has_masked_content', False)
        }

        # Send to sender
        await sio.emit('message_sent', send_data, room=sid)

        # If masked content, send warning
        if moderation_result.get('has_masked_content'):
            warning_data = {
                'type': 'info',
                'message': moderation_result['warning_message']
            }
            await sio.emit('content_masked', warning_data, room=sid)

        # Send to recipient if online
        recipient_id = conv['buyer_id'] if sender_id == conv['seller_id'] else conv['seller_id']
        if recipient_id in connected_users:
            recipient_sid = connected_users[recipient_id]
            await sio.emit('new_message', send_data, room=recipient_sid)

    except Exception as e:
        logger.error(f"Error handling message: {e}")
        await sio.emit('error', {'message': str(e)}, room=sid)

@sio.event
async def join_conversation(sid, data):
    """Join a conversation room"""
    conversation_id = data.get('conversation_id')
    if not conversation_id:
        await sio.emit('error', {'message': 'Missing conversation_id'}, room=sid)
        return
    user_id = await _get_socket_user(sid)
    if not user_id:
        await sio.emit('error', {'message': 'Unauthorized'}, room=sid)
        return
    conv = await db.conversations.find_one({'id': conversation_id})
    if not conv:
        await sio.emit('error', {'message': 'Conversation not found'}, room=sid)
        return
    if user_id not in [str(conv.get('buyer_id')), str(conv.get('seller_id'))]:
        await sio.emit('error', {'message': 'Not authorized for this conversation'}, room=sid)
        return
    await sio.enter_room(sid, conversation_id)
    logger.info(f"Socket {sid} joined conversation {conversation_id}")

# Messaging REST API Endpoints
@api_router.post("/conversations", response_model=Conversation)
async def create_conversation(
    conv: ConversationCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create or get existing conversation between two users"""
    current_user_id = str(current_user["_id"])
    if current_user_id not in [str(conv.buyer_id), str(conv.seller_id)]:
        raise HTTPException(status_code=403, detail="Not authorized to create this conversation")

    # Check if conversation already exists between these two users
    # regardless of service_id - we want one conversation per user pair
    existing = await db.conversations.find_one(
        {
            '$or': [
                {
                    'buyer_id': conv.buyer_id,
                    'seller_id': conv.seller_id
                },
                {
                    'buyer_id': conv.seller_id,
                    'seller_id': conv.buyer_id
                }
            ]
        }
    )

    if existing:
        # Update the service_id to the most recent one being discussed
        await db.conversations.update_one(
            {'id': existing['id']},
            {'$set': {'service_id': conv.service_id}}
        )
        existing['service_id'] = conv.service_id

        # Convert ObjectId to string for id field
        if '_id' in existing:
            del existing['_id']
        # Ensure datetime fields are datetime objects
        if isinstance(existing.get('created_at'), str):
            existing['created_at'] = datetime.fromisoformat(existing['created_at'])
        if existing.get('last_message_time') and isinstance(existing['last_message_time'], str):
            existing['last_message_time'] = datetime.fromisoformat(existing['last_message_time'])

        logger.info(f"Found existing conversation {existing['id']} between {conv.buyer_id} and {conv.seller_id}")
        return existing

    # Create new conversation
    conversation_data = {
        'id': str(uuid.uuid4()),
        'buyer_id': conv.buyer_id,
        'seller_id': conv.seller_id,
        'service_id': conv.service_id,
        'created_at': datetime.utcnow().isoformat(),
        'last_message': None,
        'last_message_time': None
    }

    await db.conversations.insert_one(conversation_data)

    logger.info(f"Created new conversation {conversation_data['id']} between {conv.buyer_id} and {conv.seller_id}")

    # Return with datetime objects for response
    conversation_data['created_at'] = datetime.utcnow()
    return conversation_data

@api_router.get("/conversations/user/{user_id}", response_model=List[ConversationWithDetails])
async def get_user_conversations(
    user_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get all conversations for a user"""
    if str(current_user["_id"]) != str(user_id):
        raise HTTPException(status_code=403, detail="Not authorized to view these conversations")

    conversations = await db.conversations.find(
        {
            '$or': [
                {'buyer_id': user_id},
                {'seller_id': user_id}
            ]
        }
    ).to_list(100)

    result = []
    for conv in conversations:
        # Remove MongoDB _id
        if '_id' in conv:
            del conv['_id']

        # Convert timestamps
        if isinstance(conv.get('created_at'), str):
            conv['created_at'] = datetime.fromisoformat(conv['created_at'])
        if conv.get('last_message_time') and isinstance(conv['last_message_time'], str):
            conv['last_message_time'] = datetime.fromisoformat(conv['last_message_time'])

        contact_unlock_active = await moderation_service._check_order_paid(conv.get('id'), db)

        # Determine other user - be explicit about the comparison
        buyer_id = str(conv.get('buyer_id', '')).strip()
        seller_id = str(conv.get('seller_id', '')).strip()
        current_user_id = str(user_id).strip()

        if current_user_id == buyer_id:
            # Current user is the buyer, so other user is the seller
            other_user_id = seller_id
        elif current_user_id == seller_id:
            # Current user is the seller, so other user is the buyer
            other_user_id = buyer_id
        else:
            # This shouldn't happen, but handle it gracefully
            logger.warning(f"User {current_user_id} not found in conversation {conv.get('id')}")
            other_user_id = buyer_id if buyer_id != current_user_id else seller_id

        # Fetch other user's name
        other_user_name = 'Unknown User'
        if other_user_id:
            try:
                other_user = await db.users.find_one({'_id': ObjectId(other_user_id)})
                if other_user:
                    other_user_name = other_user.get('name', 'Unknown User')
                    logger.info(f"Conversation {conv.get('id')}: User {current_user_id} chatting with {other_user_name} ({other_user_id})")
                else:
                    logger.warning(f"User {other_user_id} not found in users collection")
            except Exception as e:
                logger.error(f"Error fetching user {other_user_id}: {e}", exc_info=True)

        # Count unread (simplified - in production, track per-user read status)
        unread_count = 0

        result.append(ConversationWithDetails(
            id=conv.get('id'),
            buyer_id=buyer_id,
            seller_id=seller_id,
            service_id=conv.get('service_id'),
            created_at=conv.get('created_at'),
            last_message=(
                conv.get('last_message')
                if contact_unlock_active or not conv.get('last_message')
                else moderation_service.mask_contact_info(conv.get('last_message'))
            ),
            last_message_time=conv.get('last_message_time'),
            other_user_id=other_user_id,
            other_user_name=other_user_name,
            unread_count=unread_count
        ))

    # Sort by last message time
    result.sort(key=lambda x: x.last_message_time or x.created_at, reverse=True)

    return result

@api_router.get("/conversations/{conversation_id}/messages", response_model=List[Message])
async def get_conversation_messages(
    conversation_id: str,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """Get messages for a conversation"""
    conv = await db.conversations.find_one({'id': conversation_id})
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    current_user_id = str(current_user["_id"])
    if current_user_id not in [str(conv.get('buyer_id')), str(conv.get('seller_id'))]:
        raise HTTPException(status_code=403, detail="Not authorized to view these messages")

    messages = await db.messages.find(
        {'conversation_id': conversation_id, 'is_blocked': False}
    ).sort('timestamp', 1).limit(limit).to_list(limit)

    contact_unlock_active = await moderation_service._check_order_paid(conversation_id, db)

    # Process messages
    for msg in messages:
        # Remove MongoDB _id
        if '_id' in msg:
            del msg['_id']

        # Convert timestamps
        if isinstance(msg.get('timestamp'), str):
            msg['timestamp'] = datetime.fromisoformat(msg['timestamp'])
        if not contact_unlock_active:
            msg['content_filtered'] = moderation_service.mask_contact_info(msg.get('content_filtered', ''))
            msg['content_original'] = moderation_service.mask_contact_info(msg.get('content_original', ''))

    return messages

# Native WebSocket endpoint for React Native Hermes compatibility
@app.websocket("/ws")
async def websocket_chat_endpoint(websocket: WebSocket):
    """
    Native WebSocket endpoint for Hermes-compatible React Native chat
    Provides the same functionality as Socket.IO but using native WebSocket

    Security: Validates origin header to prevent unauthorized connections
    """
    # Validate origin header for security
    origin = websocket.headers.get('origin', '')

    # In production, validate against allowed origins
    if ENVIRONMENT == 'production':
        allowed_origins = os.environ.get('WEBSOCKET_ALLOWED_ORIGINS', '').split(',')
        allowed_origins = [o.strip() for o in allowed_origins if o.strip()]

        # If origins are configured and current origin is not in the list, reject
        if allowed_origins and origin not in allowed_origins:
            logger.warning(f"WebSocket connection rejected: invalid origin {origin}")
            await websocket.close(code=1008, reason="Invalid origin")
            return

    await websocket_endpoint(websocket, db, moderation_service)

# Auth Routes
@api_router.post("/auth/register", response_model=LoginResponse)
async def register(user_data: UserCreate, request: Request):
    # Check if user exists
    existing = await db.users.find_one({'email': user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Public registration must never create admin users.
    requested_role = user_data.role
    if requested_role == UserRole.ADMIN:
        await log_security_event(
            event_type='admin_role_assignment_attempt',
            severity='high',
            details={'source': 'auth_register'},
            user_id=None,
            request=request
        )
        requested_role = UserRole.BUYER

    # Create user
    user_dict = {
        'name': user_data.name,
        'email': user_data.email,
        'phone': user_data.phone,
        'password': hash_password(user_data.password),
        'role': requested_role,
        'kyc_status': KYCStatus.PENDING,
        'avatar': None,
        'security_question': user_data.security_question,
        'security_answer': hash_password(user_data.security_answer.lower().strip()),
        'created_at': datetime.utcnow()
    }
    
    result = await db.users.insert_one(user_dict)
    user_id = str(result.inserted_id)

    # Auto-create seller profile if user is registering as a seller
    if requested_role == UserRole.SELLER:
        seller_profile = {
            'user_id': user_id,
            'business_name': user_data.name,  # Default to user's name, can be updated later
            'rating': 0.0,
            'total_reviews': 0,
            'license_file': '',  # Empty, seller can upload later
            'bank_details': {},  # Empty, seller can add later
            'created_at': datetime.utcnow()
        }
        await db.seller_profiles.insert_one(seller_profile)

    token = create_token(user_id, requested_role)
    device_id = request.headers.get('X-Device-ID')
    refresh_token = await _create_refresh_token(user_id, device_id)

    return {
        'token': token,
        'refresh_token': refresh_token,
        'user': {
            'id': user_id,
            'name': user_data.name,
            'email': user_data.email,
            'phone': user_data.phone,
            'role': requested_role,
            'kyc_status': KYCStatus.PENDING,
            'avatar': None,
            'security_question_needs_setup': False,
            'subscription_tier': SubscriptionTier.NONE,
            'subscription_expires_at': None,
            'created_at': user_dict['created_at']
        }
    }

@api_router.post("/auth/login", response_model=LoginResponse)
async def login(credentials: UserLogin, request: Request):
    try:
        user = await db.users.find_one({'email': credentials.email})

        # Check if user exists
        if not user:
            await log_security_event(
                event_type='login_failed',
                severity='medium',
                details={'reason': 'user_not_found', 'email': credentials.email},
                request=request
            )
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Verify required fields exist
        if 'password' not in user:
            logger.error(f"User {credentials.email} missing password field")
            raise HTTPException(status_code=500, detail="User account is corrupted. Please contact support.")

        # Verify password
        try:
            if not verify_password(credentials.password, user['password']):
                await log_security_event(
                    event_type='login_failed',
                    severity='medium',
                    details={'reason': 'invalid_password', 'email': credentials.email},
                    user_id=str(user['_id']),
                    request=request
                )
                raise HTTPException(status_code=401, detail="Invalid credentials")
        except Exception as e:
            logger.error(f"Password verification error for {credentials.email}: {str(e)}")
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Check if account is suspended BEFORE generating token
        if user.get('suspended', False):
            suspension_reason = user.get('suspension_reason', 'No reason provided')
            suspension_date = user.get('suspension_date')

            detail_msg = f"Your account has been suspended. Reason: {suspension_reason}"
            if suspension_date:
                detail_msg += f" (Suspended on: {suspension_date.strftime('%Y-%m-%d')})"
            detail_msg += " Please contact support for assistance."

            logger.warning(f"Suspended user attempted login: {credentials.email} - {suspension_reason}")
            await log_security_event(
                event_type='login_suspended',
                severity='high',
                details={'reason': suspension_reason, 'email': credentials.email},
                user_id=str(user['_id']),
                request=request
            )
            raise HTTPException(status_code=403, detail=detail_msg)

        # Check for required fields
        required_fields = ['name', 'email', 'phone', 'role']
        missing_fields = [field for field in required_fields if field not in user]
        if missing_fields:
            logger.error(f"User {credentials.email} missing fields: {missing_fields}")
            raise HTTPException(status_code=500, detail="User account is incomplete. Please contact support.")

        user_id = str(user['_id'])
        token = create_token(user_id, user['role'])
        device_id = request.headers.get('X-Device-ID')
        refresh_token = await _create_refresh_token(user_id, device_id)

        return {
            'token': token,
            'refresh_token': refresh_token,
            'user': {
                'id': user_id,
                'name': user['name'],
                'email': user['email'],
                'phone': user['phone'],
                'role': user['role'],
                'kyc_status': user.get('kyc_status', KYCStatus.PENDING),
                'avatar': user.get('avatar'),
                'security_question_needs_setup': security_question_needs_setup(user),
                'subscription_tier': build_seller_subscription_payload(user)['seller_subscription_tier'],
                'subscription_expires_at': build_seller_subscription_payload(user)['subscription_expires_at'],
                'created_at': user.get('created_at', datetime.utcnow())
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during login for {credentials.email}: {str(e)}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred. Please try again later.")

@api_router.post("/auth/refresh", response_model=RefreshResponse)
async def refresh_token(request_data: RefreshTokenRequest, request: Request = None):
    try:
        token_hash = _hash_refresh_token(request_data.refresh_token)
        token_record = await db.refresh_tokens.find_one({'token_hash': token_hash, 'revoked': False})

        if not token_record:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        if token_record.get('expires_at') and datetime.utcnow() > token_record['expires_at']:
            await db.refresh_tokens.update_one({'_id': token_record['_id']}, {'$set': {'revoked': True}})
            raise HTTPException(status_code=401, detail="Refresh token expired")

        user = await db.users.find_one({'_id': ObjectId(token_record['user_id'])})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        if user.get('suspended', False):
            raise HTTPException(status_code=403, detail="Account suspended")

        if token_record.get('device_id'):
            device_id = request.headers.get('X-Device-ID') if request else None
            if not device_id or device_id != token_record.get('device_id'):
                await db.refresh_tokens.update_one({'_id': token_record['_id']}, {'$set': {'revoked': True}})
                raise HTTPException(status_code=401, detail="Refresh token device mismatch")

        # Rotate refresh token
        await db.refresh_tokens.update_one({'_id': token_record['_id']}, {'$set': {'revoked': True}})
        new_refresh = await _create_refresh_token(str(user['_id']), token_record.get('device_id'))
        new_access = create_token(str(user['_id']), user['role'])

        return {
            'token': new_access,
            'refresh_token': new_refresh
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Refresh token error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to refresh token")

@api_router.post("/auth/logout")
async def logout(request_data: LogoutRequest, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user['_id'])
        if request_data.all_devices or not request_data.refresh_token:
            await db.refresh_tokens.update_many({'user_id': user_id}, {'$set': {'revoked': True}})
            return {'success': True, 'message': 'Logged out from all devices'}

        token_hash = _hash_refresh_token(request_data.refresh_token)
        await db.refresh_tokens.update_one(
            {'user_id': user_id, 'token_hash': token_hash},
            {'$set': {'revoked': True}}
        )
        return {'success': True, 'message': 'Logged out'}
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to logout")


async def _login_or_create_google_user(email: str, name: str, avatar: Optional[str], role: UserRole, device_id: Optional[str] = None):
    # Check if user exists
    user = await db.users.find_one({'email': email})

    if user:
        # User exists, log them in
        user_id = str(user['_id'])
        token = create_token(user_id, user['role'])
        refresh_token = await _create_refresh_token(user_id, device_id)

        # Update avatar if provided and not already set
        if avatar and not user.get('avatar'):
            await db.users.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {'avatar': avatar}}
            )
            user['avatar'] = avatar

        return {
            'token': token,
            'refresh_token': refresh_token,
            'user': {
                'id': user_id,
                'name': user['name'],
                'email': user['email'],
                'phone': user.get('phone', ''),
                'role': user['role'],
                'kyc_status': user.get('kyc_status', KYCStatus.PENDING),
                'avatar': user.get('avatar'),
                'security_question_needs_setup': security_question_needs_setup(user),
                'subscription_tier': build_seller_subscription_payload(user)['seller_subscription_tier'],
                'subscription_expires_at': build_seller_subscription_payload(user)['subscription_expires_at'],
                'created_at': user['created_at']
            }
        }

    # Public OAuth flow must never create admin users.
    requested_role = role
    if requested_role == UserRole.ADMIN:
        requested_role = UserRole.BUYER

    # Create new user
    user_dict = {
        'name': name,
        'email': email,
        'phone': '',  # Can be updated later
        'password': hash_password(str(uuid.uuid4())),  # Random password
        'role': requested_role,
        'kyc_status': KYCStatus.PENDING,
        'avatar': avatar,
        'security_question': 'Google OAuth User',
        'security_answer': hash_password(str(uuid.uuid4())),  # Random answer
        'created_at': datetime.utcnow(),
        'auth_provider': 'google'
    }

    result = await db.users.insert_one(user_dict)
    user_id = str(result.inserted_id)

    # Auto-create seller profile if registering as seller
    if requested_role == UserRole.SELLER:
        seller_profile = {
            'user_id': user_id,
            'business_name': name,
            'rating': 0.0,
            'total_reviews': 0,
            'license_file': '',
            'bank_details': {},
            'created_at': datetime.utcnow()
        }
        await db.sellers.insert_one(seller_profile)

    token = create_token(user_id, requested_role)
    refresh_token = await _create_refresh_token(user_id, device_id)

    return {
        'token': token,
        'refresh_token': refresh_token,
        'user': {
            'id': user_id,
            'name': name,
            'email': email,
            'phone': '',
            'role': requested_role,
            'kyc_status': KYCStatus.PENDING,
            'avatar': avatar,
            'security_question_needs_setup': True,
            'subscription_tier': SubscriptionTier.NONE,
            'subscription_expires_at': None,
            'created_at': user_dict['created_at']
        }
    }

@api_router.post("/auth/google", response_model=LoginResponse)
async def google_auth(auth_data: GoogleAuthRequest, request: Request):
    """Authenticate user with Google OAuth"""
    try:
        id_token = auth_data.id_token

        if auth_data.code and not id_token:
            # Exchange authorization code for tokens
            client_id = os.environ.get("GOOGLE_AUTH_CLIENT_ID") or os.environ.get("GOOGLE_CLIENT_ID")
            client_secret = os.environ.get("GOOGLE_AUTH_CLIENT_SECRET") or os.environ.get("GOOGLE_CLIENT_SECRET")
            if not client_id or not client_secret:
                raise HTTPException(
                    status_code=500,
                    detail="Google OAuth client is not configured"
                )

            data = {
                "client_id": client_id,
                "client_secret": client_secret,
                "code": auth_data.code,
                "grant_type": "authorization_code",
                "redirect_uri": auth_data.redirect_uri,
            }
            if auth_data.code_verifier:
                data["code_verifier"] = auth_data.code_verifier

            async with httpx.AsyncClient() as client:
                token_response = await client.post(
                    "https://oauth2.googleapis.com/token",
                    data=data
                )

                if token_response.status_code != 200:
                    error_data = token_response.json()
                    raise HTTPException(
                        status_code=401,
                        detail=error_data.get("error_description", "Failed to exchange code")
                    )

                token_data = token_response.json()
                id_token = token_data.get("id_token")

        if not id_token:
            raise HTTPException(status_code=400, detail="Missing Google token")

        # Verify Google ID token
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}"
            )

            if response.status_code != 200:
                raise HTTPException(status_code=401, detail="Invalid Google token")

            token_info = response.json()

            # Extract user info from token
            email = token_info.get('email')
            name = token_info.get('name', email.split('@')[0])
            avatar = token_info.get('picture')

            if not email:
                raise HTTPException(status_code=400, detail="Email not provided by Google")

            device_id = request.headers.get('X-Device-ID')
            return await _login_or_create_google_user(email, name, avatar, auth_data.role, device_id)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Google auth error: {str(e)}")
        raise HTTPException(status_code=500, detail="Authentication failed")


@api_router.post("/auth/google/initiate", response_model=GoogleAuthInitiateResponse)
async def google_auth_initiate(request: GoogleAuthInitiateRequest):
    client_id = os.environ.get("GOOGLE_AUTH_CLIENT_ID") or os.environ.get("GOOGLE_CLIENT_ID")
    if not client_id:
        raise HTTPException(status_code=503, detail="Google OAuth client is not configured")

    state = secrets.token_urlsafe(32)
    google_auth_states[state] = {
        "redirect_uri": request.redirect_uri,
        "return_to": request.return_to,
        "role": request.role,
        "expires_at": datetime.utcnow() + timedelta(minutes=10)
    }

    params = {
        "client_id": client_id,
        "redirect_uri": request.redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "online",
        "prompt": "consent",
        "state": state
    }

    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
    return GoogleAuthInitiateResponse(auth_url=auth_url, state=state)


@api_router.get("/auth/google/callback")
async def google_auth_callback(code: str, state: str):
    state_data = google_auth_states.get(state)
    if not state_data:
        raise HTTPException(status_code=400, detail="Invalid or expired state")

    if datetime.utcnow() > state_data["expires_at"]:
        del google_auth_states[state]
        raise HTTPException(status_code=400, detail="State expired")

    del google_auth_states[state]

    client_id = os.environ.get("GOOGLE_AUTH_CLIENT_ID") or os.environ.get("GOOGLE_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_AUTH_CLIENT_SECRET") or os.environ.get("GOOGLE_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise HTTPException(status_code=500, detail="Google OAuth client is not configured")

    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": state_data["redirect_uri"],
    }

    async with httpx.AsyncClient() as client:
        token_response = await client.post("https://oauth2.googleapis.com/token", data=data)
        if token_response.status_code != 200:
            error_data = token_response.json()
            raise HTTPException(
                status_code=401,
                detail=error_data.get("error_description", "Failed to exchange code")
            )

        token_data = token_response.json()
        id_token = token_data.get("id_token")

    if not id_token:
        raise HTTPException(status_code=400, detail="Missing Google token")

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}"
        )
        if response.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid Google token")
        token_info = response.json()

    email = token_info.get('email')
    name = token_info.get('name', email.split('@')[0] if email else 'User')
    avatar = token_info.get('picture')

    if not email:
        raise HTTPException(status_code=400, detail="Email not provided by Google")

    login_response = await _login_or_create_google_user(email, name, avatar, state_data["role"], None)

    auth_code = secrets.token_urlsafe(24)
    google_auth_codes[auth_code] = {
        "data": login_response,
        "expires_at": datetime.utcnow() + timedelta(minutes=5)
    }

    return_to = state_data["return_to"]
    separator = '&' if ('?' in return_to) else '?'
    return RedirectResponse(f"{return_to}{separator}auth_code={auth_code}", status_code=302)


@api_router.post("/auth/google/complete", response_model=LoginResponse)
async def google_auth_complete(request: GoogleAuthCompleteRequest):
    data = google_auth_codes.get(request.auth_code)
    if not data:
        raise HTTPException(status_code=400, detail="Invalid or expired auth code")

    if datetime.utcnow() > data["expires_at"]:
        del google_auth_codes[request.auth_code]
        raise HTTPException(status_code=400, detail="Auth code expired")

    del google_auth_codes[request.auth_code]
    return data["data"]

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    subscription_info = build_seller_subscription_payload(current_user)
    return {
        'id': str(current_user['_id']),
        'name': current_user['name'],
        'email': current_user['email'],
        'phone': current_user['phone'],
        'role': current_user['role'],
        'kyc_status': current_user.get('kyc_status', KYCStatus.PENDING),
        'avatar': current_user.get('avatar'),
        'security_question_needs_setup': security_question_needs_setup(current_user),
        'subscription_tier': subscription_info['seller_subscription_tier'],
        'subscription_expires_at': subscription_info['subscription_expires_at'],
        'created_at': current_user['created_at']
    }

# ==================== GOOGLE CALENDAR INTEGRATION ROUTES ====================

from google_calendar_service import get_calendar_service
import secrets

# Pydantic Models for Calendar
class CalendarAuthInitiate(BaseModel):
    redirect_uri: Optional[str] = None
    return_to: Optional[str] = None

class CalendarAuthResponse(BaseModel):
    auth_url: str
    state: str

class CalendarOAuthCallback(BaseModel):
    code: str
    state: str
    redirect_uri: Optional[str] = None

class CalendarConnectionResponse(BaseModel):
    success: bool
    calendar_connected: bool
    primary_calendar_id: str
    calendars: list

class CalendarEventCreate(BaseModel):
    order_id: str
    sync_to: list = ["provider", "customer"]

# In-memory state storage (use Redis in production)
calendar_auth_states = {}

async def _sync_upcoming_bookings_for_user(user_id: str):
    calendar_service = get_calendar_service()
    if not calendar_service:
        return

    # Determine user and role
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        return

    is_seller = user.get('role') == UserRole.SELLER
    now = datetime.utcnow()

    query = {
        'booking_date': {'$gte': now},
        'service_status': {'$nin': ['declined', 'cancelled']},
    }

    if is_seller:
        query['seller_id'] = user_id
        query['$or'] = [
            {'calendar_events.provider_event_id': {'$exists': False}},
            {'calendar_events.provider_event_id': None},
        ]
    else:
        query['buyer_id'] = user_id
        query['$or'] = [
            {'calendar_events.customer_event_id': {'$exists': False}},
            {'calendar_events.customer_event_id': None},
        ]

    orders = await db.orders.find(query).to_list(100)
    if not orders:
        return

    access_token = await calendar_service.get_valid_access_token(user_id)
    if not access_token:
        return

    calendar_id = user.get("google_calendar", {}).get("calendar_id", "primary")

    for order in orders:
        try:
            service_id = order.get('service_id')
            listing = None
            if service_id:
                listing = await db.service_listings.find_one({'_id': ObjectId(service_id)})

            buyer = await db.users.find_one({"_id": ObjectId(order['buyer_id'])})
            provider = await db.users.find_one({"_id": ObjectId(order['seller_id'])})

            # Parse and combine booking_time with booking_date
            booking_time_str = order.get('booking_time', '09:00')
            booking_time_parts = booking_time_str.split(":")
            booking_hour = int(booking_time_parts[0])
            booking_minute = int(booking_time_parts[1]) if len(booking_time_parts) > 1 else 0

            booking_date = order.get('booking_date')
            if isinstance(booking_date, datetime):
                booking_datetime = booking_date.replace(
                    hour=booking_hour,
                    minute=booking_minute,
                    second=0,
                    microsecond=0
                )
            else:
                # Handle string dates
                booking_datetime = datetime.fromisoformat(str(booking_date).replace("Z", "+00:00"))
                booking_datetime = booking_datetime.replace(
                    hour=booking_hour,
                    minute=booking_minute,
                    second=0,
                    microsecond=0
                )

            booking_for_calendar = {
                "_id": str(order['_id']),
                "booking_date": booking_datetime,  # Now includes correct time!
                "duration_minutes": listing.get('duration_minutes', 90) if listing else 90,
                "service_name": (listing.get('service_name') if listing else None) or order.get('service_name', 'Service'),
                "total_amount": order.get('total_amount', order.get('price', 0)),
                "payment_method": order.get('payment_method', 'mpesa'),
                "payment_status": order.get('payment_status', 'pending'),
                "service_status": order.get('service_status', 'pending'),
                "service_address": order.get('service_address', ''),
                "customer_name": buyer.get('name', 'Customer') if buyer else 'Customer',
                "customer_phone": buyer.get('phone', 'N/A') if buyer else 'N/A',
                "customer_email": buyer.get('email') if buyer else None,
                "provider_name": provider.get('name', 'Provider') if provider else 'Provider',
                "provider_email": provider.get('email') if provider else None,
            }

            event_data = calendar_service.format_booking_as_event(
                booking_for_calendar,
                for_provider=is_seller
            )

            created_event = await calendar_service.create_event(
                access_token,
                calendar_id,
                event_data
            )

            if is_seller:
                await db.orders.update_one(
                    {"_id": order["_id"]},
                    {"$set": {
                        "calendar_events.provider_event_id": created_event["id"],
                        "calendar_events.calendar_sync_status": "synced",
                        "calendar_events.last_calendar_sync": datetime.utcnow()
                    }}
                )
            else:
                await db.orders.update_one(
                    {"_id": order["_id"]},
                    {"$set": {
                        "calendar_events.customer_event_id": created_event["id"]
                    }}
                )
        except Exception as e:
            logger.error(f"📅 [CALENDAR] ❌ Failed to backfill booking {order.get('_id')}: {e}")

async def _remove_calendar_events_for_order(order: dict):
    calendar_service = get_calendar_service()
    if not calendar_service:
        return

    calendar_events = order.get('calendar_events', {})
    provider_event_id = calendar_events.get('provider_event_id')
    customer_event_id = calendar_events.get('customer_event_id')

    if provider_event_id:
        try:
            provider_id = order.get('seller_id')
            provider = await db.users.find_one({'_id': ObjectId(provider_id)}) if provider_id else None
            provider_access_token = await calendar_service.get_valid_access_token(provider_id)
            if provider_access_token and provider:
                calendar_id = provider.get("google_calendar", {}).get("calendar_id", "primary")
                await calendar_service.delete_event(provider_access_token, calendar_id, provider_event_id)
        except Exception as e:
            logger.error(f"📅 [CALENDAR] ❌ Failed to delete provider event {provider_event_id}: {e}")

    if customer_event_id:
        try:
            customer_id = order.get('buyer_id')
            customer = await db.users.find_one({'_id': ObjectId(customer_id)}) if customer_id else None
            customer_access_token = await calendar_service.get_valid_access_token(customer_id)
            if customer_access_token and customer:
                calendar_id = customer.get("google_calendar", {}).get("calendar_id", "primary")
                await calendar_service.delete_event(customer_access_token, calendar_id, customer_event_id)
        except Exception as e:
            logger.error(f"📅 [CALENDAR] ❌ Failed to delete customer event {customer_event_id}: {e}")

async def _delete_failed_order(order_id: str, reason: str, request: Optional[Request] = None):
    order = await db.orders.find_one({'_id': ObjectId(order_id)})
    if not order:
        return
    await _remove_calendar_events_for_order(order)
    await db.orders.delete_one({'_id': ObjectId(order_id)})
    try:
        await log_security_event(
            event_type='order_auto_deleted',
            severity='medium',
            details={'order_id': order_id, 'reason': reason},
            user_id=order.get('buyer_id'),
            request=request
        )
    except Exception:
        pass

async def _create_calendar_events_for_order(order: dict):
    service_id = order.get('service_id')
    if not service_id:
        return

    calendar_service = get_calendar_service()
    if not calendar_service:
        return

    calendar_events = order.get('calendar_events', {})
    provider_event_id = calendar_events.get('provider_event_id')
    customer_event_id = calendar_events.get('customer_event_id')

    try:
        listing = await db.service_listings.find_one({'_id': ObjectId(service_id)})
        buyer = await db.users.find_one({'_id': ObjectId(order['buyer_id'])})
        provider = await db.users.find_one({'_id': ObjectId(order['seller_id'])})

        booking_time_str = order.get('booking_time', '09:00')
        booking_time_parts = booking_time_str.split(":")
        booking_hour = int(booking_time_parts[0])
        booking_minute = int(booking_time_parts[1]) if len(booking_time_parts) > 1 else 0

        booking_date = order.get('booking_date')
        if isinstance(booking_date, datetime):
            booking_datetime = booking_date.replace(
                hour=booking_hour,
                minute=booking_minute,
                second=0,
                microsecond=0
            )
        else:
            booking_datetime = datetime.fromisoformat(str(booking_date).replace("Z", "+00:00"))
            booking_datetime = booking_datetime.replace(
                hour=booking_hour,
                minute=booking_minute,
                second=0,
                microsecond=0
            )

        booking_for_calendar = {
            "_id": str(order['_id']),
            "booking_date": booking_datetime,
            "duration_minutes": listing.get('duration_minutes', 90) if listing else 90,
            "service_name": (listing.get('service_name') if listing else None) or order.get('service_name', 'Service'),
            "total_amount": order.get('total_amount', order.get('price', 0)),
            "payment_method": order.get('payment_method', 'mpesa'),
            "payment_status": order.get('payment_status', 'pending'),
            "service_address": order.get('service_address', ''),
            "customer_name": buyer.get('name', 'Customer') if buyer else 'Customer',
            "customer_phone": buyer.get('phone', 'N/A') if buyer else 'N/A',
            "customer_email": buyer.get('email') if buyer else None,
            "provider_name": provider.get('name', 'Provider') if provider else 'Provider',
            "provider_email": provider.get('email') if provider else None,
            "seller_id": order.get('seller_id'),
            "buyer_id": order.get('buyer_id')
        }

        if not provider_event_id:
            provider_access_token = await calendar_service.get_valid_access_token(order['seller_id'])
            if provider_access_token and provider:
                calendar_id = provider.get("google_calendar", {}).get("calendar_id", "primary")
                event_data = calendar_service.format_booking_as_event(booking_for_calendar, for_provider=True)
                created_event = await calendar_service.create_event(provider_access_token, calendar_id, event_data)
                await db.orders.update_one(
                    {"_id": order["_id"]},
                    {"$set": {
                        "calendar_events.provider_event_id": created_event["id"],
                        "calendar_events.calendar_sync_status": "synced",
                        "calendar_events.last_calendar_sync": datetime.utcnow()
                    }}
                )

        if not customer_event_id:
            customer_access_token = await calendar_service.get_valid_access_token(order['buyer_id'])
            if customer_access_token and buyer:
                calendar_id = buyer.get("google_calendar", {}).get("calendar_id", "primary")
                event_data = calendar_service.format_booking_as_event(booking_for_calendar, for_provider=False)
                created_event = await calendar_service.create_event(customer_access_token, calendar_id, event_data)
                await db.orders.update_one(
                    {"_id": order["_id"]},
                    {"$set": {
                        "calendar_events.customer_event_id": created_event["id"]
                    }}
                )
    except Exception as e:
        logger.error(f"📅 [CALENDAR] ❌ Calendar event creation failed for order {order.get('_id')}: {e}")

@api_router.post("/calendar/auth/initiate", response_model=CalendarAuthResponse)
async def initiate_calendar_oauth(
    request: CalendarAuthInitiate,
    current_user: dict = Depends(get_current_user)
):
    """
    Initiate Google OAuth flow for calendar access

    Returns authorization URL for user to visit
    """
    calendar_service = get_calendar_service()

    if not calendar_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google Calendar service not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in environment variables."
        )

    # Generate random state token for security
    state = secrets.token_urlsafe(32)

    # Store state with user ID (expires in 10 minutes)
    calendar_auth_states[state] = {
        "user_id": str(current_user["_id"]),
        "expires_at": datetime.utcnow() + timedelta(minutes=10),
        "redirect_uri": request.redirect_uri,
        "return_to": request.return_to,
    }

    # Generate authorization URL
    auth_url = calendar_service.get_auth_url(state, request.redirect_uri)

    return CalendarAuthResponse(
        auth_url=auth_url,
        state=state
    )

async def _handle_calendar_oauth_callback(
    code: str,
    state: str,
    redirect_uri: Optional[str] = None,
):
    """
    Handle OAuth callback and store tokens

    Called after user authorizes calendar access
    """
    calendar_service = get_calendar_service()

    if not calendar_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google Calendar service not configured"
        )

    # Verify state token
    state_data = calendar_auth_states.get(state)

    if not state_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired state token. Please try again."
        )

    # Check if state expired
    if datetime.utcnow() > state_data["expires_at"]:
        del calendar_auth_states[state]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="State token expired. Please restart the authorization process."
        )

    user_id = state_data["user_id"]

    # Clean up state
    del calendar_auth_states[state]

    effective_redirect_uri = (
        state_data.get("redirect_uri")
        or redirect_uri
        or os.environ.get("GOOGLE_REDIRECT_URI")
    )

    try:
        # Get user from database to use their email
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Exchange authorization code for tokens
        tokens = await calendar_service.exchange_code_for_tokens(
            code,
            effective_redirect_uri
        )

        # List user's calendars (optional; may fail if scope is limited)
        calendars = []
        try:
            calendars = await calendar_service.list_calendars(tokens["access_token"])
        except Exception as list_error:
            logger.warning(f"Calendar list failed, falling back to primary: {list_error}")

        # Find primary calendar or fall back to "primary"
        primary_calendar = next(
            (cal for cal in calendars if cal.get("primary")),
            calendars[0] if calendars else {"id": "primary"}
        )

        # Calculate token expiry
        token_expiry = datetime.utcnow() + timedelta(seconds=tokens.get("expires_in", 3600))

        # Store tokens in database (encrypted)
        # Note: We store user's existing email/name from their account
        # since we don't request userinfo scopes (using incremental authorization)
        calendar_data = {
            "connected": True,
            "access_token": calendar_service.encrypt_token(tokens["access_token"]),
            "refresh_token": calendar_service.encrypt_token(tokens.get("refresh_token", "")),
            "token_expiry": token_expiry,
            "calendar_id": primary_calendar["id"],
            "sync_enabled": True,
            "last_sync": datetime.utcnow(),
            "sync_errors": 0,
            "google_email": user.get("email"),
            "google_name": user.get("name")
        }

        # Update user document
        result = await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"google_calendar": calendar_data}}
        )

        if result.modified_count == 0:
            logger.warning(f"Failed to update user {user_id} with calendar data")

        logger.info(f"✅ Calendar connected for user {user_id}")

        # Backfill upcoming bookings into calendar for newly connected user
        try:
            await _sync_upcoming_bookings_for_user(user_id)
        except Exception as sync_error:
            logger.error(f"📅 [CALENDAR] ❌ Failed to backfill bookings for user {user_id}: {sync_error}")

        return CalendarConnectionResponse(
            success=True,
            calendar_connected=True,
            primary_calendar_id=primary_calendar["id"],
            calendars=calendars
        )

    except Exception as e:
        logger.error(f"OAuth callback failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to connect calendar: {str(e)}"
        )


@api_router.post("/calendar/auth/callback", response_model=CalendarConnectionResponse)
async def calendar_oauth_callback(request: CalendarOAuthCallback):
    return await _handle_calendar_oauth_callback(
        code=request.code,
        state=request.state,
        redirect_uri=request.redirect_uri,
    )


@api_router.get("/calendar/auth/callback")
async def calendar_oauth_callback_get(code: str, state: str):
    """
    Web callback used by Google OAuth redirects.
    After processing, redirect back to the app via return_to (if provided).
    """
    state_data = calendar_auth_states.get(state, {})
    return_to = state_data.get("return_to")

    try:
        await _handle_calendar_oauth_callback(code=code, state=state)
        if return_to:
            separator = '&' if ('?' in return_to) else '?'
            return RedirectResponse(f"{return_to}{separator}success=1", status_code=302)
        return HTMLResponse(
            content=(
                "<!doctype html>"
                "<html><head><meta charset=\"utf-8\" />"
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />"
                "<title>Calendar Connected</title>"
                "<style>"
                "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;"
                "background:#f5f7fb;color:#0f172a;margin:0;}"
                ".wrap{max-width:540px;margin:10vh auto;padding:24px;background:#fff;border-radius:12px;"
                "box-shadow:0 10px 30px rgba(15,23,42,0.08);text-align:center;}"
                ".icon{font-size:42px;}"
                "p{color:#475569;}"
                "</style></head>"
                "<body><div class=\"wrap\">"
                "<div class=\"icon\">✅</div>"
                "<h1>Google Calendar Connected</h1>"
                "<p>You can return to the app now.</p>"
                "</div></body></html>"
            ),
            status_code=200
        )
    except HTTPException as e:
        if return_to:
            separator = '&' if ('?' in return_to) else '?'
            error_msg = quote(str(e.detail))
            return RedirectResponse(
                f"{return_to}{separator}success=0&error={error_msg}",
                status_code=302
            )
        return HTMLResponse(
            content=(
                "<!doctype html>"
                "<html><head><meta charset=\"utf-8\" />"
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />"
                "<title>Calendar Connection Failed</title>"
                "<style>"
                "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;"
                "background:#fff5f5;color:#0f172a;margin:0;}"
                ".wrap{max-width:540px;margin:10vh auto;padding:24px;background:#fff;border-radius:12px;"
                "box-shadow:0 10px 30px rgba(15,23,42,0.08);text-align:center;}"
                ".icon{font-size:42px;}"
                "p{color:#991b1b;}"
                "code{background:#f1f5f9;padding:2px 6px;border-radius:6px;}"
                "</style></head>"
                "<body><div class=\"wrap\">"
                "<div class=\"icon\">❌</div>"
                "<h1>Google Calendar Connection Failed</h1>"
                "<p>Reason: <code>" + html.escape(str(e.detail)) + "</code></p>"
                "<p>Please close this page and try again.</p>"
                "</div></body></html>"
            ),
            status_code=400
        )

@api_router.delete("/calendar/disconnect")
async def disconnect_calendar(current_user: dict = Depends(get_current_user)):
    """Disconnect Google Calendar and remove access"""
    calendar_service = get_calendar_service()

    if not calendar_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google Calendar service not configured"
        )

    user_id = str(current_user["_id"])

    try:
        # Remove calendar connection from database
        result = await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {
                "$set": {
                    "google_calendar.connected": False,
                    "google_calendar.sync_enabled": False
                },
                "$unset": {
                    "google_calendar.access_token": "",
                    "google_calendar.refresh_token": ""
                }
            }
        )

        if result.modified_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Calendar connection not found"
            )

        logger.info(f"✅ Calendar disconnected for user {user_id}")

        return {
            "success": True,
            "message": "Calendar disconnected successfully"
        }

    except HTTPException as e:
        raise
    except Exception as e:
        logger.error(f"Failed to disconnect calendar: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to disconnect calendar: {str(e)}"
        )

@api_router.get("/calendar/status")
async def get_calendar_status(current_user: dict = Depends(get_current_user)):
    """Get user's calendar connection status"""
    calendar_service = get_calendar_service()

    if not calendar_service:
        return {
            "available": False,
            "connected": False,
            "message": "Google Calendar service not configured"
        }

    user_id = str(current_user["_id"])

    try:
        user = await db.users.find_one({"_id": ObjectId(user_id)})

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        calendar_data = user.get("google_calendar", {})

        return {
            "available": True,
            "connected": calendar_data.get("connected", False),
            "calendar_id": calendar_data.get("calendar_id"),
            "google_email": calendar_data.get("google_email"),
            "sync_enabled": calendar_data.get("sync_enabled", False),
            "last_sync": calendar_data.get("last_sync"),
            "sync_errors": calendar_data.get("sync_errors", 0)
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get calendar status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@api_router.post("/calendar/events/create")
async def create_calendar_event(
    event_request: CalendarEventCreate,
    current_user: dict = Depends(get_current_user)
):
    """
    Manually create calendar event for a booking
    (Usually done automatically on booking creation)
    """
    calendar_service = get_calendar_service()

    if not calendar_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google Calendar service not configured"
        )

    try:
        # Get booking details
        booking = await db.orders.find_one(
            {"_id": ObjectId(event_request.order_id)}
        )

        if not booking:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Booking not found"
            )

        events_created = {}

        # Create event for provider
        if "provider" in event_request.sync_to:
            provider_id = str(booking["seller_id"])
            access_token = await calendar_service.get_valid_access_token(provider_id)

            if access_token:
                provider = await db.users.find_one({"_id": ObjectId(provider_id)})
                calendar_id = provider.get("google_calendar", {}).get("calendar_id", "primary")

                event_data = calendar_service.format_booking_as_event(booking, for_provider=True)
                created_event = await calendar_service.create_event(access_token, calendar_id, event_data)

                events_created["provider"] = {
                    "event_id": created_event["id"],
                    "calendar_link": created_event.get("htmlLink", "")
                }

                # Update booking with event ID
                await db.orders.update_one(
                    {"_id": booking["_id"]},
                    {
                        "$set": {
                            "calendar_events.provider_event_id": created_event["id"],
                            "calendar_events.calendar_sync_status": "synced"
                        }
                    }
                )

        # Create event for customer
        if "customer" in event_request.sync_to:
            customer_id = str(booking["buyer_id"])
            access_token = await calendar_service.get_valid_access_token(customer_id)

            if access_token:
                customer = await db.users.find_one({"_id": ObjectId(customer_id)})
                calendar_id = customer.get("google_calendar", {}).get("calendar_id", "primary")

                event_data = calendar_service.format_booking_as_event(booking, for_provider=False)
                created_event = await calendar_service.create_event(access_token, calendar_id, event_data)

                events_created["customer"] = {
                    "event_id": created_event["id"],
                    "calendar_link": created_event.get("htmlLink", "")
                }

                # Update booking with event ID
                await db.orders.update_one(
                    {"_id": booking["_id"]},
                    {
                        "$set": {
                            "calendar_events.customer_event_id": created_event["id"]
                        }
                    }
                )

        return {
            "success": True,
            "events_created": events_created
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create calendar event: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@api_router.post("/calendar/sync")
async def sync_calendar_events(current_user: dict = Depends(get_current_user)):
    """
    Manually backfill upcoming bookings into the user's Google Calendar
    """
    try:
        await _sync_upcoming_bookings_for_user(str(current_user["_id"]))
        return {"success": True, "message": "Calendar sync completed"}
    except Exception as e:
        logger.error(f"Failed to sync calendar events: {e}")
        raise HTTPException(status_code=500, detail="Failed to sync calendar events")

# Image Upload Routes
class ImageUploadResponse(BaseModel):
    url: str
    public_id: str

class UserAvatarUpdate(BaseModel):
    avatar_url: str

class UserUpdate(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[EmailStr] = None
    security_question: Optional[str] = None
    security_answer: Optional[str] = None

    @validator('phone')
    def validate_phone(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        normalized = v.strip()
        if not re.fullmatch(r'^\+?\d{7,15}$', normalized):
            raise ValueError("Invalid phone number format")
        return normalized

    @validator('security_question')
    def validate_security_question(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        normalized = v.strip()
        if len(normalized) < 5:
            raise ValueError("Security question must be at least 5 characters")
        return normalized

    @validator('security_answer')
    def validate_security_answer(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        normalized = v.strip()
        if len(normalized) < 2:
            raise ValueError("Security answer must be at least 2 characters")
        return normalized

class PasswordUpdate(BaseModel):
    current_password: str
    new_password: str

class DeleteAccountRequest(BaseModel):
    password: str
    confirmation: str  # User must type "DELETE" to confirm

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ForgotPasswordVerify(BaseModel):
    email: EmailStr
    security_answer: str
    new_password: str

class OrderCancellationRequest(BaseModel):
    reason: Optional[str] = None

class OrderCancellationResponse(BaseModel):
    success: bool
    message: str
    order_id: str
    refund_amount: Optional[float] = None
    restocking_fee: Optional[float] = None

def _is_allowed_image_bytes(file_bytes: bytes) -> bool:
    if file_bytes.startswith(b'\xFF\xD8\xFF'):
        return True  # JPEG
    if file_bytes.startswith(b'\x89PNG\r\n\x1a\n'):
        return True  # PNG
    if file_bytes.startswith(b'GIF87a') or file_bytes.startswith(b'GIF89a'):
        return True  # GIF
    if file_bytes.startswith(b'RIFF') and len(file_bytes) > 12 and file_bytes[8:12] == b'WEBP':
        return True  # WEBP
    return False

def _validate_image_upload(file_bytes: bytes, content_type: Optional[str]) -> None:
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Empty file upload")
    if len(file_bytes) > MAX_IMAGE_BYTES:
        raise HTTPException(status_code=413, detail="File too large")
    if content_type and content_type not in ALLOWED_IMAGE_CONTENT_TYPES:
        raise HTTPException(status_code=400, detail="Unsupported file type")
    if not _is_allowed_image_bytes(file_bytes):
        raise HTTPException(status_code=400, detail="Invalid image file")

# Contact form endpoint removed - Web3Forms must be called directly from client-side
# Web3Forms free plan does NOT allow server-side submissions
# Frontend handles contact form submission directly to Web3Forms API

@api_router.post("/upload/image", response_model=ImageUploadResponse)
async def upload_image(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    try:
        contents = await file.read()
        _validate_image_upload(contents, file.content_type)

        result = cloudinary.uploader.upload(
            contents,
            folder="petsoko",
            resource_type="auto",
            transformation=[
                {'width': 1000, 'height': 1000, 'crop': 'limit'},
                {'quality': 'auto'},
                {'fetch_format': 'auto'}
            ]
        )

        return {
            'url': result['secure_url'],
            'public_id': result['public_id']
        }
    except Exception as e:
        logger.error(f"Error uploading image: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to upload image: {str(e)}")

@api_router.post("/upload/base64", response_model=ImageUploadResponse)
async def upload_base64_image(image_data: dict, current_user: dict = Depends(get_current_user)):
    try:
        base64_string = image_data.get('image')
        if not base64_string:
            raise HTTPException(status_code=400, detail="No image data provided")

        if ',' in base64_string:
            base64_string = base64_string.split(',')[1]

        try:
            image_bytes = base64.b64decode(base64_string, validate=True)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid base64 image data")

        _validate_image_upload(image_bytes, None)

        result = cloudinary.uploader.upload(
            f"data:image/jpeg;base64,{base64_string}",
            folder="petsoko",
            resource_type="auto",
            transformation=[
                {'width': 1000, 'height': 1000, 'crop': 'limit'},
                {'quality': 'auto'},
                {'fetch_format': 'auto'}
            ]
        )

        return {
            'url': result['secure_url'],
            'public_id': result['public_id']
        }
    except Exception as e:
        logger.error(f"Error uploading base64 image: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to upload image: {str(e)}")

@api_router.patch("/users/avatar")
async def update_avatar(avatar_data: UserAvatarUpdate, current_user: dict = Depends(get_current_user)):
    try:
        await db.users.update_one(
            {'_id': current_user['_id']},
            {'$set': {'avatar': avatar_data.avatar_url}}
        )

        return {
            'message': 'Avatar updated successfully',
            'avatar': avatar_data.avatar_url
        }
    except Exception as e:
        logger.error(f"Error updating avatar: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update avatar")

@api_router.patch("/users/profile")
async def update_profile(profile_data: UserUpdate, current_user: dict = Depends(get_current_user)):
    try:
        update_fields = {}

        if profile_data.name:
            update_fields['name'] = profile_data.name

        if profile_data.phone:
            update_fields['phone'] = profile_data.phone

        if profile_data.email:
            existing_user = await db.users.find_one({'email': profile_data.email})
            if existing_user and str(existing_user['_id']) != str(current_user['_id']):
                raise HTTPException(status_code=400, detail="Email already in use")
            update_fields['email'] = profile_data.email

        if profile_data.security_question is not None or profile_data.security_answer is not None:
            if not profile_data.security_question or not profile_data.security_answer:
                raise HTTPException(
                    status_code=400,
                    detail="Both security question and security answer are required"
                )
            update_fields['security_question'] = profile_data.security_question.strip()
            update_fields['security_answer'] = hash_password(profile_data.security_answer.lower().strip())

        if not update_fields:
            raise HTTPException(status_code=400, detail="No fields to update")

        await db.users.update_one(
            {'_id': current_user['_id']},
            {'$set': update_fields}
        )

        updated_user = await db.users.find_one({'_id': current_user['_id']})
        subscription_info = build_seller_subscription_payload(updated_user)

        return {
            'id': str(updated_user['_id']),
            'name': updated_user['name'],
            'email': updated_user['email'],
            'phone': updated_user['phone'],
            'role': updated_user['role'],
            'kyc_status': updated_user.get('kyc_status', 'pending'),
            'avatar': updated_user.get('avatar'),
            'security_question_needs_setup': security_question_needs_setup(updated_user),
            'subscription_tier': subscription_info['seller_subscription_tier'],
            'subscription_expires_at': subscription_info['subscription_expires_at'],
            'created_at': updated_user['created_at']
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating profile: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update profile")

@api_router.patch("/users/password")
async def update_password(password_data: PasswordUpdate, current_user: dict = Depends(get_current_user)):
    try:
        if not verify_password(password_data.current_password, current_user['password']):
            raise HTTPException(status_code=400, detail="Current password is incorrect")

        if len(password_data.new_password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

        new_hashed_password = hash_password(password_data.new_password)

        await db.users.update_one(
            {'_id': current_user['_id']},
            {'$set': {'password': new_hashed_password}}
        )

        return {'message': 'Password updated successfully'}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating password: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update password")

@api_router.delete("/users/account")
async def delete_account(delete_data: DeleteAccountRequest, current_user: dict = Depends(get_current_user)):
    """
    Delete user account and all associated data.
    This action is irreversible and will delete:
    - User profile
    - Seller profile (if applicable)
    - All service listings
    - All orders (as buyer and seller)
    - Wallet and transactions
    - Conversations and messages
    - Reviews
    - Verifications
    - Withdrawals
    - Job postings
    """
    try:
        auth_provider = (current_user.get('auth_provider') or '').lower()
        is_google_account = auth_provider == 'google'

        # Require a non-empty password input for explicit user confirmation.
        # For Google accounts, this input is treated as confirmation text.
        if not delete_data.password or not delete_data.password.strip():
            raise HTTPException(status_code=400, detail="Please enter your password to confirm account deletion")

        # Verify password only for non-Google accounts.
        if not is_google_account and not verify_password(delete_data.password, current_user['password']):
            raise HTTPException(status_code=400, detail="Incorrect password")

        # Verify confirmation text
        if delete_data.confirmation.upper() != "DELETE":
            raise HTTPException(status_code=400, detail="Please type DELETE to confirm account deletion")

        user_id = str(current_user['_id'])
        user_email = current_user.get('email', 'unknown')

        logger.info(f"Starting account deletion for user: {user_email} (ID: {user_id})")

        # Delete all user-related data
        deletion_results = {}
        fee_reconciliation = {
            'wallet_balance_refunded': 0.0,
            'pending_escrow_handled': 0.0,
            'pending_deductions_settled': 0.0,
            'total_amount_processed': 0.0
        }

        # 1. Handle wallet balance and reconciliation BEFORE deletion
        user_wallet = await db.wallets.find_one({'user_id': user_id})
        if user_wallet:
            available_balance = user_wallet.get('balance', 0.0)
            pending_balance = user_wallet.get('pending_balance', 0.0)
            pending_deductions = user_wallet.get('pending_deductions', 0.0)

            logger.info(f"Account deletion wallet state for {user_email}: Available={available_balance}, Pending={pending_balance}, Deductions={pending_deductions}")

            # Handle available balance - would normally refund but user is deleting account
            # If user has balance, log it and transfer to platform as unclaimed funds
            if available_balance > 0:
                # Transfer user's remaining balance to platform wallet (unclaimed funds from account deletion)
                await db.wallets.update_one(
                    {'user_id': PLATFORM_WALLET_ID},
                    {'$inc': {'balance': available_balance}}
                )

                # Create transaction record for the transfer
                await create_transaction(
                    user_id=PLATFORM_WALLET_ID,
                    amount=available_balance,
                    transaction_type=TransactionType.REFUND,
                    status=TransactionStatus.COMPLETED,
                    description=f"Unclaimed wallet balance from deleted account {user_email} (User ID: {user_id})",
                    order_id=None
                )

                fee_reconciliation['wallet_balance_refunded'] = available_balance
                logger.info(f"Transferred unclaimed balance of KES {available_balance} from {user_email} to platform wallet")

            # Handle pending escrow - release back to buyers or transfer to platform
            if pending_balance > 0:
                # Find all pending transactions for this seller
                pending_txns = await db.transactions.find({
                    'user_id': user_id,
                    'status': TransactionStatus.PENDING,
                    'transaction_type': {'$in': [
                        TransactionType.SELLER_EARNING,
                        TransactionType.DELIVERY_FEE_PAYMENT
                    ]}
                }).to_list(None)

                # Reverse each pending transaction (refund to buyers)
                for txn in pending_txns:
                    order_id = txn.get('order_id')
                    amount = abs(txn.get('amount', 0.0))

                    if order_id:
                        # Find the order to get buyer_id
                        order = await db.orders.find_one({'id': order_id})
                        if order and order.get('buyer_id'):
                            buyer_id = order['buyer_id']

                            # Refund to buyer's wallet
                            buyer_wallet = await get_or_create_wallet(buyer_id)
                            await db.wallets.update_one(
                                {'user_id': buyer_id},
                                {'$inc': {'balance': amount}}
                            )

                            # Create refund transaction for buyer
                            await create_transaction(
                                user_id=buyer_id,
                                amount=amount,
                                transaction_type=TransactionType.REFUND,
                                status=TransactionStatus.COMPLETED,
                                description=f"Refund due to seller account deletion (Order {order_id}, Seller: {user_email})",
                                order_id=order_id
                            )

                            # Send notification to buyer
                            await create_notification(
                                db=db,
                                user_id=buyer_id,
                                notification_type=NotificationType.REFUND_PROCESSED,
                                title="Refund Processed",
                                message=f"You have been refunded KES {amount:.2f} due to seller account deletion for order {order_id}.",
                                data={'order_id': order_id, 'amount': amount}
                            )

                            logger.info(f"Refunded KES {amount} to buyer {buyer_id} for pending transaction from deleted seller {user_email}")

                    # Mark the seller's transaction as reversed
                    await db.transactions.update_one(
                        {'_id': txn['_id']},
                        {'$set': {'status': TransactionStatus.REVERSED, 'updated_at': datetime.utcnow()}}
                    )

                # Remove pending balance from seller wallet
                await db.wallets.update_one(
                    {'user_id': user_id},
                    {'$set': {'pending_balance': 0.0}}
                )

                fee_reconciliation['pending_escrow_handled'] = pending_balance
                logger.info(f"Handled pending escrow of KES {pending_balance} for deleted account {user_email}")

            # Handle pending deductions - these are penalties owed to platform
            if pending_deductions > 0:
                # Transfer pending deductions to platform wallet as they are owed
                await db.wallets.update_one(
                    {'user_id': PLATFORM_WALLET_ID},
                    {'$inc': {'balance': pending_deductions}}
                )

                # Create transaction for settled deductions
                await create_transaction(
                    user_id=PLATFORM_WALLET_ID,
                    amount=pending_deductions,
                    transaction_type=TransactionType.SELLER_CANCELLATION_PENALTY,
                    status=TransactionStatus.COMPLETED,
                    description=f"Settled pending penalties from deleted account {user_email} (User ID: {user_id})",
                    order_id=None
                )

                fee_reconciliation['pending_deductions_settled'] = pending_deductions
                logger.info(f"Settled pending deductions of KES {pending_deductions} from {user_email} to platform wallet")

            fee_reconciliation['total_amount_processed'] = available_balance + pending_deductions

        # 2. Delete seller profile
        seller_result = await db.seller_profiles.delete_many({'user_id': user_id})
        deletion_results['seller_profiles'] = seller_result.deleted_count

        # 3. Delete service listings
        listings_result = await db.service_listings.delete_many({'seller_id': user_id})
        deletion_results['service_listings'] = listings_result.deleted_count

        # 4. Delete orders (both as buyer and seller)
        buyer_orders = await db.orders.delete_many({'buyer_id': user_id})
        seller_orders = await db.orders.delete_many({'seller_id': user_id})
        deletion_results['orders'] = buyer_orders.deleted_count + seller_orders.deleted_count

        # 5. Delete wallet (after reconciliation)
        wallet_result = await db.wallets.delete_many({'user_id': user_id})
        deletion_results['wallets'] = wallet_result.deleted_count

        # 6. Delete transactions
        transactions_result = await db.transactions.delete_many({'user_id': user_id})
        deletion_results['transactions'] = transactions_result.deleted_count

        # 7. Delete withdrawals
        withdrawals_result = await db.withdrawals.delete_many({'user_id': user_id})
        deletion_results['withdrawals'] = withdrawals_result.deleted_count

        # 8. Delete conversations (where user is buyer or seller)
        conversations_result = await db.conversations.delete_many({
            '$or': [{'buyer_id': user_id}, {'seller_id': user_id}]
        })
        deletion_results['conversations'] = conversations_result.deleted_count

        # 9. Delete messages (where user is sender)
        messages_result = await db.messages.delete_many({'sender_id': user_id})
        deletion_results['messages'] = messages_result.deleted_count

        # 10. Delete reviews (both as buyer and seller)
        buyer_reviews = await db.reviews.delete_many({'buyer_id': user_id})
        seller_reviews = await db.reviews.delete_many({'seller_id': user_id})
        deletion_results['reviews'] = buyer_reviews.deleted_count + seller_reviews.deleted_count

        # 11. Delete verifications
        verifications_result = await db.verifications.delete_many({'user_id': user_id})
        deletion_results['verifications'] = verifications_result.deleted_count

        # 12. Delete wallet adjustments
        adjustments_result = await db.wallet_adjustments.delete_many({'user_id': user_id})
        deletion_results['wallet_adjustments'] = adjustments_result.deleted_count

        # 13. Delete job postings
        job_postings_result = await db.job_postings.delete_many({'posted_by': user_id})
        deletion_results['job_postings'] = job_postings_result.deleted_count

        # 14. Finally, delete the user account
        user_result = await db.users.delete_one({'_id': current_user['_id']})
        deletion_results['user_account'] = user_result.deleted_count

        logger.info(f"Account deletion completed for {user_email}. Deletion summary: {deletion_results}, Fee reconciliation: {fee_reconciliation}")

        return {
            'message': 'Your account and all associated data have been permanently deleted',
            'deleted_data': deletion_results,
            'fee_reconciliation': fee_reconciliation
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting account: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete account. Please try again or contact support.")

@api_router.post("/auth/forgot-password")
async def initiate_forgot_password(request_data: ForgotPasswordRequest):
    try:
        user = await db.users.find_one({'email': request_data.email})

        if not user:
            raise HTTPException(
                status_code=404,
                detail="No account found with this email address"
            )

        if not user.get('security_question'):
            raise HTTPException(
                status_code=400,
                detail="This account does not have a security question set up. Please contact support."
            )

        logger.info(f"Forgot password initiated for: {request_data.email}")

        return {
            'email': request_data.email,
            'security_question': user['security_question'],
            'message': 'Please answer your security question to reset your password'
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error initiating forgot password: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to process request")

@api_router.post("/auth/forgot-password/verify")
async def verify_forgot_password(verify_data: ForgotPasswordVerify):
    try:
        user = await db.users.find_one({'email': verify_data.email})

        if not user:
            raise HTTPException(
                status_code=404,
                detail="No account found with this email address"
            )

        if not user.get('security_answer'):
            raise HTTPException(
                status_code=400,
                detail="This account does not have a security answer set up"
            )

        normalized_answer = verify_data.security_answer.lower().strip()

        if not verify_password(normalized_answer, user['security_answer']):
            logger.warning(f"Failed security answer attempt for: {verify_data.email}")
            raise HTTPException(
                status_code=401,
                detail="Incorrect security answer. Please try again."
            )

        if len(verify_data.new_password) < 6:
            raise HTTPException(
                status_code=400,
                detail="Password must be at least 6 characters"
            )

        new_hashed_password = hash_password(verify_data.new_password)

        await db.users.update_one(
            {'_id': user['_id']},
            {'$set': {'password': new_hashed_password}}
        )

        logger.info(f"Password reset successful for user: {user['email']}")

        return {
            'message': 'Password reset successfully! You can now log in with your new password.',
            'success': True
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error verifying forgot password: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to reset password")

# Seller Routes
@api_router.post("/sellers/apply")
async def apply_as_seller(profile_data: SellerProfileCreate, current_user: dict = Depends(get_current_user)):
    user_id = str(current_user['_id'])
    existing = await db.seller_profiles.find_one({'user_id': user_id})

    business_name = (profile_data.business_name or current_user.get('name') or 'Seller').strip()
    profile_dict = {
        'user_id': user_id,
        'business_name': business_name,
        'license_file': profile_data.license_file or '',
        'rating': 0.0,
        'bank_details': profile_data.bank_details or {},
        'created_at': datetime.utcnow()
    }

    if existing:
        await db.seller_profiles.update_one(
            {'user_id': user_id},
            {'$set': {
                'business_name': business_name,
                'license_file': profile_data.license_file or existing.get('license_file', ''),
                'bank_details': profile_data.bank_details or existing.get('bank_details', {})
            }}
        )
    else:
        await db.seller_profiles.insert_one(profile_dict)

    await db.users.update_one(
        {'_id': current_user['_id']},
        {'$set': {'role': UserRole.SELLER}}
    )

    return {
        'message': 'Account upgraded to seller successfully',
        'status': 'upgraded',
        'is_free': True
    }

@api_router.get("/sellers/{seller_id}")
async def get_seller_profile(seller_id: str):
    # Verify user exists and is a seller
    try:
        user = await db.users.find_one({'_id': ObjectId(seller_id)})
    except:
        raise HTTPException(status_code=400, detail="Invalid seller ID")

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.get('role') != UserRole.SELLER:
        raise HTTPException(status_code=400, detail="User is not a seller")

    # Get or create seller profile
    profile = await db.seller_profiles.find_one({'user_id': seller_id})

    # Auto-create missing profile for existing sellers (migration safety)
    if not profile:
        profile = {
            'user_id': seller_id,
            'business_name': user['name'],
            'rating': 0.0,
            'total_reviews': 0,
            'license_file': '',
            'bank_details': {},
            'created_at': datetime.utcnow()
        }
        await db.seller_profiles.insert_one(profile)

    return {
        'user_id': seller_id,
        'business_name': profile['business_name'],
        'rating': profile.get('rating', 0.0),
        'total_reviews': profile.get('total_reviews', 0),
        'seller_name': user['name'] if user else 'Unknown',
        'kyc_status': user.get('kyc_status', 'pending'),
        'available_now': bool(user.get('available_now', False)),
        'available_now_updated_at': user.get('available_now_updated_at'),
        'created_at': profile['created_at']
    }

@api_router.get("/sellers/{seller_id}/dashboard")
async def get_seller_dashboard(seller_id: str, current_user: dict = Depends(get_current_user)):
    # Verify the seller is accessing their own dashboard
    if str(current_user['_id']) != seller_id and current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Get seller's listings
    listings = await db.service_listings.find({'seller_id': seller_id}).to_list(None)
    total_listings = len(listings)
    active_listings = len([l for l in listings if l['status'] == ListingStatus.ACTIVE])
    # Note: Services don't have SOLD status, they remain ACTIVE

    # Get seller's orders
    orders = await db.orders.find({'seller_id': seller_id}).to_list(None)
    total_orders = len(orders)
    pending_orders = len([o for o in orders if o['payment_status'] == PaymentStatus.PENDING])
    paid_orders = [o for o in orders if o['payment_status'] == PaymentStatus.PAID]
    total_revenue = sum(o['price'] for o in paid_orders)

    # Get seller's wallet info
    wallet = await get_or_create_wallet(seller_id)
    wallet_balance = wallet.get('balance', 0.0)
    pending_balance = wallet.get('pending_balance', 0.0)
    seller = await db.users.find_one({'_id': ObjectId(seller_id)})
    subscription_info = build_seller_subscription_payload(seller)
    availability_info = parse_seller_availability_payload(seller)

    return {
        'seller_id': seller_id,
        'subscription': {
            'tier': subscription_info['seller_subscription_tier'],
            'badge': subscription_info['seller_subscription_badge'],
            'visibility_boost': subscription_info['seller_visibility_boost'],
            'expires_at': subscription_info['subscription_expires_at']
        },
        'stats': {
            'total_listings': total_listings,
            'active_listings': active_listings,
            'pending_orders': pending_orders,
            'total_revenue': total_revenue,
            'total_orders': total_orders,
            'wallet_balance': wallet_balance,
            'pending_balance': pending_balance
        },
        'availability': {
            'available_now': availability_info['seller_available_now'],
            'updated_at': availability_info['seller_available_now_updated_at']
        },
        'recent_listings': [
            {
                'id': str(l['_id']),
                'service_category': l.get('service_category', 'other'),
                'service_name': l.get('service_name', 'Unknown Service'),
                'price': l.get('price', 0),
                'status': l.get('status', 'pending'),
                'created_at': l.get('created_at', datetime.utcnow())
            }
            for l in sorted(listings, key=lambda x: x.get('created_at', datetime.utcnow()), reverse=True)[:5]
        ],
        'recent_orders': [
            {
                'id': str(o['_id']),
                'pet_id': o['pet_id'],
                'price': o['price'],
                'payment_status': o['payment_status'],
                'delivery_status': o.get('delivery_status', 'pending'),
                'created_at': o['created_at']
            }
            for o in sorted(orders, key=lambda x: x['created_at'], reverse=True)[:5]
        ]
    }

@api_router.patch("/sellers/availability-now")
async def set_seller_availability_now(
    payload: SellerAvailabilityUpdateRequest,
    current_user: dict = Depends(get_current_user)
):
    if current_user.get('role') != UserRole.SELLER:
        raise HTTPException(status_code=403, detail="Only sellers can update availability")

    now = datetime.utcnow()
    await db.users.update_one(
        {'_id': current_user['_id']},
        {'$set': {
            'available_now': payload.available_now,
            'available_now_updated_at': now
        }}
    )

    return {
        'seller_id': str(current_user['_id']),
        'available_now': payload.available_now,
        'updated_at': now
    }

@api_router.get("/sellers/{seller_id}/availability-now")
async def get_seller_availability_now(seller_id: str):
    try:
        seller = await db.users.find_one({'_id': ObjectId(seller_id), 'role': UserRole.SELLER})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid seller ID")

    if not seller:
        raise HTTPException(status_code=404, detail="Seller not found")

    availability_info = parse_seller_availability_payload(seller)
    return {
        'seller_id': seller_id,
        'available_now': availability_info['seller_available_now'],
        'updated_at': availability_info['seller_available_now_updated_at']
    }

@api_router.post("/sellers/subscription/activate")
async def activate_seller_subscription(
    subscription_data: SellerSubscriptionActivateRequest,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    idempotency_scope = 'seller_subscription_payment'
    idempotency_key = _require_idempotency_key(request)
    request_hash = _hash_request_payload({
        'tier': subscription_data.tier,
        'payment_method': subscription_data.payment_method,
        'phone_number': subscription_data.phone_number
    })
    idempotency_response = await _get_idempotency_response(
        idempotency_key,
        idempotency_scope,
        str(current_user['_id']),
        request_hash
    )
    if idempotency_response is not None:
        return idempotency_response

    if current_user.get('role') != UserRole.SELLER:
        raise HTTPException(status_code=403, detail="Only sellers can activate subscriptions")

    if subscription_data.tier == SubscriptionTier.NONE:
        raise HTTPException(status_code=400, detail="Please select bronze, silver, or gold")
    if subscription_data.payment_method not in [PaymentMethod.WALLET, PaymentMethod.MPESA]:
        raise HTTPException(status_code=400, detail="Payment method must be 'wallet' or 'mpesa'")

    settings = await _get_platform_settings_internal()
    price_map = {
        SubscriptionTier.BRONZE: settings.get('subscriptionBronzePrice', DEFAULT_SUBSCRIPTION_BRONZE_PRICE),
        SubscriptionTier.SILVER: settings.get('subscriptionSilverPrice', DEFAULT_SUBSCRIPTION_SILVER_PRICE),
        SubscriptionTier.GOLD: settings.get('subscriptionGoldPrice', DEFAULT_SUBSCRIPTION_GOLD_PRICE)
    }
    selected_price = float(price_map[subscription_data.tier])
    seller_id = str(current_user['_id'])

    if subscription_data.payment_method == PaymentMethod.WALLET:
        wallet = await get_or_create_wallet(seller_id)
        if wallet['balance'] < selected_price:
            raise HTTPException(
                status_code=400,
                detail=f"Insufficient wallet balance. Available: KES {wallet['balance']:.2f}, Required: KES {selected_price:.2f}"
            )

        buyer_txn = await create_transaction(
            user_id=seller_id,
            amount=-selected_price,
            transaction_type=TransactionType.ORDER_PAYMENT,
            status=TransactionStatus.COMPLETED,
            description=f"{subscription_data.tier.capitalize()} seller subscription fee (wallet)",
            order_id=None
        )
        await debit_wallet_balance(seller_id, selected_price, str(buyer_txn['_id']))

        platform_txn = await create_transaction(
            user_id=PLATFORM_WALLET_ID,
            amount=selected_price,
            transaction_type=TransactionType.PLATFORM_FEE,
            status=TransactionStatus.COMPLETED,
            description=f"Platform fee: {subscription_data.tier.capitalize()} seller subscription from {current_user.get('name', 'seller')}",
            order_id=None
        )
        await update_wallet_balance(PLATFORM_WALLET_ID, selected_price, str(platform_txn['_id']))
        await db.wallets.update_one(
            {'user_id': PLATFORM_WALLET_ID},
            {'$inc': {'total_earned': selected_price}}
        )

        activation = await activate_provider_subscription(seller_id, subscription_data.tier, selected_price)
        response_payload = {
            'success': True,
            'status': 'paid',
            'tier': subscription_data.tier,
            'badge': subscription_data.tier.capitalize(),
            'visibility_boost': get_subscription_visibility_boost(subscription_data.tier),
            'price': selected_price,
            'currency': 'KES',
            'started_at': activation['started_at'],
            'expires_at': activation['expires_at'],
            'message': f"{subscription_data.tier.capitalize()} subscription activated successfully"
        }
        await _finalize_idempotency(idempotency_key, idempotency_scope, seller_id, response_payload)
        return response_payload

    if not subscription_data.phone_number:
        raise HTTPException(status_code=400, detail="Phone number is required for M-Pesa payment")

    subscription_amount = int(_round_payment_amount(selected_price)) if MPESA_ENVIRONMENT == 'production' else int(selected_price)
    mpesa_response = mpesa_service.stk_push(
        phone_number=subscription_data.phone_number,
        amount=subscription_amount,
        account_reference=f"SUB-{seller_id[:8]}",
        transaction_desc=f"{subscription_data.tier.capitalize()} subscription"
    )

    if not mpesa_response.get('success'):
        response_payload = {
            'success': False,
            'status': 'failed',
            'message': f"Payment failed: {mpesa_response.get('error', 'Unknown error')}"
        }
        await _finalize_idempotency(
            idempotency_key,
            idempotency_scope,
            seller_id,
            response_payload,
            status='failed'
        )
        return response_payload

    subscription_payment = {
        'id': str(uuid.uuid4()),
        'seller_id': seller_id,
        'tier': subscription_data.tier,
        'amount': selected_price,
        'payment_method': PaymentMethod.MPESA,
        'payment_status': PaymentStatus.PENDING,
        'mpesa_checkout_request_id': mpesa_response['checkout_request_id'],
        'phone_number': subscription_data.phone_number,
        'created_at': datetime.utcnow(),
        'updated_at': datetime.utcnow()
    }
    await db.subscription_payments.insert_one(subscription_payment)

    response_payload = {
        'success': True,
        'status': 'pending',
        'payment_id': subscription_payment['id'],
        'tier': subscription_data.tier,
        'price': selected_price,
        'currency': 'KES',
        'checkout_request_id': mpesa_response['checkout_request_id'],
        'merchant_request_id': mpesa_response['merchant_request_id'],
        'message': f"Payment request sent to {subscription_data.phone_number}. Complete M-Pesa prompt to activate plan."
    }
    await _finalize_idempotency(idempotency_key, idempotency_scope, seller_id, response_payload)
    return response_payload

@api_router.get("/sellers/subscription/payment-status/{payment_id}")
async def get_seller_subscription_payment_status(
    payment_id: str,
    current_user: dict = Depends(get_current_user)
):
    if current_user.get('role') != UserRole.SELLER:
        raise HTTPException(status_code=403, detail="Only sellers can access subscription payments")

    payment = await db.subscription_payments.find_one({
        'id': payment_id,
        'seller_id': str(current_user['_id'])
    })
    if not payment:
        raise HTTPException(status_code=404, detail="Subscription payment not found")

    return {
        'payment_id': payment['id'],
        'tier': payment.get('tier'),
        'amount': payment.get('amount', 0.0),
        'payment_method': payment.get('payment_method'),
        'payment_status': payment.get('payment_status', PaymentStatus.PENDING),
        'message': payment.get('payment_message', ''),
        'mpesa_receipt_number': payment.get('mpesa_receipt_number'),
        'created_at': payment.get('created_at'),
        'updated_at': payment.get('updated_at')
    }

# Service Listing Routes
@api_router.post("/services", response_model=ServiceListing)
async def create_service_listing(listing_data: ServiceListingCreate, current_user: dict = Depends(get_current_user)):
    try:
        if current_user['role'] != UserRole.SELLER:
            raise HTTPException(status_code=403, detail="Only sellers can create listings")

        # Moderate description
        desc_moderation = await moderation_service.moderate_listing_content(
            listing_data.description,
            field_name='description'
        )
        if desc_moderation['is_blocked']:
            raise HTTPException(
                status_code=400,
                detail=desc_moderation['warning_message'] or 'Description contains restricted content'
            )

        # Moderate service name (check for contact info sneaked in)
        name_moderation = await moderation_service.moderate_listing_content(
            listing_data.service_name,
            field_name='service_name'
        )
        if name_moderation['is_blocked']:
            raise HTTPException(
                status_code=400,
                detail=name_moderation['warning_message'] or 'Service name contains restricted content'
            )

        # Moderate qualifications if provided
        if listing_data.qualifications:
            qual_moderation = await moderation_service.moderate_listing_content(
                listing_data.qualifications,
                field_name='qualifications'
            )
            if qual_moderation['is_blocked']:
                raise HTTPException(
                    status_code=400,
                    detail=qual_moderation['warning_message'] or 'Qualifications contain restricted content'
                )

        # Get settings to determine if listings should be auto-approved
        settings = await _get_platform_settings_internal()
        auto_approve = settings.get('autoApproveListings', False)

        # Set status based on auto-approve setting
        listing_status = ListingStatus.ACTIVE if auto_approve else ListingStatus.PENDING

        listing_dict = {
            'seller_id': str(current_user['_id']),
            **listing_data.dict(),
            'status': listing_status,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }

        logger.info(f"Attempting to create service listing with data: {listing_dict}")

        try:
            result = await db.service_listings.insert_one(listing_dict)
            subscription_info = build_seller_subscription_payload(current_user)
            listing_dict['id'] = str(result.inserted_id)
            listing_dict['seller_name'] = current_user['name']
            listing_dict['seller_kyc_status'] = current_user.get('kyc_status', 'pending')
            listing_dict['seller_subscription_tier'] = subscription_info['seller_subscription_tier']
            listing_dict['seller_subscription_badge'] = subscription_info['seller_subscription_badge']
            listing_dict['seller_visibility_boost'] = subscription_info['seller_visibility_boost']
            listing_dict['seller_available_now'] = bool(current_user.get('available_now', False))
            listing_dict['seller_available_now_updated_at'] = current_user.get('available_now_updated_at')
            logger.info(f"New service listing created: {listing_dict['id']} by seller {current_user['name']} - Status: {listing_status}")
        except Exception as db_error:
            logger.exception(f"Database error while creating listing: {db_error}")
            raise HTTPException(
                status_code=500,
                detail=f"Database error: Failed to create listing. Please try again later."
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error creating listing: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Server error: {str(e)}"
        )

    # Notify seller based on approval status
    try:
        if auto_approve:
            await create_notification(
                db=db,
                user_id=str(current_user['_id']),
                notification_type=NotificationType.LISTING_APPROVED,
                title="Service Listing Published! 🎉",
                message=f"Your listing for {listing_data.service_name} is now live and visible to buyers!",
                data={
                    'action': 'view_service',
                    'service_id': listing_dict['id']
                },
                send_push=True
            )
            logger.info(f"🔔 [LISTING] Notification sent to seller for new active listing: {listing_dict['id']}")
        else:
            await create_notification(
                db=db,
                user_id=str(current_user['_id']),
                notification_type=NotificationType.LISTING_APPROVED,
                title="Listing Submitted for Review",
                message=f"Your listing for {listing_data.service_name} has been submitted and is pending admin approval.",
                data={
                    'action': 'view_service',
                    'service_id': listing_dict['id']
                },
                send_push=True
            )
            logger.info(f"🔔 [LISTING] Notification sent to seller for pending listing: {listing_dict['id']}")
    except Exception as notif_error:
        logger.error(f"🔔 [LISTING] Failed to send listing creation notification: {notif_error}")

    return listing_dict

@api_router.get("/services", response_model=List[ServiceListing])
async def get_service_listings(
    service_category: Optional[ServiceCategory] = None,
    service_name: Optional[str] = None,
    service_type: Optional[ServiceType] = None,
    min_duration: Optional[int] = None,
    max_duration: Optional[int] = None,
    city: Optional[str] = None,
    service_location_type: Optional[ServiceLocationType] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    seller_id: Optional[str] = None,
    status: Optional[ListingStatus] = ListingStatus.ACTIVE,
    skip: int = 0,
    limit: int = 20
):
    query = {}

    if status:
        query['status'] = status
    if seller_id:
        query['seller_id'] = seller_id
    if service_category:
        query['service_category'] = service_category
    if service_name:
        query['service_name'] = {'$regex': service_name, '$options': 'i'}
    if service_type:
        query['service_type'] = service_type
    if min_duration is not None or max_duration is not None:
        query['duration_minutes'] = {}
        if min_duration is not None:
            query['duration_minutes']['$gte'] = min_duration
        if max_duration is not None:
            query['duration_minutes']['$lte'] = max_duration
    if city:
        query['location.city'] = {'$regex': city, '$options': 'i'}
    if service_location_type:
        query['service_location_type'] = service_location_type
    if min_price is not None or max_price is not None:
        query['price'] = {}
        if min_price is not None:
            query['price']['$gte'] = min_price
        if max_price is not None:
            query['price']['$lte'] = max_price

    listings = await db.service_listings.find(query).to_list(None)
    
    result = []
    for listing in listings:
        # Get seller name
        seller = await db.users.find_one({'_id': ObjectId(listing['seller_id'])})

        subscription_info = build_seller_subscription_payload(seller)
        availability_info = parse_seller_availability_payload(seller)

        result.append({
            'id': str(listing['_id']),
            'seller_id': listing['seller_id'],
            'seller_name': seller['name'] if seller else 'Unknown',
            'seller_kyc_status': seller.get('kyc_status', 'pending') if seller else 'pending',
            'seller_subscription_tier': subscription_info['seller_subscription_tier'],
            'seller_subscription_badge': subscription_info['seller_subscription_badge'],
            'seller_visibility_boost': subscription_info['seller_visibility_boost'],
            'seller_available_now': availability_info['seller_available_now'],
            'seller_available_now_updated_at': availability_info['seller_available_now_updated_at'],
            'service_category': listing['service_category'],
            'service_name': listing['service_name'],
            'service_type': listing['service_type'],
            'duration_minutes': listing['duration_minutes'],
            'price': listing['price'],
            'price_unit': listing['price_unit'],
            'description': listing['description'],
            'qualifications': listing.get('qualifications', ''),
            'certifications': listing.get('certifications', []),
            'experience_years': listing.get('experience_years', 0),
            'services_included': listing.get('services_included', []),
            'pet_types_accepted': listing.get('pet_types_accepted', []),
            'location': listing['location'],
            'service_location_type': listing['service_location_type'],
            'photos': listing.get('photos', []),
            'availability': listing.get('availability', {'days': [], 'hours': {}}),
            'status': listing['status'],
            'created_at': listing['created_at'],
            'updated_at': listing.get('updated_at', listing['created_at'])
        })

    result.sort(
        key=lambda l: (
            l.get('seller_visibility_boost', 0),
            l.get('created_at', datetime.utcnow())
        ),
        reverse=True
    )

    return result[skip: skip + limit]

@api_router.get("/services/{service_id}", response_model=ServiceListing)
async def get_service_listing(service_id: str):
    try:
        listing = await db.service_listings.find_one({'_id': ObjectId(service_id)})
        if not listing:
            raise HTTPException(status_code=404, detail="Service listing not found")

        # Get seller name
        seller = await db.users.find_one({'_id': ObjectId(listing['seller_id'])})

        subscription_info = build_seller_subscription_payload(seller)
        availability_info = parse_seller_availability_payload(seller)

        return {
            'id': str(listing['_id']),
            'seller_id': listing['seller_id'],
            'seller_name': seller['name'] if seller else 'Unknown',
            'seller_kyc_status': seller.get('kyc_status', 'pending') if seller else 'pending',
            'seller_subscription_tier': subscription_info['seller_subscription_tier'],
            'seller_subscription_badge': subscription_info['seller_subscription_badge'],
            'seller_visibility_boost': subscription_info['seller_visibility_boost'],
            'seller_available_now': availability_info['seller_available_now'],
            'seller_available_now_updated_at': availability_info['seller_available_now_updated_at'],
            'service_category': listing['service_category'],
            'service_name': listing['service_name'],
            'service_type': listing['service_type'],
            'duration_minutes': listing['duration_minutes'],
            'price': listing['price'],
            'price_unit': listing['price_unit'],
            'description': listing['description'],
            'qualifications': listing.get('qualifications', ''),
            'certifications': listing.get('certifications', []),
            'experience_years': listing.get('experience_years', 0),
            'services_included': listing.get('services_included', []),
            'pet_types_accepted': listing.get('pet_types_accepted', []),
            'location': listing['location'],
            'service_location_type': listing['service_location_type'],
            'photos': listing.get('photos', []),
            'availability': listing.get('availability', {'days': [], 'hours': {}}),
            'status': listing['status'],
            'created_at': listing['created_at'],
            'updated_at': listing.get('updated_at', listing['created_at'])
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid pet ID")

@api_router.patch("/services/{service_id}", response_model=ServiceListing)
async def update_service_listing(service_id: str, update_data: ServiceListingUpdate, current_user: dict = Depends(get_current_user)):
    try:
        listing = await db.service_listings.find_one({'_id': ObjectId(service_id)})
        if not listing:
            raise HTTPException(status_code=404, detail="Service listing not found")

        if listing['seller_id'] != str(current_user['_id']) and current_user['role'] != UserRole.ADMIN:
            raise HTTPException(status_code=403, detail="Not authorized")

        # Moderate description if being updated
        if update_data.description is not None:
            desc_moderation = await moderation_service.moderate_listing_content(
                update_data.description,
                field_name='description'
            )
            if desc_moderation['is_blocked']:
                raise HTTPException(
                    status_code=400,
                    detail=desc_moderation['warning_message'] or 'Description contains restricted content'
                )

        # Moderate service_name if being updated
        if update_data.service_name is not None:
            name_moderation = await moderation_service.moderate_listing_content(
                update_data.service_name,
                field_name='service_name'
            )
            if name_moderation['is_blocked']:
                raise HTTPException(
                    status_code=400,
                    detail=name_moderation['warning_message'] or 'Service name contains restricted content'
                )

        # Moderate qualifications if being updated
        if update_data.qualifications is not None:
            qual_moderation = await moderation_service.moderate_listing_content(
                update_data.qualifications,
                field_name='qualifications'
            )
            if qual_moderation['is_blocked']:
                raise HTTPException(
                    status_code=400,
                    detail=qual_moderation['warning_message'] or 'Qualifications contains restricted content'
                )

        update_dict = {k: v for k, v in update_data.dict(exclude_unset=True).items() if v is not None}
        update_dict['updated_at'] = datetime.utcnow()

        await db.service_listings.update_one(
            {'_id': ObjectId(service_id)},
            {'$set': update_dict}
        )

        updated_listing = await db.service_listings.find_one({'_id': ObjectId(service_id)})
        seller = await db.users.find_one({'_id': ObjectId(updated_listing['seller_id'])})

        subscription_info = build_seller_subscription_payload(seller)
        availability_info = parse_seller_availability_payload(seller)

        return {
            'id': str(updated_listing['_id']),
            'seller_id': updated_listing['seller_id'],
            'seller_name': seller['name'] if seller else 'Unknown',
            'seller_kyc_status': seller.get('kyc_status', 'pending') if seller else 'pending',
            'seller_subscription_tier': subscription_info['seller_subscription_tier'],
            'seller_subscription_badge': subscription_info['seller_subscription_badge'],
            'seller_visibility_boost': subscription_info['seller_visibility_boost'],
            'seller_available_now': availability_info['seller_available_now'],
            'seller_available_now_updated_at': availability_info['seller_available_now_updated_at'],
            'service_category': updated_listing['service_category'],
            'service_name': updated_listing['service_name'],
            'service_type': updated_listing['service_type'],
            'duration_minutes': updated_listing['duration_minutes'],
            'price': updated_listing['price'],
            'price_unit': updated_listing['price_unit'],
            'description': updated_listing['description'],
            'qualifications': updated_listing.get('qualifications', ''),
            'certifications': updated_listing.get('certifications', []),
            'experience_years': updated_listing.get('experience_years', 0),
            'services_included': updated_listing.get('services_included', []),
            'pet_types_accepted': updated_listing.get('pet_types_accepted', []),
            'location': updated_listing['location'],
            'service_location_type': updated_listing['service_location_type'],
            'photos': updated_listing.get('photos', []),
            'availability': updated_listing.get('availability', {'days': [], 'hours': {}}),
            'status': updated_listing['status'],
            'created_at': updated_listing['created_at'],
            'updated_at': updated_listing.get('updated_at', updated_listing['created_at'])
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.delete("/services/{service_id}")
async def delete_service_listing(service_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a service listing (only if it hasn't been booked)"""
    try:
        listing = await db.service_listings.find_one({'_id': ObjectId(service_id)})
        if not listing:
            raise HTTPException(status_code=404, detail="Service listing not found")

        # Verify ownership
        if listing['seller_id'] != str(current_user['_id']) and current_user['role'] != UserRole.ADMIN:
            raise HTTPException(status_code=403, detail="Not authorized to delete this listing")

        # Check if there are any active bookings for this listing
        existing_orders = await db.orders.find_one({
            'service_id': service_id,
            'payment_status': {'$in': [PaymentStatus.PENDING, PaymentStatus.PENDING_CASH_PAYMENT, PaymentStatus.PAID]},
            'service_completed_by_customer': {'$ne': True}
        })
        if existing_orders:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete listing with active bookings. Please complete or cancel existing bookings first."
            )

        # Delete the listing
        await db.service_listings.delete_one({'_id': ObjectId(service_id)})

        logger.info(f"Service listing {service_id} deleted by seller {current_user['name']}")

        return {
            'message': 'Listing deleted successfully',
            'id': service_id
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting service listing: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete listing")

@api_router.post("/services/{service_id}/republish")
async def republish_service_listing(service_id: str, current_user: dict = Depends(get_current_user)):
    """
    Republish a service listing that was marked as inactive (REMOVED or PAUSED) due to seller action.
    Only the seller who owns the listing can republish it.
    """
    try:
        listing = await db.service_listings.find_one({'_id': ObjectId(service_id)})
        if not listing:
            raise HTTPException(status_code=404, detail="Service listing not found")

        # Verify seller owns this listing
        if listing['seller_id'] != str(current_user['_id']):
            raise HTTPException(
                status_code=403,
                detail="Only the seller who owns this listing can republish it"
            )

        # Verify user is a seller
        if current_user.get('role') != UserRole.SELLER:
            raise HTTPException(
                status_code=403,
                detail="User must have seller role to republish listings"
            )

        # Check if listing is in REMOVED or PAUSED status (inactive)
        if listing.get('status') not in [ListingStatus.REMOVED, ListingStatus.PAUSED]:
            raise HTTPException(
                status_code=400,
                detail=f"Only inactive (REMOVED/PAUSED) listings can be republished. Current status: {listing.get('status')}"
            )

        # Check if listing was removed due to seller action
        removal_reason = listing.get('removal_reason', '')
        if removal_reason and 'Seller cancelled' not in removal_reason and 'seller' not in removal_reason.lower():
            raise HTTPException(
                status_code=400,
                detail="This listing was not marked inactive due to seller action and cannot be republished through this endpoint"
            )

        # Republish: Mark as ACTIVE again
        await db.service_listings.update_one(
            {'_id': ObjectId(service_id)},
            {
                '$set': {
                    'status': ListingStatus.ACTIVE,
                    'republished_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow()
                },
                '$unset': {
                    'removal_reason': "",
                    'previous_status': ""
                }
            }
        )

        # Audit log
        audit_log_entry = {
            'event_type': 'service_listing_republished',
            'service_id': service_id,
            'seller_id': str(current_user['_id']),
            'previous_status': listing.get('status'),
            'new_status': ListingStatus.ACTIVE,
            'timestamp': datetime.utcnow()
        }
        await db.audit_logs.insert_one(audit_log_entry)

        logger.info(f"Service listing {service_id} republished by seller {current_user['name']}")

        return {
            'success': True,
            'message': 'Service listing has been successfully republished and is now active',
            'service_id': service_id,
            'status': ListingStatus.ACTIVE
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error republishing pet listing: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to republish listing")

# Order/Booking Routes
@api_router.post("/orders", response_model=Order)
async def create_order(order_data: OrderCreate, current_user: dict = Depends(get_current_user)):
    # Get service listing
    try:
        listing = await db.service_listings.find_one({'_id': ObjectId(order_data.service_id)})
        if not listing:
            raise HTTPException(status_code=404, detail="Service listing not found")

        if listing['status'] != ListingStatus.ACTIVE:
            raise HTTPException(
                status_code=400,
                detail=f"This service is not available for booking (status: {listing['status']})"
            )

        # Prevent seller from booking their own service
        if listing['seller_id'] == str(current_user['_id']):
            raise HTTPException(
                status_code=400,
                detail="You cannot book your own service listing"
            )

        # Check for existing pending bookings for this service at the same time
        existing_pending_order = await db.orders.find_one({
            'service_id': order_data.service_id,
            'booking_date': order_data.booking_date,
            'booking_time': order_data.booking_time,
            'payment_status': {'$in': [PaymentStatus.PENDING, PaymentStatus.PENDING_CASH_PAYMENT]}
        })

        if existing_pending_order:
            # Check if this booking is old (more than 5 minutes)
            order_age = (datetime.utcnow() - existing_pending_order['created_at']).total_seconds()
            if order_age < 300:  # 5 minutes
                raise HTTPException(
                    status_code=400,
                    detail="This service already has a pending booking for this time slot. Please try a different time or wait a few minutes."
                )
            else:
                # Auto-fail old pending bookings (cleanup)
                logger.info(f"Auto-failing stale booking {str(existing_pending_order['_id'])} (age: {order_age}s)")
                await db.orders.update_one(
                    {'_id': existing_pending_order['_id']},
                    {
                        '$set': {
                            'payment_status': PaymentStatus.FAILED,
                            'payment_error_message': 'Booking timeout - payment not completed',
                            'updated_at': datetime.utcnow()
                        }
                    }
                )

        # Calculate fees
        total_price = listing['price']

        # Get platform fee percentage from settings (dynamic, set by admin)
        settings = await _get_platform_settings_internal()
        platform_fee_percentage = settings.get('platformFeePercentage', 5.0) / 100.0  # Convert from percentage to decimal
        platform_fee = total_price * platform_fee_percentage

        # Service fee is now set by provider AFTER booking is confirmed (flexible pricing)
        # Initial service_fee = 0, provider will set custom fee based on location/special needs
        service_fee = 0.0

        # Provider receives (100 - platform_fee_percentage)% of service price (service fee added later when provider sets it)
        seller_amount = total_price - platform_fee
        total_amount = total_price  # No service fee in initial total

        # Create booking
        order_dict = {
            'buyer_id': str(current_user['_id']),
            'seller_id': listing['seller_id'],
            'service_id': order_data.service_id,
            'booking_date': order_data.booking_date,
            'booking_time': order_data.booking_time,
            'service_requirements': order_data.service_requirements.dict(),
            'service_location': order_data.service_location,
            'service_address': order_data.service_address,
            'price': total_price,
            'platform_fee': platform_fee,
            'seller_amount': seller_amount,
            'service_fee': service_fee,
            'total_amount': total_amount,
            'payment_method': order_data.payment_method,
            'payment_status': PaymentStatus.PENDING,
            'service_status': 'pending',
            'service_fee_status': DeliveryFeeStatus.NOT_SET,
            'service_fee_payment_method': None,
            'service_fee_set_at': None,
            'service_fee_paid_at': None,
            'mpesa_checkout_request_id': None,
            'provider_visible': False,
            'provider_notified': False,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            # Legacy fields for backward compatibility
            'delivery_fee': service_fee,
            'delivery_option': order_data.service_location,
            'delivery_status': 'pending',
            'delivery_fee_status': DeliveryFeeStatus.NOT_SET,
            'delivery_fee_payment_method': None,
            'delivery_fee_set_at': None,
            'delivery_fee_paid_at': None,
            'scheduled_date': order_data.booking_date,
            'delivery_address': order_data.service_address,
        }

        result = await db.orders.insert_one(order_dict)
        order_dict['id'] = str(result.inserted_id)

        logger.info(f"Booking created: {order_dict['id']} by user {current_user['_id']}, payment method: {order_data.payment_method}")

        # Provider notification is sent only after payment succeeds

        # Notify customer about booking placement confirmation
        logger.info(f"🔔 [BOOKING] Preparing to notify CUSTOMER about booking placement")
        logger.info(f"🔔 [BOOKING] Customer ID: {str(current_user['_id'])}")
        logger.info(f"🔔 [BOOKING] Service: {listing.get('service_name', 'service')}")

        try:
            await create_notification(
                db=db,
                user_id=str(current_user['_id']),
                notification_type=NotificationType.ORDER_PLACED,
                title="Service Booking Requested! 🎉",
                message=f"Your booking request for {listing.get('service_name', 'service')} has been sent to the provider. You'll be notified once they confirm availability.",
                data={
                    'action': 'view_order',
                    'order_id': order_dict['id'],
                    'service_id': order_data.service_id
                },
                send_push=True
            )
            logger.info(f"🔔 [BOOKING] ✅ Customer notification created successfully")
        except Exception as e:
            logger.error(f"🔔 [BOOKING] ❌ Failed to send booking notification to customer: {e}")
            import traceback
            logger.error(f"🔔 [BOOKING] ❌ Traceback: {traceback.format_exc()}")

        return order_dict
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating order: {str(e)}")
        raise HTTPException(
            status_code=400,
            detail="Failed to create order. Please try again."
        )

@api_router.get("/orders", response_model=List[Order])
async def get_orders(current_user: dict = Depends(get_current_user)):
    user_id = str(current_user['_id'])
    user_role = current_user['role']

    # Show all orders where user is either buyer OR seller
    # Sellers only see orders after payment succeeds
    query = {
        '$or': [
            {'buyer_id': user_id},
            {'seller_id': user_id, 'provider_visible': True}
        ]
    }

    logger.info(f"Fetching orders for user {user_id} with role {user_role}, query: {query}")

    orders = await db.orders.find(query).to_list(100)

    logger.info(f"Found {len(orders)} orders for user {user_id}")

    result = []
    for order in orders:
        service_fee = order.get('service_fee', order.get('delivery_fee', 0.0))
        total_amount = order.get('total_amount', order['price'] + service_fee)
        result.append({
            'id': str(order['_id']),
            'buyer_id': order['buyer_id'],
            'seller_id': order['seller_id'],
            'service_id': order.get('service_id', order.get('pet_id')),  # Support both old and new field names
            'booking_date': order.get('booking_date'),
            'booking_time': order.get('booking_time'),
            'service_location': order.get('service_location', order.get('delivery_option')),
            'service_address': order.get('service_address', order.get('delivery_address')),
            'service_requirements': order.get('service_requirements', {}),
            'price': order['price'],
            'platform_fee': order.get('platform_fee', order['price'] * PLATFORM_FEE_PERCENTAGE),
            'seller_amount': order.get('seller_amount', order['price'] * (1 - PLATFORM_FEE_PERCENTAGE)),
            'service_fee': service_fee,
            'total_amount': total_amount,
            'payment_method': order.get('payment_method', PaymentMethod.MPESA),
            'payment_status': order['payment_status'],
            'service_status': order.get('service_status', order.get('delivery_status', 'pending')),
            'service_fee_status': order.get('service_fee_status', order.get('delivery_fee_status', DeliveryFeeStatus.NOT_SET)),
            'service_fee_payment_method': order.get('service_fee_payment_method', order.get('delivery_fee_payment_method')),
            'service_fee_set_at': order.get('service_fee_set_at', order.get('delivery_fee_set_at')),
            'service_fee_paid_at': order.get('service_fee_paid_at', order.get('delivery_fee_paid_at')),
            'tracking_id': order.get('tracking_id'),
            'mpesa_checkout_request_id': order.get('mpesa_checkout_request_id'),
            'provider_confirmed': order.get('provider_confirmed'),
            'provider_confirmed_at': order.get('provider_confirmed_at'),
            'provider_declined_at': order.get('provider_declined_at'),
            'service_completed_by_customer': order.get('service_completed_by_customer'),
            'service_completed_at': order.get('service_completed_at'),
            # Legacy fields for backward compatibility
            'delivery_option': order.get('delivery_option', order.get('service_location')),
            'delivery_status': order.get('delivery_status', order.get('service_status', 'pending')),
            'delivery_address': order.get('delivery_address', order.get('service_address')),
            'delivery_fee': order.get('delivery_fee', order.get('service_fee', 0.0)),
            'delivery_fee_status': order.get('delivery_fee_status', order.get('service_fee_status', DeliveryFeeStatus.NOT_SET)),
            'delivery_fee_payment_method': order.get('delivery_fee_payment_method', order.get('service_fee_payment_method')),
            'scheduled_date': order.get('scheduled_date', order.get('booking_date')),
            'created_at': order['created_at'],
            'updated_at': order.get('updated_at', order['created_at'])
        })

    return result

@api_router.get("/orders/{order_id}", response_model=Order)
async def get_order(order_id: str, current_user: dict = Depends(get_current_user)):
    try:
        order = await db.orders.find_one({'_id': ObjectId(order_id)})
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")
        
        # Check authorization
        if (order['buyer_id'] != str(current_user['_id']) and 
            order['seller_id'] != str(current_user['_id']) and 
            current_user['role'] != UserRole.ADMIN):
            raise HTTPException(status_code=403, detail="Not authorized")
        
        service_fee = order.get('service_fee', order.get('delivery_fee', 0.0))
        total_amount = order.get('total_amount', order['price'] + service_fee)
        return {
            'id': str(order['_id']),
            'buyer_id': order['buyer_id'],
            'seller_id': order['seller_id'],
            'service_id': order.get('service_id', order.get('pet_id')),  # Support both old and new field names
            'booking_date': order.get('booking_date'),
            'booking_time': order.get('booking_time'),
            'service_location': order.get('service_location', order.get('delivery_option')),
            'service_address': order.get('service_address', order.get('delivery_address')),
            'service_requirements': order.get('service_requirements', {}),
            'price': order['price'],
            'platform_fee': order.get('platform_fee', order['price'] * PLATFORM_FEE_PERCENTAGE),
            'seller_amount': order.get('seller_amount', order['price'] * (1 - PLATFORM_FEE_PERCENTAGE)),
            'service_fee': service_fee,
            'total_amount': total_amount,
            'payment_method': order.get('payment_method', PaymentMethod.MPESA),
            'payment_status': order['payment_status'],
            'service_status': order.get('service_status', order.get('delivery_status', 'pending')),
            'service_fee_status': order.get('service_fee_status', order.get('delivery_fee_status', DeliveryFeeStatus.NOT_SET)),
            'service_fee_payment_method': order.get('service_fee_payment_method', order.get('delivery_fee_payment_method')),
            'service_fee_set_at': order.get('service_fee_set_at', order.get('delivery_fee_set_at')),
            'service_fee_paid_at': order.get('service_fee_paid_at', order.get('delivery_fee_paid_at')),
            'tracking_id': order.get('tracking_id'),
            'mpesa_checkout_request_id': order.get('mpesa_checkout_request_id'),
            'provider_confirmed': order.get('provider_confirmed'),
            'provider_confirmed_at': order.get('provider_confirmed_at'),
            'provider_declined_at': order.get('provider_declined_at'),
            'service_completed_by_customer': order.get('service_completed_by_customer'),
            'service_completed_at': order.get('service_completed_at'),
            # Legacy fields for backward compatibility
            'delivery_option': order.get('delivery_option', order.get('service_location')),
            'delivery_status': order.get('delivery_status', order.get('service_status', 'pending')),
            'delivery_address': order.get('delivery_address', order.get('service_address')),
            'delivery_fee': order.get('delivery_fee', order.get('service_fee', 0.0)),
            'delivery_fee_status': order.get('delivery_fee_status', order.get('service_fee_status', DeliveryFeeStatus.NOT_SET)),
            'delivery_fee_payment_method': order.get('delivery_fee_payment_method', order.get('service_fee_payment_method')),
            'scheduled_date': order.get('scheduled_date', order.get('booking_date')),
            'created_at': order['created_at'],
            'updated_at': order.get('updated_at', order['created_at'])
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Wallet and Payment Routes
@api_router.get("/wallet", response_model=WalletResponse)
async def get_wallet(current_user: dict = Depends(get_current_user)):
    """Get current user's wallet balance and statistics"""
    wallet = await get_or_create_wallet(str(current_user['_id']))

    return {
        'user_id': wallet['user_id'],
        'balance': wallet['balance'],
        'total_earned': wallet['total_earned'],
        'total_withdrawn': wallet['total_withdrawn'],
        'pending_balance': wallet.get('pending_balance', 0.0),
        'pending_deductions': wallet.get('pending_deductions', 0.0),
        'created_at': wallet['created_at'],
        'updated_at': wallet['updated_at']
    }

@api_router.get("/wallet/transactions", response_model=List[Transaction])
async def get_transactions(
    current_user: dict = Depends(get_current_user),
    skip: int = 0,
    limit: int = 50
):
    """Get user's transaction history"""
    user_id = str(current_user['_id'])

    transactions = await db.transactions.find(
        {'user_id': user_id}
    ).sort('created_at', -1).skip(skip).limit(limit).to_list(limit)

    result = []
    for txn in transactions:
        result.append({
            'id': str(txn['_id']),
            'user_id': txn['user_id'],
            'order_id': txn.get('order_id'),
            'amount': txn['amount'],
            'transaction_type': txn['transaction_type'],
            'status': txn['status'],
            'description': txn['description'],
            'balance_before': txn['balance_before'],
            'balance_after': txn['balance_after'],
            'created_at': txn['created_at'],
            'updated_at': txn['updated_at']
        })

    return result

@api_router.post("/payment/initiate", response_model=InitiatePaymentResponse)
async def initiate_payment(
    payment_request: InitiatePaymentRequest,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """
    Initiate payment for an order
    - For M-Pesa payment method: Collect full amount via M-Pesa
    - For Cash payment method: Collect 5% platform fee via M-Pesa only
    - For Wallet payment method: Process immediately using wallet balance
    """
    try:
        idempotency_key = _require_idempotency_key(request)
        idempotency_scope = 'payment_initiate'
        idempotency_response = None
        request_hash = _hash_request_payload({
            'order_id': payment_request.order_id,
            'phone_number': payment_request.phone_number
        })
        idempotency_response = await _get_idempotency_response(
            idempotency_key,
            idempotency_scope,
            str(current_user['_id']),
            request_hash
        )
        if idempotency_response is not None:
            return idempotency_response

        # Get order
        order = await db.orders.find_one({'_id': ObjectId(payment_request.order_id)})
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        # Verify user is the buyer
        if order['buyer_id'] != str(current_user['_id']):
            raise HTTPException(status_code=403, detail="Not authorized")

        # NOTE: Provider confirmation is NO LONGER required before payment
        # Platform fee is paid upfront to secure the booking
        # Provider can confirm/decline AFTER platform fee is paid
        provider_confirmed = order.get('provider_confirmed')
        if provider_confirmed == False:
            raise HTTPException(status_code=400, detail="Provider has declined this booking. Please make a new booking.")

        # Check if already paid
        if order['payment_status'] == PaymentStatus.PAID:
            raise HTTPException(status_code=400, detail="Order already paid")

        # Check if order was already failed/cancelled
        if order['payment_status'] == PaymentStatus.FAILED:
            error_msg = order.get('payment_error_message', 'Order was cancelled')
            raise HTTPException(status_code=400, detail=f"Order cannot be paid: {error_msg}")

        # Verify the listing is still available (support both service_id and legacy pet_id)
        service_id = order.get('service_id', order.get('pet_id'))
        if not service_id:
            raise HTTPException(status_code=400, detail="Order is missing service_id/pet_id")

        # Check if this is a service booking or legacy pet order
        is_service_booking = 'service_id' in order

        if is_service_booking:
            # Service booking - check service_listings
            listing = await db.service_listings.find_one({'_id': ObjectId(service_id)})
            listing_type = "Service"
        else:
            # Legacy pet order - check pet_listings
            listing = await db.pet_listings.find_one({'_id': ObjectId(service_id)})
            listing_type = "Pet"

        if not listing:
            raise HTTPException(status_code=404, detail=f"{listing_type} listing not found")

        if listing['status'] != ListingStatus.ACTIVE:
            # Mark order as failed since listing is no longer available
            await db.orders.update_one(
                {'_id': ObjectId(payment_request.order_id)},
                {
                    '$set': {
                        'payment_status': PaymentStatus.FAILED,
                        'payment_error_message': f"{listing_type} is no longer available (status: {listing['status']})",
                        'updated_at': datetime.utcnow()
                    }
                }
            )
            raise HTTPException(
                status_code=400,
                detail=f"This {listing_type.lower()} is no longer available for {'booking' if is_service_booking else 'purchase'} (status: {listing['status']})"
            )

        payment_method = order.get('payment_method', PaymentMethod.MPESA)

        # Handle wallet payment with ESCROW (same as MPesa - protect buyer)
        if payment_method == PaymentMethod.WALLET:
            # Check buyer has sufficient balance
            buyer_wallet = await get_or_create_wallet(str(current_user['_id']))
            total_amount = order.get('total_amount', order['price'])

            if buyer_wallet['balance'] < total_amount:
                raise HTTPException(
                    status_code=400,
                    detail=f"Insufficient wallet balance. Available: KES {buyer_wallet['balance']:.2f}, Required: KES {total_amount:.2f}"
                )

            # Deduct from buyer wallet
            buyer_txn = await create_transaction(
                user_id=str(current_user['_id']),
                amount=-total_amount,
                transaction_type=TransactionType.ORDER_PAYMENT,
                status=TransactionStatus.COMPLETED,
                description=f"Payment for order {payment_request.order_id[:8]} (held in escrow)",
                order_id=payment_request.order_id
            )

            await debit_wallet_balance(
                str(current_user['_id']),
                total_amount,
                str(buyer_txn['_id'])
            )

            # ESCROW: Hold payment in seller's pending balance (like MPesa payments)
            # This protects the buyer - seller gets funds only after buyer confirms receipt
            await hold_payment_pending(
                order_id=payment_request.order_id,
                total_amount=order['price'],
                seller_id=order['seller_id']
            )

            # If there's a service fee (delivery fee), hold it in pending too
            service_fee = order.get('service_fee', order.get('delivery_fee', 0.0))
            if service_fee > 0:
                await db.wallets.update_one(
                    {'user_id': order['seller_id']},
                    {
                        '$inc': {'pending_balance': service_fee},
                        '$set': {'updated_at': datetime.utcnow()}
                    }
                )

                await create_transaction(
                    user_id=order['seller_id'],
                    amount=service_fee,
                    transaction_type=TransactionType.DELIVERY_FEE_PAYMENT,
                    status=TransactionStatus.PENDING,
                    description=f"Service fee for order {payment_request.order_id} (in escrow - awaiting buyer confirmation)",
                    order_id=payment_request.order_id
                )

            # Update order status to PAID with service_status reflecting completion
            await db.orders.update_one(
                {'_id': ObjectId(payment_request.order_id)},
                {
                    '$set': {
                        'payment_status': PaymentStatus.PAID,
                        'service_status': 'in_progress',
                        'wallet_payment_processed': True,
                        'payment_initiated': True,
                        'payment_initiated_at': datetime.utcnow(),
                        'provider_visible': True,
                        'updated_at': datetime.utcnow()
                    }
                }
            )

            service_field = order.get('service_id')
            # Services remain active after booking; do not mark as sold or cancel other orders.

            logger.info(f"✅ Wallet payment processed for order {payment_request.order_id}. Funds held in ESCROW until buyer confirms service completion.")

            # Notify both buyer and seller about successful wallet payment
            try:
                service_listing = await db.service_listings.find_one({'_id': ObjectId(service_field)}) if service_field else None
                service_name = service_listing.get('service_name', 'service') if service_listing else 'service'

                # Notify buyer
                await create_notification(
                    db=db,
                    user_id=str(current_user['_id']),
                    notification_type=NotificationType.PAYMENT_RECEIVED,
                    title="Payment Successful! 🎉🔒",
                    message=f"Your wallet payment for {service_name} was successful. Funds are held securely in escrow and will be released to provider when you confirm service completion.",
                    data={
                        'action': 'view_order',
                        'order_id': payment_request.order_id,
                        'service_id': service_field
                    }
                )

                # Notify seller
                await create_notification(
                    db=db,
                    user_id=order['seller_id'],
                    notification_type=NotificationType.PAYMENT_RECEIVED,
                    title="Payment Received! 💰🔒",
                    message=f"Wallet payment received for {service_name}. Funds are secured in escrow and will be released to you when customer confirms service completion.",
                    data={
                        'action': 'view_order',
                        'order_id': payment_request.order_id,
                        'service_id': service_field
                    }
                )
            except Exception as e:
                logger.error(f"Failed to send wallet payment notifications: {e}")

            # Create calendar events after payment succeeds
            await _create_calendar_events_for_order(order)

            # Notify provider after payment success (first time only)
            if not order.get('provider_notified'):
                try:
                    await create_notification(
                        db=db,
                        user_id=order['seller_id'],
                        notification_type=NotificationType.ORDER_CREATED,
                        title="New Booking Request! 🎉",
                        message=f"{current_user.get('name', 'A customer')} booked your {service_name}. Please confirm your availability.",
                        data={
                            'action': 'view_order',
                            'order_id': payment_request.order_id,
                            'service_id': service_field
                        },
                        send_push=True
                    )
                    await db.orders.update_one(
                        {'_id': ObjectId(payment_request.order_id)},
                        {'$set': {'provider_notified': True}}
                    )
                except Exception as e:
                    logger.error(f"Failed to notify provider after wallet payment: {e}")

            response_payload = {
                'success': True,
                'message': f'Payment successful! KES {total_amount:.2f} deducted from your wallet and held in escrow. Funds will be released to provider when you confirm service completion.',
                'checkout_request_id': None,
                'merchant_request_id': None
            }
            await _finalize_idempotency(
                idempotency_key,
                idempotency_scope,
                str(current_user['_id']),
                response_payload
            )
            return response_payload

        # Calculate amount to charge for M-Pesa/Cash
        if payment_method == PaymentMethod.MPESA:
            # Full amount for M-Pesa (service/pet price + service/delivery fee)
            total_amount = order.get('total_amount', order['price'])
            if MPESA_ENVIRONMENT == 'production':
                amount = int(_round_payment_amount(total_amount))
            else:
                amount = int(total_amount)
            service_fee = order.get('service_fee', order.get('delivery_fee', 0.0))
            item_type = "service" if is_service_booking else "pet"
            if service_fee > 0:
                description = f"Payment for {item_type} + fee (KES {service_fee})"
            else:
                description = f"Payment for {item_type} #{service_id[:8]}"
        else:  # Cash payment
            # Only platform fee for cash payment
            amount = int(order['platform_fee'])
            description = f"Platform fee for order #{payment_request.order_id[:8]}"

        # Initiate STK Push
        mpesa_response = mpesa_service.stk_push(
            phone_number=payment_request.phone_number,
            amount=amount,
            account_reference=payment_request.order_id[:10],
            transaction_desc=description
        )

        if mpesa_response.get('success'):
            # Update order with checkout request ID
            await db.orders.update_one(
                {'_id': ObjectId(payment_request.order_id)},
                {
                    '$set': {
                        'mpesa_checkout_request_id': mpesa_response['checkout_request_id'],
                        'payment_initiated': True,
                        'payment_initiated_at': datetime.utcnow(),
                        'updated_at': datetime.utcnow()
                    }
                }
            )

            logger.info(f"Payment initiated for order {payment_request.order_id}, method: {payment_method}, amount: {amount}")

            response_payload = {
                'success': True,
                'message': f'Payment request sent to {payment_request.phone_number}. Please enter your M-Pesa PIN to complete.',
                'checkout_request_id': mpesa_response['checkout_request_id'],
                'merchant_request_id': mpesa_response['merchant_request_id']
            }
            await _finalize_idempotency(
                idempotency_key,
                idempotency_scope,
                str(current_user['_id']),
                response_payload
            )
            return response_payload
        else:
            logger.error(f"M-Pesa payment initiation failed: {mpesa_response.get('error')}")
            await db.orders.update_one(
                {'_id': ObjectId(payment_request.order_id)},
                {
                    '$set': {
                        'payment_initiated': False,
                        'payment_error_message': mpesa_response.get('error', 'STK push failed'),
                        'payment_last_failed_at': datetime.utcnow(),
                        'updated_at': datetime.utcnow()
                    }
                }
            )
            await _delete_failed_order(payment_request.order_id, mpesa_response.get('error', 'STK push failed'), request)
            response_payload = {
                'success': False,
                'message': f"Payment failed: {mpesa_response.get('error', 'Unknown error')}",
                'order_deleted': True
            }
            await _finalize_idempotency(
                idempotency_key,
                idempotency_scope,
                str(current_user['_id']),
                response_payload,
                status='failed'
            )
            return response_payload

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error initiating payment: {str(e)}")
        await _finalize_idempotency(
            idempotency_key,
            'payment_initiate',
            str(current_user['_id']),
            {'success': False, 'message': 'Payment initiation failed'},
            status='failed'
        )
        raise HTTPException(status_code=500, detail=f"Payment initiation failed: {str(e)}")

@api_router.post("/orders/{order_id}/confirm-receipt")
async def confirm_order_receipt(
    order_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Buyer confirms receipt of service/pet and releases payment to seller/provider
    """
    try:
        # Get order
        order = await db.orders.find_one({'_id': ObjectId(order_id)})
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        # Verify user is the buyer
        if order['buyer_id'] != str(current_user['_id']):
            raise HTTPException(status_code=403, detail="Only the buyer can confirm receipt")

        # Check if order is in a valid state for confirmation
        payment_status = order['payment_status']
        payment_method = order.get('payment_method')

        # For escrow payments: Must be PAID (funds in escrow)
        # For cash payments: Must be PENDING_CASH_PAYMENT (platform fee paid, awaiting cash payment + confirmation)
        if payment_method in [PaymentMethod.MPESA, PaymentMethod.WALLET]:
            if payment_status != PaymentStatus.PAID:
                raise HTTPException(status_code=400, detail="Order must be paid before confirming receipt")
        elif payment_method == PaymentMethod.CASH:
            if payment_status != PaymentStatus.PENDING_CASH_PAYMENT:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot confirm order. Current payment status: " + payment_status
                )
        else:
            raise HTTPException(status_code=400, detail="Invalid payment method")

        # Check if already confirmed
        if order.get('delivery_status') == DeliveryStatus.CONFIRMED:
            raise HTTPException(status_code=400, detail="Receipt already confirmed")

        # Determine if this is a service booking or pet order
        is_service_booking = 'service_id' in order

        # Handle payment completion based on payment method
        if payment_method in [PaymentMethod.MPESA, PaymentMethod.WALLET]:
            # Escrow payments: Release pending payment to seller
            # This releases the main service/pet payment from pending_balance to available balance
            await release_pending_payment(order_id, order['seller_id'])
        elif payment_method == PaymentMethod.CASH:
            # Cash payment: Mark order as PAID (customer has confirmed work done and paid in cash)
            # Platform assumes cash payment completed
            await db.orders.update_one(
                {'_id': ObjectId(order_id)},
                {
                    '$set': {
                        'payment_status': PaymentStatus.PAID,
                        'cash_confirmed_by_customer_at': datetime.utcnow(),
                        'updated_at': datetime.utcnow()
                    }
                }
            )
            logger.info(f"✅ Customer confirmed work done for cash order {order_id}. Cash payment assumed completed.")

        # Release delivery fee from ESCROW if applicable
        delivery_fee = order.get('delivery_fee', 0.0)
        delivery_fee_status = order.get('delivery_fee_status', 'not_set')

        if delivery_fee > 0:
            # Find pending delivery fee transaction (in escrow)
            delivery_txn = await db.transactions.find_one({
                'order_id': order_id,
                'user_id': order['seller_id'],
                'transaction_type': TransactionType.DELIVERY_FEE_PAYMENT,  # Use correct type
                'status': TransactionStatus.PENDING
            })

            if delivery_txn:
                # Delivery fee was paid and is in escrow - release it to seller
                seller_wallet = await get_or_create_wallet(order['seller_id'])
                current_balance = seller_wallet.get('balance', 0.0)

                # Move from pending_balance (escrow) to available balance
                await db.wallets.update_one(
                    {'user_id': order['seller_id']},
                    {
                        '$inc': {
                            'pending_balance': -delivery_fee,  # Remove from escrow
                            'balance': delivery_fee,            # Add to available balance
                            'total_earned': delivery_fee        # Track total earnings
                        },
                        '$set': {'updated_at': datetime.utcnow()}
                    }
                )

                # Mark transaction as COMPLETED
                await db.transactions.update_one(
                    {'_id': delivery_txn['_id']},
                    {
                        '$set': {
                            'status': TransactionStatus.COMPLETED,
                            'description': f"Delivery fee released from escrow for order {order_id[:8]} (buyer confirmed receipt)",
                            'balance_before': current_balance,
                            'balance_after': current_balance + delivery_fee,
                            'updated_at': datetime.utcnow()
                        }
                    }
                )

                logger.info(f"✅ Delivery fee KSh {delivery_fee} released from escrow to seller for order {order_id}")

            elif delivery_fee_status == 'set_by_seller':
                # Delivery fee was set but never paid - waive it as part of order completion
                # This allows buyer to complete the order even if they haven't paid delivery fee
                logger.info(f"⚠️ Delivery fee KSh {delivery_fee} was set but not paid - waiving as part of order completion for {order_id}")

                # Mark delivery fee as waived/not required
                await db.orders.update_one(
                    {'_id': ObjectId(order_id)},
                    {
                        '$set': {
                            'delivery_fee_waived': True,
                            'delivery_fee_waived_at': datetime.utcnow(),
                            'delivery_fee_waived_reason': 'Buyer confirmed receipt - delivery fee waived',
                            'updated_at': datetime.utcnow()
                        }
                    }
                )

        # Update order delivery status
        await db.orders.update_one(
            {'_id': ObjectId(order_id)},
            {
                '$set': {
                    'delivery_status': DeliveryStatus.CONFIRMED,
                    'confirmed_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow()
                }
            }
        )

        # Remove calendar events once order is completed
        await _remove_calendar_events_for_order(order)

        # Log appropriate message based on payment method
        if payment_method in [PaymentMethod.MPESA, PaymentMethod.WALLET]:
            logger.info(f"✅ Buyer confirmed receipt for order {order_id}, escrow funds released to seller")
        else:
            logger.info(f"✅ Customer confirmed work done for order {order_id}, cash payment completed")

        # Notify seller about confirmed receipt and payment completion
        try:
            # Support both service_id and pet_id
            service_id = order.get('service_id', order.get('pet_id'))

            if is_service_booking:
                listing = await db.service_listings.find_one({'_id': ObjectId(service_id)})
                item_name = listing.get('service_name', 'service') if listing else 'service'
                user_role = 'provider'
            else:
                listing = await db.pet_listings.find_one({'_id': ObjectId(service_id)})
                item_name = listing.get('breed', 'pet') if listing else 'pet'
                user_role = 'seller'

            # Different notification messages for escrow vs cash payments
            if payment_method in [PaymentMethod.MPESA, PaymentMethod.WALLET]:
                notification_title = "Payment Released! 💸"
                notification_message = f"{'Customer' if is_service_booking else 'Buyer'} confirmed {'service completion' if is_service_booking else 'receipt'} of {item_name}. Your payment (including {'service' if is_service_booking else 'delivery'} fee) has been released from escrow to your wallet!"
            else:  # Cash payment
                notification_title = "Work Confirmed! ✅"
                notification_message = f"{'Customer' if is_service_booking else 'Buyer'} confirmed {'service completion' if is_service_booking else 'receipt'} of {item_name} and cash payment. Order marked as successful!"

            await create_notification(
                db=db,
                user_id=order['seller_id'],
                notification_type=NotificationType.ORDER_CONFIRMED,
                title=notification_title,
                message=notification_message,
                data={
                    'action': 'view_order',
                    'order_id': order_id,
                    'service_id': service_id
                }
            )
        except Exception as e:
            logger.error(f"Failed to send receipt confirmation notification: {e}")

        # Return appropriate message based on payment method
        if payment_method in [PaymentMethod.MPESA, PaymentMethod.WALLET]:
            message = f"{'Service completion' if is_service_booking else 'Receipt'} confirmed! Payment has been released from escrow to the {user_role}."
        else:  # Cash payment
            message = f"{'Service completion' if is_service_booking else 'Receipt'} confirmed! Order marked as successful. You can now leave a review."

        return {
            'success': True,
            'message': message
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error confirming receipt: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to confirm receipt: {str(e)}")


@api_router.post("/orders/{order_id}/provider-confirm")
async def provider_confirm_booking(
    order_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Service provider confirms availability and confirms the booking
    """
    try:
        # Get order
        order = await db.orders.find_one({'_id': ObjectId(order_id)})
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        # Verify user is the provider/seller
        if order['seller_id'] != str(current_user['_id']):
            raise HTTPException(status_code=403, detail="Only the service provider can confirm this booking")

        # Check if already confirmed or declined
        if order.get('provider_confirmed') == True:
            raise HTTPException(status_code=400, detail="Booking already confirmed")

        if order.get('provider_confirmed') == False:
            raise HTTPException(status_code=400, detail="Booking was already declined")

        # For Cash After Service: Require platform fee to be paid before provider can confirm
        # For Escrow Payments (M-Pesa/Wallet): Provider confirms before payment is made
        payment_method = order.get('payment_method', PaymentMethod.MPESA)
        payment_status = order.get('payment_status', PaymentStatus.PENDING)

        if not order.get('provider_visible'):
            raise HTTPException(status_code=400, detail="Booking is not ready for confirmation yet")

        if payment_method == PaymentMethod.CASH:
            # Cash payment method: Platform fee must be paid first
            if payment_status not in [PaymentStatus.PENDING_CASH_PAYMENT, PaymentStatus.PAID]:
                raise HTTPException(
                    status_code=400,
                    detail="Customer must pay the platform fee before you can confirm this booking. Please ask the customer to complete the platform fee payment."
                )
        else:
            # Escrow payments (M-Pesa/Wallet): Require payment initiation before confirmation
            # This prevents "booking goes through" when STK push fails.
            if payment_status in [PaymentStatus.FAILED, PaymentStatus.CANCELLED]:
                raise HTTPException(
                    status_code=400,
                    detail="Booking payment failed or was cancelled. Customer must re-initiate payment."
                )
            if not order.get('payment_initiated') and payment_status != PaymentStatus.PAID:
                raise HTTPException(
                    status_code=400,
                    detail="Customer must initiate payment before you can confirm this booking."
                )

        # Update order to confirmed by provider
        await db.orders.update_one(
            {'_id': ObjectId(order_id)},
            {
                '$set': {
                    'provider_confirmed': True,
                    'provider_confirmed_at': datetime.utcnow(),
                    'service_status': 'confirmed',
                    'updated_at': datetime.utcnow()
                }
            }
        )

        logger.info(f"✅ Provider confirmed booking {order_id}")

        # Notify customer about provider confirmation
        try:
            service_id = order.get('service_id')
            if service_id:
                listing = await db.service_listings.find_one({'_id': ObjectId(service_id)})
                service_name = listing.get('service_name', 'service') if listing else 'service'
            else:
                service_name = 'service'

            await create_notification(
                db=db,
                user_id=order['buyer_id'],
                notification_type=NotificationType.ORDER_CONFIRMED,
                title="Provider Confirmed! ✅",
                message=f"Great news! {current_user.get('name', 'Provider')} confirmed availability for your {service_name} booking on {order.get('booking_date', 'scheduled date')}.",
                data={
                    'action': 'view_order',
                    'order_id': order_id,
                    'service_id': service_id
                },
                send_push=True
            )
        except Exception as e:
            logger.error(f"Failed to send provider confirmation notification: {e}")

        # Update calendar events to reflect confirmation
        try:
            calendar_service = get_calendar_service()
            if calendar_service:
                listing = None
                service_id = order.get('service_id')
                if service_id:
                    listing = await db.service_listings.find_one({'_id': ObjectId(service_id)})

                buyer = await db.users.find_one({"_id": ObjectId(order['buyer_id'])})
                provider = await db.users.find_one({"_id": ObjectId(order['seller_id'])})

                # Parse and combine booking_time with booking_date
                booking_time_str = order.get('booking_time', '09:00')
                booking_time_parts = booking_time_str.split(":")
                booking_hour = int(booking_time_parts[0])
                booking_minute = int(booking_time_parts[1]) if len(booking_time_parts) > 1 else 0

                booking_date = order.get('booking_date')
                if isinstance(booking_date, datetime):
                    booking_datetime = booking_date.replace(
                        hour=booking_hour,
                        minute=booking_minute,
                        second=0,
                        microsecond=0
                    )
                else:
                    # Handle string dates
                    booking_datetime = datetime.fromisoformat(str(booking_date).replace("Z", "+00:00"))
                    booking_datetime = booking_datetime.replace(
                        hour=booking_hour,
                        minute=booking_minute,
                        second=0,
                        microsecond=0
                    )

                booking_for_calendar = {
                    "_id": str(order['_id']),
                    "booking_date": booking_datetime,  # Now includes correct time!
                    "duration_minutes": listing.get('duration_minutes', 90) if listing else 90,
                    "service_name": (listing.get('service_name') if listing else None) or order.get('service_name', 'Service'),
                    "total_amount": order.get('total_amount', order.get('price', 0)),
                    "payment_method": order.get('payment_method', 'mpesa'),
                    "payment_status": order.get('payment_status', 'pending'),
                    "service_status": order.get('service_status', 'confirmed'),
                    "service_address": order.get('service_address', ''),
                    "customer_name": buyer.get('name', 'Customer') if buyer else 'Customer',
                    "customer_phone": buyer.get('phone', 'N/A') if buyer else 'N/A',
                    "customer_email": buyer.get('email') if buyer else None,
                    "provider_name": provider.get('name', 'Provider') if provider else 'Provider',
                    "provider_email": provider.get('email') if provider else None,
                }

                calendar_events = order.get('calendar_events', {})

                # Update provider event
                provider_event_id = calendar_events.get('provider_event_id')
                if provider_event_id and provider:
                    provider_access_token = await calendar_service.get_valid_access_token(order['seller_id'])
                    if provider_access_token:
                        calendar_id = provider.get("google_calendar", {}).get("calendar_id", "primary")
                        event_data = calendar_service.format_booking_as_event(booking_for_calendar, for_provider=True)
                        await calendar_service.update_event(provider_access_token, calendar_id, provider_event_id, event_data)
                        logger.info(f"📅 [CALENDAR] ✅ Provider calendar event updated: {provider_event_id}")

                # Update customer event
                customer_event_id = calendar_events.get('customer_event_id')
                if customer_event_id and buyer:
                    customer_access_token = await calendar_service.get_valid_access_token(order['buyer_id'])
                    if customer_access_token:
                        calendar_id = buyer.get("google_calendar", {}).get("calendar_id", "primary")
                        event_data = calendar_service.format_booking_as_event(booking_for_calendar, for_provider=False)
                        await calendar_service.update_event(customer_access_token, calendar_id, customer_event_id, event_data)
                        logger.info(f"📅 [CALENDAR] ✅ Customer calendar event updated: {customer_event_id}")
        except Exception as e:
            logger.error(f"📅 [CALENDAR] ❌ Failed to update calendar events on confirmation: {e}")

        return {
            'success': True,
            'message': 'Booking confirmed successfully. Customer has been notified.'
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error confirming booking: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to confirm booking: {str(e)}")


@api_router.post("/orders/{order_id}/provider-decline")
async def provider_decline_booking(
    order_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Service provider declines the booking due to unavailability
    """
    try:
        # Get order
        order = await db.orders.find_one({'_id': ObjectId(order_id)})
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        # Verify user is the provider/seller
        if order['seller_id'] != str(current_user['_id']):
            raise HTTPException(status_code=403, detail="Only the service provider can decline this booking")

        # Check if already confirmed or declined
        if order.get('provider_confirmed') == True:
            raise HTTPException(status_code=400, detail="Cannot decline - booking already confirmed")

        if order.get('provider_confirmed') == False:
            raise HTTPException(status_code=400, detail="Booking already declined")

        # Check if payment has been made
        payment_made = order['payment_status'] in [PaymentStatus.PAID, PaymentStatus.PENDING_CASH_PAYMENT]

        # Update payment status based on whether payment was already made
        new_payment_status = PaymentStatus.REFUNDED if payment_made else PaymentStatus.FAILED

        # Update order to declined by provider
        await db.orders.update_one(
            {'_id': ObjectId(order_id)},
            {
                '$set': {
                    'provider_confirmed': False,
                    'provider_declined_at': datetime.utcnow(),
                    'service_status': 'declined',
                    'payment_status': new_payment_status,
                    'updated_at': datetime.utcnow()
                }
            }
        )

        # Only process refund if payment was already made
        refund_message = ""
        payment_method = order.get('payment_method')

        if payment_made:
            # Refund the customer (reverse escrow or refund cash payment)
            if payment_method in [PaymentMethod.MPESA, PaymentMethod.WALLET]:
                # Reverse the escrow payment
                # 1. Find and reverse pending seller transaction
                pending_txn = await db.transactions.find_one({
                    'order_id': order_id,
                    'user_id': order['seller_id'],
                    'transaction_type': TransactionType.SELLER_EARNING,
                    'status': TransactionStatus.PENDING
                })

                if pending_txn:
                    seller_amount = pending_txn['amount']

                    # Remove from seller's pending_balance
                    await db.wallets.update_one(
                        {'user_id': order['seller_id']},
                        {
                            '$inc': {'pending_balance': -seller_amount},
                            '$set': {'updated_at': datetime.utcnow()}
                        }
                    )

                    # Mark transaction as REVERSED
                    await db.transactions.update_one(
                        {'_id': pending_txn['_id']},
                        {
                            '$set': {
                                'status': TransactionStatus.REVERSED,
                                'description': f"Payment reversed for order {order_id[:8]} - Provider declined booking",
                                'updated_at': datetime.utcnow()
                            }
                        }
                    )

                # 2. Refund buyer (return full amount including platform fee)
                total_amount = order.get('total_amount', order['price'])

                if payment_method == PaymentMethod.WALLET:
                    # Refund to buyer's wallet
                    refund_txn = await create_transaction(
                        user_id=order['buyer_id'],
                        amount=total_amount,
                        transaction_type=TransactionType.REFUND,
                        status=TransactionStatus.COMPLETED,
                        description=f"Refund for order {order_id[:8]} - Provider declined booking",
                        order_id=order_id
                    )

                    await update_wallet_balance(
                        order['buyer_id'],
                        total_amount,
                        str(refund_txn['_id'])
                    )

                    refund_message = f"Full refund of KES {total_amount:.2f} credited to your wallet."
                else:
                    # M-Pesa - create refund transaction (manual M-Pesa refund may be needed)
                    refund_txn = await create_transaction(
                        user_id=order['buyer_id'],
                        amount=total_amount,
                        transaction_type=TransactionType.REFUND,
                        status=TransactionStatus.PENDING,
                        description=f"M-Pesa refund pending for order {order_id[:8]} - Provider declined booking",
                        order_id=order_id
                    )

                    refund_message = f"M-Pesa refund of KES {total_amount:.2f} is being processed."

                # 3. Reverse platform fee (return to customer)
                platform_fee = order.get('platform_fee', 0)
                if platform_fee > 0:
                    # Deduct from platform wallet
                    platform_refund_txn = await create_transaction(
                        user_id=PLATFORM_WALLET_ID,
                        amount=-platform_fee,
                        transaction_type=TransactionType.REFUND,
                        status=TransactionStatus.COMPLETED,
                        description=f"Platform fee refunded for declined order {order_id[:8]}",
                        order_id=order_id
                    )

                    await update_wallet_balance(
                        PLATFORM_WALLET_ID,
                        -platform_fee,
                        str(platform_refund_txn['_id'])
                    )

            elif payment_method == PaymentMethod.CASH:
                # For cash payments, only platform fee was paid via M-Pesa
                platform_fee = order.get('platform_fee', 0)

                # Refund platform fee to buyer's wallet
                if platform_fee > 0:
                    refund_txn = await create_transaction(
                        user_id=order['buyer_id'],
                        amount=platform_fee,
                        transaction_type=TransactionType.REFUND,
                        status=TransactionStatus.COMPLETED,
                        description=f"Platform fee refund for order {order_id[:8]} - Provider declined booking",
                        order_id=order_id
                    )

                    await update_wallet_balance(
                        order['buyer_id'],
                        platform_fee,
                        str(refund_txn['_id'])
                    )

                    # Deduct from platform wallet
                    platform_refund_txn = await create_transaction(
                        user_id=PLATFORM_WALLET_ID,
                        amount=-platform_fee,
                        transaction_type=TransactionType.REFUND,
                        status=TransactionStatus.COMPLETED,
                        description=f"Platform fee refunded for declined order {order_id[:8]}",
                        order_id=order_id
                    )

                    await update_wallet_balance(
                        PLATFORM_WALLET_ID,
                        -platform_fee,
                        str(platform_refund_txn['_id'])
                    )

                    refund_message = f"Platform fee of KES {platform_fee:.2f} refunded to your wallet."
        else:
            # No payment was made yet, so no refund needed
            refund_message = "No payment was made."

        # Mark service listing as available again
        service_id = order.get('service_id')
        if service_id:
            await db.service_listings.update_one(
                {'_id': ObjectId(service_id)},
                {'$set': {'status': ListingStatus.ACTIVE, 'updated_at': datetime.utcnow()}}
            )

        logger.info(f"✅ Provider declined booking {order_id}{' and customer refunded' if payment_made else ''}")

        # Notify customer about decline
        try:
            if service_id:
                listing = await db.service_listings.find_one({'_id': ObjectId(service_id)})
                service_name = listing.get('service_name', 'service') if listing else 'service'
            else:
                service_name = 'service'

            notification_message = f"Unfortunately, {current_user.get('name', 'Provider')} is unavailable for your {service_name} booking."
            if payment_made:
                notification_message += f" {refund_message}"

            await create_notification(
                db=db,
                user_id=order['buyer_id'],
                notification_type=NotificationType.ORDER_CANCELLED,
                title="Booking Declined 😔",
                message=notification_message,
                data={
                    'action': 'view_order',
                    'order_id': order_id,
                    'service_id': service_id
                },
                send_push=True
            )
        except Exception as e:
            logger.error(f"Failed to send provider decline notification: {e}")

        return_message = 'Booking declined successfully.'
        if payment_made:
            return_message = 'Booking declined and customer refunded successfully.'

        return {
            'success': True,
            'message': return_message
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error declining booking: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to decline booking: {str(e)}")


@api_router.post("/orders/{order_id}/complete-service")
async def customer_complete_service(
    order_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Customer confirms that the service work is complete and satisfactory.
    This releases payment from escrow to provider (for escrow payments)
    or confirms cash payment was received (for cash payments).
    """
    try:
        # Get order
        order = await db.orders.find_one({'_id': ObjectId(order_id)})
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        # Verify user is the buyer
        if order['buyer_id'] != str(current_user['_id']):
            raise HTTPException(status_code=403, detail="Only the customer can confirm service completion")

        # Check if provider confirmed the booking
        if not order.get('provider_confirmed'):
            raise HTTPException(status_code=400, detail="Provider has not confirmed this booking yet")

        # Check if order is paid
        if order['payment_status'] not in [PaymentStatus.PAID, PaymentStatus.PENDING_CASH_PAYMENT]:
            raise HTTPException(status_code=400, detail="Order must be paid before confirming completion")

        # Check if already completed
        if order.get('service_completed_by_customer'):
            raise HTTPException(status_code=400, detail="Service completion already confirmed")

        payment_method = order.get('payment_method')

        # Handle escrow release for M-Pesa and Wallet payments
        if payment_method in [PaymentMethod.MPESA, PaymentMethod.WALLET]:
            # Release pending payment to provider
            await release_pending_payment(order_id, order['seller_id'])

            # Release service fee from escrow if applicable
            service_fee = order.get('service_fee', order.get('delivery_fee', 0.0))
            if service_fee > 0:
                # Find pending service fee transaction
                service_fee_txn = await db.transactions.find_one({
                    'order_id': order_id,
                    'user_id': order['seller_id'],
                    'transaction_type': TransactionType.DELIVERY_FEE_PAYMENT,
                    'status': TransactionStatus.PENDING
                })

                if service_fee_txn:
                    seller_wallet = await get_or_create_wallet(order['seller_id'])
                    current_balance = seller_wallet.get('balance', 0.0)

                    # Move from pending_balance to available balance
                    await db.wallets.update_one(
                        {'user_id': order['seller_id']},
                        {
                            '$inc': {
                                'pending_balance': -service_fee,
                                'balance': service_fee,
                                'total_earned': service_fee
                            },
                            '$set': {'updated_at': datetime.utcnow()}
                        }
                    )

                    # Mark transaction as COMPLETED
                    await db.transactions.update_one(
                        {'_id': service_fee_txn['_id']},
                        {
                            '$set': {
                                'status': TransactionStatus.COMPLETED,
                                'description': f"Service fee released from escrow for order {order_id[:8]} (customer confirmed completion)",
                                'balance_before': current_balance,
                                'balance_after': current_balance + service_fee,
                                'updated_at': datetime.utcnow()
                            }
                        }
                    )

            completion_message = "Payment released from escrow to provider successfully!"

        elif payment_method == PaymentMethod.CASH:
            # For cash payments, mark as complete (assume cash was paid to provider)
            await db.orders.update_one(
                {'_id': ObjectId(order_id)},
                {
                    '$set': {
                        'payment_status': PaymentStatus.PAID,
                        'cash_payment_confirmed': True,
                        'cash_payment_confirmed_at': datetime.utcnow(),
                        'updated_at': datetime.utcnow()
                    }
                }
            )
            completion_message = "Service completion confirmed. Thank you for confirming cash payment to the provider!"

        # Update order status
        await db.orders.update_one(
            {'_id': ObjectId(order_id)},
            {
                '$set': {
                    'service_completed_by_customer': True,
                    'service_completed_at': datetime.utcnow(),
                    'service_status': 'completed',
                    'delivery_status': DeliveryStatus.CONFIRMED,
                    'updated_at': datetime.utcnow()
                }
            }
        )

        # Remove calendar events once service is completed
        await _remove_calendar_events_for_order(order)

        logger.info(f"✅ Customer confirmed service completion for order {order_id}, payment method: {payment_method}")

        # Notify provider about completion and payment release
        try:
            service_id = order.get('service_id')
            if service_id:
                listing = await db.service_listings.find_one({'_id': ObjectId(service_id)})
                service_name = listing.get('service_name', 'service') if listing else 'service'
            else:
                service_name = 'service'

            if payment_method in [PaymentMethod.MPESA, PaymentMethod.WALLET]:
                notify_message = f"Customer confirmed completion of {service_name}. Your payment has been released from escrow to your wallet! 💰"
            else:
                notify_message = f"Customer confirmed they paid you in cash for {service_name}. Service marked as complete! ✅"

            await create_notification(
                db=db,
                user_id=order['seller_id'],
                notification_type=NotificationType.PAYMENT_RECEIVED,
                title="Service Completed! 🎉",
                message=notify_message,
                data={
                    'action': 'view_order',
                    'order_id': order_id,
                    'service_id': service_id
                },
                send_push=True
            )
        except Exception as e:
            logger.error(f"Failed to send service completion notification: {e}")

        return {
            'success': True,
            'message': completion_message
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error confirming service completion: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to confirm service completion: {str(e)}")


@api_router.post("/admin/process-delivery-fee-reversals")
async def process_delivery_fee_auto_reversals(
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """
    Process automatic delivery fee reversals for orders where buyer didn't confirm receipt.

    Auto-Reversal Logic:
    - Checks all orders with pending delivery fee transactions (in escrow)
    - If 24 hours have passed since the delivery date (or scheduled_date)
    - And buyer has not confirmed receipt
    - Then automatically reverse the delivery fee back to buyer's wallet

    This protects buyers from losing delivery fees if seller doesn't deliver.
    Should be called periodically via cron job (e.g., every hour).
    """
    # Admin-only endpoint
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Find all pending delivery fee transactions
        cutoff_time = datetime.utcnow() - timedelta(hours=24)

        pending_delivery_txns = db.transactions.find({
            'transaction_type': TransactionType.DELIVERY_FEE_PAYMENT,
            'status': TransactionStatus.PENDING
        })

        reversed_count = 0

        async for txn in pending_delivery_txns:
            order_id = txn.get('order_id')
            if not order_id:
                continue

            # Get the order
            order = await db.orders.find_one({'_id': ObjectId(order_id)})
            if not order:
                continue

            # Skip if already reversed
            if order.get('delivery_fee_reversed'):
                continue

            # Skip if buyer confirmed receipt
            if order.get('delivery_status') == DeliveryStatus.CONFIRMED:
                continue

            # Check if 24 hours have passed since delivery/scheduled date
            delivery_date = order.get('scheduled_date') or order.get('created_at')
            if not delivery_date:
                continue

            # If 24 hours have passed, reverse it
            if delivery_date < cutoff_time:
                delivery_fee = order.get('delivery_fee', 0)
                buyer_id = order.get('buyer_id')
                seller_id = order.get('seller_id')

                if delivery_fee > 0 and buyer_id and seller_id:
                    try:
                        # Remove from seller's pending_balance
                        await db.wallets.update_one(
                            {'user_id': seller_id},
                            {
                                '$inc': {'pending_balance': -delivery_fee},
                                '$set': {'updated_at': datetime.utcnow()}
                            }
                        )

                        # Mark seller's transaction as REVERSED
                        await db.transactions.update_one(
                            {'_id': txn['_id']},
                            {
                                '$set': {
                                    'status': TransactionStatus.REVERSED,
                                    'description': f"Delivery fee reversed for order {order_id[:8]} - Buyer did not confirm receipt within 24 hours",
                                    'updated_at': datetime.utcnow()
                                }
                            }
                        )

                        # Credit buyer's wallet (refund)
                        buyer_refund_txn = await create_transaction(
                            user_id=buyer_id,
                            amount=delivery_fee,
                            transaction_type=TransactionType.REFUND,
                            status=TransactionStatus.COMPLETED,
                            description=f"Delivery fee refund for order {order_id[:8]} - Auto-reversal after 24 hours",
                            order_id=order_id
                        )

                        await update_wallet_balance(
                            buyer_id,
                            delivery_fee,
                            str(buyer_refund_txn['_id'])
                        )

                        # Update order to mark reversal
                        await db.orders.update_one(
                            {'_id': ObjectId(order_id)},
                            {
                                '$set': {
                                    'delivery_fee_reversed': True,
                                    'delivery_fee_reversed_at': datetime.utcnow(),
                                    'delivery_fee_reversal_reason': 'Automatic reversal: Buyer did not confirm receipt within 24 hours of delivery date',
                                    'updated_at': datetime.utcnow()
                                }
                            }
                        )

                        logger.info(f"✅ Auto-reversed delivery fee KSh {delivery_fee} from seller to buyer for order {order_id}")

                        # Notify buyer about refund
                        try:
                            pet_listing = await db.pet_listings.find_one({'_id': ObjectId(order['pet_id'])})
                            pet_name = pet_listing.get('breed', 'pet') if pet_listing else 'pet'

                            await create_notification(
                                db=db,
                                user_id=buyer_id,
                                notification_type=NotificationType.REFUND,
                                title="Delivery Fee Refunded 💰",
                                message=f"Your delivery fee of KSh {int(delivery_fee)} for {pet_name} has been refunded to your wallet (auto-reversal after 24 hours).",
                                data={
                                    'action': 'view_wallet',
                                    'order_id': order_id,
                                    'amount': delivery_fee
                                }
                            )
                        except Exception as e:
                            logger.error(f"Failed to notify buyer about delivery fee refund: {e}")

                        # Notify seller about reversal
                        try:
                            await create_notification(
                                db=db,
                                user_id=seller_id,
                                notification_type=NotificationType.ORDER_CANCELLED,
                                title="Delivery Fee Reversed ⚠️",
                                message=f"Delivery fee of KSh {int(delivery_fee)} has been reversed back to buyer (no receipt confirmation within 24 hours).",
                                data={
                                    'action': 'view_order',
                                    'order_id': order_id,
                                    'amount': delivery_fee
                                }
                            )
                        except Exception as e:
                            logger.error(f"Failed to notify seller about delivery fee reversal: {e}")

                        reversed_count += 1

                    except Exception as e:
                        logger.error(f"Error auto-reversing delivery fee for order {order_id}: {str(e)}", exc_info=True)
                        continue

        logger.info(f"Auto-reversal check completed. Reversed {reversed_count} delivery fees.")

        await log_admin_audit(
            action='delivery_fee.auto_reversal',
            actor=current_user,
            target_type='order',
            target_id=None,
            payload={'reversed_count': reversed_count},
            request=http_request
        )

        return {
            'success': True,
            'message': f'Processed auto-reversals for {reversed_count} orders',
            'reversed_count': reversed_count
        }

    except Exception as e:
        logger.error(f"Error processing auto-reversals: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to process auto-reversals: {str(e)}")

# Flexible Delivery Fee Endpoints

class SetDeliveryFeeRequest(BaseModel):
    delivery_fee: float = Field(..., ge=MINIMUM_DELIVERY_FEE, le=MAXIMUM_DELIVERY_FEE)

@api_router.post("/orders/{order_id}/set-delivery-fee")
async def set_delivery_fee(
    order_id: str,
    request: SetDeliveryFeeRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Seller sets custom delivery fee for an order based on distance and delivery needs.
    Can only be set after order is paid and before buyer pays delivery fee.
    """
    try:
        # Get order
        order = await db.orders.find_one({'_id': ObjectId(order_id)})
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        # Verify user is the seller
        if order['seller_id'] != str(current_user['_id']):
            raise HTTPException(status_code=403, detail="Only the seller can set delivery fee")

        # Check if delivery was requested
        if order.get('delivery_option') != DeliveryOption.DELIVERY:
            raise HTTPException(status_code=400, detail="Delivery was not requested for this order")

        # Check if order is paid (main payment completed)
        if order['payment_status'] not in [PaymentStatus.PAID, PaymentStatus.PENDING_CASH_PAYMENT]:
            raise HTTPException(
                status_code=400,
                detail="Delivery fee can only be set after order payment is completed"
            )

        # Check if delivery fee already set
        if order.get('delivery_fee_status') != DeliveryFeeStatus.NOT_SET:
            raise HTTPException(
                status_code=400,
                detail=f"Delivery fee already set to KSh {order.get('delivery_fee', 0)}. Cannot change once set."
            )

        # Validate fee amount
        if request.delivery_fee < MINIMUM_DELIVERY_FEE:
            raise HTTPException(
                status_code=400,
                detail=f"Delivery fee must be at least KSh {MINIMUM_DELIVERY_FEE}"
            )
        if request.delivery_fee > MAXIMUM_DELIVERY_FEE:
            raise HTTPException(
                status_code=400,
                detail=f"Delivery fee cannot exceed KSh {MAXIMUM_DELIVERY_FEE}"
            )

        # Update order with delivery fee
        await db.orders.update_one(
            {'_id': ObjectId(order_id)},
            {
                '$set': {
                    'delivery_fee': request.delivery_fee,
                    'delivery_fee_status': DeliveryFeeStatus.SET_BY_SELLER,
                    'delivery_fee_set_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow()
                }
            }
        )

        logger.info(f"Seller set delivery fee KSh {request.delivery_fee} for order {order_id}")

        # Notify buyer about delivery fee
        try:
            pet_listing = await db.pet_listings.find_one({'_id': ObjectId(order['pet_id'])})
            pet_name = pet_listing.get('breed', 'pet') if pet_listing else 'pet'

            await create_notification(
                db=db,
                user_id=order['buyer_id'],
                notification_type=NotificationType.DELIVERY_FEE_SET,
                title="Delivery Fee Set 📦",
                message=f"Seller set delivery fee: KSh {int(request.delivery_fee)} for {pet_name}. Choose payment method.",
                data={
                    'action': 'pay_delivery_fee',
                    'order_id': order_id,
                    'delivery_fee': request.delivery_fee,
                    'pet_id': order['pet_id']
                }
            )
        except Exception as e:
            logger.error(f"Failed to send delivery fee notification: {e}")

        return {
            'success': True,
            'message': f'Delivery fee set successfully to KSh {int(request.delivery_fee)}',
            'delivery_fee': request.delivery_fee,
            'order_id': order_id
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error setting delivery fee: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to set delivery fee: {str(e)}")

class PayDeliveryFeeRequest(BaseModel):
    payment_method: str  # 'wallet' or 'mpesa'
    phone_number: Optional[str] = None  # Required for mpesa

@api_router.post("/orders/{order_id}/pay-delivery-fee")
async def pay_delivery_fee(
    order_id: str,
    request: PayDeliveryFeeRequest,
    current_user: dict = Depends(get_current_user),
    http_request: Request = None
):
    """
    Buyer pays delivery fee online via M-Pesa or Wallet.
    Fee is credited directly to seller's wallet.
    """
    try:
        idempotency_key = _require_idempotency_key(http_request)
        idempotency_scope = 'delivery_fee_payment'
        request_hash = _hash_request_payload({
            'order_id': order_id,
            'payment_method': request.payment_method,
            'phone_number': request.phone_number
        })
        idempotency_response = await _get_idempotency_response(
            idempotency_key,
            idempotency_scope,
            str(current_user['_id']),
            request_hash
        )
        if idempotency_response is not None:
            return idempotency_response

        # Get order
        order = await db.orders.find_one({'_id': ObjectId(order_id)})
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        # Verify user is the buyer
        if order['buyer_id'] != str(current_user['_id']):
            raise HTTPException(status_code=403, detail="Only the buyer can pay delivery fee")

        # Check if delivery fee was set by seller
        if order.get('delivery_fee_status') != DeliveryFeeStatus.SET_BY_SELLER:
            raise HTTPException(
                status_code=400,
                detail="Delivery fee has not been set by seller yet"
            )

        delivery_fee = order.get('delivery_fee', 0)
        if delivery_fee <= 0:
            raise HTTPException(status_code=400, detail="Invalid delivery fee amount")

        # Validate payment method
        if request.payment_method not in ['wallet', 'mpesa']:
            raise HTTPException(status_code=400, detail="Payment method must be 'wallet' or 'mpesa'")

        # Handle wallet payment
        if request.payment_method == 'wallet':
            try:
                # Ensure buyer's wallet exists
                buyer_wallet = await get_or_create_wallet(order['buyer_id'])

                logger.info(f"Processing delivery fee payment for order {order_id}: buyer={order['buyer_id']}, seller={order['seller_id']}, fee={delivery_fee}")

                # Check buyer's wallet balance
                if buyer_wallet.get('balance', 0) < delivery_fee:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Insufficient wallet balance. Required: KSh {delivery_fee}, Available: KSh {buyer_wallet.get('balance', 0)}"
                    )

                # Ensure seller's wallet exists before processing
                seller_wallet = await get_or_create_wallet(order['seller_id'])
                logger.info(f"Seller wallet confirmed: seller_id={order['seller_id']}, balance={seller_wallet.get('balance', 0)}")

                # Deduct from buyer's wallet
                buyer_txn = await create_transaction(
                    user_id=order['buyer_id'],
                    amount=-delivery_fee,
                    transaction_type=TransactionType.DELIVERY_FEE_PAYMENT,
                    status=TransactionStatus.COMPLETED,
                    description=f"Delivery fee payment for order {order_id[:8]}",
                    order_id=order_id
                )
                logger.info(f"Buyer transaction created: txn_id={str(buyer_txn['_id'])}")

                await debit_wallet_balance(
                    order['buyer_id'],
                    delivery_fee,
                    str(buyer_txn['_id'])
                )
                logger.info(f"Buyer wallet updated: new_balance={buyer_wallet['balance'] - delivery_fee}")

                # Hold delivery fee in ESCROW (seller's pending_balance)
                # Seller will receive it when buyer confirms receipt
                # This protects the buyer - fee is locked until confirmation
                await db.wallets.update_one(
                    {'user_id': order['seller_id']},
                    {
                        '$inc': {'pending_balance': delivery_fee},
                        '$set': {'updated_at': datetime.utcnow()}
                    }
                )

                # Create PENDING transaction for seller (escrow)
                seller_txn = await create_transaction(
                    user_id=order['seller_id'],
                    amount=delivery_fee,
                    transaction_type=TransactionType.DELIVERY_FEE_PAYMENT,
                    status=TransactionStatus.PENDING,  # PENDING - not available for withdrawal yet
                    description=f"Delivery fee for order {order_id[:8]} (in escrow - awaiting buyer confirmation)",
                    order_id=order_id
                )
                logger.info(f"Delivery fee held in escrow: txn_id={str(seller_txn['_id'])}")

                # Update order delivery fee status and set delivery_status to delivered
                await db.orders.update_one(
                    {'_id': ObjectId(order_id)},
                    {
                        '$set': {
                            'delivery_fee_status': DeliveryFeeStatus.PAID_ONLINE,
                            'delivery_fee_payment_method': 'wallet',
                            'delivery_fee_paid_at': datetime.utcnow(),
                            'delivery_status': DeliveryStatus.DELIVERED,
                            'updated_at': datetime.utcnow()
                        }
                    }
                )

                logger.info(f"✅ Delivery fee KSh {delivery_fee} paid via wallet for order {order_id}")

                # Notify seller and buyer
                try:
                    pet_listing = await db.pet_listings.find_one({'_id': ObjectId(order['pet_id'])})
                    pet_name = pet_listing.get('breed', 'pet') if pet_listing else 'pet'
                    buyer_name = current_user.get('name', 'Buyer')

                    # Notify seller about escrow status
                    await create_notification(
                        db=db,
                        user_id=order['seller_id'],
                        notification_type=NotificationType.DELIVERY_FEE_PAID,
                        title="Delivery Fee Paid & Secured 💰🔒",
                        message=f"{buyer_name} paid KSh {int(delivery_fee)} delivery fee for {pet_name}. The fee is secured in escrow and will be released when buyer confirms receipt.",
                        data={
                            'action': 'view_order',
                            'order_id': order_id,
                            'delivery_fee': delivery_fee,
                            'pet_id': order['pet_id']
                        }
                    )

                    # Notify buyer about escrow protection
                    await create_notification(
                        db=db,
                        user_id=order['buyer_id'],
                        notification_type=NotificationType.DELIVERY_FEE_PAID,
                        title="Delivery Fee Payment Successful! ✅🔒",
                        message=f"You paid KSh {int(delivery_fee)} delivery fee for {pet_name}. The fee is secured and will be released to seller when you confirm receipt.",
                        data={
                            'action': 'view_order',
                            'order_id': order_id,
                            'delivery_fee': delivery_fee,
                            'pet_id': order['pet_id']
                        }
                    )
                except Exception as notif_error:
                    logger.error(f"Failed to send delivery fee payment notification: {notif_error}")

                response_payload = {
                    'success': True,
                    'message': 'Delivery fee paid successfully via wallet',
                    'delivery_fee': delivery_fee,
                    'payment_method': 'wallet',
                    'order_id': order_id
                }
                await _finalize_idempotency(
                    idempotency_key,
                    idempotency_scope,
                    str(current_user['_id']),
                    response_payload
                )
                return response_payload

            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"❌ Error processing wallet delivery fee payment for order {order_id}: {str(e)}", exc_info=True)
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to process wallet payment: {str(e)}"
                )

        # Handle M-Pesa payment
        elif request.payment_method == 'mpesa':
            if not request.phone_number:
                raise HTTPException(status_code=400, detail="Phone number required for M-Pesa payment")

            # Validate phone number format
            phone = request.phone_number.strip()
            if phone.startswith('0'):
                phone = '254' + phone[1:]
            elif phone.startswith('+'):
                phone = phone[1:]

            if not phone.startswith('254') or len(phone) != 12:
                raise HTTPException(status_code=400, detail="Invalid Kenyan phone number format")

            # Create temporary order record for M-Pesa callback tracking
            # We'll use a separate collection or update the order with mpesa_delivery_fee_checkout_request_id
            # For simplicity, let's initiate STK push
            try:
                delivery_amount = int(_round_payment_amount(delivery_fee)) if MPESA_ENVIRONMENT == 'production' else int(delivery_fee)
                result = mpesa_service.stk_push(
                    phone_number=phone,
                    amount=delivery_amount,
                    account_reference=f"DELIVERY-{order_id[:8]}",
                    transaction_desc=f"Delivery fee for order {order_id[:8]}"
                )

                if result.get('success'):
                    # Store checkout request ID in order for callback tracking
                    await db.orders.update_one(
                        {'_id': ObjectId(order_id)},
                        {
                            '$set': {
                                'mpesa_delivery_fee_checkout_request_id': result.get('checkout_request_id'),
                                'delivery_fee_payment_method': 'mpesa',
                                'updated_at': datetime.utcnow()
                            }
                        }
                    )

                    response_payload = {
                        'success': True,
                        'message': 'M-Pesa payment initiated. Please check your phone.',
                        'delivery_fee': delivery_fee,
                        'payment_method': 'mpesa',
                        'checkout_request_id': result.get('checkout_request_id'),
                        'order_id': order_id
                    }
                    await _finalize_idempotency(
                        idempotency_key,
                        idempotency_scope,
                        str(current_user['_id']),
                        response_payload
                    )
                    return response_payload
                else:
                    raise HTTPException(
                        status_code=500,
                        detail=f"M-Pesa payment failed: {result.get('error', result.get('message', 'Unknown error'))}"
                    )

            except Exception as e:
                logger.error(f"M-Pesa delivery fee payment error: {str(e)}")
                await _finalize_idempotency(
                    idempotency_key,
                    idempotency_scope,
                    str(current_user['_id']),
                    {'success': False, 'message': 'M-Pesa delivery fee payment failed'},
                    status='failed'
                )
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to initiate M-Pesa payment: {str(e)}"
                )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error paying delivery fee: {str(e)}")
        if http_request:
            await _finalize_idempotency(
                idempotency_key,
                idempotency_scope,
                str(current_user['_id']),
                {'success': False, 'message': 'Delivery fee payment failed'},
                status='failed'
            )
        raise HTTPException(status_code=500, detail=f"Failed to pay delivery fee: {str(e)}")

@api_router.post("/orders/{order_id}/mark-delivery-cash")
async def mark_delivery_cash(
    order_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Buyer chooses to pay delivery fee in cash on delivery.
    No wallet transaction occurs - seller will collect cash during delivery.
    """
    try:
        # Get order
        order = await db.orders.find_one({'_id': ObjectId(order_id)})
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        # Verify user is the buyer
        if order['buyer_id'] != str(current_user['_id']):
            raise HTTPException(status_code=403, detail="Only the buyer can mark delivery fee as cash")

        # Check if delivery fee was set by seller
        if order.get('delivery_fee_status') != DeliveryFeeStatus.SET_BY_SELLER:
            raise HTTPException(
                status_code=400,
                detail="Delivery fee has not been set by seller yet"
            )

        delivery_fee = order.get('delivery_fee', 0)

        # Update order delivery fee status
        await db.orders.update_one(
            {'_id': ObjectId(order_id)},
            {
                '$set': {
                    'delivery_fee_status': DeliveryFeeStatus.PAY_CASH_ON_DELIVERY,
                    'delivery_fee_payment_method': 'cash',
                    'updated_at': datetime.utcnow()
                }
            }
        )

        logger.info(f"Delivery fee KSh {delivery_fee} marked as cash on delivery for order {order_id}")

        # Notify seller
        try:
            pet_listing = await db.pet_listings.find_one({'_id': ObjectId(order['pet_id'])})
            pet_name = pet_listing.get('breed', 'pet') if pet_listing else 'pet'
            buyer_name = current_user.get('name', 'Buyer')

            await create_notification(
                db=db,
                user_id=order['seller_id'],
                notification_type=NotificationType.ORDER_UPDATED,
                title="Cash on Delivery 💵",
                message=f"{buyer_name} will pay KSh {int(delivery_fee)} delivery fee in cash. Collect during delivery.",
                data={
                    'action': 'view_order',
                    'order_id': order_id,
                    'delivery_fee': delivery_fee
                }
            )
        except Exception as e:
            logger.error(f"Failed to send cash on delivery notification: {e}")

        return {
            'success': True,
            'message': f'Delivery fee will be paid in cash on delivery (KSh {int(delivery_fee)})',
            'delivery_fee': delivery_fee,
            'order_id': order_id
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error marking delivery as cash: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to mark delivery as cash: {str(e)}")

@api_router.post("/orders/{order_id}/confirm-delivery-cash-received")
async def confirm_delivery_cash_received(
    order_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Seller confirms receiving delivery fee in cash.
    No wallet transaction - cash was paid directly to seller.
    """
    try:
        # Get order
        order = await db.orders.find_one({'_id': ObjectId(order_id)})
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        # Verify user is the seller
        if order['seller_id'] != str(current_user['_id']):
            raise HTTPException(status_code=403, detail="Only the seller can confirm cash receipt")

        # Check if delivery fee is marked as cash on delivery
        if order.get('delivery_fee_status') != DeliveryFeeStatus.PAY_CASH_ON_DELIVERY:
            raise HTTPException(
                status_code=400,
                detail=f"Delivery fee is not marked as cash on delivery. Current status: {order.get('delivery_fee_status')}"
            )

        delivery_fee = order.get('delivery_fee', 0)

        # Update order delivery fee status and set delivery_status to delivered
        await db.orders.update_one(
            {'_id': ObjectId(order_id)},
            {
                '$set': {
                    'delivery_fee_status': DeliveryFeeStatus.CASH_RECEIVED,
                    'delivery_fee_paid_at': datetime.utcnow(),
                    'delivery_status': DeliveryStatus.DELIVERED,
                    'updated_at': datetime.utcnow()
                }
            }
        )

        logger.info(f"Seller confirmed receiving KSh {delivery_fee} delivery fee in cash for order {order_id}")

        # Notify buyer
        try:
            pet_listing = await db.pet_listings.find_one({'_id': ObjectId(order['pet_id'])})
            pet_name = pet_listing.get('breed', 'pet') if pet_listing else 'pet'

            await create_notification(
                db=db,
                user_id=order['buyer_id'],
                notification_type=NotificationType.ORDER_UPDATED,
                title="Delivery Complete ✅",
                message=f"Seller confirmed receiving KSh {int(delivery_fee)} delivery fee for {pet_name}. Delivery complete!",
                data={
                    'action': 'view_order',
                    'order_id': order_id
                }
            )
        except Exception as e:
            logger.error(f"Failed to send delivery cash confirmation notification: {e}")

        return {
            'success': True,
            'message': f'Delivery cash payment confirmed (KSh {int(delivery_fee)})',
            'delivery_fee': delivery_fee,
            'order_id': order_id
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error confirming delivery cash: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to confirm delivery cash: {str(e)}")

@api_router.get("/payment/status/{order_id}")
async def check_payment_status(
    order_id: str,
    current_user: dict = Depends(get_current_user),
    request: Request = None
):
    """
    Check payment status for an order
    Used by frontend to poll for payment confirmation
    Returns detailed status information for better UX
    """
    try:
        order = await db.orders.find_one({'_id': ObjectId(order_id)})
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        # Verify user is the buyer or seller
        if order['buyer_id'] != str(current_user['_id']) and order['seller_id'] != str(current_user['_id']):
            raise HTTPException(status_code=403, detail="Not authorized")

        payment_status = order.get('payment_status', PaymentStatus.PENDING)
        payment_method = order.get('payment_method', PaymentMethod.MPESA)

        response = {
            'order_id': order_id,
            'payment_status': payment_status,
            'payment_method': payment_method,
            'price': order['price'],
            'platform_fee': order['platform_fee'],
            'seller_amount': order['seller_amount'],
            'mpesa_receipt_number': order.get('mpesa_receipt_number'),
            'created_at': order['created_at'].isoformat() if order.get('created_at') else None,
            'updated_at': order['updated_at'].isoformat() if order.get('updated_at') else None,
            'test_mode': order.get('payment_test_mode', False),
            'test_message': order.get('payment_test_message')
        }

        # Add specific messages and status details based on status
        if payment_status == PaymentStatus.PAID:
            if payment_method == PaymentMethod.MPESA:
                base_message = '🎉 Payment successful! Your order is confirmed.'
                # Add test mode notice if applicable
                if order.get('payment_test_mode'):
                    response['message'] = f"{base_message}\n\n⚠️ {order.get('payment_test_message', 'Test mode enabled')}"
                else:
                    response['message'] = base_message
                response['status_title'] = 'Payment Successful'
                response['status_icon'] = 'checkmark-circle'
            else:
                base_message = '✅ Platform fee paid! Complete payment in cash at handover.'
                if order.get('payment_test_mode'):
                    response['message'] = f"{base_message}\n\n⚠️ {order.get('payment_test_message', 'Test mode enabled')}"
                else:
                    response['message'] = base_message
                response['status_title'] = 'Payment Confirmed'
                response['status_icon'] = 'checkmark-circle'
        elif payment_status == PaymentStatus.PENDING_CASH_PAYMENT:
            base_message = f'Platform fee paid successfully. Pay KES {order["seller_amount"]:.2f} in cash to seller at pickup/delivery.'
            # Add test mode notice if applicable
            if order.get('payment_test_mode'):
                response['message'] = f"{base_message}\n\n⚠️ {order.get('payment_test_message', 'Test mode enabled')}"
            else:
                response['message'] = base_message
            response['status_title'] = 'Awaiting Cash Payment'
            response['status_icon'] = 'cash'
            response['cash_amount_due'] = order['seller_amount']
        elif payment_status == PaymentStatus.FAILED:
            error_msg = order.get('payment_error_message', 'Payment failed or was cancelled')
            response['message'] = f'Payment failed: {error_msg}'
            response['status_title'] = 'Payment Failed'
            response['status_icon'] = 'close-circle'
            response['error_code'] = order.get('payment_error_code')
            response['retryable'] = True
        elif payment_status == PaymentStatus.PENDING:
            # Calculate elapsed time for progressive messaging
            created_at = order.get('created_at')
            if created_at:
                elapsed_seconds = (datetime.utcnow() - created_at).total_seconds()
                response['elapsed_seconds'] = int(elapsed_seconds)

                # Quick cancellation detection via STK Query (avoid repeated calls)
                checkout_request_id = order.get('mpesa_checkout_request_id')
                last_check = order.get('payment_last_status_check_at')
                should_check = (
                    checkout_request_id
                    and elapsed_seconds > 15
                    and (not last_check or (datetime.utcnow() - last_check).total_seconds() > 30)
                )
                if should_check:
                    try:
                        stk_query = mpesa_service.stk_query(checkout_request_id)
                        await db.orders.update_one(
                            {'_id': ObjectId(order_id)},
                            {
                                '$set': {
                                    'payment_last_status_check_at': datetime.utcnow(),
                                    'payment_last_status_result': stk_query
                                }
                            }
                        )

                        result_code = stk_query.get('result_code')
                        if result_code in [0, '0']:
                            response['fast_confirmed'] = True
                            response['message'] = '✅ Payment received. Finalizing confirmation...'
                            response['status_title'] = 'Payment Received'
                            response['status_icon'] = 'checkmark-circle'
                            return response
                        if result_code in [1032, '1032']:
                            await _delete_failed_order(
                                order_id,
                                'Payment cancelled by user',
                                request
                            )
                            response['payment_status'] = PaymentStatus.FAILED
                            response['order_deleted'] = True
                            response['message'] = 'Payment cancelled on your phone. The booking was removed. Tap Retry to create a new booking.'
                            response['status_title'] = 'Payment Cancelled'
                            response['status_icon'] = 'close-circle'
                            return response
                    except Exception as e:
                        logger.error(f"STK query failed during status check for {order_id}: {e}")

                # Auto-fail orders pending for more than 10 minutes
                if elapsed_seconds > 600:
                    logger.info(f"Auto-failing stale pending order {order_id} (age: {elapsed_seconds}s)")
                    await _delete_failed_order(
                        order_id,
                        'Order timeout - payment not completed within 10 minutes',
                        request
                    )
                    response['payment_status'] = PaymentStatus.FAILED
                    response['order_deleted'] = True
                    response['message'] = '⏱️ Order expired and was removed because payment was not completed within 10 minutes. Tap Retry to create a new booking.'
                    response['status_title'] = 'Order Expired'
                    response['status_icon'] = 'time-outline'
                    return response
                elif elapsed_seconds > 90:
                    response['message'] = '⏱️ Still waiting... This is taking longer than usual. Please check your phone.'
                elif elapsed_seconds > 60:
                    response['message'] = '⏳ Waiting for M-Pesa confirmation... Please complete the prompt on your phone.'
                else:
                    response['message'] = '📱 Waiting for payment... Please check your phone for M-Pesa prompt.'
            else:
                response['message'] = 'Waiting for payment confirmation...'

            response['status_title'] = 'Processing Payment'
            response['status_icon'] = 'time'

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking payment status: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to check payment status")

@api_router.post("/orders/{order_id}/confirm-cash")
async def confirm_cash_payment(
    order_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Seller confirms receiving cash payment for an order
    Only for orders with payment_status = PENDING_CASH_PAYMENT
    Cash is paid directly to seller, so NO wallet credit is needed
    Only the platform fee was collected via M-Pesa

    NEW FLOW REQUIREMENTS:
    1. Provider must first confirm availability (provider_confirmed = True)
    2. For service bookings, buyer must confirm service completion (service_completed_by_customer = True)
    3. Then provider can confirm cash received
    """
    try:
        order = await db.orders.find_one({'_id': ObjectId(order_id)})
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        # Verify user is the seller
        if order['seller_id'] != str(current_user['_id']):
            raise HTTPException(status_code=403, detail="Only the seller can confirm cash payment")

        # Check current payment status
        if order['payment_status'] != PaymentStatus.PENDING_CASH_PAYMENT:
            raise HTTPException(
                status_code=400,
                detail=f"Order cannot be confirmed. Current status: {order['payment_status']}"
            )

        # NEW: Check if provider has confirmed availability first
        if order.get('provider_confirmed') != True:
            raise HTTPException(
                status_code=400,
                detail="You must first confirm availability for this booking before confirming cash payment. Please click 'Confirm Availability' first."
            )

        # NEW: For service bookings, check if buyer has confirmed service completion
        is_service_booking = 'service_id' in order
        if is_service_booking:
            if not order.get('service_completed_by_customer'):
                raise HTTPException(
                    status_code=400,
                    detail="Customer must confirm service completion before you can confirm cash payment. Please wait for the customer to confirm after the service is complete and they have paid you in cash."
                )

        seller_amount = order['seller_amount']

        # Update order status to PAID
        # NO wallet credit - seller receives cash directly from buyer
        await db.orders.update_one(
            {'_id': ObjectId(order_id)},
            {
                '$set': {
                    'payment_status': PaymentStatus.PAID,
                    'cash_confirmed_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow()
                }
            }
        )

        logger.info(f"✅ Cash payment confirmed for order {order_id}. Seller received KES {seller_amount} in cash (not credited to wallet)")

        # Notify buyer about cash payment confirmation
        try:
            # Support both service_id and pet_id for backward compatibility
            is_service_booking = 'service_id' in order

            if is_service_booking:
                service_id = order.get('service_id')
                listing = await db.service_listings.find_one({'_id': ObjectId(service_id)})
                item_name = listing.get('service_name', 'service') if listing else 'service'
                user_role = 'Provider'
            else:
                pet_id = order.get('pet_id')
                listing = await db.pet_listings.find_one({'_id': ObjectId(pet_id)})
                item_name = listing.get('breed', 'pet') if listing else 'pet'
                user_role = 'Seller'

            await create_notification(
                db=db,
                user_id=order['buyer_id'],
                notification_type=NotificationType.ORDER_CONFIRMED,
                title="Cash Payment Confirmed ✅",
                message=f"{user_role} confirmed receiving cash payment for {item_name}. {'Booking' if is_service_booking else 'Order'} complete!",
                data={
                    'action': 'view_order',
                    'order_id': order_id,
                    'service_id': order.get('service_id'),
                    'pet_id': order.get('pet_id')
                }
            )
        except Exception as e:
            logger.error(f"Failed to send cash confirmation notification: {e}")

        return {
            'success': True,
            'message': f'Cash payment confirmed. You received KES {seller_amount:.2f} in cash.',
            'order_id': order_id,
            'payment_status': PaymentStatus.PAID,
            'amount_received_cash': seller_amount
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error confirming cash payment: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to confirm payment: {str(e)}")

@api_router.post("/orders/{order_id}/cancel", response_model=OrderCancellationResponse)
async def cancel_order(
    order_id: str,
    cancellation_data: OrderCancellationRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Cancel an order with the following rules:
    - Can cancel when status is pending or pending_cash_payment
    - 24-hour waiting period must pass before cancellation
    - For pending_cash_payment: 50% platform fee refunded to buyer wallet, 50% retained as restocking fee
    - No cancellation allowed once order is fully paid
    - Pet listing reverts from SOLD to ACTIVE upon cancellation
    - Both buyer and seller can cancel
    """
    try:
        order = await db.orders.find_one({'_id': ObjectId(order_id)})
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        user_id = str(current_user['_id'])
        is_buyer = order['buyer_id'] == user_id
        is_seller = order['seller_id'] == user_id

        # Verify user is either buyer or seller
        if not is_buyer and not is_seller:
            raise HTTPException(status_code=403, detail="Not authorized to cancel this order")

        payment_status = order.get('payment_status')

        # Check if order can be cancelled based on payment status
        if payment_status == PaymentStatus.PAID:
            raise HTTPException(
                status_code=400,
                detail="Cannot cancel a fully paid order. Future refund logic will be introduced."
            )

        if payment_status == PaymentStatus.CANCELLED:
            raise HTTPException(
                status_code=400,
                detail="Order has already been cancelled"
            )

        if payment_status == PaymentStatus.FAILED:
            raise HTTPException(
                status_code=400,
                detail="Cannot cancel a failed order"
            )

        if payment_status not in [PaymentStatus.PENDING, PaymentStatus.PENDING_CASH_PAYMENT]:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot cancel order with status: {payment_status}"
            )

        # Check 24-hour waiting period (only for seller cancellations)
        created_at = order.get('created_at')
        if is_seller and created_at:
            elapsed_hours = (datetime.utcnow() - created_at).total_seconds() / 3600
            if elapsed_hours < 24:
                hours_remaining = 24 - elapsed_hours
                raise HTTPException(
                    status_code=400,
                    detail=f"Sellers must wait 24 hours before cancelling. Please wait {hours_remaining:.1f} more hours."
                )

        refund_amount = 0.0
        restocking_fee = 0.0
        cancellation_reason = cancellation_data.reason or f"Cancelled by {'buyer' if is_buyer else 'seller'}"

        # Handle fee-splitting for pending_cash_payment cancellations
        if payment_status == PaymentStatus.PENDING_CASH_PAYMENT:
            platform_fee = order['platform_fee']

            # Split the platform fee: 50% refund to buyer, 50% retained as restocking fee
            refund_amount = platform_fee / 2
            restocking_fee = platform_fee / 2

            # Refund 50% to buyer's wallet
            buyer_txn = await create_transaction(
                user_id=order['buyer_id'],
                amount=refund_amount,
                transaction_type=TransactionType.CANCELLATION_FEE_REFUND,
                status=TransactionStatus.COMPLETED,
                description=f"50% platform fee refund for cancelled order {order_id[:8]}",
                order_id=order_id
            )

            await update_wallet_balance(
                order['buyer_id'],
                refund_amount,
                str(buyer_txn['_id'])
            )

            # Deduct the refund from platform wallet (50% was already collected)
            platform_txn = await create_transaction(
                user_id=PLATFORM_WALLET_ID,
                amount=-refund_amount,
                transaction_type=TransactionType.CANCELLATION_FEE_REFUND,
                status=TransactionStatus.COMPLETED,
                description=f"50% platform fee refund to buyer for cancelled order {order_id[:8]}",
                order_id=order_id
            )

            await update_wallet_balance(
                PLATFORM_WALLET_ID,
                -refund_amount,
                str(platform_txn['_id'])
            )

            # Record the retained 50% as restocking fee (already in platform wallet)
            restocking_txn = await create_transaction(
                user_id=PLATFORM_WALLET_ID,
                amount=0,  # No balance change, already collected
                transaction_type=TransactionType.CANCELLATION_RESTOCKING_FEE,
                status=TransactionStatus.COMPLETED,
                description=f"50% restocking fee retained for cancelled order {order_id[:8]}",
                order_id=order_id
            )

            logger.info(f"Order {order_id} cancelled with fee split: Refund={refund_amount}, Restocking Fee={restocking_fee}")

        # Update order status to CANCELLED
        await db.orders.update_one(
            {'_id': ObjectId(order_id)},
            {
                '$set': {
                    'payment_status': PaymentStatus.CANCELLED,
                    'cancellation_reason': cancellation_reason,
                    'cancelled_by': user_id,
                    'cancelled_at': datetime.utcnow(),
                    'refund_amount': refund_amount,
                    'restocking_fee': restocking_fee,
                    'updated_at': datetime.utcnow()
                }
            }
        )

        # Revert listing from SOLD to ACTIVE (support both service and pet)
        # Determine if this is a service booking or pet order
        is_service_booking = 'service_id' in order
        listing_id = order.get('service_id') if is_service_booking else order.get('pet_id')

        if listing_id:
            # Get the appropriate collection
            collection = db.service_listings if is_service_booking else db.pet_listings
            listing = await collection.find_one({'_id': ObjectId(listing_id)})

            if listing and listing.get('status') == ListingStatus.SOLD:
                await collection.update_one(
                    {'_id': ObjectId(listing_id)},
                    {'$set': {'status': ListingStatus.ACTIVE, 'updated_at': datetime.utcnow()}}
                )
                item_type = "Service" if is_service_booking else "Pet"
                logger.info(f"{item_type} listing {listing_id} reverted from SOLD to ACTIVE")

        logger.info(f"✅ Order {order_id} cancelled by {'buyer' if is_buyer else 'seller'} {user_id}")

        return {
            'success': True,
            'message': f'Order cancelled successfully. {f"Refund of KES {refund_amount:.2f} credited to buyer wallet." if refund_amount > 0 else ""}',
            'order_id': order_id,
            'refund_amount': refund_amount if refund_amount > 0 else None,
            'restocking_fee': restocking_fee if restocking_fee > 0 else None
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling order: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to cancel order: {str(e)}")

@api_router.post("/orders/{order_id}/seller-cancel", response_model=OrderCancellationResponse)
async def seller_cancel_order(
    order_id: str,
    cancellation_data: OrderCancellationRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Seller-initiated order cancellation with the following rules:
    - Only sellers can use this endpoint
    - Can cancel only when status is pending or pending_cash_payment
    - Fully paid orders are NOT cancellable
    - Seller penalty: 10% of order value deducted from seller's wallet or future earnings
    - For pending_cash_payment orders: Handle platform fee implications correctly
    - Pet listing becomes INACTIVE (REMOVED status) and requires manual republishing
    - No time-based or frequency restrictions
    - Full audit logging and state transition enforcement
    """
    try:
        # Fetch order
        order = await db.orders.find_one({'_id': ObjectId(order_id)})
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        seller_id = str(current_user['_id'])

        # Verify user is the seller
        if order['seller_id'] != seller_id:
            raise HTTPException(
                status_code=403,
                detail="Only the seller of this order can use seller cancellation"
            )

        # Verify user role is seller
        if current_user.get('role') != UserRole.SELLER:
            raise HTTPException(
                status_code=403,
                detail="User must have seller role to perform seller cancellation"
            )

        payment_status = order.get('payment_status')
        order_amount = order['price']
        platform_fee = order['platform_fee']
        seller_amount = order['seller_amount']

        # STATUS CHECK: Only allow cancellation for pending and pending_cash_payment
        if payment_status not in [PaymentStatus.PENDING, PaymentStatus.PENDING_CASH_PAYMENT]:
            if payment_status == PaymentStatus.PAID:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot cancel a fully paid order. Fully paid orders are not cancellable by sellers."
                )
            elif payment_status == PaymentStatus.CANCELLED:
                raise HTTPException(
                    status_code=400,
                    detail="Order has already been cancelled"
                )
            elif payment_status == PaymentStatus.FAILED:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot cancel a failed order"
                )
            else:
                raise HTTPException(
                    status_code=400,
                    detail=f"Cannot cancel order with status: {payment_status}"
                )

        # Get settings for cancellation penalty
        settings = await _get_platform_settings_internal()
        penalty_percentage = settings.get('sellerCancellationPenaltyPercentage', 10.0) / 100.0  # Convert from percentage to decimal

        # Calculate seller penalty (configurable % of order value, default 10%)
        seller_penalty = order_amount * penalty_percentage

        # Get seller wallet
        seller_wallet = await get_or_create_wallet(seller_id)
        seller_current_balance = seller_wallet['balance']

        # Determine if penalty comes from wallet or future earnings
        penalty_from_wallet = min(seller_penalty, seller_current_balance)
        penalty_from_future = seller_penalty - penalty_from_wallet

        refund_amount = 0.0

        # HANDLE PENDING_CASH_PAYMENT: Platform fee was already paid by buyer
        if payment_status == PaymentStatus.PENDING_CASH_PAYMENT:
            # Refund full platform fee to buyer
            refund_amount = platform_fee

            # Refund platform fee to buyer's wallet
            buyer_txn = await create_transaction(
                user_id=order['buyer_id'],
                amount=refund_amount,
                transaction_type=TransactionType.CANCELLATION_FEE_REFUND,
                status=TransactionStatus.COMPLETED,
                description=f"Full platform fee refund for seller-cancelled order {order_id[:8]}",
                order_id=order_id
            )

            await update_wallet_balance(
                order['buyer_id'],
                refund_amount,
                str(buyer_txn['_id'])
            )

            # Deduct platform fee from platform wallet
            platform_deduct_txn = await create_transaction(
                user_id=PLATFORM_WALLET_ID,
                amount=-refund_amount,
                transaction_type=TransactionType.CANCELLATION_FEE_REFUND,
                status=TransactionStatus.COMPLETED,
                description=f"Platform fee refund to buyer for seller-cancelled order {order_id[:8]}",
                order_id=order_id
            )

            await update_wallet_balance(
                PLATFORM_WALLET_ID,
                -refund_amount,
                str(platform_deduct_txn['_id'])
            )

            logger.info(f"Refunded platform fee of KES {refund_amount:.2f} to buyer for seller-cancelled order {order_id}")

        # APPLY SELLER PENALTY
        if penalty_from_wallet > 0:
            # Deduct from seller's wallet
            seller_penalty_txn = await create_transaction(
                user_id=seller_id,
                amount=-penalty_from_wallet,
                transaction_type=TransactionType.SELLER_CANCELLATION_PENALTY,
                status=TransactionStatus.COMPLETED,
                description=f"{penalty_percentage*100:.1f}% cancellation penalty for seller-cancelled order {order_id[:8]} (from wallet)",
                order_id=order_id
            )

            await update_wallet_balance(
                seller_id,
                -penalty_from_wallet,
                str(seller_penalty_txn['_id'])
            )

            # Add penalty to platform wallet
            platform_penalty_txn = await create_transaction(
                user_id=PLATFORM_WALLET_ID,
                amount=penalty_from_wallet,
                transaction_type=TransactionType.SELLER_CANCELLATION_PENALTY,
                status=TransactionStatus.COMPLETED,
                description=f"Seller cancellation penalty from order {order_id[:8]}",
                order_id=order_id
            )

            await update_wallet_balance(
                PLATFORM_WALLET_ID,
                penalty_from_wallet,
                str(platform_penalty_txn['_id'])
            )

            logger.info(f"Deducted seller penalty of KES {penalty_from_wallet:.2f} from seller wallet for order {order_id}")

        if penalty_from_future > 0:
            # Record penalty to be deducted from future earnings
            future_penalty_txn = await create_transaction(
                user_id=seller_id,
                amount=0,  # No immediate balance change
                transaction_type=TransactionType.SELLER_CANCELLATION_PENALTY,
                status=TransactionStatus.PENDING,
                description=f"{penalty_percentage*100:.1f}% cancellation penalty for seller-cancelled order {order_id[:8]} (from future earnings: KES {penalty_from_future:.2f})",
                order_id=order_id
            )

            # Update seller's pending deductions
            await db.wallets.update_one(
                {'user_id': seller_id},
                {
                    '$inc': {'pending_deductions': penalty_from_future},
                    '$set': {'updated_at': datetime.utcnow()}
                }
            )

            logger.info(f"Recorded pending penalty of KES {penalty_from_future:.2f} from future earnings for order {order_id}")

        # UPDATE ORDER STATUS TO CANCELLED
        cancellation_reason = cancellation_data.reason or "Seller-initiated cancellation"

        await db.orders.update_one(
            {'_id': ObjectId(order_id)},
            {
                '$set': {
                    'payment_status': PaymentStatus.CANCELLED,
                    'cancellation_reason': cancellation_reason,
                    'cancelled_by': seller_id,
                    'cancelled_at': datetime.utcnow(),
                    'cancellation_type': 'seller_initiated',
                    'seller_penalty': seller_penalty,
                    'penalty_from_wallet': penalty_from_wallet,
                    'penalty_from_future': penalty_from_future,
                    'refund_amount': refund_amount,
                    'updated_at': datetime.utcnow()
                }
            }
        )

        # MARK LISTING AS INACTIVE (REMOVED status - requires manual republishing)
        # Support both service bookings and pet orders
        is_service_booking = 'service_id' in order
        listing_id = order.get('service_id') if is_service_booking else order.get('pet_id')
        item_type = "Service" if is_service_booking else "Pet"

        listing_marked_inactive = False
        if listing_id:
            # Get the appropriate collection
            collection = db.service_listings if is_service_booking else db.pet_listings
            listing = await collection.find_one({'_id': ObjectId(listing_id)})

            if listing:
                old_status = listing.get('status')
                await collection.update_one(
                    {'_id': ObjectId(listing_id)},
                    {
                        '$set': {
                            'status': ListingStatus.REMOVED,
                            'removal_reason': f'Seller cancelled order {order_id[:8]}',
                            'previous_status': old_status,
                            'updated_at': datetime.utcnow()
                        }
                    }
                )
                listing_marked_inactive = True
                logger.info(f"{item_type} listing {listing_id} marked as REMOVED (inactive) - requires manual republishing")

        # AUDIT LOG
        audit_log_entry = {
            'event_type': 'seller_order_cancellation',
            'order_id': order_id,
            'seller_id': seller_id,
            'buyer_id': order['buyer_id'],
            'listing_id': listing_id,
            'is_service_booking': is_service_booking,
            'previous_payment_status': payment_status,
            'new_payment_status': PaymentStatus.CANCELLED,
            'order_amount': order_amount,
            'seller_penalty': seller_penalty,
            'penalty_from_wallet': penalty_from_wallet,
            'penalty_from_future': penalty_from_future,
            'refund_to_buyer': refund_amount,
            'cancellation_reason': cancellation_reason,
            'listing_marked_inactive': listing_marked_inactive,
            'timestamp': datetime.utcnow()
        }

        # Keep legacy pet_id field for backward compatibility with existing audit tools
        if not is_service_booking and listing_id:
            audit_log_entry['pet_id'] = listing_id

        await db.audit_logs.insert_one(audit_log_entry)

        logger.info(f"✅ SELLER CANCELLATION: Order {order_id} cancelled by seller {seller_id}. "
                   f"Penalty: KES {seller_penalty:.2f} (wallet: {penalty_from_wallet:.2f}, future: {penalty_from_future:.2f}), "
                   f"Refund: KES {refund_amount:.2f}")

        # Build response message
        penalty_message = f"Seller penalty of KES {seller_penalty:.2f} applied"
        if penalty_from_wallet > 0 and penalty_from_future > 0:
            penalty_message += f" (KES {penalty_from_wallet:.2f} deducted from wallet, KES {penalty_from_future:.2f} will be deducted from future earnings)"
        elif penalty_from_wallet > 0:
            penalty_message += f" (deducted from wallet)"
        elif penalty_from_future > 0:
            penalty_message += f" (will be deducted from future earnings)"

        refund_message = f"Buyer refunded KES {refund_amount:.2f}. " if refund_amount > 0 else ""
        listing_message = f"{item_type} listing is now inactive and requires manual republishing." if listing_marked_inactive else ""

        return {
            'success': True,
            'message': f"Order cancelled successfully. {penalty_message}. {refund_message}{listing_message}",
            'order_id': order_id,
            'refund_amount': refund_amount if refund_amount > 0 else None,
            'restocking_fee': seller_penalty
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in seller cancellation: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to cancel order: {str(e)}")

async def _cancel_order_logic(
    order_id: str,
    current_user: dict,
    cancellation_data: Optional[OrderCancellationRequest] = None
) -> OrderCancellationResponse:
    """
    Cancel an order with proper refund logic
    - Pending/Failed orders: Full cancellation without charges
    - Paid orders: Partial refund (50% of platform fee) with restocking fee
    - Pending cash payment: Cancel without charges
    """
    try:
        order = await db.orders.find_one({'_id': ObjectId(order_id)})
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        user_id = str(current_user['_id'])
        is_buyer = order['buyer_id'] == user_id
        is_seller = order['seller_id'] == user_id

        # Check permissions
        if not is_buyer and not is_seller:
            raise HTTPException(
                status_code=403,
                detail="You don't have permission to delete this order"
            )

        # Sellers can only delete orders in terminal states (for cleanup)
        if is_seller and not is_buyer:
            terminal_states = [PaymentStatus.CANCELLED, PaymentStatus.FAILED, PaymentStatus.REFUNDED]
            if order.get('payment_status') not in terminal_states:
                raise HTTPException(
                    status_code=403,
                    detail="Sellers can only delete cancelled, failed, or refunded orders"
                )

            # Simple deletion for sellers - no refund logic needed
            await _remove_calendar_events_for_order(order)
            await db.orders.delete_one({'_id': ObjectId(order_id)})
            logger.info(f"Order {order_id} deleted by seller {user_id}")

            return OrderCancellationResponse(
                success=True,
                message='Order deleted successfully',
                order_id=order_id,
                refund_amount=0,
                restocking_fee=0
            )

        # Only buyers can cancel active orders
        if not is_buyer:
            raise HTTPException(
                status_code=403,
                detail="Only buyers can cancel orders"
            )

        payment_status = order.get('payment_status')
        pet_id = order.get('pet_id')
        seller_id = order.get('seller_id')
        order_price = order.get('price', 0)

        # Get platform fee from order or calculate from settings if not stored
        if 'platform_fee' in order:
            platform_fee = order['platform_fee']
        else:
            # Fallback: calculate from current settings
            settings = await _get_platform_settings_internal()
            platform_fee_percentage = settings.get('platformFeePercentage', 5.0) / 100.0
            platform_fee = order_price * platform_fee_percentage

        seller_amount = order.get('seller_amount', order_price - platform_fee)

        # Handle different payment statuses
        if payment_status in [PaymentStatus.PENDING, PaymentStatus.FAILED, PaymentStatus.PENDING_CASH_PAYMENT]:
            # Simple cancellation for unpaid orders
            await db.orders.update_one(
                {'_id': ObjectId(order_id)},
                {
                    '$set': {
                        'payment_status': PaymentStatus.CANCELLED,
                        'updated_at': datetime.utcnow()
                    }
                }
            )

            # Make pet available again
            await db.pet_listings.update_one(
                {'_id': ObjectId(pet_id)},
                {'$set': {'status': ListingStatus.ACTIVE, 'updated_at': datetime.utcnow()}}
            )

            logger.info(f"Order {order_id} cancelled by buyer {user_id} (unpaid)")

            return OrderCancellationResponse(
                success=True,
                message='Order cancelled successfully',
                order_id=order_id,
                refund_amount=0,
                restocking_fee=0
            )

        elif payment_status == PaymentStatus.PAID:
            # Paid order cancellation with partial refund
            # Refund 50% of platform fee to buyer, 50% kept as cancellation fee
            platform_fee_refund = platform_fee * 0.5
            cancellation_fee = platform_fee * 0.5

            # Calculate amounts
            buyer_refund = seller_amount + platform_fee_refund  # Seller amount + 50% platform fee
            platform_keeps = cancellation_fee  # 50% of platform fee

            # Reverse seller's earning
            seller_wallet = await get_or_create_wallet(seller_id)
            if seller_wallet['balance'] < seller_amount:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot cancel order: Seller has insufficient balance for reversal. Please contact support."
                )

            # Deduct from seller wallet
            seller_txn = await create_transaction(
                user_id=seller_id,
                amount=-seller_amount,
                transaction_type=TransactionType.REFUND,
                status=TransactionStatus.COMPLETED,
                description=f"Refund for cancelled order {order_id}",
                order_id=order_id
            )
            await update_wallet_balance(seller_id, -seller_amount, str(seller_txn['_id']))
            await db.wallets.update_one(
                {'user_id': seller_id},
                {'$inc': {'total_earned': -seller_amount}}
            )

            # Refund to buyer wallet
            buyer_wallet = await get_or_create_wallet(user_id)
            buyer_txn = await create_transaction(
                user_id=user_id,
                amount=buyer_refund,
                transaction_type=TransactionType.REFUND,
                status=TransactionStatus.COMPLETED,
                description=f"Refund for cancelled order {order_id} (50% platform fee deducted)",
                order_id=order_id
            )
            await update_wallet_balance(user_id, buyer_refund, str(buyer_txn['_id']))

            # Adjust platform wallet (lost 50% of fee, keeps other 50%)
            platform_wallet = await get_or_create_platform_wallet()
            platform_adjustment = -platform_fee_refund  # Return 50% to buyer
            platform_txn = await create_transaction(
                user_id=PLATFORM_WALLET_ID,
                amount=platform_adjustment,
                transaction_type=TransactionType.CANCELLATION_FEE_REFUND,
                status=TransactionStatus.COMPLETED,
                description=f"50% platform fee refund for cancelled order {order_id}",
                order_id=order_id
            )
            await update_wallet_balance(PLATFORM_WALLET_ID, platform_adjustment, str(platform_txn['_id']))

            # Update order status
            await db.orders.update_one(
                {'_id': ObjectId(order_id)},
                {
                    '$set': {
                        'payment_status': PaymentStatus.CANCELLED,
                        'cancellation_reason': cancellation_data.reason if cancellation_data else 'Buyer cancelled',
                        'cancellation_date': datetime.utcnow(),
                        'refund_amount': buyer_refund,
                        'cancellation_fee': cancellation_fee,
                        'updated_at': datetime.utcnow()
                    }
                }
            )

            # Make pet available again
            await db.pet_listings.update_one(
                {'_id': ObjectId(pet_id)},
                {'$set': {'status': ListingStatus.ACTIVE, 'updated_at': datetime.utcnow()}}
            )

            logger.info(
                f"Paid order {order_id} cancelled by buyer {user_id}. "
                f"Refund: {buyer_refund}, Platform fee kept: {cancellation_fee}"
            )

            return OrderCancellationResponse(
                success=True,
                message='Order cancelled. You have been refunded to your wallet minus a 50% platform fee.',
                order_id=order_id,
                refund_amount=buyer_refund,
                restocking_fee=cancellation_fee
            )

        else:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot cancel order with status: {payment_status}"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling order: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to cancel order: {str(e)}")

@api_router.post("/orders/{order_id}/cancel", response_model=OrderCancellationResponse)
async def cancel_order_post(
    order_id: str,
    current_user: dict = Depends(get_current_user),
    cancellation_data: Optional[OrderCancellationRequest] = None
):
    """Cancel an order (POST method)"""
    return await _cancel_order_logic(order_id, current_user, cancellation_data)

@api_router.delete("/orders/{order_id}")
async def cancel_order_delete(
    order_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Cancel an order (DELETE method for backward compatibility)"""
    result = await _cancel_order_logic(order_id, current_user, None)
    return {
        'message': result.message,
        'id': result.order_id,
        'success': result.success
    }

@api_router.delete("/orders/{order_id}/delete")
async def delete_cancelled_order(
    order_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a cancelled/failed/refunded order (buyer cleanup)."""
    order = await db.orders.find_one({'_id': ObjectId(order_id)})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    user_id = str(current_user['_id'])
    if order.get('buyer_id') != user_id:
        raise HTTPException(status_code=403, detail="Only the buyer can delete this order")

    terminal_states = [PaymentStatus.CANCELLED, PaymentStatus.FAILED, PaymentStatus.REFUNDED]
    if order.get('payment_status') not in terminal_states:
        raise HTTPException(status_code=400, detail="Only cancelled, failed, or refunded orders can be deleted")

    await _remove_calendar_events_for_order(order)
    await db.orders.delete_one({'_id': ObjectId(order_id)})
    logger.info(f"Order {order_id} deleted by buyer {user_id}")

    return {'success': True, 'message': 'Order deleted successfully', 'order_id': order_id}

@api_router.post("/wallet/withdraw", response_model=WithdrawalResponse)
async def request_withdrawal(
    withdrawal_request: WithdrawalRequest,
    current_user: dict = Depends(get_current_user),
    request: Request = None
):
    """Request withdrawal from wallet to M-Pesa (available for both buyers and sellers)"""
    try:
        idempotency_key = _require_idempotency_key(request)
        idempotency_scope = 'wallet_withdrawal'
        request_hash = _hash_request_payload({
            'amount': withdrawal_request.amount,
            'phone_number': withdrawal_request.phone_number
        })
        idempotency_response = await _get_idempotency_response(
            idempotency_key,
            idempotency_scope,
            str(current_user['_id']),
            request_hash
        )
        if idempotency_response is not None:
            return idempotency_response

        user_id = str(current_user['_id'])
        user_role = current_user.get('role', 'buyer')

        logger.info(f"Withdrawal request from {user_role} {user_id}: amount={withdrawal_request.amount}, phone={withdrawal_request.phone_number}")

        # Get settings for withdrawal limits
        settings = await _get_platform_settings_internal()
        min_withdrawal = settings.get('minimumWithdrawal', 100.0)
        max_withdrawal = settings.get('maximumWithdrawal', 100000.0)

        # Check minimum amount
        if withdrawal_request.amount < min_withdrawal:
            raise HTTPException(
                status_code=400,
                detail=f"Minimum withdrawal amount is KES {min_withdrawal}"
            )

        # Check maximum amount
        if withdrawal_request.amount > max_withdrawal:
            raise HTTPException(
                status_code=400,
                detail=f"Maximum withdrawal amount is KES {max_withdrawal}"
            )

        # SAFETY LIMIT: Check single transaction limit (Phase 1 security)
        if withdrawal_request.amount > MAX_SINGLE_TRANSACTION:
            raise HTTPException(
                status_code=400,
                detail=f"Single transaction limit is KES {MAX_SINGLE_TRANSACTION}. For larger amounts, please make multiple withdrawals or contact support."
            )

        # Get wallet
        wallet = await get_or_create_wallet(user_id)

        # Check balance
        if wallet['balance'] < withdrawal_request.amount:
            raise HTTPException(
                status_code=400,
                detail=f"Insufficient balance. Available: KES {wallet['balance']:.2f}"
            )

        # Fraud checks (may require manual approval)
        fraud_check = await check_withdrawal_fraud(
            user_id=user_id,
            amount=withdrawal_request.amount,
            user=current_user,
            request=request
        )

        if fraud_check.get('requires_approval'):
            withdrawal_data = {
                'user_id': user_id,
                'amount': withdrawal_request.amount,
                'phone_number': withdrawal_request.phone_number,
                'status': WithdrawalStatus.PENDING_APPROVAL,
                'approval_reason': fraud_check.get('reason', ''),
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }
            result = await db.withdrawals.insert_one(withdrawal_data)
            withdrawal_id = str(result.inserted_id)

            await log_security_event(
                event_type='withdrawal_requires_approval',
                severity='high',
                details={'withdrawal_id': withdrawal_id, 'reason': fraud_check.get('reason', '')},
                user_id=user_id,
                request=request
            )

            return {
                'status': 'pending_approval',
                'message': fraud_check.get('reason', 'Withdrawal pending approval'),
                'withdrawal_id': withdrawal_id
            }

        # Initiate B2C payment
        mpesa_response = mpesa_service.b2c_payment(
            phone_number=withdrawal_request.phone_number,
            amount=int(withdrawal_request.amount),
            remarks=f"Withdrawal for {current_user['name']}"
        )

        if mpesa_response.get('success'):
            # Create withdrawal record
            withdrawal_data = {
                'user_id': user_id,
                'amount': withdrawal_request.amount,
                'phone_number': withdrawal_request.phone_number,
                'status': WithdrawalStatus.PROCESSING,
                'mpesa_conversation_id': mpesa_response.get('conversation_id'),
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }

            result = await db.withdrawals.insert_one(withdrawal_data)
            withdrawal_id = str(result.inserted_id)

            # Create transaction record
            txn = await create_transaction(
                user_id=user_id,
                amount=-withdrawal_request.amount,
                transaction_type=TransactionType.WITHDRAWAL,
                status=TransactionStatus.COMPLETED,
                description=f"Withdrawal to {withdrawal_request.phone_number}"
            )

            # Deduct from wallet balance (atomic)
            await debit_wallet_balance(user_id, withdrawal_request.amount, str(txn['_id']))
            await db.wallets.update_one(
                {'user_id': user_id},
                {'$inc': {'total_withdrawn': withdrawal_request.amount}}
            )

            logger.info(f"Withdrawal initiated for user {user_id}, amount: {withdrawal_request.amount}")

            # Notify user that withdrawal is being processed
            try:
                await create_notification(
                    db=db,
                    user_id=user_id,
                    notification_type=NotificationType.WITHDRAWAL_PROCESSED,
                    title="Withdrawal Processing 💸",
                    message=f"Your withdrawal of KES {withdrawal_request.amount:.2f} to {withdrawal_request.phone_number} is being processed.",
                    data={
                        'withdrawal_id': withdrawal_id,
                        'amount': withdrawal_request.amount
                    },
                    send_push=True
                )
            except Exception as notif_error:
                logger.error(f"Failed to send withdrawal notification: {notif_error}")

            response_payload = {
                'id': withdrawal_id,
                'user_id': user_id,
                'amount': withdrawal_request.amount,
                'phone_number': withdrawal_request.phone_number,
                'status': WithdrawalStatus.PROCESSING,
                'mpesa_conversation_id': mpesa_response.get('conversation_id'),
                'created_at': withdrawal_data['created_at'],
                'updated_at': withdrawal_data['updated_at']
            }
            await _finalize_idempotency(
                idempotency_key,
                idempotency_scope,
                str(current_user['_id']),
                response_payload
            )
            return response_payload
        else:
            logger.error(f"Withdrawal failed: {mpesa_response.get('error')}")
            await _finalize_idempotency(
                idempotency_key,
                idempotency_scope,
                str(current_user['_id']),
                {'success': False, 'message': 'Withdrawal failed'},
                status='failed'
            )
            raise HTTPException(
                status_code=500,
                detail=f"Withdrawal failed: {mpesa_response.get('error', 'Unknown error')}"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing withdrawal: {str(e)}")
        if request:
            await _finalize_idempotency(
                idempotency_key,
                idempotency_scope,
                str(current_user['_id']),
                {'success': False, 'message': 'Withdrawal failed'},
                status='failed'
            )
        raise HTTPException(status_code=500, detail=f"Withdrawal failed: {str(e)}")

@api_router.get("/wallet/withdrawals")
async def get_withdrawals(
    current_user: dict = Depends(get_current_user),
    skip: int = 0,
    limit: int = 50
):
    """Get withdrawal history"""
    user_id = str(current_user['_id'])

    withdrawals = await db.withdrawals.find(
        {'user_id': user_id}
    ).sort('created_at', -1).skip(skip).limit(limit).to_list(limit)

    result = []
    for withdrawal in withdrawals:
        result.append({
            'id': str(withdrawal['_id']),
            'user_id': withdrawal['user_id'],
            'amount': withdrawal['amount'],
            'phone_number': withdrawal['phone_number'],
            'status': withdrawal['status'],
            'mpesa_conversation_id': withdrawal.get('mpesa_conversation_id'),
            'created_at': withdrawal['created_at'],
            'updated_at': withdrawal['updated_at']
        })

    return result

@api_router.post("/mpesa/callback")
async def mpesa_callback(callback_data: dict, request: Request):
    """
    M-Pesa callback endpoint
    This is called by M-Pesa to confirm payment status
    """
    checkout_request_id = None
    processing_status = None
    processing_details = None
    try:
        _verify_webhook_ip(request)
        _verify_webhook_signature(callback_data, request.headers.get('X-MPESA-SIGNATURE'))
        logger.info(f"M-Pesa callback received: {callback_data}")

        schema_error = _validate_mpesa_callback_schema(callback_data)
        if schema_error:
            await log_security_event(
                event_type='mpesa_callback_schema_invalid',
                severity='high',
                details={'error': schema_error},
                request=request
            )
            return {'ResultCode': 1, 'ResultDesc': 'Invalid callback schema'}

        # Extract M-Pesa response data
        body = callback_data.get('Body', {})
        stk_callback = body.get('stkCallback', {})

        result_code = stk_callback.get('ResultCode')
        checkout_request_id = stk_callback.get('CheckoutRequestID')

        if not checkout_request_id:
            logger.error("No CheckoutRequestID in callback")
            return {'ResultCode': 1, 'ResultDesc': 'No CheckoutRequestID'}

        # Idempotency guard for callbacks
        if await _ensure_mpesa_callback_idempotent(checkout_request_id):
            logger.info(f"M-Pesa callback already processed: {checkout_request_id}")
            return {'ResultCode': 0, 'ResultDesc': 'Already processed'}

        # Verify with STK Query API
        stk_query = mpesa_service.stk_query(checkout_request_id)
        if not stk_query.get('success') or stk_query.get('result_code') not in [0, '0']:
            await _mark_mpesa_callback_processed(checkout_request_id, 'failed', {'reason': 'stk_query_failed', 'response': stk_query})
            await log_security_event(
                event_type='mpesa_stk_query_failed',
                severity='high',
                details={'checkout_request_id': checkout_request_id, 'response': stk_query},
                request=request
            )
            return {'ResultCode': 1, 'ResultDesc': 'STK Query failed'}

        result_desc = stk_callback.get('ResultDesc', '')
        processing_status = 'processed' if result_code == 0 else 'failed'
        processing_details = {'result_code': result_code, 'result_desc': result_desc}

        # Find order by checkout request ID (either main payment or delivery fee payment)
        order = await db.orders.find_one({
            '$or': [
                {'mpesa_checkout_request_id': checkout_request_id},
                {'mpesa_delivery_fee_checkout_request_id': checkout_request_id}
            ]
        })

        # If no order found, check for verification payment
        if not order:
            verification = await db.verifications.find_one({
                'mpesa_checkout_request_id': checkout_request_id
            })

            if verification:
                # Handle verification payment callback
                logger.info(f"Processing M-Pesa callback for verification {verification['_id']}")
                settings = await _get_platform_settings_internal()
                default_verification_fee = settings.get('verificationFee', VERIFICATION_FEE)

                result_code = stk_callback.get('ResultCode')

                if verification.get('payment_status') == 'paid':
                    logger.info(f"Verification {verification['_id']} already paid. Ignoring duplicate callback.")
                    return {'ResultCode': 0, 'ResultDesc': 'Already processed'}

                # Payment successful
                if result_code == 0:
                    logger.info(f"✅ Verification payment successful for verification {verification['_id']}")

                    # Extract callback metadata
                    callback_metadata = stk_callback.get('CallbackMetadata', {})
                    items = callback_metadata.get('Item', [])

                    mpesa_receipt_number = None
                    amount_paid = None
                    for item in items:
                        if item.get('Name') == 'MpesaReceiptNumber':
                            mpesa_receipt_number = item.get('Value')
                        elif item.get('Name') == 'Amount':
                            amount_paid = item.get('Value')

                    verification_fee = verification.get('verification_fee', default_verification_fee)
                    user_id = verification['user_id']

                    if not _amount_matches(amount_paid, verification_fee):
                        await db.verifications.update_one(
                            {'_id': verification['_id']},
                            {
                                '$set': {
                                    'payment_status': 'failed',
                                    'status': VerificationStatus.PAYMENT_PENDING,
                                    'payment_error_message': f"Amount mismatch: paid {amount_paid}, expected {verification_fee}",
                                    'updated_at': datetime.utcnow()
                                }
                            }
                        )
                        await log_security_event(
                            event_type='payment_amount_mismatch',
                            severity='high',
                            details={'verification_id': str(verification['_id']), 'expected': verification_fee, 'paid': amount_paid, 'type': 'verification'},
                            user_id=user_id,
                            request=request
                        )
                        return {'ResultCode': 0, 'ResultDesc': 'Amount mismatch'}

                    # Add to platform wallet
                    await db.wallets.update_one(
                        {'user_id': PLATFORM_WALLET_ID},
                        {'$inc': {'balance': verification_fee}}
                    )

                    # Create platform earning transaction
                    await create_transaction(
                        user_id=PLATFORM_WALLET_ID,
                        amount=verification_fee,
                        transaction_type=TransactionType.PLATFORM_FEE_VERIFICATION,
                        status=TransactionStatus.COMPLETED,
                        description=f'Verification fee from user {user_id} via M-Pesa (Verification ID: {str(verification["_id"])[:8]})',
                        order_id=None
                    )

                    # Update verification payment status
                    await db.verifications.update_one(
                        {'_id': verification['_id']},
                        {
                            '$set': {
                                'payment_status': 'paid',
                                'paid_at': datetime.utcnow(),
                                'status': VerificationStatus.UNDER_REVIEW,
                                'mpesa_receipt_number': mpesa_receipt_number,
                                'updated_at': datetime.utcnow()
                            }
                        }
                    )

                    # Update user KYC status to pending
                    await db.users.update_one(
                        {'_id': ObjectId(user_id)},
                        {'$set': {'kyc_status': KYCStatus.PENDING}}
                    )

                    # Send notification
                    await create_notification(
                        db=db,
                        user_id=user_id,
                        notification_type=NotificationType.ORDER_UPDATED,
                        title="Verification Payment Successful! ✅",
                        message=f"Your verification fee payment was successful. Your verification is now under review.",
                        data={'verification_id': str(verification['_id'])}
                    )

                    logger.info(f"✅ Verification payment processed for verification {verification['_id']}")
                    return {'ResultCode': 0, 'ResultDesc': 'Verification payment processed successfully'}

                # Payment failed or cancelled
                else:
                    result_desc = stk_callback.get('ResultDesc', 'Payment failed or cancelled')
                    logger.warning(f"❌ Verification payment failed: {result_desc}")

                    # Update verification with failure reason
                    await db.verifications.update_one(
                        {'_id': verification['_id']},
                        {
                            '$set': {
                                'payment_status': 'failed',
                                'status': VerificationStatus.PAYMENT_PENDING,
                                'payment_error_message': result_desc,
                                'updated_at': datetime.utcnow()
                            },
                            '$unset': {
                                'payment_test_mode': "",
                                'payment_test_message': ""
                            },
                        }
                    )

                    # Notify user
                    await create_notification(
                        db=db,
                        user_id=verification['user_id'],
                        notification_type=NotificationType.ORDER_UPDATED,
                        title="Verification Payment Failed ❌",
                        message=f"Your verification fee payment failed: {result_desc}. Please try again.",
                        data={'verification_id': str(verification['_id'])}
                    )

                    return {'ResultCode': 0, 'ResultDesc': 'Verification payment failure processed'}

            # Check for job posting payment
            job_posting = await db.job_postings.find_one({
                'mpesa_checkout_request_id': checkout_request_id
            })

            if job_posting:
                # Handle job posting payment callback
                logger.info(f"Processing M-Pesa callback for job posting {job_posting['id']}")

                result_code = stk_callback.get('ResultCode')

                if job_posting.get('payment_status') == PaymentStatus.PAID:
                    logger.info(f"Job posting {job_posting['id']} already paid. Ignoring duplicate callback.")
                    return {'ResultCode': 0, 'ResultDesc': 'Already processed'}

                # Payment successful
                if result_code == 0:
                    logger.info(f"✅ Job posting payment successful for posting {job_posting['id']}")

                    # Extract callback metadata
                    callback_metadata = stk_callback.get('CallbackMetadata', {})
                    items = callback_metadata.get('Item', [])

                    mpesa_receipt_number = None
                    amount_paid = None
                    for item in items:
                        if item.get('Name') == 'MpesaReceiptNumber':
                            mpesa_receipt_number = item.get('Value')
                        elif item.get('Name') == 'Amount':
                            amount_paid = item.get('Value')

                    posting_fee = job_posting.get('posting_fee', DEFAULT_JOB_POSTING_FEE)
                    company_id = job_posting['company_id']

                    if not _amount_matches(amount_paid, posting_fee):
                        await db.job_postings.update_one(
                            {'id': job_posting['id']},
                            {
                                '$set': {
                                    'payment_error_message': f"Amount mismatch: paid {amount_paid}, expected {posting_fee}",
                                    'updated_at': datetime.utcnow()
                                }
                            }
                        )
                        await log_security_event(
                            event_type='payment_amount_mismatch',
                            severity='high',
                            details={'job_posting_id': job_posting['id'], 'expected': posting_fee, 'paid': amount_paid, 'type': 'job_posting'},
                            user_id=company_id,
                            request=request
                        )
                        return {'ResultCode': 0, 'ResultDesc': 'Amount mismatch'}

                    # Add to platform wallet
                    await db.wallets.update_one(
                        {'user_id': PLATFORM_WALLET_ID},
                        {'$inc': {'balance': posting_fee}}
                    )

                    # Create platform earning transaction
                    await create_transaction(
                        user_id=PLATFORM_WALLET_ID,
                        amount=posting_fee,
                        transaction_type=TransactionType.PLATFORM_FEE_JOB_POSTING,
                        status=TransactionStatus.COMPLETED,
                        description=f'Job posting fee from company {company_id} via M-Pesa (Job: {job_posting["job_title"][:30]})',
                        order_id=job_posting['id']
                    )

                    # Create transaction for company (debit)
                    await create_transaction(
                        user_id=company_id,
                        amount=-posting_fee,
                        transaction_type=TransactionType.ORDER_PAYMENT,
                        status=TransactionStatus.COMPLETED,
                        description=f"Job posting fee for '{job_posting['job_title']}'",
                        order_id=job_posting['id']
                    )

                    # Update job posting status to active
                    await db.job_postings.update_one(
                        {'id': job_posting['id']},
                        {
                            '$set': {
                                'payment_status': PaymentStatus.PAID,
                                'status': JobStatus.ACTIVE,
                                'posted_at': datetime.utcnow(),
                                'expires_at': datetime.utcnow() + timedelta(days=30),  # 30 days active
                                'mpesa_receipt_number': mpesa_receipt_number,
                                'updated_at': datetime.utcnow()
                            }
                        }
                    )

                    # Send notification to company
                    await create_notification(
                        db=db,
                        user_id=company_id,
                        notification_type=NotificationType.PAYMENT_RECEIVED,
                        title="Job Posting Payment Successful! 🎉",
                        message=f"Your job posting '{job_posting['job_title']}' is now active and will be visible to job seekers for 30 days.",
                        data={'job_posting_id': job_posting['id']}
                    )

                    logger.info(f"✅ Job posting payment processed for posting {job_posting['id']}")
                    return {'ResultCode': 0, 'ResultDesc': 'Job posting payment processed successfully'}

                # Payment failed or cancelled
                else:
                    result_desc = stk_callback.get('ResultDesc', 'Payment failed or cancelled')

                    # Check if user cancelled the payment (result code 1032)
                    # In testing mode, treat cancellations as successful payments
                    if result_code == 1032 or 'cancelled' in result_desc.lower() or 'canceled' in result_desc.lower():
                        logger.info(f"🔧 TESTING MODE: User cancelled job posting payment - processing as successful for testing")

                        test_message = f"⚠️ TESTING MODE: Payment cancelled by user but processed for testing purposes. Result: {result_desc}"
                        posting_fee = job_posting.get('posting_fee', DEFAULT_JOB_POSTING_FEE)
                        company_id = job_posting['company_id']

                        # Add to platform wallet (TEST MODE)
                        await db.wallets.update_one(
                            {'user_id': PLATFORM_WALLET_ID},
                            {'$inc': {'balance': posting_fee}}
                        )

                        # Create platform earning transaction
                        await create_transaction(
                            user_id=PLATFORM_WALLET_ID,
                            amount=posting_fee,
                            transaction_type=TransactionType.PLATFORM_FEE_JOB_POSTING,
                            status=TransactionStatus.COMPLETED,
                            description=f'Job posting fee from company {company_id} via M-Pesa TEST MODE (Job: {job_posting["job_title"][:30]})',
                            order_id=job_posting['id']
                        )

                        # Create transaction for company (debit)
                        await create_transaction(
                            user_id=company_id,
                            amount=-posting_fee,
                            transaction_type=TransactionType.ORDER_PAYMENT,
                            status=TransactionStatus.COMPLETED,
                            description=f"Job posting fee for '{job_posting['job_title']}' (TEST MODE - payment cancelled but credited)",
                            order_id=job_posting['id']
                        )

                        # Update job posting status to active
                        await db.job_postings.update_one(
                            {'id': job_posting['id']},
                            {
                                '$set': {
                                    'payment_status': PaymentStatus.PAID,
                                    'status': JobStatus.ACTIVE,
                                    'posted_at': datetime.utcnow(),
                                    'expires_at': datetime.utcnow() + timedelta(days=30),  # 30 days active
                                    'mpesa_receipt_number': 'TEST_CANCELLED',
                                    'payment_test_mode': True,
                                    'payment_test_message': test_message,
                                    'updated_at': datetime.utcnow()
                                }
                            }
                        )

                        # Send notification to company
                        await create_notification(
                            db=db,
                            user_id=company_id,
                            notification_type=NotificationType.PAYMENT_RECEIVED,
                            title="Job Posting Payment Successful! 🎉 [TEST MODE]",
                            message=f"Your job posting '{job_posting['job_title']}' is now active and will be visible to job seekers for 30 days. (TEST MODE - Payment was cancelled but processed for testing)",
                            data={'job_posting_id': job_posting['id']}
                        )

                        logger.info(f"✅ TESTING MODE: Cancelled job posting payment processed as successful for posting {job_posting['id']}")
                        return {'ResultCode': 0, 'ResultDesc': 'Testing mode: Cancelled payment processed'}

                    # Real failure - not user cancelled
                    logger.warning(f"❌ Job posting payment failed: {result_desc}")

                    # Update job posting with failure reason
                    await db.job_postings.update_one(
                        {'id': job_posting['id']},
                        {
                            '$set': {
                                'payment_error_message': result_desc,
                                'status': JobStatus.DRAFT,
                                'updated_at': datetime.utcnow()
                            }
                        }
                    )

                    # Notify company
                    await create_notification(
                        db=db,
                        user_id=job_posting['company_id'],
                        notification_type=NotificationType.ORDER_UPDATED,
                        title="Job Posting Payment Failed ❌",
                        message=f"Your job posting fee payment failed: {result_desc}. Please try again.",
                        data={'job_posting_id': job_posting['id']}
                    )

                    return {'ResultCode': 0, 'ResultDesc': 'Job posting payment failure processed'}

            # Check for seller subscription payment
            subscription_payment = await db.subscription_payments.find_one({
                'mpesa_checkout_request_id': checkout_request_id
            })

            if subscription_payment:
                logger.info(f"Processing M-Pesa callback for subscription payment {subscription_payment['id']}")
                result_code = stk_callback.get('ResultCode')
                result_desc = stk_callback.get('ResultDesc', 'Payment failed or cancelled')

                if subscription_payment.get('payment_status') == PaymentStatus.PAID:
                    logger.info(f"Subscription payment {subscription_payment['id']} already processed. Ignoring duplicate callback.")
                    return {'ResultCode': 0, 'ResultDesc': 'Already processed'}

                if result_code == 0:
                    callback_metadata = stk_callback.get('CallbackMetadata', {})
                    items = callback_metadata.get('Item', [])
                    mpesa_receipt_number = None
                    amount_paid = None
                    for item in items:
                        if item.get('Name') == 'MpesaReceiptNumber':
                            mpesa_receipt_number = item.get('Value')
                        elif item.get('Name') == 'Amount':
                            amount_paid = item.get('Value')

                    expected_amount = subscription_payment.get('amount', 0.0)
                    if not _amount_matches(amount_paid, expected_amount):
                        await db.subscription_payments.update_one(
                            {'id': subscription_payment['id']},
                            {
                                '$set': {
                                    'payment_status': PaymentStatus.FAILED,
                                    'payment_message': f"Amount mismatch: paid {amount_paid}, expected {expected_amount}",
                                    'updated_at': datetime.utcnow()
                                }
                            }
                        )
                        return {'ResultCode': 0, 'ResultDesc': 'Amount mismatch'}

                    seller_id = subscription_payment['seller_id']
                    tier = subscription_payment['tier']
                    amount = float(expected_amount)

                    await db.wallets.update_one(
                        {'user_id': PLATFORM_WALLET_ID},
                        {'$inc': {'balance': amount}}
                    )
                    await create_transaction(
                        user_id=PLATFORM_WALLET_ID,
                        amount=amount,
                        transaction_type=TransactionType.PLATFORM_FEE,
                        status=TransactionStatus.COMPLETED,
                        description=f"Platform fee: {tier.capitalize()} seller subscription via M-Pesa",
                        order_id=None
                    )
                    await create_transaction(
                        user_id=seller_id,
                        amount=-amount,
                        transaction_type=TransactionType.ORDER_PAYMENT,
                        status=TransactionStatus.COMPLETED,
                        description=f"{tier.capitalize()} seller subscription fee via M-Pesa",
                        order_id=None
                    )
                    await db.wallets.update_one(
                        {'user_id': PLATFORM_WALLET_ID},
                        {'$inc': {'total_earned': amount}}
                    )

                    activation = await activate_provider_subscription(seller_id, tier, amount)
                    await db.subscription_payments.update_one(
                        {'id': subscription_payment['id']},
                        {
                            '$set': {
                                'payment_status': PaymentStatus.PAID,
                                'mpesa_receipt_number': mpesa_receipt_number,
                                'payment_message': f"{tier.capitalize()} subscription activated successfully",
                                'paid_at': datetime.utcnow(),
                                'subscription_started_at': activation['started_at'],
                                'subscription_expires_at': activation['expires_at'],
                                'updated_at': datetime.utcnow()
                            }
                        }
                    )

                    await create_notification(
                        db=db,
                        user_id=seller_id,
                        notification_type=NotificationType.PAYMENT_RECEIVED,
                        title="Subscription Activated",
                        message=f"Your {tier.capitalize()} plan is now active.",
                        data={'tier': tier, 'expires_at': activation['expires_at'].isoformat()}
                    )
                    return {'ResultCode': 0, 'ResultDesc': 'Subscription payment processed successfully'}

                await db.subscription_payments.update_one(
                    {'id': subscription_payment['id']},
                    {
                        '$set': {
                            'payment_status': PaymentStatus.FAILED,
                            'payment_message': result_desc,
                            'updated_at': datetime.utcnow()
                        }
                    }
                )
                await create_notification(
                    db=db,
                    user_id=subscription_payment['seller_id'],
                    notification_type=NotificationType.ORDER_UPDATED,
                    title="Subscription Payment Failed",
                    message=f"Your subscription payment failed: {result_desc}",
                    data={'tier': subscription_payment.get('tier')}
                )
                return {'ResultCode': 0, 'ResultDesc': 'Subscription payment failure processed'}

            # Neither order, verification, job posting, nor subscription payment found
            logger.error(f"No order, verification, job posting, or subscription payment found for CheckoutRequestID: {checkout_request_id}")
            return {'ResultCode': 1, 'ResultDesc': 'Payment record not found'}

        # Check if this is a delivery fee payment
        is_delivery_fee_payment = order.get('mpesa_delivery_fee_checkout_request_id') == checkout_request_id

        order_id = str(order['_id'])
        current_status = order.get('payment_status')
        payment_method = order.get('payment_method', PaymentMethod.MPESA)

        # Idempotency check - if already processed, return success
        if is_delivery_fee_payment:
            # For delivery fee payments, check delivery_fee_status
            delivery_fee_status = order.get('delivery_fee_status')
            if delivery_fee_status == DeliveryFeeStatus.PAID_ONLINE:
                logger.info(f"Delivery fee for order {order_id} already processed. Ignoring duplicate callback.")
            return {'ResultCode': 0, 'ResultDesc': 'Already processed'}
        else:
            # For main payments, check payment_status
            if current_status in [PaymentStatus.PAID, PaymentStatus.PENDING_CASH_PAYMENT, PaymentStatus.FAILED]:
                logger.info(f"Order {order_id} already processed with status {current_status}. Ignoring duplicate callback.")
                return {'ResultCode': 0, 'ResultDesc': 'Already processed'}

        # Success (ResultCode 0)
        if result_code == 0:
            logger.info(f"Payment successful for order {order_id}, method: {payment_method}")

            # Extract callback metadata for audit trail
            callback_metadata = stk_callback.get('CallbackMetadata', {})
            items = callback_metadata.get('Item', [])

            # Parse M-Pesa transaction details
            mpesa_receipt_number = None
            amount_paid = None
            transaction_date = None
            phone_number = None

            for item in items:
                name = item.get('Name')
                value = item.get('Value')
                if name == 'MpesaReceiptNumber':
                    mpesa_receipt_number = value
                elif name == 'Amount':
                    amount_paid = value
                elif name == 'TransactionDate':
                    transaction_date = value
                elif name == 'PhoneNumber':
                    phone_number = value

            logger.info(f"M-Pesa Receipt: {mpesa_receipt_number}, Amount: {amount_paid}, Phone: {phone_number}")

            # Handle delivery fee payment
            if is_delivery_fee_payment:
                try:
                    delivery_fee = order.get('delivery_fee', 0)
                    if not _amount_matches(amount_paid, delivery_fee):
                        await db.orders.update_one(
                            {'_id': ObjectId(order_id)},
                            {
                                '$set': {
                                    'delivery_fee_payment_error': f"Amount mismatch: paid {amount_paid}, expected {delivery_fee}",
                                    'updated_at': datetime.utcnow()
                                }
                            }
                        )
                        await log_security_event(
                            event_type='payment_amount_mismatch',
                            severity='high',
                            details={'order_id': order_id, 'expected': delivery_fee, 'paid': amount_paid, 'type': 'delivery_fee'},
                            user_id=order.get('buyer_id'),
                            request=request
                        )
                        return {'ResultCode': 0, 'ResultDesc': 'Amount mismatch'}

                    # Ensure seller's wallet exists before processing
                    seller_wallet = await get_or_create_wallet(order['seller_id'])
                    logger.info(f"Processing M-Pesa delivery fee for order {order_id}: seller={order['seller_id']}, fee={delivery_fee}")

                    # Hold delivery fee in ESCROW (seller's pending_balance)
                    # M-Pesa payment received from buyer, but held in escrow until buyer confirms receipt
                    # This protects the buyer - fee is locked until confirmation
                    await db.wallets.update_one(
                        {'user_id': order['seller_id']},
                        {
                            '$inc': {'pending_balance': delivery_fee},
                            '$set': {'updated_at': datetime.utcnow()}
                        }
                    )

                    # Create PENDING transaction for seller (escrow)
                    seller_txn = await create_transaction(
                        user_id=order['seller_id'],
                        amount=delivery_fee,
                        transaction_type=TransactionType.DELIVERY_FEE_PAYMENT,
                        status=TransactionStatus.PENDING,  # PENDING - not available for withdrawal yet
                        description=f"Delivery fee for order {order_id[:8]} via M-Pesa (in escrow - awaiting buyer confirmation)",
                        order_id=order_id
                    )
                    logger.info(f"M-Pesa delivery fee held in escrow: txn_id={str(seller_txn['_id'])}")

                    # Update order delivery fee status and delivery_status to delivered
                    await db.orders.update_one(
                        {'_id': ObjectId(order_id)},
                        {
                            '$set': {
                                'delivery_fee_status': DeliveryFeeStatus.PAID_ONLINE,
                                'delivery_fee_paid_at': datetime.utcnow(),
                                'delivery_status': DeliveryStatus.DELIVERED,
                                'mpesa_delivery_fee_receipt': mpesa_receipt_number,
                                'updated_at': datetime.utcnow()
                            }
                        }
                    )

                    logger.info(f"✅ Delivery fee KSh {delivery_fee} paid via M-Pesa for order {order_id}")

                except Exception as e:
                    logger.error(f"❌ Error processing M-Pesa delivery fee callback for order {order_id}: {str(e)}", exc_info=True)
                    # Don't return error to M-Pesa, mark the order with error for manual review
                    await db.orders.update_one(
                        {'_id': ObjectId(order_id)},
                        {
                            '$set': {
                                'delivery_fee_payment_error': str(e),
                                'updated_at': datetime.utcnow()
                            }
                        }
                    )
                    return {'ResultCode': 1, 'ResultDesc': f'Error processing delivery fee: {str(e)}'}

                # Notify seller and buyer
                try:
                    # Support both service_id and pet_id
                    service_id = order.get('service_id', order.get('pet_id'))
                    is_service = 'service_id' in order

                    if is_service:
                        listing = await db.service_listings.find_one({'_id': ObjectId(service_id)})
                        item_name = listing.get('service_name', 'service') if listing else 'service'
                    else:
                        listing = await db.pet_listings.find_one({'_id': ObjectId(service_id)})
                        item_name = listing.get('breed', 'pet') if listing else 'pet'

                    buyer = await db.users.find_one({'_id': ObjectId(order['buyer_id'])})
                    buyer_name = buyer.get('name', 'Buyer') if buyer else 'Buyer'

                    # Notify seller
                    await create_notification(
                        db=db,
                        user_id=order['seller_id'],
                        notification_type=NotificationType.DELIVERY_FEE_PAID,
                        title="Service Fee Paid & Secured 💰🔒" if is_service else "Delivery Fee Paid & Secured 💰🔒",
                        message=f"{buyer_name} paid KSh {int(delivery_fee)} {'service' if is_service else 'delivery'} fee for {item_name} via M-Pesa. The fee is secured in escrow and will be released when buyer confirms receipt.",
                        data={
                            'action': 'view_order',
                            'order_id': order_id,
                            'delivery_fee': delivery_fee,
                            'service_id': service_id
                        }
                    )

                    # Notify buyer
                    await create_notification(
                        db=db,
                        user_id=order['buyer_id'],
                        notification_type=NotificationType.DELIVERY_FEE_PAID,
                        title="Service Fee Payment Successful! ✅🔒" if is_service else "Delivery Fee Payment Successful! ✅🔒",
                        message=f"You paid KSh {int(delivery_fee)} {'service' if is_service else 'delivery'} fee for {item_name} via M-Pesa. The fee is secured and will be released to provider when you confirm receipt.",
                        data={
                            'action': 'view_order',
                            'order_id': order_id,
                            'delivery_fee': delivery_fee,
                            'service_id': service_id
                        }
                    )
                except Exception as e:
                    logger.error(f"Failed to send delivery fee payment notification: {e}")

                return {'ResultCode': 0, 'ResultDesc': 'Delivery fee payment processed successfully'}

            # Handle main order payment
            if payment_method == PaymentMethod.MPESA:
                expected_amount = order.get('total_amount', order['price'])
                if not _amount_matches(amount_paid, expected_amount):
                    await db.orders.update_one(
                        {'_id': ObjectId(order_id)},
                        {
                            '$set': {
                                'payment_status': PaymentStatus.FAILED,
                                'payment_error_message': f"Amount mismatch: paid {amount_paid}, expected {expected_amount}",
                                'updated_at': datetime.utcnow()
                            }
                        }
                    )
                    await log_security_event(
                        event_type='payment_amount_mismatch',
                        severity='high',
                        details={'order_id': order_id, 'expected': expected_amount, 'paid': amount_paid, 'type': 'order'},
                        user_id=order.get('buyer_id'),
                        request=request
                    )
                    return {'ResultCode': 0, 'ResultDesc': 'Amount mismatch'}
                # Full M-Pesa payment - hold in pending until buyer confirms receipt
                # This protects the buyer
                await hold_payment_pending(
                    order_id=order_id,
                    total_amount=order['price'],
                    seller_id=order['seller_id']
                )

                # If there's a delivery fee, hold it in pending too
                delivery_fee = order.get('delivery_fee', 0.0)
                if delivery_fee > 0:
                    await db.wallets.update_one(
                        {'user_id': order['seller_id']},
                        {
                            '$inc': {'pending_balance': delivery_fee},
                            '$set': {'updated_at': datetime.utcnow()}
                        }
                    )

                    await create_transaction(
                        user_id=order['seller_id'],
                        amount=delivery_fee,
                        transaction_type=TransactionType.DELIVERY_FEE_PAYMENT,
                        status=TransactionStatus.PENDING,
                        description=f"Pending delivery fee for order {order_id} (awaiting buyer confirmation)",
                        order_id=order_id
                    )

                # Update order status to PAID with delivery_status DELIVERED (seller has received payment)
                await db.orders.update_one(
                    {'_id': ObjectId(order_id)},
                    {
                        '$set': {
                            'payment_status': PaymentStatus.PAID,
                            'delivery_status': DeliveryStatus.DELIVERED,
                            'mpesa_receipt_number': mpesa_receipt_number,
                            'mpesa_transaction_date': transaction_date,
                            'amount_paid': amount_paid,
                            'provider_visible': True,
                            'updated_at': datetime.utcnow()
                        }
                    }
                )

                # Atomically mark listing as sold (only if still active - prevents race condition)
                # Services stay active; only pets are marked sold.
                service_id = order.get('service_id', order.get('pet_id'))
                is_service = 'service_id' in order

                if not is_service:
                    listing_update = await db.pet_listings.find_one_and_update(
                        {'_id': ObjectId(service_id), 'status': ListingStatus.ACTIVE},
                        {'$set': {'status': ListingStatus.SOLD, 'updated_at': datetime.utcnow()}},
                        return_document=True
                    )

                    if not listing_update:
                        logger.warning(f"?????? Listing {service_id} was already sold/booked - refunding order {order_id}")
                        # Listing was already sold by another order - refund this payment
                        await db.orders.update_one(
                            {'_id': ObjectId(order_id)},
                            {
                                '$set': {
                                    'payment_status': PaymentStatus.REFUNDED,
                                    'payment_error_message': 'Pet was already sold to another buyer',
                                    'updated_at': datetime.utcnow()
                                }
                            }
                        )
                        # TODO: Implement actual M-Pesa refund via API
                        return {'ResultCode': 0, 'ResultDesc': 'Accepted - Refund initiated'}

                    # Cancel all other pending orders for this pet
                    await db.orders.update_many(
                        {
                            'pet_id': service_id,
                            '_id': {'$ne': ObjectId(order_id)},
                            'payment_status': {'$in': [PaymentStatus.PENDING, PaymentStatus.PENDING_CASH_PAYMENT]}
                        },
                        {
                            '$set': {
                                'payment_status': PaymentStatus.FAILED,
                                'payment_error_message': 'Pet was sold to another buyer',
                                'updated_at': datetime.utcnow()
                            }
                        }
                    )

                logger.info(f"✅ Full M-Pesa payment confirmed and funds split for order {order_id}")

                # Create calendar events after successful payment
                await _create_calendar_events_for_order(order)

                # Notify both buyer and seller about successful payment
                try:
                    # Support both service_id and pet_id
                    service_id = order.get('service_id', order.get('pet_id'))
                    is_service = 'service_id' in order

                    if is_service:
                        listing = await db.service_listings.find_one({'_id': ObjectId(service_id)})
                        item_name = listing.get('service_name', 'service') if listing else 'service'
                    else:
                        listing = await db.pet_listings.find_one({'_id': ObjectId(service_id)})
                        item_name = listing.get('breed', 'pet') if listing else 'pet'

                    # Notify buyer
                    await create_notification(
                        db=db,
                        user_id=order['buyer_id'],
                        notification_type=NotificationType.PAYMENT_RECEIVED,
                        title="Payment Successful! 🎉",
                        message=f"Your payment for {item_name} was successful. {'Awaiting service completion confirmation.' if is_service else 'Awaiting delivery confirmation.'}",
                        data={
                            'action': 'view_order',
                            'order_id': order_id,
                            'service_id': service_id
                        }
                    )

                    # Notify seller
                    await create_notification(
                        db=db,
                        user_id=order['seller_id'],
                        notification_type=NotificationType.PAYMENT_RECEIVED,
                        title="Payment Received! 💰",
                        message=f"Payment received for {item_name}. Funds will be released after {'service completion' if is_service else 'delivery'} confirmation.",
                        data={
                            'action': 'view_order',
                            'order_id': order_id,
                            'service_id': service_id
                        }
                    )

                    # If delivery was requested (legacy pet orders), notify seller to set delivery fee
                    if not is_service and order.get('delivery_option') == DeliveryOption.DELIVERY:
                        await create_notification(
                            db=db,
                            user_id=order['seller_id'],
                            notification_type=NotificationType.DELIVERY_FEE_REQUIRED,
                            title="Set Delivery Fee 📦",
                            message=f"Please set delivery fee for {item_name} order. Check buyer's address and set appropriate fee.",
                            data={
                                'action': 'view_order',
                                'order_id': order_id,
                                'service_id': service_id,
                                'delivery_address': order.get('delivery_address', 'Not provided')
                            }
                        )
                except Exception as e:
                    logger.error(f"Failed to send payment success notifications: {e}")

                # Notify provider about new booking (first time only)
                if is_service and not order.get('provider_notified'):
                    try:
                        buyer = await db.users.find_one({'_id': ObjectId(order['buyer_id'])})
                        buyer_name = buyer.get('name', 'Buyer') if buyer else 'Buyer'
                        await create_notification(
                            db=db,
                            user_id=order['seller_id'],
                            notification_type=NotificationType.ORDER_CREATED,
                            title="New Booking Request! 🎉",
                            message=f"{buyer_name} booked your {item_name}. Please confirm your availability.",
                            data={
                                'action': 'view_order',
                                'order_id': order_id,
                                'service_id': service_id
                            }
                        )
                        await db.orders.update_one(
                            {'_id': ObjectId(order_id)},
                            {'$set': {'provider_notified': True}}
                        )
                    except Exception as e:
                        logger.error(f"Failed to send provider booking notification: {e}")

            else:  # Cash payment - only platform fee was paid
                expected_amount = order.get('platform_fee')
                if not _amount_matches(amount_paid, expected_amount):
                    await db.orders.update_one(
                        {'_id': ObjectId(order_id)},
                        {
                            '$set': {
                                'payment_status': PaymentStatus.FAILED,
                                'payment_error_message': f"Amount mismatch: paid {amount_paid}, expected {expected_amount}",
                                'updated_at': datetime.utcnow()
                            }
                        }
                    )
                    await log_security_event(
                        event_type='payment_amount_mismatch',
                        severity='high',
                        details={'order_id': order_id, 'expected': expected_amount, 'paid': amount_paid, 'type': 'platform_fee'},
                        user_id=order.get('buyer_id'),
                        request=request
                    )
                    return {'ResultCode': 0, 'ResultDesc': 'Amount mismatch'}
                # Platform fee goes to platform wallet
                platform_txn = await create_transaction(
                    user_id=PLATFORM_WALLET_ID,
                    amount=order['platform_fee'],
                    transaction_type=TransactionType.PLATFORM_FEE,
                    status=TransactionStatus.COMPLETED,
                    description=f"5% platform fee for cash order {order_id}",
                    order_id=order_id
                )

                await update_wallet_balance(
                    PLATFORM_WALLET_ID,
                    order['platform_fee'],
                    str(platform_txn['_id'])
                )

                await db.wallets.update_one(
                    {'user_id': PLATFORM_WALLET_ID},
                    {'$inc': {'total_earned': order['platform_fee']}}
                )

                # Update order status to PENDING_CASH_PAYMENT with transaction details
                await db.orders.update_one(
                    {'_id': ObjectId(order_id)},
                    {
                        '$set': {
                            'payment_status': PaymentStatus.PENDING_CASH_PAYMENT,
                            'mpesa_receipt_number': mpesa_receipt_number,
                            'mpesa_transaction_date': transaction_date,
                            'amount_paid': amount_paid,
                            'provider_visible': True,
                            'updated_at': datetime.utcnow()
                        }
                    }
                )

                # Atomically mark listing as sold (only if still active - prevents race condition)
                # Services stay active; only pets are marked sold.
                service_id = order.get('service_id', order.get('pet_id'))
                is_service = 'service_id' in order

                if not is_service:
                    listing_update = await db.pet_listings.find_one_and_update(
                        {'_id': ObjectId(service_id), 'status': ListingStatus.ACTIVE},
                        {'$set': {'status': ListingStatus.SOLD, 'updated_at': datetime.utcnow()}},
                        return_document=True
                    )

                    if not listing_update:
                        logger.warning(f"?????? Listing {service_id} was already sold/booked - refunding platform fee {order_id}")
                        # Listing was already sold by another order - refund this payment
                        await db.orders.update_one(
                            {'_id': ObjectId(order_id)},
                            {
                                '$set': {
                                    'payment_status': PaymentStatus.REFUNDED,
                                    'payment_error_message': 'Pet was already sold to another buyer',
                                    'updated_at': datetime.utcnow()
                                }
                            }
                        )
                        # TODO: Implement actual M-Pesa refund via API
                        return {'ResultCode': 0, 'ResultDesc': 'Accepted - Refund initiated'}

                    # Cancel all other pending orders for this pet
                    await db.orders.update_many(
                        {
                            'pet_id': service_id,
                            '_id': {'$ne': ObjectId(order_id)},
                            'payment_status': {'$in': [PaymentStatus.PENDING, PaymentStatus.PENDING_CASH_PAYMENT]}
                        },
                        {
                            '$set': {
                                'payment_status': PaymentStatus.FAILED,
                                'payment_error_message': 'Pet was sold to another buyer',
                                'updated_at': datetime.utcnow()
                            }
                        }
                    )

                logger.info(f"✅ Platform fee paid for cash {'booking' if is_service else 'order'} {order_id}, awaiting cash payment {'after service' if is_service else 'at handover'}")

                # Notify provider about new booking (first time only)
                if is_service and not order.get('provider_notified'):
                    try:
                        buyer = await db.users.find_one({'_id': ObjectId(order['buyer_id'])})
                        buyer_name = buyer.get('name', 'Buyer') if buyer else 'Buyer'
                        await create_notification(
                            db=db,
                            user_id=order['seller_id'],
                            notification_type=NotificationType.ORDER_CREATED,
                            title="New Booking Request! 🎉",
                            message=f"{buyer_name} booked your {item_name}. Please confirm your availability.",
                            data={
                                'action': 'view_order',
                                'order_id': order_id,
                                'service_id': service_id
                            }
                        )
                        await db.orders.update_one(
                            {'_id': ObjectId(order_id)},
                            {'$set': {'provider_notified': True}}
                        )
                    except Exception as e:
                        logger.error(f"Failed to send provider booking notification: {e}")

                # Create calendar events after successful platform fee payment
                await _create_calendar_events_for_order(order)

                # Notify buyer about platform fee payment success
                try:
                    if is_service:
                        listing = await db.service_listings.find_one({'_id': ObjectId(service_id)})
                        item_name = listing.get('service_name', 'service') if listing else 'service'
                    else:
                        listing = await db.pet_listings.find_one({'_id': ObjectId(service_id)})
                        item_name = listing.get('breed', 'pet') if listing else 'pet'

                    cash_amount = order['seller_amount']

                    # Notify buyer
                    await create_notification(
                        db=db,
                        user_id=order['buyer_id'],
                        notification_type=NotificationType.ORDER_CONFIRMED,
                        title="Platform Fee Paid ✅",
                        message=f"Platform fee paid for {item_name}. Pay KES {cash_amount:.2f} in cash to {'provider after service completion' if is_service else 'seller at handover'}.",
                        data={
                            'action': 'view_order',
                            'order_id': order_id,
                            'service_id': service_id
                        }
                    )

                    # Notify seller
                    await create_notification(
                        db=db,
                        user_id=order['seller_id'],
                        notification_type=NotificationType.ORDER_CONFIRMED,
                        title="Booking Confirmed! 🎉" if is_service else "Order Confirmed! 🎉",
                        message=f"Platform fee paid for {item_name}. {'Customer' if is_service else 'Buyer'} will pay KES {cash_amount:.2f} in cash {'after service completion' if is_service else 'at handover'}.",
                        data={
                            'action': 'view_order',
                            'order_id': order_id,
                            'service_id': service_id
                        }
                    )

                    # If delivery was requested (legacy pet orders only), notify seller to set delivery fee
                    if not is_service and order.get('delivery_option') == DeliveryOption.DELIVERY:
                        await create_notification(
                            db=db,
                            user_id=order['seller_id'],
                            notification_type=NotificationType.DELIVERY_FEE_REQUIRED,
                            title="Set Delivery Fee 📦",
                            message=f"Please set delivery fee for {item_name} order. Check buyer's address and set appropriate fee.",
                            data={
                                'action': 'view_order',
                                'order_id': order_id,
                                'service_id': service_id,
                                'delivery_address': order.get('delivery_address', 'Not provided')
                            }
                        )
                except Exception as e:
                    logger.error(f"Failed to send cash order notifications: {e}")

        # Failed or cancelled (ResultCode != 0)
        else:
            result_desc = stk_callback.get('ResultDesc', 'Payment failed or cancelled')

            # TESTING MODE: Treat user-cancelled transactions as successful
            # ResultCode 1032 = Request cancelled by user
            if result_code == 1032:
                logger.warning(f"⚠️ TESTING MODE: User cancelled transaction for order {order_id}, but crediting account anyway")

                # Process as successful payment with test message
                test_message = "User cancelled the transaction however the amount was credited for testing purpose only"

                # Handle delivery fee payment cancellation in test mode
                if is_delivery_fee_payment:
                    try:
                        delivery_fee = order.get('delivery_fee', 0)

                        # Ensure seller's wallet exists before processing
                        seller_wallet = await get_or_create_wallet(order['seller_id'])
                        logger.info(f"TESTING MODE: Processing cancelled delivery fee for order {order_id}: seller={order['seller_id']}, fee={delivery_fee}")

                        # Hold delivery fee in ESCROW (seller's pending_balance)
                        # Simulating M-Pesa payment received from buyer, held in escrow until buyer confirms receipt
                        await db.wallets.update_one(
                            {'user_id': order['seller_id']},
                            {
                                '$inc': {'pending_balance': delivery_fee},
                                '$set': {'updated_at': datetime.utcnow()}
                            }
                        )

                        # Create PENDING transaction for seller (escrow)
                        seller_txn = await create_transaction(
                            user_id=order['seller_id'],
                            amount=delivery_fee,
                            transaction_type=TransactionType.DELIVERY_FEE_PAYMENT,
                            status=TransactionStatus.PENDING,  # PENDING - not available for withdrawal yet
                            description=f"Delivery fee for order {order_id[:8]} - TEST CANCELLED (in escrow - awaiting buyer confirmation)",
                            order_id=order_id
                        )
                        logger.info(f"TEST MODE: Delivery fee held in escrow: txn_id={str(seller_txn['_id'])}")

                        # Update order delivery fee status and delivery_status to delivered
                        await db.orders.update_one(
                            {'_id': ObjectId(order_id)},
                            {
                                '$set': {
                                    'delivery_fee_status': DeliveryFeeStatus.PAID_ONLINE,
                                    'delivery_fee_paid_at': datetime.utcnow(),
                                    'delivery_status': DeliveryStatus.DELIVERED,
                                    'mpesa_delivery_fee_receipt': 'TEST_CANCELLED',
                                    'payment_test_mode': True,
                                    'payment_test_message': test_message,
                                    'updated_at': datetime.utcnow()
                                }
                            }
                        )

                        logger.info(f"✅ TESTING MODE: Cancelled delivery fee KSh {delivery_fee} processed as PAID for order {order_id}")

                        # Notify seller and buyer
                        try:
                            pet_listing = await db.pet_listings.find_one({'_id': ObjectId(order['pet_id'])})
                            pet_name = pet_listing.get('breed', 'pet') if pet_listing else 'pet'
                            buyer = await db.users.find_one({'_id': ObjectId(order['buyer_id'])})
                            buyer_name = buyer.get('name', 'Buyer') if buyer else 'Buyer'

                            # Notify seller
                            await create_notification(
                                db=db,
                                user_id=order['seller_id'],
                                notification_type=NotificationType.DELIVERY_FEE_PAID,
                                title="Delivery Fee Paid & Secured 💰🔒 [TEST MODE]",
                                message=f"{buyer_name} paid KSh {int(delivery_fee)} delivery fee for {pet_name}. The fee is secured in escrow and will be released when buyer confirms receipt. (TEST MODE - Payment was cancelled but processed)",
                                data={
                                    'action': 'view_order',
                                    'order_id': order_id,
                                    'delivery_fee': delivery_fee,
                                    'pet_id': order['pet_id']
                                }
                            )

                            # Notify buyer
                            await create_notification(
                                db=db,
                                user_id=order['buyer_id'],
                                notification_type=NotificationType.DELIVERY_FEE_PAID,
                                title="Delivery Fee Payment Successful! ✅🔒 [TEST MODE]",
                                message=f"You paid KSh {int(delivery_fee)} delivery fee for {pet_name}. The fee is secured and will be released to seller when you confirm receipt. (TEST MODE - Payment was cancelled but processed)",
                                data={
                                    'action': 'view_order',
                                    'order_id': order_id,
                                    'delivery_fee': delivery_fee,
                                    'pet_id': order['pet_id']
                                }
                            )
                        except Exception as e:
                            logger.error(f"Failed to send delivery fee payment notification: {e}")

                    except Exception as e:
                        logger.error(f"❌ TESTING MODE: Error processing cancelled delivery fee for order {order_id}: {str(e)}", exc_info=True)

                elif payment_method == PaymentMethod.MPESA:
                    # Full M-Pesa payment - hold in pending until buyer confirms receipt
                    # This protects the buyer even in testing mode
                    await hold_payment_pending(
                        order_id=order_id,
                        total_amount=order['price'],
                        seller_id=order['seller_id']
                    )

                    # If there's a delivery fee, hold it in pending too
                    delivery_fee = order.get('delivery_fee', 0.0)
                    if delivery_fee > 0:
                        await db.wallets.update_one(
                            {'user_id': order['seller_id']},
                            {
                                '$inc': {'pending_balance': delivery_fee},
                                '$set': {'updated_at': datetime.utcnow()}
                            }
                        )

                        await create_transaction(
                            user_id=order['seller_id'],
                            amount=delivery_fee,
                            transaction_type=TransactionType.DELIVERY_FEE_PAYMENT,
                            status=TransactionStatus.PENDING,
                            description=f"Pending delivery fee for order {order_id} (awaiting buyer confirmation)",
                            order_id=order_id
                        )

                    # Update order status to PAID with test message and delivery_status DELIVERED (seller received payment)
                    await db.orders.update_one(
                        {'_id': ObjectId(order_id)},
                        {
                            '$set': {
                                'payment_status': PaymentStatus.PAID,
                                'delivery_status': DeliveryStatus.DELIVERED,
                                'mpesa_receipt_number': 'TEST_CANCELLED',
                                'mpesa_transaction_date': datetime.utcnow().strftime('%Y%m%d%H%M%S'),
                                'amount_paid': order['price'],
                                'payment_test_mode': True,
                                'payment_test_message': test_message,
                                'updated_at': datetime.utcnow()
                            }
                        }
                    )

                    # Atomically mark listing as sold
                    listing_update = await db.pet_listings.find_one_and_update(
                        {'_id': ObjectId(order['pet_id']), 'status': ListingStatus.ACTIVE},
                        {'$set': {'status': ListingStatus.SOLD, 'updated_at': datetime.utcnow()}},
                        return_document=True
                    )

                    if not listing_update:
                        logger.warning(f"⚠️ Listing {order['pet_id']} was already sold")

                    # Cancel other pending orders for this pet
                    await db.orders.update_many(
                        {
                            'pet_id': order['pet_id'],
                            '_id': {'$ne': ObjectId(order_id)},
                            'payment_status': {'$in': [PaymentStatus.PENDING, PaymentStatus.PENDING_CASH_PAYMENT]}
                        },
                        {
                            '$set': {
                                'payment_status': PaymentStatus.FAILED,
                                'payment_error_message': 'Pet was sold to another buyer',
                                'updated_at': datetime.utcnow()
                            }
                        }
                    )

                    logger.info(f"✅ TESTING MODE: Cancelled transaction processed as PAID for order {order_id}")

                else:  # Cash payment - only platform fee
                    # Platform fee goes to platform wallet
                    platform_txn = await create_transaction(
                        user_id=PLATFORM_WALLET_ID,
                        amount=order['platform_fee'],
                        transaction_type=TransactionType.PLATFORM_FEE,
                        status=TransactionStatus.COMPLETED,
                        description=f"5% platform fee for cash order {order_id} (TEST MODE)",
                        order_id=order_id
                    )

                    await update_wallet_balance(
                        PLATFORM_WALLET_ID,
                        order['platform_fee'],
                        str(platform_txn['_id'])
                    )

                    await db.wallets.update_one(
                        {'user_id': PLATFORM_WALLET_ID},
                        {'$inc': {'total_earned': order['platform_fee']}}
                    )

                    # Update order status to PENDING_CASH_PAYMENT with test message
                    await db.orders.update_one(
                        {'_id': ObjectId(order_id)},
                        {
                            '$set': {
                                'payment_status': PaymentStatus.PENDING_CASH_PAYMENT,
                                'mpesa_receipt_number': 'TEST_CANCELLED',
                                'mpesa_transaction_date': datetime.utcnow().strftime('%Y%m%d%H%M%S'),
                                'amount_paid': order['platform_fee'],
                                'payment_test_mode': True,
                                'payment_test_message': test_message,
                                'updated_at': datetime.utcnow()
                            }
                        }
                    )

                    # Atomically mark listing as sold
                    listing_update = await db.pet_listings.find_one_and_update(
                        {'_id': ObjectId(order['pet_id']), 'status': ListingStatus.ACTIVE},
                        {'$set': {'status': ListingStatus.SOLD, 'updated_at': datetime.utcnow()}},
                        return_document=True
                    )

                    if not listing_update:
                        logger.warning(f"⚠️ Listing {order['pet_id']} was already sold")

                    # Cancel other pending orders
                    await db.orders.update_many(
                        {
                            'pet_id': order['pet_id'],
                            '_id': {'$ne': ObjectId(order_id)},
                            'payment_status': {'$in': [PaymentStatus.PENDING, PaymentStatus.PENDING_CASH_PAYMENT]}
                        },
                        {
                            '$set': {
                                'payment_status': PaymentStatus.FAILED,
                                'payment_error_message': 'Pet was sold to another buyer',
                                'updated_at': datetime.utcnow()
                            }
                        }
                    )

                    logger.info(f"✅ TESTING MODE: Cancelled cash order processed as PENDING_CASH_PAYMENT for order {order_id}")

            else:
                # Real failure - not user cancelled
                logger.warning(f"❌ Payment failed for order {order_id}: ResultCode={result_code}, {result_desc}")

                await _delete_failed_order(
                    order_id,
                    f"mpesa_callback_failed:{result_code}",
                    request
                )
                # Notify buyer about payment failure
                try:
                    item_label = 'service'
                    item_data = {'order_id': order_id}
                    if order.get('service_id'):
                        service_listing = await db.service_listings.find_one({'_id': ObjectId(order['service_id'])})
                        item_label = service_listing.get('service_name', 'service') if service_listing else 'service'
                        item_data['service_id'] = order['service_id']
                    else:
                        pet_listing = await db.pet_listings.find_one({'_id': ObjectId(order['pet_id'])})
                        item_label = pet_listing.get('breed', 'pet') if pet_listing else 'pet'
                        item_data['pet_id'] = order.get('pet_id')

                    await create_notification(
                        db=db,
                        user_id=order['buyer_id'],
                        notification_type=NotificationType.PAYMENT_FAILED,
                        title="Payment Failed ❌",
                        message=f"Payment for {item_label} failed: {result_desc}. Please try again.",
                        data={
                            'action': 'view_order',
                            **item_data,
                            'error_message': result_desc
                        }
                    )
                except Exception as e:
                    logger.error(f"Failed to send payment failure notification: {e}")

        return {'ResultCode': 0, 'ResultDesc': 'Accepted'}

    except Exception as e:
        logger.error(f"❌ Error processing M-Pesa callback: {str(e)}", exc_info=True)
        return {'ResultCode': 1, 'ResultDesc': 'Internal server error'}
    finally:
        if checkout_request_id and processing_status:
            existing = await db.mpesa_callbacks.find_one({'checkout_request_id': checkout_request_id})
            if existing and existing.get('status') == 'pending':
                await _mark_mpesa_callback_processed(checkout_request_id, processing_status, processing_details)

# Review Routes
@api_router.post("/reviews", response_model=Review)
async def create_review(review_data: ReviewCreate, current_user: dict = Depends(get_current_user)):
    """Create a review for a seller after completing an order"""
    try:
        buyer_id = str(current_user['_id'])

        # Get the order
        order = await db.orders.find_one({'_id': ObjectId(review_data.order_id)})
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        # Verify buyer owns this order
        if order['buyer_id'] != buyer_id:
            raise HTTPException(status_code=403, detail="You can only review your own orders")

        # Verify order is paid
        if order['payment_status'] != PaymentStatus.PAID:
            raise HTTPException(
                status_code=400,
                detail="You can only review orders that have been paid"
            )

        # Check if review already exists for this order
        existing_review = await db.reviews.find_one({'order_id': review_data.order_id})
        if existing_review:
            raise HTTPException(
                status_code=400,
                detail="You have already reviewed this order"
            )

        # Create review - support both service bookings and legacy pet orders
        review_dict = {
            'seller_id': order['seller_id'],
            'buyer_id': buyer_id,
            'buyer_name': current_user['name'],
            'order_id': review_data.order_id,
            'rating': review_data.rating,
            'comment': review_data.comment,
            'created_at': datetime.utcnow()
        }

        # Add service_id or pet_id based on what the order has
        if order.get('service_id'):
            review_dict['service_id'] = order['service_id']
        elif order.get('pet_id'):
            review_dict['pet_id'] = order['pet_id']

        result = await db.reviews.insert_one(review_dict)
        review_id = str(result.inserted_id)

        # Update seller's average rating
        await update_seller_rating(order['seller_id'])

        logger.info(f"Review created for seller {order['seller_id']} by buyer {buyer_id}")

        # Notify seller about new review
        try:
            # Get the item name (service or pet)
            item_name = 'your service'
            if order.get('service_id'):
                service_listing = await db.service_listings.find_one({'_id': ObjectId(order['service_id'])})
                item_name = service_listing.get('service_name', 'service') if service_listing else 'service'
            elif order.get('pet_id'):
                pet_listing = await db.pet_listings.find_one({'_id': ObjectId(order['pet_id'])})
                item_name = pet_listing.get('breed', 'pet') if pet_listing else 'pet'

            # Star emoji based on rating
            stars = '⭐' * review_data.rating

            await create_notification(
                db=db,
                user_id=order['seller_id'],
                notification_type=NotificationType.REVIEW_RECEIVED,
                title=f"New {review_data.rating}-Star Review! {stars}",
                message=f"{current_user['name']} reviewed {item_name}: {review_data.comment[:50]}{'...' if len(review_data.comment) > 50 else ''}",
                data={
                    'action': 'view_seller',
                    'seller_id': order['seller_id'],
                    'order_id': review_data.order_id,
                    'service_id': order.get('service_id'),
                    'pet_id': order.get('pet_id')
                }
            )
        except Exception as e:
            logger.error(f"Failed to send review notification: {e}")

        # Return complete review data
        item_id = review_dict.get('service_id') or review_dict.get('pet_id')
        return {
            'id': review_id,
            'seller_id': review_dict['seller_id'],
            'buyer_id': review_dict['buyer_id'],
            'buyer_name': review_dict['buyer_name'],
            'order_id': review_dict['order_id'],
            'service_id': item_id,
            'rating': review_dict['rating'],
            'comment': review_dict['comment'],
            'created_at': review_dict['created_at'],
            'verified_purchase': True
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating review: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create review")

@api_router.get("/sellers/{seller_id}/reviews", response_model=SellerRatingResponse)
async def get_seller_reviews(
    seller_id: str,
    skip: int = 0,
    limit: int = 10,
    sort_by: str = 'date'  # 'date', 'rating_high', 'rating_low'
):
    """Get all reviews for a seller with average rating and statistics"""
    try:
        # Only show reviews that are not removed
        base_query = {'seller_id': seller_id, 'is_removed': {'$ne': True}}

        # Determine sort order
        sort_field = 'created_at'
        sort_direction = -1  # Descending
        if sort_by == 'rating_high':
            sort_field = 'rating'
            sort_direction = -1
        elif sort_by == 'rating_low':
            sort_field = 'rating'
            sort_direction = 1

        # Get paginated reviews
        reviews = await db.reviews.find(base_query).sort(
            sort_field, sort_direction
        ).skip(skip).limit(limit).to_list(limit)

        # Get total count and statistics (only non-removed reviews)
        all_reviews = await db.reviews.find(base_query).to_list(None)
        total_reviews = len(all_reviews)

        if total_reviews > 0:
            average_rating = sum(r['rating'] for r in all_reviews) / total_reviews
            # Calculate rating distribution
            rating_distribution = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
            for r in all_reviews:
                rating_distribution[r['rating']] = rating_distribution.get(r['rating'], 0) + 1
        else:
            average_rating = 0.0
            rating_distribution = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}

        # Format reviews
        formatted_reviews = []
        for review in reviews:
            # Support both service_id and pet_id for backward compatibility
            item_id = review.get('service_id') or review.get('pet_id')

            review_data = {
                'id': str(review['_id']),
                'seller_id': review['seller_id'],
                'buyer_id': review['buyer_id'],
                'buyer_name': review['buyer_name'],
                'order_id': review['order_id'],
                'service_id': item_id,  # Unified field name
                'rating': review['rating'],
                'comment': review['comment'],
                'created_at': review['created_at'],
                'verified_purchase': True  # All reviews come from actual orders
            }
            # Add seller response if exists
            if 'seller_response' in review and review['seller_response']:
                review_data['seller_response'] = review['seller_response']
                review_data['seller_response_date'] = review.get('seller_response_date')
            formatted_reviews.append(review_data)

        return {
            'seller_id': seller_id,
            'average_rating': round(average_rating, 1),
            'total_reviews': total_reviews,
            'reviews': formatted_reviews,
            'rating_distribution': rating_distribution
        }

    except Exception as e:
        logger.error(f"Error fetching seller reviews: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch reviews")

@api_router.get("/orders/{order_id}/can-review")
async def can_review_order(order_id: str, current_user: dict = Depends(get_current_user)):
    """Check if an order can be reviewed"""
    try:
        buyer_id = str(current_user['_id'])

        # Get the order
        order = await db.orders.find_one({'_id': ObjectId(order_id)})
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        # Check if buyer owns the order
        if order['buyer_id'] != buyer_id:
            return {
                'can_review': False,
                'reason': 'Not your order'
            }

        # Check if order is paid
        if order['payment_status'] != PaymentStatus.PAID:
            return {
                'can_review': False,
                'reason': 'Order not paid yet'
            }

        # Check if already reviewed
        existing_review = await db.reviews.find_one({'order_id': order_id})
        if existing_review:
            return {
                'can_review': False,
                'reason': 'Already reviewed',
                'review_id': str(existing_review['_id'])
            }

        return {
            'can_review': True,
            'seller_id': order['seller_id']
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking review eligibility: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to check review status")

@api_router.patch("/reviews/{review_id}", response_model=Review)
async def update_review(review_id: str, review_data: ReviewUpdate, current_user: dict = Depends(get_current_user)):
    """Update an existing review"""
    try:
        buyer_id = str(current_user['_id'])

        # Get the review
        review = await db.reviews.find_one({'_id': ObjectId(review_id)})
        if not review:
            raise HTTPException(status_code=404, detail="Review not found")

        # Verify buyer owns this review
        if review['buyer_id'] != buyer_id:
            raise HTTPException(status_code=403, detail="You can only edit your own reviews")

        # Update review
        updated_review = {
            'rating': review_data.rating,
            'comment': review_data.comment,
            'updated_at': datetime.utcnow()
        }

        await db.reviews.update_one(
            {'_id': ObjectId(review_id)},
            {'$set': updated_review}
        )

        # Update seller's average rating
        await update_seller_rating(review['seller_id'])

        logger.info(f"Review {review_id} updated by buyer {buyer_id}")

        # Get updated review
        updated_review_doc = await db.reviews.find_one({'_id': ObjectId(review_id)})

        # Support both service_id and pet_id for backward compatibility
        item_id = updated_review_doc.get('service_id') or updated_review_doc.get('pet_id')

        return {
            'id': str(updated_review_doc['_id']),
            'seller_id': updated_review_doc['seller_id'],
            'buyer_id': updated_review_doc['buyer_id'],
            'buyer_name': updated_review_doc['buyer_name'],
            'order_id': updated_review_doc['order_id'],
            'service_id': item_id,
            'rating': updated_review_doc['rating'],
            'comment': updated_review_doc['comment'],
            'created_at': updated_review_doc['created_at'],
            'seller_response': updated_review_doc.get('seller_response'),
            'seller_response_date': updated_review_doc.get('seller_response_date'),
            'verified_purchase': True
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating review: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update review")

@api_router.delete("/reviews/{review_id}")
async def delete_review(review_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a review"""
    try:
        buyer_id = str(current_user['_id'])

        # Get the review
        review = await db.reviews.find_one({'_id': ObjectId(review_id)})
        if not review:
            raise HTTPException(status_code=404, detail="Review not found")

        # Verify buyer owns this review
        if review['buyer_id'] != buyer_id:
            raise HTTPException(status_code=403, detail="You can only delete your own reviews")

        seller_id = review['seller_id']

        # Delete review
        await db.reviews.delete_one({'_id': ObjectId(review_id)})

        # Update seller's average rating
        await update_seller_rating(seller_id)

        logger.info(f"Review {review_id} deleted by buyer {buyer_id}")

        return {'message': 'Review deleted successfully'}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting review: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete review")

@api_router.post("/reviews/{review_id}/respond")
async def respond_to_review(review_id: str, response_data: SellerResponse, current_user: dict = Depends(get_current_user)):
    """Add a seller response to a review"""
    try:
        seller_id = str(current_user['_id'])

        # Verify user is a seller
        if current_user.get('role') != 'seller':
            raise HTTPException(status_code=403, detail="Only sellers can respond to reviews")

        # Get the review
        review = await db.reviews.find_one({'_id': ObjectId(review_id)})
        if not review:
            raise HTTPException(status_code=404, detail="Review not found")

        # Don't allow responding to removed reviews
        if review.get('is_removed'):
            raise HTTPException(status_code=400, detail="Cannot respond to a removed review")

        # Verify seller owns this review (review is for their products)
        if review['seller_id'] != seller_id:
            raise HTTPException(status_code=403, detail="You can only respond to reviews for your products")

        # Check if already responded (more strict check)
        if review.get('seller_response') and review.get('seller_response').strip():
            raise HTTPException(status_code=400, detail="You have already responded to this review")

        # Add seller response
        await db.reviews.update_one(
            {'_id': ObjectId(review_id)},
            {
                '$set': {
                    'seller_response': response_data.response,
                    'seller_response_date': datetime.utcnow()
                }
            }
        )

        logger.info(f"Seller {seller_id} responded to review {review_id}")

        # Notify buyer about seller response
        try:
            await create_notification(
                db=db,
                user_id=review['buyer_id'],
                notification_type=NotificationType.ORDER_UPDATED,
                title="Seller Responded to Your Review",
                message=f"The seller has responded to your review: {response_data.response[:50]}{'...' if len(response_data.response) > 50 else ''}",
                data={
                    'action': 'view_review',
                    'review_id': review_id,
                    'seller_id': seller_id
                }
            )
        except Exception as e:
            logger.error(f"Failed to send seller response notification: {e}")

        # Get updated review
        updated_review = await db.reviews.find_one({'_id': ObjectId(review_id)})

        # Support both service_id and pet_id for backward compatibility
        item_id = updated_review.get('service_id') or updated_review.get('pet_id')

        return {
            'id': str(updated_review['_id']),
            'seller_id': updated_review['seller_id'],
            'buyer_id': updated_review['buyer_id'],
            'buyer_name': updated_review['buyer_name'],
            'order_id': updated_review['order_id'],
            'service_id': item_id,
            'rating': updated_review['rating'],
            'comment': updated_review['comment'],
            'created_at': updated_review['created_at'],
            'seller_response': updated_review['seller_response'],
            'seller_response_date': updated_review['seller_response_date'],
            'verified_purchase': True
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error responding to review: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to respond to review")

async def update_seller_rating(seller_id: str):
    """Update seller's average rating in seller_profiles collection (only counts non-removed reviews)"""
    try:
        # Only count reviews that are not removed
        reviews = await db.reviews.find(
            {'seller_id': seller_id, 'is_removed': {'$ne': True}}
        ).to_list(None)

        if reviews:
            average_rating = sum(r['rating'] for r in reviews) / len(reviews)
            total_reviews = len(reviews)
        else:
            average_rating = 0.0
            total_reviews = 0

        # Update seller profile
        await db.seller_profiles.update_one(
            {'user_id': seller_id},
            {
                '$set': {
                    'rating': round(average_rating, 1),
                    'total_reviews': total_reviews,
                    'updated_at': datetime.utcnow()
                }
            }
        )

        logger.info(f"Updated seller {seller_id} rating to {average_rating:.1f} ({total_reviews} reviews)")

    except Exception as e:
        logger.error(f"Error updating seller rating: {str(e)}")

# Order Auto-Cancellation
@api_router.post("/admin/orders/auto-cancel-unpaid")
async def auto_cancel_unpaid_orders(
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """
    Auto-cancel unpaid orders after 7 days
    This endpoint should be called by a scheduled task/cron job
    Admin-only endpoint for security
    """
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Calculate 7 days ago timestamp
        seven_days_ago = datetime.utcnow() - timedelta(days=7)

        # Find all unpaid orders older than 7 days
        unpaid_orders = await db.orders.find({
            'payment_status': {'$in': [PaymentStatus.PENDING, PaymentStatus.PENDING_CASH_PAYMENT]},
            'created_at': {'$lt': seven_days_ago}
        }).to_list(None)

        cancelled_count = 0
        reverted_listings = []

        for order in unpaid_orders:
            order_id = str(order['_id'])
            payment_status = order.get('payment_status')

            # Handle fee refund for pending_cash_payment orders
            if payment_status == PaymentStatus.PENDING_CASH_PAYMENT:
                platform_fee = order['platform_fee']
                refund_amount = platform_fee / 2  # 50% refund

                # Refund 50% to buyer's wallet
                buyer_txn = await create_transaction(
                    user_id=order['buyer_id'],
                    amount=refund_amount,
                    transaction_type=TransactionType.CANCELLATION_FEE_REFUND,
                    status=TransactionStatus.COMPLETED,
                    description=f"Auto-cancelled: 50% platform fee refund for order {order_id[:8]}",
                    order_id=order_id
                )

                await update_wallet_balance(
                    order['buyer_id'],
                    refund_amount,
                    str(buyer_txn['_id'])
                )

                # Deduct refund from platform wallet
                platform_txn = await create_transaction(
                    user_id=PLATFORM_WALLET_ID,
                    amount=-refund_amount,
                    transaction_type=TransactionType.CANCELLATION_FEE_REFUND,
                    status=TransactionStatus.COMPLETED,
                    description=f"Auto-cancelled: 50% platform fee refund for order {order_id[:8]}",
                    order_id=order_id
                )

                await update_wallet_balance(
                    PLATFORM_WALLET_ID,
                    -refund_amount,
                    str(platform_txn['_id'])
                )

            # Update order status to CANCELLED
            await db.orders.update_one(
                {'_id': order['_id']},
                {
                    '$set': {
                        'payment_status': PaymentStatus.CANCELLED,
                        'cancellation_reason': 'Auto-cancelled: Unpaid order after 7 days',
                        'cancelled_by': 'system',
                        'cancelled_at': datetime.utcnow(),
                        'updated_at': datetime.utcnow()
                    }
                }
            )

            # Revert pet listing from SOLD to ACTIVE
            pet_id = order['pet_id']
            listing = await db.pet_listings.find_one({'_id': ObjectId(pet_id)})

            if listing and listing.get('status') == ListingStatus.SOLD:
                await db.pet_listings.update_one(
                    {'_id': ObjectId(pet_id)},
                    {'$set': {'status': ListingStatus.ACTIVE, 'updated_at': datetime.utcnow()}}
                )
                reverted_listings.append(pet_id)

            cancelled_count += 1
            logger.info(f"Auto-cancelled unpaid order {order_id} (created: {order['created_at']})")

        logger.info(f"✅ Auto-cancelled {cancelled_count} unpaid orders, reverted {len(reverted_listings)} listings to ACTIVE")

        await log_admin_audit(
            action='orders.auto_cancel_unpaid',
            actor=current_user,
            target_type='order',
            target_id=None,
            payload={
                'cancelled_orders': cancelled_count,
                'reverted_listings': len(reverted_listings)
            },
            request=http_request
        )

        return {
            'success': True,
            'cancelled_orders': cancelled_count,
            'reverted_listings': len(reverted_listings),
            'message': f'Successfully auto-cancelled {cancelled_count} unpaid orders older than 7 days'
        }

    except Exception as e:
        logger.error(f"Error in auto-cancel unpaid orders: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Auto-cancellation failed: {str(e)}")

# Admin Routes
@api_router.post("/admin/listings/{listing_id}/approve")
async def approve_listing(
    listing_id: str,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        listing = await db.service_listings.find_one({'_id': ObjectId(listing_id)})
        if not listing:
            raise HTTPException(status_code=404, detail="Listing not found")

        before_state = {'status': listing.get('status')}

        await db.service_listings.update_one(
            {'_id': ObjectId(listing_id)},
            {'$set': {'status': ListingStatus.ACTIVE, 'updated_at': datetime.utcnow()}}
        )

        # Notify service provider that their listing was approved
        try:
            await create_notification(
                db=db,
                user_id=listing['seller_id'],
                notification_type=NotificationType.LISTING_APPROVED,
                title="Service Listing Approved! ✅",
                message=f"Your service listing '{listing.get('service_name', 'Service')}' has been approved and is now live!",
                data={
                    'action': 'view_service',
                    'service_id': listing_id
                },
                send_push=True
            )
        except Exception as notif_error:
            logger.error(f"Failed to send approval notification: {notif_error}")

        await log_admin_audit(
            action='listing.approve',
            actor=current_user,
            target_type='listing',
            target_id=listing_id,
            before=before_state,
            after={'status': ListingStatus.ACTIVE},
            payload={'service_name': listing.get('service_name')},
            request=http_request
        )

        return {'message': 'Listing approved'}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error approving listing: {e}")
        raise HTTPException(status_code=400, detail="Invalid listing ID")

@api_router.post("/admin/listings/{listing_id}/reject")
async def reject_listing(
    listing_id: str,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        listing = await db.service_listings.find_one({'_id': ObjectId(listing_id)})
        if not listing:
            raise HTTPException(status_code=404, detail="Listing not found")

        before_state = {'status': listing.get('status')}

        await db.service_listings.update_one(
            {'_id': ObjectId(listing_id)},
            {'$set': {'status': ListingStatus.REMOVED, 'updated_at': datetime.utcnow()}}
        )

        # Notify service provider that their listing was rejected
        try:
            await create_notification(
                db=db,
                user_id=listing['seller_id'],
                notification_type=NotificationType.LISTING_REJECTED,
                title="Service Listing Not Approved ❌",
                message=f"Your service listing '{listing.get('service_name', 'Service')}' did not meet our guidelines. Please review and resubmit.",
                data={
                    'action': 'view_service',
                    'service_id': listing_id
                },
                send_push=True
            )
        except Exception as notif_error:
            logger.error(f"Failed to send rejection notification: {notif_error}")

        await log_admin_audit(
            action='listing.reject',
            actor=current_user,
            target_type='listing',
            target_id=listing_id,
            before=before_state,
            after={'status': ListingStatus.REMOVED},
            payload={'service_name': listing.get('service_name')},
            request=http_request
        )

        return {'message': 'Listing rejected'}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error rejecting listing: {e}")
        raise HTTPException(status_code=400, detail="Invalid listing ID")

@api_router.delete("/admin/listings/{listing_id}")
async def admin_delete_listing(
    listing_id: str,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """
    Admin delete listing - marks listing as REMOVED instead of hard delete.
    This ensures listings with bookings are preserved and audit trail is maintained.
    """
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        listing = await db.service_listings.find_one({'_id': ObjectId(listing_id)})
        if not listing:
            raise HTTPException(status_code=404, detail="Listing not found")

        before_state = {'status': listing.get('status')}

        # Soft delete - set status to REMOVED instead of hard deleting
        await db.service_listings.update_one(
            {'_id': ObjectId(listing_id)},
            {'$set': {'status': ListingStatus.REMOVED, 'updated_at': datetime.utcnow()}}
        )

        # Notify service provider that their listing was removed
        try:
            await create_notification(
                db=db,
                user_id=listing['seller_id'],
                notification_type=NotificationType.LISTING_REJECTED,
                title="Service Listing Removed by Admin",
                message=f"Your service listing '{listing.get('service_name', 'Service')}' has been removed by an administrator.",
                data={
                    'action': 'view_service',
                    'service_id': listing_id
                },
                send_push=True
            )
        except Exception as notif_error:
            logger.error(f"Failed to send deletion notification: {notif_error}")

        await log_admin_audit(
            action='listing.delete',
            actor=current_user,
            target_type='listing',
            target_id=listing_id,
            before=before_state,
            after={'status': ListingStatus.REMOVED},
            payload={'service_name': listing.get('service_name')},
            request=http_request
        )

        logger.info(f"Service listing {listing_id} removed by admin {current_user['name']}")

        return {'message': 'Listing deleted successfully', 'id': listing_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting listing: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete listing")

# Admin Listings Management
@api_router.get("/admin/listings")
async def get_all_listings(
    status: Optional[str] = None,
    category: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    limit: int = 50,
    current_user: dict = Depends(require_admin)
):
    """Get all service listings with filtering and pagination (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Build query filter
        query = {}

        if status:
            query['status'] = status

        if category:
            query['service_category'] = {'$regex': category, '$options': 'i'}

        if search:
            query['$or'] = [
                {'service_name': {'$regex': search, '$options': 'i'}},
                {'service_category': {'$regex': search, '$options': 'i'}},
                {'location.city': {'$regex': search, '$options': 'i'}},
                {'description': {'$regex': search, '$options': 'i'}}
            ]

        # Calculate pagination
        skip = (page - 1) * limit

        # Get total count
        total = await db.service_listings.count_documents(query)

        # Get listings
        listings_cursor = db.service_listings.find(query).sort('created_at', -1).skip(skip).limit(limit)
        listings = await listings_cursor.to_list(length=limit)

        # Format response - enrich with provider info
        listings_list = []
        for listing in listings:
            # Fetch provider info
            seller = await db.users.find_one({'_id': ObjectId(listing['seller_id'])})

            # Get provider rating
            seller_rating = 0.0
            if seller:
                seller_reviews = await db.reviews.find({'seller_id': listing['seller_id']}).to_list(None)
                if seller_reviews:
                    seller_rating = sum(r.get('rating', 0) for r in seller_reviews) / len(seller_reviews)

            listings_list.append({
                'id': str(listing['_id']),
                'sellerId': listing['seller_id'],
                'sellerName': seller.get('name', 'Unknown') if seller else 'Unknown',
                'sellerRating': round(seller_rating, 1),
                'service_category': listing.get('service_category', 'Unknown'),
                'service_name': listing.get('service_name', 'Unknown'),
                'service_type': listing.get('service_type', 'one-time'),
                'duration_minutes': listing.get('duration_minutes', 0),
                'price': listing.get('price', 0),
                'price_unit': listing.get('price_unit', 'per_session'),
                'location': listing.get('location', {}),
                'description': listing.get('description', ''),
                'images': listing.get('photos', []),
                'certifications': listing.get('certifications', []),
                'status': listing.get('status', ListingStatus.ACTIVE),
                'qualifications': listing.get('qualifications', ''),
                'experience_years': listing.get('experience_years', 0),
                'services_included': listing.get('services_included', []),
                'service_location_type': listing.get('service_location_type', 'client_location'),
                'availability': listing.get('availability', {}),
                'createdAt': listing['created_at'].isoformat() if listing.get('created_at') else None,
                'updatedAt': listing.get('updated_at', listing['created_at']).isoformat() if listing.get('created_at') else None
            })

        return {
            'services': listings_list,
            'total': total,
            'page': page,
            'limit': limit,
            'totalPages': (total + limit - 1) // limit
        }
    except Exception as e:
        logger.error(f"Error fetching listings: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch listings")

# Admin Stats
@api_router.get("/admin/stats")
async def get_admin_stats(current_user: dict = Depends(require_admin)):
    """Get platform-wide statistics for admin dashboard"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Count total users
        total_users = await db.users.count_documents({})

        # Count users by role
        buyers_count = await db.users.count_documents({'role': UserRole.BUYER})
        sellers_count = await db.users.count_documents({'role': UserRole.SELLER})
        admins_count = await db.users.count_documents({'role': UserRole.ADMIN})

        # Count listings by status
        active_listings = await db.service_listings.count_documents({'status': ListingStatus.ACTIVE})
        pending_listings = await db.service_listings.count_documents({'status': ListingStatus.PENDING})
        total_listings = await db.service_listings.count_documents({})

        # Count orders by status
        total_orders = await db.orders.count_documents({})
        paid_orders = await db.orders.count_documents({'payment_status': PaymentStatus.PAID})
        pending_orders = await db.orders.count_documents({'payment_status': {'$in': [PaymentStatus.PENDING, PaymentStatus.PENDING_CASH_PAYMENT]}})

        # Calculate total revenue (sum of all paid orders)
        revenue_pipeline = [
            {'$match': {'payment_status': PaymentStatus.PAID}},
            {'$group': {'_id': None, 'total': {'$sum': '$total_amount'}}}
        ]
        revenue_result = await db.orders.aggregate(revenue_pipeline).to_list(1)
        total_revenue = revenue_result[0]['total'] if revenue_result else 0

        # Calculate ACTUAL platform fees earned from completed transactions
        # This is more accurate than summing from orders table
        platform_fees_pipeline = [
            {
                '$match': {
                    'user_id': PLATFORM_WALLET_ID,
                    'status': TransactionStatus.COMPLETED,
                    'transaction_type': {
                        '$in': [
                            TransactionType.PLATFORM_FEE,
                            TransactionType.PLATFORM_FEE_BOOKING,
                            TransactionType.PLATFORM_FEE_VERIFICATION,
                            TransactionType.PLATFORM_FEE_JOB_POSTING,
                            TransactionType.SELLER_CANCELLATION_PENALTY
                        ]
                    }
                }
            },
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
        ]
        fees_result = await db.transactions.aggregate(platform_fees_pipeline).to_list(1)
        platform_fees = fees_result[0]['total'] if fees_result else 0

        # Get platform wallet for accurate balance
        platform_wallet = await db.wallets.find_one({'user_id': PLATFORM_WALLET_ID})
        platform_balance = platform_wallet.get('balance', 0) if platform_wallet else 0

        # Calculate total wallet balance across all users (excluding platform wallet)
        wallets_pipeline = [
            {'$match': {'user_id': {'$ne': PLATFORM_WALLET_ID}}},
            {'$group': {'_id': None, 'total_balance': {'$sum': '$balance'}, 'total_escrow': {'$sum': '$pending_balance'}}}
        ]
        wallets_result = await db.wallets.aggregate(wallets_pipeline).to_list(1)
        total_wallet_balance = wallets_result[0]['total_balance'] if wallets_result else 0
        total_escrow = wallets_result[0]['total_escrow'] if wallets_result else 0

        # Calculate total float (what can actually be withdrawn from the system)
        total_float = total_wallet_balance + total_escrow + platform_balance

        # Get recent activity count (last 7 days)
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        new_users_week = await db.users.count_documents({'created_at': {'$gte': seven_days_ago}})
        new_orders_week = await db.orders.count_documents({'created_at': {'$gte': seven_days_ago}})
        new_listings_week = await db.service_listings.count_documents({'created_at': {'$gte': seven_days_ago}})

        # Chart data: Orders by payment status
        failed_orders = await db.orders.count_documents({'payment_status': PaymentStatus.FAILED})
        refunded_orders = await db.orders.count_documents({'payment_status': PaymentStatus.REFUNDED})

        # Chart data: Listings by service category
        category_pipeline = [
            {'$group': {'_id': '$service_category', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}},
            {'$limit': 10}
        ]
        category_result = await db.service_listings.aggregate(category_pipeline).to_list(10)
        listings_by_category = [{'category': item['_id'], 'count': item['count']} for item in category_result]

        # Chart data: Payment methods distribution
        payment_methods_pipeline = [
            {'$match': {'payment_status': PaymentStatus.PAID}},
            {'$group': {'_id': '$payment_method', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}}
        ]
        payment_methods_result = await db.orders.aggregate(payment_methods_pipeline).to_list(10)
        payment_methods = [{'method': item['_id'], 'count': item['count']} for item in payment_methods_result]

        # Chart data: Revenue trend (last 6 months)
        six_months_ago = datetime.utcnow() - timedelta(days=180)
        revenue_trend_pipeline = [
            {'$match': {'payment_status': PaymentStatus.PAID, 'created_at': {'$gte': six_months_ago}}},
            {'$group': {
                '_id': {'$dateToString': {'format': '%Y-%m', 'date': '$created_at'}},
                'revenue': {'$sum': '$platform_fee'}
            }},
            {'$sort': {'_id': 1}},
            {'$limit': 6}
        ]
        revenue_trend_result = await db.orders.aggregate(revenue_trend_pipeline).to_list(6)
        revenue_trend = [{'month': item['_id'], 'revenue': round(item['revenue'], 2)} for item in revenue_trend_result]

        return {
            'totalUsers': total_users,
            'buyers': buyers_count,
            'sellers': sellers_count,
            'admins': admins_count,
            'activeListings': active_listings,
            'pendingListings': pending_listings,
            'totalListings': total_listings,
            'totalOrders': total_orders,
            'paidOrders': paid_orders,
            'pendingOrders': pending_orders,
            'failedOrders': failed_orders,
            'refundedOrders': refunded_orders,
            'totalRevenue': round(total_revenue, 2),  # Total transaction volume
            'platformFees': round(platform_fees, 2),  # Actual platform earnings from completed transactions
            'platformBalance': round(platform_balance, 2),  # Current platform wallet balance
            'walletBalance': round(total_wallet_balance, 2),  # User wallets (excludes platform)
            'pendingEscrow': round(total_escrow, 2),  # Pending escrow across all wallets
            'totalFloat': round(total_float, 2),  # Total amount that can be withdrawn (users + escrow + platform)
            'recentActivity': {
                'newUsersWeek': new_users_week,
                'newOrdersWeek': new_orders_week,
                'newListingsWeek': new_listings_week
            },
            'charts': {
                'ordersByStatus': [
                    {'name': 'Paid', 'value': paid_orders},
                    {'name': 'Pending', 'value': pending_orders},
                    {'name': 'Failed', 'value': failed_orders},
                    {'name': 'Refunded', 'value': refunded_orders}
                ],
                'listingsByCategory': listings_by_category,
                'paymentMethods': payment_methods,
                'revenueTrend': revenue_trend
            }
        }
    except Exception as e:
        logger.error(f"Error fetching admin stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch statistics")

@api_router.get("/admin/platform-earnings")
async def get_platform_earnings(current_user: dict = Depends(require_admin)):
    """Get detailed platform earnings breakdown by fee category"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Get platform wallet
        platform_wallet = await db.wallets.find_one({'user_id': PLATFORM_WALLET_ID})
        if not platform_wallet:
            platform_wallet = await get_or_create_wallet(PLATFORM_WALLET_ID)

        # Get platform settings for fee percentage
        settings = await get_platform_settings()

        # Calculate earnings by category using the new specific transaction types
        earnings_by_category = {}

        # Booking fees (service platform fees)
        booking_fees_pipeline = [
            {
                '$match': {
                    'user_id': PLATFORM_WALLET_ID,
                    'transaction_type': TransactionType.PLATFORM_FEE_BOOKING,
                    'status': TransactionStatus.COMPLETED
                }
            },
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}, 'count': {'$sum': 1}}}
        ]
        booking_fees_result = await db.transactions.aggregate(booking_fees_pipeline).to_list(1)
        earnings_by_category['booking_fees'] = {
            'amount': round(booking_fees_result[0]['total'], 2) if booking_fees_result else 0.0,
            'count': booking_fees_result[0]['count'] if booking_fees_result else 0
        }

        # Verification fees
        verification_fees_pipeline = [
            {
                '$match': {
                    'user_id': PLATFORM_WALLET_ID,
                    'transaction_type': TransactionType.PLATFORM_FEE_VERIFICATION,
                    'status': TransactionStatus.COMPLETED
                }
            },
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}, 'count': {'$sum': 1}}}
        ]
        verification_fees_result = await db.transactions.aggregate(verification_fees_pipeline).to_list(1)
        earnings_by_category['verification_fees'] = {
            'amount': round(verification_fees_result[0]['total'], 2) if verification_fees_result else 0.0,
            'count': verification_fees_result[0]['count'] if verification_fees_result else 0
        }

        # Job posting fees
        job_posting_fees_pipeline = [
            {
                '$match': {
                    'user_id': PLATFORM_WALLET_ID,
                    'transaction_type': TransactionType.PLATFORM_FEE_JOB_POSTING,
                    'status': TransactionStatus.COMPLETED
                }
            },
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}, 'count': {'$sum': 1}}}
        ]
        job_posting_fees_result = await db.transactions.aggregate(job_posting_fees_pipeline).to_list(1)
        earnings_by_category['job_posting_fees'] = {
            'amount': round(job_posting_fees_result[0]['total'], 2) if job_posting_fees_result else 0.0,
            'count': job_posting_fees_result[0]['count'] if job_posting_fees_result else 0
        }

        # Legacy platform fees (for backwards compatibility)
        legacy_fees_pipeline = [
            {
                '$match': {
                    'user_id': PLATFORM_WALLET_ID,
                    'transaction_type': TransactionType.PLATFORM_FEE,
                    'status': TransactionStatus.COMPLETED
                }
            },
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}, 'count': {'$sum': 1}}}
        ]
        legacy_fees_result = await db.transactions.aggregate(legacy_fees_pipeline).to_list(1)
        earnings_by_category['legacy_fees'] = {
            'amount': round(legacy_fees_result[0]['total'], 2) if legacy_fees_result else 0.0,
            'count': legacy_fees_result[0]['count'] if legacy_fees_result else 0
        }

        # Seller penalties
        penalties_pipeline = [
            {
                '$match': {
                    'user_id': PLATFORM_WALLET_ID,
                    'transaction_type': TransactionType.SELLER_CANCELLATION_PENALTY,
                    'status': TransactionStatus.COMPLETED
                }
            },
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}, 'count': {'$sum': 1}}}
        ]
        penalties_result = await db.transactions.aggregate(penalties_pipeline).to_list(1)
        earnings_by_category['seller_penalties'] = {
            'amount': round(penalties_result[0]['total'], 2) if penalties_result else 0.0,
            'count': penalties_result[0]['count'] if penalties_result else 0
        }

        # Calculate total earnings
        total_earnings = sum(cat['amount'] for cat in earnings_by_category.values())

        # Get user wallet balances for float allocation
        user_wallets_pipeline = [
            {
                '$match': {
                    'user_id': {'$ne': PLATFORM_WALLET_ID}
                }
            },
            {
                '$group': {
                    '_id': None,
                    'total_balance': {'$sum': '$balance'},
                    'total_pending': {'$sum': '$pending_balance'},
                    'user_count': {'$sum': 1}
                }
            }
        ]
        user_wallets_result = await db.wallets.aggregate(user_wallets_pipeline).to_list(1)
        user_wallets_data = user_wallets_result[0] if user_wallets_result else {
            'total_balance': 0.0,
            'total_pending': 0.0,
            'user_count': 0
        }

        # Calculate total user earnings (seller earnings)
        user_earnings_pipeline = [
            {
                '$match': {
                    'user_id': {'$ne': PLATFORM_WALLET_ID},
                    'transaction_type': TransactionType.SELLER_EARNING,
                    'status': TransactionStatus.COMPLETED
                }
            },
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
        ]
        user_earnings_result = await db.transactions.aggregate(user_earnings_pipeline).to_list(1)
        total_user_earnings = round(user_earnings_result[0]['total'], 2) if user_earnings_result else 0.0

        return {
            'platformWallet': {
                'balance': round(platform_wallet.get('balance', 0.0), 2),
                'totalEarned': round(platform_wallet.get('total_earned', 0.0), 2),
                'totalWithdrawn': round(platform_wallet.get('total_withdrawn', 0.0), 2),
                'availableForWithdrawal': round(platform_wallet.get('balance', 0.0), 2)
            },
            'earningsSources': {
                'bookingFees': earnings_by_category['booking_fees']['amount'],
                'verificationFees': earnings_by_category['verification_fees']['amount'],
                'jobPostingFees': earnings_by_category['job_posting_fees']['amount'],
                'legacyFees': earnings_by_category['legacy_fees']['amount'],
                'sellerPenalties': earnings_by_category['seller_penalties']['amount'],
                'total': round(total_earnings, 2),
                'transactionCount': {
                    'bookingFees': earnings_by_category['booking_fees']['count'],
                    'verificationFees': earnings_by_category['verification_fees']['count'],
                    'jobPostingFees': earnings_by_category['job_posting_fees']['count'],
                    'legacyFees': earnings_by_category['legacy_fees']['count'],
                    'sellerPenalties': earnings_by_category['seller_penalties']['count']
                }
            },
            'floatAllocation': {
                'userWalletsBalance': round(user_wallets_data['total_balance'], 2),
                'pendingEscrow': round(user_wallets_data['total_pending'], 2),
                'platformBalance': round(platform_wallet.get('balance', 0.0), 2),
                'totalFloat': round(
                    user_wallets_data['total_balance'] +
                    user_wallets_data['total_pending'] +
                    platform_wallet.get('balance', 0.0),
                    2
                ),
                'userCount': user_wallets_data['user_count']
            },
            'metrics': {
                'totalUserEarnings': total_user_earnings,
                'platformToUserRatio': round(
                    (total_earnings / total_user_earnings * 100) if total_user_earnings > 0 else 0,
                    2
                ),
                'averageWalletBalance': round(
                    user_wallets_data['total_balance'] / user_wallets_data['user_count']
                    if user_wallets_data['user_count'] > 0 else 0,
                    2
                )
            },
            'settings': {
                'platformFeePercentage': settings.get('platformFeePercentage', 5.0),
                'sellerReceivesPercentage': round(100 - settings.get('platformFeePercentage', 5.0), 2)
            }
        }

    except Exception as e:
        logger.error(f"Error fetching platform earnings: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch platform earnings")

@api_router.get("/admin/platform-earnings-history")
async def get_platform_earnings_history(
    days: int = 30,
    current_user: dict = Depends(require_admin)
):
    """Get platform earnings history for the specified number of days"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        start_date = datetime.utcnow() - timedelta(days=days)

        # Get daily earnings breakdown
        daily_pipeline = [
            {
                '$match': {
                    'user_id': PLATFORM_WALLET_ID,
                    'status': TransactionStatus.COMPLETED,
                    'created_at': {'$gte': start_date},
                    'transaction_type': {
                        '$in': [
                            TransactionType.PLATFORM_FEE_BOOKING,
                            TransactionType.PLATFORM_FEE_VERIFICATION,
                            TransactionType.PLATFORM_FEE_JOB_POSTING,
                            TransactionType.PLATFORM_FEE,
                            TransactionType.SELLER_CANCELLATION_PENALTY
                        ]
                    }
                }
            },
            {
                '$group': {
                    '_id': {
                        'date': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$created_at'}},
                        'type': '$transaction_type'
                    },
                    'amount': {'$sum': '$amount'}
                }
            },
            {'$sort': {'_id.date': 1}}
        ]

        daily_result = await db.transactions.aggregate(daily_pipeline).to_list(None)

        # Organize data by date
        daily_earnings_map = {}
        for item in daily_result:
            date = item['_id']['date']
            txn_type = item['_id']['type']
            amount = item['amount']

            if date not in daily_earnings_map:
                daily_earnings_map[date] = {
                    'date': date,
                    'bookingFees': 0.0,
                    'verificationFees': 0.0,
                    'jobPostingFees': 0.0,
                    'legacyFees': 0.0,
                    'sellerPenalties': 0.0,
                    'total': 0.0
                }

            if txn_type == TransactionType.PLATFORM_FEE_BOOKING:
                daily_earnings_map[date]['bookingFees'] += amount
            elif txn_type == TransactionType.PLATFORM_FEE_VERIFICATION:
                daily_earnings_map[date]['verificationFees'] += amount
            elif txn_type == TransactionType.PLATFORM_FEE_JOB_POSTING:
                daily_earnings_map[date]['jobPostingFees'] += amount
            elif txn_type == TransactionType.PLATFORM_FEE:
                daily_earnings_map[date]['legacyFees'] += amount
            elif txn_type == TransactionType.SELLER_CANCELLATION_PENALTY:
                daily_earnings_map[date]['sellerPenalties'] += amount

            daily_earnings_map[date]['total'] += amount

        # Convert to list and round values
        daily_earnings = []
        for date_data in sorted(daily_earnings_map.values(), key=lambda x: x['date']):
            daily_earnings.append({
                'date': date_data['date'],
                'bookingFees': round(date_data['bookingFees'], 2),
                'verificationFees': round(date_data['verificationFees'], 2),
                'jobPostingFees': round(date_data['jobPostingFees'], 2),
                'legacyFees': round(date_data['legacyFees'], 2),
                'sellerPenalties': round(date_data['sellerPenalties'], 2),
                'total': round(date_data['total'], 2)
            })

        # Calculate summary statistics
        total_earnings = sum(day['total'] for day in daily_earnings)
        avg_daily_earnings = total_earnings / days if days > 0 else 0
        peak_day = max(daily_earnings, key=lambda x: x['total']) if daily_earnings else None

        return {
            'dailyEarnings': daily_earnings,
            'summary': {
                'totalEarnings': round(total_earnings, 2),
                'averageDailyEarnings': round(avg_daily_earnings, 2),
                'peakDay': peak_day['date'] if peak_day else None,
                'peakDayEarnings': round(peak_day['total'], 2) if peak_day else 0.0,
                'days': days
            }
        }

    except Exception as e:
        logger.error(f"Error fetching platform earnings history: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch earnings history")

# Admin Users Management
@api_router.get("/admin/users")
async def get_all_users(
    role: Optional[str] = None,
    kyc_status: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    limit: int = 50,
    current_user: dict = Depends(require_admin)
):
    """Get all users with filtering and pagination"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Build query filter
        query = {}

        if role:
            query['role'] = role

        if kyc_status:
            query['kyc_status'] = kyc_status

        if search:
            query['$or'] = [
                {'name': {'$regex': search, '$options': 'i'}},
                {'email': {'$regex': search, '$options': 'i'}},
                {'phone': {'$regex': search, '$options': 'i'}}
            ]

        # Calculate pagination
        skip = (page - 1) * limit

        # Get total count
        total = await db.users.count_documents(query)

        # Get users
        users_cursor = db.users.find(query).sort('created_at', -1).skip(skip).limit(limit)
        users = await users_cursor.to_list(length=limit)

        # Format response
        users_list = []
        for user in users:
            users_list.append({
                'id': str(user['_id']),
                'name': user.get('name', ''),
                'email': user.get('email', ''),
                'phone': user.get('phone', ''),
                'role': user.get('role', 'buyer'),
                'kycStatus': user.get('kyc_status', 'pending'),
                'createdAt': user.get('created_at', datetime.utcnow()).isoformat(),
                'fcmToken': user.get('fcm_token', None) is not None,
                'suspended': user.get('suspended', False),
                'suspensionReason': user.get('suspension_reason', None)
            })

        return {
            'users': users_list,
            'total': total,
            'page': page,
            'limit': limit,
            'totalPages': (total + limit - 1) // limit
        }
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch users")

@api_router.get("/admin/users/{user_id}")
async def get_user_by_id(
    user_id: str,
    current_user: dict = Depends(require_admin)
):
    """Get detailed user information by ID (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        user = await db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Get wallet info
        wallet = await db.wallets.find_one({'user_id': user_id})

        # Get user's orders
        orders_count = await db.orders.count_documents({'$or': [{'buyer_id': user_id}, {'seller_id': user_id}]})

        # Get user's listings if seller
        listings_count = 0
        if user.get('role') == UserRole.SELLER:
            listings_count = await db.service_listings.count_documents({'seller_id': user_id})

        return {
            'id': str(user['_id']),
            'name': user.get('name', ''),
            'email': user.get('email', ''),
            'phone': user.get('phone', ''),
            'role': user.get('role', 'buyer'),
            'kycStatus': user.get('kyc_status', 'pending'),
            'createdAt': user.get('created_at', datetime.utcnow()).isoformat(),
            'fcmToken': user.get('fcm_token'),
            'suspended': user.get('suspended', False),
            'suspensionReason': user.get('suspension_reason', None),
            'suspensionDate': user.get('suspension_date').isoformat() if user.get('suspension_date') else None,
            'wallet': {
                'balance': round(wallet.get('balance', 0.0), 2) if wallet else 0.0,
                'pendingBalance': round(wallet.get('pending_balance', 0.0), 2) if wallet else 0.0,
                'totalEarned': round(wallet.get('total_earned', 0.0), 2) if wallet else 0.0,
                'totalWithdrawn': round(wallet.get('total_withdrawn', 0.0), 2) if wallet else 0.0,
            },
            'ordersCount': orders_count,
            'listingsCount': listings_count
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch user details")

# Admin User Actions
@api_router.post("/admin/users/{user_id}/suspend")
async def suspend_user(
    user_id: str,
    request: SuspendUserRequest,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """Suspend or unsuspend a user account (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        user = await db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Prevent admins from suspending other admins
        if user.get('role') == UserRole.ADMIN:
            raise HTTPException(status_code=403, detail="Cannot suspend admin users")

        before_state = {
            'suspended': user.get('suspended', False),
            'suspension_reason': user.get('suspension_reason', None),
            'suspension_date': user.get('suspension_date')
        }

        # Update user suspension status
        update_data = {
            'suspended': request.suspend,
            'suspension_reason': request.reason if request.suspend else None,
            'suspension_date': datetime.utcnow() if request.suspend else None,
            'updated_at': datetime.utcnow()
        }

        await db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': update_data}
        )

        after_state = {
            'suspended': update_data['suspended'],
            'suspension_reason': update_data['suspension_reason'],
            'suspension_date': update_data['suspension_date']
        }

        await log_admin_audit(
            action='user.suspend' if request.suspend else 'user.unsuspend',
            actor=current_user,
            target_type='user',
            target_id=user_id,
            before=before_state,
            after=after_state,
            payload={'suspend': request.suspend, 'reason': request.reason},
            request=http_request
        )

        logger.info(f"User {user_id} {'suspended' if request.suspend else 'unsuspended'} by admin {current_user['name']}")

        return {
            'message': f"User {'suspended' if request.suspend else 'unsuspended'} successfully",
            'user_id': user_id,
            'suspended': request.suspend
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error suspending user: {e}")
        raise HTTPException(status_code=500, detail="Failed to suspend user")

@api_router.post("/admin/users/{user_id}/reset-password")
async def admin_reset_user_password(
    user_id: str,
    new_password: Optional[str] = None,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """Reset a user's password (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        user = await db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Prevent admins from resetting other admin passwords
        if user.get('role') == UserRole.ADMIN and str(user['_id']) != str(current_user['_id']):
            raise HTTPException(status_code=403, detail="Cannot reset admin user passwords")

        # Generate random password if not provided
        if not new_password:
            import random
            import string
            new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))

        # Hash the new password
        hashed_password = hash_password(new_password)

        # Update user password
        await db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'password': hashed_password,
                'password_reset_required': True,
                'updated_at': datetime.utcnow()
            }}
        )

        await log_admin_audit(
            action='user.reset_password',
            actor=current_user,
            target_type='user',
            target_id=user_id,
            before={'password_reset_required': user.get('password_reset_required', False)},
            after={'password_reset_required': True},
            payload={'password_provided': bool(new_password)},
            request=http_request
        )

        logger.info(f"Password reset for user {user_id} by admin {current_user['name']}")

        return {
            'message': 'Password reset successfully',
            'user_id': user_id,
            'temporary_password': new_password,
            'note': 'User will be required to change password on next login'
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resetting password: {e}")
        raise HTTPException(status_code=500, detail="Failed to reset password")

@api_router.post("/admin/users/{user_id}/kyc/approve")
async def approve_user_kyc(
    user_id: str,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """Approve user KYC (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        user = await db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        before_state = {
            'kyc_status': user.get('kyc_status', 'pending'),
            'kyc_verified_at': user.get('kyc_verified_at')
        }

        # Update KYC status
        await db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'kyc_status': 'verified',
                'kyc_verified_at': datetime.utcnow(),
                'kyc_verified_by': str(current_user['_id']),
                'updated_at': datetime.utcnow()
            }}
        )

        await log_admin_audit(
            action='user.kyc_approve',
            actor=current_user,
            target_type='user',
            target_id=user_id,
            before=before_state,
            after={'kyc_status': 'verified', 'kyc_verified_at': datetime.utcnow()},
            payload={'reason': None},
            request=http_request
        )

        logger.info(f"KYC approved for user {user_id} by admin {current_user['name']}")

        # Send notification to user
        try:
            await db.notifications.insert_one({
                'user_id': user_id,
                'title': 'KYC Verified',
                'message': 'Your KYC verification has been approved. You can now access all platform features.',
                'type': 'kyc_approved',
                'read': False,
                'created_at': datetime.utcnow()
            })
        except Exception as e:
            logger.warning(f"Failed to send KYC approval notification: {e}")

        return {
            'message': 'KYC approved successfully',
            'user_id': user_id,
            'kyc_status': 'verified'
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error approving KYC: {e}")
        raise HTTPException(status_code=500, detail="Failed to approve KYC")

@api_router.post("/admin/users/{user_id}/kyc/reject")
async def reject_user_kyc(
    user_id: str,
    reason: str,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """Reject user KYC (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    if not reason or not reason.strip():
        raise HTTPException(status_code=400, detail="Rejection reason is required")

    try:
        user = await db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        before_state = {
            'kyc_status': user.get('kyc_status', 'pending'),
            'kyc_rejection_reason': user.get('kyc_rejection_reason')
        }

        # Update KYC status
        await db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'kyc_status': 'rejected',
                'kyc_rejection_reason': reason,
                'kyc_rejected_at': datetime.utcnow(),
                'kyc_rejected_by': str(current_user['_id']),
                'updated_at': datetime.utcnow()
            }}
        )

        await log_admin_audit(
            action='user.kyc_reject',
            actor=current_user,
            target_type='user',
            target_id=user_id,
            before=before_state,
            after={'kyc_status': 'rejected', 'kyc_rejection_reason': reason},
            payload={'reason': reason},
            request=http_request
        )

        logger.info(f"KYC rejected for user {user_id} by admin {current_user['name']}")

        # Send notification to user
        try:
            await db.notifications.insert_one({
                'user_id': user_id,
                'title': 'KYC Rejected',
                'message': f'Your KYC verification has been rejected. Reason: {reason}',
                'type': 'kyc_rejected',
                'read': False,
                'created_at': datetime.utcnow()
            })
        except Exception as e:
            logger.warning(f"Failed to send KYC rejection notification: {e}")

        return {
            'message': 'KYC rejected successfully',
            'user_id': user_id,
            'kyc_status': 'rejected',
            'reason': reason
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error rejecting KYC: {e}")
        raise HTTPException(status_code=500, detail="Failed to reject KYC")

# Admin Orders Management
@api_router.get("/admin/orders")
async def get_all_orders(
    status: Optional[str] = None,
    payment_status: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    limit: int = 50,
    current_user: dict = Depends(require_admin)
):
    """Get all orders with filtering and pagination (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Build query filter
        query = {}

        if payment_status:
            query['payment_status'] = payment_status

        if status:
            query['delivery_status'] = status

        # Search by order ID, buyer/seller name (requires join - simplified for now)
        # For advanced search, consider implementing aggregation pipeline

        # Calculate pagination
        skip = (page - 1) * limit

        # Get total count
        total = await db.orders.count_documents(query)

        # Get orders
        orders_cursor = db.orders.find(query).sort('created_at', -1).skip(skip).limit(limit)
        orders = await orders_cursor.to_list(length=limit)

        # Format response - enrich with buyer/seller and service info
        orders_list = []
        for order in orders:
            # Fetch buyer and seller info
            buyer = await db.users.find_one({'_id': ObjectId(order['buyer_id'])})
            seller = await db.users.find_one({'_id': ObjectId(order['seller_id'])})

            # Fetch service listing info (support both service_id and legacy pet_id)
            service_id = order.get('service_id', order.get('pet_id'))
            service = None
            if service_id:
                try:
                    service = await db.service_listings.find_one({'_id': ObjectId(service_id)})
                except:
                    pass

            service_fee = order.get('service_fee', order.get('delivery_fee', 0.0))
            total_amount = order.get('total_amount', order['price'] + service_fee)

            orders_list.append({
                'id': str(order['_id']),
                '_id': str(order['_id']),
                'buyerId': order['buyer_id'],
                'buyer_id': order['buyer_id'],
                'buyerName': buyer.get('name', 'Unknown') if buyer else 'Unknown',
                'buyer_name': buyer.get('name', 'Unknown') if buyer else 'Unknown',
                'buyerEmail': buyer.get('email', '') if buyer else '',
                'buyer_email': buyer.get('email', '') if buyer else '',
                'sellerId': order['seller_id'],
                'seller_id': order['seller_id'],
                'sellerName': seller.get('name', 'Unknown') if seller else 'Unknown',
                'seller_name': seller.get('name', 'Unknown') if seller else 'Unknown',
                'sellerEmail': seller.get('email', '') if seller else '',
                'seller_email': seller.get('email', '') if seller else '',
                'serviceId': service_id,
                'service_id': service_id,
                'serviceName': service.get('service_name', 'Unknown') if service else 'Unknown',
                'service_name': service.get('service_name', 'Unknown') if service else 'Unknown',
                'serviceCategory': service.get('service_category', 'Unknown') if service else 'Unknown',
                'service_category': service.get('service_category', 'Unknown') if service else 'Unknown',
                'booking_date': order.get('booking_date'),
                'bookingDate': order.get('booking_date'),
                'booking_time': order.get('booking_time'),
                'bookingTime': order.get('booking_time'),
                'service_location': order.get('service_location', order.get('delivery_option')),
                'serviceLocation': order.get('service_location', order.get('delivery_option')),
                'service_address': order.get('service_address', order.get('delivery_address')),
                'serviceAddress': order.get('service_address', order.get('delivery_address')),
                'service_requirements': order.get('service_requirements', {}),
                'serviceRequirements': order.get('service_requirements', {}),
                'price': order['price'],
                'platformFee': order.get('platform_fee', order['price'] * PLATFORM_FEE_PERCENTAGE),
                'platform_fee': order.get('platform_fee', order['price'] * PLATFORM_FEE_PERCENTAGE),
                'sellerAmount': order.get('seller_amount', order['price'] * (1 - PLATFORM_FEE_PERCENTAGE)),
                'seller_amount': order.get('seller_amount', order['price'] * (1 - PLATFORM_FEE_PERCENTAGE)),
                'serviceFee': service_fee,
                'service_fee': service_fee,
                'deliveryFee': service_fee,  # Legacy field
                'delivery_fee': service_fee,  # Legacy field
                'totalAmount': total_amount,
                'total_amount': total_amount,
                'paymentMethod': order.get('payment_method', PaymentMethod.MPESA),
                'payment_method': order.get('payment_method', PaymentMethod.MPESA),
                'paymentStatus': order['payment_status'],
                'payment_status': order['payment_status'],
                'serviceStatus': order.get('service_status', order.get('delivery_status', 'pending')),
                'service_status': order.get('service_status', order.get('delivery_status', 'pending')),
                'deliveryOption': order.get('delivery_option', order.get('service_location')),  # Legacy
                'delivery_option': order.get('delivery_option', order.get('service_location')),  # Legacy
                'deliveryStatus': order.get('delivery_status', order.get('service_status', 'pending')),  # Legacy
                'delivery_status': order.get('delivery_status', order.get('service_status', 'pending')),  # Legacy
                'serviceFeeStatus': order.get('service_fee_status', order.get('delivery_fee_status', DeliveryFeeStatus.NOT_SET)),
                'service_fee_status': order.get('service_fee_status', order.get('delivery_fee_status', DeliveryFeeStatus.NOT_SET)),
                'deliveryFeeStatus': order.get('delivery_fee_status', order.get('service_fee_status', DeliveryFeeStatus.NOT_SET)),  # Legacy
                'delivery_fee_status': order.get('delivery_fee_status', order.get('service_fee_status', DeliveryFeeStatus.NOT_SET)),  # Legacy
                'deliveryAddress': order.get('delivery_address', order.get('service_address')),  # Legacy
                'delivery_address': order.get('delivery_address', order.get('service_address')),  # Legacy
                'mpesaReceipt': order.get('mpesa_checkout_request_id'),
                'mpesa_receipt': order.get('mpesa_checkout_request_id'),
                'createdAt': order['created_at'].isoformat() if order.get('created_at') else None,
                'created_at': order['created_at'].isoformat() if order.get('created_at') else None,
                'updatedAt': order.get('updated_at', order['created_at']).isoformat() if order.get('created_at') else None,
                'updated_at': order.get('updated_at', order['created_at']).isoformat() if order.get('created_at') else None,
            })

        return {
            'orders': orders_list,
            'total': total,
            'page': page,
            'limit': limit,
            'totalPages': (total + limit - 1) // limit
        }
    except Exception as e:
        logger.error(f"Error fetching orders: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch orders")

@api_router.get("/admin/orders/{order_id}")
async def get_admin_order_detail(order_id: str, current_user: dict = Depends(require_admin)):
    """Get detailed order information for admin"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        order = await db.orders.find_one({'_id': ObjectId(order_id)})
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        # Enrich with related data
        buyer = await db.users.find_one({'_id': ObjectId(order['buyer_id'])})
        seller = await db.users.find_one({'_id': ObjectId(order['seller_id'])})

        service_id = order.get('service_id', order.get('pet_id'))
        service = None
        if service_id:
            try:
                service = await db.service_listings.find_one({'_id': ObjectId(service_id)})
            except:
                pass

        # Get related transactions
        transactions = await db.transactions.find({'order_id': order_id}).to_list(None)

        service_fee = order.get('service_fee', order.get('delivery_fee', 0.0))
        total_amount = order.get('total_amount', order['price'] + service_fee)

        return {
            'id': str(order['_id']),
            'buyer': {
                'id': order['buyer_id'],
                'name': buyer.get('name', 'Unknown') if buyer else 'Unknown',
                'email': buyer.get('email', '') if buyer else '',
                'phone': buyer.get('phone', '') if buyer else ''
            },
            'seller': {
                'id': order['seller_id'],
                'name': seller.get('name', 'Unknown') if seller else 'Unknown',
                'email': seller.get('email', '') if seller else '',
                'phone': seller.get('phone', '') if seller else ''
            },
            'service': {
                'id': service_id,
                'name': service.get('service_name', 'Unknown') if service else 'Unknown',
                'category': service.get('service_category', 'Unknown') if service else 'Unknown'
            } if service else None,
            'booking_date': order.get('booking_date'),
            'booking_time': order.get('booking_time'),
            'service_location': order.get('service_location', order.get('delivery_option')),
            'service_address': order.get('service_address', order.get('delivery_address')),
            'service_requirements': order.get('service_requirements', {}),
            'price': order['price'],
            'platform_fee': order.get('platform_fee', order['price'] * PLATFORM_FEE_PERCENTAGE),
            'seller_amount': order.get('seller_amount', order['price'] * (1 - PLATFORM_FEE_PERCENTAGE)),
            'service_fee': service_fee,
            'total_amount': total_amount,
            'payment_status': order.get('payment_status', PaymentStatus.PENDING),
            'payment_method': order.get('payment_method'),
            'mpesa_code': order.get('mpesa_code'),
            'delivery_status': order.get('delivery_status', DeliveryStatus.PENDING),
            'created_at': order['created_at'].isoformat() if order.get('created_at') else None,
            'updated_at': order.get('updated_at').isoformat() if order.get('updated_at') else None,
            'buyer_confirmed_at': order.get('buyer_confirmed_at').isoformat() if order.get('buyer_confirmed_at') else None,
            'notes': order.get('notes'),
            'cancellation_reason': order.get('cancellation_reason'),
            'transactions': [
                {
                    'id': str(txn['_id']),
                    'amount': txn['amount'],
                    'type': txn['transaction_type'],
                    'status': txn['status'],
                    'description': txn.get('description'),
                    'created_at': txn['created_at'].isoformat() if txn.get('created_at') else None
                } for txn in transactions
            ]
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching order detail: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch order details")

@api_router.get("/admin/listings/{listing_id}")
async def get_admin_listing_detail(listing_id: str, current_user: dict = Depends(require_admin)):
    """Get detailed listing information for admin"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Try service_listings first, then pet_listings (legacy)
        listing = await db.service_listings.find_one({'_id': ObjectId(listing_id)})
        if not listing:
            listing = await db.pet_listings.find_one({'_id': ObjectId(listing_id)})

        if not listing:
            raise HTTPException(status_code=404, detail="Listing not found")

        # Get seller info
        seller = await db.users.find_one({'_id': ObjectId(listing['seller_id'])})
        seller_profile = await db.seller_profiles.find_one({'user_id': listing['seller_id']})

        # Get reviews for this seller
        reviews_count = await db.reviews.count_documents({'seller_id': listing['seller_id']})

        return {
            'id': str(listing['_id']),
            'seller': {
                'id': listing['seller_id'],
                'name': seller.get('name', 'Unknown') if seller else 'Unknown',
                'email': seller.get('email', '') if seller else '',
                'phone': seller.get('phone', '') if seller else '',
                'business_name': seller_profile.get('business_name', '') if seller_profile else '',
                'rating': seller_profile.get('rating', 0.0) if seller_profile else 0.0,
                'total_reviews': reviews_count
            },
            'service_category': listing.get('service_category', listing.get('species')),
            'service_name': listing.get('service_name', listing.get('breed')),
            'service_type': listing.get('service_type', 'one-time'),
            'duration_minutes': listing.get('duration_minutes', 60),
            'price': listing['price'],
            'price_unit': listing.get('price_unit', 'per_session'),
            'description': listing.get('description', ''),
            'qualifications': listing.get('qualifications', ''),
            'experience_years': listing.get('experience_years', 0),
            'services_included': listing.get('services_included', []),
            'location': listing.get('location', {}),
            'service_location_type': listing.get('service_location_type', 'at_customer'),
            'photos': listing.get('photos', []),
            'certifications': listing.get('certifications', []),
            'availability': listing.get('availability', {}),
            'status': listing.get('status', ListingStatus.PENDING),
            'created_at': listing['created_at'].isoformat() if listing.get('created_at') else None,
            'updated_at': listing.get('updated_at').isoformat() if listing.get('updated_at') else None,
            'views': listing.get('views', 0),
            'rejection_reason': listing.get('rejection_reason')
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching listing detail: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch listing details")

@api_router.get("/admin/payments")
async def get_admin_payments(
    status: Optional[str] = None,
    method: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    limit: int = 50,
    current_user: dict = Depends(require_admin)
):
    """Get all payment transactions for admin with filtering"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Build query filter
        query = {}

        if status:
            query['payment_status'] = status

        if method:
            query['payment_method'] = method

        # Calculate pagination
        skip = (page - 1) * limit

        # Get total count
        total = await db.orders.count_documents(query)

        # Get orders (which contain payment info)
        orders_cursor = db.orders.find(query).sort('created_at', -1).skip(skip).limit(limit)
        orders = await orders_cursor.to_list(length=limit)

        # Format response
        payments_list = []
        for order in orders:
            buyer = await db.users.find_one({'_id': ObjectId(order['buyer_id'])})
            seller = await db.users.find_one({'_id': ObjectId(order['seller_id'])})

            payments_list.append({
                'id': str(order['_id']),
                'order_id': str(order['_id']),
                'buyer_name': buyer.get('name', 'Unknown') if buyer else 'Unknown',
                'seller_name': seller.get('name', 'Unknown') if seller else 'Unknown',
                'amount': order.get('total_amount', order['price']),
                'payment_method': order.get('payment_method'),
                'payment_status': order.get('payment_status', PaymentStatus.PENDING),
                'mpesa_code': order.get('mpesa_code'),
                'platform_fee': order.get('platform_fee', order['price'] * PLATFORM_FEE_PERCENTAGE),
                'created_at': order['created_at'].isoformat() if order.get('created_at') else None
            })

        return {
            'payments': payments_list,
            'total': total,
            'page': page,
            'limit': limit,
            'totalPages': (total + limit - 1) // limit
        }
    except Exception as e:
        logger.error(f"Error fetching payments: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch payments")

@api_router.get("/admin/security-events")
async def get_security_events(
    current_user: dict = Depends(require_admin),
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 100
):
    try:
        limit = max(1, min(limit, 500))
        query = {}
        if severity:
            query['severity'] = severity
        if event_type:
            query['event_type'] = event_type

        events = await db.security_events.find(query).sort('created_at', -1).limit(limit).to_list(limit)
        for event in events:
            event['id'] = str(event.pop('_id'))
        return {'events': events}
    except Exception as e:
        logger.error(f"Failed to fetch security events: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch security events")

@api_router.get("/admin/security-events/summary")
async def get_security_events_summary(
    current_user: dict = Depends(require_admin),
    hours: int = 24
):
    try:
        hours = max(1, min(hours, 168))
        now = datetime.utcnow()
        since = now - timedelta(hours=hours)

        total_events = await db.security_events.count_documents({})
        window_count = await db.security_events.count_documents({'created_at': {'$gte': since}})

        severity_agg = await db.security_events.aggregate([
            {'$match': {'created_at': {'$gte': since}}},
            {'$group': {'_id': '$severity', 'count': {'$sum': 1}}}
        ]).to_list(None)
        severity_counts = {row['_id']: row.get('count', 0) for row in severity_agg if row.get('_id')}

        event_types = await db.security_events.distinct('event_type')

        critical_recent = await db.security_events.find({
            'severity': 'critical',
            'created_at': {'$gte': since}
        }).sort('created_at', -1).limit(5).to_list(5)
        for event in critical_recent:
            event['id'] = str(event.pop('_id'))

        return {
            'total': total_events,
            'window_hours': hours,
            'window_count': window_count,
            'severity_counts': severity_counts,
            'event_types': sorted([evt for evt in event_types if evt]),
            'critical_recent': critical_recent
        }
    except Exception as e:
        logger.error(f"Failed to fetch security event summary: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch security event summary")

@api_router.get("/admin/audit-logs")
async def get_admin_audit_logs(
    current_user: dict = Depends(require_admin),
    action: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    actor_id: Optional[str] = None,
    limit: int = 100,
    skip: int = 0
):
    try:
        limit = max(1, min(limit, 500))
        skip = max(0, min(skip, 5000))
        query = {}
        if action:
            query['action'] = action
        if target_type:
            query['target_type'] = target_type
        if target_id:
            query['target_id'] = target_id
        if actor_id:
            query['actor_id'] = actor_id

        logs = await db.admin_audit_logs.find(query).sort('created_at', -1).skip(skip).limit(limit).to_list(limit)
        for log in logs:
            log['id'] = str(log.pop('_id'))
        return {'logs': logs, 'limit': limit, 'skip': skip}
    except Exception as e:
        logger.error(f"Failed to fetch admin audit logs: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch admin audit logs")

@api_router.get("/admin/ledger/summary")
async def get_ledger_summary(current_user: dict = Depends(require_admin)):
    try:
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)

        total_entries = await db.ledger_entries.count_documents({})
        last_24h_count = await db.ledger_entries.count_documents({'created_at': {'$gte': last_24h}})

        agg = await db.ledger_entries.aggregate([
            {
                '$group': {
                    '_id': '$direction',
                    'total': {'$sum': '$amount'},
                    'count': {'$sum': 1}
                }
            }
        ]).to_list(None)

        totals = {'credit': 0, 'debit': 0}
        counts = {'credit': 0, 'debit': 0}
        for row in agg:
            direction = row.get('_id')
            if direction in totals:
                totals[direction] = row.get('total', 0)
                counts[direction] = row.get('count', 0)

        recent_entries = await db.ledger_entries.find({}).sort('created_at', -1).limit(10).to_list(10)
        for entry in recent_entries:
            entry['id'] = str(entry.pop('_id'))
            entry['created_at'] = entry.get('created_at')

        return {
            'total_entries': total_entries,
            'last_24h': last_24h_count,
            'totals': totals,
            'counts': counts,
            'recent': recent_entries
        }
    except Exception as e:
        logger.error(f"Ledger summary error: {e}")
        raise HTTPException(status_code=500, detail="Failed to load ledger summary")

@api_router.get("/admin/ledger/integrity")
async def verify_transaction_integrity(
    current_user: dict = Depends(require_admin),
    limit: int = 500
):
    """Verify transaction integrity hash chain (admin only)."""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    try:
        limit = max(1, min(limit, 2000))
        bad = []
        cursor = db.transactions.find({}).sort('created_at', 1).limit(limit)
        previous_by_user: Dict[str, Optional[str]] = {}

        async for txn in cursor:
            user_id = txn.get('user_id')
            prev_hash = previous_by_user.get(user_id)
            expected = _compute_transaction_hash(txn, prev_hash)
            if txn.get('integrity_hash') != expected:
                bad.append({
                    'transaction_id': str(txn.get('_id')),
                    'user_id': user_id,
                    'expected': expected,
                    'actual': txn.get('integrity_hash'),
                    'created_at': txn.get('created_at')
                })
            previous_by_user[user_id] = txn.get('integrity_hash')

        return {
            'status': 'ok' if not bad else 'failed',
            'checked': limit,
            'failed': len(bad),
            'samples': bad[:20]
        }
    except Exception as e:
        logger.error(f"Ledger integrity verification failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to verify transaction integrity")

@api_router.post("/admin/ledger/reconcile")
async def run_ledger_reconciliation(
    fix: bool = False,
    current_user: dict = Depends(require_admin),
    request: Request = None
):
    """Manually trigger double-entry ledger reconciliation (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    tolerance = RECONCILIATION_TOLERANCE_PROD if ENVIRONMENT == 'production' else RECONCILIATION_TOLERANCE_DEV
    result = await reconcile_double_entry_ledger(tolerance=tolerance)

    if fix:
        if ENVIRONMENT == 'production':
            raise HTTPException(status_code=400, detail="Auto-fix is disabled in production")
        fixed = 0
        for drift in result.get('balance_drifts', []):
            user_id = drift['user_id']
            before = await db.wallets.find_one({'user_id': user_id})
            await db.wallets.update_one(
                {'user_id': user_id},
                {'$set': {'balance': drift['ledger_balance'], 'updated_at': datetime.utcnow()}}
            )
            after = await db.wallets.find_one({'user_id': user_id})
            fixed += 1
            await log_admin_audit(
                action='ledger.reconcile.fix',
                actor=current_user,
                target_type='wallet',
                target_id=user_id,
                before=before,
                after=after,
                payload={'ledger_balance': drift['ledger_balance'], 'wallet_balance': drift['wallet_balance']},
                request=request
            )
        result['auto_fixed'] = fixed
    if result.get('status') != 'ok':
        await log_security_event(
            event_type='ledger_reconciliation_issue',
            severity='high',
            details=result,
            user_id=str(current_user['_id']),
            request=request
        )
    return result

# Admin Sellers Management
@api_router.get("/admin/sellers")
async def get_all_sellers(
    page: int = 1,
    limit: int = 50,
    min_rating: Optional[float] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    current_user: dict = Depends(require_admin)
):
    """Get all sellers with performance metrics (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Build query filter for sellers
        query = {'role': UserRole.SELLER}

        if status:
            query['kyc_status'] = status

        # Calculate pagination
        skip = (page - 1) * limit

        # Get total count
        total = await db.users.count_documents(query)

        # Get sellers
        sellers_cursor = db.users.find(query).sort('created_at', -1).skip(skip).limit(limit)
        sellers = await sellers_cursor.to_list(length=limit)

        # Format response with metrics
        sellers_list = []
        for seller in sellers:
            seller_id = str(seller['_id'])

            # Get seller metrics
            # Total active listings
            active_listings = await db.service_listings.count_documents({
                'seller_id': seller_id,
                'status': ListingStatus.ACTIVE
            })

            # Total sales (paid orders)
            total_sales = await db.orders.count_documents({
                'seller_id': seller_id,
                'payment_status': PaymentStatus.PAID
            })

            # Total revenue
            revenue_pipeline = [
                {'$match': {
                    'seller_id': seller_id,
                    'payment_status': PaymentStatus.PAID
                }},
                {'$group': {'_id': None, 'total': {'$sum': '$seller_amount'}}}
            ]
            revenue_result = await db.orders.aggregate(revenue_pipeline).to_list(1)
            total_revenue = revenue_result[0]['total'] if revenue_result else 0.0

            # Get reviews
            reviews = await db.reviews.find({'seller_id': seller_id}).to_list(None)
            total_reviews = len(reviews)
            average_rating = sum(r['rating'] for r in reviews) / total_reviews if total_reviews > 0 else 0.0

            # Apply rating filter if specified
            if min_rating and average_rating < min_rating:
                continue

            # Get wallet info
            wallet = await db.wallets.find_one({'user_id': seller_id})
            wallet_balance = wallet.get('balance', 0.0) if wallet else 0.0
            pending_balance = wallet.get('pending_balance', 0.0) if wallet else 0.0
            subscription_info = build_seller_subscription_payload(seller)
            availability_info = parse_seller_availability_payload(seller)

            sellers_list.append({
                'id': seller_id,
                'name': seller.get('name', 'Unknown'),
                'email': seller.get('email', ''),
                'phone': seller.get('phone', ''),
                'kycStatus': seller.get('kyc_status', KYCStatus.PENDING),
                'subscriptionTier': subscription_info['seller_subscription_tier'],
                'subscriptionBadge': subscription_info['seller_subscription_badge'],
                'subscriptionVisibilityBoost': subscription_info['seller_visibility_boost'],
                'subscriptionExpiresAt': subscription_info['subscription_expires_at'].isoformat() if subscription_info['subscription_expires_at'] else None,
                'availableNow': availability_info['seller_available_now'],
                'availableNowUpdatedAt': availability_info['seller_available_now_updated_at'].isoformat() if availability_info['seller_available_now_updated_at'] else None,
                'rating': round(average_rating, 2),
                'totalReviews': total_reviews,
                'activeListings': active_listings,
                'totalSales': total_sales,
                'totalRevenue': round(total_revenue, 2),
                'walletBalance': round(wallet_balance, 2),
                'pendingBalance': round(pending_balance, 2),
                'createdAt': seller.get('created_at', datetime.utcnow()).isoformat()
            })

        return {
            'sellers': sellers_list,
            'total': total,
            'page': page,
            'limit': limit,
            'totalPages': (total + limit - 1) // limit
        }
    except Exception as e:
        logger.error(f"Error fetching sellers: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch sellers")

@api_router.get("/admin/sellers/{seller_id}")
async def get_seller_details(
    seller_id: str,
    current_user: dict = Depends(require_admin)
):
    """Get detailed seller information (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Get seller
        seller = await db.users.find_one({'_id': ObjectId(seller_id), 'role': UserRole.SELLER})
        if not seller:
            raise HTTPException(status_code=404, detail="Seller not found")

        # Get listings
        listings = await db.service_listings.find({'seller_id': seller_id}).to_list(None)

        # Get orders
        orders = await db.orders.find({'seller_id': seller_id}).to_list(None)

        # Get reviews
        reviews = await db.reviews.find({'seller_id': seller_id}).to_list(None)

        # Get wallet
        wallet = await db.wallets.find_one({'user_id': seller_id})

        # Calculate metrics
        total_reviews = len(reviews)
        average_rating = sum(r['rating'] for r in reviews) / total_reviews if total_reviews > 0 else 0.0
        subscription_info = build_seller_subscription_payload(seller)
        availability_info = parse_seller_availability_payload(seller)

        total_revenue = sum(o.get('seller_amount', 0) for o in orders if o.get('payment_status') == PaymentStatus.PAID)

        return {
            'id': seller_id,
            'name': seller.get('name', ''),
            'email': seller.get('email', ''),
            'phone': seller.get('phone', ''),
            'kycStatus': seller.get('kyc_status', KYCStatus.PENDING),
            'subscriptionTier': subscription_info['seller_subscription_tier'],
            'subscriptionBadge': subscription_info['seller_subscription_badge'],
            'subscriptionVisibilityBoost': subscription_info['seller_visibility_boost'],
            'subscriptionExpiresAt': subscription_info['subscription_expires_at'].isoformat() if subscription_info['subscription_expires_at'] else None,
            'availableNow': availability_info['seller_available_now'],
            'availableNowUpdatedAt': availability_info['seller_available_now_updated_at'].isoformat() if availability_info['seller_available_now_updated_at'] else None,
            'fcmToken': seller.get('fcm_token'),
            'rating': round(average_rating, 2),
            'totalReviews': total_reviews,
            'totalListings': len(listings),
            'activeListings': sum(1 for l in listings if l.get('status') == ListingStatus.ACTIVE),
            'totalOrders': len(orders),
            'completedOrders': sum(1 for o in orders if o.get('payment_status') == PaymentStatus.PAID),
            'totalRevenue': round(total_revenue, 2),
            'wallet': {
                'balance': round(wallet.get('balance', 0.0), 2) if wallet else 0.0,
                'pendingBalance': round(wallet.get('pending_balance', 0.0), 2) if wallet else 0.0,
                'totalEarned': round(wallet.get('total_earned', 0.0), 2) if wallet else 0.0,
                'totalWithdrawn': round(wallet.get('total_withdrawn', 0.0), 2) if wallet else 0.0
            },
            'recentListings': [
                {
                    'id': str(l['_id']),
                    'breed': l.get('breed', ''),
                    'species': l.get('species', ''),
                    'price': l.get('price', 0),
                    'status': l.get('status', ''),
                    'createdAt': l.get('created_at', datetime.utcnow()).isoformat()
                }
                for l in sorted(listings, key=lambda x: x.get('created_at', datetime.utcnow()), reverse=True)[:5]
            ],
            'createdAt': seller.get('created_at', datetime.utcnow()).isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching seller details: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch seller details")

@api_router.patch("/admin/sellers/{seller_id}/subscription")
async def set_seller_subscription_tier(
    seller_id: str,
    subscription_data: AdminSetSellerSubscriptionRequest,
    current_user: dict = Depends(require_admin),
    request: Request = None
):
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    seller = await db.users.find_one({'_id': ObjectId(seller_id), 'role': UserRole.SELLER})
    if not seller:
        raise HTTPException(status_code=404, detail="Seller not found")

    now = datetime.utcnow()
    duration_days = max(subscription_data.duration_days or 30, 0)

    if subscription_data.tier == SubscriptionTier.NONE:
        new_subscription = {
            'tier': SubscriptionTier.NONE,
            'is_active': False,
            'started_at': None,
            'expires_at': None,
            'price_paid': 0.0
        }
    else:
        settings = await _get_platform_settings_internal()
        price_map = {
            SubscriptionTier.BRONZE: settings.get('subscriptionBronzePrice', DEFAULT_SUBSCRIPTION_BRONZE_PRICE),
            SubscriptionTier.SILVER: settings.get('subscriptionSilverPrice', DEFAULT_SUBSCRIPTION_SILVER_PRICE),
            SubscriptionTier.GOLD: settings.get('subscriptionGoldPrice', DEFAULT_SUBSCRIPTION_GOLD_PRICE)
        }
        new_subscription = {
            'tier': subscription_data.tier,
            'is_active': True,
            'started_at': now,
            'expires_at': now + timedelta(days=duration_days),
            'price_paid': float(price_map[subscription_data.tier])
        }

    await db.users.update_one(
        {'_id': ObjectId(seller_id)},
        {'$set': {'provider_subscription': new_subscription}}
    )

    await log_admin_audit(
        action='seller.subscription.update',
        actor=current_user,
        target_type='user',
        target_id=seller_id,
        before={'provider_subscription': seller.get('provider_subscription')},
        after={'provider_subscription': new_subscription},
        payload={'tier': subscription_data.tier, 'duration_days': duration_days},
        request=request
    )

    updated_seller = await db.users.find_one({'_id': ObjectId(seller_id)})
    subscription_info = build_seller_subscription_payload(updated_seller)
    return {
        'success': True,
        'sellerId': seller_id,
        'tier': subscription_info['seller_subscription_tier'],
        'badge': subscription_info['seller_subscription_badge'],
        'visibility_boost': subscription_info['seller_visibility_boost'],
        'expires_at': subscription_info['subscription_expires_at']
    }

# Admin Messages Moderation
@api_router.get("/admin/messages/flagged")
async def get_flagged_messages(
    page: int = 1,
    limit: int = 50,
    current_user: dict = Depends(require_admin)
):
    """Get flagged/moderated messages (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Get flagged or blocked messages
        query = {
            '$or': [
                {'violation_type': {'$ne': None}},
                {'is_blocked': True}
            ]
        }

        skip = (page - 1) * limit
        total = await db.messages.count_documents(query)

        messages = await db.messages.find(query).sort('timestamp', -1).skip(skip).limit(limit).to_list(limit)

        # Format response with user details
        messages_list = []
        for msg in messages:
            # Get sender info
            sender = await db.users.find_one({'_id': ObjectId(msg['sender_id'])})

            # Get conversation to find recipient
            conv = await db.conversations.find_one({'id': msg['conversation_id']})
            recipient_id = conv['buyer_id'] if conv and conv['seller_id'] == msg['sender_id'] else conv['seller_id'] if conv else None
            recipient = await db.users.find_one({'_id': ObjectId(recipient_id)}) if recipient_id else None

            messages_list.append({
                'id': msg['id'],
                'conversationId': msg['conversation_id'],
                'senderId': msg['sender_id'],
                'senderName': sender.get('name', 'Unknown') if sender else 'Unknown',
                'senderEmail': sender.get('email', '') if sender else '',
                'recipientId': recipient_id,
                'recipientName': recipient.get('name', 'Unknown') if recipient else 'Unknown',
                'contentOriginal': msg.get('content_original', ''),
                'contentFiltered': msg.get('content_filtered', ''),
                'isBlocked': msg.get('is_blocked', False),
                'violationType': msg.get('violation_type', ''),
                'timestamp': msg.get('timestamp', datetime.utcnow().isoformat()),
                'status': msg.get('status', 'sent')
            })

        return {
            'messages': messages_list,
            'total': total,
            'page': page,
            'limit': limit,
            'totalPages': (total + limit - 1) // limit
        }
    except Exception as e:
        logger.error(f"Error fetching flagged messages: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch flagged messages")

@api_router.post("/admin/messages/{message_id}/moderate")
async def moderate_message(
    message_id: str,
    action: str,  # "approve" or "block"
    current_user: dict = Depends(require_admin)
):
    """Moderate a message - approve or permanently block (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        msg = await db.messages.find_one({'id': message_id})
        if not msg:
            raise HTTPException(status_code=404, detail="Message not found")

        if action == "block":
            # Permanently block the message
            await db.messages.update_one(
                {'id': message_id},
                {'$set': {
                    'is_blocked': True,
                    'status': MessageStatus.BLOCKED,
                    'moderated_by': str(current_user['_id']),
                    'moderated_at': datetime.utcnow()
                }}
            )
            return {'message': 'Message blocked successfully'}

        elif action == "approve":
            # Approve the message (clear violation)
            await db.messages.update_one(
                {'id': message_id},
                {'$set': {
                    'is_blocked': False,
                    'violation_type': None,
                    'moderated_by': str(current_user['_id']),
                    'moderated_at': datetime.utcnow()
                }}
            )
            return {'message': 'Message approved successfully'}

        else:
            raise HTTPException(status_code=400, detail="Invalid action. Use 'approve' or 'block'")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error moderating message: {e}")
        raise HTTPException(status_code=500, detail="Failed to moderate message")

# Admin Reviews Management
@api_router.get("/admin/reviews")
async def get_all_reviews(
    page: int = 1,
    limit: int = 50,
    min_rating: Optional[int] = None,
    max_rating: Optional[int] = None,
    search: Optional[str] = None,
    current_user: dict = Depends(require_admin)
):
    """Get all reviews with filtering (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Build query
        query = {}

        if min_rating:
            query['rating'] = {'$gte': min_rating}
        if max_rating:
            if 'rating' in query:
                query['rating']['$lte'] = max_rating
            else:
                query['rating'] = {'$lte': max_rating}

        skip = (page - 1) * limit
        total = await db.reviews.count_documents(query)

        reviews = await db.reviews.find(query).sort('created_at', -1).skip(skip).limit(limit).to_list(limit)

        # Optimize: Fetch all unique user IDs and service IDs first
        buyer_ids = list(set(review['buyer_id'] for review in reviews))
        seller_ids = list(set(review['seller_id'] for review in reviews))
        service_ids = list(set(
            review.get('service_id') or review.get('pet_id')
            for review in reviews
            if review.get('service_id') or review.get('pet_id')
        ))

        # Batch fetch users
        buyers = {}
        sellers = {}
        if buyer_ids:
            buyer_docs = await db.users.find({'_id': {'$in': [ObjectId(bid) for bid in buyer_ids]}}).to_list(None)
            buyers = {str(u['_id']): u for u in buyer_docs}
        if seller_ids:
            seller_docs = await db.users.find({'_id': {'$in': [ObjectId(sid) for sid in seller_ids]}}).to_list(None)
            sellers = {str(u['_id']): u for u in seller_docs}

        # Batch fetch services
        services = {}
        if service_ids:
            service_docs = await db.service_listings.find(
                {'_id': {'$in': [ObjectId(sid) for sid in service_ids if sid]}}
            ).to_list(None)
            services = {str(s['_id']): s for s in service_docs}

        # Format response with user/service details
        reviews_list = []
        for review in reviews:
            buyer = buyers.get(review['buyer_id'])
            seller = sellers.get(review['seller_id'])
            service_id = review.get('service_id') or review.get('pet_id')
            service = services.get(service_id) if service_id else None

            reviews_list.append({
                'id': str(review['_id']),
                'sellerId': review['seller_id'],
                'sellerName': seller.get('name', 'Unknown') if seller else 'Unknown',
                'buyerId': review['buyer_id'],
                'buyerName': review.get('buyer_name', buyer.get('name', 'Unknown') if buyer else 'Unknown'),
                'orderId': review['order_id'],
                'serviceId': service_id,
                'serviceName': service.get('service_name', 'Unknown') if service else 'Unknown',
                'service_category': service.get('category', 'Unknown') if service else 'Unknown',
                'rating': review['rating'],
                'comment': review['comment'],
                'sellerResponse': review.get('seller_response'),
                'sellerResponseDate': review.get('seller_response_date').isoformat() if review.get('seller_response_date') else None,
                'createdAt': review.get('created_at', datetime.utcnow()).isoformat(),
                'isRemoved': review.get('is_removed', False),
                'removalReason': review.get('removal_reason')
            })

        return {
            'reviews': reviews_list,
            'total': total,
            'page': page,
            'limit': limit,
            'totalPages': (total + limit - 1) // limit
        }
    except Exception as e:
        logger.error(f"Error fetching reviews: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch reviews")

@api_router.post("/admin/reviews/{review_id}/moderate")
async def moderate_review(
    review_id: str,
    action: str,  # "approve" or "remove"
    reason: Optional[str] = None,
    current_user: dict = Depends(require_admin)
):
    """Moderate a review - approve or remove inappropriate reviews (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        review = await db.reviews.find_one({'_id': ObjectId(review_id)})
        if not review:
            raise HTTPException(status_code=404, detail="Review not found")

        if action == "remove":
            # Mark review as removed/hidden
            await db.reviews.update_one(
                {'_id': ObjectId(review_id)},
                {'$set': {
                    'is_removed': True,
                    'removal_reason': reason or 'Violated community guidelines',
                    'moderated_by': str(current_user['_id']),
                    'moderated_at': datetime.utcnow()
                }}
            )

            # Recalculate seller rating
            await update_seller_rating(review['seller_id'])

            # Notify buyer
            try:
                await create_notification(
                    db=db,
                    user_id=review['buyer_id'],
                    notification_type=NotificationType.ORDER_UPDATED,
                    title="Review Removed",
                    message=f"Your review has been removed: {reason or 'Violated community guidelines'}",
                    data={'review_id': review_id}
                )
            except Exception as e:
                logger.error(f"Failed to send notification: {e}")

            return {'message': 'Review removed successfully'}

        elif action == "approve":
            # Approve review (clear any flags)
            await db.reviews.update_one(
                {'_id': ObjectId(review_id)},
                {'$set': {
                    'is_removed': False,
                    'removal_reason': None,
                    'moderated_by': str(current_user['_id']),
                    'moderated_at': datetime.utcnow()
                }}
            )

            # Recalculate seller rating
            await update_seller_rating(review['seller_id'])

            return {'message': 'Review approved successfully'}

        else:
            raise HTTPException(status_code=400, detail="Invalid action. Use 'approve' or 'remove'")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error moderating review: {e}")
        raise HTTPException(status_code=500, detail="Failed to moderate review")

# Admin Transactions Management
@api_router.get("/admin/transactions")
async def get_all_transactions(
    transaction_type: Optional[str] = None,
    status: Optional[str] = None,
    user_id: Optional[str] = None,
    page: int = 1,
    limit: int = 50,
    current_user: dict = Depends(require_admin)
):
    """Get all wallet transactions with filtering and pagination (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Build query filter
        query = {}

        if transaction_type:
            query['transaction_type'] = transaction_type

        if status:
            query['status'] = status

        if user_id:
            query['user_id'] = user_id

        # Calculate pagination
        skip = (page - 1) * limit

        # Get total count
        total = await db.transactions.count_documents(query)

        # Get transactions
        transactions_cursor = db.transactions.find(query).sort('created_at', -1).skip(skip).limit(limit)
        transactions = await transactions_cursor.to_list(length=limit)

        # Format response - enrich with user info
        transactions_list = []
        for txn in transactions:
            # Fetch user info - handle platform wallet specially
            user_id = txn['user_id']
            if user_id == PLATFORM_WALLET_ID:
                # Platform wallet - don't query users collection
                user = None
                user_name = 'Platform'
                user_email = 'platform@petsoko.com'
            else:
                try:
                    user = await db.users.find_one({'_id': ObjectId(user_id)})
                    user_name = user.get('name', 'Unknown') if user else 'Unknown'
                    user_email = user.get('email', '') if user else ''
                except Exception as e:
                    logger.warning(f"Failed to fetch user for transaction {txn['_id']}: {e}")
                    user = None
                    user_name = 'Unknown'
                    user_email = ''

            transactions_list.append({
                'id': str(txn['_id']),
                'userId': txn['user_id'],
                'userName': user_name,
                'userEmail': user_email,
                'orderId': txn.get('order_id'),
                'transactionType': txn.get('transaction_type', 'UNKNOWN'),
                'amount': txn.get('amount', 0),
                'status': txn.get('status', 'PENDING'),
                'description': txn.get('description', ''),
                'referenceId': txn.get('reference_id'),
                'createdAt': txn['created_at'].isoformat() if txn.get('created_at') else None,
            })

        # Calculate summary stats
        total_completed = await db.transactions.count_documents({**query, 'status': 'COMPLETED'})
        total_pending = await db.transactions.count_documents({**query, 'status': 'PENDING'})
        total_failed = await db.transactions.count_documents({**query, 'status': 'FAILED'})

        # Calculate amount totals
        completed_amount_pipeline = [
            {'$match': {**query, 'status': 'COMPLETED'}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
        ]
        completed_result = await db.transactions.aggregate(completed_amount_pipeline).to_list(1)
        total_amount = completed_result[0]['total'] if completed_result else 0

        return {
            'transactions': transactions_list,
            'total': total,
            'page': page,
            'limit': limit,
            'totalPages': (total + limit - 1) // limit,
            'summary': {
                'totalCompleted': total_completed,
                'totalPending': total_pending,
                'totalFailed': total_failed,
                'totalAmount': round(total_amount, 2)
            }
        }
    except Exception as e:
        logger.error(f"Error fetching transactions: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch transactions")

# Admin Analytics
@api_router.get("/admin/analytics")
async def get_analytics(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: dict = Depends(require_admin)
):
    """Get advanced analytics with date range filtering (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Parse dates
        if start_date:
            start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
        else:
            start = datetime.utcnow() - timedelta(days=30)  # Default 30 days

        if end_date:
            end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
        else:
            end = datetime.utcnow()

        # Revenue over time (daily for selected range)
        revenue_pipeline = [
            {'$match': {
                'payment_status': PaymentStatus.PAID,
                'created_at': {'$gte': start, '$lte': end}
            }},
            {'$group': {
                '_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$created_at'}},
                'revenue': {'$sum': '$platform_fee'},
                'orders': {'$sum': 1},
                'total_amount': {'$sum': '$total_amount'}
            }},
            {'$sort': {'_id': 1}}
        ]
        revenue_data = await db.orders.aggregate(revenue_pipeline).to_list(None)

        # User growth (daily signups)
        user_growth_pipeline = [
            {'$match': {'created_at': {'$gte': start, '$lte': end}}},
            {'$group': {
                '_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$created_at'}},
                'newUsers': {'$sum': 1}
            }},
            {'$sort': {'_id': 1}}
        ]
        user_growth = await db.users.aggregate(user_growth_pipeline).to_list(None)

        # Conversion rates
        total_users_in_period = await db.users.count_documents({'created_at': {'$gte': start, '$lte': end}})
        buyers_in_period = await db.orders.distinct('buyer_id', {'created_at': {'$gte': start, '$lte': end}})
        conversion_rate = (len(buyers_in_period) / total_users_in_period * 100) if total_users_in_period > 0 else 0

        # Top sellers
        top_sellers_pipeline = [
            {'$match': {
                'payment_status': PaymentStatus.PAID,
                'created_at': {'$gte': start, '$lte': end}
            }},
            {'$group': {
                '_id': '$seller_id',
                'totalSales': {'$sum': 1},
                'totalRevenue': {'$sum': '$seller_amount'}
            }},
            {'$sort': {'totalRevenue': -1}},
            {'$limit': 10}
        ]
        top_sellers_data = await db.orders.aggregate(top_sellers_pipeline).to_list(10)

        # Enrich with seller names
        top_sellers = []
        for seller_data in top_sellers_data:
            seller = await db.users.find_one({'_id': ObjectId(seller_data['_id'])})
            top_sellers.append({
                'sellerId': seller_data['_id'],
                'sellerName': seller.get('name', 'Unknown') if seller else 'Unknown',
                'totalSales': seller_data['totalSales'],
                'totalRevenue': round(seller_data['totalRevenue'], 2)
            })

        # Service category popularity
        category_pipeline = [
            {'$match': {'created_at': {'$gte': start, '$lte': end}}},
            {'$group': {
                '_id': '$service_category',
                'count': {'$sum': 1}
            }},
            {'$sort': {'count': -1}}
        ]
        category_data = await db.service_listings.aggregate(category_pipeline).to_list(None)

        return {
            'dateRange': {
                'start': start.isoformat(),
                'end': end.isoformat()
            },
            'revenueOverTime': [
                {
                    'date': item['_id'],
                    'revenue': round(item['revenue'], 2),
                    'orders': item['orders'],
                    'totalAmount': round(item['total_amount'], 2)
                }
                for item in revenue_data
            ],
            'userGrowth': [
                {
                    'date': item['_id'],
                    'newUsers': item['newUsers']
                }
                for item in user_growth
            ],
            'conversionRate': round(conversion_rate, 2),
            'topSellers': top_sellers,
            'categoryPopularity': [
                {
                    'category': item['_id'],
                    'count': item['count']
                }
                for item in category_data
            ]
        }
    except Exception as e:
        logger.error(f"Error fetching analytics: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch analytics")

# Admin Notifications Management
@api_router.get("/admin/notifications")
async def get_all_notifications(
    page: int = 1,
    limit: int = 50,
    notification_type: Optional[str] = None,
    current_user: dict = Depends(require_admin)
):
    """Get all platform notifications (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        query = {}
        if notification_type:
            query['type'] = notification_type

        skip = (page - 1) * limit
        total = await db.notifications.count_documents(query)

        notifications = await db.notifications.find(query).sort('created_at', -1).skip(skip).limit(limit).to_list(limit)

        # Format response
        notifications_list = []
        for notif in notifications:
            # Get user info
            user = await db.users.find_one({'_id': ObjectId(notif['user_id'])})

            notifications_list.append({
                'id': str(notif['_id']),
                'userId': notif['user_id'],
                'userName': user.get('name', 'Unknown') if user else 'Unknown',
                'userEmail': user.get('email', '') if user else '',
                'type': notif['type'],
                'title': notif['title'],
                'message': notif['message'],
                'data': notif.get('data', {}),
                'read': notif.get('read', False),
                'pushSent': notif.get('push_sent', False),
                'createdAt': notif.get('created_at', datetime.utcnow()).isoformat()
            })

        return {
            'notifications': notifications_list,
            'total': total,
            'page': page,
            'limit': limit,
            'totalPages': (total + limit - 1) // limit
        }
    except Exception as e:
        logger.error(f"Error fetching notifications: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch notifications")

# Removed old broadcast endpoint - using the modern version below with request body

# Admin Settings Management
# Internal helper function to get platform settings without authentication
async def _get_platform_settings_internal():
    """Internal function to get platform settings without authentication (for internal use only)"""
    try:
        # Get settings from database
        settings = await db.settings.find_one({'key': 'platform_config'})

        # Default settings if not found
        if not settings:
            default_settings = {
                'key': 'platform_config',
                # Financial Settings
                'platformFeePercentage': PLATFORM_FEE_PERCENTAGE * 100,
                'deliveryFeeEscrowHours': 24,
                'unpaidOrderCancellationDays': 7,
                'minimumWithdrawal': 100.0,
                'maximumWithdrawal': 100000.0,
                'verificationFee': VERIFICATION_FEE,

                # Listing Settings
                'maxImagesPerListing': 10,
                'autoApproveListings': False,
                'maxListingDurationDays': 90,
                'requireVetCertificate': True,

                # Order Settings
                'orderConfirmationHours': 72,
                'autoCompleteDeliveryDays': 7,
                'cancellationRefundPercentage': 90.0,
                'sellerCancellationPenaltyPercentage': 10.0,

                # Security Settings
                'minPasswordLength': 8,
                'sessionTimeoutHours': 168,  # 7 days
                'maxLoginAttempts': 5,
                'requireEmailVerification': False,

                # Moderation Settings
                'autoModerationEnabled': True,
                'flaggedContentThreshold': 3,
                'reviewApprovalRequired': False,

                # Communication Settings
                'supportEmail': 'support@petsoko.com',
                'supportPhone': '+254700000000',
                'systemAnnouncement': '',
                'announcementActive': False,

                # Advertisement Settings
                'adImageUrl': '',
                'adLinkUrl': '',
                'adActive': False,
                'adAnimationStyle': 'fade',
                'adDisplayFrequency': 'daily',

                # Notification Settings
                'enableEmailNotifications': True,
                'enableSmsNotifications': False,
                'enablePushNotifications': True,

                # Maintenance
                'maintenanceMode': False,
                'apiRateLimitPerMinute': 60,

                # Seller Subscription Settings
                'subscriptionBronzePrice': DEFAULT_SUBSCRIPTION_BRONZE_PRICE,
                'subscriptionSilverPrice': DEFAULT_SUBSCRIPTION_SILVER_PRICE,
                'subscriptionGoldPrice': DEFAULT_SUBSCRIPTION_GOLD_PRICE,

                # Feature Toggles
                'features': {
                    'enableMpesa': True,
                    'enableWallet': True,
                    'enableCashPayment': True,
                    'enableDelivery': True,
                    'enableReviews': True,
                    'enableChat': True
                },
                'updatedAt': datetime.utcnow()
            }
            # Insert default settings
            await db.settings.insert_one(default_settings)
            settings = default_settings

        return {
            # Financial Settings
            'platformFeePercentage': settings.get('platformFeePercentage', 5.0),
            'deliveryFeeEscrowHours': settings.get('deliveryFeeEscrowHours', 24),
            'unpaidOrderCancellationDays': settings.get('unpaidOrderCancellationDays', 7),
            'minimumWithdrawal': settings.get('minimumWithdrawal', 100.0),
            'maximumWithdrawal': settings.get('maximumWithdrawal', 100000.0),
            'verificationFee': settings.get('verificationFee', VERIFICATION_FEE),

            # Listing Settings
            'maxImagesPerListing': settings.get('maxImagesPerListing', 10),
            'autoApproveListings': settings.get('autoApproveListings', False),
            'maxListingDurationDays': settings.get('maxListingDurationDays', 90),
            'requireVetCertificate': settings.get('requireVetCertificate', True),

            # Order Settings
            'orderConfirmationHours': settings.get('orderConfirmationHours', 72),
            'autoCompleteDeliveryDays': settings.get('autoCompleteDeliveryDays', 7),
            'cancellationRefundPercentage': settings.get('cancellationRefundPercentage', 90.0),
            'sellerCancellationPenaltyPercentage': settings.get('sellerCancellationPenaltyPercentage', 10.0),

            # Security Settings
            'minPasswordLength': settings.get('minPasswordLength', 8),
            'sessionTimeoutHours': settings.get('sessionTimeoutHours', 168),
            'maxLoginAttempts': settings.get('maxLoginAttempts', 5),
            'requireEmailVerification': settings.get('requireEmailVerification', False),

            # Moderation Settings
            'autoModerationEnabled': settings.get('autoModerationEnabled', True),
            'flaggedContentThreshold': settings.get('flaggedContentThreshold', 3),
            'reviewApprovalRequired': settings.get('reviewApprovalRequired', False),

            # Communication Settings
            'supportEmail': settings.get('supportEmail', 'support@petsoko.com'),
            'supportPhone': settings.get('supportPhone', '+254700000000'),
            'systemAnnouncement': settings.get('systemAnnouncement', ''),
            'announcementActive': settings.get('announcementActive', False),

            # Advertisement Settings
            'adImageUrl': settings.get('adImageUrl', ''),
            'adLinkUrl': settings.get('adLinkUrl', ''),
            'adActive': settings.get('adActive', False),
            'adAnimationStyle': settings.get('adAnimationStyle', 'fade'),
            'adDisplayFrequency': settings.get('adDisplayFrequency', 'daily'),

            # Notification Settings
            'enableEmailNotifications': settings.get('enableEmailNotifications', True),
            'enableSmsNotifications': settings.get('enableSmsNotifications', False),
            'enablePushNotifications': settings.get('enablePushNotifications', True),

            # Maintenance
            'maintenanceMode': settings.get('maintenanceMode', False),
            'apiRateLimitPerMinute': settings.get('apiRateLimitPerMinute', 60),

            # Job Posting Settings
            'jobPostingFee': settings.get('jobPostingFee', DEFAULT_JOB_POSTING_FEE),
            'jobPostingPromotionalMessage': settings.get('jobPostingPromotionalMessage', ''),

            # Seller Subscription Settings
            'subscriptionBronzePrice': settings.get('subscriptionBronzePrice', DEFAULT_SUBSCRIPTION_BRONZE_PRICE),
            'subscriptionSilverPrice': settings.get('subscriptionSilverPrice', DEFAULT_SUBSCRIPTION_SILVER_PRICE),
            'subscriptionGoldPrice': settings.get('subscriptionGoldPrice', DEFAULT_SUBSCRIPTION_GOLD_PRICE),

            # Feature Toggles
            'features': settings.get('features', {}),

            'updatedAt': settings.get('updatedAt', datetime.utcnow()).isoformat()
        }
    except Exception as e:
        logger.error(f"Error fetching settings internally: {e}")
        # Return default values instead of raising exception for internal use
        return {
            'platformFeePercentage': 5.0,
            'deliveryFeeEscrowHours': 24,
            'unpaidOrderCancellationDays': 7,
            'minimumWithdrawal': 100.0,
            'maximumWithdrawal': 100000.0,
            'verificationFee': VERIFICATION_FEE,
            'maxImagesPerListing': 10,
            'autoApproveListings': False,
            'maxListingDurationDays': 90,
            'requireVetCertificate': True,
            'orderConfirmationHours': 72,
            'autoCompleteDeliveryDays': 7,
            'cancellationRefundPercentage': 90.0,
            'sellerCancellationPenaltyPercentage': 10.0,
            'minPasswordLength': 8,
            'sessionTimeoutHours': 168,
            'maxLoginAttempts': 5,
            'requireEmailVerification': False,
            'autoModerationEnabled': True,
            'flaggedContentThreshold': 3,
            'reviewApprovalRequired': False,
            'supportEmail': 'support@petsoko.com',
            'supportPhone': '+254700000000',
            'systemAnnouncement': '',
            'announcementActive': False,
            'enableEmailNotifications': True,
            'enableSmsNotifications': False,
            'enablePushNotifications': True,
            'maintenanceMode': False,
            'apiRateLimitPerMinute': 60,
            'jobPostingFee': DEFAULT_JOB_POSTING_FEE,
            'jobPostingPromotionalMessage': '',
            'subscriptionBronzePrice': DEFAULT_SUBSCRIPTION_BRONZE_PRICE,
            'subscriptionSilverPrice': DEFAULT_SUBSCRIPTION_SILVER_PRICE,
            'subscriptionGoldPrice': DEFAULT_SUBSCRIPTION_GOLD_PRICE,
            'features': {},
            'updatedAt': datetime.utcnow().isoformat()
        }

@api_router.get("/admin/settings")
async def get_platform_settings(current_user: dict = Depends(require_admin)):
    """Get platform configuration settings (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    # Use internal function to get settings
    try:
        return await _get_platform_settings_internal()
    except Exception as e:
        logger.error(f"Error fetching settings: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch settings")

@api_router.put("/admin/settings")
async def update_platform_settings(
    settings_update: PlatformSettingsUpdate,
    current_user: dict = Depends(require_admin),
    request: Request = None
):
    """Update platform configuration settings (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        before_settings = await _get_platform_settings_internal()

        # Build update document
        update_doc = {'updatedAt': datetime.utcnow()}

        # Financial Settings
        if settings_update.platform_fee_percentage is not None:
            update_doc['platformFeePercentage'] = settings_update.platform_fee_percentage
        if settings_update.delivery_fee_escrow_hours is not None:
            update_doc['deliveryFeeEscrowHours'] = settings_update.delivery_fee_escrow_hours
        if settings_update.unpaid_order_cancellation_days is not None:
            update_doc['unpaidOrderCancellationDays'] = settings_update.unpaid_order_cancellation_days
        if settings_update.minimum_withdrawal is not None:
            update_doc['minimumWithdrawal'] = settings_update.minimum_withdrawal
        if settings_update.maximum_withdrawal is not None:
            update_doc['maximumWithdrawal'] = settings_update.maximum_withdrawal
        if settings_update.verification_fee is not None:
            if settings_update.verification_fee < 0:
                raise HTTPException(status_code=400, detail="Verification fee cannot be negative")
            update_doc['verificationFee'] = settings_update.verification_fee

        # Listing Settings
        if settings_update.max_images_per_listing is not None:
            update_doc['maxImagesPerListing'] = settings_update.max_images_per_listing
        if settings_update.auto_approve_listings is not None:
            update_doc['autoApproveListings'] = settings_update.auto_approve_listings
        if settings_update.max_listing_duration_days is not None:
            update_doc['maxListingDurationDays'] = settings_update.max_listing_duration_days
        if settings_update.require_vet_certificate is not None:
            update_doc['requireVetCertificate'] = settings_update.require_vet_certificate

        # Order Settings
        if settings_update.order_confirmation_hours is not None:
            update_doc['orderConfirmationHours'] = settings_update.order_confirmation_hours
        if settings_update.auto_complete_delivery_days is not None:
            update_doc['autoCompleteDeliveryDays'] = settings_update.auto_complete_delivery_days
        if settings_update.cancellation_refund_percentage is not None:
            update_doc['cancellationRefundPercentage'] = settings_update.cancellation_refund_percentage
        if settings_update.seller_cancellation_penalty_percentage is not None:
            update_doc['sellerCancellationPenaltyPercentage'] = settings_update.seller_cancellation_penalty_percentage

        # Security Settings
        if settings_update.min_password_length is not None:
            update_doc['minPasswordLength'] = settings_update.min_password_length
        if settings_update.session_timeout_hours is not None:
            update_doc['sessionTimeoutHours'] = settings_update.session_timeout_hours
        if settings_update.max_login_attempts is not None:
            update_doc['maxLoginAttempts'] = settings_update.max_login_attempts
        if settings_update.require_email_verification is not None:
            update_doc['requireEmailVerification'] = settings_update.require_email_verification

        # Moderation Settings
        if settings_update.auto_moderation_enabled is not None:
            update_doc['autoModerationEnabled'] = settings_update.auto_moderation_enabled
        if settings_update.flagged_content_threshold is not None:
            update_doc['flaggedContentThreshold'] = settings_update.flagged_content_threshold
        if settings_update.review_approval_required is not None:
            update_doc['reviewApprovalRequired'] = settings_update.review_approval_required

        # Communication Settings
        if settings_update.support_email is not None:
            update_doc['supportEmail'] = settings_update.support_email
        if settings_update.support_phone is not None:
            update_doc['supportPhone'] = settings_update.support_phone
        if settings_update.system_announcement is not None:
            update_doc['systemAnnouncement'] = settings_update.system_announcement
        if settings_update.announcement_active is not None:
            update_doc['announcementActive'] = settings_update.announcement_active

        # Advertisement Settings
        if settings_update.ad_image_url is not None:
            update_doc['adImageUrl'] = settings_update.ad_image_url
        if settings_update.ad_link_url is not None:
            # Validate ad link URL (basic validation for security)
            ad_link = settings_update.ad_link_url.strip()
            if ad_link:  # Only validate if not empty
                if not ad_link.startswith(('http://', 'https://')):
                    raise HTTPException(
                        status_code=400,
                        detail="Advertisement link URL must start with http:// or https://"
                    )
                # Recommend HTTPS for security but allow HTTP for testing
                if not ad_link.startswith('https://'):
                    logger.warning(f"Ad link URL uses HTTP instead of HTTPS: {ad_link}")
            update_doc['adLinkUrl'] = ad_link
        if settings_update.ad_active is not None:
            update_doc['adActive'] = settings_update.ad_active
        if settings_update.ad_animation_style is not None:
            update_doc['adAnimationStyle'] = settings_update.ad_animation_style
        if settings_update.ad_display_frequency is not None:
            # Valid frequencies: 'once', 'daily', 'every_6_hours', 'every_2_hours', 'always', 'testing' (2 minutes)
            valid_frequencies = ['once', 'daily', 'every_6_hours', 'every_2_hours', 'always', 'testing']
            if settings_update.ad_display_frequency in valid_frequencies:
                update_doc['adDisplayFrequency'] = settings_update.ad_display_frequency
            else:
                logger.warning(f"Invalid ad display frequency: {settings_update.ad_display_frequency}, using default 'daily'")
                update_doc['adDisplayFrequency'] = 'daily'

        # Notification Settings
        if settings_update.enable_email_notifications is not None:
            update_doc['enableEmailNotifications'] = settings_update.enable_email_notifications
        if settings_update.enable_sms_notifications is not None:
            update_doc['enableSmsNotifications'] = settings_update.enable_sms_notifications
        if settings_update.enable_push_notifications is not None:
            update_doc['enablePushNotifications'] = settings_update.enable_push_notifications

        # Maintenance
        if settings_update.maintenance_mode is not None:
            update_doc['maintenanceMode'] = settings_update.maintenance_mode
        if settings_update.api_rate_limit_per_minute is not None:
            update_doc['apiRateLimitPerMinute'] = settings_update.api_rate_limit_per_minute

        # Job Posting Settings
        if settings_update.jobPostingFee is not None:
            if settings_update.jobPostingFee < 0:
                raise HTTPException(status_code=400, detail="Job posting fee cannot be negative")
            update_doc['jobPostingFee'] = settings_update.jobPostingFee
        if settings_update.jobPostingPromotionalMessage is not None:
            update_doc['jobPostingPromotionalMessage'] = settings_update.jobPostingPromotionalMessage

        # Seller Subscription Settings
        if settings_update.subscriptionBronzePrice is not None:
            if settings_update.subscriptionBronzePrice < 0:
                raise HTTPException(status_code=400, detail="Bronze subscription price cannot be negative")
            update_doc['subscriptionBronzePrice'] = settings_update.subscriptionBronzePrice
        if settings_update.subscriptionSilverPrice is not None:
            if settings_update.subscriptionSilverPrice < 0:
                raise HTTPException(status_code=400, detail="Silver subscription price cannot be negative")
            update_doc['subscriptionSilverPrice'] = settings_update.subscriptionSilverPrice
        if settings_update.subscriptionGoldPrice is not None:
            if settings_update.subscriptionGoldPrice < 0:
                raise HTTPException(status_code=400, detail="Gold subscription price cannot be negative")
            update_doc['subscriptionGoldPrice'] = settings_update.subscriptionGoldPrice

        # Feature Toggles
        if settings_update.features is not None:
            update_doc['features'] = settings_update.features

        # Update settings
        result = await db.settings.update_one(
            {'key': 'platform_config'},
            {'$set': update_doc},
            upsert=True
        )

        # Invalidate cache to force fresh fetch
        invalidate_settings_cache()

        # Get updated settings  (reuse the GET endpoint logic)
        updated_settings = await db.settings.find_one({'key': 'platform_config'})

        response_settings = {
            # Financial Settings
            'platformFeePercentage': updated_settings.get('platformFeePercentage', 5.0),
            'deliveryFeeEscrowHours': updated_settings.get('deliveryFeeEscrowHours', 24),
            'unpaidOrderCancellationDays': updated_settings.get('unpaidOrderCancellationDays', 7),
            'minimumWithdrawal': updated_settings.get('minimumWithdrawal', 100.0),
            'maximumWithdrawal': updated_settings.get('maximumWithdrawal', 100000.0),
            'verificationFee': updated_settings.get('verificationFee', VERIFICATION_FEE),

            # Listing Settings
            'maxImagesPerListing': updated_settings.get('maxImagesPerListing', 10),
            'autoApproveListings': updated_settings.get('autoApproveListings', False),
            'maxListingDurationDays': updated_settings.get('maxListingDurationDays', 90),
            'requireVetCertificate': updated_settings.get('requireVetCertificate', True),

            # Order Settings
            'orderConfirmationHours': updated_settings.get('orderConfirmationHours', 72),
            'autoCompleteDeliveryDays': updated_settings.get('autoCompleteDeliveryDays', 7),
            'cancellationRefundPercentage': updated_settings.get('cancellationRefundPercentage', 90.0),
            'sellerCancellationPenaltyPercentage': updated_settings.get('sellerCancellationPenaltyPercentage', 10.0),

            # Security Settings
            'minPasswordLength': updated_settings.get('minPasswordLength', 8),
            'sessionTimeoutHours': updated_settings.get('sessionTimeoutHours', 168),
            'maxLoginAttempts': updated_settings.get('maxLoginAttempts', 5),
            'requireEmailVerification': updated_settings.get('requireEmailVerification', False),

            # Moderation Settings
            'autoModerationEnabled': updated_settings.get('autoModerationEnabled', True),
            'flaggedContentThreshold': updated_settings.get('flaggedContentThreshold', 3),
            'reviewApprovalRequired': updated_settings.get('reviewApprovalRequired', False),

            # Communication Settings
            'supportEmail': updated_settings.get('supportEmail', 'support@petsoko.com'),
            'supportPhone': updated_settings.get('supportPhone', '+254700000000'),
            'systemAnnouncement': updated_settings.get('systemAnnouncement', ''),
            'announcementActive': updated_settings.get('announcementActive', False),

            # Advertisement Settings
            'adImageUrl': updated_settings.get('adImageUrl', ''),
            'adLinkUrl': updated_settings.get('adLinkUrl', ''),
            'adActive': updated_settings.get('adActive', False),
            'adAnimationStyle': updated_settings.get('adAnimationStyle', 'fade'),
            'adDisplayFrequency': updated_settings.get('adDisplayFrequency', 'daily'),

            # Notification Settings
            'enableEmailNotifications': updated_settings.get('enableEmailNotifications', True),
            'enableSmsNotifications': updated_settings.get('enableSmsNotifications', False),
            'enablePushNotifications': updated_settings.get('enablePushNotifications', True),

            # Maintenance
            'maintenanceMode': updated_settings.get('maintenanceMode', False),
            'apiRateLimitPerMinute': updated_settings.get('apiRateLimitPerMinute', 60),

            # Job Posting Settings
            'jobPostingFee': updated_settings.get('jobPostingFee', DEFAULT_JOB_POSTING_FEE),
            'jobPostingPromotionalMessage': updated_settings.get('jobPostingPromotionalMessage', ''),

            # Seller Subscription Settings
            'subscriptionBronzePrice': updated_settings.get('subscriptionBronzePrice', DEFAULT_SUBSCRIPTION_BRONZE_PRICE),
            'subscriptionSilverPrice': updated_settings.get('subscriptionSilverPrice', DEFAULT_SUBSCRIPTION_SILVER_PRICE),
            'subscriptionGoldPrice': updated_settings.get('subscriptionGoldPrice', DEFAULT_SUBSCRIPTION_GOLD_PRICE),

            # Feature Toggles
            'features': updated_settings.get('features', {}),

            'updatedAt': updated_settings.get('updatedAt', datetime.utcnow()).isoformat()
        }

        await log_admin_audit(
            action='platform_settings.update',
            actor=current_user,
            target_type='settings',
            target_id='platform_config',
            before=before_settings,
            after=response_settings,
            payload=settings_update.dict(exclude_none=True),
            request=request
        )

        return {
            'success': True,
            'message': 'Settings updated successfully',
            'settings': response_settings
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating settings: {e}")
        raise HTTPException(status_code=500, detail="Failed to update settings")

# Public Settings Endpoint (for frontend app)
@api_router.get("/settings")
async def get_public_settings():
    """Get public platform settings (accessible to all users)"""
    try:
        # Get settings from database
        settings = await db.settings.find_one({'key': 'platform_config'})

        # Default settings if not found
        if not settings:
            default_settings = {
                'key': 'platform_config',
                # Financial Settings
                'platformFeePercentage': PLATFORM_FEE_PERCENTAGE * 100,
                'minimumWithdrawal': 100.0,
                'maximumWithdrawal': 100000.0,
                'verificationFee': VERIFICATION_FEE,

                # Listing Settings
                'maxImagesPerListing': 10,

                # Communication Settings
                'supportEmail': 'support@petsoko.com',
                'supportPhone': '+254700000000',
                'systemAnnouncement': '',
                'announcementActive': False,

                # Advertisement Settings
                'adImageUrl': '',
                'adLinkUrl': '',
                'adActive': False,
                'adAnimationStyle': 'fade',
                'adDisplayFrequency': 'daily',

                # Maintenance
                'maintenanceMode': False,

                # Seller Subscription Settings
                'subscriptionBronzePrice': DEFAULT_SUBSCRIPTION_BRONZE_PRICE,
                'subscriptionSilverPrice': DEFAULT_SUBSCRIPTION_SILVER_PRICE,
                'subscriptionGoldPrice': DEFAULT_SUBSCRIPTION_GOLD_PRICE,

                # Feature Toggles
                'features': {
                    'enableMpesa': True,
                    'enableWallet': True,
                    'enableCashPayment': True,
                    'enableDelivery': True,
                    'enableReviews': True,
                    'enableChat': True
                },
                'updatedAt': datetime.utcnow()
            }
            # Insert default settings
            await db.settings.insert_one(default_settings)
            settings = default_settings

        # Return only public-facing settings
        return {
            # Financial Settings (public info)
            'platformFeePercentage': settings.get('platformFeePercentage', 5.0),
            'minimumWithdrawal': settings.get('minimumWithdrawal', 100.0),
            'maximumWithdrawal': settings.get('maximumWithdrawal', 100000.0),
            'verificationFee': settings.get('verificationFee', VERIFICATION_FEE),

            # Listing Settings (public info)
            'maxImagesPerListing': settings.get('maxImagesPerListing', 10),

            # Communication Settings (public info)
            'supportEmail': settings.get('supportEmail', 'support@petsoko.com'),
            'supportPhone': settings.get('supportPhone', '+254700000000'),
            'systemAnnouncement': settings.get('systemAnnouncement', ''),
            'announcementActive': settings.get('announcementActive', False),

            # Advertisement Settings (public info)
            'adImageUrl': settings.get('adImageUrl', ''),
            'adLinkUrl': settings.get('adLinkUrl', ''),
            'adActive': settings.get('adActive', False),
            'adAnimationStyle': settings.get('adAnimationStyle', 'fade'),
            'adDisplayFrequency': settings.get('adDisplayFrequency', 'daily'),

            # Maintenance (public info)
            'maintenanceMode': settings.get('maintenanceMode', False),

            # Seller Subscription Settings (public info)
            'subscriptionBronzePrice': settings.get('subscriptionBronzePrice', DEFAULT_SUBSCRIPTION_BRONZE_PRICE),
            'subscriptionSilverPrice': settings.get('subscriptionSilverPrice', DEFAULT_SUBSCRIPTION_SILVER_PRICE),
            'subscriptionGoldPrice': settings.get('subscriptionGoldPrice', DEFAULT_SUBSCRIPTION_GOLD_PRICE),

            # Feature Toggles (public info)
            'features': settings.get('features', {
                'enableMpesa': True,
                'enableWallet': True,
                'enableCashPayment': True,
                'enableDelivery': True,
                'enableReviews': True,
                'enableChat': True
            }),

            'updatedAt': settings.get('updatedAt', datetime.utcnow()).isoformat()
        }
    except Exception as e:
        logger.error(f"Error fetching public settings: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch settings")

# Notification Routes
@api_router.post("/notifications/register-token")
async def register_push_token(
    token_data: PushTokenUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Register or update user's push notification token"""
    user_id = str(current_user['_id'])

    logger.info(f"🔔 [PUSH] Registering FCM token for user {user_id}")
    logger.info(f"🔔 [PUSH] Token: {token_data.fcm_token[:50]}...")

    result = await db.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'fcm_token': token_data.fcm_token}}
    )

    if result.modified_count > 0:
        logger.info(f"🔔 [PUSH] ✅ FCM token updated successfully for user {user_id}")
    else:
        logger.info(f"🔔 [PUSH] ⚠️ FCM token unchanged (same token) for user {user_id}")

    # Verify it was saved
    user = await db.users.find_one({'_id': ObjectId(user_id)})
    if user and user.get('fcm_token'):
        logger.info(f"🔔 [PUSH] ✅ Verified token is saved in database")
    else:
        logger.error(f"🔔 [PUSH] ❌ Token NOT found in database after save!")

    return {'success': True, 'message': 'FCM token registered'}

@api_router.post("/notifications/test-push")
async def test_push_notification(current_user: dict = Depends(get_current_user)):
    """Send a test push notification to the current user"""
    from notification_service import NotificationService

    user_id = str(current_user['_id'])
    logger.info(f"🔔 [TEST] Test push notification requested for user {user_id}")

    # Get user's push token
    user = await db.users.find_one({'_id': ObjectId(user_id)})

    if not user:
        logger.error(f"🔔 [TEST] ❌ User not found: {user_id}")
        return {'success': False, 'message': 'User not found'}

    fcm_token = user.get('fcm_token')
    if not fcm_token:
        logger.warning(f"🔔 [TEST] ⚠️ User has no FCM token registered")
        return {
            'success': False,
            'message': 'No FCM token registered. Please ensure notifications are enabled and you are logged in.'
        }

    logger.info(f"🔔 [TEST] Found FCM token: {fcm_token[:50]}...")

    # Send test notification
    success = NotificationService.send_push_notification(
        fcm_token=fcm_token,
        title='🔔 Test Notification',
        body='This is a test push notification from PetSoko! If you see this, push notifications are working! 🎉',
        data={'type': 'test', 'test_id': '123'}
    )

    if success:
        logger.info(f"🔔 [TEST] ✅ Test notification sent successfully")
        return {
            'success': True,
            'message': 'Test notification sent! Check your device.',
            'fcm_token': fcm_token[:20] + '...'
        }
    else:
        logger.error(f"🔔 [TEST] ❌ Test notification failed to send")
        return {
            'success': False,
            'message': 'Failed to send test notification. Check backend logs for details.',
            'fcm_token': fcm_token[:20] + '...'
        }

@api_router.get("/notifications", response_model=List[NotificationResponse])
async def get_notifications(
    skip: int = 0,
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """Get user's notifications"""
    user_id = str(current_user['_id'])

    notifications = await db.notifications.find(
        {'user_id': user_id}
    ).sort('created_at', -1).skip(skip).limit(limit).to_list(limit)

    result = []
    for notif in notifications:
        result.append({
            'id': str(notif['_id']),
            'type': notif['type'],
            'title': notif['title'],
            'message': notif['message'],
            'data': notif.get('data', {}),
            'read': notif.get('read', False),
            'created_at': notif['created_at'].isoformat()
        })

    return result

@api_router.get("/notifications/unread-count")
async def get_unread_count(current_user: dict = Depends(get_current_user)):
    """Get count of unread notifications"""
    user_id = str(current_user['_id'])

    count = await db.notifications.count_documents({
        'user_id': user_id,
        'read': False
    })

    return {'count': count}

@api_router.patch("/notifications/{notification_id}/read")
async def mark_notification_read(
    notification_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Mark a notification as read"""
    user_id = str(current_user['_id'])

    try:
        result = await db.notifications.update_one(
            {
                '_id': ObjectId(notification_id),
                'user_id': user_id
            },
            {'$set': {'read': True}}
        )

        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Notification not found")

        return {'success': True}
    except:
        raise HTTPException(status_code=400, detail="Invalid notification ID")

@api_router.patch("/notifications/mark-all-read")
async def mark_all_read(current_user: dict = Depends(get_current_user)):
    """Mark all notifications as read"""
    user_id = str(current_user['_id'])

    result = await db.notifications.update_many(
        {'user_id': user_id, 'read': False},
        {'$set': {'read': True}}
    )

    return {'success': True, 'marked_read': result.modified_count}

@api_router.delete("/notifications/{notification_id}")
async def delete_notification(
    notification_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a notification"""
    user_id = str(current_user['_id'])

    try:
        result = await db.notifications.delete_one({
            '_id': ObjectId(notification_id),
            'user_id': user_id
        })

        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Notification not found")

        return {'success': True}
    except:
        raise HTTPException(status_code=400, detail="Invalid notification ID")

@api_router.get("/notifications/diagnostic")
async def notification_diagnostic(current_user: dict = Depends(get_current_user)):
    """
    Comprehensive diagnostic check for notification system
    Helps identify why notifications aren't working
    """
    try:
        logger.info("🔍 Running notification diagnostic...")

        diagnostic_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'user_id': str(current_user['_id']),
            'checks': {}
        }

        # 1. Check Firebase Configuration
        firebase_check = {
            'status': 'unknown',
            'details': {}
        }

        firebase_json = os.getenv('FIREBASE_SERVICE_ACCOUNT_JSON')
        firebase_path = os.getenv('FIREBASE_SERVICE_ACCOUNT_PATH')

        if firebase_json:
            try:
                import json
                config = json.loads(firebase_json)
                required_fields = ['project_id', 'private_key', 'client_email']
                missing = [f for f in required_fields if f not in config]

                if missing:
                    firebase_check['status'] = 'error'
                    firebase_check['details'] = {
                        'configured': True,
                        'valid': False,
                        'missing_fields': missing
                    }
                else:
                    firebase_check['status'] = 'ok'
                    firebase_check['details'] = {
                        'configured': True,
                        'valid': True,
                        'project_id': config.get('project_id')
                    }
            except json.JSONDecodeError:
                firebase_check['status'] = 'error'
                firebase_check['details'] = {
                    'configured': True,
                    'valid': False,
                    'error': 'Invalid JSON'
                }
        elif firebase_path and os.path.exists(firebase_path):
            firebase_check['status'] = 'ok'
            firebase_check['details'] = {
                'configured': True,
                'valid': True,
                'source': 'file',
                'path': firebase_path
            }
        else:
            firebase_check['status'] = 'error'
            firebase_check['details'] = {
                'configured': False,
                'message': 'No Firebase credentials found. Push notifications will not work.'
            }

        diagnostic_results['checks']['firebase'] = firebase_check

        # 2. Check Current User's FCM Token
        user_check = {
            'status': 'unknown',
            'details': {}
        }

        user = await db.users.find_one({'_id': current_user['_id']})
        fcm_token = user.get('fcm_token') if user else None

        if fcm_token:
            user_check['status'] = 'ok'
            user_check['details'] = {
                'has_token': True,
                'token_preview': fcm_token[:30] + '...' if len(fcm_token) > 30 else fcm_token
            }
        else:
            user_check['status'] = 'warning'
            user_check['details'] = {
                'has_token': False,
                'message': 'No FCM token registered. Login on a physical device with EAS build.'
            }

        diagnostic_results['checks']['user_token'] = user_check

        # 3. Check Recent Notifications for Current User
        notifications_check = {
            'status': 'unknown',
            'details': {}
        }

        total_notifs = await db.notifications.count_documents({'user_id': str(current_user['_id'])})
        unread_notifs = await db.notifications.count_documents({'user_id': str(current_user['_id']), 'read': False})

        recent_notifs = await db.notifications.find(
            {'user_id': str(current_user['_id'])}
        ).sort('created_at', -1).limit(5).to_list(5)

        notifications_check['status'] = 'ok' if total_notifs > 0 else 'warning'
        notifications_check['details'] = {
            'total': total_notifs,
            'unread': unread_notifs,
            'recent_count': len(recent_notifs),
            'recent_types': [n.get('type') for n in recent_notifs]
        }

        diagnostic_results['checks']['notifications'] = notifications_check

        # 4. Check Recent Orders
        orders_check = {
            'status': 'unknown',
            'details': {}
        }

        user_id = str(current_user['_id'])
        recent_orders = await db.orders.find({
            '$or': [
                {'buyer_id': user_id},
                {'seller_id': user_id}
            ]
        }).sort('created_at', -1).limit(5).to_list(5)

        orders_with_notifs = 0
        for order in recent_orders:
            order_id = str(order['_id'])
            has_notif = await db.notifications.find_one({
                'user_id': user_id,
                'data.order_id': order_id
            })
            if has_notif:
                orders_with_notifs += 1

        orders_check['status'] = 'ok'
        orders_check['details'] = {
            'total_recent_orders': len(recent_orders),
            'orders_with_notifications': orders_with_notifs,
            'orders_without_notifications': len(recent_orders) - orders_with_notifs
        }

        diagnostic_results['checks']['orders'] = orders_check

        # 5. Overall Status
        all_ok = (
            firebase_check['status'] == 'ok' and
            user_check['status'] == 'ok' and
            notifications_check['status'] == 'ok'
        )

        diagnostic_results['overall_status'] = 'healthy' if all_ok else 'issues_found'

        # 6. Recommendations
        recommendations = []

        if firebase_check['status'] == 'error':
            recommendations.append({
                'priority': 'critical',
                'issue': 'Firebase not configured',
                'action': 'Set FIREBASE_SERVICE_ACCOUNT_JSON environment variable with Firebase credentials'
            })

        if user_check['status'] == 'warning':
            recommendations.append({
                'priority': 'high',
                'issue': 'No FCM token registered',
                'action': 'Logout and login again on a physical device with EAS build to register for notifications'
            })

        if len(recent_orders) > 0 and orders_with_notifs == 0:
            recommendations.append({
                'priority': 'high',
                'issue': 'Orders created but no notifications',
                'action': 'Check backend logs for errors during notification creation'
            })

        diagnostic_results['recommendations'] = recommendations

        logger.info(f"🔍 Diagnostic complete. Status: {diagnostic_results['overall_status']}")

        return diagnostic_results

    except Exception as e:
        logger.error(f"Error running diagnostic: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Diagnostic failed: {str(e)}")

# ============================================================================
# ADMIN NOTIFICATION MANAGEMENT ENDPOINTS
# ============================================================================

@api_router.get("/admin/notifications")
async def get_all_notifications_admin(
    user_id: Optional[str] = None,
    notification_type: Optional[str] = None,
    read: Optional[bool] = None,
    search: Optional[str] = None,
    page: int = 1,
    limit: int = 50,
    current_user: dict = Depends(require_admin)
):
    """Get all notifications with filtering (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Build query filter
        query = {}

        if user_id:
            query['user_id'] = user_id

        if notification_type:
            query['type'] = notification_type

        if read is not None:
            query['read'] = read

        if search:
            query['$or'] = [
                {'title': {'$regex': search, '$options': 'i'}},
                {'message': {'$regex': search, '$options': 'i'}}
            ]

        # Calculate pagination
        skip = (page - 1) * limit

        # Get total count
        total = await db.notifications.count_documents(query)

        # Get notifications
        notifications_cursor = db.notifications.find(query).sort('created_at', -1).skip(skip).limit(limit)
        notifications = await notifications_cursor.to_list(length=limit)

        # Format response and get user info
        notifications_list = []
        for notif in notifications:
            # Get user info
            user = await db.users.find_one({'_id': ObjectId(notif['user_id'])})
            user_name = user.get('name', 'Unknown') if user else 'Unknown'
            user_email = user.get('email', 'N/A') if user else 'N/A'

            notifications_list.append({
                'id': str(notif['_id']),
                'userId': notif['user_id'],
                'userName': user_name,
                'userEmail': user_email,
                'type': notif['type'],
                'title': notif['title'],
                'message': notif['message'],
                'data': notif.get('data', {}),
                'read': notif.get('read', False),
                'createdAt': notif['created_at'].isoformat()
            })

        return {
            'notifications': notifications_list,
            'total': total,
            'page': page,
            'limit': limit,
            'totalPages': (total + limit - 1) // limit
        }
    except Exception as e:
        logger.error(f"Error fetching notifications: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch notifications")

@api_router.get("/admin/notifications/stats")
async def get_notifications_stats(current_user: dict = Depends(require_admin)):
    """Get notification statistics (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Total notifications
        total_notifications = await db.notifications.count_documents({})

        # Count by read status
        total_read = await db.notifications.count_documents({'read': True})
        total_unread = await db.notifications.count_documents({'read': False})

        # Count by type
        type_pipeline = [
            {'$group': {'_id': '$type', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}}
        ]
        type_result = await db.notifications.aggregate(type_pipeline).to_list(None)
        notifications_by_type = [{'type': item['_id'], 'count': item['count']} for item in type_result]

        # Recent activity (last 7 days)
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        new_notifications_week = await db.notifications.count_documents({'created_at': {'$gte': seven_days_ago}})

        # Notifications per day (last 7 days)
        daily_pipeline = [
            {'$match': {'created_at': {'$gte': seven_days_ago}}},
            {'$group': {
                '_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$created_at'}},
                'count': {'$sum': 1}
            }},
            {'$sort': {'_id': 1}}
        ]
        daily_result = await db.notifications.aggregate(daily_pipeline).to_list(None)
        notifications_per_day = [{'date': item['_id'], 'count': item['count']} for item in daily_result]

        # Users with FCM tokens
        users_with_fcm = await db.users.count_documents({'fcm_token': {'$exists': True, '$ne': None}})
        total_users = await db.users.count_documents({})

        return {
            'totalNotifications': total_notifications,
            'totalRead': total_read,
            'totalUnread': total_unread,
            'newNotificationsWeek': new_notifications_week,
            'notificationsByType': notifications_by_type,
            'notificationsPerDay': notifications_per_day,
            'pushCapability': {
                'usersWithFcm': users_with_fcm,
                'totalUsers': total_users,
                'percentage': round((users_with_fcm / total_users * 100), 2) if total_users > 0 else 0
            }
        }
    except Exception as e:
        logger.error(f"Error fetching notification stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch notification statistics")

class BulkNotificationRequest(BaseModel):
    user_ids: List[str]
    title: str
    message: str
    notification_type: str = "admin_announcement"
    data: Optional[Dict] = None
    send_push: bool = True

@api_router.post("/admin/notifications/send-bulk")
async def send_bulk_notifications(
    request: BulkNotificationRequest,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """Send bulk notifications to multiple users (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        logger.info(f"🔔 [ADMIN] Sending bulk notification to {len(request.user_ids)} users")
        logger.info(f"🔔 [ADMIN] Title: {request.title}")

        success_count = 0
        failed_count = 0
        notifications_created = []

        for user_id in request.user_ids:
            try:
                # Validate user exists
                user = await db.users.find_one({'_id': ObjectId(user_id)})
                if not user:
                    logger.warning(f"🔔 [ADMIN] User not found: {user_id}")
                    failed_count += 1
                    continue

                # Create notification
                notification = await create_notification(
                    db=db,
                    user_id=user_id,
                    notification_type=request.notification_type,
                    title=request.title,
                    message=request.message,
                    data=request.data or {},
                    send_push=request.send_push
                )

                notifications_created.append(str(notification['_id']))
                success_count += 1
                logger.info(f"🔔 [ADMIN] ✅ Notification sent to user {user_id}")

            except Exception as e:
                logger.error(f"🔔 [ADMIN] ❌ Failed to send notification to user {user_id}: {e}")
                failed_count += 1

        logger.info(f"🔔 [ADMIN] Bulk notification complete: {success_count} success, {failed_count} failed")

        await log_admin_audit(
            action='notifications.send_bulk',
            actor=current_user,
            target_type='notification',
            target_id=None,
            payload={
                'title': request.title,
                'message': request.message,
                'notification_type': request.notification_type,
                'send_push': request.send_push,
                'user_count': len(request.user_ids),
                'success_count': success_count,
                'failed_count': failed_count
            },
            request=http_request
        )

        return {
            'success': True,
            'successCount': success_count,
            'failedCount': failed_count,
            'notificationsCreated': notifications_created,
            'message': f'Sent {success_count} notifications successfully'
        }

    except Exception as e:
        logger.error(f"Error sending bulk notifications: {e}")
        raise HTTPException(status_code=500, detail="Failed to send bulk notifications")

@api_router.post("/admin/notifications/broadcast")
async def broadcast_notification(
    request: BulkNotificationRequest,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """Broadcast notification to all users (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        logger.info(f"🔔 [ADMIN] Broadcasting notification to all users")
        logger.info(f"🔔 [ADMIN] Title: {request.title}")

        # Get all users
        users = await db.users.find({}).to_list(None)
        user_ids = [str(user['_id']) for user in users]

        logger.info(f"🔔 [ADMIN] Found {len(user_ids)} users for broadcast")

        success_count = 0
        failed_count = 0
        notifications_created = []

        for user_id in user_ids:
            try:
                # Create notification
                notification = await create_notification(
                    db=db,
                    user_id=user_id,
                    notification_type=request.notification_type,
                    title=request.title,
                    message=request.message,
                    data=request.data or {},
                    send_push=request.send_push
                )

                notifications_created.append(str(notification['_id']))
                success_count += 1

            except Exception as e:
                logger.error(f"🔔 [ADMIN] ❌ Failed to send notification to user {user_id}: {e}")
                failed_count += 1

        logger.info(f"🔔 [ADMIN] Broadcast complete: {success_count} success, {failed_count} failed")

        await log_admin_audit(
            action='notifications.broadcast',
            actor=current_user,
            target_type='notification',
            target_id=None,
            payload={
                'title': request.title,
                'message': request.message,
                'notification_type': request.notification_type,
                'send_push': request.send_push,
                'user_count': len(user_ids),
                'success_count': success_count,
                'failed_count': failed_count
            },
            request=http_request
        )

        return {
            'success': True,
            'successCount': success_count,
            'failedCount': failed_count,
            'totalUsers': len(user_ids),
            'notificationsCreated': notifications_created,
            'message': f'Broadcast sent to {success_count} users successfully'
        }

    except Exception as e:
        logger.error(f"Error broadcasting notification: {e}")
        raise HTTPException(status_code=500, detail="Failed to broadcast notification")

@api_router.delete("/admin/notifications/{notification_id}")
async def delete_notification_admin(
    notification_id: str,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """Delete a notification (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        result = await db.notifications.delete_one({
            '_id': ObjectId(notification_id)
        })

        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Notification not found")

        await log_admin_audit(
            action='notifications.delete',
            actor=current_user,
            target_type='notification',
            target_id=notification_id,
            payload=None,
            request=http_request
        )

        return {'success': True, 'message': 'Notification deleted successfully'}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting notification: {e}")
        raise HTTPException(status_code=400, detail="Invalid notification ID")

@api_router.patch("/admin/notifications/{notification_id}/read")
async def mark_notification_read_admin(
    notification_id: str,
    read_status: bool = True,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """Mark a notification as read/unread (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        result = await db.notifications.update_one(
            {'_id': ObjectId(notification_id)},
            {'$set': {'read': read_status}}
        )

        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Notification not found")

        await log_admin_audit(
            action='notifications.mark_read',
            actor=current_user,
            target_type='notification',
            target_id=notification_id,
            payload={'read': read_status},
            request=http_request
        )

        return {'success': True, 'message': f'Notification marked as {"read" if read_status else "unread"}'}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating notification: {e}")
        raise HTTPException(status_code=400, detail="Invalid notification ID")

# ============================================================================
# ADMIN PAYMENT MANAGEMENT ENDPOINTS
# ============================================================================

# Admin Escrow Management
@api_router.get("/admin/escrow/details")
async def get_escrow_details(current_user: dict = Depends(require_admin)):
    """Get detailed escrow breakdown (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Get all pending transactions grouped by type
        pending_txns = await db.transactions.find({
            'status': TransactionStatus.PENDING
        }).to_list(None)

        # Calculate totals by transaction type
        escrow_breakdown = {
            'SELLER_EARNING': 0,
            'DELIVERY_FEE_PAYMENT': 0,
            'OTHER': 0
        }

        total_pending = 0
        escrow_items = []

        for txn in pending_txns:
            amount = txn.get('amount', 0)
            total_pending += amount
            txn_type = txn.get('transaction_type', 'OTHER')

            if txn_type in escrow_breakdown:
                escrow_breakdown[txn_type] += amount
            else:
                escrow_breakdown['OTHER'] += amount

            # Get user and order info
            user = await db.users.find_one({'_id': ObjectId(txn['user_id'])})
            order = None
            if txn.get('order_id'):
                order = await db.orders.find_one({'_id': ObjectId(txn['order_id'])})

            # Calculate age
            created_at = txn.get('created_at', datetime.utcnow())
            age_hours = (datetime.utcnow() - created_at).total_seconds() / 3600

            escrow_items.append({
                'id': str(txn['_id']),
                'userId': txn['user_id'],
                'userName': user.get('name', 'Unknown') if user else 'Unknown',
                'orderId': txn.get('order_id'),
                'transactionType': txn_type,
                'amount': amount,
                'description': txn.get('description', ''),
                'createdAt': created_at.isoformat(),
                'ageHours': round(age_hours, 2),
                'isStuck': age_hours > 24,
                'orderStatus': order.get('delivery_status') if order else None
            })

        # Count stuck escrow (>24 hours)
        stuck_count = sum(1 for item in escrow_items if item['isStuck'])
        stuck_amount = sum(item['amount'] for item in escrow_items if item['isStuck'])

        # Sort by age (oldest first)
        escrow_items.sort(key=lambda x: x['ageHours'], reverse=True)

        return {
            'totalPendingEscrow': round(total_pending, 2),
            'breakdown': {
                'sellerEarnings': round(escrow_breakdown['SELLER_EARNING'], 2),
                'deliveryFees': round(escrow_breakdown['DELIVERY_FEE_PAYMENT'], 2),
                'other': round(escrow_breakdown['OTHER'], 2)
            },
            'stuckEscrow': {
                'count': stuck_count,
                'amount': round(stuck_amount, 2)
            },
            'items': escrow_items,
            'totalItems': len(escrow_items)
        }
    except Exception as e:
        logger.error(f"Error fetching escrow details: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch escrow details")

@api_router.post("/admin/escrow/release/{transaction_id}")
async def release_escrow_manually(
    transaction_id: str,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """Manually release a pending escrow transaction (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Get the pending transaction
        txn = await db.transactions.find_one({
            '_id': ObjectId(transaction_id),
            'status': TransactionStatus.PENDING
        })

        if not txn:
            raise HTTPException(status_code=404, detail="Pending transaction not found")

        before_state = {
            'status': txn.get('status'),
            'amount': txn.get('amount'),
            'user_id': txn.get('user_id')
        }

        user_id = txn['user_id']
        amount = txn.get('amount', 0)

        # Get user's wallet
        wallet = await db.wallets.find_one({'user_id': user_id})
        if not wallet:
            raise HTTPException(status_code=404, detail="User wallet not found")

        # Move from pending_balance to balance
        new_pending = wallet.get('pending_balance', 0) - amount
        new_balance = wallet.get('balance', 0) + amount

        # Update wallet
        await db.wallets.update_one(
            {'user_id': user_id},
            {
                '$set': {
                    'pending_balance': max(0, new_pending),
                    'balance': new_balance,
                    'updated_at': datetime.utcnow()
                }
            }
        )

        # Update transaction status
        await db.transactions.update_one(
            {'_id': ObjectId(transaction_id)},
            {
                '$set': {
                    'status': TransactionStatus.COMPLETED,
                    'updated_at': datetime.utcnow(),
                    'admin_released': True,
                    'released_by': str(current_user['_id'])
                }
            }
        )

        await log_admin_audit(
            action='escrow.release',
            actor=current_user,
            target_type='transaction',
            target_id=transaction_id,
            before=before_state,
            after={'status': TransactionStatus.COMPLETED, 'admin_released': True},
            payload={'amount': amount, 'user_id': user_id},
            request=http_request
        )

        # Create notification for user
        user = await db.users.find_one({'_id': ObjectId(user_id)})
        if user:
            await create_notification(
                user_id=user_id,
                notification_type='PAYMENT_RELEASED',
                title='💰 Payment Released',
                message=f'KES {amount:,.0f} has been released to your wallet by admin',
                data={'transaction_id': transaction_id, 'amount': amount}
            )

        logger.info(f"Admin {current_user['email']} released escrow transaction {transaction_id}")

        return {
            'success': True,
            'message': 'Escrow released successfully',
            'transactionId': transaction_id,
            'amount': amount
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error releasing escrow: {e}")
        raise HTTPException(status_code=500, detail="Failed to release escrow")

@api_router.post("/admin/escrow/reverse/{transaction_id}")
async def reverse_escrow_manually(
    transaction_id: str,
    reason: str,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """Manually reverse a pending escrow transaction (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Get the pending transaction
        txn = await db.transactions.find_one({
            '_id': ObjectId(transaction_id),
            'status': TransactionStatus.PENDING
        })

        if not txn:
            raise HTTPException(status_code=404, detail="Pending transaction not found")

        before_state = {
            'status': txn.get('status'),
            'amount': txn.get('amount'),
            'user_id': txn.get('user_id')
        }

        seller_id = txn['user_id']
        amount = txn.get('amount', 0)
        order_id = txn.get('order_id')

        # Get the order to find buyer
        order = await db.orders.find_one({'_id': ObjectId(order_id)}) if order_id else None
        if not order:
            raise HTTPException(status_code=404, detail="Associated order not found")

        buyer_id = order.get('buyer_id')

        # Get seller's wallet
        seller_wallet = await db.wallets.find_one({'user_id': seller_id})
        if not seller_wallet:
            raise HTTPException(status_code=404, detail="Seller wallet not found")

        # Reduce seller's pending balance
        new_pending = seller_wallet.get('pending_balance', 0) - amount
        await db.wallets.update_one(
            {'user_id': seller_id},
            {
                '$set': {
                    'pending_balance': max(0, new_pending),
                    'updated_at': datetime.utcnow()
                }
            }
        )

        # Mark seller transaction as REVERSED
        await db.transactions.update_one(
            {'_id': ObjectId(transaction_id)},
            {
                '$set': {
                    'status': TransactionStatus.REVERSED,
                    'updated_at': datetime.utcnow(),
                    'reversal_reason': reason,
                    'admin_reversed': True,
                    'reversed_by': str(current_user['_id'])
                }
            }
        )

        # Refund buyer
        buyer_wallet = await get_or_create_wallet(buyer_id)
        new_buyer_balance = buyer_wallet['balance'] + amount

        await db.wallets.update_one(
            {'user_id': buyer_id},
            {
                '$set': {
                    'balance': new_buyer_balance,
                    'updated_at': datetime.utcnow()
                }
            }
        )

        # Create refund transaction for buyer
        await create_transaction(
            user_id=buyer_id,
            order_id=order_id,
            amount=amount,
            transaction_type=TransactionType.REFUND,
            description=f'Refund for order (Admin reversed escrow: {reason})',
            balance_before=buyer_wallet['balance'],
            balance_after=new_buyer_balance,
            status=TransactionStatus.COMPLETED
        )

        await log_admin_audit(
            action='escrow.reverse',
            actor=current_user,
            target_type='transaction',
            target_id=transaction_id,
            before=before_state,
            after={'status': TransactionStatus.REVERSED, 'admin_reversed': True},
            payload={'amount': amount, 'reason': reason, 'buyer_id': buyer_id, 'seller_id': seller_id},
            request=http_request
        )

        # Notify both parties
        await create_notification(
            user_id=seller_id,
            notification_type='PAYMENT_REVERSED',
            title='⚠️ Payment Reversed',
            message=f'Escrow payment of KES {amount:,.0f} was reversed by admin. Reason: {reason}',
            data={'transaction_id': transaction_id, 'amount': amount, 'reason': reason}
        )

        await create_notification(
            user_id=buyer_id,
            notification_type='REFUND_PROCESSED',
            title='💰 Refund Processed',
            message=f'You received a refund of KES {amount:,.0f}. Reason: {reason}',
            data={'transaction_id': transaction_id, 'amount': amount, 'reason': reason}
        )

        logger.info(f"Admin {current_user['email']} reversed escrow transaction {transaction_id}")

        return {
            'success': True,
            'message': 'Escrow reversed and buyer refunded',
            'transactionId': transaction_id,
            'amount': amount
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error reversing escrow: {e}")
        raise HTTPException(status_code=500, detail="Failed to reverse escrow")

# Admin Withdrawals Management
@api_router.get("/admin/withdrawals")
async def get_all_withdrawals(
    status: Optional[str] = None,
    page: int = 1,
    limit: int = 50,
    current_user: dict = Depends(require_admin)
):
    """Get all withdrawal requests with filtering (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Build query
        query = {}
        if status:
            query['status'] = status

        # Pagination
        skip = (page - 1) * limit

        # Get total count
        total = await db.withdrawals.count_documents(query)

        # Get withdrawals
        withdrawals_cursor = db.withdrawals.find(query).sort('created_at', -1).skip(skip).limit(limit)
        withdrawals = await withdrawals_cursor.to_list(length=limit)

        # Enrich with user info
        withdrawals_list = []
        for withdrawal in withdrawals:
            user = await db.users.find_one({'_id': ObjectId(withdrawal['user_id'])})

            withdrawals_list.append({
                'id': str(withdrawal['_id']),
                'userId': withdrawal['user_id'],
                'userName': user.get('name', 'Unknown') if user else 'Unknown',
                'userEmail': user.get('email', '') if user else '',
                'amount': withdrawal.get('amount', 0),
                'phoneNumber': withdrawal.get('phone_number', ''),
                'status': withdrawal.get('status', 'PENDING'),
                'mpesaConversationId': withdrawal.get('mpesa_conversation_id'),
                'mpesaOriginatorConversationId': withdrawal.get('mpesa_originator_conversation_id'),
                'createdAt': withdrawal['created_at'].isoformat() if withdrawal.get('created_at') else None,
                'updatedAt': withdrawal['updated_at'].isoformat() if withdrawal.get('updated_at') else None
            })

        # Calculate summary
        total_pending = await db.withdrawals.count_documents({**query, 'status': {'$in': ['PENDING', 'PENDING_APPROVAL']}})
        total_processing = await db.withdrawals.count_documents({**query, 'status': 'PROCESSING'})
        total_completed = await db.withdrawals.count_documents({**query, 'status': 'COMPLETED'})
        total_failed = await db.withdrawals.count_documents({**query, 'status': 'FAILED'})

        # Calculate amounts
        pending_amount_pipeline = [
            {'$match': {**query, 'status': {'$in': ['PENDING', 'PENDING_APPROVAL']}}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
        ]
        pending_result = await db.withdrawals.aggregate(pending_amount_pipeline).to_list(1)
        pending_amount = pending_result[0]['total'] if pending_result else 0

        return {
            'withdrawals': withdrawals_list,
            'total': total,
            'page': page,
            'limit': limit,
            'totalPages': (total + limit - 1) // limit,
            'summary': {
                'totalPending': total_pending,
                'totalProcessing': total_processing,
                'totalCompleted': total_completed,
                'totalFailed': total_failed,
                'pendingAmount': round(pending_amount, 2)
            }
        }
    except Exception as e:
        logger.error(f"Error fetching withdrawals: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch withdrawals")

# Admin Payment Analytics
@api_router.get("/admin/payment-analytics")
async def get_payment_analytics(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: dict = Depends(require_admin)
):
    """Get detailed payment analytics (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Parse dates
        if start_date:
            start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
        else:
            start = datetime.utcnow() - timedelta(days=30)

        if end_date:
            end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
        else:
            end = datetime.utcnow()

        # Revenue trend by day
        revenue_trend_pipeline = [
            {
                '$match': {
                    'transaction_type': TransactionType.PLATFORM_FEE,
                    'status': TransactionStatus.COMPLETED,
                    'created_at': {'$gte': start, '$lte': end}
                }
            },
            {
                '$group': {
                    '_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$created_at'}},
                    'revenue': {'$sum': '$amount'},
                    'count': {'$sum': 1}
                }
            },
            {'$sort': {'_id': 1}}
        ]
        revenue_trend = await db.transactions.aggregate(revenue_trend_pipeline).to_list(None)

        # Transaction types distribution
        txn_types_pipeline = [
            {
                '$match': {
                    'status': TransactionStatus.COMPLETED,
                    'created_at': {'$gte': start, '$lte': end}
                }
            },
            {
                '$group': {
                    '_id': '$transaction_type',
                    'count': {'$sum': 1},
                    'totalAmount': {'$sum': '$amount'}
                }
            },
            {'$sort': {'count': -1}}
        ]
        txn_types = await db.transactions.aggregate(txn_types_pipeline).to_list(None)

        # Payment methods distribution (from orders)
        payment_methods_pipeline = [
            {
                '$match': {
                    'payment_status': PaymentStatus.PAID,
                    'created_at': {'$gte': start, '$lte': end}
                }
            },
            {
                '$group': {
                    '_id': '$payment_method',
                    'count': {'$sum': 1},
                    'totalAmount': {'$sum': '$total_amount'}
                }
            },
            {'$sort': {'count': -1}}
        ]
        payment_methods = await db.orders.aggregate(payment_methods_pipeline).to_list(None)

        return {
            'dateRange': {
                'start': start.isoformat(),
                'end': end.isoformat()
            },
            'revenueTrend': [
                {
                    'date': item['_id'],
                    'revenue': round(item['revenue'], 2),
                    'count': item['count']
                }
                for item in revenue_trend
            ],
            'transactionTypes': [
                {
                    'type': item['_id'],
                    'count': item['count'],
                    'totalAmount': round(item['totalAmount'], 2)
                }
                for item in txn_types
            ],
            'paymentMethods': [
                {
                    'method': item['_id'],
                    'count': item['count'],
                    'totalAmount': round(item['totalAmount'], 2)
                }
                for item in payment_methods
            ]
        }
    except Exception as e:
        logger.error(f"Error fetching payment analytics: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch payment analytics")

# Get Account Deletion Fee Statistics
@api_router.get("/admin/account-deletion-stats")
async def get_account_deletion_stats(
    days: int = 30,
    current_user: dict = Depends(require_admin)
):
    """Get account deletion fee statistics (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        start = datetime.utcnow() - timedelta(days=days)

        # Get all account deletion related transactions (unclaimed funds, penalties settled)
        # These are identified by specific description patterns
        deletion_txns = await db.transactions.find({
            'user_id': PLATFORM_WALLET_ID,
            'status': TransactionStatus.COMPLETED,
            'created_at': {'$gte': start},
            '$or': [
                {'description': {'$regex': 'deleted account', '$options': 'i'}},
                {'description': {'$regex': 'unclaimed wallet balance', '$options': 'i'}},
                {'description': {'$regex': 'pending penalties', '$options': 'i'}}
            ]
        }).to_list(None)

        # Categorize transactions
        unclaimed_funds = 0.0
        pending_escrow_handled = 0.0
        pending_deductions_settled = 0.0
        deletion_count = 0
        deletion_emails = set()

        for txn in deletion_txns:
            description = txn.get('description', '').lower()
            amount = abs(txn.get('amount', 0.0))

            if 'unclaimed wallet balance' in description:
                unclaimed_funds += amount
                # Extract email from description
                if 'deleted account' in description:
                    deletion_emails.add(description.split('deleted account')[1].split('(')[0].strip())
            elif 'pending penalties' in description or 'pending deductions' in description:
                pending_deductions_settled += amount
                if 'deleted account' in description:
                    deletion_emails.add(description.split('deleted account')[1].split('(')[0].strip())

        deletion_count = len(deletion_emails)

        # Get daily breakdown
        daily_pipeline = [
            {
                '$match': {
                    'user_id': PLATFORM_WALLET_ID,
                    'status': TransactionStatus.COMPLETED,
                    'created_at': {'$gte': start},
                    '$or': [
                        {'description': {'$regex': 'deleted account', '$options': 'i'}},
                        {'description': {'$regex': 'unclaimed wallet balance', '$options': 'i'}},
                        {'description': {'$regex': 'pending penalties', '$options': 'i'}}
                    ]
                }
            },
            {
                '$group': {
                    '_id': {
                        '$dateToString': {
                            'format': '%Y-%m-%d',
                            'date': '$created_at'
                        }
                    },
                    'totalAmount': {'$sum': '$amount'},
                    'count': {'$sum': 1}
                }
            },
            {'$sort': {'_id': 1}}
        ]
        daily_breakdown = await db.transactions.aggregate(daily_pipeline).to_list(None)

        # Get all-time total (for context)
        all_time_txns = await db.transactions.find({
            'user_id': PLATFORM_WALLET_ID,
            'status': TransactionStatus.COMPLETED,
            '$or': [
                {'description': {'$regex': 'deleted account', '$options': 'i'}},
                {'description': {'$regex': 'unclaimed wallet balance', '$options': 'i'}},
                {'description': {'$regex': 'pending penalties', '$options': 'i'}}
            ]
        }).to_list(None)

        all_time_total = sum(abs(txn.get('amount', 0.0)) for txn in all_time_txns)
        all_time_count = len(set(
            txn.get('description', '').split('deleted account')[1].split('(')[0].strip()
            for txn in all_time_txns
            if 'deleted account' in txn.get('description', '').lower()
        ))

        total_fees_collected = unclaimed_funds + pending_deductions_settled

        return {
            'period': {
                'days': days,
                'start': start.isoformat(),
                'end': datetime.utcnow().isoformat()
            },
            'summary': {
                'totalAccountDeletions': deletion_count,
                'totalFeesCollected': round(total_fees_collected, 2),
                'unclaimedFunds': round(unclaimed_funds, 2),
                'pendingDeductionsSettled': round(pending_deductions_settled, 2),
                'averageFeePerDeletion': round(total_fees_collected / deletion_count, 2) if deletion_count > 0 else 0.0
            },
            'allTime': {
                'totalAccountDeletions': all_time_count,
                'totalFeesCollected': round(all_time_total, 2)
            },
            'dailyBreakdown': [
                {
                    'date': item['_id'],
                    'totalAmount': round(item['totalAmount'], 2),
                    'count': item['count']
                }
                for item in daily_breakdown
            ],
            'recentDeletions': [
                {
                    'date': txn.get('created_at').isoformat() if txn.get('created_at') else None,
                    'amount': abs(txn.get('amount', 0.0)),
                    'description': txn.get('description', ''),
                    'type': (
                        'Unclaimed Balance' if 'unclaimed' in txn.get('description', '').lower()
                        else 'Pending Deductions' if 'pending' in txn.get('description', '').lower()
                        else 'Other'
                    )
                }
                for txn in deletion_txns[:20]  # Last 20 deletion-related transactions
            ]
        }

    except Exception as e:
        logger.error(f"Error fetching account deletion stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch account deletion statistics")

# Export Transactions
@api_router.get("/admin/transactions/export")
async def export_transactions(
    transaction_type: Optional[str] = None,
    status: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: dict = Depends(require_admin)
):
    """Export transactions as CSV (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Build query
        query = {}

        if transaction_type:
            query['transaction_type'] = transaction_type

        if status:
            query['status'] = status

        if start_date or end_date:
            query['created_at'] = {}
            if start_date:
                query['created_at']['$gte'] = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            if end_date:
                query['created_at']['$lte'] = datetime.fromisoformat(end_date.replace('Z', '+00:00'))

        # Get all transactions matching query
        transactions = await db.transactions.find(query).sort('created_at', -1).to_list(None)

        # Build CSV
        import csv
        from io import StringIO

        output = StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            'Transaction ID',
            'User ID',
            'User Name',
            'Order ID',
            'Type',
            'Amount',
            'Status',
            'Description',
            'Balance Before',
            'Balance After',
            'Created At'
        ])

        # Rows
        for txn in transactions:
            user = await db.users.find_one({'_id': ObjectId(txn['user_id'])})

            writer.writerow([
                str(txn['_id']),
                txn['user_id'],
                user.get('name', 'Unknown') if user else 'Unknown',
                txn.get('order_id', ''),
                txn.get('transaction_type', ''),
                txn.get('amount', 0),
                txn.get('status', ''),
                txn.get('description', ''),
                txn.get('balance_before', 0),
                txn.get('balance_after', 0),
                txn['created_at'].isoformat() if txn.get('created_at') else ''
            ])

        csv_content = output.getvalue()

        from fastapi.responses import Response

        return Response(
            content=csv_content,
            media_type='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=transactions_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'
            }
        )
    except Exception as e:
        logger.error(f"Error exporting transactions: {e}")
        raise HTTPException(status_code=500, detail="Failed to export transactions")

# ============================================================================
# ADVANCED PAYMENT MANAGEMENT ENDPOINTS
# ============================================================================

# Approve withdrawal
@api_router.post("/admin/withdrawals/{withdrawal_id}/approve")
async def approve_withdrawal(
    withdrawal_id: str,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """Approve a pending withdrawal request (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Get the withdrawal request
        withdrawal = await db.withdrawals.find_one({
            '_id': ObjectId(withdrawal_id),
            'status': {'$in': [WithdrawalStatus.PENDING, WithdrawalStatus.PENDING_APPROVAL]}
        })

        if not withdrawal:
            raise HTTPException(status_code=404, detail="Pending withdrawal not found")

        before_state = {
            'status': withdrawal.get('status'),
            'amount': withdrawal.get('amount'),
            'user_id': withdrawal.get('user_id')
        }

        # Update withdrawal status to PROCESSING
        await db.withdrawals.update_one(
            {'_id': ObjectId(withdrawal_id)},
            {
                '$set': {
                    'status': WithdrawalStatus.PROCESSING,
                    'approved_by': str(current_user['_id']),
                    'approved_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow()
                }
            }
        )

        # Trigger M-Pesa B2C payment
        try:
            result = await mpesa_service.b2c_payment(
                phone_number=withdrawal['phone_number'],
                amount=withdrawal['amount'],
                occasion=f"Withdrawal {withdrawal_id[:8]}"
            )

            if result.get('success'):
                # Update with M-Pesa details
                await db.withdrawals.update_one(
                    {'_id': ObjectId(withdrawal_id)},
                    {
                        '$set': {
                            'status': WithdrawalStatus.COMPLETED,
                            'mpesa_conversation_id': result.get('ConversationID'),
                            'mpesa_originator_conversation_id': result.get('OriginatorConversationID'),
                            'updated_at': datetime.utcnow()
                        }
                    }
                )

                await log_admin_audit(
                    action='withdrawal.approve',
                    actor=current_user,
                    target_type='withdrawal',
                    target_id=withdrawal_id,
                    before=before_state,
                    after={
                        'status': WithdrawalStatus.COMPLETED,
                        'mpesa_conversation_id': result.get('ConversationID'),
                        'mpesa_originator_conversation_id': result.get('OriginatorConversationID')
                    },
                    payload={'amount': withdrawal.get('amount'), 'phone_number': withdrawal.get('phone_number')},
                    request=http_request
                )

                # Create notification
                await create_notification(
                    user_id=withdrawal['user_id'],
                    notification_type='WITHDRAWAL_COMPLETED',
                    title='💰 Withdrawal Completed',
                    message=f'KES {withdrawal["amount"]:,.0f} has been sent to {withdrawal["phone_number"]}'
                )

                logger.info(f"✅ Withdrawal {withdrawal_id} approved and processed successfully")
                return {'success': True, 'message': 'Withdrawal approved and processed successfully'}
            else:
                # M-Pesa failed, revert to PENDING
                await db.withdrawals.update_one(
                    {'_id': ObjectId(withdrawal_id)},
                    {
                        '$set': {
                            'status': WithdrawalStatus.FAILED,
                            'failure_reason': result.get('errorMessage', 'M-Pesa payment failed'),
                            'updated_at': datetime.utcnow()
                        }
                    }
                )

                # Refund user's wallet
                user_wallet = await get_or_create_wallet(withdrawal['user_id'])
                await db.wallets.update_one(
                    {'user_id': withdrawal['user_id']},
                    {'$inc': {'balance': withdrawal['amount']}}
                )

                # Create transaction for refund
                await create_transaction(
                    user_id=withdrawal['user_id'],
                    amount=withdrawal['amount'],
                    transaction_type=TransactionType.REFUND,
                    status=TransactionStatus.COMPLETED,
                    description=f'Withdrawal failed - amount refunded (Withdrawal ID: {withdrawal_id[:8]})',
                    order_id=None
                )

                await log_admin_audit(
                    action='withdrawal.approve_failed',
                    actor=current_user,
                    target_type='withdrawal',
                    target_id=withdrawal_id,
                    before=before_state,
                    after={
                        'status': WithdrawalStatus.FAILED,
                        'failure_reason': result.get('errorMessage', 'M-Pesa payment failed')
                    },
                    payload={'amount': withdrawal.get('amount'), 'phone_number': withdrawal.get('phone_number')},
                    request=http_request
                )

                raise HTTPException(status_code=500, detail=f"M-Pesa payment failed: {result.get('errorMessage')}")

        except Exception as mpesa_error:
            logger.error(f"M-Pesa error for withdrawal {withdrawal_id}: {mpesa_error}")
            # Revert withdrawal status
            await db.withdrawals.update_one(
                {'_id': ObjectId(withdrawal_id)},
                {
                    '$set': {
                        'status': WithdrawalStatus.FAILED,
                        'failure_reason': str(mpesa_error),
                        'updated_at': datetime.utcnow()
                    }
                }
            )

            # Refund wallet
            await db.wallets.update_one(
                {'user_id': withdrawal['user_id']},
                {'$inc': {'balance': withdrawal['amount']}}
            )

            # Create refund transaction
            await create_transaction(
                user_id=withdrawal['user_id'],
                amount=withdrawal['amount'],
                transaction_type=TransactionType.REFUND,
                status=TransactionStatus.COMPLETED,
                description=f'Withdrawal failed - amount refunded (Error: {str(mpesa_error)[:50]})',
                order_id=None
            )

            await log_admin_audit(
                action='withdrawal.approve_failed',
                actor=current_user,
                target_type='withdrawal',
                target_id=withdrawal_id,
                before=before_state,
                after={
                    'status': WithdrawalStatus.FAILED,
                    'failure_reason': str(mpesa_error)
                },
                payload={'amount': withdrawal.get('amount'), 'phone_number': withdrawal.get('phone_number')},
                request=http_request
            )

            raise HTTPException(status_code=500, detail=f"Failed to process withdrawal: {str(mpesa_error)}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error approving withdrawal: {e}")
        raise HTTPException(status_code=500, detail="Failed to approve withdrawal")


# Reject withdrawal
@api_router.post("/admin/withdrawals/{withdrawal_id}/reject")
async def reject_withdrawal(
    withdrawal_id: str,
    reason: str,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """Reject a pending withdrawal request (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Get the withdrawal request
        withdrawal = await db.withdrawals.find_one({
            '_id': ObjectId(withdrawal_id),
            'status': {'$in': [WithdrawalStatus.PENDING, WithdrawalStatus.PENDING_APPROVAL]}
        })

        if not withdrawal:
            raise HTTPException(status_code=404, detail="Pending withdrawal not found")

        before_state = {
            'status': withdrawal.get('status'),
            'amount': withdrawal.get('amount'),
            'user_id': withdrawal.get('user_id')
        }

        # Update withdrawal status to FAILED
        await db.withdrawals.update_one(
            {'_id': ObjectId(withdrawal_id)},
            {
                '$set': {
                    'status': WithdrawalStatus.FAILED,
                    'failure_reason': reason,
                    'rejected_by': str(current_user['_id']),
                    'rejected_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow()
                }
            }
        )

        # Refund the amount back to user's wallet
        await db.wallets.update_one(
            {'user_id': withdrawal['user_id']},
            {'$inc': {'balance': withdrawal['amount']}}
        )

        # Create refund transaction
        await create_transaction(
            user_id=withdrawal['user_id'],
            amount=withdrawal['amount'],
            transaction_type=TransactionType.REFUND,
            status=TransactionStatus.COMPLETED,
            description=f'Withdrawal rejected by admin - amount refunded. Reason: {reason}',
            order_id=None
        )

        await log_admin_audit(
            action='withdrawal.reject',
            actor=current_user,
            target_type='withdrawal',
            target_id=withdrawal_id,
            before=before_state,
            after={'status': WithdrawalStatus.FAILED, 'failure_reason': reason},
            payload={'reason': reason, 'amount': withdrawal.get('amount')},
            request=http_request
        )

        # Create notification
        await create_notification(
            user_id=withdrawal['user_id'],
            notification_type='WITHDRAWAL_FAILED',
            title='❌ Withdrawal Rejected',
            message=f'Your withdrawal of KES {withdrawal["amount"]:,.0f} was rejected. Reason: {reason}'
        )

        logger.info(f"✅ Withdrawal {withdrawal_id} rejected by admin")
        return {'success': True, 'message': 'Withdrawal rejected and amount refunded'}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error rejecting withdrawal: {e}")
        raise HTTPException(status_code=500, detail="Failed to reject withdrawal")


# Get wallet details for a specific user
@api_router.get("/admin/wallets/{user_id}")
async def get_user_wallet(
    user_id: str,
    current_user: dict = Depends(require_admin)
):
    """Get detailed wallet information for a specific user (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Get wallet
        wallet = await get_or_create_wallet(user_id)

        # Get user info
        user = await db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Get recent transactions
        transactions = await db.transactions.find({'user_id': user_id}).sort('created_at', -1).limit(20).to_list(20)

        # Calculate totals by type
        earnings_pipeline = [
            {'$match': {'user_id': user_id, 'status': TransactionStatus.COMPLETED, 'amount': {'$gt': 0}}},
            {'$group': {'_id': '$transaction_type', 'total': {'$sum': '$amount'}, 'count': {'$sum': 1}}}
        ]
        earnings_by_type = await db.transactions.aggregate(earnings_pipeline).to_list(None)

        # Get withdrawal history
        withdrawals = await db.withdrawals.find({'user_id': user_id}).sort('created_at', -1).limit(10).to_list(10)

        return {
            'userId': user_id,
            'userName': user.get('name', 'Unknown'),
            'userEmail': user.get('email', ''),
            'wallet': {
                'balance': wallet.get('balance', 0),
                'pendingBalance': wallet.get('pending_balance', 0),
                'totalEarned': wallet.get('total_earned', 0),
                'totalWithdrawn': wallet.get('total_withdrawn', 0),
                'pendingDeductions': wallet.get('pending_deductions', 0),
                'createdAt': wallet.get('created_at').isoformat() if wallet.get('created_at') else None,
                'updatedAt': wallet.get('updated_at').isoformat() if wallet.get('updated_at') else None
            },
            'earningsByType': [
                {
                    'type': item['_id'],
                    'total': round(item['total'], 2),
                    'count': item['count']
                }
                for item in earnings_by_type
            ],
            'recentTransactions': [
                {
                    'id': str(txn['_id']),
                    'type': txn.get('transaction_type'),
                    'amount': txn.get('amount', 0),
                    'status': txn.get('status'),
                    'description': txn.get('description', ''),
                    'createdAt': txn.get('created_at').isoformat() if txn.get('created_at') else None
                }
                for txn in transactions
            ],
            'withdrawalHistory': [
                {
                    'id': str(w['_id']),
                    'amount': w.get('amount', 0),
                    'status': w.get('status'),
                    'phoneNumber': w.get('phone_number', ''),
                    'createdAt': w.get('created_at').isoformat() if w.get('created_at') else None
                }
                for w in withdrawals
            ]
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching user wallet: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch user wallet")


# Get all wallets with balances
@api_router.get("/admin/wallets")
async def get_all_wallets(
    page: int = 1,
    limit: int = 50,
    min_balance: Optional[float] = None,
    current_user: dict = Depends(require_admin)
):
    """Get all user wallets with balances (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Build query
        query = {}
        if min_balance is not None:
            query['balance'] = {'$gte': min_balance}

        # Pagination
        skip = (page - 1) * limit

        # Get total count
        total = await db.wallets.count_documents(query)

        # Get wallets
        wallets_cursor = db.wallets.find(query).sort('balance', -1).skip(skip).limit(limit)
        wallets = await wallets_cursor.to_list(length=limit)

        # Enrich with user info
        wallets_list = []
        for wallet in wallets:
            # Skip platform wallet
            if wallet['user_id'] == PLATFORM_WALLET_ID:
                continue

            # Fetch user info - handle invalid ObjectIds gracefully
            try:
                user = await db.users.find_one({'_id': ObjectId(wallet['user_id'])})
                user_name = user.get('name', 'Unknown') if user else 'Unknown'
                user_email = user.get('email', '') if user else ''
                user_role = user.get('role', '') if user else ''
            except Exception as e:
                logger.warning(f"Failed to fetch user for wallet {wallet['user_id']}: {e}")
                user_name = 'Unknown'
                user_email = ''
                user_role = ''

            wallets_list.append({
                'userId': wallet['user_id'],
                'userName': user_name,
                'userEmail': user_email,
                'userRole': user_role,
                'balance': wallet.get('balance', 0),
                'pendingBalance': wallet.get('pending_balance', 0),
                'totalEarned': wallet.get('total_earned', 0),
                'totalWithdrawn': wallet.get('total_withdrawn', 0),
                'pendingDeductions': wallet.get('pending_deductions', 0),
                'lastActivity': wallet.get('updated_at').isoformat() if wallet.get('updated_at') else None
            })

        # Get platform wallet separately
        platform_wallet = await get_or_create_platform_wallet()

        return {
            'wallets': wallets_list,
            'total': total,
            'page': page,
            'limit': limit,
            'totalPages': (total + limit - 1) // limit,
            'platformWallet': {
                'balance': platform_wallet.get('balance', 0),
                'totalEarned': platform_wallet.get('total_earned', 0)
            }
        }

    except Exception as e:
        logger.error(f"Error fetching wallets: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch wallets")


# Reconcile wallet balance
@api_router.post("/admin/wallets/{user_id}/reconcile")
async def reconcile_wallet(
    user_id: str,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """Recalculate and reconcile wallet balance based on transactions (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Get all completed transactions for user
        completed_txns = await db.transactions.find({
            'user_id': user_id,
            'status': TransactionStatus.COMPLETED
        }).to_list(None)

        # Calculate balance
        calculated_balance = sum(txn.get('amount', 0) for txn in completed_txns)

        # Get pending transactions
        pending_txns = await db.transactions.find({
            'user_id': user_id,
            'status': TransactionStatus.PENDING
        }).to_list(None)

        calculated_pending = sum(txn.get('amount', 0) for txn in pending_txns)

        # Get current wallet
        wallet = await get_or_create_wallet(user_id)
        current_balance = wallet.get('balance', 0)
        current_pending = wallet.get('pending_balance', 0)

        discrepancy_balance = calculated_balance - current_balance
        discrepancy_pending = calculated_pending - current_pending

        # Update wallet if there's a discrepancy
        if discrepancy_balance != 0 or discrepancy_pending != 0:
            await db.wallets.update_one(
                {'user_id': user_id},
                {
                    '$set': {
                        'balance': calculated_balance,
                        'pending_balance': calculated_pending,
                        'updated_at': datetime.utcnow(),
                        'last_reconciled_at': datetime.utcnow(),
                        'last_reconciled_by': str(current_user['_id'])
                    }
                }
            )

            logger.info(f"✅ Wallet reconciled for user {user_id}. Balance diff: {discrepancy_balance}, Pending diff: {discrepancy_pending}")

        await log_admin_audit(
            action='wallet.reconcile',
            actor=current_user,
            target_type='wallet',
            target_id=user_id,
            before={
                'balance': current_balance,
                'pending_balance': current_pending
            },
            after={
                'balance': calculated_balance,
                'pending_balance': calculated_pending
            },
            payload={
                'discrepancy_balance': discrepancy_balance,
                'discrepancy_pending': discrepancy_pending,
                'was_updated': discrepancy_balance != 0 or discrepancy_pending != 0
            },
            request=http_request
        )

        return {
            'success': True,
            'userId': user_id,
            'reconciliation': {
                'previousBalance': current_balance,
                'calculatedBalance': calculated_balance,
                'discrepancyBalance': discrepancy_balance,
                'previousPending': current_pending,
                'calculatedPending': calculated_pending,
                'discrepancyPending': discrepancy_pending,
                'wasUpdated': discrepancy_balance != 0 or discrepancy_pending != 0
            }
        }

    except Exception as e:
        logger.error(f"Error reconciling wallet: {e}")
        raise HTTPException(status_code=500, detail="Failed to reconcile wallet")


# Manually adjust wallet balance (emergency use only)
@api_router.post("/admin/wallets/{user_id}/adjust")
async def adjust_wallet_balance(
    user_id: str,
    amount: float,
    reason: str,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """Manually adjust wallet balance with reason (admin only - use with caution)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    if not reason or len(reason.strip()) < 10:
        raise HTTPException(status_code=400, detail="Detailed reason is required (minimum 10 characters)")

    try:
        # Get wallet
        wallet = await get_or_create_wallet(user_id)

        # Create adjustment transaction
        txn = await create_transaction(
            user_id=user_id,
            amount=amount,
            transaction_type=TransactionType.REFUND if amount > 0 else TransactionType.SELLER_CANCELLATION_PENALTY,
            status=TransactionStatus.COMPLETED,
            description=f'Admin adjustment: {reason} (by {current_user["name"]})',
            order_id=None
        )

        # Update wallet balance
        new_balance = await update_wallet_balance(user_id, amount, str(txn['_id']))

        # Log the adjustment
        await db.wallet_adjustments.insert_one({
            'user_id': user_id,
            'admin_id': str(current_user['_id']),
            'admin_name': current_user['name'],
            'amount': amount,
            'reason': reason,
            'previous_balance': wallet.get('balance', 0),
            'new_balance': new_balance,
            'transaction_id': str(txn['_id']),
            'created_at': datetime.utcnow()
        })

        await log_admin_audit(
            action='wallet.adjust',
            actor=current_user,
            target_type='wallet',
            target_id=user_id,
            before={'balance': wallet.get('balance', 0)},
            after={'balance': new_balance},
            payload={'amount': amount, 'reason': reason, 'transaction_id': str(txn['_id'])},
            request=http_request
        )

        # Notify user
        await create_notification(
            user_id=user_id,
            notification_type='PAYMENT_RELEASED',
            title='💰 Wallet Adjustment',
            message=f'Admin adjusted your wallet by KES {amount:,.2f}. Reason: {reason}'
        )

        logger.info(f"✅ Wallet adjusted for user {user_id} by {amount}. Reason: {reason}")

        return {
            'success': True,
            'userId': user_id,
            'adjustment': {
                'amount': amount,
                'reason': reason,
                'previousBalance': wallet.get('balance', 0),
                'newBalance': new_balance,
                'transactionId': str(txn['_id'])
            }
        }

    except Exception as e:
        logger.error(f"Error adjusting wallet: {e}")
        raise HTTPException(status_code=500, detail="Failed to adjust wallet balance")


# Get payment reconciliation report
@api_router.get("/admin/payments/reconciliation")
async def get_payment_reconciliation(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: dict = Depends(require_admin)
):
    """Get payment reconciliation report (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Parse dates
        if start_date:
            start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
        else:
            start = datetime.utcnow() - timedelta(days=30)

        if end_date:
            end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
        else:
            end = datetime.utcnow()

        # Get all paid orders in date range
        orders = await db.orders.find({
            'payment_status': PaymentStatus.PAID,
            'created_at': {'$gte': start, '$lte': end}
        }).to_list(None)

        total_order_amount = sum(order.get('total_amount', 0) for order in orders)
        total_platform_fees = sum(order.get('platform_fee', 0) for order in orders)
        total_seller_amounts = sum(order.get('seller_amount', 0) for order in orders)

        # Get all completed transactions in date range
        completed_txns = await db.transactions.find({
            'status': TransactionStatus.COMPLETED,
            'created_at': {'$gte': start, '$lte': end}
        }).to_list(None)

        # Group transactions by type
        txn_by_type = {}
        for txn in completed_txns:
            txn_type = txn.get('transaction_type', 'UNKNOWN')
            if txn_type not in txn_by_type:
                txn_by_type[txn_type] = {'count': 0, 'total': 0}
            txn_by_type[txn_type]['count'] += 1
            txn_by_type[txn_type]['total'] += txn.get('amount', 0)

        # Get all withdrawals in date range
        withdrawals = await db.withdrawals.find({
            'created_at': {'$gte': start, '$lte': end}
        }).to_list(None)

        total_withdrawal_amount = sum(w.get('amount', 0) for w in withdrawals if w.get('status') == WithdrawalStatus.COMPLETED)

        # Calculate platform wallet balance
        platform_wallet = await get_or_create_platform_wallet()

        # Get all user wallets total
        wallets_pipeline = [
            {'$group': {
                '_id': None,
                'total_balance': {'$sum': '$balance'},
                'total_pending': {'$sum': '$pending_balance'},
                'total_earned': {'$sum': '$total_earned'},
                'total_withdrawn': {'$sum': '$total_withdrawn'}
            }}
        ]
        wallets_result = await db.wallets.aggregate(wallets_pipeline).to_list(1)
        wallets_totals = wallets_result[0] if wallets_result else {}

        return {
            'period': {
                'start': start.isoformat(),
                'end': end.isoformat()
            },
            'orders': {
                'count': len(orders),
                'totalAmount': round(total_order_amount, 2),
                'platformFees': round(total_platform_fees, 2),
                'sellerAmounts': round(total_seller_amounts, 2)
            },
            'transactions': {
                'byType': [
                    {
                        'type': txn_type,
                        'count': data['count'],
                        'total': round(data['total'], 2)
                    }
                    for txn_type, data in txn_by_type.items()
                ],
                'totalCompleted': len(completed_txns)
            },
            'withdrawals': {
                'total': len(withdrawals),
                'completed': len([w for w in withdrawals if w.get('status') == WithdrawalStatus.COMPLETED]),
                'pending': len([w for w in withdrawals if w.get('status') in [WithdrawalStatus.PENDING, WithdrawalStatus.PENDING_APPROVAL]]),
                'failed': len([w for w in withdrawals if w.get('status') == WithdrawalStatus.FAILED]),
                'totalAmount': round(total_withdrawal_amount, 2)
            },
            'wallets': {
                'totalBalance': round(wallets_totals.get('total_balance', 0), 2),
                'totalPending': round(wallets_totals.get('total_pending', 0), 2),
                'totalEarned': round(wallets_totals.get('total_earned', 0), 2),
                'totalWithdrawn': round(wallets_totals.get('total_withdrawn', 0), 2),
                'platformBalance': round(platform_wallet.get('balance', 0), 2),
                'platformEarned': round(platform_wallet.get('total_earned', 0), 2)
            },
            'summary': {
                'revenue': round(total_platform_fees, 2),
                'payouts': round(total_seller_amounts, 2),
                'withdrawals': round(total_withdrawal_amount, 2),
                'netPlatformBalance': round(total_platform_fees - total_withdrawal_amount, 2)
            }
        }

    except Exception as e:
        logger.error(f"Error generating reconciliation report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate reconciliation report")

# ===== Ledger Reconciliation (Double-Entry) =====
async def reconcile_double_entry_ledger(tolerance: float = 0.01) -> dict:
    """
    Daily reconciliation for double-entry ledger:
    - Sum of all entries should be ~0
    - Each transaction_id should balance to 0
    - Wallet balances should match transactions aggregation
    """
    try:
        issues = []

        # 1) Global ledger sum should be ~0
        total_result = await db.double_entry_ledger.aggregate([
            {'$group': {'_id': None, 'sum': {'$sum': '$amount'}}}
        ]).to_list(1)
        total_sum = total_result[0]['sum'] if total_result else 0.0
        if abs(total_sum) > tolerance:
            issues.append(f"GLOBAL_LEDGER_IMBALANCE: {total_sum:.2f}")

        # 2) Per-transaction balance should be ~0
        per_txn = await db.double_entry_ledger.aggregate([
            {'$group': {'_id': '$transaction_id', 'sum': {'$sum': '$amount'}}},
            {'$match': {'$or': [{'sum': {'$gt': tolerance}}, {'sum': {'$lt': -tolerance}}]}}
        ]).to_list(50)
        if per_txn:
            issues.append(f"UNBALANCED_TRANSACTIONS: {len(per_txn)} (showing up to 50)")

        # 3) Wallet balance vs transactions aggregation
        # Only for wallets (exclude platform/clearing)
        wallets = await db.wallets.find({'user_id': {'$nin': [PLATFORM_WALLET_ID, CLEARING_WALLET_ID]}}).to_list(200)
        balance_drifts = []
        for wallet in wallets:
            user_id = wallet['user_id']
            agg = await db.transactions.aggregate([
                {'$match': {'user_id': user_id, 'status': TransactionStatus.COMPLETED}},
                {'$group': {'_id': None, 'sum': {'$sum': '$amount'}}}
            ]).to_list(1)
            calculated = agg[0]['sum'] if agg else 0.0
            current_balance = wallet.get('balance', 0.0)
            if abs(calculated - current_balance) > tolerance:
                balance_drifts.append({
                    'user_id': user_id,
                    'ledger_balance': calculated,
                    'wallet_balance': current_balance
                })
                issues.append(
                    f"BALANCE_DRIFT: user={user_id} ledger={calculated:.2f} wallet={current_balance:.2f}"
                )

        status = "ok" if not issues else "issues_detected"
        return {
            'status': status,
            'issues': issues,
            'checked_at': datetime.utcnow().isoformat(),
            'balance_drifts': balance_drifts
        }
    except Exception as e:
        logger.error(f"Double-entry ledger reconciliation failed: {e}", exc_info=True)
        return {
            'status': 'error',
            'issues': [str(e)],
            'checked_at': datetime.utcnow().isoformat()
        }

async def check_withdrawal_fraud(
    user_id: str,
    amount: float,
    user: dict,
    request: Optional[Request] = None
) -> dict:
    """Basic withdrawal fraud checks and review gating."""
    now = datetime.utcnow()
    reasons = []
    requires_approval = False

    # Account age check
    created_at = user.get('created_at')
    if created_at:
        age_hours = (now - created_at).total_seconds() / 3600
        if age_hours < WITHDRAWAL_MIN_ACCOUNT_AGE_HOURS:
            requires_approval = True
            reasons.append(f"New account ({age_hours:.1f}h old)")

    # Daily totals
    day_start = now - timedelta(hours=24)
    daily_withdrawals = await db.withdrawals.find({
        'user_id': user_id,
        'created_at': {'$gte': day_start},
        'status': {'$in': [WithdrawalStatus.PENDING, WithdrawalStatus.PENDING_APPROVAL, WithdrawalStatus.PROCESSING, WithdrawalStatus.COMPLETED]}
    }).to_list(None)
    daily_count = len(daily_withdrawals)
    daily_amount = sum(w.get('amount', 0) for w in daily_withdrawals)
    if daily_count >= WITHDRAWAL_DAILY_COUNT:
        requires_approval = True
        reasons.append(f"Daily count exceeded ({daily_count}/{WITHDRAWAL_DAILY_COUNT})")
    if daily_amount + amount > WITHDRAWAL_DAILY_LIMIT:
        requires_approval = True
        reasons.append(f"Daily amount exceeded (KES {daily_amount + amount:.2f}/{WITHDRAWAL_DAILY_LIMIT:.2f})")

    # Velocity check
    window_start = now - timedelta(minutes=WITHDRAWAL_VELOCITY_WINDOW_MINUTES)
    recent = await db.withdrawals.count_documents({
        'user_id': user_id,
        'created_at': {'$gte': window_start}
    })
    if recent >= WITHDRAWAL_VELOCITY_COUNT:
        requires_approval = True
        reasons.append(f"Velocity limit exceeded ({recent}/{WITHDRAWAL_VELOCITY_COUNT} in {WITHDRAWAL_VELOCITY_WINDOW_MINUTES}m)")

    # Large amount review
    if amount >= WITHDRAWAL_MANUAL_REVIEW_THRESHOLD:
        requires_approval = True
        reasons.append(f"Amount ≥ manual review threshold (KES {WITHDRAWAL_MANUAL_REVIEW_THRESHOLD:.2f})")

    allowed = True
    reason = "; ".join(reasons) if reasons else None
    return {
        'allowed': allowed,
        'requires_approval': requires_approval,
        'reason': reason or ''
    }

async def _reconciliation_loop():
    """Background reconciliation loop (in-app scheduler)."""
    while True:
        try:
            tolerance = RECONCILIATION_TOLERANCE_PROD if ENVIRONMENT == 'production' else RECONCILIATION_TOLERANCE_DEV
            result = await reconcile_double_entry_ledger(tolerance=tolerance)
            if result.get('status') != 'ok':
                await log_security_event(
                    event_type='ledger_reconciliation_issue',
                    severity='high',
                    details=result
                )
            else:
                logger.info("✅ Ledger reconciliation OK")
        except Exception as e:
            logger.error(f"Reconciliation loop error: {e}", exc_info=True)
        await asyncio.sleep(RECONCILIATION_INTERVAL_HOURS * 3600)


async def _cleanup_expired_contact_messages_once():
    """
    Auto-clean chat contact details when no active contact unlock exists.
    This runs repeatedly so completed orders quickly lose contact visibility.
    """
    try:
        scanned_conversations = 0
        sanitized_messages = 0
        sanitized_conversations = 0

        async for conv in db.conversations.find({}):
            conv_id = conv.get('id')
            if not conv_id:
                continue

            scanned_conversations += 1
            contact_unlock_active = await moderation_service._check_order_paid(conv_id, db)
            if contact_unlock_active:
                continue

            conv_message_sanitized = False
            async for msg in db.messages.find({'conversation_id': conv_id, 'is_blocked': False}):
                original = msg.get('content_original', '')
                filtered = msg.get('content_filtered', '')
                sanitized_original = moderation_service.mask_contact_info(original)
                sanitized_filtered = moderation_service.mask_contact_info(filtered)

                if sanitized_original == original and sanitized_filtered == filtered:
                    continue

                await db.messages.update_one(
                    {'_id': msg['_id']},
                    {'$set': {
                        'content_original': sanitized_original,
                        'content_filtered': sanitized_filtered,
                        'contact_sanitized_at': datetime.utcnow()
                    }}
                )
                sanitized_messages += 1
                conv_message_sanitized = True

            # Keep conversation preview clean too when unlock is inactive.
            last_message = conv.get('last_message')
            if last_message:
                sanitized_last = moderation_service.mask_contact_info(last_message)
                if sanitized_last != last_message:
                    await db.conversations.update_one(
                        {'_id': conv['_id']},
                        {'$set': {
                            'last_message': sanitized_last,
                            'contact_sanitized_at': datetime.utcnow()
                        }}
                    )
                    conv_message_sanitized = True

            if conv_message_sanitized:
                sanitized_conversations += 1

        logger.info(
            f"🧹 Chat contact cleanup complete: conversations_scanned={scanned_conversations}, "
            f"conversations_sanitized={sanitized_conversations}, messages_sanitized={sanitized_messages}"
        )
    except Exception as e:
        logger.error(f"Chat contact cleanup failed: {e}", exc_info=True)


async def _chat_contact_cleanup_loop():
    while True:
        await _cleanup_expired_contact_messages_once()
        await asyncio.sleep(CHAT_CONTACT_CLEANUP_INTERVAL_HOURS * 3600)


async def _integrity_scan_loop():
    """Background transaction integrity scan loop (in-app scheduler)."""
    while True:
        try:
            bad = []
            cursor = db.transactions.find({}).sort('created_at', 1).limit(INTEGRITY_SCAN_LIMIT)
            previous_by_user: Dict[str, Optional[str]] = {}
            async for txn in cursor:
                user_id = txn.get('user_id')
                prev_hash = previous_by_user.get(user_id)
                expected = _compute_transaction_hash(txn, prev_hash)
                if txn.get('integrity_hash') != expected:
                    bad.append({
                        'transaction_id': str(txn.get('_id')),
                        'user_id': user_id,
                        'expected': expected,
                        'actual': txn.get('integrity_hash'),
                        'created_at': txn.get('created_at')
                    })
                previous_by_user[user_id] = txn.get('integrity_hash')

            if bad:
                await log_security_event(
                    event_type='ledger_integrity_failure',
                    severity='high',
                    details={'checked': INTEGRITY_SCAN_LIMIT, 'failed': len(bad), 'samples': bad[:20]}
                )
            else:
                logger.info("✅ Ledger integrity scan OK")
        except Exception as e:
            logger.error(f"Integrity scan error: {e}", exc_info=True)
        await asyncio.sleep(INTEGRITY_SCAN_INTERVAL_HOURS * 3600)


# Get platform earnings breakdown
@api_router.get("/admin/platform/earnings")
async def get_platform_earnings(
    current_user: dict = Depends(require_admin)
):
    """Get detailed breakdown of platform earnings and float balances (admin only)"""
    # Validate current_user is properly injected
    if not current_user or not isinstance(current_user, dict):
        logger.error(f"Invalid current_user in get_platform_earnings: {type(current_user)}")
        raise HTTPException(status_code=401, detail="Authentication failed")

    if current_user.get('role') != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Get platform wallet
        platform_wallet = await get_or_create_platform_wallet()
        if not platform_wallet:
            logger.error("Failed to get or create platform wallet")
            raise HTTPException(status_code=500, detail="Platform wallet not available")

        # Get all user wallets totals (excluding platform wallet)
        wallets_pipeline = [
            {'$match': {'user_id': {'$ne': PLATFORM_WALLET_ID}}},
            {'$group': {
                '_id': None,
                'total_balance': {'$sum': '$balance'},
                'total_pending': {'$sum': '$pending_balance'},
                'total_earned': {'$sum': '$total_earned'},
                'total_withdrawn': {'$sum': '$total_withdrawn'}
            }}
        ]
        wallets_result = await db.wallets.aggregate(wallets_pipeline).to_list(1)
        wallets_totals = wallets_result[0] if wallets_result else {}

        # Get platform settings to show current fee percentage
        settings = await _get_platform_settings_internal()
        if not settings:
            logger.warning("Platform settings not found, using defaults")
            settings = {'platformFeePercentage': 5.0}

        # Calculate platform withdrawals
        platform_withdrawals = await db.withdrawals.find({
            'user_id': PLATFORM_WALLET_ID,
            'status': WithdrawalStatus.COMPLETED
        }).to_list(None)
        total_platform_withdrawn = sum(w.get('amount', 0) for w in platform_withdrawals)

        # Get breakdown of platform fee sources - Enhanced categorization

        # 1. Service booking platform fees (5% of bookings)
        booking_fee_txns = await db.transactions.find({
            'user_id': PLATFORM_WALLET_ID,
            '$or': [
                {'transaction_type': TransactionType.PLATFORM_FEE},  # Legacy generic fees
                {'transaction_type': TransactionType.PLATFORM_FEE_BOOKING}  # New specific type
            ],
            'status': TransactionStatus.COMPLETED
        }).to_list(None)
        total_booking_fees = sum(txn.get('amount', 0) for txn in booking_fee_txns)

        # 2. Verification fees (user verification payments)
        verification_fee_txns = await db.transactions.find({
            'user_id': PLATFORM_WALLET_ID,
            '$or': [
                {'transaction_type': TransactionType.PLATFORM_FEE_VERIFICATION},
                {'description': {'$regex': 'verification fee', '$options': 'i'}}
            ],
            'status': TransactionStatus.COMPLETED
        }).to_list(None)
        total_verification_fees = sum(txn.get('amount', 0) for txn in verification_fee_txns)

        # 3. Job posting fees
        job_posting_txns = await db.transactions.find({
            'user_id': PLATFORM_WALLET_ID,
            '$or': [
                {'transaction_type': TransactionType.JOB_POSTING_FEE},
                {'transaction_type': TransactionType.PLATFORM_FEE_JOB_POSTING},
                {'description': {'$regex': 'job posting fee', '$options': 'i'}}
            ],
            'status': TransactionStatus.COMPLETED
        }).to_list(None)
        total_job_posting_fees = sum(txn.get('amount', 0) for txn in job_posting_txns)

        # 4. Seller cancellation penalties
        penalty_txns = await db.transactions.find({
            'user_id': PLATFORM_WALLET_ID,
            'transaction_type': TransactionType.SELLER_CANCELLATION_PENALTY,
            'status': TransactionStatus.COMPLETED
        }).to_list(None)
        total_penalties = sum(txn.get('amount', 0) for txn in penalty_txns)

        # 5. Account deletion fees (unclaimed balances and settled deductions)
        deletion_fee_txns = await db.transactions.find({
            'user_id': PLATFORM_WALLET_ID,
            'status': TransactionStatus.COMPLETED,
            '$or': [
                {'description': {'$regex': 'deleted account', '$options': 'i'}},
                {'description': {'$regex': 'unclaimed wallet balance', '$options': 'i'}},
                {'description': {'$regex': 'settled pending penalties', '$options': 'i'}}
            ]
        }).to_list(None)
        total_deletion_fees = sum(abs(txn.get('amount', 0)) for txn in deletion_fee_txns)

        # Calculate statistics
        total_user_earnings = wallets_totals.get('total_earned', 0)
        total_earnings = (
            total_booking_fees +
            total_verification_fees +
            total_job_posting_fees +
            total_penalties +
            total_deletion_fees
        )
        platform_balance = platform_wallet.get('balance', 0)

        # Validate data consistency
        if platform_balance < 0:
            logger.warning(f"Platform wallet has negative balance: {platform_balance}")

        return {
            'platformWallet': {
                'balance': round(platform_balance, 2),
                'totalEarned': round(platform_wallet.get('total_earned', 0), 2),
                'totalWithdrawn': round(total_platform_withdrawn, 2),
                'availableForWithdrawal': round(max(platform_balance, 0), 2)  # Ensure non-negative
            },
            'earningsSources': {
                'serviceBookingFees': round(total_booking_fees, 2),
                'verificationFees': round(total_verification_fees, 2),
                'jobPostingFees': round(total_job_posting_fees, 2),
                'sellerPenalties': round(total_penalties, 2),
                'accountDeletionFees': round(total_deletion_fees, 2),
                'total': round(total_earnings, 2),
                'transactionCount': {
                    'serviceBookingFees': len(booking_fee_txns),
                    'verificationFees': len(verification_fee_txns),
                    'jobPostingFees': len(job_posting_txns),
                    'sellerPenalties': len(penalty_txns),
                    'accountDeletionFees': len(deletion_fee_txns)
                },
                'breakdown': {
                    'platformFees': {
                        'serviceBookings': round(total_booking_fees, 2),
                        'verifications': round(total_verification_fees, 2),
                        'jobPostings': round(total_job_posting_fees, 2),
                        'subtotal': round(total_booking_fees + total_verification_fees + total_job_posting_fees, 2)
                    },
                    'penalties': round(total_penalties, 2),
                    'accountDeletions': round(total_deletion_fees, 2)
                }
            },
            'floatAllocation': {
                'userWalletsBalance': round(wallets_totals.get('total_balance', 0), 2),
                'pendingEscrow': round(wallets_totals.get('total_pending', 0), 2),
                'platformBalance': round(platform_balance, 2),
                'totalFloat': round(
                    wallets_totals.get('total_balance', 0) +
                    wallets_totals.get('total_pending', 0) +
                    platform_balance,
                    2
                ),
                'userCount': await db.wallets.count_documents({'user_id': {'$ne': PLATFORM_WALLET_ID}})
            },
            'settings': {
                'platformFeePercentage': settings.get('platformFeePercentage', 5.0),
                'sellerReceivesPercentage': 100 - settings.get('platformFeePercentage', 5.0)
            },
            'metrics': {
                'totalUserEarnings': round(total_user_earnings, 2),
                'platformToUserRatio': round((total_earnings / max(total_user_earnings, 1)) * 100, 2) if total_user_earnings > 0 else 0,
                'averageWalletBalance': round(wallets_totals.get('total_balance', 0) / max(await db.wallets.count_documents({'user_id': {'$ne': PLATFORM_WALLET_ID}}), 1), 2)
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting platform earnings: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get platform earnings: {str(e)}")


# Platform withdrawal request
class PlatformWithdrawalRequest(BaseModel):
    amount: float = Field(..., gt=0)
    recipient_phone: str
    reason: str = Field(..., min_length=10)


# Get platform earnings history
@api_router.get("/admin/platform/earnings/history")
async def get_platform_earnings_history(
    days: int = 30,
    current_user: dict = Depends(require_admin)
):
    """Get historical platform earnings data (admin only)"""
    if not current_user or not isinstance(current_user, dict):
        raise HTTPException(status_code=401, detail="Authentication failed")

    if current_user.get('role') != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        from datetime import datetime, timedelta

        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        # Group transactions by day
        daily_earnings = []
        for i in range(days):
            current_date = start_date + timedelta(days=i)
            next_date = current_date + timedelta(days=1)

            # Get service booking fee transactions for this day
            booking_fee_txns = await db.transactions.find({
                'user_id': PLATFORM_WALLET_ID,
                '$or': [
                    {'transaction_type': TransactionType.PLATFORM_FEE},
                    {'transaction_type': TransactionType.PLATFORM_FEE_BOOKING}
                ],
                'status': TransactionStatus.COMPLETED,
                'created_at': {
                    '$gte': current_date,
                    '$lt': next_date
                }
            }).to_list(None)

            # Get verification fee transactions for this day
            verification_fee_txns = await db.transactions.find({
                'user_id': PLATFORM_WALLET_ID,
                '$or': [
                    {'transaction_type': TransactionType.PLATFORM_FEE_VERIFICATION},
                    {'description': {'$regex': 'verification fee', '$options': 'i'}}
                ],
                'status': TransactionStatus.COMPLETED,
                'created_at': {
                    '$gte': current_date,
                    '$lt': next_date
                }
            }).to_list(None)

            # Get job posting fee transactions for this day
            job_posting_txns = await db.transactions.find({
                'user_id': PLATFORM_WALLET_ID,
                '$or': [
                    {'transaction_type': TransactionType.JOB_POSTING_FEE},
                    {'transaction_type': TransactionType.PLATFORM_FEE_JOB_POSTING},
                    {'description': {'$regex': 'job posting fee', '$options': 'i'}}
                ],
                'status': TransactionStatus.COMPLETED,
                'created_at': {
                    '$gte': current_date,
                    '$lt': next_date
                }
            }).to_list(None)

            # Get penalty transactions for this day
            penalty_txns = await db.transactions.find({
                'user_id': PLATFORM_WALLET_ID,
                'transaction_type': TransactionType.SELLER_CANCELLATION_PENALTY,
                'status': TransactionStatus.COMPLETED,
                'created_at': {
                    '$gte': current_date,
                    '$lt': next_date
                }
            }).to_list(None)

            # Get account deletion fee transactions for this day
            deletion_fee_txns = await db.transactions.find({
                'user_id': PLATFORM_WALLET_ID,
                'status': TransactionStatus.COMPLETED,
                '$or': [
                    {'description': {'$regex': 'deleted account', '$options': 'i'}},
                    {'description': {'$regex': 'unclaimed wallet balance', '$options': 'i'}},
                    {'description': {'$regex': 'settled pending penalties', '$options': 'i'}}
                ],
                'created_at': {
                    '$gte': current_date,
                    '$lt': next_date
                }
            }).to_list(None)

            booking_fees = sum(txn.get('amount', 0) for txn in booking_fee_txns)
            verification_fees = sum(txn.get('amount', 0) for txn in verification_fee_txns)
            job_posting_fees = sum(txn.get('amount', 0) for txn in job_posting_txns)
            penalties = sum(txn.get('amount', 0) for txn in penalty_txns)
            deletion_fees = sum(abs(txn.get('amount', 0)) for txn in deletion_fee_txns)

            daily_earnings.append({
                'date': current_date.strftime('%Y-%m-%d'),
                'serviceBookingFees': round(booking_fees, 2),
                'verificationFees': round(verification_fees, 2),
                'jobPostingFees': round(job_posting_fees, 2),
                'sellerPenalties': round(penalties, 2),
                'accountDeletionFees': round(deletion_fees, 2),
                'total': round(booking_fees + verification_fees + job_posting_fees + penalties + deletion_fees, 2),
                'transactionCount': len(booking_fee_txns) + len(verification_fee_txns) + len(job_posting_txns) + len(penalty_txns) + len(deletion_fee_txns)
            })

        # Calculate summary statistics
        total_earnings = sum(day['total'] for day in daily_earnings)
        avg_daily_earnings = total_earnings / max(days, 1)
        peak_day = max(daily_earnings, key=lambda x: x['total']) if daily_earnings else None

        return {
            'dailyEarnings': daily_earnings,
            'summary': {
                'totalEarnings': round(total_earnings, 2),
                'averageDailyEarnings': round(avg_daily_earnings, 2),
                'peakDay': peak_day['date'] if peak_day else None,
                'peakDayEarnings': peak_day['total'] if peak_day else 0,
                'daysTracked': days
            }
        }

    except Exception as e:
        logger.error(f"Error getting platform earnings history: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get earnings history: {str(e)}")


@api_router.post("/admin/platform/withdraw")
async def request_platform_withdrawal(
    withdrawal_data: PlatformWithdrawalRequest,
    current_user: dict = Depends(require_admin)
):
    """Request platform earnings withdrawal (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Get platform wallet
        platform_wallet = await get_or_create_platform_wallet()
        current_balance = platform_wallet.get('balance', 0)

        # Validate amount
        if withdrawal_data.amount > current_balance:
            raise HTTPException(
                status_code=400,
                detail=f"Insufficient platform balance. Available: KES {current_balance:,.2f}"
            )

        # Check minimum/maximum limits
        settings = await _get_platform_settings_internal()
        min_withdrawal = settings.get('minimumWithdrawal', 100.0)
        max_withdrawal = settings.get('maximumWithdrawal', 100000.0)

        if withdrawal_data.amount < min_withdrawal:
            raise HTTPException(
                status_code=400,
                detail=f"Minimum withdrawal amount is KES {min_withdrawal:,.2f}"
            )

        if withdrawal_data.amount > max_withdrawal:
            raise HTTPException(
                status_code=400,
                detail=f"Maximum withdrawal amount is KES {max_withdrawal:,.2f}"
            )

        # Create withdrawal transaction (debit platform wallet immediately)
        withdrawal_txn = await create_transaction(
            user_id=PLATFORM_WALLET_ID,
            amount=-withdrawal_data.amount,
            transaction_type=TransactionType.WITHDRAWAL,
            status=TransactionStatus.COMPLETED,
            description=f'Platform earnings withdrawal: {withdrawal_data.reason} (by {current_user["name"]})',
            order_id=None
        )

        # Update platform wallet balance
        new_balance = await update_wallet_balance(
            PLATFORM_WALLET_ID,
            -withdrawal_data.amount,
            str(withdrawal_txn['_id'])
        )

        # Create withdrawal record
        withdrawal_doc = {
            'user_id': PLATFORM_WALLET_ID,
            'admin_id': str(current_user['_id']),
            'admin_name': current_user['name'],
            'amount': withdrawal_data.amount,
            'phone_number': withdrawal_data.recipient_phone,
            'status': WithdrawalStatus.PENDING,
            'reason': withdrawal_data.reason,
            'transaction_id': str(withdrawal_txn['_id']),
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }

        result = await db.withdrawals.insert_one(withdrawal_doc)
        withdrawal_id = str(result.inserted_id)

        # Attempt M-Pesa B2C payment
        try:
            mpesa_result = await mpesa_service.b2c_payment(
                phone_number=withdrawal_data.recipient_phone,
                amount=withdrawal_data.amount,
                occasion=f'Platform withdrawal {withdrawal_id}'
            )

            if mpesa_result.get('success'):
                # Update withdrawal status
                await db.withdrawals.update_one(
                    {'_id': result.inserted_id},
                    {
                        '$set': {
                            'status': WithdrawalStatus.COMPLETED,
                            'mpesa_receipt': mpesa_result.get('receipt'),
                            'completed_at': datetime.utcnow(),
                            'updated_at': datetime.utcnow()
                        }
                    }
                )

                logger.info(f"✅ Platform withdrawal completed: KES {withdrawal_data.amount} to {withdrawal_data.recipient_phone}")

                return {
                    'success': True,
                    'message': 'Platform withdrawal completed successfully',
                    'withdrawalId': withdrawal_id,
                    'amount': withdrawal_data.amount,
                    'newBalance': new_balance,
                    'mpesaReceipt': mpesa_result.get('receipt')
                }
            else:
                # M-Pesa failed - refund platform wallet
                refund_txn = await create_transaction(
                    user_id=PLATFORM_WALLET_ID,
                    amount=withdrawal_data.amount,
                    transaction_type=TransactionType.REFUND,
                    status=TransactionStatus.COMPLETED,
                    description=f'Platform withdrawal refund (M-Pesa failed): {withdrawal_id}',
                    order_id=None
                )

                await update_wallet_balance(
                    PLATFORM_WALLET_ID,
                    withdrawal_data.amount,
                    str(refund_txn['_id'])
                )

                await db.withdrawals.update_one(
                    {'_id': result.inserted_id},
                    {
                        '$set': {
                            'status': WithdrawalStatus.FAILED,
                            'failure_reason': mpesa_result.get('error', 'M-Pesa payment failed'),
                            'updated_at': datetime.utcnow()
                        }
                    }
                )

                raise HTTPException(
                    status_code=500,
                    detail=f"M-Pesa payment failed: {mpesa_result.get('error', 'Unknown error')}"
                )

        except Exception as mpesa_error:
            # M-Pesa exception - refund platform wallet
            logger.error(f"M-Pesa B2C error: {mpesa_error}")

            refund_txn = await create_transaction(
                user_id=PLATFORM_WALLET_ID,
                amount=withdrawal_data.amount,
                transaction_type=TransactionType.REFUND,
                status=TransactionStatus.COMPLETED,
                description=f'Platform withdrawal refund (M-Pesa error): {withdrawal_id}',
                order_id=None
            )

            await update_wallet_balance(
                PLATFORM_WALLET_ID,
                withdrawal_data.amount,
                str(refund_txn['_id'])
            )

            await db.withdrawals.update_one(
                {'_id': result.inserted_id},
                {
                    '$set': {
                        'status': WithdrawalStatus.FAILED,
                        'failure_reason': str(mpesa_error),
                        'updated_at': datetime.utcnow()
                    }
                }
            )

            raise HTTPException(
                status_code=500,
                detail=f"M-Pesa service error: {str(mpesa_error)}"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing platform withdrawal: {e}")
        raise HTTPException(status_code=500, detail="Failed to process platform withdrawal")


# ============================================================================
# SELLER VERIFICATION ENDPOINTS
# ============================================================================

@api_router.post("/verification/submit")
async def submit_verification(
    verification_data: VerificationDocumentCreate,
    current_user: dict = Depends(get_current_user)
):
    """Submit verification documents for seller verification"""
    try:
        # Check if user is a seller
        if current_user.get('role') != UserRole.SELLER:
            raise HTTPException(
                status_code=403,
                detail="Only sellers can submit verification"
            )

        # Check if already verified
        if current_user.get('kyc_status') == 'verified':
            raise HTTPException(
                status_code=400,
                detail="You are already verified"
            )

        # Check for terms agreement
        if not verification_data.agree_to_terms:
            raise HTTPException(
                status_code=400,
                detail="You must agree to the verification terms"
            )

        # Check if verification already submitted
        existing_verification = await db.verifications.find_one({
            'user_id': str(current_user['_id']),
            'status': {'$in': ['pending', 'payment_pending', 'under_review']}
        })

        if existing_verification:
            raise HTTPException(
                status_code=400,
                detail="Verification already submitted. Please wait for review."
            )

        settings = await _get_platform_settings_internal()
        verification_fee = settings.get('verificationFee', VERIFICATION_FEE)

        # Create verification record
        verification = {
            'user_id': str(current_user['_id']),
            'user_name': current_user.get('name'),
            'user_email': current_user.get('email'),
            'user_phone': current_user.get('phone'),
            'documents': {
                'national_id_front_url': verification_data.national_id_front_url,
                'national_id_back_url': verification_data.national_id_back_url,
                'business_license_url': verification_data.business_license_url,
                'proof_of_address_url': verification_data.proof_of_address_url,
                'selfie_url': verification_data.selfie_url
            },
            'status': VerificationStatus.PAYMENT_PENDING,
            'verification_fee': verification_fee,
            'payment_status': 'pending',
            'agreed_to_terms': True,
            'submitted_at': datetime.utcnow(),
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }

        result = await db.verifications.insert_one(verification)
        verification_id = str(result.inserted_id)

        logger.info(f"✅ Verification submitted for user {current_user['_id']} - Verification ID: {verification_id}")

        return {
            'message': 'Verification submitted successfully. Please complete payment to continue.',
            'verification_id': verification_id,
            'verification_fee': verification_fee,
            'status': VerificationStatus.PAYMENT_PENDING
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error submitting verification: {e}")
        raise HTTPException(status_code=500, detail="Failed to submit verification")


@api_router.post("/verification/pay")
async def pay_verification_fee(
    payment_data: VerificationPaymentRequest,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Process verification fee payment"""
    try:
        settings = await _get_platform_settings_internal()
        default_verification_fee = settings.get('verificationFee', VERIFICATION_FEE)

        idempotency_key = _require_idempotency_key(request)
        idempotency_scope = 'verification_payment'
        request_hash = _hash_request_payload({
            'verification_id': payment_data.verification_id,
            'payment_method': payment_data.payment_method,
            'phone_number': payment_data.phone_number
        })
        idempotency_response = await _get_idempotency_response(
            idempotency_key,
            idempotency_scope,
            str(current_user['_id']),
            request_hash
        )
        if idempotency_response is not None:
            return idempotency_response

        logger.info(f"🔄 Processing verification payment for user {current_user['_id']}, verification_id: {payment_data.verification_id}, method: {payment_data.payment_method}")

        # Validate verification_id format
        try:
            verification_obj_id = ObjectId(payment_data.verification_id)
        except Exception as e:
            logger.error(f"❌ Invalid verification_id format: {payment_data.verification_id} - {e}")
            raise HTTPException(status_code=400, detail=f"Invalid verification ID format")

        # Get verification
        verification = await db.verifications.find_one({
            '_id': verification_obj_id,
            'user_id': str(current_user['_id'])
        })

        if not verification:
            logger.error(f"❌ Verification not found: {payment_data.verification_id} for user {current_user['_id']}")
            raise HTTPException(status_code=404, detail="Verification not found or you don't have permission to access it")

        if verification.get('payment_status') == 'paid':
            logger.warning(f"⚠️ Verification {payment_data.verification_id} already paid")
            raise HTTPException(status_code=400, detail="Verification fee already paid")

        verification_fee = verification.get('verification_fee', default_verification_fee)
        logger.info(f"💰 Verification fee amount: KES {verification_fee}")

        if payment_data.payment_method == PaymentMethod.WALLET:
            # Process wallet payment
            logger.info(f"💳 Processing wallet payment for user {current_user['_id']}")
            user_wallet = await get_or_create_wallet(str(current_user['_id']))

            current_balance = float(user_wallet.get('balance', 0))
            logger.info(f"💰 User wallet balance: KES {current_balance}, Required: KES {verification_fee}")

            if current_balance < verification_fee:
                logger.warning(f"⚠️ Insufficient wallet balance for user {current_user['_id']}: has {current_balance}, needs {verification_fee}")
                raise HTTPException(
                    status_code=400,
                    detail=f"Insufficient wallet balance. You have KES {current_balance:.2f}, but need KES {verification_fee:.2f}. Please top up your wallet or use M-Pesa payment."
                )

            # Create user deduction transaction
            logger.info(f"???? Creating user deduction transaction")
            user_txn = await create_transaction(
                user_id=str(current_user['_id']),
                amount=-verification_fee,
                transaction_type=TransactionType.PLATFORM_FEE_VERIFICATION,
                status=TransactionStatus.COMPLETED,
                description=f'Seller verification fee (Verification ID: {payment_data.verification_id[:8]})',
                order_id=None
            )

            logger.info(f"???? Debiting KES {verification_fee} from user {current_user['_id']} wallet")
            await debit_wallet_balance(str(current_user['_id']), verification_fee, str(user_txn['_id']))

            # Create platform earning transaction
            logger.info(f"???? Creating platform earning transaction")
            platform_txn = await create_transaction(
                user_id=PLATFORM_WALLET_ID,
                amount=verification_fee,
                transaction_type=TransactionType.PLATFORM_FEE_VERIFICATION,
                status=TransactionStatus.COMPLETED,
                description=f'Verification fee from {current_user["name"]} (Verification ID: {payment_data.verification_id[:8]})',
                order_id=None
            )
            await update_wallet_balance(PLATFORM_WALLET_ID, verification_fee, str(platform_txn['_id']))


            # Update verification payment status
            logger.info(f"📋 Updating verification status to paid and under review")
            result = await db.verifications.update_one(
                {'_id': verification_obj_id},
                {
                    '$set': {
                        'payment_status': 'paid',
                        'payment_method': 'wallet',
                        'paid_at': datetime.utcnow(),
                        'status': VerificationStatus.UNDER_REVIEW,
                        'updated_at': datetime.utcnow()
                    }
                }
            )

            if result.modified_count == 0:
                logger.warning(f"⚠️ Failed to update verification status (may already be updated): {payment_data.verification_id}")

            # Update user KYC status to pending
            logger.info(f"👤 Updating user KYC status to PENDING")
            await db.users.update_one(
                {'_id': current_user['_id']},
                {'$set': {'kyc_status': KYCStatus.PENDING}}
            )

            # Send notification
            logger.info(f"🔔 Sending success notification to user")
            await create_notification(
                db=db,
                user_id=str(current_user['_id']),
                notification_type=NotificationType.ORDER_UPDATED,
                title="Verification Submitted",
                message=f"Your verification has been submitted for review. You will be notified once reviewed.",
                data={'verification_id': payment_data.verification_id}
            )

            logger.info(f"✅ Verification fee paid successfully for user {current_user['_id']} via wallet - Amount: KES {verification_fee}")

            response_payload = {
                'success': True,
                'message': 'Verification fee paid successfully. Your verification is now under review.',
                'payment_method': 'wallet',
                'amount': verification_fee,
                'status': VerificationStatus.UNDER_REVIEW
            }
            await _finalize_idempotency(
                idempotency_key,
                idempotency_scope,
                str(current_user['_id']),
                response_payload
            )
            return response_payload

        elif payment_data.payment_method == PaymentMethod.MPESA:
            # Validate phone number
            logger.info(f"📱 Processing M-Pesa payment for user {current_user['_id']}")

            if not payment_data.phone_number:
                logger.error(f"❌ Phone number not provided for M-Pesa payment")
                raise HTTPException(status_code=400, detail="Phone number required for M-Pesa payment")

            # Validate phone format
            phone = payment_data.phone_number.strip()
            original_phone = phone

            if not phone.startswith('254'):
                if phone.startswith('0'):
                    phone = '254' + phone[1:]
                elif phone.startswith('+254'):
                    phone = phone[1:]
                elif phone.startswith('7') or phone.startswith('1'):
                    phone = '254' + phone

            if len(phone) != 12 or not phone.isdigit():
                logger.error(f"❌ Invalid phone number format: {original_phone}")
                raise HTTPException(status_code=400, detail=f"Invalid phone number format: {original_phone}. Please use format: 0712345678 or 254712345678")

            logger.info(f"📲 Initiating M-Pesa STK push to {phone} for KES {verification_fee}")

            # Initiate M-Pesa STK push
            try:
                verification_amount = int(_round_payment_amount(verification_fee)) if MPESA_ENVIRONMENT == 'production' else int(verification_fee)
                result = mpesa_service.stk_push(
                    phone_number=phone,
                    amount=verification_amount,
                    account_reference=f"VER{payment_data.verification_id[:8]}",
                    transaction_desc=f"Seller verification fee - PetSoko"
                )
            except Exception as mpesa_error:
                logger.error(f"❌ M-Pesa STK push exception: {mpesa_error}")
                raise HTTPException(status_code=500, detail=f"M-Pesa service error. Please try again later.")

            if not result.get('success'):
                error_msg = result.get('errorMessage', 'M-Pesa payment initiation failed')
                logger.error(f"❌ M-Pesa STK push failed: {error_msg}")
                raise HTTPException(status_code=400, detail=f"M-Pesa payment failed: {error_msg}. Please check your phone number and try again.")

            # Update verification with M-Pesa checkout ID
            logger.info(f"📋 Updating verification with M-Pesa checkout details")
            checkout_request_id = result.get('checkout_request_id') or result.get('CheckoutRequestID')
            merchant_request_id = result.get('merchant_request_id') or result.get('MerchantRequestID')
            await db.verifications.update_one(
                {'_id': verification_obj_id},
                {
                    '$set': {
                        'payment_method': 'mpesa',
                        'mpesa_checkout_request_id': checkout_request_id,
                        'mpesa_merchant_request_id': merchant_request_id,
                        'phone_number': phone,
                        'updated_at': datetime.utcnow()
                    }
                }
            )

            logger.info(f"✅ M-Pesa STK push initiated successfully for verification {payment_data.verification_id}, CheckoutRequestID: {checkout_request_id}")

            response_payload = {
                'success': True,
                'message': 'M-Pesa payment initiated. Please check your phone and enter your M-Pesa PIN to complete the payment.',
                'payment_method': 'mpesa',
                'amount': verification_fee,
                'checkout_request_id': checkout_request_id,
                'merchant_request_id': merchant_request_id
            }
            await _finalize_idempotency(
                idempotency_key,
                idempotency_scope,
                str(current_user['_id']),
                response_payload
            )
            return response_payload

        else:
            logger.error(f"❌ Invalid payment method: {payment_data.payment_method}")
            raise HTTPException(status_code=400, detail="Invalid payment method. Please use 'wallet' or 'mpesa'")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error processing verification payment for user {current_user['_id']}: {str(e)}", exc_info=True)
        await _finalize_idempotency(
            idempotency_key,
            'verification_payment',
            str(current_user['_id']),
            {'success': False, 'message': 'Verification payment failed'},
            status='failed'
        )
        raise HTTPException(status_code=500, detail=f"Failed to process payment. Please try again or contact support if the issue persists.")


@api_router.get("/verification/status")
async def get_verification_status(current_user: dict = Depends(get_current_user)):
    """Get current user's verification status"""
    try:
        settings = await _get_platform_settings_internal()
        verification_fee = settings.get('verificationFee', VERIFICATION_FEE)

        # Get latest verification
        verification = await db.verifications.find_one(
            {'user_id': str(current_user['_id'])},
            sort=[('created_at', -1)]
        )

        if not verification:
            return {
                'has_verification': False,
                'status': VerificationStatus.NOT_SUBMITTED,
                'kyc_status': current_user.get('kyc_status', 'pending'),
                'verification_fee': verification_fee
            }

        return {
            'has_verification': True,
            'verification_id': str(verification['_id']),
            'status': verification.get('status'),
            'payment_status': verification.get('payment_status'),
            'kyc_status': current_user.get('kyc_status'),
            'submitted_at': verification.get('submitted_at'),
            'paid_at': verification.get('paid_at'),
            'reviewed_at': verification.get('reviewed_at'),
            'rejection_reason': verification.get('rejection_reason'),
            'verification_fee': verification.get('verification_fee', verification_fee)
        }

    except Exception as e:
        logger.error(f"Error getting verification status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get verification status")


@api_router.get("/verification/status/{verification_id}")
async def get_verification_status_by_id(
    verification_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Get specific verification status by ID
    Used by frontend to poll for payment confirmation
    Returns detailed status information for better UX
    """
    try:
        settings = await _get_platform_settings_internal()
        verification_fee = settings.get('verificationFee', VERIFICATION_FEE)

        # Validate verification_id format
        try:
            verification_obj_id = ObjectId(verification_id)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid verification ID format")

        # Get verification
        verification = await db.verifications.find_one({
            '_id': verification_obj_id,
            'user_id': str(current_user['_id'])
        })

        if not verification:
            raise HTTPException(status_code=404, detail="Verification not found or you don't have permission to access it")

        payment_status = verification.get('payment_status', 'pending')
        status = verification.get('status', VerificationStatus.PAYMENT_PENDING)

        response = {
            'verification_id': verification_id,
            'payment_status': payment_status,
            'status': status,
            'verification_fee': verification.get('verification_fee', verification_fee),
            'payment_method': verification.get('payment_method'),
            'mpesa_receipt_number': verification.get('mpesa_receipt_number'),
            'created_at': verification.get('created_at').isoformat() if verification.get('created_at') else None,
            'submitted_at': verification.get('submitted_at').isoformat() if verification.get('submitted_at') else None,
            'paid_at': verification.get('paid_at').isoformat() if verification.get('paid_at') else None,
            'updated_at': verification.get('updated_at').isoformat() if verification.get('updated_at') else None,
        }

        # Add specific messages based on payment status
        if payment_status == 'paid':
            response['message'] = '🎉 Payment successful! Your verification is now under review.'
            response['status_title'] = 'Payment Successful'
            response['status_icon'] = 'checkmark-circle'
        elif payment_status == 'failed':
            error_msg = verification.get('payment_error_message', 'Payment failed or was cancelled')
            response['message'] = f'Payment failed: {error_msg}'
            response['status_title'] = 'Payment Failed'
            response['status_icon'] = 'close-circle'
        elif payment_status == 'pending':
            # Calculate elapsed time for progressive messaging
            created_at = verification.get('created_at')
            if created_at:
                elapsed_seconds = (datetime.utcnow() - created_at).total_seconds()
                response['elapsed_seconds'] = int(elapsed_seconds)

                if elapsed_seconds > 90:
                    response['message'] = '⏱️ Still waiting... This is taking longer than usual. Please check your phone.'
                elif elapsed_seconds > 60:
                    response['message'] = '⏳ Waiting for M-Pesa confirmation... Please complete the prompt on your phone.'
                else:
                    response['message'] = '📱 Waiting for payment... Please check your phone for M-Pesa prompt.'
            else:
                response['message'] = '📱 Waiting for payment confirmation...'
        else:
            response['message'] = f'Payment status: {payment_status}'

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting verification status by ID: {e}")
        raise HTTPException(status_code=500, detail="Failed to get verification status")


@api_router.post("/verification/cancel")
async def cancel_verification_payment(
    cancellation_data: VerificationCancellationRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Legacy endpoint kept for backward compatibility.
    Verification status is now only updated from successful payment webhooks.
    """
    raise HTTPException(
        status_code=410,
        detail="Verification test cancellation is disabled. Complete payment via wallet or M-Pesa and wait for webhook confirmation."
    )


# Admin endpoints for verification management

@api_router.get("/admin/verifications")
async def get_all_verifications(
    status: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    limit: int = 50,
    current_user: dict = Depends(require_admin)
):
    """Get all verification requests (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Build query
        query = {}
        if status:
            query['status'] = status
        if search:
            query['$or'] = [
                {'user_name': {'$regex': search, '$options': 'i'}},
                {'user_email': {'$regex': search, '$options': 'i'}},
                {'user_phone': {'$regex': search, '$options': 'i'}}
            ]

        # Get total count
        total = await db.verifications.count_documents(query)

        # Get verifications with pagination
        skip = (page - 1) * limit
        verifications = await db.verifications.find(query).sort('created_at', -1).skip(skip).limit(limit).to_list(None)

        # Format response
        formatted_verifications = []
        for v in verifications:
            formatted_verifications.append({
                'id': str(v['_id']),
                'user_id': v['user_id'],
                'user_name': v.get('user_name'),
                'user_email': v.get('user_email'),
                'user_phone': v.get('user_phone'),
                'status': v.get('status'),
                'payment_status': v.get('payment_status'),
                'verification_fee': v.get('verification_fee', VERIFICATION_FEE),
                'documents': v.get('documents', {}),
                'submitted_at': v.get('submitted_at').isoformat() if v.get('submitted_at') else None,
                'paid_at': v.get('paid_at').isoformat() if v.get('paid_at') else None,
                'reviewed_at': v.get('reviewed_at').isoformat() if v.get('reviewed_at') else None,
                'reviewed_by': v.get('reviewed_by'),
                'rejection_reason': v.get('rejection_reason')
            })

        return {
            'verifications': formatted_verifications,
            'total': total,
            'page': page,
            'limit': limit,
            'totalPages': (total + limit - 1) // limit
        }

    except Exception as e:
        logger.error(f"Error getting verifications: {e}")
        raise HTTPException(status_code=500, detail="Failed to get verifications")


@api_router.get("/admin/verifications/{verification_id}")
async def get_verification_details(
    verification_id: str,
    current_user: dict = Depends(require_admin)
):
    """Get verification details (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        verification = await db.verifications.find_one({'_id': ObjectId(verification_id)})

        if not verification:
            raise HTTPException(status_code=404, detail="Verification not found")

        # Get user details
        user = await db.users.find_one({'_id': ObjectId(verification['user_id'])})

        # Fetch seller's listings to get their certifications
        seller_certifications = []
        try:
            listings = await db.service_listings.find({
                'seller_id': verification['user_id']
            }).to_list(length=None)

            # Collect all certifications from all listings
            for listing in listings:
                certs = listing.get('certifications', [])
                if certs:
                    for cert_url in certs:
                        seller_certifications.append({
                            'url': cert_url,
                            'listing_id': str(listing.get('_id')),
                            'listing_name': listing.get('service_name', 'Unknown Service'),
                            'uploaded_at': listing.get('created_at')
                        })
        except Exception as e:
            logger.warning(f"Failed to fetch seller certifications: {e}")
            # Continue without certifications if there's an error

        return {
            'id': str(verification['_id']),
            'user': {
                'id': verification['user_id'],
                'name': user.get('name') if user else verification.get('user_name'),
                'email': user.get('email') if user else verification.get('user_email'),
                'phone': user.get('phone') if user else verification.get('user_phone'),
                'kyc_status': user.get('kyc_status') if user else 'unknown'
            },
            'documents': verification.get('documents', {}),
            'certifications': seller_certifications,
            'status': verification.get('status'),
            'payment_status': verification.get('payment_status'),
            'payment_method': verification.get('payment_method'),
            'verification_fee': verification.get('verification_fee', VERIFICATION_FEE),
            'submitted_at': verification.get('submitted_at'),
            'paid_at': verification.get('paid_at'),
            'reviewed_at': verification.get('reviewed_at'),
            'reviewed_by': verification.get('reviewed_by'),
            'rejection_reason': verification.get('rejection_reason'),
            'created_at': verification.get('created_at'),
            'updated_at': verification.get('updated_at')
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting verification details: {e}")
        raise HTTPException(status_code=500, detail="Failed to get verification details")


@api_router.post("/admin/verifications/{verification_id}/approve")
async def approve_verification(
    verification_id: str,
    override_payment: bool = False,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """Approve seller verification (admin only)

    Args:
        verification_id: ID of the verification to approve
        override_payment: If True, allows approval even without payment (admin override)
        current_user: Current authenticated user (must be admin)
    """
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        verification = await db.verifications.find_one({'_id': ObjectId(verification_id)})

        if not verification:
            raise HTTPException(status_code=404, detail="Verification not found")

        before_state = {
            'status': verification.get('status'),
            'payment_status': verification.get('payment_status'),
            'payment_overridden': verification.get('payment_overridden', False)
        }

        # Check payment status unless overridden
        payment_status = verification.get('payment_status')
        if not override_payment and payment_status != 'paid':
            raise HTTPException(
                status_code=400,
                detail=f"Verification fee must be paid before approval. Current payment status: {payment_status or 'not started'}. Use override_payment=true to bypass this check."
            )

        # Update verification status
        update_data = {
            'status': VerificationStatus.VERIFIED,
            'reviewed_at': datetime.utcnow(),
            'reviewed_by': str(current_user['_id']),
            'updated_at': datetime.utcnow()
        }

        # If payment was overridden, mark it in the record
        if override_payment and payment_status != 'paid':
            update_data['payment_overridden'] = True
            update_data['payment_overridden_by'] = str(current_user['_id'])
            update_data['payment_overridden_at'] = datetime.utcnow()

        await db.verifications.update_one(
            {'_id': ObjectId(verification_id)},
            {'$set': update_data}
        )

        # Update user KYC status to verified
        await db.users.update_one(
            {'_id': ObjectId(verification['user_id'])},
            {
                '$set': {
                    'kyc_status': KYCStatus.VERIFIED,
                    'kyc_verified_at': datetime.utcnow(),
                    'kyc_verified_by': str(current_user['_id']),
                    'updated_at': datetime.utcnow()
                }
            }
        )

        await log_admin_audit(
            action='verification.approve',
            actor=current_user,
            target_type='verification',
            target_id=verification_id,
            before=before_state,
            after={
                'status': VerificationStatus.VERIFIED,
                'payment_overridden': override_payment and payment_status != 'paid'
            },
            payload={'override_payment': override_payment, 'payment_status': payment_status},
            request=http_request
        )

        # Send notification to user
        await create_notification(
            db=db,
            user_id=verification['user_id'],
            notification_type=NotificationType.ORDER_UPDATED,
            title="✅ Verification Approved!",
            message="Congratulations! Your seller verification has been approved. You now have a verified badge on your listings.",
            data={'verification_id': verification_id}
        )

        logger.info(f"✅ Verification {verification_id} approved by admin {current_user['name']}" +
                   (f" (payment overridden)" if override_payment and payment_status != 'paid' else ""))

        return {
            'message': 'Verification approved successfully',
            'verification_id': verification_id,
            'user_id': verification['user_id'],
            'payment_overridden': override_payment and payment_status != 'paid'
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error approving verification {verification_id}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to approve verification: {str(e)}")


@api_router.post("/admin/verifications/{verification_id}/reject")
async def reject_verification(
    verification_id: str,
    reject_data: RejectVerificationRequest,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """Reject seller verification (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    reason = reject_data.reason
    if not reason or len(reason.strip()) < 10:
        raise HTTPException(status_code=400, detail="Rejection reason must be at least 10 characters")

    try:
        verification = await db.verifications.find_one({'_id': ObjectId(verification_id)})

        if not verification:
            raise HTTPException(status_code=404, detail="Verification not found")

        before_state = {
            'status': verification.get('status'),
            'rejection_reason': verification.get('rejection_reason')
        }

        # Update verification status
        await db.verifications.update_one(
            {'_id': ObjectId(verification_id)},
            {
                '$set': {
                    'status': VerificationStatus.REJECTED,
                    'rejection_reason': reason,
                    'reviewed_at': datetime.utcnow(),
                    'reviewed_by': str(current_user['_id']),
                    'updated_at': datetime.utcnow()
                }
            }
        )

        # Update user KYC status to rejected
        await db.users.update_one(
            {'_id': ObjectId(verification['user_id'])},
            {
                '$set': {
                    'kyc_status': KYCStatus.REJECTED,
                    'kyc_rejection_reason': reason,
                    'kyc_rejected_at': datetime.utcnow(),
                    'kyc_rejected_by': str(current_user['_id']),
                    'updated_at': datetime.utcnow()
                }
            }
        )

        await log_admin_audit(
            action='verification.reject',
            actor=current_user,
            target_type='verification',
            target_id=verification_id,
            before=before_state,
            after={'status': VerificationStatus.REJECTED, 'rejection_reason': reason},
            payload={'reason': reason},
            request=http_request
        )

        # Send notification to user
        await create_notification(
            db=db,
            user_id=verification['user_id'],
            notification_type=NotificationType.ORDER_UPDATED,
            title="Verification Rejected",
            message=f"Your verification has been rejected. Reason: {reason}. You can submit a new verification with corrected documents.",
            data={'verification_id': verification_id, 'reason': reason}
        )

        logger.info(f"❌ Verification {verification_id} rejected by admin {current_user['name']}")

        return {
            'message': 'Verification rejected',
            'verification_id': verification_id,
            'user_id': verification['user_id'],
            'reason': reason
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error rejecting verification: {e}")
        raise HTTPException(status_code=500, detail="Failed to reject verification")


# ============================================================================
# Job Posting Routes
# ============================================================================

# Admin: Get and set job posting fee and promotional message
@api_router.get("/admin/job-posting/settings")
async def get_job_posting_settings_admin(current_user: dict = Depends(require_admin)):
    """Get job posting fee and promotional message (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        settings = await get_job_posting_settings()
        return settings
    except Exception as e:
        logger.error(f"Error fetching job posting settings: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch job posting settings")

@api_router.put("/admin/job-posting/settings")
async def update_job_posting_settings(
    settings_update: JobPostingFeeUpdate,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """Update job posting fee and promotional message (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        before_settings = await get_job_posting_settings()
        # Validate posting fee
        if settings_update.posting_fee < 0:
            raise HTTPException(status_code=400, detail="Posting fee cannot be negative")

        # Update settings
        update_doc = {
            'jobPostingFee': settings_update.posting_fee,
            'updatedAt': datetime.utcnow()
        }

        if settings_update.promotional_message is not None:
            update_doc['jobPostingPromotionalMessage'] = settings_update.promotional_message

        await db.settings.update_one(
            {'key': 'platform_config'},
            {'$set': update_doc},
            upsert=True
        )

        # Invalidate cache
        invalidate_settings_cache()

        after_settings = {
            'jobPostingFee': settings_update.posting_fee,
            'jobPostingPromotionalMessage': settings_update.promotional_message or ''
        }

        await log_admin_audit(
            action='job_posting.settings_update',
            actor=current_user,
            target_type='settings',
            target_id='job_posting',
            before=before_settings,
            after=after_settings,
            payload=settings_update.dict(exclude_none=True),
            request=http_request
        )

        logger.info(f"Job posting settings updated by admin {current_user['name']}: Fee={settings_update.posting_fee}, Message={settings_update.promotional_message}")

        return {
            'success': True,
            'message': 'Job posting settings updated successfully',
            'jobPostingFee': settings_update.posting_fee,
            'jobPostingPromotionalMessage': settings_update.promotional_message or ''
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating job posting settings: {e}")
        raise HTTPException(status_code=500, detail="Failed to update job posting settings")

# Public: Get job posting fee and promotional message
@api_router.get("/job-posting/settings")
async def get_job_posting_settings_public():
    """Get job posting fee and promotional message (public)"""
    try:
        settings = await get_job_posting_settings()
        return settings
    except Exception as e:
        logger.error(f"Error fetching job posting settings: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch job posting settings")

# Corporate: Create job posting (draft)
@api_router.post("/job-postings", response_model=JobPosting)
async def create_job_posting(
    posting_data: JobPostingCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new job posting (corporate users)"""
    try:
        # Get job posting fee
        settings = await get_job_posting_settings()
        posting_fee = settings['jobPostingFee']

        # Create job posting as draft
        job_posting = {
            'id': str(uuid.uuid4()),
            'company_id': str(current_user['_id']),
            'company_name': posting_data.company_name,
            'job_title': posting_data.job_title,
            'employment_type': posting_data.employment_type,
            'experience_level': posting_data.experience_level,
            'location': posting_data.location,
            'salary_range_min': posting_data.salary_range_min,
            'salary_range_max': posting_data.salary_range_max,
            'salary_currency': posting_data.salary_currency,
            'job_description': posting_data.job_description,
            'requirements': posting_data.requirements,
            'responsibilities': posting_data.responsibilities,
            'benefits': posting_data.benefits,
            'application_deadline': posting_data.application_deadline,
            'application_email': posting_data.application_email,
            'application_url': posting_data.application_url,
            'contact_phone': posting_data.contact_phone,
            'status': JobStatus.DRAFT,
            'payment_status': PaymentStatus.PENDING,
            'posting_fee': posting_fee,
            'mpesa_checkout_request_id': None,
            'posted_at': None,
            'expires_at': None,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }

        await db.job_postings.insert_one(job_posting)

        logger.info(f"Job posting created by user {current_user['name']}: {job_posting['id']}")

        return job_posting
    except Exception as e:
        logger.error(f"Error creating job posting: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create job posting: {str(e)}")

# Corporate: Get all job postings for current user
@api_router.get("/job-postings", response_model=List[JobPosting])
async def get_job_postings(
    current_user: dict = Depends(get_current_user),
    status: Optional[JobStatus] = None
):
    """Get job postings for current corporate user"""
    try:
        query = {'company_id': str(current_user['_id'])}
        if status:
            query['status'] = status

        postings = await db.job_postings.find(query).sort('created_at', -1).to_list(100)

        return postings
    except Exception as e:
        logger.error(f"Error fetching job postings: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch job postings")

# Public: Get active job postings
@api_router.get("/job-postings/active", response_model=List[JobPosting])
async def get_active_job_postings(
    skip: int = 0,
    limit: int = 50,
    employment_type: Optional[JobEmploymentType] = None,
    experience_level: Optional[JobExperienceLevel] = None,
    location: Optional[str] = None
):
    """Get all active job postings (public)"""
    try:
        query = {'status': JobStatus.ACTIVE, 'payment_status': PaymentStatus.PAID}

        # Add filters
        if employment_type:
            query['employment_type'] = employment_type
        if experience_level:
            query['experience_level'] = experience_level
        if location:
            query['location'] = {'$regex': location, '$options': 'i'}

        postings = await db.job_postings.find(query).sort('posted_at', -1).skip(skip).limit(limit).to_list(limit)

        return postings
    except Exception as e:
        logger.error(f"Error fetching active job postings: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch job postings")

# Get specific job posting
@api_router.get("/job-postings/{job_posting_id}", response_model=JobPosting)
async def get_job_posting(job_posting_id: str):
    """Get specific job posting by ID"""
    try:
        posting = await db.job_postings.find_one({'id': job_posting_id})
        if not posting:
            raise HTTPException(status_code=404, detail="Job posting not found")

        return posting
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching job posting: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch job posting")

# Corporate: Update job posting
@api_router.patch("/job-postings/{job_posting_id}", response_model=JobPosting)
async def update_job_posting(
    job_posting_id: str,
    update_data: JobPostingUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update job posting"""
    try:
        posting = await db.job_postings.find_one({'id': job_posting_id})
        if not posting:
            raise HTTPException(status_code=404, detail="Job posting not found")

        # Verify ownership
        if posting['company_id'] != str(current_user['_id']):
            raise HTTPException(status_code=403, detail="Not authorized to update this job posting")

        # Build update document
        update_doc = {'updated_at': datetime.utcnow()}

        # Handle status updates separately
        if update_data.status is not None:
            current_status = posting['status']
            new_status = update_data.status

            # Allow these status transitions:
            # ACTIVE -> PAUSED, ACTIVE -> CLOSED
            # PAUSED -> ACTIVE, PAUSED -> CLOSED
            # DRAFT -> PENDING_PAYMENT (handled elsewhere via payment)
            allowed_transitions = {
                JobStatus.ACTIVE: [JobStatus.PAUSED, JobStatus.CLOSED],
                JobStatus.PAUSED: [JobStatus.ACTIVE, JobStatus.CLOSED],
                JobStatus.DRAFT: [JobStatus.PENDING_PAYMENT],
                JobStatus.PENDING_PAYMENT: [JobStatus.DRAFT]
            }

            if current_status in allowed_transitions and new_status in allowed_transitions[current_status]:
                update_doc['status'] = new_status
            else:
                raise HTTPException(status_code=400, detail=f"Cannot change status from {current_status} to {new_status}")

        # Only allow content updates if in draft or pending payment
        if posting['status'] in [JobStatus.DRAFT, JobStatus.PENDING_PAYMENT]:
            if update_data.job_title is not None:
                update_doc['job_title'] = update_data.job_title
            if update_data.employment_type is not None:
                update_doc['employment_type'] = update_data.employment_type
            if update_data.experience_level is not None:
                update_doc['experience_level'] = update_data.experience_level
            if update_data.location is not None:
                update_doc['location'] = update_data.location
            if update_data.salary_range_min is not None:
                update_doc['salary_range_min'] = update_data.salary_range_min
            if update_data.salary_range_max is not None:
                update_doc['salary_range_max'] = update_data.salary_range_max
            if update_data.job_description is not None:
                update_doc['job_description'] = update_data.job_description
            if update_data.requirements is not None:
                update_doc['requirements'] = update_data.requirements
            if update_data.responsibilities is not None:
                update_doc['responsibilities'] = update_data.responsibilities
            if update_data.benefits is not None:
                update_doc['benefits'] = update_data.benefits
            if update_data.application_deadline is not None:
                update_doc['application_deadline'] = update_data.application_deadline
            if update_data.application_email is not None:
                update_doc['application_email'] = update_data.application_email
            if update_data.application_url is not None:
                update_doc['application_url'] = update_data.application_url
            if update_data.contact_phone is not None:
                update_doc['contact_phone'] = update_data.contact_phone
        elif update_data.status is None:
            # If not a status-only update and not in editable status, reject
            raise HTTPException(status_code=400, detail="Cannot update job posting content in current status. Only status changes allowed.")

        await db.job_postings.update_one(
            {'id': job_posting_id},
            {'$set': update_doc}
        )

        updated_posting = await db.job_postings.find_one({'id': job_posting_id})

        logger.info(f"Job posting {job_posting_id} updated by user {current_user['name']}")

        return updated_posting
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating job posting: {e}")
        raise HTTPException(status_code=500, detail="Failed to update job posting")

# Corporate: Delete job posting
@api_router.delete("/job-postings/{job_posting_id}")
async def delete_job_posting(
    job_posting_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete job posting"""
    try:
        posting = await db.job_postings.find_one({'id': job_posting_id})
        if not posting:
            raise HTTPException(status_code=404, detail="Job posting not found")

        # Verify ownership
        if posting['company_id'] != str(current_user['_id']):
            raise HTTPException(status_code=403, detail="Not authorized to delete this job posting")

        # Allow deletion in any status - companies should be able to remove their postings
        await db.job_postings.delete_one({'id': job_posting_id})

        logger.info(f"Job posting {job_posting_id} (status: {posting['status']}) deleted by user {current_user['name']}")

        return {'message': 'Job posting deleted successfully'}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting job posting: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete job posting")

# Corporate: Initiate payment for job posting
@api_router.post("/job-postings/pay")
async def pay_job_posting_fee(
    payment_request: JobPostingPaymentRequest,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Initiate payment for job posting fee"""
    try:
        idempotency_key = _require_idempotency_key(request)
        idempotency_scope = 'job_posting_payment'
        request_hash = _hash_request_payload({
            'job_posting_id': payment_request.job_posting_id,
            'payment_method': payment_request.payment_method,
            'phone_number': payment_request.phone_number
        })
        idempotency_response = await _get_idempotency_response(
            idempotency_key,
            idempotency_scope,
            str(current_user['_id']),
            request_hash
        )
        if idempotency_response is not None:
            return idempotency_response

        # Get job posting
        posting = await db.job_postings.find_one({'id': payment_request.job_posting_id})
        if not posting:
            raise HTTPException(status_code=404, detail="Job posting not found")

        # Verify ownership
        if posting['company_id'] != str(current_user['_id']):
            raise HTTPException(status_code=403, detail="Not authorized")

        # Check if already paid
        if posting['payment_status'] == PaymentStatus.PAID:
            raise HTTPException(status_code=400, detail="Job posting fee already paid")

        posting_fee = posting['posting_fee']
        payment_method = payment_request.payment_method

        # Handle wallet payment
        if payment_method == PaymentMethod.WALLET:
            # Check balance
            user_wallet = await get_or_create_wallet(str(current_user['_id']))
            if user_wallet['balance'] < posting_fee:
                raise HTTPException(
                    status_code=400,
                    detail=f"Insufficient wallet balance. Available: KES {user_wallet['balance']:.2f}, Required: KES {posting_fee:.2f}"
                )

            # Deduct from wallet
            buyer_txn = await create_transaction(
                user_id=str(current_user['_id']),
                amount=-posting_fee,
                transaction_type=TransactionType.ORDER_PAYMENT,
                status=TransactionStatus.COMPLETED,
                description=f"Job posting fee for '{posting['job_title']}'",
                order_id=payment_request.job_posting_id
            )

            await debit_wallet_balance(
                str(current_user['_id']),
                posting_fee,
                str(buyer_txn['_id'])
            )

            # Credit platform wallet
            platform_txn = await create_transaction(
                user_id=PLATFORM_WALLET_ID,
                amount=posting_fee,
                transaction_type=TransactionType.PLATFORM_FEE_JOB_POSTING,
                status=TransactionStatus.COMPLETED,
                description=f"Job posting fee from {current_user.get('name', 'user')}",
                order_id=payment_request.job_posting_id
            )

            await update_wallet_balance(
                PLATFORM_WALLET_ID,
                posting_fee,
                str(platform_txn['_id'])
            )


            await db.wallets.update_one(
                {'user_id': PLATFORM_WALLET_ID},
                {'$inc': {'total_earned': posting_fee}}
            )

            # Update job posting status
            await db.job_postings.update_one(
                {'id': payment_request.job_posting_id},
                {
                    '$set': {
                        'payment_status': PaymentStatus.PAID,
                        'status': JobStatus.ACTIVE,
                        'posted_at': datetime.utcnow(),
                        'expires_at': datetime.utcnow() + timedelta(days=30),  # 30 days active
                        'updated_at': datetime.utcnow()
                    }
                }
            )

            logger.info(f"Job posting fee paid via wallet for posting {payment_request.job_posting_id}")

            response_payload = {
                'success': True,
                'message': f'Job posting fee of KES {posting_fee:.2f} paid successfully! Your job posting is now active.',
                'checkout_request_id': None,
                'merchant_request_id': None
            }
            await _finalize_idempotency(
                idempotency_key,
                idempotency_scope,
                str(current_user['_id']),
                response_payload
            )
            return response_payload

        # Handle M-Pesa payment
        elif payment_method == PaymentMethod.MPESA:
            if not payment_request.phone_number:
                raise HTTPException(status_code=400, detail="Phone number required for M-Pesa payment")

            # Initiate STK Push
            posting_amount = int(_round_payment_amount(posting_fee)) if MPESA_ENVIRONMENT == 'production' else int(posting_fee)
            mpesa_response = mpesa_service.stk_push(
                phone_number=payment_request.phone_number,
                amount=posting_amount,
                account_reference=payment_request.job_posting_id[:10],
                transaction_desc=f"Job posting fee - {posting['job_title'][:30]}"
            )

            if mpesa_response.get('success'):
                # Update job posting
                await db.job_postings.update_one(
                    {'id': payment_request.job_posting_id},
                    {
                        '$set': {
                            'mpesa_checkout_request_id': mpesa_response['checkout_request_id'],
                            'status': JobStatus.PENDING_PAYMENT,
                            'updated_at': datetime.utcnow()
                        }
                    }
                )

                logger.info(f"M-Pesa payment initiated for job posting {payment_request.job_posting_id}")

                response_payload = {
                    'success': True,
                    'message': f'Payment request sent to {payment_request.phone_number}. Please enter your M-Pesa PIN to complete.',
                    'checkout_request_id': mpesa_response['checkout_request_id'],
                    'merchant_request_id': mpesa_response['merchant_request_id']
                }
                await _finalize_idempotency(
                    idempotency_key,
                    idempotency_scope,
                    str(current_user['_id']),
                    response_payload
                )
                return response_payload
            else:
                logger.error(f"M-Pesa payment initiation failed: {mpesa_response.get('error')}")
                response_payload = {
                    'success': False,
                    'message': f"Payment failed: {mpesa_response.get('error', 'Unknown error')}"
                }
                await _finalize_idempotency(
                    idempotency_key,
                    idempotency_scope,
                    str(current_user['_id']),
                    response_payload,
                    status='failed'
                )
                return response_payload
        else:
            raise HTTPException(status_code=400, detail="Invalid payment method. Use 'wallet' or 'mpesa'")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing job posting payment: {str(e)}")
        await _finalize_idempotency(
            idempotency_key,
            'job_posting_payment',
            str(current_user['_id']),
            {'success': False, 'message': 'Job posting payment failed'},
            status='failed'
        )
        raise HTTPException(status_code=500, detail=f"Payment processing failed: {str(e)}")

# Admin: Get all job postings
@api_router.get("/admin/job-postings", response_model=List[JobPosting])
async def get_all_job_postings_admin(
    current_user: dict = Depends(require_admin),
    status: Optional[JobStatus] = None,
    skip: int = 0,
    limit: int = 100
):
    """Get all job postings (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        query = {}
        if status:
            query['status'] = status

        postings = await db.job_postings.find(query).sort('created_at', -1).skip(skip).limit(limit).to_list(limit)

        return postings
    except Exception as e:
        logger.error(f"Error fetching job postings: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch job postings")

# Admin: Update job posting status
@api_router.patch("/admin/job-postings/{job_posting_id}/status")
async def update_job_posting_status_admin(
    job_posting_id: str,
    status: JobStatus,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """Update job posting status (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        posting = await db.job_postings.find_one({'id': job_posting_id})
        if not posting:
            raise HTTPException(status_code=404, detail="Job posting not found")

        before_state = {'status': posting.get('status')}

        await db.job_postings.update_one(
            {'id': job_posting_id},
            {'$set': {'status': status, 'updated_at': datetime.utcnow()}}
        )

        await log_admin_audit(
            action='job_posting.status_update',
            actor=current_user,
            target_type='job_posting',
            target_id=job_posting_id,
            before=before_state,
            after={'status': status},
            payload={'status': status},
            request=http_request
        )

        logger.info(f"Job posting {job_posting_id} status updated to {status} by admin {current_user['name']}")

        return {'message': 'Job posting status updated successfully', 'status': status}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating job posting status: {e}")
        raise HTTPException(status_code=500, detail="Failed to update job posting status")

# Admin: Delete job posting
@api_router.delete("/admin/job-postings/{job_posting_id}")
async def delete_job_posting_admin(
    job_posting_id: str,
    current_user: dict = Depends(require_admin),
    http_request: Request = None
):
    """Delete job posting (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        posting = await db.job_postings.find_one({'id': job_posting_id})
        if not posting:
            raise HTTPException(status_code=404, detail="Job posting not found")

        before_state = {'status': posting.get('status')}

        # Delete the job posting
        result = await db.job_postings.delete_one({'id': job_posting_id})

        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Job posting not found")

        await log_admin_audit(
            action='job_posting.delete',
            actor=current_user,
            target_type='job_posting',
            target_id=job_posting_id,
            before=before_state,
            after=None,
            payload={'company_id': posting.get('company_id')},
            request=http_request
        )

        logger.info(f"Job posting {job_posting_id} deleted by admin {current_user['name']}")

        return {'message': 'Job posting deleted successfully', 'deleted_id': job_posting_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting job posting: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete job posting")


# Health check
@api_router.get("/health")
async def health_check():
    return {'status': 'healthy', 'service': 'PetSoko API'}

@api_router.post("/sentry/test")
async def sentry_test(current_user: dict = Depends(get_current_user)):
    """
    Admin-only endpoint to verify Sentry backend integration.
    Captures a synthetic exception and returns the Sentry event id.
    """
    if current_user.get('role') != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    if not SENTRY_DSN:
        raise HTTPException(status_code=400, detail="Sentry is not configured on this server")

    try:
        raise RuntimeError("Sentry backend smoke test")
    except Exception as exc:
        event_id = sentry_sdk.capture_exception(exc)
        sentry_sdk.flush(timeout=2.0)
        return {
            'success': True,
            'message': 'Sentry test event captured',
            'event_id': event_id,
        }

# ============================================================================
# CORS Configuration - Environment-Based for Security
# ============================================================================

# Get allowed origins from environment
cors_origins_str = os.environ.get('CORS_ORIGINS', '')
environment = ENVIRONMENT

# Parse CORS origins
if cors_origins_str:
    # Split by comma and strip whitespace
    allowed_origins = [origin.strip() for origin in cors_origins_str.split(',') if origin.strip()]
else:
    # Default based on environment
    if environment == 'production':
        # In production, CORS_ORIGINS must be explicitly set
        allowed_origins = []  # Will block all cross-origin requests - MUST be configured!
        logger.warning("⚠️  PRODUCTION MODE: CORS_ORIGINS not set! Cross-origin requests will be blocked.")
        logger.warning("⚠️  Please set CORS_ORIGINS environment variable with your frontend domain(s)")
    else:
        # Development defaults - local testing
        allowed_origins = [
            "http://localhost:3000",
            "http://localhost:3001",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:3001",
        ]

# Log CORS configuration on startup
logger.info("=" * 80)
logger.info("🌐 CORS Configuration")
logger.info("=" * 80)
logger.info(f"   Environment: {environment}")
logger.info(f"   Allowed Origins: {allowed_origins}")
logger.info(f"   Allow Credentials: True")
logger.info(f"   Allow Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS")
logger.info("=" * 80)

# Add CORS middleware BEFORE including router
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,           # ✅ Specific origins only (environment-based)
    allow_credentials=True,                  # ✅ Allow cookies/auth headers
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],  # ✅ Specific methods only
    allow_headers=["Content-Type", "Authorization", "Accept", "Origin", "X-Requested-With"],  # ✅ Specific headers
    expose_headers=["Content-Length", "Content-Type"],
    max_age=3600,  # Cache preflight requests for 1 hour
)

logger.info("✅ CORS middleware configured successfully")
logger.info("")

# Include router
app.include_router(api_router)

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "Welcome to PetSoko API! 🐾",
        "version": "1.0.0",
        "status": "operational",
        "documentation": "/docs",
        "health_check": "/api/health",
        "endpoints": {
            "auth": {
                "register": "POST /api/auth/register",
                "login": "POST /api/auth/login",
                "me": "GET /api/auth/me"
            },
            "pets": {
                "list": "GET /api/pets",
                "create": "POST /api/pets",
                "get": "GET /api/pets/{pet_id}",
                "update": "PATCH /api/pets/{pet_id}"
            },
            "orders": {
                "list": "GET /api/orders",
                "create": "POST /api/orders",
                "get": "GET /api/orders/{order_id}"
            },
            "sellers": {
                "apply": "POST /api/sellers/apply",
                "profile": "GET /api/sellers/{seller_id}",
                "dashboard": "GET /api/sellers/{seller_id}/dashboard"
            }
        }
    }

# Root-level health check for Railway and other platforms
@app.get("/health")
async def root_health_check():
    """Root-level health check endpoint for deployment platforms"""
    return {'status': 'healthy', 'service': 'PetSoko API'}

# CORS Diagnostic Endpoint (Development Only)
@app.get("/api/cors-info")
async def cors_info():
    """
    Returns current CORS configuration for diagnostics
    Only available in development mode for security
    """
    if environment == 'production':
        raise HTTPException(status_code=404, detail="Not found")

    return {
        "status": "CORS configuration details",
        "environment": environment,
        "allowed_origins": allowed_origins,
        "allow_credentials": True,
        "allow_methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "Accept", "Origin", "X-Requested-With"],
        "expose_headers": ["Content-Length", "Content-Type"],
        "max_age": 3600,
        "note": "This endpoint is only available in development mode"
    }

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    # CRITICAL: Validate production security configurations
    if ENVIRONMENT == 'production':
        logger.info("🔒 Validating production security configurations...")
        required_production_vars = {
            'REDIS_URL': 'Required for distributed rate limiting across Railway instances',
            'MPESA_WEBHOOK_SECRET': 'Required for M-Pesa webhook signature verification',
            'TRANSACTION_HASH_SECRET': 'Required for financial ledger integrity',
            'JWT_SECRET': 'Required for secure authentication tokens',
        }

        missing = []
        for var, reason in required_production_vars.items():
            if not os.environ.get(var):
                missing.append(f"  • {var}: {reason}")

        if missing:
            error_msg = (
                "❌ PRODUCTION SECURITY ERROR - Missing critical environment variables:\n" +
                "\n".join(missing) +
                "\n\nProduction deployment blocked. Configure these variables in Railway dashboard."
            )
            logger.error(error_msg)
            raise EnvironmentError(error_msg)

        logger.info("✅ All production security configurations validated")

    try:
        logger.info("🚀 Initializing Firebase Admin SDK...")
        initialize_firebase()
        logger.info("✅ Firebase Admin SDK initialized successfully")
    except Exception as e:
        logger.error(f"❌ Failed to initialize Firebase Admin SDK: {e}")
        logger.warning("⚠️ Push notifications will not work until Firebase is properly configured")

    # Initialize Google Calendar service
    try:
        logger.info("🚀 Initializing Google Calendar service...")
        initialize_calendar_service(db)
        logger.info("✅ Google Calendar service initialized successfully")
    except Exception as e:
        logger.error(f"❌ Failed to initialize Google Calendar service: {e}")
        logger.warning("⚠️ Calendar integration will not work until properly configured")

    # Start background ledger reconciliation loop
    global reconciliation_task
    if reconciliation_task is None:
        logger.info("🔁 Starting ledger reconciliation background task")
        reconciliation_task = asyncio.create_task(_reconciliation_loop())
    
    # Start background integrity scan loop
    global integrity_task
    if integrity_task is None:
        logger.info("🔁 Starting ledger integrity scan background task")
        integrity_task = asyncio.create_task(_integrity_scan_loop())

    # Start background chat contact cleanup loop
    global chat_contact_cleanup_task
    if chat_contact_cleanup_task is None:
        logger.info("🔁 Starting chat contact cleanup background task")
        chat_contact_cleanup_task = asyncio.create_task(_chat_contact_cleanup_loop())

    # Redis connectivity check (rate limiting)
    if redis_client:
        try:
            await redis_client.ping()
            logger.info("✅ Redis rate limiter connected")
        except Exception as e:
            logger.error(f"❌ Redis rate limiter not reachable: {e}")
    else:
        logger.warning("⚠️  Redis rate limiter not configured; using in-memory limits")

@app.on_event("shutdown")
async def shutdown_db_client():
    global reconciliation_task
    if reconciliation_task:
        reconciliation_task.cancel()
    global integrity_task
    if integrity_task:
        integrity_task.cancel()
    global chat_contact_cleanup_task
    if chat_contact_cleanup_task:
        chat_contact_cleanup_task.cancel()
    client.close()

# Mount Socket.IO - This must be at the very end
socket_app = socketio.ASGIApp(sio)
app.mount("/socket.io", socket_app)
