from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr, ValidationError
from typing import List, Optional, Dict, Any, Tuple
from difflib import SequenceMatcher
import os
import logging
import asyncio
import uuid
import re
import sys
import secrets
import hashlib
import math
from collections import Counter
from datetime import datetime, timezone, timedelta
import time
import random
import bcrypt
import jwt
import aiofiles
from pypdf import PdfReader
from docx import Document
import io
import httpx
import json
from urllib.parse import quote, urlparse
from openai_helper import build_embedding_client, EmbeddingGenerationError

ROOT_DIR = Path(__file__).parent
# Ensure imports resolve to backend/* modules even when app is started from repo root.
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
from mpesa_service import MPesaService
load_dotenv(ROOT_DIR / ".env")

mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY") or os.environ.get("EMERGENT_LLM_KEY")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_API_KEYS = [
    k.strip()
    for k in os.environ.get("GEMINI_API_KEYS", "").split(",")
    if k.strip()
]
EMBEDDING_PROVIDER = os.environ.get("EMBEDDING_PROVIDER", "openai").lower()
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "openai").lower()
LLM_PROVIDERS = [
    p.strip().lower()
    for p in os.environ.get("LLM_PROVIDERS", "").split(",")
    if p.strip()
]
LLM_ROUTING_MODE = os.environ.get("LLM_ROUTING_MODE", "round_robin").strip().lower()
LLM_EXAM_PROVIDER = os.environ.get("LLM_EXAM_PROVIDER", "").strip().lower()
OPENAI_EMBEDDING_MODEL = os.environ.get("OPENAI_EMBEDDING_MODEL", "text-embedding-3-small")
GEMINI_EMBEDDING_MODEL = os.environ.get("GEMINI_EMBEDDING_MODEL", "gemini-embedding-001")
GEMINI_EMBEDDING_DIMENSIONS = int(os.environ.get("GEMINI_EMBEDDING_DIMENSIONS", "1536"))
OPENAI_CHAT_MODEL = os.environ.get("OPENAI_CHAT_MODEL", "gpt-4o")
GEMINI_CHAT_MODEL = os.environ.get("GEMINI_CHAT_MODEL", "gemini-2.0-flash")
GEMINI_CHAT_MODELS = [
    m.strip()
    for m in os.environ.get("GEMINI_CHAT_MODELS", "").split(",")
    if m.strip()
]
NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "").strip()
NVIDIA_CHAT_MODEL = os.environ.get("NVIDIA_CHAT_MODEL", "qwen/qwen3.5-397b-a17b")
NVIDIA_CHAT_MODELS = [
    m.strip()
    for m in os.environ.get("NVIDIA_CHAT_MODELS", "").split(",")
    if m.strip()
]
NVIDIA_MODEL_KEYS_JSON = os.environ.get("NVIDIA_MODEL_KEYS_JSON", "").strip()
NVIDIA_BASE_URL = os.environ.get("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1").rstrip("/")
NVIDIA_MAX_TOKENS = int(os.environ.get("NVIDIA_MAX_TOKENS", "1000"))
NVIDIA_FORCE_JSON_MODE = os.environ.get("NVIDIA_FORCE_JSON_MODE", "false").lower() == "true"
NVIDIA_COOLDOWN_SECONDS = float(os.environ.get("NVIDIA_COOLDOWN_SECONDS", "180"))
GEMINI_RATE_LIMIT_COOLDOWN_SECONDS = float(os.environ.get("GEMINI_RATE_LIMIT_COOLDOWN_SECONDS", "20"))
GEMINI_RATE_LIMIT_MAX_BACKOFF_SECONDS = float(os.environ.get("GEMINI_RATE_LIMIT_MAX_BACKOFF_SECONDS", "30"))
NVIDIA_TIMEOUT_SECONDS = float(os.environ.get("NVIDIA_TIMEOUT_SECONDS", "45"))
REFRESH_ROTATION_GRACE_SECONDS = int(os.environ.get("REFRESH_ROTATION_GRACE_SECONDS", "120"))

NVIDIA_MODEL_KEYS: Dict[str, str] = {}
NVIDIA_MODEL_KEYS_PARSE_ERROR: Optional[str] = None
if NVIDIA_MODEL_KEYS_JSON:
    try:
        parsed_model_keys = json.loads(NVIDIA_MODEL_KEYS_JSON)
        if not isinstance(parsed_model_keys, dict):
            raise ValueError("NVIDIA_MODEL_KEYS_JSON must be a JSON object")
        for model_name, key_value in parsed_model_keys.items():
            model_text = str(model_name).strip()
            key_text = str(key_value).strip()
            if model_text and key_text:
                NVIDIA_MODEL_KEYS[model_text] = key_text
    except Exception as exc:
        NVIDIA_MODEL_KEYS_PARSE_ERROR = str(exc)
JWT_SECRET = os.environ["JWT_SECRET"]
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", "/tmp/uploads"))
UPLOAD_DIR.mkdir(exist_ok=True, parents=True)

ACCESS_TOKEN_MINUTES = int(os.environ.get("ACCESS_TOKEN_MINUTES", "20"))
REFRESH_TOKEN_DAYS = int(os.environ.get("REFRESH_TOKEN_DAYS", "30"))
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(20 * 1024 * 1024)))
EMBEDDING_CONCURRENCY = int(os.environ.get("EMBEDDING_CONCURRENCY", "8"))
GEN_PER_MIN_LIMIT = int(os.environ.get("GEN_PER_MIN_LIMIT", "20"))
UPLOAD_PER_MIN_LIMIT = int(os.environ.get("UPLOAD_PER_MIN_LIMIT", "6"))
AUTH_PER_MIN_LIMIT = int(os.environ.get("AUTH_PER_MIN_LIMIT", "20"))
JOB_STATUS_PER_MIN_LIMIT = int(os.environ.get("JOB_STATUS_PER_MIN_LIMIT", "120"))
CLASS_CREATE_PER_MIN_LIMIT = int(os.environ.get("CLASS_CREATE_PER_MIN_LIMIT", "12"))
CLASS_JOIN_PER_MIN_LIMIT = int(os.environ.get("CLASS_JOIN_PER_MIN_LIMIT", "30"))
CLASS_REVIEW_PER_MIN_LIMIT = int(os.environ.get("CLASS_REVIEW_PER_MIN_LIMIT", "20"))
CLASS_WITHDRAW_PER_MIN_LIMIT = int(os.environ.get("CLASS_WITHDRAW_PER_MIN_LIMIT", "8"))
ADMIN_READ_PER_MIN_LIMIT = int(os.environ.get("ADMIN_READ_PER_MIN_LIMIT", "120"))
ADMIN_WITHDRAW_PER_MIN_LIMIT = int(os.environ.get("ADMIN_WITHDRAW_PER_MIN_LIMIT", "20"))
TOPIC_CREATE_PER_MIN_LIMIT = int(os.environ.get("TOPIC_CREATE_PER_MIN_LIMIT", "6"))
TOPIC_UPVOTE_PER_MIN_LIMIT = int(os.environ.get("TOPIC_UPVOTE_PER_MIN_LIMIT", "30"))
TOPIC_READ_PER_MIN_LIMIT = int(os.environ.get("TOPIC_READ_PER_MIN_LIMIT", "90"))
TOPIC_CREATE_PER_HOUR_IP_LIMIT = int(os.environ.get("TOPIC_CREATE_PER_HOUR_IP_LIMIT", "18"))
TOPIC_CREATE_PER_HOUR_FINGERPRINT_LIMIT = int(
    os.environ.get("TOPIC_CREATE_PER_HOUR_FINGERPRINT_LIMIT", "24")
)
TOPIC_UPVOTE_PER_HOUR_IP_LIMIT = int(os.environ.get("TOPIC_UPVOTE_PER_HOUR_IP_LIMIT", "80"))
TOPIC_UPVOTE_PER_HOUR_FINGERPRINT_LIMIT = int(
    os.environ.get("TOPIC_UPVOTE_PER_HOUR_FINGERPRINT_LIMIT", "100")
)
TOPIC_UPVOTE_SUGGESTION_IP_WINDOW_SECONDS = int(
    os.environ.get("TOPIC_UPVOTE_SUGGESTION_IP_WINDOW_SECONDS", "300")
)
TOPIC_UPVOTE_SUGGESTION_IP_MAX = int(os.environ.get("TOPIC_UPVOTE_SUGGESTION_IP_MAX", "5"))
TOPIC_UPVOTE_SUGGESTION_FINGERPRINT_MAX = int(
    os.environ.get("TOPIC_UPVOTE_SUGGESTION_FINGERPRINT_MAX", "4")
)
TOPIC_VOTE_SPIKE_WINDOW_SECONDS = int(os.environ.get("TOPIC_VOTE_SPIKE_WINDOW_SECONDS", "300"))
TOPIC_VOTE_SPIKE_MAX = int(os.environ.get("TOPIC_VOTE_SPIKE_MAX", "30"))
TOPIC_ABUSE_READ_PER_MIN_LIMIT = int(os.environ.get("TOPIC_ABUSE_READ_PER_MIN_LIMIT", "60"))
TOPIC_ABUSE_REVIEW_ROLES = {
    r.strip().lower()
    for r in os.environ.get("TOPIC_ABUSE_REVIEW_ROLES", "teacher").split(",")
    if r.strip()
}
TOPIC_CATEGORY_MAX_SUGGESTIONS = int(os.environ.get("TOPIC_CATEGORY_MAX_SUGGESTIONS", "30"))
TOPIC_REQUIRE_ACTIVE_SUBSCRIPTION = os.environ.get("TOPIC_REQUIRE_ACTIVE_SUBSCRIPTION", "false").lower() == "true"
TOPIC_DUPLICATE_SIMILARITY_THRESHOLD = float(
    os.environ.get("TOPIC_DUPLICATE_SIMILARITY_THRESHOLD", "0.82")
)
MAX_GENERATIONS_PER_DAY = int(os.environ.get("MAX_GENERATIONS_PER_DAY", "100"))
MAX_CONTEXT_TOKENS = int(os.environ.get("MAX_CONTEXT_TOKENS", "6000"))
RETRIEVAL_TOP_K = int(os.environ.get("RETRIEVAL_TOP_K", "8"))
VECTOR_INDEX_NAME = os.environ.get("VECTOR_INDEX_NAME", "vector_index")
VECTOR_INDEX_REQUIRED = os.environ.get("VECTOR_INDEX_REQUIRED", "false").lower() == "true"
SUBSCRIPTIONS_ENABLED = os.environ.get("SUBSCRIPTIONS_ENABLED", "false").lower() == "true"
FREE_PLAN_MAX_DOCUMENTS = int(os.environ.get("FREE_PLAN_MAX_DOCUMENTS", "1"))
FREE_PLAN_MAX_GENERATIONS = int(os.environ.get("FREE_PLAN_MAX_GENERATIONS", "2"))
WEEKLY_PLAN_MAX_GENERATIONS = int(os.environ.get("WEEKLY_PLAN_MAX_GENERATIONS", "15"))
MONTHLY_PLAN_MAX_GENERATIONS = int(os.environ.get("MONTHLY_PLAN_MAX_GENERATIONS", "80"))
ANNUAL_PLAN_MAX_GENERATIONS = int(os.environ.get("ANNUAL_PLAN_MAX_GENERATIONS", "1200"))
WEEKLY_PLAN_MAX_EXAMS = int(os.environ.get("WEEKLY_PLAN_MAX_EXAMS", "2"))
MONTHLY_PLAN_MAX_EXAMS = int(os.environ.get("MONTHLY_PLAN_MAX_EXAMS", "8"))
ANNUAL_PLAN_MAX_EXAMS = int(os.environ.get("ANNUAL_PLAN_MAX_EXAMS", "128"))
SUBSCRIPTION_WEEKLY_KES = int(os.environ.get("SUBSCRIPTION_WEEKLY_KES", "149"))
SUBSCRIPTION_MONTHLY_KES = int(os.environ.get("SUBSCRIPTION_MONTHLY_KES", "499"))
SUBSCRIPTION_ANNUAL_KES = int(os.environ.get("SUBSCRIPTION_ANNUAL_KES", "4499"))
SUBSCRIPTION_MONTHLY_DISCOUNT_PCT = int(os.environ.get("SUBSCRIPTION_MONTHLY_DISCOUNT_PCT", "20"))
SUBSCRIPTION_ANNUAL_DISCOUNT_PCT = int(os.environ.get("SUBSCRIPTION_ANNUAL_DISCOUNT_PCT", "40"))
SUBSCRIPTION_WEEKLY_LABEL = os.environ.get("SUBSCRIPTION_WEEKLY_LABEL", "")
SUBSCRIPTION_MONTHLY_LABEL = os.environ.get("SUBSCRIPTION_MONTHLY_LABEL", "Most popular")
SUBSCRIPTION_ANNUAL_LABEL = os.environ.get("SUBSCRIPTION_ANNUAL_LABEL", "Best value")
SUBSCRIPTION_ACCOUNT_REFERENCE_PREFIX = os.environ.get("SUBSCRIPTION_ACCOUNT_REFERENCE_PREFIX", "SUB")
SUBSCRIPTION_TRANSACTION_DESC_PREFIX = os.environ.get("SUBSCRIPTION_TRANSACTION_DESC_PREFIX", "Exam OS")
SUBSCRIPTION_PLANS_JSON = os.environ.get("SUBSCRIPTION_PLANS_JSON", "")
ACCOUNT_REUSE_GRACE_DAYS = int(os.environ.get("ACCOUNT_REUSE_GRACE_DAYS", "3"))
SUPPORT_CONTACT_EMAIL = os.environ.get("SUPPORT_CONTACT_EMAIL", "support@examos.app")
SUPPORT_CONTACT_PHONE = os.environ.get("SUPPORT_CONTACT_PHONE", "0114090740")
LOCALPRO_BASE_URL = os.environ.get("LOCALPRO_BASE_URL", "").strip().rstrip("/")
LOCALPRO_API_KEY = os.environ.get("LOCALPRO_API_KEY", "").strip()
LOCALPRO_TUTORS_PATH = os.environ.get("LOCALPRO_TUTORS_PATH", "/api/services").strip() or "/api/services"
LOCALPRO_TUTOR_CATEGORY = os.environ.get("LOCALPRO_TUTOR_CATEGORY", "tutoring").strip().lower()
LOCALPRO_TIMEOUT_SECONDS = float(os.environ.get("LOCALPRO_TIMEOUT_SECONDS", "12"))
LOCALPRO_APP_SCHEME = os.environ.get("LOCALPRO_APP_SCHEME", "localpro").strip() or "localpro"
LOCALPRO_APP_PACKAGE = os.environ.get("LOCALPRO_APP_PACKAGE", "com.ericko2525.petsoko").strip() or "com.ericko2525.petsoko"
LOCALPRO_PLAYSTORE_URL = os.environ.get(
    "LOCALPRO_PLAYSTORE_URL",
    "https://play.google.com/store/apps/details?id=com.ericko2525.petsoko",
).strip()
PASSWORD_RESET_TTL_MINUTES = int(os.environ.get("PASSWORD_RESET_TTL_MINUTES", "30"))
PASSWORD_RESET_TOKEN_BYTES = int(os.environ.get("PASSWORD_RESET_TOKEN_BYTES", "32"))
PASSWORD_RESET_REQUEST_PER_HOUR_LIMIT = int(os.environ.get("PASSWORD_RESET_REQUEST_PER_HOUR_LIMIT", "6"))
PASSWORD_RESET_CONFIRM_PER_MIN_LIMIT = int(os.environ.get("PASSWORD_RESET_CONFIRM_PER_MIN_LIMIT", "12"))
PASSWORD_RESET_SCHEME = os.environ.get("PASSWORD_RESET_SCHEME", "examos")
PASSWORD_RESET_DEEP_LINK_HOST = os.environ.get("PASSWORD_RESET_DEEP_LINK_HOST", "reset-password")
PASSWORD_RESET_REQUIRE_HTTPS = os.environ.get("PASSWORD_RESET_REQUIRE_HTTPS", "true").lower() == "true"
PASSWORD_RESET_TOKEN_PEPPER = os.environ.get("PASSWORD_RESET_TOKEN_PEPPER", JWT_SECRET)
BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "")
BREVO_API_KEY2 = os.environ.get("BREVO_API_KEY2", "").strip()
BREVO_SENDER_EMAIL = os.environ.get("BREVO_SENDER_EMAIL", "")
BREVO_SENDER_NAME = os.environ.get("BREVO_SENDER_NAME", "Exam OS")
BREVO_TEMPLATE_ID = os.environ.get("BREVO_TEMPLATE_ID", "").strip()
BREVO_PASSWORD_RESET_TEMPLATE_ID = os.environ.get("BREVO_PASSWORD_RESET_TEMPLATE_ID", "").strip()
BREVO_SIGNUP_OTP_TEMPLATE_ID = os.environ.get("BREVO_SIGNUP_OTP_TEMPLATE_ID", "").strip()
BREVO_TIMEOUT_SECONDS = float(os.environ.get("BREVO_TIMEOUT_SECONDS", "10"))
RETENTION_INSIGHTS_ENABLED = os.environ.get("RETENTION_INSIGHTS_ENABLED", "false").lower() == "true"
RETENTION_EMAIL_DAILY_LIMIT = int(os.environ.get("RETENTION_EMAIL_DAILY_LIMIT", "300"))
RETENTION_EMAIL_BATCH_SIZE = int(os.environ.get("RETENTION_EMAIL_BATCH_SIZE", "300"))
RETENTION_EMAIL_MIN_DAYS_BETWEEN_SENDS = int(
    os.environ.get("RETENTION_EMAIL_MIN_DAYS_BETWEEN_SENDS", "5")
)
SIGNUP_OTP_TTL_MINUTES = int(os.environ.get("SIGNUP_OTP_TTL_MINUTES", "10"))
SIGNUP_OTP_LENGTH = int(os.environ.get("SIGNUP_OTP_LENGTH", "6"))
SIGNUP_OTP_MAX_ATTEMPTS = int(os.environ.get("SIGNUP_OTP_MAX_ATTEMPTS", "5"))
SIGNUP_OTP_REQUEST_PER_HOUR_LIMIT = int(os.environ.get("SIGNUP_OTP_REQUEST_PER_HOUR_LIMIT", "6"))
SIGNUP_OTP_VERIFY_PER_MIN_LIMIT = int(os.environ.get("SIGNUP_OTP_VERIFY_PER_MIN_LIMIT", "20"))
SIGNUP_OTP_PEPPER = os.environ.get("SIGNUP_OTP_PEPPER", JWT_SECRET)
SIGNUP_EMAIL_AGENT_NAME = os.environ.get("SIGNUP_EMAIL_AGENT_NAME", "Erick")
GENERATION_JOB_ESTIMATE_MINUTES = int(os.environ.get("GENERATION_JOB_ESTIMATE_MINUTES", "3"))
CLASS_ESCROW_PLATFORM_FEE_PERCENT = float(os.environ.get("CLASS_ESCROW_PLATFORM_FEE_PERCENT", "10"))
CLASS_MIN_FEE_KES = int(os.environ.get("CLASS_MIN_FEE_KES", "50"))
CLASS_MAX_FEE_KES = int(os.environ.get("CLASS_MAX_FEE_KES", "20000"))
PLATFORM_WITHDRAWAL_MIN_KES = int(os.environ.get("PLATFORM_WITHDRAWAL_MIN_KES", "100"))
RUNTIME_SETTINGS_DOC_ID = "runtime_settings"


def _runtime_default_settings() -> Dict[str, Any]:
    return {
        "subscription_weekly_kes": SUBSCRIPTION_WEEKLY_KES,
        "subscription_monthly_kes": SUBSCRIPTION_MONTHLY_KES,
        "subscription_annual_kes": SUBSCRIPTION_ANNUAL_KES,
        "weekly_plan_max_exams": _runtime_int("weekly_plan_max_exams", WEEKLY_PLAN_MAX_EXAMS),
        "monthly_plan_max_exams": _runtime_int("monthly_plan_max_exams", MONTHLY_PLAN_MAX_EXAMS),
        "annual_plan_max_exams": _runtime_int("annual_plan_max_exams", ANNUAL_PLAN_MAX_EXAMS),
        "class_escrow_platform_fee_percent": CLASS_ESCROW_PLATFORM_FEE_PERCENT,
        "class_min_fee_kes": CLASS_MIN_FEE_KES,
        "class_max_fee_kes": CLASS_MAX_FEE_KES,
        "account_reuse_grace_days": ACCOUNT_REUSE_GRACE_DAYS,
    }


RUNTIME_SETTINGS_CACHE: Dict[str, Any] = _runtime_default_settings()
ADMIN_RUNTIME_EDITABLE_SETTINGS = set(_runtime_default_settings().keys())

TOPIC_CATEGORY_LABELS: Dict[str, str] = {
    "grade_1_4": "Grade 1-4",
    "grade_5_6": "Grade 5-6",
    "junior_secondary": "Junior Secondary",
    "senior_secondary": "Senior Secondary",
}
TOPIC_CATEGORY_ALIASES: Dict[str, str] = {
    "grade_1_4": "grade_1_4",
    "grade 1-4": "grade_1_4",
    "grade 1 4": "grade_1_4",
    "grade_5_6": "grade_5_6",
    "grade 5-6": "grade_5_6",
    "grade 5 6": "grade_5_6",
    "junior_secondary": "junior_secondary",
    "junior secondary": "junior_secondary",
    "senior_secondary": "senior_secondary",
    "senior secondary": "senior_secondary",
}
TOPIC_SORT_OPTIONS = {"top", "new"}
USER_ROLE_OPTIONS = {"student", "teacher"}
TOPIC_TEXT_STOPWORDS = {
    "a",
    "an",
    "and",
    "for",
    "in",
    "into",
    "of",
    "on",
    "the",
    "to",
    "topic",
    "class",
    "lesson",
    "study",
    "studies",
}
TOPIC_TOKEN_SYNONYMS = {
    "intro": "basics",
    "introduction": "basics",
    "basic": "basics",
    "basics": "basics",
    "fundamental": "basics",
    "fundamentals": "basics",
    "foundation": "basics",
    "foundations": "basics",
}
try:
    BREVO_TEMPLATE_ID_INT = int(BREVO_TEMPLATE_ID) if BREVO_TEMPLATE_ID else None
except ValueError:
    BREVO_TEMPLATE_ID_INT = None
try:
    BREVO_PASSWORD_RESET_TEMPLATE_ID_INT = (
        int(BREVO_PASSWORD_RESET_TEMPLATE_ID) if BREVO_PASSWORD_RESET_TEMPLATE_ID else None
    )
except ValueError:
    BREVO_PASSWORD_RESET_TEMPLATE_ID_INT = None
try:
    BREVO_SIGNUP_OTP_TEMPLATE_ID_INT = (
        int(BREVO_SIGNUP_OTP_TEMPLATE_ID) if BREVO_SIGNUP_OTP_TEMPLATE_ID else None
    )
except ValueError:
    BREVO_SIGNUP_OTP_TEMPLATE_ID_INT = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

_GEMINI_KEY_COOLDOWN_UNTIL: Dict[str, float] = {}
_LLM_PROVIDER_COOLDOWN_UNTIL: Dict[str, float] = {}
_LLM_ROUTER_LOCK = asyncio.Lock()
_LLM_ROUTER_NEXT_INDEX = 0
_NVIDIA_MODEL_ROUTER_LOCK = asyncio.Lock()
_NVIDIA_MODEL_ROUTER_NEXT_INDEX = 0

security = HTTPBearer()
embedding_client = build_embedding_client(
    provider=EMBEDDING_PROVIDER,
    openai_api_key=OPENAI_API_KEY,
    gemini_api_key=GEMINI_API_KEY,
    gemini_api_keys=GEMINI_API_KEYS,
    openai_model=OPENAI_EMBEDDING_MODEL,
    gemini_model=GEMINI_EMBEDDING_MODEL,
    gemini_output_dimensionality=GEMINI_EMBEDDING_DIMENSIONS,
)
mpesa_service = MPesaService()

app = FastAPI(title="Exam OS API")
api_router = APIRouter(prefix="/api")


class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    role: str = "student"


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = None


class UpdateProfileRequest(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class DeleteAccountRequest(BaseModel):
    password: str


class SignupOtpVerifyRequest(BaseModel):
    signup_id: str
    otp: str


class SignupOtpResendRequest(BaseModel):
    signup_id: str


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirmRequest(BaseModel):
    token: str
    new_password: str


class SubscriptionCheckoutRequest(BaseModel):
    plan_id: str
    phone_number: str


class SignupChallengeResponse(BaseModel):
    signup_id: str
    message: str


class SubscriptionPlan(BaseModel):
    plan_id: str
    name: str
    cycle_days: int
    amount_kes: int
    generation_quota: int
    exam_quota: Optional[int] = None
    discount_pct: int = 0
    savings_label: Optional[str] = None


class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    full_name: str
    role: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: User


class DocumentMetadata(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    filename: str
    file_type: str
    file_path: str
    file_size: int
    total_chunks: int
    keywords: List[str] = Field(default_factory=list)
    uploaded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DocumentChunk(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    document_id: str
    user_id: str
    chunk_index: int
    text: str
    embedding: List[float]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GenerationRequest(BaseModel):
    document_ids: List[str]
    generation_type: str
    topic: Optional[str] = None
    difficulty: str = "medium"
    marks: Optional[int] = None
    question_types: Optional[List[str]] = None
    num_questions: Optional[int] = 10
    additional_instructions: Optional[str] = None


class GenerationResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    generation_type: str
    content: Dict[str, Any]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GenerationJobEnqueueResponse(BaseModel):
    job_id: str
    status: str
    estimated_time: str


class JobStatusResponse(BaseModel):
    job_id: str
    user_id: str
    type: str
    status: str
    progress: Optional[int] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    result_reference: Optional[str] = None
    error: Optional[str] = None


class ClassCreateRequest(BaseModel):
    title: str
    description: Optional[str] = None
    meeting_link: str
    scheduled_start_at: datetime
    scheduled_end_at: datetime
    fee_kes: int = Field(ge=0)


class ClassReviewCreateRequest(BaseModel):
    rating: int = Field(ge=1, le=5)
    comment: Optional[str] = None


class ClassJoinRequest(BaseModel):
    phone_number: Optional[str] = None


class ClassWithdrawalRequest(BaseModel):
    amount_kes: int = Field(gt=0)
    phone_number: Optional[str] = None
    note: Optional[str] = None


class AdminPlatformWithdrawalRequest(BaseModel):
    amount_kes: int = Field(gt=0)
    phone_number: Optional[str] = None
    note: Optional[str] = None


class AdminRuntimeSettingsUpdateRequest(BaseModel):
    subscription_weekly_kes: Optional[int] = Field(default=None, ge=1)
    subscription_monthly_kes: Optional[int] = Field(default=None, ge=1)
    subscription_annual_kes: Optional[int] = Field(default=None, ge=1)
    weekly_plan_max_exams: Optional[int] = Field(default=None, ge=1)
    monthly_plan_max_exams: Optional[int] = Field(default=None, ge=1)
    annual_plan_max_exams: Optional[int] = Field(default=None, ge=1)
    class_escrow_platform_fee_percent: Optional[float] = Field(default=None, ge=0, le=100)
    class_min_fee_kes: Optional[int] = Field(default=None, ge=0)
    class_max_fee_kes: Optional[int] = Field(default=None, ge=0)
    account_reuse_grace_days: Optional[int] = Field(default=None, ge=0, le=60)


class AdminRetentionInsightCampaignCreateRequest(BaseModel):
    audience_roles: List[str] = Field(default_factory=lambda: ["student", "teacher"])
    force_resend: bool = False


class ClassSessionResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    teacher_id: str
    teacher_name: str
    title: str
    description: Optional[str] = None
    meeting_link: str
    scheduled_start_at: datetime
    scheduled_end_at: datetime
    status: str
    created_at: datetime
    fee_kes: int = 0
    duration_minutes: int = 0
    join_count: int = 0
    joined: bool = False
    average_rating: Optional[float] = None
    review_count: int = 0


class ClassReviewResponse(BaseModel):
    id: str
    class_id: str
    student_id: str
    teacher_id: str
    rating: int
    comment: Optional[str] = None
    created_at: datetime


class NotificationResponse(BaseModel):
    id: str
    user_id: str
    status: str
    message: str
    created_at: datetime
    read: bool = False
    class_id: Optional[str] = None
    job_id: Optional[str] = None
    result_reference: Optional[str] = None
    meeting_link: Optional[str] = None


class PushTokenUpdateRequest(BaseModel):
    fcm_token: str


class TopicCreateRequest(BaseModel):
    title: str
    description: Optional[str] = None
    category: str


class PrivateTutorProfileResponse(BaseModel):
    id: str
    provider_id: str
    provider_name: str
    headline: str
    bio: str
    price_kes: float
    price_unit: str
    experience_years: int
    qualifications: str
    certifications: List[str]
    city: str
    service_type: str
    available_now: bool = False
    photo_url: Optional[str] = None
    booking_deep_link: str
    booking_web_url: Optional[str] = None
    source: str = "localpro_ke"


class PrivateTutorBookingIntentResponse(BaseModel):
    tutor_id: str
    deep_link: str
    playstore_url: str
    package_name: str
    web_url: Optional[str] = None


class TopicSuggestionResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    title: str
    description: Optional[str] = None
    category: str
    category_label: str
    created_by: str
    created_at: datetime
    upvote_count: int
    status: str
    user_has_upvoted: bool = False


class TopicListResponse(BaseModel):
    items: List[TopicSuggestionResponse]
    category: str
    category_label: str
    total_suggestions: int
    total_votes: int


class TopicAbuseEventResponse(BaseModel):
    id: str
    event_type: str
    user_id: str
    suggestion_id: Optional[str] = None
    category: Optional[str] = None
    ip_address: Optional[str] = None
    device_fingerprint: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class TopicFlaggedResponse(BaseModel):
    id: str
    title: str
    category: str
    category_label: str
    upvote_count: int
    fraud_spike_flag: bool
    fraud_spike_flagged_at: Optional[datetime] = None


class AdminDashboardSummaryResponse(BaseModel):
    platform_wallet_balance_kes: int
    platform_wallet_total_earned_kes: int
    platform_wallet_total_withdrawn_kes: int
    students_count: int
    teachers_count: int
    admins_count: int
    users_total: int


class AdminRetentionInsightCampaignResponse(BaseModel):
    id: str
    status: str
    audience_roles: List[str]
    total_targets: int
    pending_count: int
    sent_count: int
    failed_count: int
    skipped_count: int
    daily_limit: int
    batch_size: int
    estimated_batches: int
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    error: Optional[str] = None


class QuizQuestion(BaseModel):
    type: str
    question: str
    options: Optional[List[str]] = None
    correct_answer: Optional[str] = None
    model_answer: Optional[str] = None
    marks: int
    explanation: Optional[str] = None


class QuizOutput(BaseModel):
    quiz: List[QuizQuestion]


class ExamQuestion(BaseModel):
    question_number: str
    question_text: str
    marks: int
    type: str
    options: Optional[List[str]] = None
    sub_questions: Optional[List[str]] = None
    mark_scheme: str


class ExamSection(BaseModel):
    section_name: str
    questions: List[ExamQuestion]


class ExamOutput(BaseModel):
    school_name: Optional[str] = None
    exam_title: str
    subject: Optional[str] = None
    class_level: Optional[str] = None
    total_marks: int
    time_allowed: str
    instructions: List[str]
    sections: List[ExamSection]


class InMemoryRateLimiter:
    def __init__(self):
        self._buckets: Dict[str, List[float]] = {}
        self._lock = asyncio.Lock()

    async def check(self, key: str, limit: int, window_seconds: int) -> None:
        now = time.time()
        threshold = now - window_seconds
        async with self._lock:
            events = self._buckets.get(key, [])
            events = [t for t in events if t > threshold]
            if len(events) >= limit:
                raise HTTPException(status_code=429, detail="Rate limit exceeded")
            events.append(now)
            self._buckets[key] = events


rate_limiter = InMemoryRateLimiter()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def hash_reset_token(token: str) -> str:
    material = f"{token}{PASSWORD_RESET_TOKEN_PEPPER}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def hash_signup_otp(signup_id: str, otp: str) -> str:
    material = f"{signup_id}:{otp}:{SIGNUP_OTP_PEPPER}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def generate_signup_otp() -> str:
    max_value = 10 ** max(4, min(8, SIGNUP_OTP_LENGTH))
    return str(secrets.randbelow(max_value)).zfill(SIGNUP_OTP_LENGTH)


def create_signup_challenge() -> Tuple[str, str, str, datetime]:
    signup_id = str(uuid.uuid4())
    otp = generate_signup_otp()
    otp_hash = hash_signup_otp(signup_id, otp)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=SIGNUP_OTP_TTL_MINUTES)
    return signup_id, otp, otp_hash, expires_at


def create_password_reset_token() -> Tuple[str, str, datetime]:
    token = secrets.token_urlsafe(max(16, PASSWORD_RESET_TOKEN_BYTES))
    token_hash = hash_reset_token(token)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=PASSWORD_RESET_TTL_MINUTES)
    return token, token_hash, expires_at


def build_password_reset_deep_link(token: str) -> str:
    safe_token = quote(token, safe="")
    return f"{PASSWORD_RESET_SCHEME}://{PASSWORD_RESET_DEEP_LINK_HOST}?token={safe_token}"


def request_is_https(request: Request) -> bool:
    scheme = (request.url.scheme or "").lower()
    if scheme == "https":
        return True
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    if "https" in forwarded_proto.lower():
        return True
    host = (request.headers.get("host") or "").split(":")[0].lower()
    return host in {"localhost", "127.0.0.1"}


def describe_remaining_grace(blocked_until_iso: str) -> str:
    blocked_until = datetime.fromisoformat(blocked_until_iso)
    remaining = blocked_until - datetime.now(timezone.utc)
    if remaining.total_seconds() <= 0:
        return "0 hours"
    total_hours = int((remaining.total_seconds() + 3599) // 3600)
    days = total_hours // 24
    hours = total_hours % 24
    if days > 0:
        return f"{days} day(s) {hours} hour(s)"
    return f"{hours} hour(s)"


async def send_brevo_transactional_email(
    *,
    api_key: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    if not api_key:
        raise RuntimeError("Brevo API key is missing")
    headers = {
        "accept": "application/json",
        "api-key": api_key,
        "content-type": "application/json",
    }
    async with httpx.AsyncClient(timeout=BREVO_TIMEOUT_SECONDS) as client:
        response = await client.post("https://api.brevo.com/v3/smtp/email", headers=headers, json=payload)
        response.raise_for_status()
        if not response.text:
            return {}
        try:
            return response.json()
        except ValueError:
            return {}


async def send_password_reset_email(email: str, full_name: str, deep_link: str) -> None:
    if not BREVO_API_KEY or not BREVO_SENDER_EMAIL:
        logger.warning("Password reset email skipped: Brevo not configured")
        return

    payload: Dict[str, Any]
    password_reset_template_id = BREVO_PASSWORD_RESET_TEMPLATE_ID_INT or BREVO_TEMPLATE_ID_INT
    if password_reset_template_id:
        payload = {
            "sender": {"email": BREVO_SENDER_EMAIL, "name": BREVO_SENDER_NAME},
            "to": [{"email": email, "name": full_name or email}],
            "templateId": password_reset_template_id,
            "params": {
                "reset_link": deep_link,
                "expiry_minutes": PASSWORD_RESET_TTL_MINUTES,
                "app_name": "Exam OS",
                "agent_name": SIGNUP_EMAIL_AGENT_NAME,
            },
        }
    else:
        html_content = (
            "<p>Hello,</p>"
            "<p>We received a password reset request for your Exam OS account.</p>"
            f"<p><a href=\"{deep_link}\">Reset your password</a></p>"
            f"<p>This link expires in {PASSWORD_RESET_TTL_MINUTES} minutes and can only be used once.</p>"
            "<p>If you did not request this, you can ignore this email.</p>"
        )
        payload = {
            "sender": {"email": BREVO_SENDER_EMAIL, "name": BREVO_SENDER_NAME},
            "to": [{"email": email, "name": full_name or email}],
            "subject": "Reset your Exam OS password",
            "htmlContent": html_content,
        }

    await send_brevo_transactional_email(api_key=BREVO_API_KEY, payload=payload)


async def send_signup_otp_email(email: str, full_name: str, otp: str) -> None:
    if not BREVO_API_KEY or not BREVO_SENDER_EMAIL:
        logger.warning("Signup OTP email skipped: Brevo not configured")
        return

    greeting_name = (full_name or "").strip().split(" ")[0] or "there"
    if BREVO_SIGNUP_OTP_TEMPLATE_ID_INT:
        payload = {
            "sender": {"email": BREVO_SENDER_EMAIL, "name": BREVO_SENDER_NAME},
            "to": [{"email": email, "name": full_name or email}],
            "templateId": BREVO_SIGNUP_OTP_TEMPLATE_ID_INT,
            "params": {
                "first_name": greeting_name,
                "otp_code": otp,
                "expiry_minutes": SIGNUP_OTP_TTL_MINUTES,
                "agent_name": SIGNUP_EMAIL_AGENT_NAME,
                "app_name": "Exam OS",
            },
        }
    else:
        html_content = (
            f"<p>Hi {greeting_name},</p>"
            f"<p>It&apos;s {SIGNUP_EMAIL_AGENT_NAME} from Exam OS. Welcome aboard.</p>"
            "<p>Use this one-time verification code to finish creating your account:</p>"
            f"<p style=\"font-size:24px;font-weight:700;letter-spacing:4px;\">{otp}</p>"
            f"<p>This code expires in {SIGNUP_OTP_TTL_MINUTES} minutes and can be used once.</p>"
            "<p>If you did not start this signup, please ignore this email.</p>"
        )
        payload = {
            "sender": {"email": BREVO_SENDER_EMAIL, "name": BREVO_SENDER_NAME},
            "to": [{"email": email, "name": full_name or email}],
            "subject": "Your Exam OS verification code",
            "htmlContent": html_content,
        }
    await send_brevo_transactional_email(api_key=BREVO_API_KEY, payload=payload)


async def send_subscription_updated_email(
    email: str,
    full_name: str,
    plan_name: str,
    generation_limit: int,
    exam_limit: Optional[int],
    window_end_at: Optional[str],
) -> None:
    if not BREVO_API_KEY or not BREVO_SENDER_EMAIL:
        logger.warning("Subscription update email skipped: Brevo not configured")
        return

    greeting_name = (full_name or "").strip().split(" ")[0] or "there"
    exam_limit_text = str(exam_limit) if exam_limit is not None else "unlimited"
    renewal_text = window_end_at or "your current billing window end date"

    html_content = (
        f"<p>Hi {greeting_name},</p>"
        "<p>Your payment has been confirmed.</p>"
        f"<p>Your <strong>{plan_name}</strong> subscription is now active and updated.</p>"
        f"<p>You can now enjoy up to <strong>{generation_limit}</strong> total generations and "
        f"<strong>{exam_limit_text}</strong> exam generations in this billing window.</p>"
        f"<p>Your current window ends on: <strong>{renewal_text}</strong>.</p>"
        "<p>Thank you for subscribing to Exam OS.</p>"
    )
    payload = {
        "sender": {"email": BREVO_SENDER_EMAIL, "name": BREVO_SENDER_NAME},
        "to": [{"email": email, "name": full_name or email}],
        "subject": "Your subscription has been updated",
        "htmlContent": html_content,
    }
    await send_brevo_transactional_email(api_key=BREVO_API_KEY, payload=payload)


async def enqueue_password_reset_email(email: str, full_name: str, deep_link: str) -> None:
    try:
        await send_password_reset_email(email=email, full_name=full_name, deep_link=deep_link)
    except Exception as exc:
        logger.error("Password reset email delivery failed: %s", exc)


async def enqueue_signup_otp_email(email: str, full_name: str, otp: str) -> None:
    try:
        await send_signup_otp_email(email=email, full_name=full_name, otp=otp)
    except Exception as exc:
        logger.error("Signup OTP email delivery failed: %s", exc)


async def enqueue_subscription_updated_email(
    email: str,
    full_name: str,
    plan_name: str,
    generation_limit: int,
    exam_limit: Optional[int],
    window_end_at: Optional[str],
) -> None:
    try:
        await send_subscription_updated_email(
            email=email,
            full_name=full_name,
            plan_name=plan_name,
            generation_limit=generation_limit,
            exam_limit=exam_limit,
            window_end_at=window_end_at,
        )
    except Exception as exc:
        logger.error("Subscription update email delivery failed: %s", exc)

def create_token(user_id: str, email: str, token_type: str, expires_delta: timedelta) -> Tuple[str, str, datetime]:
    jti = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + expires_delta
    payload = {
        "user_id": user_id,
        "email": email,
        "type": token_type,
        "jti": jti,
        "exp": expires_at,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return token, jti, expires_at


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def assemble_context_with_budget(chunks: List[Dict[str, Any]], max_tokens: int) -> str:
    selected: List[str] = []
    used_tokens = 0
    for chunk in chunks:
        text = chunk.get("text", "")
        chunk_tokens = estimate_tokens(text)
        if used_tokens + chunk_tokens > max_tokens:
            break
        selected.append(text)
        used_tokens += chunk_tokens
    if not selected:
        raise HTTPException(status_code=400, detail="No context chunks fit within token budget")
    return "\n\n".join(selected)


def detect_mime(file_content: bytes, extension: str, declared_mime: Optional[str]) -> str:
    ext = extension.lower()
    detected = ""
    if file_content.startswith(b"%PDF-"):
        detected = "application/pdf"
    elif file_content.startswith(b"PK\x03\x04"):
        detected = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    else:
        try:
            file_content.decode("utf-8")
            detected = "text/plain"
        except UnicodeDecodeError:
            detected = "application/octet-stream"

    allowed_map = {
        "pdf": {"application/pdf"},
        "docx": {
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/zip",
        },
        "txt": {"text/plain"},
    }

    if ext not in allowed_map:
        raise HTTPException(status_code=400, detail="Unsupported file extension")

    if detected not in allowed_map[ext]:
        raise HTTPException(status_code=400, detail=f"Invalid file content for .{ext}")

    # Client-declared MIME is often noisy on mobile (for example, generic octet-stream
    # or platform-specific aliases). If file signature/content matches extension, prefer
    # that verified detection and only warn on mismatches.
    normalized_declared = (declared_mime or "").split(";")[0].strip().lower()
    generic_mimes = {
        "",
        "application/octet-stream",
        "binary/octet-stream",
        "application/unknown",
        "*/*",
    }
    if normalized_declared not in generic_mimes:
        if ext == "txt":
            declared_ok = normalized_declared.startswith("text/")
        else:
            declared_ok = normalized_declared in allowed_map[ext]
        if not declared_ok:
            logger.warning(
                "Declared MIME '%s' mismatched extension '.%s'; using detected MIME '%s'",
                normalized_declared,
                ext,
                detected,
            )

    return detected


async def read_upload_with_limit(file: UploadFile, max_bytes: int) -> Tuple[bytes, int]:
    chunks: List[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(status_code=413, detail=f"File too large. Max {max_bytes} bytes.")
        chunks.append(chunk)
    return b"".join(chunks), total


def extract_text_from_pdf(file_content: bytes) -> str:
    try:
        pdf_file = io.BytesIO(file_content)
        reader = PdfReader(pdf_file)
        text = ""
        for page in reader.pages:
            text += (page.extract_text() or "") + "\n"
        return text.strip()
    except Exception as e:
        logger.error("PDF extraction error: %s", e)
        message = str(e)
        if "cryptography>=" in message or "AES algorithm" in message:
            raise HTTPException(
                status_code=500,
                detail=(
                    "Server PDF support is missing crypto dependency. "
                    "Install/upgrade 'cryptography>=3.1' and redeploy."
                ),
            )
        raise HTTPException(status_code=400, detail=f"Failed to extract PDF text: {message}")


def extract_text_from_docx(file_content: bytes) -> str:
    try:
        docx_file = io.BytesIO(file_content)
        doc = Document(docx_file)
        text = "\n".join([para.text for para in doc.paragraphs])
        return text.strip()
    except Exception as e:
        logger.error("DOCX extraction error: %s", e)
        raise HTTPException(status_code=400, detail=f"Failed to extract DOCX text: {str(e)}")


def chunk_text(text: str, chunk_size: int = 1000, overlap: int = 200) -> List[str]:
    chunks: List[str] = []
    start = 0
    text_length = len(text)
    while start < text_length:
        end = start + chunk_size
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        start += max(1, chunk_size - overlap)
    return chunks


def extract_keywords(text: str, max_keywords: int = 10) -> List[str]:
    # Lightweight keyword extraction so uploads can show immediate smart tags.
    tokens = re.findall(r"[A-Za-z][A-Za-z0-9\-\+]{2,}", text.lower())
    stopwords = {
        "the", "and", "for", "that", "with", "this", "from", "have", "into", "your",
        "their", "there", "were", "which", "when", "what", "where", "while", "would",
        "about", "after", "before", "being", "because", "between", "through", "during",
        "using", "used", "use", "than", "then", "into", "over", "under", "more", "less",
        "also", "only", "such", "these", "those", "each", "other", "some", "most", "many",
        "will", "shall", "can", "could", "should", "must", "may", "might", "not",
        "you", "they", "them", "our", "ours", "his", "her", "its", "who", "why", "how",
        "are", "was", "were", "is", "be", "been", "to", "of", "in", "on", "at", "by",
    }
    filtered = [t for t in tokens if t not in stopwords and not t.isdigit()]
    if not filtered:
        return []

    counts = Counter(filtered)
    ranked = sorted(
        counts.items(),
        key=lambda kv: (-kv[1], -len(kv[0]), kv[0]),
    )
    keywords: List[str] = []
    for word, _ in ranked:
        keywords.append(word.replace("-", " ").title())
        if len(keywords) >= max_keywords:
            break
    return keywords


async def generate_embedding(text: str) -> List[float]:
    try:
        return await embedding_client.create_embedding(text=text)
    except EmbeddingGenerationError as e:
        logger.error("Embedding generation failed: %s", e)
        error_text = str(e)
        if "429" in error_text or "rate limit" in error_text.lower():
            raise HTTPException(
                status_code=429,
                detail=(
                    "Embedding provider rate limit reached. "
                    "Try again shortly or add more embedding provider keys."
                ),
            )
        if "401" in error_text or "invalid_api_key" in error_text:
            raise HTTPException(
                status_code=502,
                detail=(
                    "Embedding provider authentication failed. "
                    "Check embedding provider API key configuration."
                ),
            )
        raise HTTPException(status_code=502, detail="Embedding generation failed after retries")


async def embed_chunks_parallel(document_id: str, user_id: str, chunks: List[str]) -> None:
    semaphore = asyncio.Semaphore(EMBEDDING_CONCURRENCY)

    async def embed_one(index: int, text: str) -> DocumentChunk:
        async with semaphore:
            embedding = await generate_embedding(text)
            return DocumentChunk(
                document_id=document_id,
                user_id=user_id,
                chunk_index=index,
                text=text,
                embedding=embedding,
            )

    results = await asyncio.gather(
        *(embed_one(idx, chunk) for idx, chunk in enumerate(chunks)),
        return_exceptions=True,
    )

    failed = [r for r in results if isinstance(r, Exception)]
    if failed:
        first_error = failed[0]
        logger.error(
            "Chunk embedding failed document_id=%s user_id=%s failures=%s first_error=%s",
            document_id,
            user_id,
            len(failed),
            first_error,
        )
        if isinstance(first_error, HTTPException):
            # Preserve meaningful upstream status/detail (e.g., 429 rate-limit).
            raise first_error
        raise HTTPException(
            status_code=502,
            detail=f"Embedding failed for {len(failed)} chunks: {str(first_error)}",
        )

    chunk_docs = []
    for chunk in results:
        assert isinstance(chunk, DocumentChunk)
        chunk_dict = chunk.model_dump()
        chunk_dict["created_at"] = chunk_dict["created_at"].isoformat()
        chunk_docs.append(chunk_dict)

    if chunk_docs:
        await db.document_chunks.insert_many(chunk_docs)


async def _vector_search_chunks(
    query_embedding: List[float],
    user_id: str,
    document_filter: Dict[str, Any],
    top_k: int,
) -> List[Dict[str, Any]]:
    pipeline = [
        {
            "$vectorSearch": {
                "index": VECTOR_INDEX_NAME,
                "path": "embedding",
                "queryVector": query_embedding,
                "numCandidates": max(top_k * 10, 40),
                "limit": top_k,
                "filter": {
                    "user_id": user_id,
                    **document_filter,
                },
            }
        },
        {
            "$project": {
                "_id": 0,
                "text": 1,
                "document_id": 1,
                "chunk_index": 1,
                "score": {"$meta": "vectorSearchScore"},
            }
        },
    ]
    return await db.document_chunks.aggregate(pipeline).to_list(top_k)


async def retrieve_relevant_chunks(
    user_id: str,
    document_ids: List[str],
    query: str,
    top_k: int = 10,
) -> List[Dict[str, Any]]:
    query_embedding = await generate_embedding(query)
    if not document_ids:
        return []

    try:
        if len(document_ids) == 1:
            chunks = await _vector_search_chunks(
                query_embedding,
                user_id,
                {"document_id": {"$in": document_ids}},
                top_k,
            )
        else:
            per_doc = max(1, top_k // len(document_ids))
            chunks = []
            for doc_id in document_ids:
                chunks.extend(
                    await _vector_search_chunks(
                        query_embedding,
                        user_id,
                        {"document_id": doc_id},
                        per_doc,
                    )
                )

            if len(chunks) < top_k:
                needed = top_k - len(chunks)
                extra = await _vector_search_chunks(
                    query_embedding,
                    user_id,
                    {"document_id": {"$in": document_ids}},
                    needed,
                )
                seen = {(c.get("document_id"), c.get("chunk_index")) for c in chunks}
                for item in extra:
                    key = (item.get("document_id"), item.get("chunk_index"))
                    if key not in seen:
                        chunks.append(item)
                        seen.add(key)
                        if len(chunks) >= top_k:
                            break

        if not chunks:
            raise HTTPException(status_code=404, detail="No relevant chunks found for selected documents")

        chunks.sort(key=lambda c: c.get("score", 0), reverse=True)
        return chunks[:top_k]
    except Exception as e:
        logger.error("Vector search failed: %s", e)
        raise HTTPException(status_code=500, detail="Vector search failed; check Atlas index configuration")


def normalize_datetime_fields(doc: Dict[str, Any], fields: List[str]) -> Dict[str, Any]:
    for field in fields:
        if isinstance(doc.get(field), str):
            doc[field] = datetime.fromisoformat(doc[field])
    return doc


def normalize_user_role(raw_role: str) -> str:
    role = (raw_role or "student").strip().lower()
    if role not in USER_ROLE_OPTIONS:
        raise HTTPException(status_code=400, detail="Invalid role. Use student or teacher")
    return role


def normalize_retention_audience_roles(raw_roles: List[str]) -> List[str]:
    allowed = {"student", "teacher", "admin"}
    cleaned = sorted(
        {
            (role or "").strip().lower()
            for role in (raw_roles or [])
            if (role or "").strip().lower() in allowed
        }
    )
    if not cleaned:
        cleaned = ["student", "teacher"]
    return cleaned


def retention_campaign_response_model(doc: Dict[str, Any]) -> AdminRetentionInsightCampaignResponse:
    norm = normalize_datetime_fields(
        doc,
        ["created_at", "started_at", "completed_at", "next_run_at"],
    )
    total_targets = int(norm.get("total_targets", 0))
    batch_size = max(1, int(norm.get("batch_size", RETENTION_EMAIL_BATCH_SIZE)))
    return AdminRetentionInsightCampaignResponse(
        id=str(norm.get("id", "")),
        status=str(norm.get("status", "queued")),
        audience_roles=[str(r) for r in (norm.get("audience_roles") or [])],
        total_targets=total_targets,
        pending_count=int(norm.get("pending_count", 0)),
        sent_count=int(norm.get("sent_count", 0)),
        failed_count=int(norm.get("failed_count", 0)),
        skipped_count=int(norm.get("skipped_count", 0)),
        daily_limit=int(norm.get("daily_limit", RETENTION_EMAIL_DAILY_LIMIT)),
        batch_size=batch_size,
        estimated_batches=max(1, math.ceil(total_targets / batch_size)) if total_targets > 0 else 0,
        created_at=norm.get("created_at") or datetime.now(timezone.utc),
        started_at=norm.get("started_at"),
        completed_at=norm.get("completed_at"),
        next_run_at=norm.get("next_run_at"),
        error=(norm.get("error") or None),
    )


def normalize_topic_category(raw_category: str) -> str:
    key = (raw_category or "").strip().lower().replace("\u2013", "-")
    key = re.sub(r"\s+", " ", key).replace("-", "_")
    key = key.replace(" _ ", "_").replace(" ", "_")
    normalized = TOPIC_CATEGORY_ALIASES.get(key)
    if normalized:
        return normalized

    fallback_key = (raw_category or "").strip().lower().replace("\u2013", "-")
    fallback_key = re.sub(r"\s+", " ", fallback_key)
    normalized = TOPIC_CATEGORY_ALIASES.get(fallback_key)
    if normalized:
        return normalized

    raise HTTPException(
        status_code=400,
        detail=(
            "Invalid category. Allowed values: "
            + ", ".join(TOPIC_CATEGORY_LABELS.values())
        ),
    )


def get_topic_sort(sort_value: str) -> List[Tuple[str, int]]:
    sort_key = (sort_value or "top").strip().lower()
    if sort_key not in TOPIC_SORT_OPTIONS:
        raise HTTPException(status_code=400, detail="Invalid sort. Use top or new")
    if sort_key == "top":
        return [("upvote_count", -1), ("created_at", -1)]
    return [("created_at", -1)]


def extract_request_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip() or "unknown"
    return request.client.host if request.client else "unknown"


def compute_vote_device_fingerprint(request: Request) -> str:
    provided = (
        request.headers.get("x-device-fingerprint")
        or request.headers.get("x-device-id")
        or ""
    ).strip()
    ua = request.headers.get("user-agent", "").strip().lower()
    lang = request.headers.get("accept-language", "").strip().lower()
    source = provided or f"{ua}|{lang}"
    if not source:
        source = "unknown-device"
    return hashlib.sha256(source.encode("utf-8")).hexdigest()[:24]


def normalize_topic_title_tokens(raw_title: str) -> List[str]:
    clean = re.sub(r"[^a-z0-9\s]+", " ", (raw_title or "").strip().lower())
    clean = re.sub(r"\s+", " ", clean).strip()
    if not clean:
        return []
    tokens: List[str] = []
    for token in clean.split(" "):
        if token in TOPIC_TEXT_STOPWORDS:
            continue
        if len(token) > 4 and token.endswith("ies"):
            token = f"{token[:-3]}y"
        elif len(token) > 3 and token.endswith("s"):
            token = token[:-1]
        token = TOPIC_TOKEN_SYNONYMS.get(token, token)
        if token in TOPIC_TEXT_STOPWORDS or len(token) < 2:
            continue
        tokens.append(token)
    return tokens


def topic_title_token_signature(raw_title: str) -> str:
    tokens = normalize_topic_title_tokens(raw_title)
    return " ".join(sorted(set(tokens)))


def topic_token_jaccard_similarity(a_signature: str, b_signature: str) -> float:
    a_tokens = set(a_signature.split()) if a_signature else set()
    b_tokens = set(b_signature.split()) if b_signature else set()
    if not a_tokens or not b_tokens:
        return 0.0
    return len(a_tokens & b_tokens) / len(a_tokens | b_tokens)


def build_topic_response(
    suggestion: Dict[str, Any],
    has_upvoted: bool = False,
) -> TopicSuggestionResponse:
    norm = normalize_datetime_fields(dict(suggestion), ["created_at"])
    category = norm.get("category", "")
    return TopicSuggestionResponse(
        id=norm["id"],
        title=norm["title"],
        description=norm.get("description"),
        category=category,
        category_label=TOPIC_CATEGORY_LABELS.get(category, category),
        created_by=norm["created_by"],
        created_at=norm["created_at"],
        upvote_count=int(norm.get("upvote_count", 0)),
        status=norm.get("status", "open"),
        user_has_upvoted=has_upvoted,
    )


async def find_similar_topic_suggestion(
    category: str,
    title: str,
) -> Optional[Dict[str, Any]]:
    new_signature = topic_title_token_signature(title)
    if not new_signature:
        return None
    threshold = min(max(TOPIC_DUPLICATE_SIMILARITY_THRESHOLD, 0.0), 1.0)

    candidates = await db.topic_suggestions.find(
        {"category": category, "status": {"$ne": "archived"}},
        {"_id": 0, "id": 1, "title": 1, "title_token_signature": 1},
    ).to_list(TOPIC_CATEGORY_MAX_SUGGESTIONS * 2)
    for candidate in candidates:
        existing_signature = (
            candidate.get("title_token_signature")
            or topic_title_token_signature(candidate.get("title", ""))
        )
        if not existing_signature:
            continue
        if existing_signature == new_signature:
            return candidate
        if topic_token_jaccard_similarity(new_signature, existing_signature) >= threshold:
            return candidate

        # Fallback for near-identical phrasing when token overlap misses due to rare wording.
        ratio = SequenceMatcher(None, new_signature, existing_signature).ratio()
        if ratio >= 0.92:
            return candidate
    return None


async def log_topic_abuse_event(
    *,
    event_type: str,
    user_id: str,
    suggestion_id: Optional[str] = None,
    category: Optional[str] = None,
    ip_address: Optional[str] = None,
    device_fingerprint: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    event_doc = {
        "id": str(uuid.uuid4()),
        "event_type": event_type,
        "user_id": user_id,
        "suggestion_id": suggestion_id,
        "category": category,
        "ip_address": ip_address,
        "device_fingerprint": device_fingerprint,
        "details": details or {},
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        await db.topic_vote_abuse_events.insert_one(event_doc)
    except Exception as exc:
        logger.warning("topic_abuse_event_log_failed event_type=%s error=%s", event_type, exc)


def build_job_status_response(job_doc: Dict[str, Any]) -> JobStatusResponse:
    norm = normalize_datetime_fields(dict(job_doc), ["created_at", "completed_at"])
    return JobStatusResponse(
        job_id=norm["job_id"],
        user_id=norm["user_id"],
        type=norm["type"],
        status=norm["status"],
        progress=norm.get("progress"),
        created_at=norm["created_at"],
        completed_at=norm.get("completed_at"),
        result_reference=norm.get("result_reference"),
        error=norm.get("error"),
    )


def normalize_meeting_link(raw_link: str) -> str:
    link = (raw_link or "").strip()
    parsed = urlparse(link)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Meeting link must be a valid http(s) URL")
    return link


async def compute_class_rating_snapshot(class_id: str) -> Tuple[Optional[float], int]:
    agg = await db.class_reviews.aggregate(
        [
            {"$match": {"class_id": class_id}},
            {"$group": {"_id": None, "avg": {"$avg": "$rating"}, "count": {"$sum": 1}}},
        ]
    ).to_list(1)
    if not agg:
        return None, 0
    avg = agg[0].get("avg")
    count = int(agg[0].get("count", 0))
    return (round(float(avg), 2) if avg is not None else None), count


def compute_class_escrow_split(amount_kes: int) -> Tuple[int, int]:
    fee_pct = current_class_escrow_platform_fee_percent()
    platform_fee = int(round(float(amount_kes) * fee_pct / 100.0))
    teacher_net = max(int(amount_kes) - platform_fee, 0)
    return teacher_net, platform_fee


async def build_class_response(
    class_doc: Dict[str, Any],
    current_user_id: str,
    current_user_role: str,
) -> ClassSessionResponse:
    norm = normalize_datetime_fields(dict(class_doc), ["scheduled_start_at", "scheduled_end_at", "created_at"])
    joined = False
    if current_user_role == "student":
        enrollment = await db.class_enrollments.find_one(
            {"class_id": norm["id"], "student_id": current_user_id},
            {"_id": 0, "id": 1},
        )
        joined = bool(enrollment)
    avg_rating, review_count = await compute_class_rating_snapshot(norm["id"])
    return ClassSessionResponse(
        id=norm["id"],
        teacher_id=norm["teacher_id"],
        teacher_name=norm.get("teacher_name", "Teacher"),
        title=norm["title"],
        description=norm.get("description"),
        meeting_link=norm["meeting_link"],
        scheduled_start_at=norm["scheduled_start_at"],
        scheduled_end_at=norm["scheduled_end_at"],
        status=norm.get("status", "scheduled"),
        created_at=norm["created_at"],
        fee_kes=int(norm.get("fee_kes", 0)),
        duration_minutes=int(norm.get("duration_minutes", 0)),
        join_count=int(norm.get("join_count", 0)),
        joined=joined,
        average_rating=avg_rating,
        review_count=review_count,
    )


def build_notification_response(notification_doc: Dict[str, Any]) -> NotificationResponse:
    norm = normalize_datetime_fields(dict(notification_doc), ["created_at"])
    return NotificationResponse(
        id=norm["id"],
        user_id=norm["user_id"],
        status=norm.get("status", "info"),
        message=norm.get("message", ""),
        created_at=norm["created_at"],
        read=bool(norm.get("read", False)),
        class_id=norm.get("class_id"),
        job_id=norm.get("job_id"),
        result_reference=norm.get("result_reference"),
        meeting_link=norm.get("meeting_link"),
    )


def _localpro_enabled() -> bool:
    return bool(LOCALPRO_BASE_URL)


def _localpro_headers() -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    if LOCALPRO_API_KEY:
        headers["X-API-Key"] = LOCALPRO_API_KEY
    return headers


def _normalize_localpro_tutor(raw: Dict[str, Any]) -> PrivateTutorProfileResponse:
    tutor_id = str(raw.get("id") or raw.get("_id") or "")
    provider_id = str(raw.get("seller_id") or "")
    provider_name = str(raw.get("seller_name") or "Tutor").strip() or "Tutor"
    title = str(raw.get("service_name") or "Private Tutoring").strip() or "Private Tutoring"
    bio = str(raw.get("description") or "").strip()
    price = float(raw.get("price") or 0)
    price_unit = str(raw.get("price_unit") or "per_session").strip() or "per_session"
    experience_years = int(raw.get("experience_years") or 0)
    qualifications = str(raw.get("qualifications") or "").strip()
    certifications = [str(c) for c in (raw.get("certifications") or []) if str(c).strip()]
    location = raw.get("location") if isinstance(raw.get("location"), dict) else {}
    city = str(location.get("city") or "").strip()
    service_type = str(raw.get("service_type") or "").strip()
    photos = raw.get("photos") if isinstance(raw.get("photos"), list) else []
    photo_url = str(photos[0]).strip() if photos else None
    available_now = bool(raw.get("seller_available_now", False))
    deep_link = f"{LOCALPRO_APP_SCHEME}://service/{tutor_id}"
    web_url = f"{LOCALPRO_BASE_URL}/service/{tutor_id}" if LOCALPRO_BASE_URL else None

    return PrivateTutorProfileResponse(
        id=tutor_id,
        provider_id=provider_id,
        provider_name=provider_name,
        headline=title,
        bio=bio,
        price_kes=price,
        price_unit=price_unit,
        experience_years=experience_years,
        qualifications=qualifications,
        certifications=certifications,
        city=city,
        service_type=service_type,
        available_now=available_now,
        photo_url=photo_url,
        booking_deep_link=deep_link,
        booking_web_url=web_url,
    )


async def fetch_localpro_tutors(limit: int = 20, city: Optional[str] = None) -> List[PrivateTutorProfileResponse]:
    if not _localpro_enabled():
        return []

    params: Dict[str, Any] = {
        "status": "active",
        "service_category": LOCALPRO_TUTOR_CATEGORY,
        "skip": 0,
        "limit": max(1, min(limit, 60)),
    }
    if city:
        params["city"] = city.strip()
    url = f"{LOCALPRO_BASE_URL}{LOCALPRO_TUTORS_PATH if LOCALPRO_TUTORS_PATH.startswith('/') else '/' + LOCALPRO_TUTORS_PATH}"

    try:
        async with httpx.AsyncClient(timeout=LOCALPRO_TIMEOUT_SECONDS) as http_client:
            response = await http_client.get(url, params=params, headers=_localpro_headers())
            response.raise_for_status()
            payload = response.json()
    except Exception as exc:
        logger.warning("localpro_fetch_failed url=%s error=%s", url, exc)
        return []

    if not isinstance(payload, list):
        return []

    tutors: List[PrivateTutorProfileResponse] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        try:
            normalized = _normalize_localpro_tutor(item)
            if normalized.id:
                tutors.append(normalized)
        except Exception:
            continue
    return tutors


def _runtime_int(name: str, fallback: int) -> int:
    try:
        return int(RUNTIME_SETTINGS_CACHE.get(name, fallback))
    except Exception:
        return int(fallback)


def _runtime_float(name: str, fallback: float) -> float:
    try:
        return float(RUNTIME_SETTINGS_CACHE.get(name, fallback))
    except Exception:
        return float(fallback)


def current_account_reuse_grace_days() -> int:
    return max(0, _runtime_int("account_reuse_grace_days", ACCOUNT_REUSE_GRACE_DAYS))


def current_class_fee_bounds() -> Tuple[int, int]:
    min_fee = max(0, _runtime_int("class_min_fee_kes", CLASS_MIN_FEE_KES))
    max_fee = max(min_fee, _runtime_int("class_max_fee_kes", CLASS_MAX_FEE_KES))
    return min_fee, max_fee


def current_class_escrow_platform_fee_percent() -> float:
    return min(max(_runtime_float("class_escrow_platform_fee_percent", CLASS_ESCROW_PLATFORM_FEE_PERCENT), 0.0), 100.0)


def current_runtime_settings() -> Dict[str, Any]:
    payload = _runtime_default_settings()
    payload.update({k: v for k, v in RUNTIME_SETTINGS_CACHE.items() if k in payload})
    return payload


async def load_runtime_settings_cache() -> None:
    doc = await db.runtime_settings.find_one({"id": RUNTIME_SETTINGS_DOC_ID}, {"_id": 0})
    merged = _runtime_default_settings()
    if doc:
        merged.update({k: v for k, v in doc.items() if k in merged})
    RUNTIME_SETTINGS_CACHE.clear()
    RUNTIME_SETTINGS_CACHE.update(merged)


def get_subscription_plans() -> List[SubscriptionPlan]:
    if SUBSCRIPTION_PLANS_JSON.strip():
        try:
            raw = json.loads(SUBSCRIPTION_PLANS_JSON)
            if isinstance(raw, list):
                return [SubscriptionPlan.model_validate(item) for item in raw]
        except Exception as exc:
            logger.warning("Invalid SUBSCRIPTION_PLANS_JSON, using defaults: %s", exc)

    return [
        SubscriptionPlan(
            plan_id="weekly",
            name="Weekly",
            cycle_days=7,
            amount_kes=_runtime_int("subscription_weekly_kes", SUBSCRIPTION_WEEKLY_KES),
            generation_quota=WEEKLY_PLAN_MAX_GENERATIONS,
            exam_quota=_runtime_int("weekly_plan_max_exams", WEEKLY_PLAN_MAX_EXAMS),
            savings_label=SUBSCRIPTION_WEEKLY_LABEL or None,
        ),
        SubscriptionPlan(
            plan_id="monthly",
            name="Monthly",
            cycle_days=30,
            amount_kes=_runtime_int("subscription_monthly_kes", SUBSCRIPTION_MONTHLY_KES),
            generation_quota=MONTHLY_PLAN_MAX_GENERATIONS,
            exam_quota=_runtime_int("monthly_plan_max_exams", MONTHLY_PLAN_MAX_EXAMS),
            discount_pct=SUBSCRIPTION_MONTHLY_DISCOUNT_PCT,
            savings_label=SUBSCRIPTION_MONTHLY_LABEL or None,
        ),
        SubscriptionPlan(
            plan_id="annual",
            name="Annual",
            cycle_days=365,
            amount_kes=_runtime_int("subscription_annual_kes", SUBSCRIPTION_ANNUAL_KES),
            generation_quota=ANNUAL_PLAN_MAX_GENERATIONS,
            exam_quota=_runtime_int("annual_plan_max_exams", ANNUAL_PLAN_MAX_EXAMS),
            discount_pct=SUBSCRIPTION_ANNUAL_DISCOUNT_PCT,
            savings_label=SUBSCRIPTION_ANNUAL_LABEL or None,
        ),
    ]


def get_subscription_plan(plan_id: str) -> SubscriptionPlan:
    for plan in get_subscription_plans():
        if plan.plan_id == plan_id:
            return plan
    raise HTTPException(status_code=400, detail="Invalid subscription plan")


def active_subscription_filter(now_iso: str) -> Dict[str, Any]:
    return {
        "status": "active",
        "end_at": {"$gte": now_iso},
    }


async def get_active_subscription(user_id: str) -> Optional[Dict[str, Any]]:
    now_iso = datetime.now(timezone.utc).isoformat()
    return await db.subscriptions.find_one(
        {"user_id": user_id, **active_subscription_filter(now_iso)},
        {"_id": 0},
    )


async def get_generation_entitlement(user_id: str) -> Dict[str, Any]:
    active_sub = await get_active_subscription(user_id)
    counters = await get_usage_counters(user_id)
    current_documents = await db.documents.count_documents({"user_id": user_id})
    current_generations = await db.generations.count_documents({"user_id": user_id})
    if active_sub:
        plan = get_subscription_plan(active_sub.get("plan_id", ""))
        quota_multiplier = max(1, int(active_sub.get("quota_multiplier", 1)))
        generation_limit = int(plan.generation_quota) * quota_multiplier
        start_at = active_sub.get("start_at") or datetime.now(timezone.utc).isoformat()
        end_at = active_sub.get("end_at") or datetime.now(timezone.utc).isoformat()
        # Track in-period usage as monotonic by including deleted count signal.
        used_current_rows = await db.generations.count_documents(
            {
                "user_id": user_id,
                "created_at": {"$gte": start_at, "$lte": end_at},
            }
        )
        used = max(
            used_current_rows,
            used_current_rows + counters["generations_deleted_total"],
        )
        exam_used = await get_window_exam_usage(user_id, start_at, end_at)
        exam_limit = (
            int(plan.exam_quota) * quota_multiplier
            if plan.exam_quota is not None
            else None
        )
        exam_remaining = None if exam_limit is None else max(0, exam_limit - exam_used)
        remaining = max(0, generation_limit - used)
        return {
            "plan_id": plan.plan_id,
            "plan_name": plan.name,
            "is_free": False,
            "generation_limit": generation_limit,
            "generation_used": used,
            "generation_remaining": remaining,
            "generation_used_lifetime": counters["generations_total"],
            "generation_current_items": current_generations,
            "window_end_at": end_at,
            "exam_limit": exam_limit,
            "exam_used": exam_used,
            "exam_remaining": exam_remaining,
            "quota_multiplier": quota_multiplier,
            "document_limit": None,
            "document_used": counters["documents_uploaded_total"],
            "document_remaining": None,
            "document_used_lifetime": counters["documents_uploaded_total"],
            "document_current_items": current_documents,
        }

    # Free plan limits are lifetime counters and do not reset on deletion.
    historical_quota_used = 0
    quota_sum = await db.user_quotas.aggregate(
        [
            {"$match": {"user_id": user_id}},
            {"$group": {"_id": None, "total": {"$sum": "$generation_count"}}},
        ]
    ).to_list(1)
    if quota_sum:
        historical_quota_used = int(quota_sum[0].get("total", 0))

    used = max(
        counters["generations_total"],
        current_generations + counters["generations_deleted_total"],
        historical_quota_used,
    )
    docs_used = max(
        counters["documents_uploaded_total"],
        current_documents + counters["documents_deleted_total"],
    )
    return {
        "plan_id": "free",
        "plan_name": "Free",
        "is_free": True,
        "generation_limit": FREE_PLAN_MAX_GENERATIONS,
        "generation_used": used,
        "generation_remaining": max(0, FREE_PLAN_MAX_GENERATIONS - used),
        "generation_used_lifetime": used,
        "generation_current_items": current_generations,
        "window_end_at": None,
        "exam_limit": None,
        "exam_used": None,
        "exam_remaining": None,
        "document_limit": FREE_PLAN_MAX_DOCUMENTS,
        "document_used": docs_used,
        "document_remaining": max(0, FREE_PLAN_MAX_DOCUMENTS - docs_used),
        "document_used_lifetime": docs_used,
        "document_current_items": current_documents,
    }


def record_metric(name: str, value: float = 1.0, tags: Optional[Dict[str, str]] = None) -> None:
    logger.info("metric=%s value=%s tags=%s", name, value, tags or {})


def validate_structured_output(generation_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        if generation_type == "quiz":
            return QuizOutput.model_validate(payload).model_dump()
        if generation_type == "exam":
            return ExamOutput.model_validate(payload).model_dump()
        return payload
    except ValidationError as ve:
        raise HTTPException(status_code=502, detail=f"LLM output schema validation failed: {ve.errors()}")


def parse_llm_json_output(text: str) -> Any:
    cleaned = (text or "").strip()
    if not cleaned:
        raise ValueError("Empty LLM output")

    # direct JSON
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, (dict, list)):
            return parsed
    except json.JSONDecodeError:
        pass

    # fenced markdown block
    if "```" in cleaned:
        start = cleaned.find("```")
        end = cleaned.rfind("```")
        if end > start:
            block = cleaned[start + 3 : end].strip()
            if block.lower().startswith("json"):
                block = block[4:].strip()
            try:
                parsed = json.loads(block)
                if isinstance(parsed, (dict, list)):
                    return parsed
            except json.JSONDecodeError:
                pass

    # fallback: object/array slices
    candidates: List[str] = []
    first_obj = cleaned.find("{")
    last_obj = cleaned.rfind("}")
    if first_obj != -1 and last_obj != -1 and last_obj > first_obj:
        candidates.append(cleaned[first_obj : last_obj + 1])
    first_arr = cleaned.find("[")
    last_arr = cleaned.rfind("]")
    if first_arr != -1 and last_arr != -1 and last_arr > first_arr:
        candidates.append(cleaned[first_arr : last_arr + 1])

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, (dict, list)):
                return parsed
        except json.JSONDecodeError:
            repaired = _repair_llm_json(candidate)
            if repaired is not None:
                return repaired

    raise ValueError("LLM returned non-JSON output")


def _repair_llm_json(candidate: str) -> Optional[Any]:
    """Best-effort repair for common LLM JSON mistakes before failing hard."""
    working = candidate.strip()
    # Remove dangling commas before closing brackets/braces.
    working = re.sub(r",(\s*[}\]])", r"\1", working)
    # Insert missing comma when two containers are adjacent.
    working = re.sub(r"([}\]])(\s*[{[])", r"\1,\2", working)
    # Insert missing comma between a completed JSON value and the next object key.
    working = re.sub(
        r'(".*?"|\d+|true|false|null|\]|\})(\s*)(?="[^"]+"\s*:)',
        r"\1,\2",
        working,
        flags=re.IGNORECASE | re.DOTALL,
    )
    working = _append_missing_json_closers(working)
    try:
        parsed = json.loads(working)
        if isinstance(parsed, (dict, list)):
            logger.warning("LLM JSON required auto-repair before parsing")
            return parsed
    except json.JSONDecodeError:
        return None
    return None


def coerce_generation_payload(
    request: GenerationRequest,
    payload: Any,
) -> Dict[str, Any]:
    if isinstance(payload, dict):
        return payload

    if request.generation_type == "quiz" and isinstance(payload, list):
        # Some models return a bare quiz array instead of {"quiz":[...]}.
        return {"quiz": payload}

    if request.generation_type == "exam" and isinstance(payload, list):
        # Some models return sections directly.
        return {
            "school_name": "",
            "exam_title": "Exam",
            "subject": "",
            "class_level": "",
            "total_marks": request.marks or 100,
            "time_allowed": "",
            "instructions": [],
            "sections": payload,
        }

    raise ValueError("LLM returned unexpected JSON shape")


def _append_missing_json_closers(text: str) -> str:
    stack: List[str] = []
    in_string = False
    escape = False
    for ch in text:
        if in_string:
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
        elif ch == "{":
            stack.append("}")
        elif ch == "[":
            stack.append("]")
        elif ch in {"}", "]"} and stack and ch == stack[-1]:
            stack.pop()

    if not stack:
        return text
    return text + "".join(reversed(stack))

def _is_llm_provider_configured(provider: str) -> bool:
    if provider == "gemini":
        return bool(GEMINI_API_KEY or GEMINI_API_KEYS)
    if provider == "nvidia":
        return bool(NVIDIA_API_KEY or any(v for v in NVIDIA_MODEL_KEYS.values()))
    if provider == "openai":
        return bool(OPENAI_API_KEY)
    return False


def _resolve_llm_providers() -> List[str]:
    if LLM_PROVIDER in {"openai", "gemini", "nvidia"}:
        return [LLM_PROVIDER]
    if LLM_PROVIDER == "hybrid":
        configured = LLM_PROVIDERS or ["gemini", "nvidia"]
        deduped: List[str] = []
        for provider in configured:
            if provider in {"openai", "gemini", "nvidia"} and provider not in deduped:
                deduped.append(provider)
        return deduped
    return []


def _mark_provider_cooldown(provider: str, seconds: float) -> None:
    if seconds <= 0:
        return
    _LLM_PROVIDER_COOLDOWN_UNTIL[provider] = time.time() + seconds
    logger.warning("llm_provider_cooldown provider=%s seconds=%s", provider, seconds)


async def _provider_order_for_request(providers: List[str]) -> List[str]:
    now = time.time()
    active_providers = [
        p for p in providers if _LLM_PROVIDER_COOLDOWN_UNTIL.get(p, 0.0) <= now
    ]
    if active_providers:
        providers = active_providers
    else:
        logger.warning("All providers are in cooldown, using configured list: %s", providers)

    if len(providers) <= 1 or LLM_ROUTING_MODE != "round_robin":
        return providers
    global _LLM_ROUTER_NEXT_INDEX
    async with _LLM_ROUTER_LOCK:
        start_index = _LLM_ROUTER_NEXT_INDEX % len(providers)
        _LLM_ROUTER_NEXT_INDEX += 1
    ordered = providers[start_index:] + providers[:start_index]
    logger.info(
        "llm_router mode=%s providers=%s ordered=%s",
        LLM_ROUTING_MODE,
        providers,
        ordered,
    )
    return ordered


async def _generate_with_openai_style_provider(
    endpoint_url: str,
    api_key: str,
    model_name: str,
    provider_label: str,
    prompt: str,
    system_message: str,
    timeout_seconds: float = 60.0,
    max_attempts: int = 3,
    max_tokens: Optional[int] = None,
    force_json_object: bool = True,
) -> str:
    if not api_key:
        raise HTTPException(status_code=502, detail=f"{provider_label} API key is not configured")
    last_error: Optional[Exception] = None
    saw_rate_limit = False
    for attempt in range(1, max_attempts + 1):
        try:
            logger.info(
                "llm_provider_attempt provider=%s model=%s attempt=%s/%s",
                provider_label.lower(),
                model_name,
                attempt,
                max_attempts,
            )
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                payload: Dict[str, Any] = {
                    "model": model_name,
                    "messages": [
                        {"role": "system", "content": system_message},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                    "stream": False,
                }
                if force_json_object:
                    payload["response_format"] = {"type": "json_object"}
                if max_tokens is not None and max_tokens > 0:
                    payload["max_tokens"] = max_tokens
                response = await client.post(
                    endpoint_url,
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
                message = (
                    data.get("choices", [{}])[0]
                    .get("message", {})
                    .get("content", "")
                )
                if not isinstance(message, str) or not message.strip():
                    raise ValueError("Empty LLM response")
                logger.info(
                    "llm_provider_success provider=%s model=%s attempt=%s",
                    provider_label.lower(),
                    model_name,
                    attempt,
                )
                return message
        except httpx.HTTPStatusError as e:
            last_error = e
            status = e.response.status_code if e.response is not None else 0
            logger.warning("%s generation attempt %s/%s failed: %s", provider_label, attempt, max_attempts, e)
            if status == 429:
                saw_rate_limit = True
                if provider_label.lower() == "nvidia":
                    _mark_provider_cooldown("nvidia", NVIDIA_COOLDOWN_SECONDS)
            if attempt < max_attempts:
                await asyncio.sleep(min(8.0, 0.8 * attempt))
        except httpx.TimeoutException as e:
            last_error = e
            logger.warning(
                "%s generation attempt %s/%s timed out after %ss",
                provider_label,
                attempt,
                max_attempts,
                timeout_seconds,
            )
            if provider_label.lower() == "nvidia":
                _mark_provider_cooldown("nvidia", NVIDIA_COOLDOWN_SECONDS)
            if attempt < max_attempts:
                await asyncio.sleep(min(4.0, 0.6 * attempt))
        except Exception as e:
            last_error = e
            logger.warning("%s generation attempt %s/%s failed: %s", provider_label, attempt, max_attempts, e)
            if attempt < max_attempts:
                await asyncio.sleep(0.75 * attempt)

    if saw_rate_limit:
        raise HTTPException(
            status_code=429,
            detail=f"{provider_label} generation rate limit reached",
        )
    raise HTTPException(
        status_code=502,
        detail=f"{provider_label} generation failed after retries: {last_error}",
    )


async def _generate_with_gemini(prompt: str, system_message: str) -> str:
    gemini_keys = list(GEMINI_API_KEYS)
    if GEMINI_API_KEY and GEMINI_API_KEY not in gemini_keys:
        gemini_keys.append(GEMINI_API_KEY)
    if not gemini_keys:
        raise HTTPException(
            status_code=502,
            detail="GEMINI_API_KEY or GEMINI_API_KEYS is required when using Gemini",
        )
    gemini_models = list(GEMINI_CHAT_MODELS)
    if GEMINI_CHAT_MODEL and GEMINI_CHAT_MODEL not in gemini_models:
        gemini_models.append(GEMINI_CHAT_MODEL)
    if not gemini_models:
        gemini_models = ["gemini-2.0-flash"]

    last_error: Optional[Exception] = None
    saw_rate_limit = False
    saw_model_not_found = False
    max_attempts = max(1, len(gemini_keys) * len(gemini_models)) * 3
    for attempt in range(1, max_attempts + 1):
        current_api_key: Optional[str] = None
        key_wait: Optional[float] = None
        try:
            now = time.time()
            available_keys = [
                key for key in gemini_keys if _GEMINI_KEY_COOLDOWN_UNTIL.get(key, 0.0) <= now
            ]
            if not available_keys:
                next_ready = min(_GEMINI_KEY_COOLDOWN_UNTIL.get(k, now) for k in gemini_keys)
                key_wait = max(0.5, next_ready - now)
                if attempt < max_attempts:
                    await asyncio.sleep(key_wait)
                    continue
                raise RuntimeError("All Gemini API keys are cooling down")

            key_index = (attempt - 1) % len(available_keys)
            model_index = (attempt - 1) % len(gemini_models)
            current_api_key = available_keys[key_index]
            model_name = gemini_models[model_index]
            logger.info(
                "llm_provider_attempt provider=gemini model=%s attempt=%s/%s available_keys=%s",
                model_name,
                attempt,
                max_attempts,
                len(available_keys),
            )

            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent",
                    params={"key": current_api_key},
                    headers={"Content-Type": "application/json"},
                    json={
                        "system_instruction": {
                            "parts": [{"text": system_message}],
                        },
                        "contents": [
                            {
                                "role": "user",
                                "parts": [{"text": prompt}],
                            }
                        ],
                        "generationConfig": {
                            "temperature": 0.2,
                            "responseMimeType": "application/json",
                        },
                    },
                )
                response.raise_for_status()
                data = response.json()
                parts = (
                    data.get("candidates", [{}])[0]
                    .get("content", {})
                    .get("parts", [])
                )
                message = "\n".join(
                    part.get("text", "") for part in parts if isinstance(part, dict)
                )
                if not isinstance(message, str) or not message.strip():
                    raise ValueError("Empty LLM response")
                logger.info(
                    "llm_provider_success provider=gemini model=%s attempt=%s",
                    model_name,
                    attempt,
                )
                return message
        except httpx.HTTPStatusError as e:
            last_error = e
            status = e.response.status_code if e.response is not None else 0
            logger.warning("Gemini generation attempt %s/%s failed: %s", attempt, max_attempts, e)
            if status == 429:
                saw_rate_limit = True
                retry_after = 0.0
                if e.response is not None:
                    retry_header = e.response.headers.get("Retry-After")
                    if retry_header:
                        try:
                            retry_after = float(retry_header)
                        except ValueError:
                            retry_after = 0.0
                if current_api_key:
                    cooldown = max(retry_after, GEMINI_RATE_LIMIT_COOLDOWN_SECONDS)
                    _GEMINI_KEY_COOLDOWN_UNTIL[current_api_key] = time.time() + cooldown
                if attempt < max_attempts:
                    jitter = random.uniform(0.0, 0.6)
                    backoff = min(
                        GEMINI_RATE_LIMIT_MAX_BACKOFF_SECONDS,
                        max(retry_after, 1.5 * (2 ** (attempt - 1)) + jitter),
                    )
                    await asyncio.sleep(backoff)
            elif status == 404:
                saw_model_not_found = True
                if attempt < max_attempts:
                    await asyncio.sleep(0.1)
            elif attempt < max_attempts:
                await asyncio.sleep(0.75 * attempt)
        except Exception as e:
            last_error = e
            logger.warning("Gemini generation attempt %s/%s failed: %s", attempt, max_attempts, e)
            if attempt < max_attempts:
                if key_wait:
                    await asyncio.sleep(key_wait)
                else:
                    await asyncio.sleep(0.75 * attempt)

    if saw_model_not_found:
        raise HTTPException(
            status_code=400,
            detail=(
                "One or more Gemini chat models are invalid/unavailable. "
                "Update GEMINI_CHAT_MODEL / GEMINI_CHAT_MODELS."
            ),
        )
    if saw_rate_limit:
        raise HTTPException(status_code=429, detail="Gemini generation rate limit reached")
    raise HTTPException(status_code=502, detail=f"Gemini generation failed after retries: {last_error}")


def _nvidia_max_tokens_for_generation(generation_type: Optional[str]) -> int:
    gtype = (generation_type or "").strip().lower()
    if gtype == "exam":
        return max(NVIDIA_MAX_TOKENS, 2600)
    if gtype == "quiz":
        return max(NVIDIA_MAX_TOKENS, 2000)
    return max(NVIDIA_MAX_TOKENS, 1200)


def _resolve_nvidia_models() -> List[str]:
    # If explicit fallback list is provided, respect it exactly in that order.
    if NVIDIA_CHAT_MODELS:
        return list(NVIDIA_CHAT_MODELS)
    if NVIDIA_CHAT_MODEL:
        return [NVIDIA_CHAT_MODEL]
    return ["qwen/qwen3.5-397b-a17b"]


async def _ordered_nvidia_models_for_request() -> List[str]:
    models = _resolve_nvidia_models()
    if len(models) <= 1:
        return models
    global _NVIDIA_MODEL_ROUTER_NEXT_INDEX
    async with _NVIDIA_MODEL_ROUTER_LOCK:
        start_index = _NVIDIA_MODEL_ROUTER_NEXT_INDEX % len(models)
        _NVIDIA_MODEL_ROUTER_NEXT_INDEX += 1
    ordered = models[start_index:] + models[:start_index]
    logger.info("llm_nvidia_router models=%s ordered=%s", models, ordered)
    return ordered


def _resolve_nvidia_api_key_for_model(model_name: str) -> str:
    model_key = NVIDIA_MODEL_KEYS.get(model_name, "").strip()
    if model_key:
        return model_key
    return NVIDIA_API_KEY


async def _generate_with_llm_internal(
    prompt: str,
    system_message: str,
    generation_type: Optional[str],
) -> str:
    providers = _resolve_llm_providers()
    if not providers:
        raise HTTPException(
            status_code=500,
            detail="LLM_PROVIDER is invalid. Use openai, gemini, nvidia, or hybrid.",
        )
    ordered_providers = await _provider_order_for_request(providers)
    if (generation_type or "").strip().lower() == "exam" and LLM_EXAM_PROVIDER in {"openai", "gemini", "nvidia"}:
        if LLM_EXAM_PROVIDER in ordered_providers:
            ordered_providers = [LLM_EXAM_PROVIDER] + [p for p in ordered_providers if p != LLM_EXAM_PROVIDER]
        else:
            ordered_providers = [LLM_EXAM_PROVIDER] + ordered_providers
        logger.info(
            "llm_exam_override provider=%s ordered=%s",
            LLM_EXAM_PROVIDER,
            ordered_providers,
        )
    logger.info(
        "llm_request routing_mode=%s configured=%s ordered=%s",
        LLM_ROUTING_MODE,
        providers,
        ordered_providers,
    )

    failure_details: List[str] = []
    for provider in ordered_providers:
        try:
            logger.info("llm_request_try provider=%s", provider)
            if provider == "gemini":
                return await _generate_with_gemini(prompt, system_message)
            if provider == "openai":
                return await _generate_with_openai_style_provider(
                    endpoint_url="https://api.openai.com/v1/chat/completions",
                    api_key=OPENAI_API_KEY or "",
                    model_name=OPENAI_CHAT_MODEL,
                    provider_label="OpenAI",
                    prompt=prompt,
                    system_message=system_message,
                    timeout_seconds=60.0,
                    max_attempts=3,
                    force_json_object=True,
                )
            if provider == "nvidia":
                last_nvidia_error: Optional[HTTPException] = None
                for nvidia_model in await _ordered_nvidia_models_for_request():
                    try:
                        logger.info("llm_nvidia_model_try model=%s", nvidia_model)
                        return await _generate_with_openai_style_provider(
                            endpoint_url=f"{NVIDIA_BASE_URL}/chat/completions",
                            api_key=_resolve_nvidia_api_key_for_model(nvidia_model),
                            model_name=nvidia_model,
                            provider_label="NVIDIA",
                            prompt=prompt,
                            system_message=system_message,
                            timeout_seconds=NVIDIA_TIMEOUT_SECONDS,
                            max_attempts=1,
                            max_tokens=_nvidia_max_tokens_for_generation(generation_type),
                            force_json_object=NVIDIA_FORCE_JSON_MODE,
                        )
                    except HTTPException as nvidia_exc:
                        last_nvidia_error = nvidia_exc
                        logger.warning(
                            "llm_nvidia_model_fallback from_model=%s status=%s detail=%s",
                            nvidia_model,
                            nvidia_exc.status_code,
                            nvidia_exc.detail,
                        )
                        continue
                if last_nvidia_error is not None:
                    raise last_nvidia_error
                raise HTTPException(status_code=502, detail="NVIDIA generation failed without a model attempt")
            failure_details.append(f"{provider}: unsupported provider")
        except HTTPException as exc:
            failure_details.append(f"{provider}: {exc.status_code} {exc.detail}")
            # Fallback for provider-specific failures in hybrid mode.
            if len(ordered_providers) > 1 and exc.status_code in {400, 429, 500, 502, 503, 504}:
                logger.warning(
                    "llm_request_fallback from=%s status=%s detail=%s",
                    provider,
                    exc.status_code,
                    exc.detail,
                )
                continue
            raise

    all_rate_limited = bool(failure_details) and all(": 429 " in detail for detail in failure_details)
    if all_rate_limited:
        raise HTTPException(
            status_code=429,
            detail="All configured LLM providers are rate-limited. Try again shortly.",
        )
    raise HTTPException(
        status_code=502,
        detail=f"All configured LLM providers failed: {' | '.join(failure_details)}",
    )


async def generate_with_llm(prompt: str, system_message: str, generation_type: Optional[str] = None) -> str:
    return await _generate_with_llm_internal(prompt, system_message, generation_type=generation_type)


async def repair_json_with_llm(raw_text: str, generation_type: str) -> Dict[str, Any]:
    repair_prompt = (
        "Convert the following content into one valid JSON object only. "
        "Do not add new content, do not omit existing fields intentionally, "
        "and do not include markdown fences.\n\n"
        f"{raw_text}"
    )
    repair_system = "You are a strict JSON repair tool. Output only valid JSON."
    # JSON repair should be fast and deterministic; avoid round-robin routing.
    # Prefer Gemini first when available, then OpenAI, and only then NVIDIA.
    if _is_llm_provider_configured("gemini"):
        repaired_text = await _generate_with_gemini(repair_prompt, repair_system)
    elif _is_llm_provider_configured("openai"):
        repaired_text = await _generate_with_openai_style_provider(
            endpoint_url="https://api.openai.com/v1/chat/completions",
            api_key=OPENAI_API_KEY or "",
            model_name=OPENAI_CHAT_MODEL,
            provider_label="OpenAI",
            prompt=repair_prompt,
            system_message=repair_system,
            timeout_seconds=45.0,
            max_attempts=2,
            max_tokens=1800,
        )
    elif _is_llm_provider_configured("nvidia"):
        nvidia_model = _resolve_nvidia_models()[0]
        repaired_text = await _generate_with_openai_style_provider(
            endpoint_url=f"{NVIDIA_BASE_URL}/chat/completions",
            api_key=_resolve_nvidia_api_key_for_model(nvidia_model),
            model_name=nvidia_model,
            provider_label="NVIDIA",
            prompt=repair_prompt,
            system_message=repair_system,
            timeout_seconds=min(NVIDIA_TIMEOUT_SECONDS, 35.0),
            max_attempts=1,
            max_tokens=1800,
        )
    else:
        raise HTTPException(status_code=500, detail="No configured LLM provider available for JSON repair")
    return parse_llm_json_output(repaired_text)


async def ensure_rate_limit(identity: str, bucket: str, limit: int) -> None:
    await rate_limiter.check(f"{bucket}:{identity}", limit=limit, window_seconds=60)


async def get_usage_counters(user_id: str) -> Dict[str, int]:
    counters = await db.user_usage_counters.find_one({"user_id": user_id}, {"_id": 0})
    return {
        "documents_uploaded_total": int((counters or {}).get("documents_uploaded_total", 0)),
        "generations_total": int((counters or {}).get("generations_total", 0)),
        "documents_deleted_total": int((counters or {}).get("documents_deleted_total", 0)),
        "generations_deleted_total": int((counters or {}).get("generations_deleted_total", 0)),
    }


async def increment_usage_counter(user_id: str, field: str, amount: int = 1) -> None:
    await db.user_usage_counters.update_one(
        {"user_id": user_id},
        {
            "$setOnInsert": {
                "user_id": user_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
            "$set": {"updated_at": datetime.now(timezone.utc).isoformat()},
            "$inc": {field: amount},
        },
        upsert=True,
    )


async def get_window_exam_usage(user_id: str, start_at_iso: str, end_at_iso: str) -> int:
    # Use exact generation timestamps to avoid same-day renewal quota drift.
    # `created_at` is stored in ISO-8601 UTC, so lexicographical range works.
    return await db.generations.count_documents(
        {
            "user_id": user_id,
            "generation_type": "exam",
            "created_at": {"$gte": start_at_iso, "$lte": end_at_iso},
        }
    )


async def consume_generation_quota(user_id: str, generation_type: str) -> None:
    entitlement = await get_generation_entitlement(user_id)
    if entitlement["generation_remaining"] <= 0:
        if entitlement["is_free"]:
            raise HTTPException(
                status_code=402,
                detail=(
                    "Free plan generation quota reached. "
                    "Subscribe to continue generating content."
                ),
            )
        raise HTTPException(
            status_code=402,
            detail=(
                f"{entitlement['plan_name']} plan generation quota reached. "
                "Renew or upgrade your subscription."
            ),
        )

    if (
        generation_type == "exam"
        and not entitlement["is_free"]
        and entitlement.get("exam_limit") is not None
        and int(entitlement.get("exam_remaining", 0)) <= 0
    ):
        raise HTTPException(
            status_code=402,
            detail=(
                f"{entitlement['plan_name']} plan exam quota reached "
                f"({entitlement.get('exam_limit')} per billing cycle). "
                "Upgrade or renew to continue generating exams."
            ),
        )

    today = datetime.now(timezone.utc).date().isoformat()
    inc: Dict[str, int] = {"generation_count": 1}
    if generation_type == "exam":
        inc["exam_generation_count"] = 1
    quota_doc = await db.user_quotas.find_one_and_update(
        {
            "user_id": user_id,
            "date": today,
            "$or": [{"generation_count": {"$lt": MAX_GENERATIONS_PER_DAY}}, {"generation_count": {"$exists": False}}],
        },
        {
            "$setOnInsert": {
                "user_id": user_id,
                "date": today,
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
            "$inc": inc,
        },
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    if not quota_doc:
        raise HTTPException(status_code=429, detail="Daily generation quota exceeded")


async def ensure_topic_access(user_id: str) -> None:
    if not SUBSCRIPTIONS_ENABLED:
        return
    if TOPIC_REQUIRE_ACTIVE_SUBSCRIPTION:
        active_sub = await get_active_subscription(user_id)
        if not active_sub:
            raise HTTPException(
                status_code=402,
                detail="An active subscription is required to use topic suggestions.",
            )
        return
    # Validation hook: confirms subscription subsystem and current entitlement can be resolved.
    await get_generation_entitlement(user_id)


def ensure_topic_abuse_reviewer(current_user: Dict[str, Any]) -> None:
    role = str(current_user.get("role", "")).strip().lower()
    if role not in TOPIC_ABUSE_REVIEW_ROLES:
        raise HTTPException(status_code=403, detail="Not authorized to review topic abuse events")


def ensure_admin_user(current_user: Dict[str, Any]) -> None:
    role = str(current_user.get("role", "")).strip().lower()
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")


async def persist_refresh_token(user_id: str, jti: str, expires_at: datetime) -> None:
    await db.refresh_tokens.insert_one(
        {
            "jti": jti,
            "user_id": user_id,
            "revoked": False,
            "expires_at": expires_at.isoformat(),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    )


async def is_token_revoked(jti: str) -> bool:
    revoked = await db.revoked_tokens.find_one({"jti": jti}, {"_id": 0, "jti": 1})
    return revoked is not None


async def revoke_token(
    jti: str,
    expires_at: datetime,
    token_type: str,
    reason: str = "manual",
    rotated_to_jti: Optional[str] = None,
) -> None:
    await db.revoked_tokens.update_one(
        {"jti": jti},
        {
            "$set": {
                "jti": jti,
                "token_type": token_type,
                "expires_at": expires_at.isoformat(),
                "reason": reason,
                "rotated_to_jti": rotated_to_jti,
                "revoked_at": datetime.now(timezone.utc).isoformat(),
            }
        },
        upsert=True,
    )
    if token_type == "refresh":
        await db.refresh_tokens.update_one(
            {"jti": jti},
            {
                "$set": {
                    "revoked": True,
                    "revoked_at": datetime.now(timezone.utc).isoformat(),
                    "revoked_reason": reason,
                    "rotated_to_jti": rotated_to_jti,
                }
            },
        )


async def decode_token(token: str, expected_type: str, check_revoked: bool = True) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    if payload.get("type") != expected_type:
        raise HTTPException(status_code=401, detail=f"Invalid token type: expected {expected_type}")

    jti = payload.get("jti")
    if not jti:
        raise HTTPException(status_code=401, detail="Malformed token")
    if check_revoked and await is_token_revoked(jti):
        raise HTTPException(status_code=401, detail="Token has been revoked")
    return payload


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    payload = await decode_token(credentials.credentials, "access")
    user = await db.users.find_one({"id": payload["user_id"]}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    request_id = str(uuid.uuid4())
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception as e:
        duration_ms = int((time.perf_counter() - start) * 1000)
        logger.exception(
            "request_id=%s method=%s path=%s status=500 duration_ms=%s error=%s",
            request_id,
            request.method,
            request.url.path,
            duration_ms,
            str(e),
        )
        raise
    duration_ms = int((time.perf_counter() - start) * 1000)
    response.headers["X-Request-ID"] = request_id
    logger.info(
        "request_id=%s method=%s path=%s status=%s duration_ms=%s",
        request_id,
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.warning(
        "HTTPException request_id=%s path=%s status=%s detail=%s",
        getattr(request.state, "request_id", "-"),
        request.url.path,
        exc.status_code,
        exc.detail,
    )
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(Exception)
async def unhandled_exception_handler(_: Request, exc: Exception):
    logger.exception("Unhandled server error: %s", exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@api_router.post("/auth/register", response_model=SignupChallengeResponse)
async def register(user_data: UserRegister, request: Request):
    ip = request.client.host if request.client else "unknown"
    await ensure_rate_limit(ip, "auth_register", AUTH_PER_MIN_LIMIT)
    await rate_limiter.check(
        f"auth_signup_otp_request_ip:{ip}",
        limit=SIGNUP_OTP_REQUEST_PER_HOUR_LIMIT,
        window_seconds=60 * 60,
    )
    normalized_email = user_data.email.lower()

    existing_user = await db.users.find_one({"email": normalized_email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    now_iso = datetime.now(timezone.utc).isoformat()
    deleted_email_doc = await db.deleted_account_emails.find_one(
        {
            "email": normalized_email,
            "blocked_until": {"$gte": now_iso},
        },
        {"_id": 0, "blocked_until": 1},
    )
    if deleted_email_doc:
        remaining = describe_remaining_grace(str(deleted_email_doc["blocked_until"]))
        raise HTTPException(
            status_code=403,
            detail=(
                f"This email is in account-reuse grace period. "
                f"You can create a new account after {current_account_reuse_grace_days()} day(s). "
                f"Time remaining: {remaining}."
            ),
        )

    if len(user_data.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    role = normalize_user_role(user_data.role)

    signup_id, otp, otp_hash, expires_at = create_signup_challenge()
    await db.pending_signups.update_many(
        {"email": normalized_email, "verified_at": None, "invalidated_at": None},
        {"$set": {"invalidated_at": now_iso}},
    )
    await db.pending_signups.insert_one(
        {
            "id": signup_id,
            "email": normalized_email,
            "full_name": user_data.full_name.strip(),
            "role": role,
            "password_hash": hash_password(user_data.password),
            "otp_hash": otp_hash,
            "attempts": 0,
            "requested_ip": ip,
            "expires_at": expires_at.isoformat(),
            "verified_at": None,
            "invalidated_at": None,
            "created_at": now_iso,
        }
    )
    asyncio.create_task(
        enqueue_signup_otp_email(
            email=normalized_email,
            full_name=user_data.full_name.strip(),
            otp=otp,
        )
    )
    await asyncio.sleep(0.12)
    return SignupChallengeResponse(
        signup_id=signup_id,
        message="Verification code sent to your email. Enter OTP to continue.",
    )


@api_router.post("/auth/register/verify", response_model=TokenResponse)
async def verify_signup_otp(payload: SignupOtpVerifyRequest, request: Request):
    ip = request.client.host if request.client else "unknown"
    await ensure_rate_limit(ip, "auth_register_verify", AUTH_PER_MIN_LIMIT)
    await ensure_rate_limit(payload.signup_id, "auth_signup_otp_verify_signup", SIGNUP_OTP_VERIFY_PER_MIN_LIMIT)

    now_iso = datetime.now(timezone.utc).isoformat()
    signup_doc = await db.pending_signups.find_one(
        {
            "id": payload.signup_id,
            "verified_at": None,
            "invalidated_at": None,
            "expires_at": {"$gte": now_iso},
        },
        {"_id": 0},
    )
    if not signup_doc:
        raise HTTPException(status_code=400, detail="OTP challenge is invalid or expired")

    expected_hash = hash_signup_otp(payload.signup_id, payload.otp.strip())
    if expected_hash != signup_doc.get("otp_hash"):
        new_attempts = int(signup_doc.get("attempts", 0)) + 1
        updates: Dict[str, Any] = {"attempts": new_attempts}
        if new_attempts >= SIGNUP_OTP_MAX_ATTEMPTS:
            updates["invalidated_at"] = now_iso
        await db.pending_signups.update_one({"id": payload.signup_id}, {"$set": updates})
        raise HTTPException(status_code=400, detail="Invalid verification code")

    existing_user = await db.users.find_one({"email": signup_doc["email"]}, {"_id": 0, "id": 1})
    if existing_user:
        await db.pending_signups.update_one(
            {"id": payload.signup_id},
            {"$set": {"invalidated_at": now_iso}},
        )
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=signup_doc["email"],
        full_name=signup_doc["full_name"],
        role=normalize_user_role(str(signup_doc.get("role", "student"))),
    )
    await db.users.insert_one(
        {
            **user.model_dump(),
            "created_at": user.created_at.isoformat(),
            "password_hash": signup_doc["password_hash"],
        }
    )
    await db.pending_signups.update_one(
        {"id": payload.signup_id},
        {"$set": {"verified_at": now_iso, "verified_ip": ip}},
    )

    access_token, _, _ = create_token(
        user.id, user.email, "access", timedelta(minutes=ACCESS_TOKEN_MINUTES)
    )
    refresh_token, refresh_jti, refresh_exp = create_token(
        user.id, user.email, "refresh", timedelta(days=REFRESH_TOKEN_DAYS)
    )
    await persist_refresh_token(user.id, refresh_jti, refresh_exp)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token, user=user)


@api_router.post("/auth/register/resend")
async def resend_signup_otp(payload: SignupOtpResendRequest, request: Request):
    ip = request.client.host if request.client else "unknown"
    await ensure_rate_limit(ip, "auth_register_resend", AUTH_PER_MIN_LIMIT)
    await rate_limiter.check(
        f"auth_signup_otp_resend_ip:{ip}",
        limit=SIGNUP_OTP_REQUEST_PER_HOUR_LIMIT,
        window_seconds=60 * 60,
    )
    now_iso = datetime.now(timezone.utc).isoformat()
    signup_doc = await db.pending_signups.find_one(
        {
            "id": payload.signup_id,
            "verified_at": None,
            "invalidated_at": None,
            "expires_at": {"$gte": now_iso},
        },
        {"_id": 0},
    )
    if not signup_doc:
        raise HTTPException(status_code=400, detail="OTP challenge is invalid or expired")

    _, otp, otp_hash, expires_at = create_signup_challenge()
    await db.pending_signups.update_one(
        {"id": payload.signup_id},
        {
            "$set": {
                "otp_hash": otp_hash,
                "attempts": 0,
                "expires_at": expires_at.isoformat(),
                "updated_at": now_iso,
                "requested_ip": ip,
            }
        },
    )
    asyncio.create_task(
        enqueue_signup_otp_email(
            email=signup_doc["email"],
            full_name=signup_doc.get("full_name", ""),
            otp=otp,
        )
    )
    return {"message": "A new verification code has been sent."}


@api_router.post("/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin, request: Request):
    ip = request.client.host if request.client else "unknown"
    await ensure_rate_limit(ip, "auth_login", AUTH_PER_MIN_LIMIT)
    normalized_email = credentials.email.lower()

    user_doc = await db.users.find_one({"email": normalized_email}, {"_id": 0})
    if not user_doc or not verify_password(credentials.password, user_doc["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user = User(**{k: v for k, v in user_doc.items() if k != "password_hash"})
    access_token, _, _ = create_token(
        user.id, user.email, "access", timedelta(minutes=ACCESS_TOKEN_MINUTES)
    )
    refresh_token, refresh_jti, refresh_exp = create_token(
        user.id, user.email, "refresh", timedelta(days=REFRESH_TOKEN_DAYS)
    )
    await persist_refresh_token(user.id, refresh_jti, refresh_exp)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token, user=user)


@api_router.post("/auth/password-reset/request")
async def request_password_reset(payload: PasswordResetRequest, request: Request):
    ip = request.client.host if request.client else "unknown"
    await rate_limiter.check(
        f"auth_password_reset_request_ip:{ip}",
        limit=PASSWORD_RESET_REQUEST_PER_HOUR_LIMIT,
        window_seconds=60 * 60,
    )
    await rate_limiter.check(
        f"auth_password_reset_request_email:{payload.email.lower()}",
        limit=PASSWORD_RESET_REQUEST_PER_HOUR_LIMIT,
        window_seconds=60 * 60,
    )

    if PASSWORD_RESET_REQUIRE_HTTPS and not request_is_https(request):
        raise HTTPException(status_code=400, detail="Password reset requires HTTPS")

    user_doc = await db.users.find_one({"email": payload.email.lower()}, {"_id": 0, "id": 1, "email": 1, "full_name": 1})
    if user_doc:
        token, token_hash, expires_at = create_password_reset_token()
        now_iso = datetime.now(timezone.utc).isoformat()
        await db.password_reset_tokens.update_many(
            {
                "user_id": user_doc["id"],
                "used_at": None,
            },
            {"$set": {"invalidated_at": now_iso}},
        )
        await db.password_reset_tokens.insert_one(
            {
                "id": str(uuid.uuid4()),
                "user_id": user_doc["id"],
                "email": user_doc["email"],
                "token_hash": token_hash,
                "used_at": None,
                "invalidated_at": None,
                "expires_at": expires_at.isoformat(),
                "requested_ip": ip,
                "created_at": now_iso,
            }
        )
        deep_link = build_password_reset_deep_link(token)
        asyncio.create_task(
            enqueue_password_reset_email(
                email=user_doc["email"],
                full_name=user_doc.get("full_name", ""),
                deep_link=deep_link,
            )
        )

    await asyncio.sleep(0.15)

    # Always return the same response to prevent account enumeration.
    return {
        "message": (
            "If an account exists for that email, a password reset link has been sent."
        )
    }


@api_router.post("/auth/password-reset/confirm")
async def confirm_password_reset(payload: PasswordResetConfirmRequest, request: Request):
    ip = request.client.host if request.client else "unknown"
    await ensure_rate_limit(ip, "auth_password_reset_confirm_ip", PASSWORD_RESET_CONFIRM_PER_MIN_LIMIT)

    if len(payload.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")

    token_hash = hash_reset_token(payload.token)
    now_iso = datetime.now(timezone.utc).isoformat()
    token_doc = await db.password_reset_tokens.find_one_and_update(
        {
            "token_hash": token_hash,
            "used_at": None,
            "invalidated_at": None,
            "expires_at": {"$gte": now_iso},
        },
        {
            "$set": {
                "used_at": now_iso,
                "used_ip": ip,
            }
        },
        return_document=ReturnDocument.BEFORE,
    )
    if not token_doc:
        raise HTTPException(status_code=400, detail="Reset token is invalid or expired")

    user_doc = await db.users.find_one({"id": token_doc["user_id"]}, {"_id": 0, "id": 1, "password_hash": 1})
    if not user_doc:
        raise HTTPException(status_code=400, detail="Reset token is invalid or expired")

    if verify_password(payload.new_password, user_doc["password_hash"]):
        raise HTTPException(status_code=400, detail="New password must be different from current password")

    await db.users.update_one(
        {"id": user_doc["id"]},
        {"$set": {"password_hash": hash_password(payload.new_password)}},
    )
    await db.refresh_tokens.delete_many({"user_id": user_doc["id"]})
    await db.password_reset_tokens.update_many(
        {"user_id": user_doc["id"], "used_at": None},
        {"$set": {"invalidated_at": now_iso}},
    )

    return {"message": "Password reset successful. Please sign in with your new password."}


@api_router.post("/auth/refresh", response_model=TokenResponse)
async def refresh_tokens(payload: RefreshTokenRequest):
    refresh_payload = await decode_token(payload.refresh_token, "refresh", check_revoked=False)
    refresh_doc = await db.refresh_tokens.find_one({"jti": refresh_payload["jti"]}, {"_id": 0})
    if not refresh_doc:
        raise HTTPException(status_code=401, detail="Refresh token invalid or revoked")
    if refresh_doc.get("revoked"):
        revoked_reason = str(refresh_doc.get("revoked_reason") or "")
        revoked_at_raw = refresh_doc.get("revoked_at")
        allow_reuse = False
        if revoked_reason == "rotated" and revoked_at_raw:
            try:
                revoked_at = datetime.fromisoformat(str(revoked_at_raw))
                age_seconds = (datetime.now(timezone.utc) - revoked_at).total_seconds()
                allow_reuse = age_seconds <= max(0, REFRESH_ROTATION_GRACE_SECONDS)
            except Exception:
                allow_reuse = False
        if not allow_reuse:
            raise HTTPException(status_code=401, detail="Refresh token invalid or revoked")
        logger.info(
            "refresh_token_reuse_within_grace user_id=%s jti=%s grace_seconds=%s",
            refresh_payload["user_id"],
            refresh_payload["jti"],
            REFRESH_ROTATION_GRACE_SECONDS,
        )

    user_doc = await db.users.find_one({"id": refresh_payload["user_id"]}, {"_id": 0})
    if not user_doc:
        raise HTTPException(status_code=401, detail="User not found")

    user = User(**{k: v for k, v in user_doc.items() if k != "password_hash"})
    access_token, _, _ = create_token(
        user.id, user.email, "access", timedelta(minutes=ACCESS_TOKEN_MINUTES)
    )
    new_refresh_token, refresh_jti, refresh_exp = create_token(
        user.id, user.email, "refresh", timedelta(days=REFRESH_TOKEN_DAYS)
    )
    await revoke_token(
        refresh_payload["jti"],
        datetime.fromtimestamp(refresh_payload["exp"], tz=timezone.utc),
        "refresh",
        reason="rotated",
        rotated_to_jti=refresh_jti,
    )
    await persist_refresh_token(user.id, refresh_jti, refresh_exp)
    return TokenResponse(access_token=access_token, refresh_token=new_refresh_token, user=user)


@api_router.post("/auth/logout")
async def logout(
    request: LogoutRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    access_payload = await decode_token(credentials.credentials, "access")
    access_exp = datetime.fromtimestamp(access_payload["exp"], tz=timezone.utc)
    await revoke_token(access_payload["jti"], access_exp, "access", reason="logout")

    if request.refresh_token:
        refresh_payload = await decode_token(request.refresh_token, "refresh")
        refresh_exp = datetime.fromtimestamp(refresh_payload["exp"], tz=timezone.utc)
        await revoke_token(refresh_payload["jti"], refresh_exp, "refresh", reason="logout")

    return {"message": "Logged out"}


@api_router.get("/auth/me", response_model=User)
async def get_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    return User(**normalize_datetime_fields(current_user, ["created_at"]))


@api_router.get("/subscriptions/plans", response_model=List[SubscriptionPlan])
async def subscription_plans():
    return get_subscription_plans()


@api_router.get("/subscriptions/me")
async def my_subscription(current_user: Dict[str, Any] = Depends(get_current_user)):
    now_iso = datetime.now(timezone.utc).isoformat()
    sub = await db.subscriptions.find_one(
        {"user_id": current_user["id"], **active_subscription_filter(now_iso)},
        {"_id": 0},
    )
    if not sub:
        return {"active": False, "plan_id": None, "end_at": None}
    return {"active": True, **sub}


@api_router.get("/subscriptions/entitlement")
async def my_subscription_entitlement(current_user: Dict[str, Any] = Depends(get_current_user)):
    return await get_generation_entitlement(current_user["id"])


@api_router.post("/subscriptions/checkout")
async def start_subscription_checkout(
    payload: SubscriptionCheckoutRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    if not SUBSCRIPTIONS_ENABLED:
        raise HTTPException(status_code=400, detail="Subscriptions are not enabled")
    if not mpesa_service.enabled:
        raise HTTPException(status_code=500, detail="M-Pesa is not configured")

    plan = get_subscription_plan(payload.plan_id)
    account_reference = f"{SUBSCRIPTION_ACCOUNT_REFERENCE_PREFIX}{current_user['id'][-6:].upper()}"
    description = f"{SUBSCRIPTION_TRANSACTION_DESC_PREFIX} {plan.name} Plan"
    stk_result = await mpesa_service.stk_push(
        phone_number=payload.phone_number,
        amount=plan.amount_kes,
        account_reference=account_reference,
        transaction_desc=description,
    )
    if not stk_result.get("success"):
        raise HTTPException(
            status_code=502,
            detail=f"STK push failed: {stk_result.get('error', 'Unknown error')}",
        )

    payment_doc = {
        "id": str(uuid.uuid4()),
        "user_id": current_user["id"],
        "plan_id": plan.plan_id,
        "amount_kes": plan.amount_kes,
        "phone_number": mpesa_service.normalize_phone(payload.phone_number),
        "status": "pending",
        "merchant_request_id": stk_result.get("merchant_request_id"),
        "checkout_request_id": stk_result.get("checkout_request_id"),
        "response_code": stk_result.get("response_code"),
        "response_description": stk_result.get("response_description"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.subscription_payments.insert_one(payment_doc)
    return {
        "message": "STK push sent to customer phone",
        "payment_id": payment_doc["id"],
        "checkout_request_id": payment_doc["checkout_request_id"],
        "customer_message": stk_result.get("customer_message"),
    }


@api_router.get("/subscriptions/payment/{checkout_request_id}")
async def subscription_payment_status(
    checkout_request_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    payment = await db.subscription_payments.find_one(
        {"checkout_request_id": checkout_request_id, "user_id": current_user["id"]},
        {"_id": 0},
    )
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")
    return payment


@api_router.post("/payments/mpesa/callback")
async def mpesa_callback(payload: Dict[str, Any], background_tasks: BackgroundTasks):
    callback = (
        payload.get("Body", {})
        .get("stkCallback", {})
    )
    checkout_request_id = callback.get("CheckoutRequestID")
    merchant_request_id = callback.get("MerchantRequestID")
    result_code = str(callback.get("ResultCode", ""))
    result_desc = callback.get("ResultDesc", "")

    if not checkout_request_id:
        return {"ResultCode": 0, "ResultDesc": "Accepted"}

    updates: Dict[str, Any] = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "result_code": result_code,
        "result_desc": result_desc,
        "merchant_request_id": merchant_request_id,
        "callback_payload": callback,
    }

    receipt = None
    paid_phone = None
    amount = None
    callback_items = callback.get("CallbackMetadata", {}).get("Item", [])
    if isinstance(callback_items, list):
        for item in callback_items:
            name = item.get("Name")
            value = item.get("Value")
            if name == "MpesaReceiptNumber":
                receipt = value
            elif name == "PhoneNumber":
                paid_phone = str(value)
            elif name == "Amount":
                amount = int(value)

    subscription_payment = await db.subscription_payments.find_one(
        {"checkout_request_id": checkout_request_id},
        {"_id": 0},
    )
    class_payment = None
    if not subscription_payment:
        class_payment = await db.class_payments.find_one(
            {"checkout_request_id": checkout_request_id},
            {"_id": 0},
        )
    if not subscription_payment and not class_payment:
        return {"ResultCode": 0, "ResultDesc": "Accepted"}

    if subscription_payment and result_code == "0":
        was_already_paid = str(subscription_payment.get("status", "")).lower() == "paid"
        updates.update(
            {
                "status": "paid",
                "paid_at": datetime.now(timezone.utc).isoformat(),
                "mpesa_receipt_number": receipt,
                "paid_phone_number": paid_phone,
            }
        )
        if amount is not None:
            updates["amount_kes"] = amount

        plan = get_subscription_plan(subscription_payment["plan_id"])
        now_utc = datetime.now(timezone.utc)
        existing_sub = await db.subscriptions.find_one({"user_id": subscription_payment["user_id"]}, {"_id": 0})
        should_stack = False
        start_at = now_utc
        end_at = now_utc + timedelta(days=plan.cycle_days)
        quota_multiplier = 1

        if existing_sub and existing_sub.get("status") == "active" and existing_sub.get("plan_id") == plan.plan_id:
            existing_end_raw = existing_sub.get("end_at")
            existing_start_raw = existing_sub.get("start_at")
            try:
                existing_end = datetime.fromisoformat(str(existing_end_raw))
            except Exception:
                existing_end = now_utc
            if existing_end.tzinfo is None:
                existing_end = existing_end.replace(tzinfo=timezone.utc)

            if existing_end >= now_utc:
                should_stack = True
                try:
                    existing_start = datetime.fromisoformat(str(existing_start_raw))
                    if existing_start.tzinfo is None:
                        existing_start = existing_start.replace(tzinfo=timezone.utc)
                except Exception:
                    existing_start = now_utc
                start_at = existing_start
                end_at = existing_end + timedelta(days=plan.cycle_days)
                quota_multiplier = max(1, int(existing_sub.get("quota_multiplier", 1))) + 1

        await db.subscriptions.update_one(
            {"user_id": subscription_payment["user_id"]},
            {
                "$set": {
                    "user_id": subscription_payment["user_id"],
                    "plan_id": plan.plan_id,
                    "plan_name": plan.name,
                    "status": "active",
                    "amount_kes": subscription_payment.get("amount_kes", plan.amount_kes),
                    "mpesa_receipt_number": receipt,
                    "start_at": start_at.isoformat(),
                    "end_at": end_at.isoformat(),
                    "quota_multiplier": quota_multiplier,
                    "renewal_mode": "stacked" if should_stack else "reset",
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            },
            upsert=True,
        )
        if not was_already_paid:
            user_doc = await db.users.find_one(
                {"id": subscription_payment["user_id"]},
                {"_id": 0, "email": 1, "full_name": 1},
            )
            if user_doc and user_doc.get("email"):
                entitlement = await get_generation_entitlement(subscription_payment["user_id"])
                background_tasks.add_task(
                    enqueue_subscription_updated_email,
                    email=user_doc["email"],
                    full_name=user_doc.get("full_name", ""),
                    plan_name=entitlement.get("plan_name", plan.name),
                    generation_limit=int(entitlement.get("generation_limit", int(plan.generation_quota))),
                    exam_limit=entitlement.get("exam_limit"),
                    window_end_at=entitlement.get("window_end_at"),
                )
                logger.info(
                    "subscription_update_email_queued user_id=%s email=%s plan=%s",
                    subscription_payment["user_id"],
                    user_doc["email"],
                    entitlement.get("plan_name", plan.name),
                )
            else:
                logger.warning(
                    "subscription_update_email_skipped user_id=%s reason=user_email_not_found",
                    subscription_payment["user_id"],
                )
        await db.subscription_payments.update_one(
            {"checkout_request_id": checkout_request_id},
            {"$set": updates},
        )
    elif subscription_payment:
        updates["status"] = "failed"
        await db.subscription_payments.update_one(
            {"checkout_request_id": checkout_request_id},
            {"$set": updates},
        )
    elif class_payment:
        class_updates = dict(updates)
        if result_code == "0":
            was_already_paid = str(class_payment.get("status", "")).lower() == "paid"
            class_updates.update(
                {
                    "status": "paid",
                    "paid_at": datetime.now(timezone.utc).isoformat(),
                    "mpesa_receipt_number": receipt,
                    "paid_phone_number": paid_phone,
                }
            )
            if amount is not None:
                class_updates["amount_kes"] = amount
            await db.class_payments.update_one(
                {"checkout_request_id": checkout_request_id},
                {"$set": class_updates},
            )
            if not was_already_paid:
                now_iso = datetime.now(timezone.utc).isoformat()
                enrollment_doc = {
                    "id": str(uuid.uuid4()),
                    "class_id": class_payment["class_id"],
                    "student_id": class_payment["student_id"],
                    "joined_at": now_iso,
                    "payment_status": "paid",
                    "payment_id": class_payment["id"],
                }
                join_result = await db.class_enrollments.update_one(
                    {
                        "class_id": class_payment["class_id"],
                        "student_id": class_payment["student_id"],
                    },
                    {"$setOnInsert": enrollment_doc, "$set": {"payment_status": "paid"}},
                    upsert=True,
                )
                if join_result.upserted_id is not None:
                    await db.class_sessions.update_one(
                        {"id": class_payment["class_id"]},
                        {"$inc": {"join_count": 1}},
                    )

                teacher_net, platform_fee = compute_class_escrow_split(int(class_payment.get("amount_kes", 0)))
                escrow_doc = {
                    "id": str(uuid.uuid4()),
                    "payment_id": class_payment["id"],
                    "class_id": class_payment["class_id"],
                    "student_id": class_payment["student_id"],
                    "teacher_id": class_payment["teacher_id"],
                    "gross_amount_kes": int(class_payment.get("amount_kes", 0)),
                    "platform_fee_percent": current_class_escrow_platform_fee_percent(),
                    "platform_fee_kes": platform_fee,
                    "teacher_net_kes": teacher_net,
                    "status": "held",
                    "held_at": now_iso,
                    "created_at": now_iso,
                    "updated_at": now_iso,
                }
                await db.class_escrow.update_one(
                    {"payment_id": class_payment["id"]},
                    {"$setOnInsert": escrow_doc},
                    upsert=True,
                )
        else:
            class_updates["status"] = "failed"
            await db.class_payments.update_one(
                {"checkout_request_id": checkout_request_id},
                {"$set": class_updates},
            )
    return {"ResultCode": 0, "ResultDesc": "Accepted"}


async def delete_user_data(user_id: str):
    docs = await db.documents.find({"user_id": user_id}, {"_id": 0}).to_list(1000)
    for doc in docs:
        file_path = Path(doc.get("file_path", ""))
        if file_path.exists():
            try:
                file_path.unlink()
            except OSError:
                logger.warning("Unable to delete uploaded file: %s", file_path)

    await db.document_chunks.delete_many({"user_id": user_id})
    await db.documents.delete_many({"user_id": user_id})
    await db.generations.delete_many({"user_id": user_id})
    await db.subscription_payments.delete_many({"user_id": user_id})
    await db.subscriptions.delete_many({"user_id": user_id})
    await db.generation_jobs.delete_many({"user_id": user_id})
    await db.notifications.delete_many({"user_id": user_id})
    await db.analytics_runs.delete_many({"user_id": user_id})
    teacher_classes = await db.class_sessions.find({"teacher_id": user_id}, {"_id": 0, "id": 1}).to_list(2000)
    teacher_class_ids = [c.get("id") for c in teacher_classes if c.get("id")]
    if teacher_class_ids:
        await db.class_enrollments.delete_many({"class_id": {"$in": teacher_class_ids}})
        await db.class_reviews.delete_many({"class_id": {"$in": teacher_class_ids}})
        await db.class_payments.delete_many({"class_id": {"$in": teacher_class_ids}})
        await db.class_escrow.delete_many({"class_id": {"$in": teacher_class_ids}})
    await db.class_sessions.delete_many({"teacher_id": user_id})
    await db.class_enrollments.delete_many({"student_id": user_id})
    await db.class_reviews.delete_many({"student_id": user_id})
    await db.class_reviews.delete_many({"teacher_id": user_id})
    await db.class_payments.delete_many({"student_id": user_id})
    await db.class_payments.delete_many({"teacher_id": user_id})
    await db.class_escrow.delete_many({"student_id": user_id})
    await db.class_escrow.delete_many({"teacher_id": user_id})
    await db.class_withdrawals.delete_many({"teacher_id": user_id})
    await db.teacher_escrow_wallets.delete_many({"teacher_id": user_id})
    await db.platform_withdrawals.delete_many({"requested_by": user_id})
    await db.password_reset_tokens.delete_many({"user_id": user_id})
    await db.user_quotas.delete_many({"user_id": user_id})
    await db.user_usage_counters.delete_many({"user_id": user_id})
    await db.refresh_tokens.delete_many({"user_id": user_id})
    await db.retention_email_targets.delete_many({"user_id": user_id})
    await db.retention_email_recipients.delete_many({"user_id": user_id})
    await db.users.delete_one({"id": user_id})


@api_router.put("/auth/me", response_model=User)
async def update_me(
    payload: UpdateProfileRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    updates: Dict[str, Any] = {}

    if payload.full_name is not None:
        full_name = payload.full_name.strip()
        if len(full_name) < 2:
            raise HTTPException(status_code=400, detail="Full name must be at least 2 characters")
        updates["full_name"] = full_name

    if payload.email is not None:
        email = payload.email.strip().lower()
        existing = await db.users.find_one(
            {"email": email, "id": {"$ne": current_user["id"]}},
            {"_id": 0},
        )
        if existing:
            raise HTTPException(status_code=400, detail="Email already in use")
        updates["email"] = email

    if not updates:
        raise HTTPException(status_code=400, detail="No profile fields to update")

    updated = await db.users.find_one_and_update(
        {"id": current_user["id"]},
        {"$set": updates},
        return_document=ReturnDocument.AFTER,
        projection={"_id": 0},
    )
    if not updated:
        raise HTTPException(status_code=404, detail="User not found")
    return User(**normalize_datetime_fields(updated, ["created_at"]))


@api_router.post("/auth/change-password")
async def change_password(
    payload: ChangePasswordRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    if len(payload.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
    if payload.new_password == payload.current_password:
        raise HTTPException(status_code=400, detail="New password must be different from current password")

    user_doc = await db.users.find_one({"id": current_user["id"]}, {"_id": 0})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")
    if not verify_password(payload.current_password, user_doc["password_hash"]):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    await db.users.update_one(
        {"id": current_user["id"]},
        {"$set": {"password_hash": hash_password(payload.new_password)}},
    )
    await db.refresh_tokens.delete_many({"user_id": current_user["id"]})
    return {"message": "Password updated successfully. Please login again."}


@api_router.post("/auth/delete-account")
async def delete_account(
    payload: DeleteAccountRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    user_doc = await db.users.find_one({"id": current_user["id"]}, {"_id": 0})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")
    if not verify_password(payload.password, user_doc["password_hash"]):
        raise HTTPException(status_code=401, detail="Password is incorrect")

    deleted_at = datetime.now(timezone.utc)
    blocked_until = deleted_at + timedelta(days=current_account_reuse_grace_days())
    await db.deleted_account_emails.update_one(
        {"email": user_doc["email"].lower()},
        {
            "$set": {
                "email": user_doc["email"].lower(),
                "blocked_until": blocked_until.isoformat(),
                "deleted_at": deleted_at.isoformat(),
                "reason": "account_deleted",
            }
        },
        upsert=True,
    )
    await delete_user_data(current_user["id"])
    return {
        "message": (
            f"Account deleted successfully. This email can be used again after "
            f"{current_account_reuse_grace_days()} day(s)."
        )
    }


@api_router.post("/documents/upload", response_model=DocumentMetadata)
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    await ensure_rate_limit(current_user["id"], "upload_user", UPLOAD_PER_MIN_LIMIT)
    entitlement = await get_generation_entitlement(current_user["id"])
    if entitlement["is_free"] and entitlement["document_used"] >= FREE_PLAN_MAX_DOCUMENTS:
        raise HTTPException(
            status_code=402,
            detail=(
                f"Free plan allows only {FREE_PLAN_MAX_DOCUMENTS} document upload. "
                "Subscribe to upload more documents."
            ),
        )
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    file_ext = file.filename.split(".")[-1].lower()
    if file_ext not in {"pdf", "docx", "txt"}:
        raise HTTPException(status_code=400, detail="Only PDF, DOCX, and TXT files are supported")

    file_content, file_size = await read_upload_with_limit(file, MAX_UPLOAD_BYTES)
    detect_mime(file_content, file_ext, file.content_type)

    if file_ext == "pdf":
        text = extract_text_from_pdf(file_content)
    elif file_ext == "docx":
        text = extract_text_from_docx(file_content)
    else:
        try:
            text = file_content.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="TXT file must be UTF-8 encoded")

    if not text.strip():
        raise HTTPException(status_code=400, detail="No text content found in document")

    doc_id = str(uuid.uuid4())
    safe_filename = Path(file.filename).name
    file_path = UPLOAD_DIR / f"{doc_id}_{safe_filename}"
    async with aiofiles.open(file_path, "wb") as f:
        await f.write(file_content)

    chunks = chunk_text(text)
    if not chunks:
        raise HTTPException(status_code=400, detail="Document could not be chunked")

    doc_metadata = DocumentMetadata(
        id=doc_id,
        user_id=current_user["id"],
        filename=safe_filename,
        file_type=file_ext,
        file_path=str(file_path),
        file_size=file_size,
        total_chunks=len(chunks),
        keywords=extract_keywords(text),
    )

    doc_dict = doc_metadata.model_dump()
    doc_dict["uploaded_at"] = doc_dict["uploaded_at"].isoformat()
    await db.documents.insert_one(doc_dict)

    try:
        await embed_chunks_parallel(doc_id, current_user["id"], chunks)
    except HTTPException as exc:
        await db.documents.delete_one({"id": doc_id})
        await db.document_chunks.delete_many({"document_id": doc_id})
        if file_path.exists():
            file_path.unlink()
        logger.warning(
            "Document upload rolled back doc_id=%s user_id=%s status=%s detail=%s",
            doc_id,
            current_user["id"],
            exc.status_code,
            exc.detail,
        )
        raise

    await increment_usage_counter(current_user["id"], "documents_uploaded_total", 1)
    record_metric("document_upload_success", tags={"user_id": current_user["id"], "chunks": str(len(chunks))})
    return doc_metadata


@api_router.get("/documents", response_model=List[DocumentMetadata])
async def list_documents(
    limit: int = 50,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    safe_limit = max(1, min(limit, 200))
    docs = await db.documents.find({"user_id": current_user["id"]}, {"_id": 0}).sort("uploaded_at", -1).to_list(safe_limit)
    return [DocumentMetadata(**normalize_datetime_fields(doc, ["uploaded_at"])) for doc in docs]


@api_router.delete("/documents/{document_id}")
async def delete_document(document_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    doc = await db.documents.find_one({"id": document_id, "user_id": current_user["id"]}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    file_path = Path(doc["file_path"])
    if file_path.exists():
        file_path.unlink()

    await db.documents.delete_one({"id": document_id})
    await db.document_chunks.delete_many({"document_id": document_id})
    await increment_usage_counter(current_user["id"], "documents_deleted_total", 1)
    return {"message": "Document deleted successfully"}

def build_prompt(request: GenerationRequest, context: str) -> str:
    strict_json_clause = (
        "Return ONLY valid JSON. Do not include markdown, comments, prose, or trailing text."
    )

    if request.generation_type == "summary":
        return f"""Based on the coursework material below, generate a comprehensive summary.
{f'Focus on topic: {request.topic}' if request.topic else ''}
Coursework Material:
{context}
Provide JSON:
{{"summary":"...","key_points":["..."]}}
{strict_json_clause}"""

    if request.generation_type == "concepts":
        return f"""Based on the coursework material below, break down key concepts.
{f'Focus on topic: {request.topic}' if request.topic else ''}
Coursework Material:
{context}
Provide JSON:
{{"concepts":[{{"name":"...","explanation":"...","related_to":["..."]}}]}}
{strict_json_clause}"""

    if request.generation_type == "examples":
        return f"""Based on the coursework material below, create worked examples.
{f'Focus on topic: {request.topic}' if request.topic else ''}
Difficulty: {request.difficulty}
Coursework Material:
{context}
Provide JSON:
{{"examples":[{{"problem":"...","solution_steps":["..."],"answer":"...","learning_points":["..."]}}]}}
{strict_json_clause}"""

    if request.generation_type == "quiz":
        num_q = request.num_questions or 10
        q_types = request.question_types or ["mcq", "structured"]
        return f"""Based STRICTLY on the coursework material, generate a revision quiz.
{f'Focus on topic: {request.topic}' if request.topic else ''}
Difficulty: {request.difficulty}
Number of questions: {num_q}
Question types: {", ".join(q_types)}
Coursework Material:
{context}
Provide JSON:
{{"quiz":[{{"type":"mcq|structured","question":"...","options":["A","B","C","D"],"correct_answer":"...","model_answer":"...","marks":5,"explanation":"..."}}]}}
Rules:
- Use only provided material.
- Include options and correct_answer for MCQ.
- Include model_answer for every question (including non-MCQ).
- Include marks for every question.
{strict_json_clause}"""

    if request.generation_type == "exam":
        total_marks = request.marks or 100
        instruction_text = (request.additional_instructions or "").strip()
        normalized_instructions = instruction_text.lower()
        q_types = list(request.question_types or ["mcq", "structured", "essay"])
        if ("do not include" in normalized_instructions or "without" in normalized_instructions) and (
            "multiple choice" in normalized_instructions or "mcq" in normalized_instructions
        ):
            q_types = [q for q in q_types if q.lower() != "mcq"]
        if ("do not include" in normalized_instructions or "without" in normalized_instructions) and (
            "essay" in normalized_instructions
        ):
            q_types = [q for q in q_types if q.lower() != "essay"]
        if not q_types:
            q_types = ["structured"]
        return f"""Based STRICTLY on the coursework material, generate an exam paper.
{f'Focus on topic: {request.topic}' if request.topic else ''}
Difficulty: {request.difficulty}
Total marks: {total_marks}
Question types: {", ".join(q_types)}
{f'Additional instructions: {instruction_text}' if instruction_text else ''}
Coursework Material:
{context}
Provide JSON:
{{
  "school_name":"...",
  "exam_title":"...",
  "subject":"...",
  "class_level":"...",
  "total_marks":{total_marks},
  "time_allowed":"...",
  "instructions":["..."],
  "sections":[
    {{
      "section_name":"...",
      "questions":[
        {{
          "question_number":"1",
          "question_text":"...",
          "marks":10,
          "type":"mcq|structured|essay",
          "options":["A","B","C","D"],
          "sub_questions":["..."],
          "mark_scheme":"..."
        }}
      ]
    }}
  ]
}}
Rules:
- Ensure total marks equals {total_marks}.
- Follow additional instructions exactly.
{strict_json_clause}"""

    raise HTTPException(status_code=400, detail="Invalid generation type")


def _extract_exam_constraints(additional_instructions: Optional[str]) -> Dict[str, Any]:
    text = (additional_instructions or "").strip()
    lowered = text.lower()
    title: Optional[str] = None
    school_name: Optional[str] = None
    title_match = re.search(
        r"(?:title(?:\s+the\s+document)?(?:\s+as)?|exam\s+title(?:\s+as)?)\s*[:\-]?\s*(.+)",
        text,
        flags=re.IGNORECASE,
    )
    if title_match:
        title = title_match.group(1).strip().strip("\"'").strip()
        if "." in title:
            title = title.split(".", 1)[0].strip()

    school_quoted_match = re.search(
        r"(?:school\s+name|institution(?:\s+name)?)\s*(?:as|is|=|:)?\s*[\"']([^\"']+)[\"']",
        text,
        flags=re.IGNORECASE,
    )
    if school_quoted_match:
        school_name = school_quoted_match.group(1).strip()
    else:
        school_line_match = re.search(
            r"(?:school\s+name|institution(?:\s+name)?)\s*(?:as|is|=|:)\s*([^\n\.,;]+)",
            text,
            flags=re.IGNORECASE,
        )
        if school_line_match:
            school_name = school_line_match.group(1).strip().strip("\"'")

    disallow_mcq = bool(
        re.search(r"(do\s+not\s+include|without|exclude)[^.\n]*(mcq|multiple\s+choice)", lowered)
    )
    disallow_essay = bool(re.search(r"(do\s+not\s+include|without|exclude)[^.\n]*essay", lowered))
    single_section = bool(re.search(r"\b(one|single)\s+section\b", lowered))
    question_marks_only = bool(
        re.search(r"(question\s+and\s*\(?marks\)?\s+only|only\s+have\s+question\s+and\s*\(?marks\)?)", lowered)
    )
    return {
        "title": title,
        "school_name": school_name,
        "disallow_mcq": disallow_mcq,
        "disallow_essay": disallow_essay,
        "single_section": single_section,
        "question_marks_only": question_marks_only,
    }


def apply_exam_constraints(
    content: Dict[str, Any],
    additional_instructions: Optional[str],
) -> Dict[str, Any]:
    constraints = _extract_exam_constraints(additional_instructions)
    if not any(constraints.values()):
        return content

    updated = dict(content)
    if constraints.get("school_name"):
        updated["school_name"] = constraints["school_name"]
    if constraints["title"]:
        updated["exam_title"] = constraints["title"]
    instructions = updated.get("instructions")
    instruction_lines: List[str] = []
    if isinstance(instructions, list):
        instruction_lines = [str(item).strip() for item in instructions if str(item).strip()]
    elif isinstance(instructions, str) and instructions.strip():
        instruction_lines = [instructions.strip()]

    if constraints["title"]:
        title_line = constraints["title"].strip()
        if not instruction_lines or instruction_lines[0].lower() != title_line.lower():
            instruction_lines.insert(0, title_line)

    if instruction_lines:
        # Keep title as the first line, indent the remaining instruction items.
        styled_lines: List[str] = [instruction_lines[0]]
        for line in instruction_lines[1:]:
            styled_lines.append(f"   {line.lstrip()}")
        updated["instructions"] = styled_lines

    sections = updated.get("sections")
    if not isinstance(sections, list):
        return updated

    if constraints["single_section"] and sections:
        sections = sections[:1]

    normalized_sections: List[Dict[str, Any]] = []
    for section in sections:
        if not isinstance(section, dict):
            continue
        section_copy = dict(section)
        questions = section_copy.get("questions", [])
        normalized_questions: List[Dict[str, Any]] = []
        for question in questions if isinstance(questions, list) else []:
            if not isinstance(question, dict):
                continue
            q = dict(question)
            q_type = str(q.get("type", "")).lower()
            if (constraints["disallow_mcq"] and q_type == "mcq") or (
                constraints["disallow_essay"] and q_type == "essay"
            ):
                q["type"] = "structured"

            if constraints["disallow_mcq"] or constraints["question_marks_only"]:
                q.pop("options", None)
            if constraints["question_marks_only"]:
                q["type"] = "structured"
                q.pop("sub_questions", None)
                if not q.get("mark_scheme"):
                    q["mark_scheme"] = "Award marks for correct and relevant points."

            normalized_questions.append(q)
        section_copy["questions"] = normalized_questions
        normalized_sections.append(section_copy)

    updated["sections"] = normalized_sections
    return updated


async def run_generation_pipeline(
    user_id: str,
    request: GenerationRequest,
    generation_id: Optional[str] = None,
) -> GenerationResponse:
    if not request.document_ids:
        raise HTTPException(status_code=400, detail="At least one document must be selected")

    docs = await db.documents.find(
        {"id": {"$in": request.document_ids}, "user_id": user_id},
        {"_id": 0},
    ).to_list(100)
    if len(docs) != len(request.document_ids):
        raise HTTPException(status_code=403, detail="Some documents not found or access denied")

    retrieval_query = f"{request.generation_type} {request.topic or ''}".strip()
    relevant_chunks = await retrieve_relevant_chunks(
        user_id,
        request.document_ids,
        retrieval_query,
        top_k=RETRIEVAL_TOP_K,
    )
    logger.info(
        "generation_retrieval_success user_id=%s type=%s chunks=%s",
        user_id,
        request.generation_type,
        len(relevant_chunks),
    )
    context = assemble_context_with_budget(relevant_chunks, MAX_CONTEXT_TOKENS)
    prompt = build_prompt(request, context)
    system_msg = (
        "You are an expert academic assistant. "
        "Always use the provided coursework material only."
    )
    generated_text = await generate_with_llm(prompt, system_msg, generation_type=request.generation_type)
    logger.info(
        "generation_llm_success user_id=%s type=%s chars=%s",
        user_id,
        request.generation_type,
        len(generated_text or ""),
    )

    try:
        raw_content = coerce_generation_payload(
            request,
            parse_llm_json_output(generated_text),
        )
    except Exception as e:
        logger.warning(
            "generation_json_parse_failed user_id=%s type=%s error=%s; attempting llm json repair",
            user_id,
            request.generation_type,
            e,
        )
        try:
            raw_content = coerce_generation_payload(
                request,
                await repair_json_with_llm(generated_text, request.generation_type),
            )
            logger.info(
                "generation_json_repair_success user_id=%s type=%s",
                user_id,
                request.generation_type,
            )
        except Exception as repair_exc:
            preview = (generated_text or "").strip().replace("\n", " ")[:180]
            raise HTTPException(
                status_code=502,
                detail=(
                    f"LLM returned non-JSON output: {str(e)} | "
                    f"repair_failed={str(repair_exc)} | preview='{preview}'"
                ),
            )

    if request.generation_type == "exam":
        raw_content = apply_exam_constraints(raw_content, request.additional_instructions)
    content = validate_structured_output(request.generation_type, raw_content)
    logger.info(
        "generation_validation_success user_id=%s type=%s",
        user_id,
        request.generation_type,
    )

    generation = GenerationResponse(
        id=generation_id or str(uuid.uuid4()),
        user_id=user_id,
        generation_type=request.generation_type,
        content=content,
    )
    gen_dict = generation.model_dump()
    gen_dict["created_at"] = gen_dict["created_at"].isoformat()

    existing = await db.generations.find_one({"id": generation.id}, {"_id": 0, "id": 1})
    if not existing:
        try:
            await db.generations.insert_one(gen_dict)
        except Exception as exc:
            logger.error(
                "generation_save_failed user_id=%s generation_id=%s type=%s error=%s",
                user_id,
                generation.id,
                request.generation_type,
                exc,
            )
            raise HTTPException(status_code=500, detail="Generated content could not be saved")

    logger.info(
        "generation_save_success user_id=%s generation_id=%s type=%s",
        user_id,
        generation.id,
        request.generation_type,
    )
    return generation


@api_router.post("/generate", response_model=GenerationJobEnqueueResponse)
async def queue_generation_content(
    request: GenerationRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    logger.info(
        "generation_job_request_start user_id=%s type=%s docs=%s",
        current_user["id"],
        request.generation_type,
        len(request.document_ids or []),
    )
    await ensure_rate_limit(current_user["id"], "generate_user", GEN_PER_MIN_LIMIT)
    await consume_generation_quota(current_user["id"], request.generation_type)

    if not request.document_ids:
        raise HTTPException(status_code=400, detail="At least one document must be selected")

    docs = await db.documents.find(
        {"id": {"$in": request.document_ids}, "user_id": current_user["id"]},
        {"_id": 0, "id": 1},
    ).to_list(100)
    if len(docs) != len(request.document_ids):
        raise HTTPException(status_code=403, detail="Some documents not found or access denied")

    job_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    job_doc = {
        "job_id": job_id,
        "user_id": current_user["id"],
        "type": request.generation_type,
        "status": "queued",
        "progress": 0,
        "created_at": now_iso,
        "completed_at": None,
        "result_reference": job_id,
        "error": None,
        "attempt": 0,
        "request": request.model_dump(),
    }
    await db.generation_jobs.insert_one(job_doc)

    try:
        from tasks.exam_generation import process_generation_job

        process_generation_job.delay(job_id)
    except Exception as exc:
        logger.error("generation_job_enqueue_failed user_id=%s job_id=%s error=%s", current_user["id"], job_id, exc)
        await db.generation_jobs.update_one(
            {"job_id": job_id},
            {
                "$set": {
                    "status": "failed",
                    "error": f"Queue enqueue failed: {str(exc)}",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                }
            },
        )
        raise HTTPException(status_code=503, detail="Generation queue is unavailable")

    return GenerationJobEnqueueResponse(
        job_id=job_id,
        status="queued",
        estimated_time=f"{GENERATION_JOB_ESTIMATE_MINUTES} minutes",
    )


@api_router.get("/v1/jobs/{job_id}", response_model=JobStatusResponse)
async def get_generation_job_status(
    job_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    await ensure_rate_limit(current_user["id"], "jobs_status_user", JOB_STATUS_PER_MIN_LIMIT)
    job_doc = await db.generation_jobs.find_one(
        {"job_id": job_id, "user_id": current_user["id"]},
        {"_id": 0},
    )
    if not job_doc:
        raise HTTPException(status_code=404, detail="Job not found")
    return build_job_status_response(job_doc)


@api_router.get("/v1/jobs", response_model=List[JobStatusResponse])
async def list_generation_jobs(
    limit: int = 50,
    status: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    await ensure_rate_limit(current_user["id"], "jobs_status_user", JOB_STATUS_PER_MIN_LIMIT)
    safe_limit = max(1, min(limit, 200))
    query: Dict[str, Any] = {"user_id": current_user["id"]}
    if status:
        normalized = status.strip().lower()
        if normalized not in {"queued", "processing", "retrying", "completed", "failed"}:
            raise HTTPException(status_code=400, detail="Invalid status filter")
        query["status"] = normalized
    docs = await db.generation_jobs.find(query, {"_id": 0}).sort("created_at", -1).to_list(safe_limit)
    return [build_job_status_response(doc) for doc in docs]


@api_router.get("/v1/jobs/", response_model=List[JobStatusResponse], include_in_schema=False)
async def list_generation_jobs_trailing_slash(
    limit: int = 50,
    status: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    return await list_generation_jobs(limit=limit, status=status, current_user=current_user)


@api_router.get("/generations", response_model=List[GenerationResponse])
async def list_generations(
    limit: int = 50,
    compact: bool = False,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    safe_limit = max(1, min(limit, 200))
    projection: Dict[str, int] = {"_id": 0}
    if compact:
        projection["content"] = 0
    gens = await db.generations.find({"user_id": current_user["id"]}, projection).sort("created_at", -1).to_list(safe_limit)
    normalized: List[GenerationResponse] = []
    for gen in gens:
        norm = normalize_datetime_fields(gen, ["created_at"])
        if compact and "content" not in norm:
            norm["content"] = {}
        normalized.append(GenerationResponse(**norm))
    return normalized


@api_router.get("/generations/{generation_id}", response_model=GenerationResponse)
async def get_generation(generation_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    gen = await db.generations.find_one({"id": generation_id, "user_id": current_user["id"]}, {"_id": 0})
    if not gen:
        raise HTTPException(status_code=404, detail="Generation not found")
    return GenerationResponse(**normalize_datetime_fields(gen, ["created_at"]))


@api_router.delete("/generations/{generation_id}")
async def delete_generation(generation_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    generation = await db.generations.find_one(
        {"id": generation_id, "user_id": current_user["id"]},
        {"_id": 0},
    )
    if not generation:
        raise HTTPException(status_code=404, detail="Generation not found")

    await db.generations.delete_one({"id": generation_id})
    await increment_usage_counter(current_user["id"], "generations_deleted_total", 1)
    return {"message": "Generation deleted successfully"}


@api_router.post("/v1/classes", response_model=ClassSessionResponse)
async def create_class_session(
    payload: ClassCreateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    if current_user.get("role", "").lower() != "teacher":
        raise HTTPException(status_code=403, detail="Only teachers can create classes")
    await ensure_rate_limit(current_user["id"], "class_create_user", CLASS_CREATE_PER_MIN_LIMIT)
    await ensure_topic_access(current_user["id"])

    title = (payload.title or "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="Class title is required")
    if len(title) > 180:
        raise HTTPException(status_code=400, detail="Class title must be 180 characters or fewer")
    description = (payload.description or "").strip()
    if len(description) > 2400:
        raise HTTPException(status_code=400, detail="Description must be 2400 characters or fewer")
    meeting_link = normalize_meeting_link(payload.meeting_link)
    start_at = payload.scheduled_start_at
    end_at = payload.scheduled_end_at
    now = datetime.now(timezone.utc)
    if start_at.tzinfo is None:
        start_at = start_at.replace(tzinfo=timezone.utc)
    if end_at.tzinfo is None:
        end_at = end_at.replace(tzinfo=timezone.utc)
    if start_at <= now:
        raise HTTPException(status_code=400, detail="Class start time must be in the future")
    if end_at <= start_at:
        raise HTTPException(status_code=400, detail="Class end time must be after start time")
    fee_kes = int(payload.fee_kes)
    class_min_fee_kes, class_max_fee_kes = current_class_fee_bounds()
    if fee_kes > 0 and fee_kes < class_min_fee_kes:
        raise HTTPException(
            status_code=400,
            detail=f"Class fee must be at least KES {class_min_fee_kes} when charging students",
        )
    if fee_kes > class_max_fee_kes:
        raise HTTPException(
            status_code=400,
            detail=f"Class fee must not exceed KES {class_max_fee_kes}",
        )
    duration_minutes = max(int((end_at - start_at).total_seconds() // 60), 1)

    class_doc = {
        "id": str(uuid.uuid4()),
        "teacher_id": current_user["id"],
        "teacher_name": current_user.get("full_name", "Teacher"),
        "title": title,
        "description": description or None,
        "meeting_link": meeting_link,
        "scheduled_start_at": start_at.isoformat(),
        "scheduled_end_at": end_at.isoformat(),
        "duration_minutes": duration_minutes,
        "fee_kes": fee_kes,
        "currency": "KES",
        "status": "scheduled",
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "join_count": 0,
    }
    await db.class_sessions.insert_one(class_doc)

    # Alert all students immediately for scheduled class visibility.
    student_cursor = db.users.find({"role": "student"}, {"_id": 0, "id": 1})
    students = await student_cursor.to_list(5000)
    if students:
        notification_docs = [
            {
                "id": str(uuid.uuid4()),
                "user_id": student["id"],
                "status": "class_scheduled",
                "message": (
                    f"New class: {title} by {class_doc['teacher_name']} "
                    f"at {start_at.strftime('%Y-%m-%d %H:%M UTC')}"
                ),
                "class_id": class_doc["id"],
                "meeting_link": meeting_link,
                "read": False,
                "created_at": now.isoformat(),
            }
            for student in students
        ]
        await db.notifications.insert_many(notification_docs)
        try:
            from tasks.notifications import send_class_scheduled_push

            send_class_scheduled_push.delay(
                user_ids=[student["id"] for student in students if student.get("id")],
                class_id=class_doc["id"],
                title=title,
                teacher_name=class_doc["teacher_name"],
                meeting_link=meeting_link,
                scheduled_start_at=class_doc["scheduled_start_at"],
            )
        except Exception as exc:
            logger.warning("class_push_enqueue_failed class_id=%s error=%s", class_doc["id"], exc)
        await db.class_sessions.update_one(
            {"id": class_doc["id"]},
            {"$set": {"alert_sent_at": now.isoformat()}},
        )

    return await build_class_response(class_doc, current_user["id"], "teacher")


@api_router.get("/v1/classes", response_model=List[ClassSessionResponse])
async def list_class_sessions(
    status: str = "upcoming",
    limit: int = 50,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    await ensure_rate_limit(current_user["id"], "class_read_user", JOB_STATUS_PER_MIN_LIMIT)
    await ensure_topic_access(current_user["id"])
    role = current_user.get("role", "").lower()
    now_iso = datetime.now(timezone.utc).isoformat()
    query: Dict[str, Any] = {}
    if role == "teacher":
        query["teacher_id"] = current_user["id"]
    elif role == "student":
        query["status"] = {"$in": ["scheduled", "live", "completed"]}
    else:
        raise HTTPException(status_code=403, detail="Unsupported role")

    normalized_status = (status or "upcoming").strip().lower()
    if normalized_status == "upcoming":
        query["scheduled_end_at"] = {"$gte": now_iso}
        query["status"] = {"$in": ["scheduled", "live"]}
    elif normalized_status == "past":
        query["scheduled_end_at"] = {"$lt": now_iso}
    elif normalized_status != "all":
        raise HTTPException(status_code=400, detail="Invalid status filter")

    safe_limit = max(1, min(limit, 200))
    docs = await db.class_sessions.find(query, {"_id": 0}).sort("scheduled_start_at", 1).to_list(safe_limit)
    return [await build_class_response(doc, current_user["id"], role) for doc in docs]


@api_router.get("/v1/classes/", response_model=List[ClassSessionResponse], include_in_schema=False)
async def list_class_sessions_trailing_slash(
    status: str = "upcoming",
    limit: int = 50,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    return await list_class_sessions(status=status, limit=limit, current_user=current_user)


@api_router.get("/v1/classes/{class_id}", response_model=ClassSessionResponse)
async def get_class_session(
    class_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    await ensure_rate_limit(current_user["id"], "class_read_user", JOB_STATUS_PER_MIN_LIMIT)
    await ensure_topic_access(current_user["id"])
    class_doc = await db.class_sessions.find_one({"id": class_id}, {"_id": 0})
    if not class_doc:
        raise HTTPException(status_code=404, detail="Class not found")
    role = current_user.get("role", "").lower()
    if role == "teacher" and class_doc.get("teacher_id") != current_user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    return await build_class_response(class_doc, current_user["id"], role)


@api_router.post("/v1/classes/{class_id}/join")
async def join_class_session(
    class_id: str,
    payload: Optional[ClassJoinRequest] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    if current_user.get("role", "").lower() != "student":
        raise HTTPException(status_code=403, detail="Only students can join classes")
    await ensure_rate_limit(current_user["id"], "class_join_user", CLASS_JOIN_PER_MIN_LIMIT)
    await ensure_topic_access(current_user["id"])

    class_doc = await db.class_sessions.find_one({"id": class_id}, {"_id": 0})
    if not class_doc:
        raise HTTPException(status_code=404, detail="Class not found")
    if class_doc.get("status") in {"cancelled"}:
        raise HTTPException(status_code=409, detail="Class is cancelled")
    now_iso = datetime.now(timezone.utc).isoformat()
    if class_doc.get("scheduled_end_at", "") < now_iso:
        raise HTTPException(status_code=409, detail="Class has already ended")

    existing_enrollment = await db.class_enrollments.find_one(
        {"class_id": class_id, "student_id": current_user["id"]},
        {"_id": 0, "id": 1, "payment_status": 1},
    )
    if existing_enrollment and existing_enrollment.get("payment_status") in {"paid", "free"}:
        return {
            "message": "Class join recorded",
            "class_id": class_id,
            "meeting_link": class_doc["meeting_link"],
            "scheduled_start_at": class_doc["scheduled_start_at"],
            "requires_payment": False,
            "payment_status": existing_enrollment.get("payment_status", "paid"),
        }

    fee_kes = int(class_doc.get("fee_kes", 0))
    now_iso = datetime.now(timezone.utc).isoformat()
    if fee_kes <= 0:
        enrollment = {
            "id": str(uuid.uuid4()),
            "class_id": class_id,
            "student_id": current_user["id"],
            "joined_at": now_iso,
            "payment_status": "free",
        }
        join_result = await db.class_enrollments.update_one(
            {"class_id": class_id, "student_id": current_user["id"]},
            {"$setOnInsert": enrollment},
            upsert=True,
        )
        if join_result.upserted_id is not None:
            await db.class_sessions.update_one({"id": class_id}, {"$inc": {"join_count": 1}})
        return {
            "message": "Class join recorded",
            "class_id": class_id,
            "meeting_link": class_doc["meeting_link"],
            "scheduled_start_at": class_doc["scheduled_start_at"],
            "requires_payment": False,
            "payment_status": "free",
        }

    if not mpesa_service.enabled:
        raise HTTPException(status_code=500, detail="M-Pesa is not configured for class payments")

    phone_number = ((payload.phone_number if payload else None) or "").strip()
    if not phone_number:
        raise HTTPException(status_code=400, detail="Phone number is required for paid classes")

    account_reference = f"CLS{class_id[-6:].upper()}"
    transaction_desc = f"Class {class_doc.get('title', 'Session')}"
    stk_result = await mpesa_service.stk_push(
        phone_number=phone_number,
        amount=fee_kes,
        account_reference=account_reference,
        transaction_desc=transaction_desc,
    )
    if not stk_result.get("success"):
        raise HTTPException(
            status_code=502,
            detail=f"STK push failed: {stk_result.get('error', 'Unknown error')}",
        )

    payment_doc = {
        "id": str(uuid.uuid4()),
        "payment_type": "class_join",
        "class_id": class_id,
        "student_id": current_user["id"],
        "teacher_id": class_doc["teacher_id"],
        "amount_kes": fee_kes,
        "platform_fee_percent": current_class_escrow_platform_fee_percent(),
        "phone_number": mpesa_service.normalize_phone(phone_number),
        "status": "pending",
        "merchant_request_id": stk_result.get("merchant_request_id"),
        "checkout_request_id": stk_result.get("checkout_request_id"),
        "response_code": stk_result.get("response_code"),
        "response_description": stk_result.get("response_description"),
        "created_at": now_iso,
        "updated_at": now_iso,
    }
    await db.class_payments.insert_one(payment_doc)
    return {
        "message": "STK push sent to customer phone",
        "class_id": class_id,
        "requires_payment": True,
        "payment_status": "pending",
        "checkout_request_id": payment_doc["checkout_request_id"],
        "amount_kes": fee_kes,
    }


@api_router.post("/v1/classes/{class_id}/complete", response_model=ClassSessionResponse)
async def complete_class_session(
    class_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    if current_user.get("role", "").lower() != "teacher":
        raise HTTPException(status_code=403, detail="Only teachers can complete classes")
    await ensure_rate_limit(current_user["id"], "class_create_user", CLASS_CREATE_PER_MIN_LIMIT)
    await ensure_topic_access(current_user["id"])
    class_doc = await db.class_sessions.find_one({"id": class_id}, {"_id": 0})
    if not class_doc:
        raise HTTPException(status_code=404, detail="Class not found")
    if class_doc.get("teacher_id") != current_user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    updated = await db.class_sessions.find_one_and_update(
        {"id": class_id},
        {"$set": {"status": "completed", "updated_at": datetime.now(timezone.utc).isoformat()}},
        return_document=ReturnDocument.AFTER,
        projection={"_id": 0},
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Class not found")

    held_escrows = await db.class_escrow.find(
        {"class_id": class_id, "status": "held"},
        {"_id": 0},
    ).to_list(5000)
    if held_escrows:
        now_iso = datetime.now(timezone.utc).isoformat()
        teacher_release = 0
        platform_release = 0
        for escrow in held_escrows:
            teacher_release += int(escrow.get("teacher_net_kes", 0))
            platform_release += int(escrow.get("platform_fee_kes", 0))
            await db.class_escrow.update_one(
                {"id": escrow["id"], "status": "held"},
                {"$set": {"status": "released", "released_at": now_iso}},
            )
        await db.teacher_escrow_wallets.update_one(
            {"teacher_id": current_user["id"]},
            {
                "$inc": {
                    "withdrawable_balance_kes": teacher_release,
                    "total_released_kes": teacher_release,
                },
                "$set": {"updated_at": now_iso},
                "$setOnInsert": {
                    "teacher_id": current_user["id"],
                    "created_at": now_iso,
                    "total_withdrawn_kes": 0,
                },
            },
            upsert=True,
        )
        await db.platform_escrow_wallet.update_one(
            {"wallet_id": "platform_escrow"},
            {
                "$inc": {
                    "balance_kes": platform_release,
                    "total_earned_kes": platform_release,
                },
                "$set": {"updated_at": now_iso},
                "$setOnInsert": {
                    "wallet_id": "platform_escrow",
                    "created_at": now_iso,
                    "total_withdrawn_kes": 0,
                },
            },
            upsert=True,
        )
        await db.class_sessions.update_one(
            {"id": class_id},
            {"$set": {"escrow_released_at": now_iso}},
        )
    return await build_class_response(updated, current_user["id"], "teacher")


@api_router.get("/v1/classes/{class_id}/payment/{checkout_request_id}")
async def class_payment_status(
    class_id: str,
    checkout_request_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    if current_user.get("role", "").lower() != "student":
        raise HTTPException(status_code=403, detail="Only students can check class payment status")
    await ensure_rate_limit(current_user["id"], "class_read_user", JOB_STATUS_PER_MIN_LIMIT)
    payment = await db.class_payments.find_one(
        {
            "class_id": class_id,
            "checkout_request_id": checkout_request_id,
            "student_id": current_user["id"],
        },
        {"_id": 0},
    )
    if not payment:
        raise HTTPException(status_code=404, detail="Class payment not found")
    return payment


@api_router.get("/v1/classes/earnings/me")
async def teacher_class_earnings(current_user: Dict[str, Any] = Depends(get_current_user)):
    if current_user.get("role", "").lower() != "teacher":
        raise HTTPException(status_code=403, detail="Only teachers can access class earnings")
    await ensure_rate_limit(current_user["id"], "class_read_user", JOB_STATUS_PER_MIN_LIMIT)
    wallet = await db.teacher_escrow_wallets.find_one(
        {"teacher_id": current_user["id"]},
        {"_id": 0},
    )
    if not wallet:
        return {
            "teacher_id": current_user["id"],
            "withdrawable_balance_kes": 0,
            "total_released_kes": 0,
            "total_withdrawn_kes": 0,
        }
    return wallet


@api_router.get("/v1/private-tutors", response_model=List[PrivateTutorProfileResponse])
async def list_private_tutors(
    limit: int = 20,
    city: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    await ensure_rate_limit(current_user["id"], "class_read_user", JOB_STATUS_PER_MIN_LIMIT)
    safe_limit = max(1, min(limit, 60))
    tutors = await fetch_localpro_tutors(limit=safe_limit, city=city)
    if not tutors:
        raise HTTPException(
            status_code=503,
            detail="Private tutor directory is unavailable right now. Try again shortly.",
        )
    return tutors


@api_router.get("/v1/private-tutors/", response_model=List[PrivateTutorProfileResponse], include_in_schema=False)
async def list_private_tutors_trailing_slash(
    limit: int = 20,
    city: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    return await list_private_tutors(limit=limit, city=city, current_user=current_user)


@api_router.get(
    "/v1/private-tutors/{tutor_id}/booking-intent",
    response_model=PrivateTutorBookingIntentResponse,
)
async def private_tutor_booking_intent(
    tutor_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    await ensure_rate_limit(current_user["id"], "class_read_user", JOB_STATUS_PER_MIN_LIMIT)
    tutor_id = (tutor_id or "").strip()
    if not tutor_id:
        raise HTTPException(status_code=400, detail="Tutor ID is required")
    deep_link = f"{LOCALPRO_APP_SCHEME}://service/{tutor_id}"
    web_url = f"{LOCALPRO_BASE_URL}/service/{tutor_id}" if LOCALPRO_BASE_URL else None
    return PrivateTutorBookingIntentResponse(
        tutor_id=tutor_id,
        deep_link=deep_link,
        playstore_url=LOCALPRO_PLAYSTORE_URL,
        package_name=LOCALPRO_APP_PACKAGE,
        web_url=web_url,
    )


@api_router.post("/v1/classes/withdrawals")
async def teacher_request_withdrawal(
    payload: ClassWithdrawalRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    if current_user.get("role", "").lower() != "teacher":
        raise HTTPException(status_code=403, detail="Only teachers can withdraw class earnings")
    await ensure_rate_limit(current_user["id"], "class_withdraw_user", CLASS_WITHDRAW_PER_MIN_LIMIT)

    amount_kes = int(payload.amount_kes)
    wallet = await db.teacher_escrow_wallets.find_one({"teacher_id": current_user["id"]}, {"_id": 0})
    current_balance = int((wallet or {}).get("withdrawable_balance_kes", 0))
    if amount_kes > current_balance:
        raise HTTPException(
            status_code=400,
            detail=f"Insufficient withdrawable balance. Available: KES {current_balance}",
        )
    now_iso = datetime.now(timezone.utc).isoformat()
    withdrawal_doc = {
        "id": str(uuid.uuid4()),
        "teacher_id": current_user["id"],
        "amount_kes": amount_kes,
        "phone_number": (payload.phone_number or "").strip() or None,
        "note": (payload.note or "").strip() or None,
        "status": "requested",
        "created_at": now_iso,
        "updated_at": now_iso,
    }
    await db.class_withdrawals.insert_one(withdrawal_doc)
    await db.teacher_escrow_wallets.update_one(
        {"teacher_id": current_user["id"]},
        {
            "$inc": {
                "withdrawable_balance_kes": -amount_kes,
                "total_withdrawn_kes": amount_kes,
            },
            "$set": {"updated_at": now_iso},
            "$setOnInsert": {"teacher_id": current_user["id"], "created_at": now_iso},
        },
        upsert=True,
    )
    return {
        "message": "Withdrawal request submitted",
        "withdrawal_id": withdrawal_doc["id"],
        "status": withdrawal_doc["status"],
    }


@api_router.get("/v1/admin/dashboard-summary", response_model=AdminDashboardSummaryResponse)
async def admin_dashboard_summary(
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    ensure_admin_user(current_user)
    await ensure_rate_limit(current_user["id"], "admin_read_user", ADMIN_READ_PER_MIN_LIMIT)

    platform_wallet = await db.platform_escrow_wallet.find_one(
        {"wallet_id": "platform_escrow"},
        {"_id": 0},
    )
    role_counts = await db.users.aggregate(
        [
            {"$group": {"_id": "$role", "count": {"$sum": 1}}},
        ]
    ).to_list(20)
    counts: Dict[str, int] = {}
    total_users = 0
    for row in role_counts:
        role = str(row.get("_id", "")).strip().lower()
        count = int(row.get("count", 0))
        counts[role] = count
        total_users += count

    return AdminDashboardSummaryResponse(
        platform_wallet_balance_kes=int((platform_wallet or {}).get("balance_kes", 0)),
        platform_wallet_total_earned_kes=int((platform_wallet or {}).get("total_earned_kes", 0)),
        platform_wallet_total_withdrawn_kes=int((platform_wallet or {}).get("total_withdrawn_kes", 0)),
        students_count=int(counts.get("student", 0)),
        teachers_count=int(counts.get("teacher", 0)),
        admins_count=int(counts.get("admin", 0)),
        users_total=int(total_users),
    )


@api_router.get("/v1/admin/runtime-settings")
async def admin_runtime_settings(
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    ensure_admin_user(current_user)
    await ensure_rate_limit(current_user["id"], "admin_read_user", ADMIN_READ_PER_MIN_LIMIT)
    return {
        **current_runtime_settings(),
        "subscription_plans": [plan.model_dump() for plan in get_subscription_plans()],
    }


@api_router.put("/v1/admin/runtime-settings")
async def admin_update_runtime_settings(
    payload: AdminRuntimeSettingsUpdateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    ensure_admin_user(current_user)
    await ensure_rate_limit(current_user["id"], "admin_withdraw_user", ADMIN_WITHDRAW_PER_MIN_LIMIT)
    updates = payload.model_dump(exclude_none=True)
    updates = {k: v for k, v in updates.items() if k in ADMIN_RUNTIME_EDITABLE_SETTINGS}
    if not updates:
        raise HTTPException(status_code=400, detail="No runtime settings to update")

    merged = current_runtime_settings()
    merged.update(updates)
    min_fee = int(merged.get("class_min_fee_kes", 0))
    max_fee = int(merged.get("class_max_fee_kes", 0))
    if max_fee < min_fee:
        raise HTTPException(status_code=400, detail="class_max_fee_kes must be >= class_min_fee_kes")

    now_iso = datetime.now(timezone.utc).isoformat()
    await db.runtime_settings.update_one(
        {"id": RUNTIME_SETTINGS_DOC_ID},
        {
            "$set": {
                **updates,
                "updated_at": now_iso,
                "updated_by": current_user["id"],
                "id": RUNTIME_SETTINGS_DOC_ID,
            }
        },
        upsert=True,
    )
    await load_runtime_settings_cache()
    return {
        "message": "Runtime settings updated",
        "settings": current_runtime_settings(),
        "subscription_plans": [plan.model_dump() for plan in get_subscription_plans()],
    }


@api_router.post("/v1/admin/platform-withdrawals")
async def admin_request_platform_withdrawal(
    payload: AdminPlatformWithdrawalRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    ensure_admin_user(current_user)
    await ensure_rate_limit(current_user["id"], "admin_withdraw_user", ADMIN_WITHDRAW_PER_MIN_LIMIT)
    amount_kes = int(payload.amount_kes)
    if amount_kes < PLATFORM_WITHDRAWAL_MIN_KES:
        raise HTTPException(
            status_code=400,
            detail=f"Minimum platform withdrawal is KES {PLATFORM_WITHDRAWAL_MIN_KES}",
        )

    wallet = await db.platform_escrow_wallet.find_one({"wallet_id": "platform_escrow"}, {"_id": 0})
    balance = int((wallet or {}).get("balance_kes", 0))
    if amount_kes > balance:
        raise HTTPException(
            status_code=400,
            detail=f"Insufficient platform wallet balance. Available: KES {balance}",
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    withdrawal_doc = {
        "id": str(uuid.uuid4()),
        "wallet_id": "platform_escrow",
        "requested_by": current_user["id"],
        "amount_kes": amount_kes,
        "phone_number": (payload.phone_number or "").strip() or None,
        "note": (payload.note or "").strip() or None,
        "status": "requested",
        "created_at": now_iso,
        "updated_at": now_iso,
    }
    await db.platform_withdrawals.insert_one(withdrawal_doc)
    await db.platform_escrow_wallet.update_one(
        {"wallet_id": "platform_escrow"},
        {
            "$inc": {
                "balance_kes": -amount_kes,
                "total_withdrawn_kes": amount_kes,
            },
            "$set": {"updated_at": now_iso},
            "$setOnInsert": {
                "wallet_id": "platform_escrow",
                "created_at": now_iso,
                "total_earned_kes": 0,
            },
        },
        upsert=True,
    )
    return {
        "message": "Platform withdrawal request submitted",
        "withdrawal_id": withdrawal_doc["id"],
        "status": withdrawal_doc["status"],
    }


@api_router.post(
    "/v1/admin/retention-insights/campaigns",
    response_model=AdminRetentionInsightCampaignResponse,
)
async def admin_create_retention_campaign(
    payload: AdminRetentionInsightCampaignCreateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    ensure_admin_user(current_user)
    await ensure_rate_limit(current_user["id"], "admin_read_user", ADMIN_READ_PER_MIN_LIMIT)
    if not RETENTION_INSIGHTS_ENABLED:
        raise HTTPException(status_code=400, detail="Retention insights emails are disabled")
    if not BREVO_API_KEY2:
        raise HTTPException(status_code=400, detail="BREVO_API_KEY2 is not configured")
    if not BREVO_SENDER_EMAIL:
        raise HTTPException(status_code=400, detail="BREVO_SENDER_EMAIL is required for retention insights")

    audience_roles = normalize_retention_audience_roles(payload.audience_roles)
    filter_query: Dict[str, Any] = {
        "email": {"$exists": True, "$ne": ""},
        "role": {"$in": audience_roles},
    }
    if not payload.force_resend:
        cooldown_cutoff = (
            datetime.now(timezone.utc) - timedelta(days=RETENTION_EMAIL_MIN_DAYS_BETWEEN_SENDS)
        ).isoformat()
        cooled_user_ids = await db.retention_email_recipients.distinct(
            "user_id",
            {"last_sent_at": {"$gte": cooldown_cutoff}},
        )
        if cooled_user_ids:
            filter_query["id"] = {"$nin": list(cooled_user_ids)}

    users = await db.users.find(
        filter_query,
        {"_id": 0, "id": 1, "email": 1, "full_name": 1, "role": 1},
    ).sort("created_at", 1).to_list(None)
    if not users:
        raise HTTPException(status_code=400, detail="No eligible users found for retention campaign")

    now_iso = datetime.now(timezone.utc).isoformat()
    campaign_id = f"retention_{uuid.uuid4()}"
    campaign_doc = {
        "id": campaign_id,
        "created_by": current_user["id"],
        "status": "queued",
        "audience_roles": audience_roles,
        "daily_limit": RETENTION_EMAIL_DAILY_LIMIT,
        "batch_size": RETENTION_EMAIL_BATCH_SIZE,
        "total_targets": len(users),
        "pending_count": len(users),
        "sent_count": 0,
        "failed_count": 0,
        "skipped_count": 0,
        "created_at": now_iso,
        "updated_at": now_iso,
        "next_run_at": now_iso,
        "error": None,
    }
    await db.retention_email_campaigns.insert_one(campaign_doc)

    target_docs = [
        {
            "id": f"retention_target_{uuid.uuid4()}",
            "campaign_id": campaign_id,
            "user_id": row["id"],
            "email": row["email"],
            "full_name": row.get("full_name") or "",
            "role": row.get("role") or "student",
            "status": "pending",
            "attempts": 0,
            "created_at": now_iso,
            "updated_at": now_iso,
        }
        for row in users
    ]
    for start in range(0, len(target_docs), 500):
        await db.retention_email_targets.insert_many(target_docs[start : start + 500], ordered=False)

    try:
        from tasks.notifications import process_retention_insight_campaign

        process_retention_insight_campaign.delay(campaign_id=campaign_id)
    except Exception as exc:
        logger.error("retention_campaign_enqueue_failed campaign_id=%s error=%s", campaign_id, exc)
        await db.retention_email_campaigns.update_one(
            {"id": campaign_id},
            {"$set": {"status": "failed", "error": f"Task enqueue failed: {exc}", "updated_at": now_iso}},
        )
        raise HTTPException(status_code=500, detail="Failed to enqueue retention campaign")

    created = await db.retention_email_campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not created:
        raise HTTPException(status_code=500, detail="Failed to create retention campaign")
    return retention_campaign_response_model(created)


@api_router.get(
    "/v1/admin/retention-insights/campaigns/{campaign_id}",
    response_model=AdminRetentionInsightCampaignResponse,
)
async def admin_get_retention_campaign(
    campaign_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    ensure_admin_user(current_user)
    await ensure_rate_limit(current_user["id"], "admin_read_user", ADMIN_READ_PER_MIN_LIMIT)
    doc = await db.retention_email_campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Retention campaign not found")
    return retention_campaign_response_model(doc)


@api_router.post("/v1/classes/{class_id}/reviews", response_model=ClassReviewResponse)
async def create_class_review(
    class_id: str,
    payload: ClassReviewCreateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    if current_user.get("role", "").lower() != "student":
        raise HTTPException(status_code=403, detail="Only students can leave reviews")
    await ensure_rate_limit(current_user["id"], "class_review_user", CLASS_REVIEW_PER_MIN_LIMIT)
    await ensure_topic_access(current_user["id"])

    class_doc = await db.class_sessions.find_one({"id": class_id}, {"_id": 0})
    if not class_doc:
        raise HTTPException(status_code=404, detail="Class not found")
    now_iso = datetime.now(timezone.utc).isoformat()
    if class_doc.get("status") != "completed" and class_doc.get("scheduled_end_at", "") > now_iso:
        raise HTTPException(status_code=409, detail="Reviews are available only after class ends")
    enrollment = await db.class_enrollments.find_one(
        {"class_id": class_id, "student_id": current_user["id"]},
        {"_id": 0, "id": 1},
    )
    if not enrollment:
        raise HTTPException(status_code=403, detail="Only students who joined the class can review")

    review_doc = {
        "id": str(uuid.uuid4()),
        "class_id": class_id,
        "student_id": current_user["id"],
        "teacher_id": class_doc["teacher_id"],
        "rating": payload.rating,
        "comment": (payload.comment or "").strip() or None,
        "created_at": now_iso,
        "updated_at": now_iso,
    }
    await db.class_reviews.update_one(
        {"class_id": class_id, "student_id": current_user["id"]},
        {"$setOnInsert": review_doc},
        upsert=True,
    )
    saved = await db.class_reviews.find_one(
        {"class_id": class_id, "student_id": current_user["id"]},
        {"_id": 0},
    )
    norm = normalize_datetime_fields(saved or review_doc, ["created_at"])
    return ClassReviewResponse(
        id=norm["id"],
        class_id=norm["class_id"],
        student_id=norm["student_id"],
        teacher_id=norm["teacher_id"],
        rating=int(norm["rating"]),
        comment=norm.get("comment"),
        created_at=norm["created_at"],
    )


@api_router.get("/v1/classes/{class_id}/reviews", response_model=List[ClassReviewResponse])
async def list_class_reviews(
    class_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    await ensure_rate_limit(current_user["id"], "class_read_user", JOB_STATUS_PER_MIN_LIMIT)
    await ensure_topic_access(current_user["id"])
    class_doc = await db.class_sessions.find_one({"id": class_id}, {"_id": 0, "teacher_id": 1})
    if not class_doc:
        raise HTTPException(status_code=404, detail="Class not found")
    role = current_user.get("role", "").lower()
    if role == "teacher" and class_doc.get("teacher_id") != current_user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    reviews = await db.class_reviews.find({"class_id": class_id}, {"_id": 0}).sort("created_at", -1).to_list(200)
    output: List[ClassReviewResponse] = []
    for review in reviews:
        norm = normalize_datetime_fields(review, ["created_at"])
        output.append(
            ClassReviewResponse(
                id=norm["id"],
                class_id=norm["class_id"],
                student_id=norm["student_id"],
                teacher_id=norm["teacher_id"],
                rating=int(norm["rating"]),
                comment=norm.get("comment"),
                created_at=norm["created_at"],
            )
        )
    return output


@api_router.get("/v1/notifications", response_model=List[NotificationResponse])
async def list_notifications(
    limit: int = 60,
    unread_only: bool = False,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    await ensure_rate_limit(current_user["id"], "notifications_read_user", JOB_STATUS_PER_MIN_LIMIT)
    safe_limit = max(1, min(limit, 200))
    query: Dict[str, Any] = {"user_id": current_user["id"]}
    if unread_only:
        query["read"] = {"$ne": True}
    docs = await db.notifications.find(query, {"_id": 0}).sort("created_at", -1).to_list(safe_limit)
    return [build_notification_response(doc) for doc in docs]


@api_router.post("/v1/notifications/register-token")
async def register_push_token(
    payload: PushTokenUpdateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    await ensure_rate_limit(current_user["id"], "notifications_write_user", JOB_STATUS_PER_MIN_LIMIT)
    token = (payload.fcm_token or "").strip()
    if len(token) < 20:
        raise HTTPException(status_code=400, detail="Invalid FCM token")
    await db.users.update_one(
        {"id": current_user["id"]},
        {"$set": {"fcm_token": token, "fcm_token_updated_at": datetime.now(timezone.utc).isoformat()}},
    )
    return {"success": True, "message": "FCM token registered"}


@api_router.post("/v1/notifications/{notification_id}/read")
async def mark_notification_read(
    notification_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    await ensure_rate_limit(current_user["id"], "notifications_write_user", JOB_STATUS_PER_MIN_LIMIT)
    updated = await db.notifications.find_one_and_update(
        {"id": notification_id, "user_id": current_user["id"]},
        {"$set": {"read": True, "read_at": datetime.now(timezone.utc).isoformat()}},
        return_document=ReturnDocument.AFTER,
        projection={"_id": 0, "id": 1, "read": 1},
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Notification not found")
    return {"id": updated["id"], "read": bool(updated.get("read", True))}


@api_router.post("/v1/topics", response_model=TopicSuggestionResponse)
async def create_topic_suggestion(
    payload: TopicCreateRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    if current_user.get("role", "").lower() != "student":
        raise HTTPException(status_code=403, detail="Only students can create topic suggestions")
    await ensure_rate_limit(current_user["id"], "topic_create_user", TOPIC_CREATE_PER_MIN_LIMIT)
    await ensure_topic_access(current_user["id"])
    ip_address = extract_request_ip(request)
    device_fingerprint = compute_vote_device_fingerprint(request)
    await rate_limiter.check(
        f"topic_create_ip:{ip_address}",
        limit=TOPIC_CREATE_PER_HOUR_IP_LIMIT,
        window_seconds=60 * 60,
    )
    await rate_limiter.check(
        f"topic_create_fp:{device_fingerprint}",
        limit=TOPIC_CREATE_PER_HOUR_FINGERPRINT_LIMIT,
        window_seconds=60 * 60,
    )
    category = normalize_topic_category(payload.category)

    current_count = await db.topic_suggestions.count_documents(
        {"category": category, "status": {"$in": ["open", "class_created"]}}
    )
    if current_count >= TOPIC_CATEGORY_MAX_SUGGESTIONS:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Suggestion limit reached for {TOPIC_CATEGORY_LABELS[category]} "
                f"({TOPIC_CATEGORY_MAX_SUGGESTIONS}). Upvote an existing topic instead."
            ),
        )

    title = (payload.title or "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="Title is required")
    if len(title) > 180:
        raise HTTPException(status_code=400, detail="Title must be 180 characters or fewer")
    description = (payload.description or "").strip()
    if len(description) > 2000:
        raise HTTPException(status_code=400, detail="Description must be 2000 characters or fewer")
    title_signature = topic_title_token_signature(title)
    if not title_signature:
        raise HTTPException(status_code=400, detail="Title should contain meaningful words")
    similar = await find_similar_topic_suggestion(category=category, title=title)
    if similar:
        raise HTTPException(
            status_code=409,
            detail=(
                "A similar topic already exists in this category: "
                f"\"{similar.get('title', 'Existing topic')}\". Please upvote it instead."
            ),
        )

    suggestion = {
        "id": str(uuid.uuid4()),
        "title": title,
        "title_token_signature": title_signature,
        "description": description or None,
        "category": category,
        "created_by": current_user["id"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "upvote_count": 0,
        "status": "open",
        "created_ip": ip_address,
        "created_device_fingerprint": device_fingerprint,
    }
    await db.topic_suggestions.insert_one(suggestion)
    return build_topic_response(suggestion, has_upvoted=False)


@api_router.get("/v1/topics", response_model=TopicListResponse)
async def list_topic_suggestions(
    category: str,
    sort: str = "top",
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    await ensure_rate_limit(current_user["id"], "topic_read_user", TOPIC_READ_PER_MIN_LIMIT)
    await ensure_topic_access(current_user["id"])
    category_key = normalize_topic_category(category)
    sort_order = get_topic_sort(sort)

    docs = await db.topic_suggestions.find(
        {"category": category_key, "status": {"$ne": "archived"}},
        {"_id": 0},
    ).sort(sort_order).to_list(TOPIC_CATEGORY_MAX_SUGGESTIONS)

    voted_ids: set[str] = set()
    if docs:
        suggestion_ids = [doc["id"] for doc in docs]
        vote_docs = await db.suggestion_votes.find(
            {"user_id": current_user["id"], "suggestion_id": {"$in": suggestion_ids}},
            {"_id": 0, "suggestion_id": 1},
        ).to_list(len(suggestion_ids))
        voted_ids = {vote["suggestion_id"] for vote in vote_docs}

    items = [build_topic_response(doc, has_upvoted=doc["id"] in voted_ids) for doc in docs]
    total_votes = sum(item.upvote_count for item in items)
    return TopicListResponse(
        items=items,
        category=category_key,
        category_label=TOPIC_CATEGORY_LABELS[category_key],
        total_suggestions=len(items),
        total_votes=total_votes,
    )


@api_router.get("/v1/topics/", response_model=TopicListResponse, include_in_schema=False)
async def list_topic_suggestions_trailing_slash(
    category: str,
    sort: str = "top",
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    return await list_topic_suggestions(
        category=category,
        sort=sort,
        current_user=current_user,
    )


@api_router.post("/v1/topics/{topic_id}/upvote")
async def upvote_topic_suggestion(
    topic_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    if current_user.get("role", "").lower() != "student":
        raise HTTPException(status_code=403, detail="Only students can upvote topic suggestions")
    await ensure_rate_limit(current_user["id"], "topic_upvote_user", TOPIC_UPVOTE_PER_MIN_LIMIT)
    await ensure_topic_access(current_user["id"])
    ip_address = extract_request_ip(request)
    device_fingerprint = compute_vote_device_fingerprint(request)
    await rate_limiter.check(
        f"topic_upvote_ip:{ip_address}",
        limit=TOPIC_UPVOTE_PER_HOUR_IP_LIMIT,
        window_seconds=60 * 60,
    )
    await rate_limiter.check(
        f"topic_upvote_fp:{device_fingerprint}",
        limit=TOPIC_UPVOTE_PER_HOUR_FINGERPRINT_LIMIT,
        window_seconds=60 * 60,
    )

    suggestion = await db.topic_suggestions.find_one(
        {"id": topic_id},
        {"_id": 0, "id": 1, "status": 1, "created_by": 1, "category": 1},
    )
    if not suggestion:
        raise HTTPException(status_code=404, detail="Topic suggestion not found")
    if suggestion.get("status") == "archived":
        raise HTTPException(status_code=409, detail="Archived topics cannot be upvoted")
    if suggestion.get("created_by") == current_user["id"]:
        raise HTTPException(status_code=409, detail="You cannot upvote your own topic suggestion")

    cutoff_iso = (
        datetime.now(timezone.utc) - timedelta(seconds=TOPIC_UPVOTE_SUGGESTION_IP_WINDOW_SECONDS)
    ).isoformat()
    same_ip_votes = await db.suggestion_votes.count_documents(
        {
            "suggestion_id": topic_id,
            "created_ip": ip_address,
            "created_at": {"$gte": cutoff_iso},
        }
    )
    if same_ip_votes >= TOPIC_UPVOTE_SUGGESTION_IP_MAX:
        await log_topic_abuse_event(
            event_type="topic_upvote_ip_burst_blocked",
            user_id=current_user["id"],
            suggestion_id=topic_id,
            category=suggestion.get("category"),
            ip_address=ip_address,
            device_fingerprint=device_fingerprint,
            details={
                "window_seconds": TOPIC_UPVOTE_SUGGESTION_IP_WINDOW_SECONDS,
                "ip_votes": same_ip_votes,
            },
        )
        raise HTTPException(status_code=429, detail="Too many votes from this network. Try again later.")

    same_fp_votes = await db.suggestion_votes.count_documents(
        {
            "suggestion_id": topic_id,
            "device_fingerprint": device_fingerprint,
            "created_at": {"$gte": cutoff_iso},
        }
    )
    if same_fp_votes >= TOPIC_UPVOTE_SUGGESTION_FINGERPRINT_MAX:
        await log_topic_abuse_event(
            event_type="topic_upvote_fingerprint_burst_blocked",
            user_id=current_user["id"],
            suggestion_id=topic_id,
            category=suggestion.get("category"),
            ip_address=ip_address,
            device_fingerprint=device_fingerprint,
            details={
                "window_seconds": TOPIC_UPVOTE_SUGGESTION_IP_WINDOW_SECONDS,
                "fingerprint_votes": same_fp_votes,
            },
        )
        raise HTTPException(status_code=429, detail="Too many votes from this device. Try again later.")

    spike_cutoff_iso = (
        datetime.now(timezone.utc) - timedelta(seconds=TOPIC_VOTE_SPIKE_WINDOW_SECONDS)
    ).isoformat()
    spike_count = await db.suggestion_votes.count_documents(
        {
            "suggestion_id": topic_id,
            "created_at": {"$gte": spike_cutoff_iso},
        }
    )
    if spike_count >= TOPIC_VOTE_SPIKE_MAX:
        await db.topic_suggestions.update_one(
            {"id": topic_id},
            {
                "$set": {
                    "fraud_spike_flag": True,
                    "fraud_spike_flagged_at": datetime.now(timezone.utc).isoformat(),
                }
            },
        )
        await log_topic_abuse_event(
            event_type="topic_upvote_spike_blocked",
            user_id=current_user["id"],
            suggestion_id=topic_id,
            category=suggestion.get("category"),
            ip_address=ip_address,
            device_fingerprint=device_fingerprint,
            details={
                "window_seconds": TOPIC_VOTE_SPIKE_WINDOW_SECONDS,
                "spike_count": spike_count,
            },
        )
        raise HTTPException(status_code=429, detail="Voting is temporarily limited on this topic.")

    vote_doc = {
        "id": str(uuid.uuid4()),
        "suggestion_id": topic_id,
        "user_id": current_user["id"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_ip": ip_address,
        "device_fingerprint": device_fingerprint,
        "user_agent": request.headers.get("user-agent", "")[:240],
    }
    try:
        await db.suggestion_votes.insert_one(vote_doc)
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="You have already upvoted this topic")

    updated = await db.topic_suggestions.find_one_and_update(
        {"id": topic_id},
        {"$inc": {"upvote_count": 1}},
        return_document=ReturnDocument.AFTER,
        projection={"_id": 0},
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Topic suggestion not found")
    return {
        "message": "Upvote recorded",
        "topic_id": topic_id,
        "upvote_count": int(updated.get("upvote_count", 0)),
    }


@api_router.get("/v1/topics/moderation/abuse-events", response_model=List[TopicAbuseEventResponse])
async def list_topic_abuse_events(
    limit: int = 100,
    event_type: Optional[str] = None,
    suggestion_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    ensure_topic_abuse_reviewer(current_user)
    await ensure_rate_limit(current_user["id"], "topic_abuse_read_user", TOPIC_ABUSE_READ_PER_MIN_LIMIT)
    safe_limit = max(1, min(limit, 300))
    query: Dict[str, Any] = {}
    if event_type and event_type.strip():
        query["event_type"] = event_type.strip()
    if suggestion_id and suggestion_id.strip():
        query["suggestion_id"] = suggestion_id.strip()

    docs = await db.topic_vote_abuse_events.find(query, {"_id": 0}).sort("created_at", -1).to_list(safe_limit)
    output: List[TopicAbuseEventResponse] = []
    for doc in docs:
        norm = normalize_datetime_fields(doc, ["created_at"])
        output.append(
            TopicAbuseEventResponse(
                id=norm["id"],
                event_type=norm["event_type"],
                user_id=norm["user_id"],
                suggestion_id=norm.get("suggestion_id"),
                category=norm.get("category"),
                ip_address=norm.get("ip_address"),
                device_fingerprint=norm.get("device_fingerprint"),
                details=norm.get("details") or {},
                created_at=norm["created_at"],
            )
        )
    return output


@api_router.get("/v1/topics/moderation/flagged", response_model=List[TopicFlaggedResponse])
async def list_flagged_topic_suggestions(
    category: Optional[str] = None,
    limit: int = 100,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    ensure_topic_abuse_reviewer(current_user)
    await ensure_rate_limit(current_user["id"], "topic_abuse_read_user", TOPIC_ABUSE_READ_PER_MIN_LIMIT)
    safe_limit = max(1, min(limit, 300))
    query: Dict[str, Any] = {"fraud_spike_flag": True, "status": {"$ne": "archived"}}
    if category and category.strip():
        query["category"] = normalize_topic_category(category.strip())

    docs = await db.topic_suggestions.find(query, {"_id": 0}).sort("fraud_spike_flagged_at", -1).to_list(safe_limit)
    output: List[TopicFlaggedResponse] = []
    for doc in docs:
        norm = normalize_datetime_fields(doc, ["fraud_spike_flagged_at"])
        cat = norm.get("category", "")
        output.append(
            TopicFlaggedResponse(
                id=norm["id"],
                title=norm.get("title", ""),
                category=cat,
                category_label=TOPIC_CATEGORY_LABELS.get(cat, cat),
                upvote_count=int(norm.get("upvote_count", 0)),
                fraud_spike_flag=bool(norm.get("fraud_spike_flag", False)),
                fraud_spike_flagged_at=norm.get("fraud_spike_flagged_at"),
            )
        )
    return output


@api_router.post("/v1/topics/{topic_id}/moderation/resolve")
async def resolve_flagged_topic_suggestion(
    topic_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    ensure_topic_abuse_reviewer(current_user)
    await ensure_rate_limit(current_user["id"], "topic_abuse_read_user", TOPIC_ABUSE_READ_PER_MIN_LIMIT)
    updated = await db.topic_suggestions.find_one_and_update(
        {"id": topic_id},
        {
            "$set": {
                "fraud_spike_flag": False,
                "fraud_spike_resolved_at": datetime.now(timezone.utc).isoformat(),
                "fraud_spike_resolved_by": current_user["id"],
            }
        },
        return_document=ReturnDocument.AFTER,
        projection={"_id": 0, "id": 1, "fraud_spike_flag": 1},
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Topic suggestion not found")
    return {
        "id": updated["id"],
        "fraud_spike_flag": bool(updated.get("fraud_spike_flag", False)),
        "message": "Topic abuse flag resolved",
    }


@api_router.get("/v1/topics/{topic_id}", response_model=TopicSuggestionResponse)
async def get_topic_suggestion(
    topic_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    await ensure_rate_limit(current_user["id"], "topic_read_user", TOPIC_READ_PER_MIN_LIMIT)
    await ensure_topic_access(current_user["id"])

    suggestion = await db.topic_suggestions.find_one({"id": topic_id}, {"_id": 0})
    if not suggestion:
        raise HTTPException(status_code=404, detail="Topic suggestion not found")
    vote_doc = await db.suggestion_votes.find_one(
        {"user_id": current_user["id"], "suggestion_id": topic_id},
        {"_id": 0, "id": 1},
    )
    return build_topic_response(suggestion, has_upvoted=bool(vote_doc))


@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "service": "Exam OS API"}


@api_router.get("/dashboard/overview")
async def dashboard_overview(current_user: Dict[str, Any] = Depends(get_current_user)):
    user_id = current_user["id"]
    docs_count, gens_count, recent_docs = await asyncio.gather(
        db.documents.count_documents({"user_id": user_id}),
        db.generations.count_documents({"user_id": user_id}),
        db.documents.find({"user_id": user_id}, {"_id": 0}).sort("uploaded_at", -1).to_list(5),
    )
    return {
        "documents_count": docs_count,
        "generations_count": gens_count,
        "recent_documents": [
            DocumentMetadata(**normalize_datetime_fields(doc, ["uploaded_at"])).model_dump()
            for doc in recent_docs
        ],
    }


@api_router.get("/config")
async def runtime_config():
    return {
        "embedding_provider": EMBEDDING_PROVIDER,
        "llm_provider": LLM_PROVIDER,
        "llm_providers": _resolve_llm_providers(),
        "llm_routing_mode": LLM_ROUTING_MODE,
        "llm_exam_provider": LLM_EXAM_PROVIDER,
        "openai_embedding_model": OPENAI_EMBEDDING_MODEL,
        "openai_chat_model": OPENAI_CHAT_MODEL,
        "nvidia_chat_model": NVIDIA_CHAT_MODEL,
        "nvidia_chat_models": _resolve_nvidia_models(),
        "nvidia_base_url": NVIDIA_BASE_URL,
        "nvidia_timeout_seconds": NVIDIA_TIMEOUT_SECONDS,
        "nvidia_max_tokens": NVIDIA_MAX_TOKENS,
        "nvidia_force_json_mode": NVIDIA_FORCE_JSON_MODE,
        "nvidia_cooldown_seconds": NVIDIA_COOLDOWN_SECONDS,
        "has_nvidia_model_keys": bool(NVIDIA_MODEL_KEYS),
        "nvidia_model_keys_count": len(NVIDIA_MODEL_KEYS),
        "gemini_embedding_model": GEMINI_EMBEDDING_MODEL,
        "gemini_embedding_dimensions": GEMINI_EMBEDDING_DIMENSIONS,
        "gemini_chat_model": GEMINI_CHAT_MODEL,
        "gemini_chat_models": GEMINI_CHAT_MODELS,
        "gemini_key_count": len(set([k for k in GEMINI_API_KEYS if k] + ([GEMINI_API_KEY] if GEMINI_API_KEY else []))),
        "has_openai_api_key": bool(OPENAI_API_KEY),
        "has_nvidia_api_key": bool(NVIDIA_API_KEY),
        "has_gemini_api_key": bool(GEMINI_API_KEY),
        "vector_index_name": VECTOR_INDEX_NAME,
        "vector_index_required": VECTOR_INDEX_REQUIRED,
        "retrieval_top_k": RETRIEVAL_TOP_K,
        "subscriptions_enabled": SUBSCRIPTIONS_ENABLED,
        "mpesa_enabled": mpesa_service.enabled,
        "free_plan_max_documents": FREE_PLAN_MAX_DOCUMENTS,
        "free_plan_max_generations": FREE_PLAN_MAX_GENERATIONS,
        "weekly_plan_max_exams": WEEKLY_PLAN_MAX_EXAMS,
        "monthly_plan_max_exams": MONTHLY_PLAN_MAX_EXAMS,
        "annual_plan_max_exams": ANNUAL_PLAN_MAX_EXAMS,
        "free_plan_lifetime_usage_tracking": True,
        "subscription_account_reference_prefix": SUBSCRIPTION_ACCOUNT_REFERENCE_PREFIX,
        "subscription_transaction_desc_prefix": SUBSCRIPTION_TRANSACTION_DESC_PREFIX,
        "subscription_plans_from_json": bool(SUBSCRIPTION_PLANS_JSON.strip()),
        "subscription_plans": [plan.model_dump() for plan in get_subscription_plans()],
        "account_reuse_grace_days": current_account_reuse_grace_days(),
        "class_escrow_platform_fee_percent": current_class_escrow_platform_fee_percent(),
        "class_min_fee_kes": current_class_fee_bounds()[0],
        "class_max_fee_kes": current_class_fee_bounds()[1],
        "platform_withdrawal_min_kes": PLATFORM_WITHDRAWAL_MIN_KES,
        "topic_duplicate_similarity_threshold": TOPIC_DUPLICATE_SIMILARITY_THRESHOLD,
        "topic_vote_spike_window_seconds": TOPIC_VOTE_SPIKE_WINDOW_SECONDS,
        "topic_vote_spike_max": TOPIC_VOTE_SPIKE_MAX,
        "topic_abuse_read_per_min_limit": TOPIC_ABUSE_READ_PER_MIN_LIMIT,
        "topic_abuse_review_roles": sorted(TOPIC_ABUSE_REVIEW_ROLES),
        "localpro_enabled": _localpro_enabled(),
        "localpro_tutor_category": LOCALPRO_TUTOR_CATEGORY,
        "localpro_app_scheme": LOCALPRO_APP_SCHEME,
        "localpro_app_package": LOCALPRO_APP_PACKAGE,
        "localpro_playstore_url": LOCALPRO_PLAYSTORE_URL,
        "support_contact_email": SUPPORT_CONTACT_EMAIL,
        "support_contact_phone": SUPPORT_CONTACT_PHONE,
        "password_reset_ttl_minutes": PASSWORD_RESET_TTL_MINUTES,
        "password_reset_scheme": PASSWORD_RESET_SCHEME,
        "password_reset_deep_link_host": PASSWORD_RESET_DEEP_LINK_HOST,
        "password_reset_require_https": PASSWORD_RESET_REQUIRE_HTTPS,
        "has_brevo_api_key": bool(BREVO_API_KEY),
        "has_brevo_api_key2": bool(BREVO_API_KEY2),
        "has_brevo_sender_email": bool(BREVO_SENDER_EMAIL),
        "has_brevo_password_reset_template_id": bool(BREVO_PASSWORD_RESET_TEMPLATE_ID_INT or BREVO_TEMPLATE_ID_INT),
        "has_brevo_signup_otp_template_id": bool(BREVO_SIGNUP_OTP_TEMPLATE_ID_INT),
        "retention_insights_enabled": RETENTION_INSIGHTS_ENABLED,
        "retention_email_daily_limit": RETENTION_EMAIL_DAILY_LIMIT,
        "retention_email_batch_size": RETENTION_EMAIL_BATCH_SIZE,
        "retention_email_min_days_between_sends": RETENTION_EMAIL_MIN_DAYS_BETWEEN_SENDS,
        "signup_otp_ttl_minutes": SIGNUP_OTP_TTL_MINUTES,
        "signup_otp_length": SIGNUP_OTP_LENGTH,
        "signup_email_agent_name": SIGNUP_EMAIL_AGENT_NAME,
        "refresh_rotation_grace_seconds": REFRESH_ROTATION_GRACE_SECONDS,
    }

@app.on_event("startup")
async def startup_checks():
    if EMBEDDING_PROVIDER not in {"openai", "gemini"}:
        raise RuntimeError("EMBEDDING_PROVIDER must be 'openai' or 'gemini'")
    if LLM_PROVIDER not in {"openai", "gemini", "nvidia", "hybrid"}:
        raise RuntimeError("LLM_PROVIDER must be 'openai', 'gemini', 'nvidia', or 'hybrid'")
    if TOPIC_DUPLICATE_SIMILARITY_THRESHOLD < 0 or TOPIC_DUPLICATE_SIMILARITY_THRESHOLD > 1:
        raise RuntimeError("TOPIC_DUPLICATE_SIMILARITY_THRESHOLD must be between 0 and 1")
    if TOPIC_VOTE_SPIKE_WINDOW_SECONDS <= 0 or TOPIC_VOTE_SPIKE_MAX <= 0:
        raise RuntimeError("TOPIC vote spike settings must be greater than zero")
    if not TOPIC_ABUSE_REVIEW_ROLES:
        raise RuntimeError("TOPIC_ABUSE_REVIEW_ROLES must include at least one role")
    if LOCALPRO_BASE_URL and not LOCALPRO_BASE_URL.startswith(("http://", "https://")):
        raise RuntimeError("LOCALPRO_BASE_URL must start with http:// or https://")
    if LOCALPRO_TIMEOUT_SECONDS <= 0:
        raise RuntimeError("LOCALPRO_TIMEOUT_SECONDS must be greater than zero")
    if LLM_ROUTING_MODE not in {"round_robin", "priority"}:
        raise RuntimeError("LLM_ROUTING_MODE must be 'round_robin' or 'priority'")
    if LLM_EXAM_PROVIDER and LLM_EXAM_PROVIDER not in {"openai", "gemini", "nvidia"}:
        raise RuntimeError("LLM_EXAM_PROVIDER must be one of: openai, gemini, nvidia (or empty)")
    if NVIDIA_MODEL_KEYS_PARSE_ERROR:
        raise RuntimeError(f"NVIDIA_MODEL_KEYS_JSON is invalid: {NVIDIA_MODEL_KEYS_PARSE_ERROR}")

    if EMBEDDING_PROVIDER == "openai" and not OPENAI_API_KEY:
        raise RuntimeError("OPENAI_API_KEY (or EMERGENT_LLM_KEY) required for openai embeddings")
    if EMBEDDING_PROVIDER == "gemini" and not (GEMINI_API_KEY or GEMINI_API_KEYS):
        raise RuntimeError("GEMINI_API_KEY or GEMINI_API_KEYS required for gemini embeddings")
    if LLM_PROVIDER == "openai" and not OPENAI_API_KEY:
        raise RuntimeError("OPENAI_API_KEY (or EMERGENT_LLM_KEY) required for openai LLM")
    if LLM_PROVIDER == "gemini" and not (GEMINI_API_KEY or GEMINI_API_KEYS):
        raise RuntimeError("GEMINI_API_KEY or GEMINI_API_KEYS required for gemini LLM")
    if LLM_PROVIDER == "nvidia" and not _is_llm_provider_configured("nvidia"):
        raise RuntimeError("NVIDIA_API_KEY or NVIDIA_MODEL_KEYS_JSON required for nvidia LLM")
    if LLM_PROVIDER == "hybrid":
        providers = _resolve_llm_providers()
        if not providers:
            raise RuntimeError(
                "LLM_PROVIDER=hybrid requires LLM_PROVIDERS (e.g. 'gemini,nvidia') with supported values"
            )
        missing = [p for p in providers if not _is_llm_provider_configured(p)]
        if missing:
            raise RuntimeError(
                f"LLM_PROVIDER=hybrid has missing credentials for provider(s): {', '.join(missing)}"
            )
    logger.info(
        "LLM routing config provider=%s providers=%s mode=%s",
        LLM_PROVIDER,
        _resolve_llm_providers(),
        LLM_ROUTING_MODE,
    )
    if SUBSCRIPTIONS_ENABLED and not mpesa_service.enabled:
        raise RuntimeError("SUBSCRIPTIONS_ENABLED=true but M-Pesa Daraja credentials are incomplete")
    if not BREVO_API_KEY:
        raise RuntimeError("BREVO_API_KEY is required for signup OTP and password reset emails")
    if not BREVO_SENDER_EMAIL:
        raise RuntimeError("BREVO_SENDER_EMAIL must be configured when BREVO_API_KEY is set")
    if BREVO_TEMPLATE_ID and BREVO_TEMPLATE_ID_INT is None:
        raise RuntimeError("BREVO_TEMPLATE_ID must be a valid integer")
    if BREVO_PASSWORD_RESET_TEMPLATE_ID and BREVO_PASSWORD_RESET_TEMPLATE_ID_INT is None:
        raise RuntimeError("BREVO_PASSWORD_RESET_TEMPLATE_ID must be a valid integer")
    if BREVO_SIGNUP_OTP_TEMPLATE_ID and BREVO_SIGNUP_OTP_TEMPLATE_ID_INT is None:
        raise RuntimeError("BREVO_SIGNUP_OTP_TEMPLATE_ID must be a valid integer")
    if RETENTION_EMAIL_DAILY_LIMIT <= 0:
        raise RuntimeError("RETENTION_EMAIL_DAILY_LIMIT must be greater than zero")
    if RETENTION_EMAIL_BATCH_SIZE <= 0:
        raise RuntimeError("RETENTION_EMAIL_BATCH_SIZE must be greater than zero")
    if RETENTION_EMAIL_MIN_DAYS_BETWEEN_SENDS < 0:
        raise RuntimeError("RETENTION_EMAIL_MIN_DAYS_BETWEEN_SENDS cannot be negative")
    if RETENTION_INSIGHTS_ENABLED and not BREVO_API_KEY2:
        raise RuntimeError("RETENTION_INSIGHTS_ENABLED=true requires BREVO_API_KEY2")
    logger.info("Using MPesa service implementation from backend/mpesa_service.py")

    await db.users.create_index("email", unique=True)
    await db.users.create_index("fcm_token", sparse=True)
    await db.runtime_settings.create_index("id", unique=True)
    await db.documents.create_index("user_id")
    await db.documents.create_index([("user_id", 1), ("uploaded_at", -1)])
    await db.document_chunks.create_index("document_id")
    await db.document_chunks.create_index("user_id")
    await db.generations.create_index("user_id")
    await db.generations.create_index([("user_id", 1), ("created_at", -1)])
    await db.generation_jobs.create_index("job_id", unique=True)
    await db.generation_jobs.create_index([("user_id", 1), ("created_at", -1)])
    await db.generation_jobs.create_index([("status", 1), ("created_at", -1)])
    await db.notifications.create_index("id", unique=True)
    await db.notifications.create_index([("user_id", 1), ("created_at", -1)])
    await db.notifications.create_index([("user_id", 1), ("read", 1), ("created_at", -1)])
    await db.analytics_runs.create_index([("user_id", 1), ("created_at", -1)])
    await db.class_sessions.create_index("id", unique=True)
    await db.class_sessions.create_index([("teacher_id", 1), ("scheduled_start_at", -1)])
    await db.class_sessions.create_index([("status", 1), ("scheduled_start_at", 1)])
    await db.class_enrollments.create_index("id", unique=True)
    await db.class_enrollments.create_index([("class_id", 1), ("student_id", 1)], unique=True)
    await db.class_enrollments.create_index([("student_id", 1), ("joined_at", -1)])
    await db.class_payments.create_index("id", unique=True)
    await db.class_payments.create_index("checkout_request_id", unique=True, sparse=True)
    await db.class_payments.create_index([("class_id", 1), ("student_id", 1), ("created_at", -1)])
    await db.class_payments.create_index([("teacher_id", 1), ("created_at", -1)])
    await db.class_payments.create_index([("status", 1), ("created_at", -1)])
    await db.class_escrow.create_index("id", unique=True)
    await db.class_escrow.create_index("payment_id", unique=True)
    await db.class_escrow.create_index([("class_id", 1), ("status", 1)])
    await db.class_escrow.create_index([("teacher_id", 1), ("status", 1), ("created_at", -1)])
    await db.teacher_escrow_wallets.create_index("teacher_id", unique=True)
    await db.class_withdrawals.create_index("id", unique=True)
    await db.class_withdrawals.create_index([("teacher_id", 1), ("created_at", -1)])
    await db.platform_escrow_wallet.create_index("wallet_id", unique=True)
    await db.platform_withdrawals.create_index("id", unique=True)
    await db.platform_withdrawals.create_index([("requested_by", 1), ("created_at", -1)])
    await db.platform_withdrawals.create_index([("status", 1), ("created_at", -1)])
    await db.retention_email_campaigns.create_index("id", unique=True)
    await db.retention_email_campaigns.create_index([("status", 1), ("next_run_at", 1)])
    await db.retention_email_campaigns.create_index([("created_at", -1)])
    await db.retention_email_targets.create_index("id", unique=True)
    await db.retention_email_targets.create_index([("campaign_id", 1), ("status", 1), ("created_at", 1)])
    await db.retention_email_targets.create_index([("campaign_id", 1), ("user_id", 1)], unique=True)
    await db.retention_email_recipients.create_index("user_id", unique=True)
    await db.retention_email_daily_usage.create_index("day_key", unique=True)
    await db.class_reviews.create_index("id", unique=True)
    await db.class_reviews.create_index([("class_id", 1), ("student_id", 1)], unique=True)
    await db.class_reviews.create_index([("teacher_id", 1), ("created_at", -1)])
    await db.topic_suggestions.create_index("id", unique=True)
    await db.topic_suggestions.create_index("category")
    await db.topic_suggestions.create_index([("category", 1), ("title_token_signature", 1)])
    await db.topic_suggestions.create_index([("category", 1), ("upvote_count", -1)])
    await db.topic_suggestions.create_index([("category", 1), ("created_at", -1)])
    await db.topic_suggestions.create_index("created_at")
    await db.topic_suggestions.create_index("status")
    await db.topic_suggestions.create_index([("fraud_spike_flag", 1), ("fraud_spike_flagged_at", -1)])
    await db.suggestion_votes.create_index("id", unique=True)
    await db.suggestion_votes.create_index([("user_id", 1), ("suggestion_id", 1)], unique=True)
    await db.suggestion_votes.create_index("suggestion_id")
    await db.suggestion_votes.create_index([("suggestion_id", 1), ("created_at", -1)])
    await db.suggestion_votes.create_index([("suggestion_id", 1), ("created_ip", 1), ("created_at", -1)])
    await db.suggestion_votes.create_index([("suggestion_id", 1), ("device_fingerprint", 1), ("created_at", -1)])
    await db.topic_vote_abuse_events.create_index("id", unique=True)
    await db.topic_vote_abuse_events.create_index([("suggestion_id", 1), ("created_at", -1)])
    await db.topic_vote_abuse_events.create_index([("event_type", 1), ("created_at", -1)])
    await db.subscriptions.create_index("user_id", unique=True)
    await db.subscription_payments.create_index("checkout_request_id", unique=True, sparse=True)
    await db.subscription_payments.create_index("user_id")
    await db.user_usage_counters.create_index("user_id", unique=True)
    await db.user_quotas.create_index([("user_id", 1), ("date", 1)], unique=True)
    await db.refresh_tokens.create_index("jti", unique=True)
    await db.revoked_tokens.create_index("jti", unique=True)
    await db.password_reset_tokens.create_index("token_hash", unique=True)
    await db.password_reset_tokens.create_index("user_id")
    await db.password_reset_tokens.create_index("expires_at")
    await db.password_reset_tokens.create_index(
        "created_at",
        expireAfterSeconds=60 * 60 * 24 * 7,
    )
    await db.pending_signups.create_index("id", unique=True)
    await db.pending_signups.create_index("email")
    await db.pending_signups.create_index("expires_at")
    await db.pending_signups.create_index(
        "created_at",
        expireAfterSeconds=60 * 60 * 24 * 2,
    )
    await db.deleted_account_emails.create_index("email", unique=True)
    await db.deleted_account_emails.create_index("blocked_until")
    await db.deleted_account_emails.create_index(
        "deleted_at",
        expireAfterSeconds=60 * 60 * 24 * 30,
    )
    await load_runtime_settings_cache()

    try:
        search_indexes = await db.document_chunks.list_search_indexes().to_list(50)
        found = any(idx.get("name") == VECTOR_INDEX_NAME for idx in search_indexes)
        if not found:
            message = f"Atlas vector index '{VECTOR_INDEX_NAME}' not found on document_chunks"
            if VECTOR_INDEX_REQUIRED:
                raise RuntimeError(message)
            logger.warning(message)
    except Exception as e:
        if VECTOR_INDEX_REQUIRED:
            raise RuntimeError(f"Vector index validation failed at startup: {str(e)}")
        logger.warning("Vector index validation skipped due to error: %s", e)

    logger.info("Startup checks completed")


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()


app.include_router(api_router)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)
