# LocalPro KE API Key Enforcement Guide

This document shows how to enforce a server-to-server API key on LocalPro KE endpoints (for example, when Exam OS calls LocalPro tutor/service APIs).

The examples below assume your backend is FastAPI and your main app file is `backend/server.py`.

---

## 1. Add environment variables

In `backend/.env.example` (LocalPro project), add:

```env
# API key auth for external server-to-server access
API_KEY_ENFORCEMENT_ENABLED=false
LOCALPRO_PUBLIC_API_KEY=""
```

In production:

- set `API_KEY_ENFORCEMENT_ENABLED=true`
- set `LOCALPRO_PUBLIC_API_KEY` to a long random secret

---

## 2. Load config in `backend/server.py`

Near other env config:

```python
API_KEY_ENFORCEMENT_ENABLED = os.getenv("API_KEY_ENFORCEMENT_ENABLED", "false").lower() == "true"
LOCALPRO_PUBLIC_API_KEY = os.getenv("LOCALPRO_PUBLIC_API_KEY", "").strip()
```

Optional startup validation:

```python
if API_KEY_ENFORCEMENT_ENABLED and not LOCALPRO_PUBLIC_API_KEY:
    raise RuntimeError("LOCALPRO_PUBLIC_API_KEY must be set when API key enforcement is enabled")
```

---

## 3. Add API key dependency

Add imports:

```python
from fastapi import Header
```

Add this helper function:

```python
async def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")):
    # Only enforce when feature flag is enabled.
    if not API_KEY_ENFORCEMENT_ENABLED:
        return

    if not x_api_key or x_api_key != LOCALPRO_PUBLIC_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
```

---

## 4. Protect selected endpoints (recommended)

Best practice: protect only endpoints used by external platforms.

Example for services listing endpoint:

Before:

```python
@api_router.get("/services", response_model=List[ServiceListing])
async def get_service_listings(...):
    ...
```

After:

```python
@api_router.get("/services", response_model=List[ServiceListing])
async def get_service_listings(
    ...,
    _api_key_ok: None = Depends(require_api_key),
):
    ...
```

Do same for:

- `GET /api/services/{service_id}`
- any dedicated partner endpoint you expose for Exam OS

---

## 5. (Alternative) Protect all `/api/*` routes with middleware

Use this only if you want global enforcement for all API routes.

```python
from fastapi import Request
from fastapi.responses import JSONResponse

@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    if API_KEY_ENFORCEMENT_ENABLED:
        path = request.url.path
        # Protect API paths; allow health/docs/auth if needed
        protected = path.startswith("/api/")
        allowlist = {
            "/api/health",
            "/docs",
            "/openapi.json",
        }
        if protected and path not in allowlist:
            provided = request.headers.get("X-API-Key", "")
            if provided != LOCALPRO_PUBLIC_API_KEY:
                return JSONResponse(status_code=401, content={"detail": "Invalid or missing API key"})

    return await call_next(request)
```

---

## 6. Client side (Exam OS) header

When Exam OS calls LocalPro, include:

```http
X-API-Key: <same value as LOCALPRO_PUBLIC_API_KEY>
```

In your current Exam OS integration, this is already wired via backend env:

- `LOCALPRO_API_KEY` (Exam OS backend)

---

## 7. Security notes

- Use a long random key (32+ chars).
- Rotate keys periodically.
- Never commit real key values to git.
- Keep `API_KEY_ENFORCEMENT_ENABLED=false` in local dev unless needed.
- Prefer key enforcement on only partner-facing endpoints if your mobile app uses public endpoints without key.

---

## 8. Quick test

Without key (should fail when enabled):

```bash
curl "https://<localpro-domain>/api/services?status=active"
```

With key (should pass):

```bash
curl -H "X-API-Key: <YOUR_KEY>" "https://<localpro-domain>/api/services?status=active"
```

---

## 9. Recommended rollout plan

1. Deploy code with enforcement disabled.
2. Set Exam OS `LOCALPRO_API_KEY`.
3. Verify Exam OS requests are sending `X-API-Key`.
4. Enable `API_KEY_ENFORCEMENT_ENABLED=true` on LocalPro.
5. Monitor 401 logs for unexpected clients.
