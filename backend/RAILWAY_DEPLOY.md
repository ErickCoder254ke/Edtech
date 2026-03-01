# Railway Deployment (Backend)

## 1) Service Setup
- Create a new Railway service from this repo.
- Set the service **Root Directory** to `backend`.
- Railway will detect Python from `requirements.txt`.

## 2) Start Command
- Already configured in:
  - `Procfile`
  - `railway.json`
- Command used:
  - `uvicorn server:app --host 0.0.0.0 --port ${PORT:-8000}`
- Worker command:
  - `celery -A task_queue.celery_app worker --loglevel=info`

## 3) Required Environment Variables
Copy from `.env.example` and set real values in Railway:
- `MONGO_URL`
- `DB_NAME`
- `EMERGENT_LLM_KEY`
- `JWT_SECRET`

Recommended:
- `CORS_ORIGINS` (set to your frontend origin, not `*` in production)
- `REDIS_BROKER_URL`
- `REDIS_RESULT_BACKEND`
- `VECTOR_INDEX_REQUIRED`:
  - `false` for first deploy if Atlas vector index is not created yet
  - `true` after index exists and has been validated

## 4) Atlas Search Index
- Ensure Atlas vector search index exists on `document_chunks` with name matching `VECTOR_INDEX_NAME` (default `vector_index`).
- App startup validates index presence.

## 5) Health Check
- Endpoint: `/api/health`
- Configured in `railway.json`.

## 6) Notes
- File uploads use `/tmp/uploads` by default (ephemeral filesystem on Railway).
- For persistent file storage, move uploads to object storage (e.g., S3, R2, GCS).
