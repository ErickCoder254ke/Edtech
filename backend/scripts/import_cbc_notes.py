import argparse
import hashlib
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import httpx
from dotenv import load_dotenv
from pymongo import MongoClient


STOP_TOKENS = {
    "NOTES",
    "NOTE",
    "TERM",
    "COMPLETE",
    "TEACHER",
    "CO",
    "KE",
    "KCSEREVISION",
    "COM",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def slugify(text: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "-", text.strip().lower())
    return re.sub(r"-{2,}", "-", text).strip("-")


def parse_grade(stem: str) -> Optional[int]:
    match = re.search(r"grade[-_\s]?(\d+)", stem, flags=re.IGNORECASE)
    if not match:
        return None
    return int(match.group(1))


def parse_subject(stem: str) -> str:
    cleaned = stem.replace("_", "-")
    cleaned = re.sub(r"[^A-Za-z0-9-]+", "-", cleaned)
    tokens = [t for t in cleaned.split("-") if t]
    upper_tokens = [t.upper() for t in tokens]

    start_idx = 0
    if "GRADE" in upper_tokens:
        grade_idx = upper_tokens.index("GRADE")
        start_idx = min(grade_idx + 2, len(tokens))

    subject_parts: List[str] = []
    for token in upper_tokens[start_idx:]:
        if token in STOP_TOKENS:
            break
        if token.isdigit():
            continue
        subject_parts.append(token)

    if not subject_parts:
        return "General"

    special = {"CRE", "IRE", "ICT"}
    pretty_parts = [p if p in special else p.capitalize() for p in subject_parts]
    return " ".join(pretty_parts)


def cloudinary_signature(params: Dict[str, str], api_secret: str) -> str:
    signature_base = "&".join(f"{k}={params[k]}" for k in sorted(params) if params[k] is not None)
    signature_base += api_secret
    return hashlib.sha1(signature_base.encode("utf-8")).hexdigest()


def upload_pdf_to_cloudinary(
    *,
    file_path: Path,
    folder: str,
    cloud_name: str,
    api_key: str,
    api_secret: str,
    public_id: str,
) -> Dict[str, object]:
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    sign_params = {
        "folder": folder,
        "overwrite": "true",
        "public_id": public_id,
        "timestamp": timestamp,
    }
    signature = cloudinary_signature(sign_params, api_secret)
    upload_url = f"https://api.cloudinary.com/v1_1/{cloud_name}/raw/upload"

    form_data = {
        "api_key": api_key,
        "folder": folder,
        "overwrite": "true",
        "public_id": public_id,
        "timestamp": timestamp,
        "signature": signature,
    }
    with file_path.open("rb") as fp:
        files = {"file": (file_path.name, fp, "application/pdf")}
        with httpx.Client(timeout=120) as client:
            response = client.post(upload_url, data=form_data, files=files)
            if response.status_code >= 400:
                detail = response.text.strip()
                raise RuntimeError(
                    f"Cloudinary upload failed ({response.status_code}): {detail or 'no details'}"
                )
            return response.json()


def ensure_indexes(collection) -> None:
    collection.create_index("cloudinary_public_id", unique=True)
    collection.create_index([("grade", 1), ("subject", 1)])
    collection.create_index("title")
    collection.create_index("updated_at")


def build_note_doc(
    *,
    file_path: Path,
    grade: int,
    subject: str,
    cloudinary_payload: Dict[str, object],
    source_root: Path,
) -> Dict[str, object]:
    title = f"Grade {grade} {subject} Notes"
    tags = ["cbc", f"grade_{grade}", slugify(subject)]
    relative_path = str(file_path.relative_to(source_root.parent)).replace("\\", "/")
    return {
        "id": str(uuid.uuid4()),
        "grade": grade,
        "subject": subject,
        "title": title,
        "description": f"CBC Grade {grade} notes for {subject}",
        "filename": file_path.name,
        "source_path": relative_path,
        "cloudinary_url": str(cloudinary_payload.get("secure_url") or ""),
        "cloudinary_public_id": str(cloudinary_payload.get("public_id") or ""),
        "cloudinary_resource_type": str(cloudinary_payload.get("resource_type") or "raw"),
        "bytes": int(cloudinary_payload.get("bytes") or file_path.stat().st_size),
        "format": str(cloudinary_payload.get("format") or "pdf"),
        "version": cloudinary_payload.get("version"),
        "etag": cloudinary_payload.get("etag"),
        "tags": tags,
        "active": True,
        "updated_at": now_iso(),
    }


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Import CBC notes PDFs to Cloudinary and MongoDB metadata.")
    parser.add_argument(
        "--source",
        default="CBC Notes",
        help="Source folder containing grade folders and PDF files (default: CBC Notes).",
    )
    parser.add_argument(
        "--folder",
        default=os.environ.get("NOTES_CLOUDINARY_FOLDER", "exam_os/notes/cbc"),
        help="Cloudinary folder root (default: NOTES_CLOUDINARY_FOLDER or exam_os/notes/cbc).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and print files without uploading or writing to DB.",
    )
    args = parser.parse_args()

    mongo_url = (os.environ.get("MONGO_URL") or "").strip()
    db_name = (os.environ.get("DB_NAME") or "").strip()
    cloud_name = (os.environ.get("CLOUDINARY_CLOUD_NAME") or "").strip()
    api_key = (os.environ.get("CLOUDINARY_API_KEY") or "").strip()
    api_secret = (os.environ.get("CLOUDINARY_API_SECRET") or "").strip()

    if not mongo_url or not db_name:
        print("ERROR: MONGO_URL and DB_NAME are required.", file=sys.stderr)
        return 1
    if not args.dry_run and (not cloud_name or not api_key or not api_secret):
        print(
            "ERROR: CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET are required.",
            file=sys.stderr,
        )
        return 1

    source_root = Path(args.source).resolve()
    if not source_root.exists() or not source_root.is_dir():
        print(f"ERROR: Source folder not found: {source_root}", file=sys.stderr)
        return 1

    max_upload_mb = int(os.environ.get("NOTES_MAX_UPLOAD_MB", "10"))
    max_upload_bytes = max_upload_mb * 1024 * 1024
    pdf_files = sorted(source_root.rglob("*.pdf"))
    if not pdf_files:
        print("No PDF files found.")
        return 0

    client = MongoClient(mongo_url)
    db = client[db_name]
    collection = db.cbc_notes
    ensure_indexes(collection)

    uploaded = 0
    failed = 0

    for file_path in pdf_files:
        stem = file_path.stem
        grade = parse_grade(stem)
        subject = parse_subject(stem)
        if grade is None:
            print(f"SKIP: Could not infer grade from {file_path.name}")
            continue

        subject_slug = slugify(subject)
        filename_slug = slugify(stem)[:70]
        public_id = f"grade_{grade}/{subject_slug}/{filename_slug}"
        folder = f"{args.folder}/grade_{grade}"

        if args.dry_run:
            print(f"DRY RUN: {file_path.name} -> grade={grade}, subject={subject}, public_id={public_id}")
            continue

        file_size = file_path.stat().st_size
        if file_size > max_upload_bytes:
            failed += 1
            print(
                f"SKIP: {file_path.name} is {round(file_size / 1024 / 1024, 2)}MB, "
                f"exceeds NOTES_MAX_UPLOAD_MB={max_upload_mb}.",
                file=sys.stderr,
            )
            continue

        try:
            cloudinary_payload = upload_pdf_to_cloudinary(
                file_path=file_path,
                folder=folder,
                cloud_name=cloud_name,
                api_key=api_key,
                api_secret=api_secret,
                public_id=public_id,
            )
            note_doc = build_note_doc(
                file_path=file_path,
                grade=grade,
                subject=subject,
                cloudinary_payload=cloudinary_payload,
                source_root=source_root,
            )
            collection.update_one(
                {"cloudinary_public_id": note_doc["cloudinary_public_id"]},
                {
                    "$set": {k: v for k, v in note_doc.items() if k not in {"id"}},
                    "$setOnInsert": {"id": note_doc["id"], "created_at": now_iso()},
                },
                upsert=True,
            )
            uploaded += 1
            print(f"OK: {file_path.name} -> {note_doc['cloudinary_public_id']}")
        except Exception as exc:
            failed += 1
            print(f"FAIL: {file_path.name} -> {exc}", file=sys.stderr)

    print(f"\nDone. Processed={len(pdf_files)} uploaded={uploaded} failed={failed}")
    return 0 if failed == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
