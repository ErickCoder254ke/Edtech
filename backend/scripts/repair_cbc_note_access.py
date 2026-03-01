from __future__ import annotations

import argparse
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote

import httpx
from pymongo import MongoClient


# ----------------- ENVIRONMENT -----------------
def _read_env_value_from_file(env_path: Path, key: str) -> str:
    """Read a single key=value from a .env file."""
    if not env_path.exists():
        return ""
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=\s*(.*)\s*$")
    try:
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            m = pattern.match(raw_line)
            if m:
                value = m.group(1).strip().strip('"').strip("'")
                return value
    except Exception:
        return ""
    return ""


def _get_env(key: str, env_path: Optional[Path] = None) -> str:
    """Fetch key from .env file first, fallback to OS environment variable."""
    if env_path:
        val = _read_env_value_from_file(env_path, key)
        if val:
            return val.strip()
    return os.getenv(key, "").strip()


# ----------------- UTILITY -----------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def check_url(url: str, timeout_seconds: float = 20.0) -> Tuple[bool, Optional[int], str]:
    if not url.strip():
        return False, None, "empty_url"
    try:
        with httpx.Client(timeout=timeout_seconds, follow_redirects=True) as client:
            response = client.get(url)
        if 200 <= response.status_code < 300:
            return True, response.status_code, "ok"
        return False, response.status_code, f"http_{response.status_code}"
    except Exception as exc:
        return False, None, f"request_error:{exc}"


def _strip_ext(name: str) -> str:
    raw = str(name or "").strip()
    if not raw:
        return ""
    normalized = raw.replace("\\", "/")
    return str(Path(normalized).with_suffix("")).strip()


def _extract_public_id_from_url(url: str) -> str:
    raw = str(url or "").strip()
    if not raw:
        return ""
    marker = "/raw/upload/"
    idx = raw.find(marker)
    if idx < 0:
        return ""
    tail = raw[idx + len(marker) :]
    # Drop version prefix if present: v123456/
    if tail.startswith("v"):
        first = tail.split("/", 1)
        if len(first) == 2 and first[0][1:].isdigit():
            tail = first[1]
    # Remove extension
    if "." in Path(tail).name:
        tail = str(Path(tail).with_suffix("")).replace("\\", "/")
    return tail.strip("/")


def _build_public_id_candidates(row: Dict[str, Any], default_folder: str) -> list[str]:
    candidates: list[str] = []
    direct = str(row.get("cloudinary_public_id") or "").strip().replace("\\", "/").strip("/")
    if direct:
        candidates.append(_strip_ext(direct))
    from_url = _extract_public_id_from_url(str(row.get("cloudinary_url") or ""))
    if from_url:
        candidates.append(_strip_ext(from_url))
    source_path = str(row.get("source_path") or "").strip().replace("\\", "/")
    if source_path:
        # source_path may include local roots like "CBC Notes/Grade 10/..."
        source_no_ext = _strip_ext(source_path).strip("/")
        if source_no_ext:
            candidates.append(source_no_ext.replace("\\", "/"))
            # Also try as Cloudinary nested path under configured folder.
            leaf = _strip_ext(Path(source_no_ext).name)
            if leaf:
                candidates.append(f"{default_folder.strip('/').replace('\\', '/')}/{leaf}")
    filename = str(row.get("filename") or "").strip()
    if filename:
        leaf = _strip_ext(filename)
        if leaf:
            candidates.append(leaf.replace("\\", "/"))
            candidates.append(f"{default_folder.strip('/').replace('\\', '/')}/{leaf}")
    # Deduplicate while preserving order.
    seen = set()
    ordered = []
    for item in candidates:
        key = item.replace("\\", "/").strip("/")
        if key and key not in seen:
            seen.add(key)
            ordered.append(key)
    return ordered


def _build_cloudinary_raw_upload_url(cloud_name: str, public_id: str, extension: str = "pdf") -> str:
    # Keep folder slashes; encode each segment safely.
    segments = [quote(seg, safe="._-") for seg in public_id.strip("/").split("/") if seg]
    path = "/".join(segments)
    ext = (extension or "pdf").strip().lower().lstrip(".")
    if path.lower().endswith(f".{ext}"):
        return f"https://res.cloudinary.com/{cloud_name}/raw/upload/{path}"
    return f"https://res.cloudinary.com/{cloud_name}/raw/upload/{path}.{ext}"


def resolve_local_source_file(*, row: Dict[str, Any], source_root: Path) -> Optional[Path]:
    """Try to locate the PDF file locally for re-upload."""
    source_path = str(row.get("source_path") or "").strip()
    filename = str(row.get("filename") or "").strip()
    candidates = []

    if source_path:
        candidates.append(source_root.parent / source_path)
        candidates.append(source_root / source_path)
        candidates.append(source_root / Path(source_path).name)
    if filename:
        candidates.append(source_root / filename)

    for path in candidates:
        if path.exists() and path.is_file():
            return path

    # Fallback: recursive search
    if filename:
        matches = list(source_root.rglob(filename))
        if matches:
            return matches[0]
    return None


def cloudinary_admin_fetch(
    *, cloud_name: str, api_key: str, api_secret: str, public_id: str, delivery_type: str = "upload"
) -> Optional[Dict[str, Any]]:
    """Fetch metadata from Cloudinary Admin API."""
    encoded_public_id = quote(public_id, safe="")
    url = f"https://api.cloudinary.com/v1_1/{cloud_name}/resources/raw/{delivery_type}/{encoded_public_id}"
    try:
        with httpx.Client(timeout=20.0) as client:
            response = client.get(url, auth=(api_key, api_secret))
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, dict):
                return data
        return None
    except Exception:
        return None


def cloudinary_signature(params: Dict[str, str], api_secret: str) -> str:
    """Compute SHA1 signature for Cloudinary upload."""
    import hashlib

    signature_base = "&".join(f"{k}={params[k]}" for k in sorted(params) if params[k] is not None)
    signature_base += api_secret
    return hashlib.sha1(signature_base.encode("utf-8")).hexdigest()


def upload_pdf_to_cloudinary(
    *, file_path: Path, cloud_name: str, api_key: str, api_secret: str, public_id: str
) -> Dict[str, Any]:
    """Upload a local PDF to Cloudinary."""
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    sign_params = {
        "access_mode": "public",
        "overwrite": "true",
        "public_id": public_id,
        "timestamp": timestamp,
        "type": "upload",
    }
    signature = cloudinary_signature(sign_params, api_secret)
    upload_url = f"https://api.cloudinary.com/v1_1/{cloud_name}/raw/upload"

    form_data = {
        "api_key": api_key,
        "access_mode": "public",
        "overwrite": "true",
        "public_id": public_id,
        "timestamp": timestamp,
        "signature": signature,
        "type": "upload",
    }

    with file_path.open("rb") as fp:
        files = {"file": (file_path.name, fp, "application/pdf")}
        with httpx.Client(timeout=120) as client:
            response = client.post(upload_url, data=form_data, files=files)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise RuntimeError("Unexpected Cloudinary upload response")
        return payload


# ----------------- MAIN -----------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Repair inaccessible CBC shared-note URLs by querying Cloudinary metadata, "
            "optionally re-uploading from local source path, and deactivating inaccessible notes."
        )
    )
    parser.add_argument("--apply", action="store_true", help="Apply updates. Default is dry-run.")
    parser.add_argument(
        "--deactivate-inaccessible",
        action="store_true",
        help="Set active=false for notes still inaccessible after repair attempts.",
    )
    parser.add_argument(
        "--reupload-from-source",
        action="store_true",
        help="If note remains inaccessible and source file exists locally, re-upload to Cloudinary.",
    )
    parser.add_argument(
        "--source-root",
        default="CBC Notes",
        help="Local root path for source PDFs when using --reupload-from-source (default: CBC Notes).",
    )
    parser.add_argument("--limit", type=int, default=0, help="Max notes to process (0 = all).")
    parser.add_argument(
        "--include-inactive",
        action="store_true",
        help="Include notes with active=false (useful if you previously deactivated broken notes).",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    env_path = root / ".env"

    # Read credentials from .env or environment
    mongo_url = _get_env("MONGO_URL", env_path)
    db_name = _get_env("DB_NAME", env_path)
    cloud_name = _get_env("CLOUDINARY_CLOUD_NAME", env_path)
    api_key = _get_env("CLOUDINARY_API_KEY", env_path)
    api_secret = _get_env("CLOUDINARY_API_SECRET", env_path)
    default_folder = (_get_env("NOTES_CLOUDINARY_FOLDER", env_path) or "exam_os/notes/cbc").strip()
    source_root = Path(args.source_root)

    if not mongo_url or not db_name or not cloud_name or not api_key or not api_secret:
        raise RuntimeError("MONGO_URL, DB_NAME, and Cloudinary credentials are required.")

    client = MongoClient(mongo_url)
    db = client[db_name]
    notes = db.cbc_notes

    query: Dict[str, Any] = {} if args.include_inactive else {"active": {"$ne": False}}
    cursor = notes.find(query, {"_id": 0})
    if args.limit and args.limit > 0:
        cursor = cursor.limit(int(args.limit))
    rows = list(cursor)
    total = len(rows)
    print(f"Found {total} active note(s).")

    ok_count = 0
    fixed_count = 0
    deactivated_count = 0
    failed_count = 0

    for row in rows:
        note_id = str(row.get("id") or "")
        title = str(row.get("title") or "")
        current_url = str(row.get("cloudinary_url") or "").strip()
        public_id = str(row.get("cloudinary_public_id") or "").strip()

        ok, status_code, reason = check_url(current_url)
        if ok:
            ok_count += 1
            print(f"OK   note_id={note_id} status={status_code} title={title}")
            continue

        print(f"MISS note_id={note_id} status={status_code} reason={reason} title={title}")

        repaired_payload: Optional[Dict[str, Any]] = None
        repaired_url: Optional[str] = None

        # 1) Try direct raw/upload public URLs using full nested public_id candidates.
        ext = str(row.get("format") or "pdf").strip().lower() or "pdf"
        for candidate_public_id in _build_public_id_candidates(row, default_folder):
            candidate_url = _build_cloudinary_raw_upload_url(cloud_name, candidate_public_id, ext)
            ok2, status2, reason2 = check_url(candidate_url)
            print(
                f"TRY  note_id={note_id} delivery=upload status={status2} reason={reason2} "
                f"public_id={candidate_public_id}"
            )
            if ok2:
                repaired_payload = {
                    "public_id": candidate_public_id,
                    "secure_url": candidate_url,
                    "resource_type": "raw",
                    "format": ext,
                }
                repaired_url = candidate_url
                break

        # 2) Optionally re-upload from local source
        if not repaired_url and args.reupload_from_source:
            local_file = resolve_local_source_file(row=row, source_root=source_root)
            if local_file and local_file.exists() and local_file.is_file():
                try:
                    candidate_public_ids = _build_public_id_candidates(row, default_folder)
                    upload_public_id = (
                        candidate_public_ids[0]
                        if candidate_public_ids
                        else f"{default_folder.strip('/')}/{_strip_ext(local_file.name)}"
                    )
                    payload = upload_pdf_to_cloudinary(
                        file_path=local_file,
                        cloud_name=cloud_name,
                        api_key=api_key,
                        api_secret=api_secret,
                        public_id=upload_public_id,
                    )
                    candidate_url = str(payload.get("secure_url") or "").strip()
                    ok3, status3, reason3 = check_url(candidate_url)
                    print(f"UPLD note_id={note_id} status={status3} reason={reason3} source={local_file.name}")
                    if ok3:
                        repaired_payload = payload
                        repaired_url = candidate_url
                    elif status3 == 401:
                        print(f"HINT cloudinary_delivery_blocked note_id={note_id} cloud={cloud_name}")
                except Exception as exc:
                    print(f"ERR  note_id={note_id} reupload_failed={exc}")
            else:
                print(f"MISS note_id={note_id} local_source_not_found filename={row.get('filename')} source_path={row.get('source_path')}")

        if repaired_url:
            update_doc = {
                "cloudinary_url": repaired_url,
                "cloudinary_public_id": str(repaired_payload.get("public_id") or public_id),
                "cloudinary_resource_type": str(repaired_payload.get("resource_type") or "raw"),
                "bytes": int(repaired_payload.get("bytes") or row.get("bytes") or 0),
                "format": str(repaired_payload.get("format") or row.get("format") or "pdf"),
                "version": repaired_payload.get("version"),
                "etag": repaired_payload.get("etag"),
                "active": True,
                "last_delivery_error": None,
                "last_delivery_error_status": None,
                "last_delivery_error_at": None,
                "updated_at": now_iso(),
            }
            if args.apply:
                notes.update_one({"id": note_id}, {"$set": update_doc})
            fixed_count += 1
            print(f"FIXD note_id={note_id} url={repaired_url}")
            continue

        failed_count += 1
        if args.deactivate_inaccessible and args.apply:
            notes.update_one(
                {"id": note_id},
                {
                    "$set": {
                        "active": False,
                        "last_delivery_error": reason,
                        "last_delivery_error_status": status_code,
                        "last_delivery_error_at": now_iso(),
                        "updated_at": now_iso(),
                    }
                },
            )
            deactivated_count += 1
            print(f"DEAC note_id={note_id} title={title}")

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(
        f"\n[{mode}] done total={total} ok={ok_count} fixed={fixed_count} "
        f"failed={failed_count} deactivated={deactivated_count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
