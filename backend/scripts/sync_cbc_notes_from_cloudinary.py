from __future__ import annotations

import argparse
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from pymongo import MongoClient


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_env_value_from_file(env_path: Path, key: str) -> str:
    if not env_path.exists():
        return ""
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=\s*(.*)\s*$")
    for raw_line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        m = pattern.match(raw_line)
        if not m:
            continue
        value = m.group(1).strip()
        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            value = value[1:-1]
        if value.startswith("'") and value.endswith("'") and len(value) >= 2:
            value = value[1:-1]
        return value
    return ""


def _get_env(key: str, env_path: Path) -> str:
    # Prefer backend/.env values so local shell env does not override unexpectedly.
    from_file = _read_env_value_from_file(env_path, key).strip()
    if from_file:
        return from_file
    return os.getenv(key, "").strip()


def _extract_grade(text: str) -> Optional[int]:
    m = re.search(r"grade[\s_\-]?(\d{1,2})", text, flags=re.IGNORECASE)
    if m:
        return int(m.group(1))
    m = re.search(r"\b(\d{1,2})\b", text)
    if m:
        value = int(m.group(1))
        if 1 <= value <= 12:
            return value
    return None


def _extract_form(text: str) -> Optional[int]:
    m = re.search(r"form[\s_\-]?(\d{1,2})", text, flags=re.IGNORECASE)
    if m:
        value = int(m.group(1))
        if 1 <= value <= 12:
            return value
    return None


def _strip_cloudinary_suffix(text: str) -> str:
    raw = str(text or "")
    if not raw:
        return ""
    # Remove Cloudinary-style random tail in filenames/public IDs like "__u3o94l"
    return re.sub(r"__?[a-z0-9]{5,}$", "", raw, flags=re.IGNORECASE)


def _clean_subject(raw: str) -> str:
    cleaned = _strip_cloudinary_suffix(raw)
    tokens = re.split(r"[^a-zA-Z0-9]+", cleaned.lower())
    stop = {
        "grade",
        "form",
        "notes",
        "note",
        "term",
        "teacher",
        "co",
        "ke",
        "kcserevision",
        "com",
        "comterm",
        "complete",
        "1",
        "2",
        "3",
        "pdf",
        "",
    }
    keep = [t for t in tokens if t not in stop and not t.isdigit()]
    if not keep:
        return "General"
    return " ".join(w.capitalize() for w in keep[:4])


def _derive_grade_subject(public_id: str, filename: str) -> Tuple[int, str, str, str]:
    cleaned_public_id = _strip_cloudinary_suffix(public_id)
    cleaned_filename = _strip_cloudinary_suffix(Path(filename).stem)
    blob = f"{cleaned_public_id} {cleaned_filename}"
    form = _extract_form(blob)
    grade = _extract_grade(blob)
    if form is not None:
        level_type = "form"
        level_number = form
    elif grade is not None:
        level_type = "grade"
        level_number = grade
    else:
        level_type = "grade"
        level_number = 10
    level_label = f"{'Form' if level_type == 'form' else 'Grade'} {level_number}"

    path_parts = [p for p in cleaned_public_id.split("/") if p.strip()]
    subject_part = ""
    for idx, part in enumerate(path_parts):
        if _extract_grade(part) is not None and idx + 1 < len(path_parts):
            subject_part = path_parts[idx + 1]
            break
    if not subject_part and path_parts:
        subject_part = path_parts[-1]
    subject = _clean_subject(subject_part or cleaned_filename)
    return level_number, subject, level_type, level_label


def _filename_from_resource(resource: Dict[str, Any]) -> str:
    public_id = str(resource.get("public_id") or "")
    basename = public_id.split("/")[-1] if public_id else "note"
    fmt = str(resource.get("format") or "").strip().lower()
    if fmt and not basename.lower().endswith(f".{fmt}"):
        return f"{basename}.{fmt}"
    return basename


def _normalize_file_key(value: str) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    stem = Path(raw).stem
    # remove random cloudinary suffix like _u3o94l
    stem = re.sub(r"_[a-z0-9]{4,}$", "", stem)
    return stem


def fetch_cloudinary_resources(
    *,
    cloud_name: str,
    api_key: str,
    api_secret: str,
    prefix: str,
    resource_type: str,
    delivery_type: str,
    max_results: int = 500,
) -> List[Dict[str, Any]]:
    url = f"https://api.cloudinary.com/v1_1/{cloud_name}/resources/{resource_type}/{delivery_type}"
    rows: List[Dict[str, Any]] = []
    next_cursor: Optional[str] = None
    with httpx.Client(timeout=45) as client:
        while True:
            params: Dict[str, Any] = {
                "prefix": prefix,
                "max_results": max(1, min(max_results, 500)),
            }
            if next_cursor:
                params["next_cursor"] = next_cursor
            resp = client.get(url, params=params, auth=(api_key, api_secret))
            resp.raise_for_status()
            payload = resp.json()
            page = payload.get("resources", [])
            if isinstance(page, list):
                rows.extend([x for x in page if isinstance(x, dict)])
            next_cursor = payload.get("next_cursor")
            if not next_cursor:
                break
    return rows


def _suggest_prefixes(resources: List[Dict[str, Any]]) -> List[str]:
    counts: Dict[str, int] = {}
    for item in resources:
        pid = str(item.get("public_id") or "").strip("/")
        if not pid:
            continue
        parts = pid.split("/")
        if len(parts) >= 3:
            key = "/".join(parts[:3])
        elif len(parts) >= 2:
            key = "/".join(parts[:2])
        else:
            key = parts[0]
        counts[key] = counts.get(key, 0) + 1
    return [k for k, _ in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:12]]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sync CBC notes metadata from a Cloudinary folder into MongoDB cbc_notes."
    )
    parser.add_argument("--cloudinary-folder", default="", help='Cloudinary folder path, e.g. "Home/CBC/exam-os/grade10"')
    parser.add_argument("--prefix", default="", help="Alias for --cloudinary-folder")
    parser.add_argument("--resource-types", default="raw,image", help='Comma-separated Cloudinary resource types')
    parser.add_argument("--delivery-types", default="upload,authenticated,private", help='Comma-separated delivery types')
    parser.add_argument("--apply", action="store_true", help="Apply DB updates (dry-run by default)")
    parser.add_argument("--deactivate-missing", action="store_true", help="Deactivate notes missing from folder")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of fetched resources")
    parser.add_argument(
        "--discover",
        action="store_true",
        help="Ignore folder filter and print sample Cloudinary public_ids/prefixes for troubleshooting.",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    env_path = root / ".env"
    mongo_url = _get_env("MONGO_URL", env_path)
    db_name = _get_env("DB_NAME", env_path)
    cloud_name = _get_env("CLOUDINARY_CLOUD_NAME", env_path)
    api_key = _get_env("CLOUDINARY_API_KEY", env_path)
    api_secret = _get_env("CLOUDINARY_API_SECRET", env_path)
    notes_folder_env = _get_env("NOTES_CLOUDINARY_FOLDER", env_path).strip().strip("/")

    if not mongo_url or not db_name:
        raise RuntimeError("MONGO_URL and DB_NAME are required")
    if not cloud_name or not api_key or not api_secret:
        raise RuntimeError("CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET are required")

    prefix = (args.cloudinary_folder.strip().strip("/") or args.prefix.strip().strip("/") or notes_folder_env)
    if not prefix and not args.discover:
        raise RuntimeError("Provide --cloudinary-folder/--prefix or set NOTES_CLOUDINARY_FOLDER in backend/.env")

    resource_types = [x.strip() for x in args.resource_types.split(",") if x.strip()]
    delivery_types = [x.strip() for x in args.delivery_types.split(",") if x.strip()]
    resources: List[Dict[str, Any]] = []
    seen_public_ids = set()

    print(f"Cloudinary cloud='{cloud_name}' prefix='{prefix or '<root>'}'")
    for rtype in resource_types:
        for dtype in delivery_types:
            try:
                items = fetch_cloudinary_resources(
                    cloud_name=cloud_name,
                    api_key=api_key,
                    api_secret=api_secret,
                    prefix=(prefix if not args.discover else ""),
                    resource_type=rtype,
                    delivery_type=dtype,
                )
                print(f"Fetched {len(items)} item(s) from {rtype}/{dtype}")
                for item in items:
                    pid = str(item.get("public_id") or "").strip()
                    if not pid or pid in seen_public_ids:
                        continue
                    seen_public_ids.add(pid)
                    item["resource_type"] = item.get("resource_type") or rtype
                    item["_delivery_type"] = dtype
                    resources.append(item)
            except Exception as exc:
                print(f"WARN could_not_fetch {rtype}/{dtype}: {exc}")

    if args.limit and args.limit > 0:
        resources = resources[: args.limit]
    print(f"Fetched {len(resources)} Cloudinary resource(s) for prefix='{prefix}'.")
    if not resources:
        print("No assets found for given prefix.")
        print("Attempting root discovery sample...")
        discovery: List[Dict[str, Any]] = []
        for rtype in resource_types:
            for dtype in delivery_types:
                try:
                    sample = fetch_cloudinary_resources(
                        cloud_name=cloud_name,
                        api_key=api_key,
                        api_secret=api_secret,
                        prefix="",
                        resource_type=rtype,
                        delivery_type=dtype,
                        max_results=100,
                    )
                    discovery.extend(sample[:50])
                except Exception:
                    pass
        if discovery:
            print(f"Discovery found {len(discovery)} resource sample(s).")
            print("Sample public_ids:")
            for row in discovery[:15]:
                print(f" - {row.get('public_id')}")
            suggestions = _suggest_prefixes(discovery)
            if suggestions:
                print("Suggested prefixes:")
                for s in suggestions:
                    print(f" - {s}")
        else:
            print(
                "No resources found at root either. Check CLOUDINARY_CLOUD_NAME/API key/secret for this account."
            )
        if not args.apply:
            return 0

    client = MongoClient(mongo_url)
    db = client[db_name]
    notes = db.cbc_notes
    existing = list(notes.find({}, {"_id": 0}))
    by_public_id = {str(d.get("cloudinary_public_id") or ""): d for d in existing}
    by_filename = {str(d.get("filename") or "").lower(): d for d in existing if d.get("filename")}
    by_filename_normalized = {
        _normalize_file_key(str(d.get("filename") or "")): d
        for d in existing
        if _normalize_file_key(str(d.get("filename") or ""))
    }

    matched_ids = set()
    created = 0
    updated = 0

    for res in resources:
        public_id = str(res.get("public_id") or "").strip()
        secure_url = str(res.get("secure_url") or "").strip()
        if not public_id or not secure_url:
            continue
        filename = _filename_from_resource(res)
        normalized_cloud_key = _normalize_file_key(filename)
        target = (
            by_public_id.get(public_id)
            or by_filename.get(filename.lower())
            or by_filename_normalized.get(normalized_cloud_key)
        )

        grade, subject, level_type, level_label = _derive_grade_subject(public_id, filename)
        title = f"{level_label} {subject} Notes"
        update_doc: Dict[str, Any] = {
            "grade": grade,
            "level_type": level_type,
            "level_label": level_label,
            "subject": subject,
            "title": title,
            "description": f"{level_label} notes for {subject}",
            "filename": filename,
            "source_path": f"{prefix}/{filename}",
            "cloudinary_url": secure_url,
            "cloudinary_public_id": public_id,
            "cloudinary_resource_type": str(res.get("resource_type") or "raw"),
            "bytes": int(res.get("bytes") or 0),
            "format": str(res.get("format") or "pdf"),
            "version": res.get("version"),
            "etag": res.get("etag"),
            "active": True,
            "last_delivery_error": None,
            "last_delivery_error_status": None,
            "last_delivery_error_at": None,
            "updated_at": now_iso(),
        }

        if target:
            note_id = str(target.get("id") or "")
            matched_ids.add(note_id)
            updated += 1
            print(f"UPDT id={note_id} file={filename} public_id={public_id}")
            if args.apply:
                notes.update_one({"id": note_id}, {"$set": update_doc})
        else:
            new_id = str(uuid.uuid4())
            created += 1
            print(f"NEW  id={new_id} file={filename} public_id={public_id}")
            if args.apply:
                notes.insert_one({"id": new_id, "created_at": now_iso(), **update_doc})

    deactivated = 0
    if args.deactivate_missing:
        cloud_files = {(_filename_from_resource(r)).lower() for r in resources}
        for doc in existing:
            note_id = str(doc.get("id") or "")
            if note_id in matched_ids:
                continue
            file_key = str(doc.get("filename") or "").lower()
            if file_key and file_key in cloud_files:
                continue
            if str(doc.get("active", True)).lower() == "false":
                continue
            deactivated += 1
            print(f"DEAC id={note_id} file={doc.get('filename')}")
            if args.apply:
                notes.update_one(
                    {"id": note_id},
                    {
                        "$set": {
                            "active": False,
                            "updated_at": now_iso(),
                            "last_delivery_error": "missing_from_cloudinary_prefix",
                            "last_delivery_error_at": now_iso(),
                        }
                    },
                )

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(
        f"\n[{mode}] done resources={len(resources)} updated={updated} created={created} deactivated={deactivated}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
