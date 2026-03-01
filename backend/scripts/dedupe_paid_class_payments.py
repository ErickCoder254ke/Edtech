from __future__ import annotations

import argparse
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv
from pymongo import MongoClient


def _parse_dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    raw = str(value or "").strip()
    if not raw:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.fromtimestamp(0, tz=timezone.utc)


def _payment_rank(doc: Dict[str, Any], escrow_by_payment_id: Dict[str, Dict[str, Any]]) -> Tuple[int, int, datetime]:
    escrow = escrow_by_payment_id.get(str(doc.get("id", "")), {})
    escrow_status = str(escrow.get("status", "")).lower()
    escrow_weight = 0
    if escrow_status == "released":
        escrow_weight = 3
    elif escrow_status == "held":
        escrow_weight = 2
    elif escrow:
        escrow_weight = 1

    receipt_weight = 1 if str(doc.get("mpesa_receipt_number", "")).strip() else 0
    time_weight = max(
        _parse_dt(doc.get("paid_at")),
        _parse_dt(doc.get("updated_at")),
        _parse_dt(doc.get("created_at")),
    )
    return (escrow_weight, receipt_weight, time_weight)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Deduplicate class_payments so each (class_id, student_id) has only one status=paid record."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply changes. Without this flag, runs in dry-run mode.",
    )
    parser.add_argument(
        "--create-index",
        action="store_true",
        help="Create/ensure unique partial index for paid records after dedupe.",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    load_dotenv(root / ".env")

    mongo_url = os.getenv("MONGO_URL", "").strip()
    db_name = os.getenv("DB_NAME", "").strip()
    if not mongo_url:
        raise RuntimeError("MONGO_URL is required")
    if not db_name:
        raise RuntimeError("DB_NAME is required")

    client = MongoClient(mongo_url)
    db = client[db_name]
    class_payments = db.class_payments
    class_escrow = db.class_escrow
    class_enrollments = db.class_enrollments

    duplicate_groups = list(
        class_payments.aggregate(
            [
                {"$match": {"status": "paid", "class_id": {"$ne": None}, "student_id": {"$ne": None}}},
                {
                    "$group": {
                        "_id": {"class_id": "$class_id", "student_id": "$student_id"},
                        "count": {"$sum": 1},
                        "payment_ids": {"$push": "$id"},
                    }
                },
                {"$match": {"count": {"$gt": 1}}},
            ]
        )
    )

    if not duplicate_groups:
        print("No duplicate paid class payment groups found.")
    else:
        print(f"Found {len(duplicate_groups)} duplicate paid group(s).")

    total_archived = 0
    total_groups_changed = 0
    now_iso = datetime.now(timezone.utc).isoformat()

    for group in duplicate_groups:
        class_id = str(group["_id"]["class_id"])
        student_id = str(group["_id"]["student_id"])
        docs: List[Dict[str, Any]] = list(
            class_payments.find(
                {"class_id": class_id, "student_id": student_id, "status": "paid"},
                {"_id": 0},
            )
        )
        if len(docs) <= 1:
            continue

        payment_ids = [str(d.get("id", "")) for d in docs if str(d.get("id", "")).strip()]
        escrow_docs = list(class_escrow.find({"payment_id": {"$in": payment_ids}}, {"_id": 0, "payment_id": 1, "status": 1}))
        escrow_by_payment_id = {str(e.get("payment_id", "")): e for e in escrow_docs}

        ranked = sorted(
            docs,
            key=lambda d: _payment_rank(d, escrow_by_payment_id),
            reverse=True,
        )
        keep = ranked[0]
        archive = ranked[1:]
        archive_ids = [str(d["id"]) for d in archive if str(d.get("id", "")).strip()]

        print(
            f"[GROUP] class_id={class_id} student_id={student_id} keep={keep.get('id')} archive={len(archive_ids)}"
        )

        if not args.apply:
            continue

        if archive_ids:
            result = class_payments.update_many(
                {"id": {"$in": archive_ids}, "status": "paid"},
                {
                    "$set": {
                        "status": "duplicate_archived",
                        "duplicate_of_payment_id": str(keep["id"]),
                        "duplicate_archived_at": now_iso,
                        "updated_at": now_iso,
                    }
                },
            )
            total_archived += int(result.modified_count)
            total_groups_changed += 1

            class_enrollments.update_many(
                {"class_id": class_id, "student_id": student_id, "payment_id": {"$in": archive_ids}},
                {"$set": {"payment_id": str(keep["id"]), "payment_status": "paid", "updated_at": now_iso}},
            )

    if args.apply:
        print(f"Applied changes. groups_changed={total_groups_changed} archived_paid_records={total_archived}")
    else:
        print("Dry run only. Re-run with --apply to persist changes.")

    if args.create_index:
        print("Ensuring unique paid index on (class_id, student_id, status='paid') ...")
        class_payments.create_index(
            [("class_id", 1), ("student_id", 1), ("status", 1)],
            unique=True,
            partialFilterExpression={"status": "paid"},
            name="uniq_class_student_paid_payment",
        )
        print("Index ensured: uniq_class_student_paid_payment")


if __name__ == "__main__":
    main()

