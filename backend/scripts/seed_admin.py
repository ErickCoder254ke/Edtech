import argparse
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import bcrypt
from dotenv import load_dotenv
from pymongo import MongoClient


DEFAULT_ADMIN_NAME = "Erick"
DEFAULT_ADMIN_PASSWORD = "erichege56"
DEFAULT_ADMIN_EMAIL = "examos254@gmail.com"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def main() -> None:
    env_path = Path(__file__).resolve().parents[1] / ".env"
    load_dotenv(env_path)

    parser = argparse.ArgumentParser(description="Seed or update an admin user in MongoDB.")
    parser.add_argument("--name", default=DEFAULT_ADMIN_NAME, help="Admin full name")
    parser.add_argument("--password", default=DEFAULT_ADMIN_PASSWORD, help="Admin password")
    parser.add_argument("--email", default=DEFAULT_ADMIN_EMAIL, help="Admin login email")
    args = parser.parse_args()

    mongo_url = os.getenv("MONGO_URL")
    db_name = os.getenv("DB_NAME", "academic_assistant")
    if not mongo_url:
        raise RuntimeError("MONGO_URL is required")

    email = args.email.strip().lower()
    full_name = args.name.strip()
    if len(args.password) < 8:
        raise ValueError("Password must be at least 8 characters")

    client = MongoClient(mongo_url)
    db = client[db_name]
    users = db["users"]

    now_iso = datetime.now(timezone.utc).isoformat()
    existing = users.find_one({"email": email}, {"_id": 0, "id": 1})

    if existing:
        users.update_one(
            {"email": email},
            {
                "$set": {
                    "full_name": full_name,
                    "role": "admin",
                    "password_hash": hash_password(args.password),
                    "updated_at": now_iso,
                }
            },
        )
        print(f"Updated existing admin user: {email}")
    else:
        users.insert_one(
            {
                "id": str(uuid.uuid4()),
                "email": email,
                "full_name": full_name,
                "role": "admin",
                "created_at": now_iso,
                "password_hash": hash_password(args.password),
            }
        )
        print(f"Created new admin user: {email}")

    print("Seed complete.")
    print(f"Name: {full_name}")
    print(f"Email: {email}")


if __name__ == "__main__":
    main()
