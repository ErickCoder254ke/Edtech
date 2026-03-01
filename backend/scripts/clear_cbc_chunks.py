from pathlib import Path
import re

from pymongo import MongoClient


def get_env_value(key: str) -> str:
    env_lines = Path("backend/.env").read_text(encoding="utf-8", errors="ignore").splitlines()
    for line in env_lines:
        match = re.match(rf"^\s*{re.escape(key)}\s*=\s*(.*)\s*$", line)
        if match:
            return match.group(1).strip().strip('"').strip("'")
    return ""


def main() -> None:
    mongo_url = get_env_value("MONGO_URL")
    db_name = get_env_value("DB_NAME")
    if not mongo_url or not db_name:
        raise RuntimeError("MONGO_URL and DB_NAME must exist in backend/.env")
    client = MongoClient(mongo_url)
    db = client[db_name]
    deleted = db.cbc_note_chunks.delete_many({}).deleted_count
    print("deleted cbc_note_chunks:", deleted)


if __name__ == "__main__":
    main()
