import asyncio
import os
from motor.motor_asyncio import AsyncIOMotorClient


async def apply_idempotency_indexes() -> None:
    mongo_url = os.environ.get("MONGO_URL")
    db_name = os.environ.get("DB_NAME")

    if not mongo_url or not db_name:
        raise EnvironmentError("MONGO_URL and DB_NAME must be set")

    client = AsyncIOMotorClient(mongo_url)
    db = client[db_name]

    # TTL cleanup for idempotency keys
    await db.idempotency_keys.create_index(
        "expires_at",
        expireAfterSeconds=0,
        name="idempotency_expires_at_ttl"
    )

    # Prevent duplicates per scope/user/key
    await db.idempotency_keys.create_index(
        [("key", 1), ("scope", 1), ("user_id", 1)],
        unique=True,
        name="idempotency_key_scope_user_unique"
    )

    client.close()


def main() -> None:
    asyncio.run(apply_idempotency_indexes())


if __name__ == "__main__":
    main()
