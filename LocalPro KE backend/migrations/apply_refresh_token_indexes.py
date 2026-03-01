import asyncio
import os
from motor.motor_asyncio import AsyncIOMotorClient


async def apply_refresh_token_indexes() -> None:
    mongo_url = os.environ.get("MONGO_URL")
    db_name = os.environ.get("DB_NAME")

    if not mongo_url or not db_name:
        raise EnvironmentError("MONGO_URL and DB_NAME must be set")

    client = AsyncIOMotorClient(mongo_url)
    db = client[db_name]

    await db.refresh_tokens.create_index(
        "expires_at",
        expireAfterSeconds=0,
        name="refresh_tokens_expires_at_ttl"
    )
    await db.refresh_tokens.create_index(
        [("user_id", 1), ("token_hash", 1)],
        unique=True,
        name="refresh_tokens_user_token_unique"
    )

    client.close()


def main() -> None:
    asyncio.run(apply_refresh_token_indexes())


if __name__ == "__main__":
    main()
