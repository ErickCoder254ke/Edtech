import asyncio
import os
from motor.motor_asyncio import AsyncIOMotorClient


async def apply_ledger_indexes() -> None:
    mongo_url = os.environ.get("MONGO_URL")
    db_name = os.environ.get("DB_NAME")

    if not mongo_url or not db_name:
        raise EnvironmentError("MONGO_URL and DB_NAME must be set")

    client = AsyncIOMotorClient(mongo_url)
    db = client[db_name]

    await db.ledger_entries.create_index(
        "transaction_id",
        unique=True,
        name="ledger_transaction_unique"
    )
    await db.ledger_entries.create_index(
        [("user_id", 1), ("created_at", -1)],
        name="ledger_user_created_at"
    )

    client.close()


def main() -> None:
    asyncio.run(apply_ledger_indexes())


if __name__ == "__main__":
    main()
