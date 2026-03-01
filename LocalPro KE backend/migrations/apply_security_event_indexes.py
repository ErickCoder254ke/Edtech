import asyncio
import os
from motor.motor_asyncio import AsyncIOMotorClient


async def apply_security_event_indexes() -> None:
    mongo_url = os.environ.get("MONGO_URL")
    db_name = os.environ.get("DB_NAME")

    if not mongo_url or not db_name:
        raise EnvironmentError("MONGO_URL and DB_NAME must be set")

    client = AsyncIOMotorClient(mongo_url)
    db = client[db_name]

    await db.security_events.create_index(
        "expires_at",
        expireAfterSeconds=0,
        name="security_events_expires_at_ttl"
    )
    await db.security_events.create_index(
        [("severity", 1), ("created_at", -1)],
        name="security_events_severity_created_at"
    )
    await db.security_events.create_index(
        "event_type",
        name="security_events_event_type"
    )

    client.close()


def main() -> None:
    asyncio.run(apply_security_event_indexes())


if __name__ == "__main__":
    main()
