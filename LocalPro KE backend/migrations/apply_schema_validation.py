import asyncio
import os
from motor.motor_asyncio import AsyncIOMotorClient


async def apply_schema_validation() -> None:
    mongo_url = os.environ.get("MONGO_URL")
    db_name = os.environ.get("DB_NAME")

    if not mongo_url or not db_name:
        raise EnvironmentError("MONGO_URL and DB_NAME must be set")

    client = AsyncIOMotorClient(mongo_url)
    db = client[db_name]

    # Default to strict enforcement; override via env if needed.
    validation_action = os.environ.get("MONGO_VALIDATION_ACTION", "error")
    validation_level = os.environ.get("MONGO_VALIDATION_LEVEL", "strict")

    await db.command({
        "collMod": "users",
        "validator": {
            "$jsonSchema": {
                "bsonType": "object",
                "required": ["email", "password", "role", "created_at"],
                "properties": {
                    "email": {"bsonType": "string"},
                    "password": {"bsonType": "string"},
                    "role": {"enum": ["buyer", "seller", "admin"]},
                    "phone": {"bsonType": "string"},
                    "created_at": {"bsonType": "date"}
                }
            }
        },
        "validationAction": validation_action,
        "validationLevel": validation_level
    })

    await db.command({
        "collMod": "orders",
        "validator": {
            "$jsonSchema": {
                "bsonType": "object",
                "required": ["buyer_id", "seller_id", "created_at"],
                "properties": {
                    "buyer_id": {"bsonType": "string"},
                    "seller_id": {"bsonType": "string"},
                    "created_at": {"bsonType": "date"}
                }
            }
        },
        "validationAction": validation_action,
        "validationLevel": validation_level
    })

    client.close()


def main() -> None:
    asyncio.run(apply_schema_validation())


if __name__ == "__main__":
    main()
