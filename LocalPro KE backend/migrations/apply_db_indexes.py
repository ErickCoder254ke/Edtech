import asyncio
import os
from motor.motor_asyncio import AsyncIOMotorClient


async def apply_indexes() -> None:
    mongo_url = os.environ.get("MONGO_URL")
    db_name = os.environ.get("DB_NAME")

    if not mongo_url or not db_name:
        raise EnvironmentError("MONGO_URL and DB_NAME must be set")

    client = AsyncIOMotorClient(mongo_url)
    db = client[db_name]

    # Unique indexes (integrity)
    await db.users.create_index("email", unique=True, name="users_email_unique")
    await db.users.create_index("phone", unique=True, sparse=True, name="users_phone_unique")
    await db.wallets.create_index("user_id", unique=True, name="wallets_user_id_unique")
    await db.seller_profiles.create_index("user_id", unique=True, name="seller_profiles_user_id_unique")

    # Performance indexes (query speed)
    await db.orders.create_index("buyer_id", name="orders_buyer_id")
    await db.orders.create_index("seller_id", name="orders_seller_id")
    await db.orders.create_index([("payment_status", 1), ("created_at", -1)], name="orders_payment_status_created_at")

    await db.transactions.create_index([("user_id", 1), ("created_at", -1)], name="transactions_user_created_at")

    await db.service_listings.create_index("seller_id", name="service_listings_seller_id")
    await db.service_listings.create_index([("status", 1), ("created_at", -1)], name="service_listings_status_created_at")

    await db.reviews.create_index("seller_id", name="reviews_seller_id")

    await db.conversations.create_index("buyer_id", name="conversations_buyer_id")
    await db.conversations.create_index("seller_id", name="conversations_seller_id")

    await db.messages.create_index([("conversation_id", 1), ("timestamp", -1)], name="messages_conversation_timestamp")

    client.close()


def main() -> None:
    asyncio.run(apply_indexes())


if __name__ == "__main__":
    main()
