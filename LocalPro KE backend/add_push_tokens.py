import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import os

async def add_push_token_field():
    """Add push_token field to users collection"""
    mongo_url = os.getenv('MONGODB_URI', 'mongodb://localhost:27017')
    client = AsyncIOMotorClient(mongo_url)
    db = client.petsoko
    
    print("Adding push_token field to users collection...")
    
    result = await db.users.update_many(
        {},
        {'$set': {'push_token': None}}
    )
    
    print(f"Updated {result.modified_count} users with push_token field")
    
    print("Creating index on push_token...")
    await db.users.create_index('push_token')
    print("Created index on push_token")
    
    print("\nCreating indexes for notifications collection...")
    await db.notifications.create_index([('user_id', 1), ('created_at', -1)])
    await db.notifications.create_index([('user_id', 1), ('read', 1)])
    print("Created indexes for notifications")
    
    client.close()
    print("\n✅ Migration completed successfully!")

if __name__ == "__main__":
    asyncio.run(add_push_token_field())
