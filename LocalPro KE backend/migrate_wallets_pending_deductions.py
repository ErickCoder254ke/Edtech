"""
Migration Script: Add pending_deductions field to existing wallets
Run this once to update all existing wallet documents
"""
import asyncio
import os
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

async def migrate_wallets():
    """Add pending_deductions field to all existing wallets"""
    
    # MongoDB connection
    mongo_url = os.environ['MONGO_URL']
    client = AsyncIOMotorClient(mongo_url)
    db = client[os.environ['DB_NAME']]
    
    print("Starting wallet migration...")
    
    # Update all wallets that don't have pending_deductions field
    result = await db.wallets.update_many(
        {'pending_deductions': {'$exists': False}},
        {'$set': {'pending_deductions': 0.0}}
    )
    
    print(f"✅ Migration complete!")
    print(f"   - Modified {result.modified_count} wallet(s)")
    print(f"   - Matched {result.matched_count} wallet(s)")
    
    # Verify migration
    total_wallets = await db.wallets.count_documents({})
    wallets_with_field = await db.wallets.count_documents({'pending_deductions': {'$exists': True}})
    
    print(f"\nVerification:")
    print(f"   - Total wallets: {total_wallets}")
    print(f"   - Wallets with pending_deductions: {wallets_with_field}")
    
    if total_wallets == wallets_with_field:
        print("   ✅ All wallets successfully migrated!")
    else:
        print(f"   ⚠️  Warning: {total_wallets - wallets_with_field} wallets missing the field")
    
    client.close()

if __name__ == "__main__":
    asyncio.run(migrate_wallets())
