"""
Migration script to fix pet listing statuses in the database.

This script:
1. Updates all listings with status 'draft' to 'active'
2. Updates all listings with missing status field to 'active'
3. Prints a summary of changes made

Usage:
    python fix_listing_status.py
"""

import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# MongoDB configuration
MONGODB_URL = os.getenv('MONGODB_URL', 'mongodb://localhost:27017')
DATABASE_NAME = os.getenv('DATABASE_NAME', 'petsoko')


async def fix_listing_statuses():
    """Fix pet listing statuses in the database."""
    
    # Connect to MongoDB
    client = AsyncIOMotorClient(MONGODB_URL)
    db = client[DATABASE_NAME]
    
    print("🔄 Starting listing status migration...")
    print(f"📊 Connected to database: {DATABASE_NAME}")
    print("-" * 60)
    
    try:
        # Count total listings
        total_listings = await db.pet_listings.count_documents({})
        print(f"📋 Total listings in database: {total_listings}")
        
        # Count listings with draft status
        draft_count = await db.pet_listings.count_documents({'status': 'draft'})
        print(f"📝 Listings with 'draft' status: {draft_count}")
        
        # Count listings without status field
        missing_status_count = await db.pet_listings.count_documents({'status': {'$exists': False}})
        print(f"❓ Listings with missing status field: {missing_status_count}")
        
        # Count listings with other statuses
        active_count = await db.pet_listings.count_documents({'status': 'active'})
        sold_count = await db.pet_listings.count_documents({'status': 'sold'})
        removed_count = await db.pet_listings.count_documents({'status': 'removed'})
        pending_count = await db.pet_listings.count_documents({'status': 'pending'})
        
        print(f"✅ Listings with 'active' status: {active_count}")
        print(f"💰 Listings with 'sold' status: {sold_count}")
        print(f"🚫 Listings with 'removed' status: {removed_count}")
        print(f"⏳ Listings with 'pending' status: {pending_count}")
        print("-" * 60)
        
        # Update listings with draft status to active
        if draft_count > 0:
            print(f"🔧 Updating {draft_count} listings from 'draft' to 'active'...")
            result = await db.pet_listings.update_many(
                {'status': 'draft'},
                {
                    '$set': {
                        'status': 'active',
                        'updated_at': datetime.utcnow()
                    }
                }
            )
            print(f"   ✓ Updated {result.modified_count} listings")
        
        # Update listings with missing status field to active
        if missing_status_count > 0:
            print(f"🔧 Updating {missing_status_count} listings with missing status to 'active'...")
            result = await db.pet_listings.update_many(
                {'status': {'$exists': False}},
                {
                    '$set': {
                        'status': 'active',
                        'updated_at': datetime.utcnow()
                    }
                }
            )
            print(f"   ✓ Updated {result.modified_count} listings")
        
        print("-" * 60)
        
        # Count after migration
        print("📊 Status after migration:")
        active_count_after = await db.pet_listings.count_documents({'status': 'active'})
        draft_count_after = await db.pet_listings.count_documents({'status': 'draft'})
        missing_status_count_after = await db.pet_listings.count_documents({'status': {'$exists': False}})
        
        print(f"✅ Listings with 'active' status: {active_count_after}")
        print(f"📝 Listings with 'draft' status: {draft_count_after}")
        print(f"❓ Listings with missing status field: {missing_status_count_after}")
        
        print("-" * 60)
        print("✅ Migration completed successfully!")
        
        # Show sample of updated listings
        print("\n📋 Sample of updated listings:")
        updated_listings = db.pet_listings.find({'status': 'active'}).limit(5)
        async for listing in updated_listings:
            print(f"   - {listing.get('breed', 'Unknown')} ({listing.get('species', 'Unknown')}) - Status: {listing.get('status')}")
        
    except Exception as e:
        print(f"❌ Error during migration: {e}")
        raise
    finally:
        # Close connection
        client.close()
        print("\n🔌 Database connection closed")


if __name__ == "__main__":
    print("=" * 60)
    print("  PetSoko - Listing Status Migration")
    print("=" * 60)
    print()
    
    # Run the migration
    asyncio.run(fix_listing_statuses())
    
    print()
    print("=" * 60)
    print("  Migration script finished")
    print("=" * 60)
