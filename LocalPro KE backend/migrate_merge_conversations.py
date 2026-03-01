"""
Migration script to merge duplicate conversations between the same user pairs.
Keeps the oldest conversation and migrates messages from duplicates.
"""
import asyncio
import os
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime
from dotenv import load_dotenv
from pathlib import Path
from collections import defaultdict

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / 'backend.env')

async def merge_duplicate_conversations():
    """Merge conversations between the same user pairs"""

    # Connect to MongoDB
    mongo_url = os.environ.get('MONGO_URL')
    db_name = os.environ.get('DB_NAME')

    if not mongo_url:
        print("❌ Error: MONGO_URL environment variable not found!")
        print("   Please create a .env file in the backend directory with:")
        print("   MONGO_URL=your_mongodb_connection_string")
        print("   DB_NAME=your_database_name")
        return

    if not db_name:
        print("❌ Error: DB_NAME environment variable not found!")
        return

    client = AsyncIOMotorClient(mongo_url)
    db = client[db_name]
    
    print("🔍 Fetching all conversations...")
    conversations = await db.conversations.find({}).to_list(None)
    
    print(f"📊 Found {len(conversations)} total conversations")
    
    # Group conversations by user pair (normalized so order doesn't matter)
    user_pairs = defaultdict(list)
    
    for conv in conversations:
        buyer_id = conv.get('buyer_id')
        seller_id = conv.get('seller_id')
        
        # Create normalized key (sorted so buyer/seller order doesn't matter)
        pair_key = tuple(sorted([buyer_id, seller_id]))
        user_pairs[pair_key].append(conv)
    
    # Find duplicates
    duplicates_found = 0
    conversations_merged = 0
    messages_migrated = 0
    
    for pair_key, pair_conversations in user_pairs.items():
        if len(pair_conversations) > 1:
            duplicates_found += 1
            print(f"\n🔄 Found {len(pair_conversations)} conversations between users: {pair_key}")
            
            # Sort by created_at to keep the oldest
            pair_conversations.sort(key=lambda x: x.get('created_at', ''))
            
            primary_conv = pair_conversations[0]
            duplicate_convs = pair_conversations[1:]
            
            print(f"   ✅ Keeping conversation: {primary_conv['id']}")
            print(f"   🗑️  Merging {len(duplicate_convs)} duplicate(s)")
            
            # Migrate messages from duplicates to primary
            for dup_conv in duplicate_convs:
                # Find all messages in this duplicate conversation
                messages = await db.messages.find({'conversation_id': dup_conv['id']}).to_list(None)
                
                if messages:
                    print(f"      📨 Migrating {len(messages)} messages from {dup_conv['id']}")
                    
                    # Update all messages to point to primary conversation
                    for msg in messages:
                        await db.messages.update_one(
                            {'_id': msg['_id']},
                            {'$set': {'conversation_id': primary_conv['id']}}
                        )
                        messages_migrated += 1
                
                # Delete the duplicate conversation
                await db.conversations.delete_one({'id': dup_conv['id']})
                conversations_merged += 1
                print(f"      ✅ Deleted duplicate conversation: {dup_conv['id']}")
            
            # Update primary conversation's last_message info if needed
            all_messages = await db.messages.find(
                {'conversation_id': primary_conv['id']}
            ).sort('timestamp', -1).limit(1).to_list(1)
            
            if all_messages:
                last_msg = all_messages[0]
                await db.conversations.update_one(
                    {'id': primary_conv['id']},
                    {
                        '$set': {
                            'last_message': last_msg.get('content_filtered', last_msg.get('content_original')),
                            'last_message_time': last_msg.get('timestamp')
                        }
                    }
                )
    
    print("\n" + "="*60)
    print("✨ Migration Complete!")
    print(f"📊 User pairs with duplicates: {duplicates_found}")
    print(f"🗑️  Conversations merged: {conversations_merged}")
    print(f"📨 Messages migrated: {messages_migrated}")
    print("="*60)
    
    # Show final count
    final_count = await db.conversations.count_documents({})
    print(f"📈 Final conversation count: {final_count}")
    
    client.close()

if __name__ == "__main__":
    print("🚀 Starting conversation deduplication migration...")
    asyncio.run(merge_duplicate_conversations())
