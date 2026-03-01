"""
Migration Script: Fix Platform Wallet ID
=========================================
This script fixes the platform wallet ID mismatch between seed_admin.py and server.py.
It updates the wallet ID from "PLATFORM_WALLET" (uppercase) to "platform_wallet" (lowercase).

Usage:
    python fix_platform_wallet_id.py
"""

import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime
import os
from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL')
db_name = os.environ.get('DB_NAME', 'pet')

if not mongo_url:
    print("❌ Error: MONGO_URL not found in .env file")
    exit(1)

client = AsyncIOMotorClient(mongo_url)
db = client[db_name]

OLD_PLATFORM_WALLET_ID = "PLATFORM_WALLET"
NEW_PLATFORM_WALLET_ID = "platform_wallet"


async def fix_platform_wallet():
    """Fix platform wallet ID from uppercase to lowercase"""
    print("\n" + "="*60)
    print("FIXING PLATFORM WALLET ID")
    print("="*60)
    
    try:
        # Check if old wallet exists
        old_wallet = await db.wallets.find_one({'user_id': OLD_PLATFORM_WALLET_ID})
        
        if not old_wallet:
            print("ℹ️  No wallet with ID 'PLATFORM_WALLET' found.")
            
            # Check if new wallet exists
            new_wallet = await db.wallets.find_one({'user_id': NEW_PLATFORM_WALLET_ID})
            if new_wallet:
                print("✅ Platform wallet already has correct ID: 'platform_wallet'")
                print(f"   Balance: KES {new_wallet.get('balance', 0):.2f}")
                print(f"   Total Earned: KES {new_wallet.get('total_earned', 0):.2f}")
            else:
                print("⚠️  No platform wallet found at all!")
                print("   Creating new platform wallet...")
                
                platform_wallet = {
                    'user_id': NEW_PLATFORM_WALLET_ID,
                    'balance': 0.0,
                    'total_earned': 0.0,
                    'total_withdrawn': 0.0,
                    'pending_balance': 0.0,
                    'pending_deductions': 0.0,
                    'created_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow()
                }
                
                await db.wallets.insert_one(platform_wallet)
                print("✅ New platform wallet created with ID: 'platform_wallet'")
            
            return
        
        # Old wallet exists - need to migrate
        print(f"📋 Found old platform wallet:")
        print(f"   ID: {OLD_PLATFORM_WALLET_ID}")
        print(f"   Balance: KES {old_wallet.get('balance', 0):.2f}")
        print(f"   Total Earned: KES {old_wallet.get('total_earned', 0):.2f}")
        print(f"   Pending: KES {old_wallet.get('pending_balance', 0):.2f}")
        
        # Check if new wallet already exists
        new_wallet = await db.wallets.find_one({'user_id': NEW_PLATFORM_WALLET_ID})
        
        if new_wallet:
            print("\n⚠️  WARNING: Both old and new platform wallets exist!")
            print(f"\n   Old wallet (PLATFORM_WALLET):")
            print(f"      Balance: KES {old_wallet.get('balance', 0):.2f}")
            print(f"   New wallet (platform_wallet):")
            print(f"      Balance: KES {new_wallet.get('balance', 0):.2f}")
            
            print("\n❓ Which wallet should we keep?")
            print("   1. Merge old into new (keep platform_wallet, add old balance)")
            print("   2. Update old to new ID (rename PLATFORM_WALLET -> platform_wallet)")
            print("   3. Delete old wallet (keep only platform_wallet)")
            print("   4. Cancel (do nothing)")
            
            choice = input("\nEnter choice (1-4): ").strip()
            
            if choice == '1':
                # Merge old into new
                combined_balance = old_wallet.get('balance', 0) + new_wallet.get('balance', 0)
                combined_earned = old_wallet.get('total_earned', 0) + new_wallet.get('total_earned', 0)
                combined_pending = old_wallet.get('pending_balance', 0) + new_wallet.get('pending_balance', 0)
                
                await db.wallets.update_one(
                    {'user_id': NEW_PLATFORM_WALLET_ID},
                    {
                        '$set': {
                            'balance': combined_balance,
                            'total_earned': combined_earned,
                            'pending_balance': combined_pending,
                            'updated_at': datetime.utcnow()
                        }
                    }
                )
                
                await db.wallets.delete_one({'user_id': OLD_PLATFORM_WALLET_ID})
                
                print(f"\n✅ Merged successfully!")
                print(f"   New balance: KES {combined_balance:.2f}")
                print(f"   Total earned: KES {combined_earned:.2f}")
                
            elif choice == '2':
                # Rename old to new
                await db.wallets.delete_one({'user_id': NEW_PLATFORM_WALLET_ID})
                await db.wallets.update_one(
                    {'user_id': OLD_PLATFORM_WALLET_ID},
                    {'$set': {'user_id': NEW_PLATFORM_WALLET_ID, 'updated_at': datetime.utcnow()}}
                )
                print("\n✅ Renamed old wallet to new ID successfully!")
                
            elif choice == '3':
                # Delete old wallet
                await db.wallets.delete_one({'user_id': OLD_PLATFORM_WALLET_ID})
                print("\n✅ Deleted old wallet successfully!")
                
            else:
                print("\n❌ Cancelled - no changes made")
                return
        
        else:
            # Simply rename the old wallet
            print("\n🔄 Updating wallet ID...")
            
            await db.wallets.update_one(
                {'user_id': OLD_PLATFORM_WALLET_ID},
                {'$set': {'user_id': NEW_PLATFORM_WALLET_ID, 'updated_at': datetime.utcnow()}}
            )
            
            print("✅ Platform wallet ID updated successfully!")
            print(f"   Old ID: {OLD_PLATFORM_WALLET_ID}")
            print(f"   New ID: {NEW_PLATFORM_WALLET_ID}")
        
        # Update transactions if any reference the old ID
        print("\n🔄 Updating transactions...")
        txn_result = await db.transactions.update_many(
            {'user_id': OLD_PLATFORM_WALLET_ID},
            {'$set': {'user_id': NEW_PLATFORM_WALLET_ID}}
        )
        if txn_result.modified_count > 0:
            print(f"✅ Updated {txn_result.modified_count} transactions")
        else:
            print("ℹ️  No transactions to update")
        
        # Update withdrawals if any reference the old ID
        print("🔄 Updating withdrawals...")
        wd_result = await db.withdrawals.update_many(
            {'user_id': OLD_PLATFORM_WALLET_ID},
            {'$set': {'user_id': NEW_PLATFORM_WALLET_ID}}
        )
        if wd_result.modified_count > 0:
            print(f"✅ Updated {wd_result.modified_count} withdrawals")
        else:
            print("ℹ️  No withdrawals to update")
        
        print("\n" + "="*60)
        print("MIGRATION COMPLETED SUCCESSFULLY!")
        print("="*60)
        print("\n✅ Platform wallet is now using the correct ID: 'platform_wallet'")
        print("✅ All transactions and withdrawals updated")
        print("\nYou can now restart your backend server.")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.close()


if __name__ == "__main__":
    print("🐾 PetSoko Platform Wallet ID Migration")
    print("="*60)
    
    # Check if .env exists
    env_path = Path(__file__).parent / '.env'
    if not env_path.exists():
        print("❌ Error: .env file not found")
        print("\nPlease ensure backend/.env file exists")
        exit(1)
    
    asyncio.run(fix_platform_wallet())
