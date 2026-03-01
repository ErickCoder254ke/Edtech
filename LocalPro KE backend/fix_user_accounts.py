"""
Fix User Accounts Script

This script checks all user accounts for missing required fields
and repairs them to prevent 500 errors during login.

Usage:
    python fix_user_accounts.py                # Check only (dry run)
    python fix_user_accounts.py --fix          # Check and fix issues
"""

import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime
import os
from dotenv import load_dotenv
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL')
db_name = os.environ.get('DB_NAME', 'pet')

if not mongo_url:
    print("❌ Error: MONGO_URL not found in .env file")
    sys.exit(1)

client = AsyncIOMotorClient(mongo_url)
db = client[db_name]


async def check_and_fix_users():
    """Check and optionally fix user accounts"""
    try:
        # Parse command line arguments
        args = sys.argv[1:]
        fix_mode = '--fix' in args
        
        print("=" * 80)
        print("🔍 CHECKING USER ACCOUNTS")
        print("=" * 80)
        print(f"Mode: {'FIX' if fix_mode else 'CHECK ONLY (DRY RUN)'}")
        print()
        
        # Get all users
        users = await db.users.find({}).to_list(length=None)
        
        if not users:
            print("⚠️  No users found in database")
            print("\nRun one of these scripts to create users:")
            print("  python seed_admin.py --with-sample")
            print("  python seed_data.py")
            return
        
        print(f"Found {len(users)} users in database")
        print()
        
        # Required fields
        required_fields = {
            'name': 'Unknown User',
            'email': None,  # Cannot have default
            'password': None,  # Cannot have default
            'phone': '+254700000000',
            'role': 'buyer',
            'created_at': datetime.utcnow()
        }
        
        issues_found = []
        
        # Check each user
        for i, user in enumerate(users, 1):
            user_id = str(user.get('_id', 'unknown'))
            email = user.get('email', f'user_{i}@unknown.com')
            
            print(f"\n{'='*80}")
            print(f"User {i}/{len(users)}: {email}")
            print(f"User ID: {user_id}")
            print(f"{'='*80}")
            
            # Check for missing fields
            missing_fields = []
            for field, default_value in required_fields.items():
                if field not in user:
                    missing_fields.append(field)
                    status = "❌ MISSING"
                    issues_found.append({
                        'user_id': user_id,
                        'email': email,
                        'field': field,
                        'default': default_value
                    })
                else:
                    value = user[field]
                    if value is None:
                        status = f"⚠️  NULL"
                        issues_found.append({
                            'user_id': user_id,
                            'email': email,
                            'field': field,
                            'default': default_value
                        })
                    else:
                        status = "✅ OK"
                
                # Display field status
                if status != "✅ OK":
                    print(f"  {field:<20} {status:<15} (default: {default_value})")
                else:
                    print(f"  {field:<20} {status}")
            
            # Check password format
            if 'password' in user and user['password']:
                pwd = user['password']
                if isinstance(pwd, str) and pwd.startswith('$2'):
                    print(f"  {'password_format':<20} ✅ OK (bcrypt)")
                else:
                    print(f"  {'password_format':<20} ⚠️  INVALID (not bcrypt hash)")
                    issues_found.append({
                        'user_id': user_id,
                        'email': email,
                        'field': 'password_format',
                        'default': None
                    })
        
        # Summary
        print("\n" + "=" * 80)
        print("📊 SUMMARY")
        print("=" * 80)
        print(f"Total users checked: {len(users)}")
        print(f"Issues found: {len(issues_found)}")
        print()
        
        if issues_found:
            print("Issues by type:")
            issue_types = {}
            for issue in issues_found:
                field = issue['field']
                issue_types[field] = issue_types.get(field, 0) + 1
            
            for field, count in issue_types.items():
                print(f"  {field}: {count} user(s)")
            
            print()
            
            if fix_mode:
                print("=" * 80)
                print("🔧 FIXING ISSUES")
                print("=" * 80)
                
                fixed_count = 0
                
                for issue in issues_found:
                    user_id = issue['user_id']
                    field = issue['field']
                    default = issue['default']
                    email = issue['email']
                    
                    # Skip if field cannot have default (email, password)
                    if default is None:
                        if field == 'password':
                            print(f"⚠️  {email}: Cannot auto-fix missing password (manual intervention required)")
                        elif field == 'email':
                            print(f"⚠️  User {user_id}: Cannot auto-fix missing email (manual intervention required)")
                        elif field == 'password_format':
                            print(f"⚠️  {email}: Invalid password format (manual intervention required)")
                        continue
                    
                    # Fix the field
                    try:
                        from bson import ObjectId
                        await db.users.update_one(
                            {'_id': ObjectId(user_id)},
                            {'$set': {field: default}}
                        )
                        print(f"✅ Fixed {email}: Set {field} = {default}")
                        fixed_count += 1
                    except Exception as e:
                        print(f"❌ Failed to fix {email} ({field}): {str(e)}")
                
                print()
                print(f"✅ Fixed {fixed_count} issues")
                
                # Count remaining issues
                remaining = len([i for i in issues_found if i['default'] is None])
                if remaining > 0:
                    print(f"⚠️  {remaining} issues require manual intervention")
                    print("\nUsers with unfixable issues:")
                    for issue in issues_found:
                        if issue['default'] is None:
                            print(f"  - {issue['email']}: missing {issue['field']}")
                    
                    print("\nRecommendation:")
                    print("  1. Delete these users if they're invalid:")
                    print("     await db.users.delete_one({'_id': ObjectId('user_id')})")
                    print("  2. Or manually set the required fields in MongoDB")
            else:
                print("=" * 80)
                print("💡 TO FIX THESE ISSUES")
                print("=" * 80)
                print("Run this script with --fix flag:")
                print("  python fix_user_accounts.py --fix")
                print()
        else:
            print("✅ All user accounts are healthy!")
        
        print("\n" + "=" * 80)
        print("✅ CHECK COMPLETE")
        print("=" * 80)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.close()


if __name__ == "__main__":
    print("🔍 PetSoko User Account Diagnostic Tool")
    print("=" * 80)
    
    # Check if .env exists
    env_path = Path(__file__).parent / '.env'
    if not env_path.exists():
        print("❌ Error: .env file not found")
        print("\nPlease create backend/.env file")
        sys.exit(1)
    
    asyncio.run(check_and_fix_users())
