"""
Diagnostic script to check notification system health
Run this to identify why order notifications aren't working
"""
import asyncio
import logging
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from datetime import datetime, timedelta
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# MongoDB connection
MONGODB_URL = os.getenv('MONGODB_URL', 'mongodb://localhost:27017/petsoko')

async def diagnose_notification_system():
    """
    Comprehensive diagnostic check for notification system
    """
    print("\n" + "="*80)
    print("🔍 NOTIFICATION SYSTEM DIAGNOSTIC REPORT")
    print("="*80 + "\n")
    
    try:
        # Connect to MongoDB
        client = AsyncIOMotorClient(MONGODB_URL)
        db = client.get_database()
        print("✅ Connected to MongoDB\n")
        
        # 1. Check Firebase Configuration
        print("📋 1. FIREBASE CONFIGURATION")
        print("-" * 40)
        firebase_json = os.getenv('FIREBASE_SERVICE_ACCOUNT_JSON')
        firebase_path = os.getenv('FIREBASE_SERVICE_ACCOUNT_PATH')
        
        if firebase_json:
            print("✅ FIREBASE_SERVICE_ACCOUNT_JSON is set")
            try:
                import json
                config = json.loads(firebase_json)
                print(f"   Project ID: {config.get('project_id', 'NOT FOUND')}")
                print(f"   Client Email: {config.get('client_email', 'NOT FOUND')}")
                required_fields = ['project_id', 'private_key', 'client_email']
                missing = [f for f in required_fields if f not in config]
                if missing:
                    print(f"❌ Missing fields: {missing}")
                else:
                    print("✅ All required fields present")
            except Exception as e:
                print(f"❌ Error parsing JSON: {e}")
        elif firebase_path and os.path.exists(firebase_path):
            print(f"✅ FIREBASE_SERVICE_ACCOUNT_PATH found: {firebase_path}")
        else:
            print("❌ NO FIREBASE CREDENTIALS FOUND!")
            print("   This is likely why push notifications aren't working.")
            print("   Set FIREBASE_SERVICE_ACCOUNT_JSON environment variable.")
        
        print()
        
        # 2. Check Users with FCM Tokens
        print("📋 2. USER FCM TOKEN REGISTRATION")
        print("-" * 40)
        total_users = await db.users.count_documents({})
        users_with_tokens = await db.users.count_documents({'fcm_token': {'$exists': True, '$ne': None}})
        
        print(f"Total users: {total_users}")
        print(f"Users with FCM tokens: {users_with_tokens}")
        print(f"Users WITHOUT tokens: {total_users - users_with_tokens}")
        
        if users_with_tokens == 0:
            print("\n❌ NO USERS HAVE FCM TOKENS!")
            print("   Users need to login on a physical device with EAS build")
            print("   to register for push notifications.")
        elif users_with_tokens < total_users:
            print(f"\n⚠️ {total_users - users_with_tokens} users haven't registered for notifications")
        else:
            print("\n✅ All users have FCM tokens registered")
        
        print()
        
        # 3. Check Recent Orders and Their Notifications
        print("📋 3. RECENT ORDERS & NOTIFICATIONS")
        print("-" * 40)
        
        # Get orders from last 7 days
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        recent_orders = await db.orders.find(
            {'created_at': {'$gte': seven_days_ago}}
        ).sort('created_at', -1).limit(10).to_list(10)
        
        print(f"Recent orders (last 7 days): {len(recent_orders)}\n")
        
        if not recent_orders:
            print("⚠️ No recent orders found to analyze")
        else:
            for order in recent_orders:
                order_id = str(order['_id'])
                buyer_id = order.get('buyer_id')
                seller_id = order.get('seller_id')
                created_at = order.get('created_at')
                
                print(f"\nOrder: {order_id}")
                print(f"Created: {created_at}")
                print(f"Buyer ID: {buyer_id}")
                print(f"Seller ID: {seller_id}")
                
                # Check if notifications were created for this order
                buyer_notif = await db.notifications.find_one({
                    'user_id': buyer_id,
                    'data.order_id': order_id,
                    'type': 'ORDER_PLACED'
                })
                
                seller_notif = await db.notifications.find_one({
                    'user_id': seller_id,
                    'data.order_id': order_id,
                    'type': 'ORDER_CREATED'
                })
                
                # Check if users have FCM tokens
                buyer = await db.users.find_one({'_id': ObjectId(buyer_id)}) if buyer_id else None
                seller = await db.users.find_one({'_id': ObjectId(seller_id)}) if seller_id else None
                
                buyer_has_token = bool(buyer and buyer.get('fcm_token')) if buyer else False
                seller_has_token = bool(seller and seller.get('fcm_token')) if seller else False
                
                # Report findings
                print("\n  Buyer Notification:")
                if buyer_notif:
                    print(f"    ✅ Database notification created")
                    print(f"    FCM Token: {'✅ Yes' if buyer_has_token else '❌ No - PUSH NOT SENT'}")
                else:
                    print(f"    ❌ NO DATABASE NOTIFICATION FOUND!")
                    print(f"    This indicates the notification creation code didn't run")
                
                print("  Seller Notification:")
                if seller_notif:
                    print(f"    ✅ Database notification created")
                    print(f"    FCM Token: {'✅ Yes' if seller_has_token else '❌ No - PUSH NOT SENT'}")
                else:
                    print(f"    ❌ NO DATABASE NOTIFICATION FOUND!")
                    print(f"    This indicates the notification creation code didn't run")
                
                print("  " + "-" * 35)
        
        print()
        
        # 4. Check Total Notifications
        print("📋 4. NOTIFICATION STATISTICS")
        print("-" * 40)
        total_notifications = await db.notifications.count_documents({})
        order_created_notifs = await db.notifications.count_documents({'type': 'ORDER_CREATED'})
        order_placed_notifs = await db.notifications.count_documents({'type': 'ORDER_PLACED'})
        
        print(f"Total notifications in database: {total_notifications}")
        print(f"ORDER_CREATED notifications: {order_created_notifs}")
        print(f"ORDER_PLACED notifications: {order_placed_notifs}")
        
        if total_notifications == 0:
            print("\n❌ NO NOTIFICATIONS IN DATABASE!")
            print("   This means the notification creation code is not running.")
        
        print()
        
        # 5. Summary and Recommendations
        print("="*80)
        print("📊 DIAGNOSIS SUMMARY")
        print("="*80 + "\n")
        
        issues_found = []
        
        if not firebase_json and not (firebase_path and os.path.exists(str(firebase_path))):
            issues_found.append("❌ Firebase credentials not configured - Push notifications will NOT work")
        
        if users_with_tokens == 0:
            issues_found.append("❌ No users have FCM tokens - Users need to login on physical device")
        
        if len(recent_orders) > 0:
            orders_with_notifs = sum(1 for order in recent_orders 
                                    if db.notifications.find_one({'data.order_id': str(order['_id'])}))
            if orders_with_notifs == 0:
                issues_found.append("❌ Orders created but NO notifications in database - Code not executing")
        
        if not issues_found:
            print("✅ No critical issues found!")
            print("   The notification system appears to be configured correctly.")
            print("   If users still aren't receiving notifications:")
            print("   - Check backend logs for Firebase initialization errors")
            print("   - Verify users have notifications enabled in device settings")
            print("   - Test with the /notifications/test-push endpoint")
        else:
            print("🚨 ISSUES FOUND:\n")
            for i, issue in enumerate(issues_found, 1):
                print(f"{i}. {issue}")
            
            print("\n📝 RECOMMENDED ACTIONS:\n")
            
            if "Firebase credentials" in str(issues_found):
                print("1. Add Firebase credentials:")
                print("   - Go to https://console.firebase.google.com/")
                print("   - Select your project")
                print("   - Settings → Service Accounts")
                print("   - Generate New Private Key")
                print("   - Add JSON content to FIREBASE_SERVICE_ACCOUNT_JSON env var")
                print()
            
            if "FCM tokens" in str(issues_found):
                print("2. Register FCM tokens:")
                print("   - Users must login on a physical device")
                print("   - App must be EAS build (not Expo Go)")
                print("   - Check frontend logs for token registration errors")
                print()
            
            if "notifications in database" in str(issues_found):
                print("3. Check order creation code:")
                print("   - Verify backend/server.py lines 2079-2111 are executing")
                print("   - Check backend logs for errors during order creation")
                print("   - Ensure create_notification is being called")
                print()
        
        print("="*80)
        print("🔍 Diagnostic complete!")
        print("="*80 + "\n")
        
        client.close()
        
    except Exception as e:
        logger.error(f"Error running diagnostic: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(diagnose_notification_system())
