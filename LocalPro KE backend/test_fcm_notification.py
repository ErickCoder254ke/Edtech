#!/usr/bin/env python3
"""
Test script for FCM HTTP v1 push notifications
Usage: python test_fcm_notification.py <FCM_TOKEN>
Example: python test_fcm_notification.py dXJ1YWxseS1hbmRyb2lkLXRva2Vu...
"""

import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from notification_service import NotificationService, initialize_firebase


def test_fcm_push(fcm_token: str):
    """Test sending a push notification to a specific FCM token"""
    
    print("=" * 70)
    print("  FCM HTTP v1 Push Notification Test")
    print("=" * 70)
    print()
    
    # Initialize Firebase
    try:
        print("📋 Initializing Firebase Admin SDK...")
        initialize_firebase()
        print("✅ Firebase initialized successfully!")
        print()
    except FileNotFoundError as e:
        print(f"❌ ERROR: {e}")
        print()
        print("📝 To fix this:")
        print("   1. Go to https://console.firebase.google.com/")
        print("   2. Select project: churchapp-3efc3")
        print("   3. Go to Settings ⚙️ → Service Accounts")
        print("   4. Click 'Generate New Private Key'")
        print("   5. Save as: backend/firebase-service-account.json")
        print()
        return False
    except Exception as e:
        print(f"❌ ERROR initializing Firebase: {e}")
        return False
    
    # Send test notification
    print(f"📱 Target FCM Token: {fcm_token[:30]}...")
    print()
    print("📤 Sending test notification via FCM HTTP v1...")
    print()
    
    success = NotificationService.send_push_notification(
        fcm_token=fcm_token,
        title='🔥 FCM HTTP v1 Test',
        body='This is a test notification using Firebase Cloud Messaging HTTP v1 API! 🎉',
        data={
            'test': 'true',
            'timestamp': str(os.time.time()) if hasattr(os, 'time') else 'now',
            'source': 'test_fcm_notification.py'
        }
    )
    
    print()
    print("=" * 70)
    
    if success:
        print("✅ SUCCESS! Push notification sent successfully!")
        print()
        print("📱 Check your device for the notification")
        print("   (It may take 5-30 seconds to arrive)")
        print()
        print("🔍 If you don't see it:")
        print("   - Make sure app is installed and logged in")
        print("   - Check notification permissions are granted")
        print("   - Try putting the app in the background")
        print("   - Wait up to 1 minute")
    else:
        print("❌ FAILED! Could not send push notification")
        print()
        print("🔍 Check the logs above for error details")
        print()
        print("Common issues:")
        print("   - Invalid FCM token")
        print("   - Token from different Firebase project")
        print("   - Token expired (user uninstalled app)")
        print("   - Service account permissions issue")
    
    print("=" * 70)
    print()
    
    return success


def main():
    if len(sys.argv) != 2:
        print("Usage: python test_fcm_notification.py <FCM_TOKEN>")
        print()
        print("Example:")
        print("  python test_fcm_notification.py dXJ1YWxseS1hbmRyb2lkLXRva2Vu...")
        print()
        print("How to get an FCM token:")
        print("  1. Install the app on a device")
        print("  2. Login to the app")
        print("  3. Check backend logs for 'FCM token registered'")
        print("  4. Or query the database: db.users.find({ fcm_token: { $exists: true } })")
        sys.exit(1)
    
    fcm_token = sys.argv[1]
    
    # Validate token format (basic check)
    if len(fcm_token) < 20:
        print("❌ ERROR: FCM token seems too short")
        print("   Make sure you copied the full token")
        sys.exit(1)
    
    # Run test
    success = test_fcm_push(fcm_token)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
