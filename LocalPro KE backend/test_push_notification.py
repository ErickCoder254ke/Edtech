#!/usr/bin/env python3
"""
Standalone Push Notification Test Script

This script tests if your Expo push notification setup is working correctly.
It sends a test notification directly to a specified Expo push token.

Usage:
    python test_push_notification.py ExponentPushToken[YOUR_TOKEN_HERE]

Example:
    python test_push_notification.py ExponentPushToken[LZd9eAFR-Y0dYI4pSU8HH4]
"""

import sys
from exponent_server_sdk import (
    DeviceNotRegisteredError,
    PushClient,
    PushMessage,
    PushServerError,
)


def test_push_notification(push_token: str):
    """
    Send a test push notification to verify the setup is working.
    
    Args:
        push_token: The Expo push token to test (format: ExponentPushToken[...])
    
    Returns:
        bool: True if successful, False otherwise
    """
    
    print("=" * 60)
    print("🔔 EXPO PUSH NOTIFICATION TEST")
    print("=" * 60)
    print()
    
    # Validate token format
    if not push_token.startswith("ExponentPushToken["):
        print("❌ ERROR: Invalid token format!")
        print(f"   Expected: ExponentPushToken[...]")
        print(f"   Got: {push_token}")
        return False
    
    print(f"📱 Target Token: {push_token}")
    print()
    
    # Create test message
    try:
        print("📝 Creating push message...")
        message = PushMessage(
            to=push_token,
            title='🧪 Test Notification',
            body='If you see this, push notifications are working correctly! 🎉',
            data={
                'type': 'test',
                'timestamp': str(int(__import__('time').time())),
                'test_id': 'manual_test'
            },
            sound='default',
            badge=1,
            priority='high'
        )
        print("✅ Message created successfully")
        print()
        
    except Exception as e:
        print(f"❌ ERROR creating message: {e}")
        return False
    
    # Send notification
    try:
        print("📤 Sending push notification to Expo Push Service...")
        response = PushClient().publish(message)
        print()
        
        # Check response
        print(f"📊 Response received: {response}")
        print(f"   Response type: {type(response).__name__}")
        print(f"   Status: {getattr(response, 'status', 'unknown')}")
        print()

        if response.is_success():
            print("=" * 60)
            print("✅ SUCCESS! Push notification sent successfully!")
            print("=" * 60)
            print()
            print("📱 Check your device for the notification.")
            print("   Title: 🧪 Test Notification")
            print("   Body: If you see this, push notifications are working...")
            print()
            print("⏰ Note: It may take 5-30 seconds for the notification to arrive.")
            print()
            print("Response details:")
            print(f"   Push Token: {push_token}")
            print(f"   Status: {getattr(response, 'status', 'ok')}")
            if hasattr(response, 'id'):
                print(f"   Ticket ID: {response.id}")
            print()
            return True
        else:
            print("=" * 60)
            print("❌ FAILURE: Push notification failed to send")
            print("=" * 60)
            print()
            print(f"Status: {getattr(response, 'status', 'unknown')}")
            if hasattr(response, 'message'):
                print(f"Message: {response.message}")
            if hasattr(response, 'details'):
                print(f"Details: {response.details}")
            print()
            print("Common error statuses:")
            print("   - DeviceNotRegistered: Token expired, user needs to re-login")
            print("   - MessageTooBig: Notification payload too large")
            print("   - MessageRateExceeded: Too many notifications sent")
            print("   - InvalidCredentials: FCM configuration issue")
            print()
            return False
            
    except DeviceNotRegisteredError:
        print("=" * 60)
        print("❌ FAILURE: Device token is no longer valid")
        print("=" * 60)
        print()
        print("Possible reasons:")
        print("   1. App was uninstalled and reinstalled")
        print("   2. Token has expired")
        print("   3. User cleared app data")
        print()
        print("Solution:")
        print("   1. Have the user logout and login again")
        print("   2. This will generate a new push token")
        print()
        return False
        
    except PushServerError as e:
        print("=" * 60)
        print("❌ FAILURE: Expo Push Server Error")
        print("=" * 60)
        print()
        print(f"Error: {e}")
        print()
        print("Possible reasons:")
        print("   1. Expo push service is down")
        print("   2. Rate limit exceeded")
        print("   3. Invalid token format")
        print()
        print("Check Expo status: https://status.expo.dev")
        print()
        return False
        
    except Exception as e:
        print("=" * 60)
        print("❌ FAILURE: Unexpected error")
        print("=" * 60)
        print()
        print(f"Error: {e}")
        print(f"Type: {type(e).__name__}")
        print()
        import traceback
        print("Traceback:")
        traceback.print_exc()
        print()
        return False


def main():
    """Main entry point for the script."""
    
    if len(sys.argv) != 2:
        print("=" * 60)
        print("🔔 EXPO PUSH NOTIFICATION TEST SCRIPT")
        print("=" * 60)
        print()
        print("Usage:")
        print("   python test_push_notification.py <EXPO_PUSH_TOKEN>")
        print()
        print("Example:")
        print("   python test_push_notification.py ExponentPushToken[LZd9eAFR-Y0dYI4pSU8HH4]")
        print()
        print("To get your token:")
        print("   1. Check backend logs when user logs in")
        print("   2. Look for: 🔔 [PUSH] Token: ExponentPushToken[...]")
        print("   3. Or query database: db.users.find({push_token: {$exists: true}})")
        print()
        sys.exit(1)
    
    push_token = sys.argv[1].strip()
    success = test_push_notification(push_token)
    
    print()
    print("=" * 60)
    
    if success:
        print("✅ TEST PASSED - Push notifications are working!")
        print()
        print("Next steps:")
        print("   1. Verify notification appeared on device")
        print("   2. Test from your backend application")
        print("   3. Monitor backend logs for any issues")
        sys.exit(0)
    else:
        print("❌ TEST FAILED - See error details above")
        print()
        print("Debugging steps:")
        print("   1. Verify token format: ExponentPushToken[...]")
        print("   2. Try getting a fresh token (logout/login)")
        print("   3. Test token at: https://expo.dev/notifications")
        print("   4. Check Expo service status: https://status.expo.dev")
        sys.exit(1)


if __name__ == "__main__":
    main()
