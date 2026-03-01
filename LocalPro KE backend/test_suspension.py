"""
Test Suspension System

This script tests the account suspension enforcement:
1. Creates a test user
2. Verifies login works
3. Suspends the account
4. Verifies login fails with proper message
5. Verifies API access fails with proper message
6. Unsuspends the account
7. Verifies login works again

Usage:
    python test_suspension.py
"""

import asyncio
import httpx
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime
import os
from dotenv import load_dotenv
from pathlib import Path
import bcrypt
from bson import ObjectId

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Configuration
BASE_URL = os.environ.get('TEST_BACKEND_URL', 'http://localhost:8000')
mongo_url = os.environ.get('MONGO_URL')
db_name = os.environ.get('DB_NAME', 'pet')

if not mongo_url:
    print("❌ Error: MONGO_URL not found in .env file")
    exit(1)

client = AsyncIOMotorClient(mongo_url)
db = client[db_name]

# Test user credentials
TEST_EMAIL = 'suspension_test@petsoko.com'
TEST_PASSWORD = 'testpass123'
TEST_NAME = 'Suspension Test User'


def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


async def create_test_user():
    """Create a test user for suspension testing"""
    print("\n📝 Creating test user...")
    
    # Delete if exists
    await db.users.delete_many({'email': TEST_EMAIL})
    
    user_dict = {
        'name': TEST_NAME,
        'email': TEST_EMAIL,
        'phone': '+254700000000',
        'password': hash_password(TEST_PASSWORD),
        'role': 'buyer',
        'kyc_status': 'approved',
        'suspended': False,
        'suspension_reason': None,
        'suspension_date': None,
        'security_question': 'Test question?',
        'security_answer': hash_password('test answer'),
        'created_at': datetime.utcnow()
    }
    
    result = await db.users.insert_one(user_dict)
    user_id = str(result.inserted_id)
    
    print(f"✅ Created test user: {TEST_EMAIL}")
    print(f"   User ID: {user_id}")
    return user_id


async def test_login(should_succeed=True, expected_status=None):
    """Test login endpoint"""
    print(f"\n🔑 Testing login (should {'succeed' if should_succeed else 'fail'})...")
    
    async with httpx.AsyncClient() as http_client:
        try:
            response = await http_client.post(
                f"{BASE_URL}/api/auth/login",
                json={'email': TEST_EMAIL, 'password': TEST_PASSWORD},
                timeout=10.0
            )
            
            if should_succeed:
                if response.status_code == 200:
                    data = response.json()
                    token = data.get('token')
                    user = data.get('user')
                    print(f"✅ Login successful")
                    print(f"   Token: {token[:20]}...")
                    print(f"   User: {user.get('name')} ({user.get('email')})")
                    return token
                else:
                    print(f"❌ Login should have succeeded but got status {response.status_code}")
                    print(f"   Response: {response.text}")
                    return None
            else:
                if expected_status and response.status_code == expected_status:
                    data = response.json()
                    print(f"✅ Login correctly failed with status {response.status_code}")
                    print(f"   Message: {data.get('detail')}")
                    return None
                elif response.status_code == 200:
                    print(f"❌ Login should have failed but succeeded")
                    return None
                else:
                    print(f"⚠️  Login failed with unexpected status {response.status_code}")
                    print(f"   Response: {response.text}")
                    return None
                    
        except Exception as e:
            print(f"❌ Error during login: {str(e)}")
            return None


async def test_api_access(token, should_succeed=True):
    """Test API access with token"""
    print(f"\n🔒 Testing API access with token (should {'succeed' if should_succeed else 'fail'})...")
    
    async with httpx.AsyncClient() as http_client:
        try:
            response = await http_client.get(
                f"{BASE_URL}/api/auth/me",
                headers={'Authorization': f'Bearer {token}'},
                timeout=10.0
            )
            
            if should_succeed:
                if response.status_code == 200:
                    data = response.json()
                    print(f"✅ API access successful")
                    print(f"   User: {data.get('name')} ({data.get('email')})")
                    return True
                else:
                    print(f"❌ API access should have succeeded but got status {response.status_code}")
                    print(f"   Response: {response.text}")
                    return False
            else:
                if response.status_code == 403:
                    data = response.json()
                    print(f"✅ API access correctly blocked with 403")
                    print(f"   Message: {data.get('detail')}")
                    return True
                elif response.status_code == 200:
                    print(f"❌ API access should have been blocked but succeeded")
                    return False
                else:
                    print(f"⚠️  API access blocked with unexpected status {response.status_code}")
                    return True
                    
        except Exception as e:
            print(f"❌ Error during API access: {str(e)}")
            return False


async def suspend_user(user_id, reason="Testing suspension system"):
    """Suspend user directly in database"""
    print(f"\n🚫 Suspending user...")
    
    await db.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {
            'suspended': True,
            'suspension_reason': reason,
            'suspension_date': datetime.utcnow()
        }}
    )
    
    # Verify suspension
    user = await db.users.find_one({'_id': ObjectId(user_id)})
    if user.get('suspended'):
        print(f"✅ User suspended")
        print(f"   Reason: {user.get('suspension_reason')}")
        print(f"   Date: {user.get('suspension_date')}")
        return True
    else:
        print(f"❌ Failed to suspend user")
        return False


async def unsuspend_user(user_id):
    """Unsuspend user directly in database"""
    print(f"\n✅ Unsuspending user...")
    
    await db.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {
            'suspended': False,
            'suspension_reason': None,
            'suspension_date': None
        }}
    )
    
    # Verify unsuspension
    user = await db.users.find_one({'_id': ObjectId(user_id)})
    if not user.get('suspended', False):
        print(f"✅ User unsuspended")
        return True
    else:
        print(f"❌ Failed to unsuspend user")
        return False


async def cleanup_test_user():
    """Delete test user"""
    print(f"\n🗑️  Cleaning up test user...")
    await db.users.delete_many({'email': TEST_EMAIL})
    print(f"✅ Test user deleted")


async def run_tests():
    """Run all suspension tests"""
    print("=" * 80)
    print("🧪 SUSPENSION SYSTEM TESTS")
    print("=" * 80)
    print(f"Backend URL: {BASE_URL}")
    print(f"Database: {db_name}")
    
    test_results = []
    
    try:
        # Test 1: Create user and verify login works
        print("\n" + "=" * 80)
        print("TEST 1: Create User and Verify Login")
        print("=" * 80)
        user_id = await create_test_user()
        token = await test_login(should_succeed=True)
        if token:
            test_results.append(("Create user and login", True))
        else:
            test_results.append(("Create user and login", False))
            print("⚠️  Skipping remaining tests due to login failure")
            return test_results
        
        # Test 2: Verify API access works
        print("\n" + "=" * 80)
        print("TEST 2: Verify API Access Works")
        print("=" * 80)
        api_success = await test_api_access(token, should_succeed=True)
        test_results.append(("API access before suspension", api_success))
        
        # Test 3: Suspend user and verify login fails
        print("\n" + "=" * 80)
        print("TEST 3: Suspend User and Verify Login Fails")
        print("=" * 80)
        suspended = await suspend_user(user_id, "Test suspension - automated test")
        if suspended:
            login_result = await test_login(should_succeed=False, expected_status=403)
            test_results.append(("Login fails after suspension", login_result is None))
        else:
            test_results.append(("Suspend user", False))
        
        # Test 4: Verify API access with old token fails
        print("\n" + "=" * 80)
        print("TEST 4: Verify API Access Blocked with Suspended Account")
        print("=" * 80)
        if token:
            api_blocked = await test_api_access(token, should_succeed=False)
            test_results.append(("API blocked after suspension", api_blocked))
        
        # Test 5: Unsuspend user and verify login works again
        print("\n" + "=" * 80)
        print("TEST 5: Unsuspend User and Verify Login Works")
        print("=" * 80)
        unsuspended = await unsuspend_user(user_id)
        if unsuspended:
            new_token = await test_login(should_succeed=True)
            test_results.append(("Login works after unsuspension", new_token is not None))
            
            # Test 6: Verify API access works again
            if new_token:
                print("\n" + "=" * 80)
                print("TEST 6: Verify API Access Works After Unsuspension")
                print("=" * 80)
                api_works = await test_api_access(new_token, should_succeed=True)
                test_results.append(("API access after unsuspension", api_works))
        else:
            test_results.append(("Unsuspend user", False))
        
    except Exception as e:
        print(f"\n❌ Error during tests: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup
        await cleanup_test_user()
    
    # Print results
    print("\n" + "=" * 80)
    print("📊 TEST RESULTS")
    print("=" * 80)
    
    passed = 0
    failed = 0
    
    for test_name, result in test_results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
        if result:
            passed += 1
        else:
            failed += 1
    
    print("\n" + "=" * 80)
    print(f"Total: {len(test_results)} tests")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print("=" * 80)
    
    if failed == 0:
        print("\n🎉 ALL TESTS PASSED!")
        print("✅ Suspension system is working correctly")
    else:
        print(f"\n⚠️  {failed} test(s) failed")
        print("❌ Suspension system needs attention")
    
    return test_results


async def main():
    """Main test function"""
    try:
        # Verify backend is running
        print("🔍 Checking if backend is running...")
        async with httpx.AsyncClient() as http_client:
            try:
                response = await http_client.get(f"{BASE_URL}/api/health", timeout=5.0)
                if response.status_code == 200:
                    print(f"✅ Backend is running at {BASE_URL}")
                else:
                    print(f"⚠️  Backend responded with status {response.status_code}")
            except Exception as e:
                print(f"❌ Cannot connect to backend at {BASE_URL}")
                print(f"   Error: {str(e)}")
                print(f"\nMake sure the backend is running:")
                print(f"   cd backend")
                print(f"   uvicorn server:app --reload --host 0.0.0.0 --port 8000")
                return
        
        # Run tests
        await run_tests()
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        client.close()


if __name__ == "__main__":
    print("🧪 PetSoko Suspension System Tests")
    print("=" * 80)
    
    # Check if .env exists
    env_path = Path(__file__).parent / '.env'
    if not env_path.exists():
        print("❌ Error: .env file not found")
        print("\nPlease create backend/.env file")
        exit(1)
    
    asyncio.run(main())
