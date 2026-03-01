"""
Test Backend Connection and Database
This script checks if the backend can connect to MongoDB and if all required environment variables are set.
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
import asyncio

# Load environment variables
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

async def test_connection():
    print("=" * 60)
    print("  PetSoko Backend Connection Test")
    print("=" * 60)
    print()
    
    # Check environment variables
    print("1. Checking Environment Variables...")
    required_vars = ['MONGO_URL', 'DB_NAME']
    optional_vars = ['JWT_SECRET', 'CLOUDINARY_CLOUD_NAME', 'CLOUDINARY_API_KEY']
    
    all_set = True
    for var in required_vars:
        value = os.environ.get(var)
        if value:
            # Mask sensitive data
            if 'URL' in var or 'SECRET' in var:
                masked = value[:10] + '...' + value[-10:] if len(value) > 20 else '***'
                print(f"   ✓ {var}: {masked}")
            else:
                print(f"   ✓ {var}: {value}")
        else:
            print(f"   ✗ {var}: NOT SET (REQUIRED)")
            all_set = False
    
    print()
    for var in optional_vars:
        value = os.environ.get(var)
        if value:
            print(f"   ✓ {var}: Set")
        else:
            print(f"   ⚠ {var}: Not set (Optional)")
    
    if not all_set:
        print()
        print("ERROR: Required environment variables are missing!")
        print("Please check your .env file in the backend directory.")
        return False
    
    print()
    print("2. Testing MongoDB Connection...")
    
    try:
        mongo_url = os.environ['MONGO_URL']
        db_name = os.environ['DB_NAME']
        
        # Create client
        client = AsyncIOMotorClient(mongo_url, serverSelectionTimeoutMS=5000)
        
        # Test connection
        await client.admin.command('ping')
        print(f"   ✓ Connected to MongoDB successfully!")
        
        # Get database
        db = client[db_name]
        
        # List collections
        collections = await db.list_collection_names()
        print(f"   ✓ Database: {db_name}")
        print(f"   ✓ Collections found: {len(collections)}")
        
        if collections:
            print(f"      Collections: {', '.join(collections[:5])}")
            if len(collections) > 5:
                print(f"      ... and {len(collections) - 5} more")
        
        # Test write operation
        print()
        print("3. Testing Database Operations...")
        test_collection = db['_connection_test']
        
        # Insert test document
        result = await test_collection.insert_one({'test': True, 'timestamp': 'test'})
        print(f"   ✓ Write test successful (ID: {result.inserted_id})")
        
        # Read test document
        doc = await test_collection.find_one({'_id': result.inserted_id})
        print(f"   ✓ Read test successful")
        
        # Delete test document
        await test_collection.delete_one({'_id': result.inserted_id})
        print(f"   ✓ Delete test successful")
        
        # Close connection
        client.close()
        
        print()
        print("=" * 60)
        print("  All Tests Passed! ✓")
        print("=" * 60)
        print()
        print("Your backend is ready to start!")
        print("Run: python -m uvicorn server:app --reload --host 0.0.0.0 --port 8000")
        print()
        
        return True
        
    except Exception as e:
        print(f"   ✗ Error: {str(e)}")
        print()
        print("=" * 60)
        print("  Connection Test Failed")
        print("=" * 60)
        print()
        print("Possible issues:")
        print("1. MongoDB is not running")
        print("2. MONGO_URL is incorrect")
        print("3. Network connectivity issues")
        print("4. Firewall blocking connection")
        print()
        print("If using MongoDB Atlas:")
        print("- Check if your IP is whitelisted")
        print("- Verify username and password")
        print("- Ensure cluster is running")
        print()
        print(f"Error details: {e}")
        return False

if __name__ == "__main__":
    result = asyncio.run(test_connection())
    sys.exit(0 if result else 1)
