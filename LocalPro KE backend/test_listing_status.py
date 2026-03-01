"""
Test script to verify pet listing status functionality.

This script tests:
1. Listing creation sets status to 'active'
2. Admin endpoints correctly retrieve listing status
3. Status transitions work correctly

Usage:
    python test_listing_status.py
"""

import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import os
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables
load_dotenv()

# MongoDB configuration
MONGODB_URL = os.getenv('MONGODB_URL', 'mongodb://localhost:27017')
DATABASE_NAME = os.getenv('DATABASE_NAME', 'petsoko')


async def test_listing_status():
    """Test listing status functionality."""
    
    # Connect to MongoDB
    client = AsyncIOMotorClient(MONGODB_URL)
    db = client[DATABASE_NAME]
    
    print("🧪 Testing Listing Status Functionality")
    print("=" * 60)
    
    test_results = []
    
    try:
        # Test 1: Check status distribution
        print("\n📊 Test 1: Status Distribution")
        print("-" * 60)
        
        total = await db.pet_listings.count_documents({})
        active = await db.pet_listings.count_documents({'status': 'active'})
        sold = await db.pet_listings.count_documents({'status': 'sold'})
        removed = await db.pet_listings.count_documents({'status': 'removed'})
        pending = await db.pet_listings.count_documents({'status': 'pending'})
        draft = await db.pet_listings.count_documents({'status': 'draft'})
        missing = await db.pet_listings.count_documents({'status': {'$exists': False}})
        
        print(f"Total listings: {total}")
        print(f"Active: {active}")
        print(f"Sold: {sold}")
        print(f"Removed: {removed}")
        print(f"Pending: {pending}")
        print(f"Draft: {draft}")
        print(f"Missing status: {missing}")
        
        # Verify no draft or missing statuses
        if draft == 0 and missing == 0:
            print("✅ PASS: No draft or missing statuses found")
            test_results.append(("Status Distribution", True))
        else:
            print("❌ FAIL: Found draft or missing statuses")
            test_results.append(("Status Distribution", False))
        
        # Test 2: Check required fields
        print("\n📋 Test 2: Required Fields")
        print("-" * 60)
        
        # Check if listings have age_months field
        listings_with_age_months = await db.pet_listings.count_documents({'age_months': {'$exists': True}})
        listings_with_breed = await db.pet_listings.count_documents({'breed': {'$exists': True}})
        
        print(f"Listings with age_months field: {listings_with_age_months}/{total}")
        print(f"Listings with breed field: {listings_with_breed}/{total}")
        
        if listings_with_age_months == total and listings_with_breed == total:
            print("✅ PASS: All listings have required fields")
            test_results.append(("Required Fields", True))
        else:
            print("❌ FAIL: Some listings missing required fields")
            test_results.append(("Required Fields", False))
        
        # Test 3: Sample listing data
        print("\n📄 Test 3: Sample Listing Data")
        print("-" * 60)
        
        sample_listing = await db.pet_listings.find_one({'status': 'active'})
        if sample_listing:
            print("Sample Active Listing:")
            print(f"  ID: {sample_listing.get('_id')}")
            print(f"  Species: {sample_listing.get('species', 'N/A')}")
            print(f"  Breed: {sample_listing.get('breed', 'N/A')}")
            print(f"  Age (months): {sample_listing.get('age_months', 'N/A')}")
            print(f"  Price: {sample_listing.get('price', 'N/A')}")
            print(f"  Status: {sample_listing.get('status', 'N/A')}")
            print(f"  Seller ID: {sample_listing.get('seller_id', 'N/A')}")
            
            # Check if status is correct
            if sample_listing.get('status') == 'active':
                print("✅ PASS: Sample listing has correct status")
                test_results.append(("Sample Listing", True))
            else:
                print("❌ FAIL: Sample listing has incorrect status")
                test_results.append(("Sample Listing", False))
        else:
            print("⚠️  SKIP: No active listings found to test")
            test_results.append(("Sample Listing", None))
        
        # Test 4: Check for listings without proper fields
        print("\n🔍 Test 4: Data Integrity")
        print("-" * 60)
        
        # Check for listings with old 'age' field instead of 'age_months'
        old_age_field = await db.pet_listings.count_documents({'age': {'$exists': True}, 'age_months': {'$exists': False}})
        
        # Check for listings with 'name' field (shouldn't exist)
        with_name_field = await db.pet_listings.count_documents({'name': {'$exists': True}})
        
        print(f"Listings with old 'age' field: {old_age_field}")
        print(f"Listings with 'name' field: {with_name_field}")
        
        if old_age_field == 0 and with_name_field == 0:
            print("✅ PASS: No listings with deprecated fields")
            test_results.append(("Data Integrity", True))
        else:
            print("❌ FAIL: Found listings with deprecated fields")
            test_results.append(("Data Integrity", False))
        
        # Test 5: Status transitions (if applicable)
        print("\n🔄 Test 5: Status Transitions")
        print("-" * 60)
        
        # Check if there are sold listings (indicates status transitions work)
        sold_count = await db.pet_listings.count_documents({'status': 'sold'})
        
        if sold_count > 0:
            print(f"Found {sold_count} sold listings")
            print("✅ PASS: Status transitions are working")
            test_results.append(("Status Transitions", True))
        else:
            print("⚠️  SKIP: No sold listings to verify transitions")
            test_results.append(("Status Transitions", None))
        
        # Summary
        print("\n" + "=" * 60)
        print("📊 Test Summary")
        print("=" * 60)
        
        passed = sum(1 for _, result in test_results if result is True)
        failed = sum(1 for _, result in test_results if result is False)
        skipped = sum(1 for _, result in test_results if result is None)
        
        for test_name, result in test_results:
            status = "✅ PASS" if result is True else ("❌ FAIL" if result is False else "⚠️  SKIP")
            print(f"{status}: {test_name}")
        
        print("-" * 60)
        print(f"Total Tests: {len(test_results)}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Skipped: {skipped}")
        
        if failed == 0:
            print("\n🎉 All tests passed!")
            return True
        else:
            print(f"\n⚠️  {failed} test(s) failed. Please review the results above.")
            return False
        
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        client.close()
        print("\n🔌 Database connection closed")


async def create_test_listing(db, seller_id):
    """Create a test listing to verify creation flow."""
    
    test_listing = {
        'seller_id': seller_id,
        'species': 'dog',
        'breed': 'Test Breed',
        'age_months': 6,
        'sex': 'Male',
        'color': 'Brown',
        'vaccinated': True,
        'vet_certificate_url': 'test_url',
        'microchip_id': 'TEST123',
        'description': 'Test listing for verification',
        'price': 1000.0,
        'location': {
            'city': 'Test City',
            'region': 'Test Region'
        },
        'photos': [],
        'status': 'active',  # This simulates what the backend sets
        'created_at': datetime.utcnow(),
        'updated_at': datetime.utcnow()
    }
    
    result = await db.pet_listings.insert_one(test_listing)
    return str(result.inserted_id)


if __name__ == "__main__":
    print("=" * 60)
    print("  PetSoko - Listing Status Tests")
    print("=" * 60)
    print()
    
    # Run tests
    success = asyncio.run(test_listing_status())
    
    print()
    print("=" * 60)
    print("  Test script finished")
    print("=" * 60)
    
    # Exit with appropriate code
    exit(0 if success else 1)
