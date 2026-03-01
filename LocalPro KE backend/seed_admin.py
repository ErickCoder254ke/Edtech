"""
Seed Admin User and Sample Data for PetSoko

This script creates an admin user (Erick) and optionally seeds the database
with sample data for testing.

Usage:
    python seed_admin.py                    # Create admin only
    python seed_admin.py --with-sample      # Create admin + sample data
    python seed_admin.py --clean            # Clean all data and recreate admin
"""

import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime
import os
from dotenv import load_dotenv
from pathlib import Path
import bcrypt
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

# Platform wallet ID constant (matches server.py)
PLATFORM_WALLET_ID = "platform_wallet"


def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


async def create_admin_user():
    """Create admin user: Erick with password erichege56"""
    print("\n" + "="*60)
    print("CREATING ADMIN USER")
    print("="*60)
    
    admin_email = "erick@petsoko.com"
    admin_password = "erichege56"
    admin_name = "Erick"
    
    # Check if admin exists
    existing = await db.users.find_one({'email': admin_email})
    
    if existing:
        print(f"⚠️  Admin user with email {admin_email} already exists!")
        print(f"   User ID: {existing['_id']}")
        print(f"   Name: {existing.get('name')}")
        print(f"   Role: {existing.get('role')}")
        
        # Update password to ensure it's correct
        hashed = hash_password(admin_password)
        await db.users.update_one(
            {'email': admin_email},
            {
                '$set': {
                    'password': hashed,
                    'role': 'admin',
                    'name': admin_name,
                    'updated_at': datetime.utcnow()
                }
            }
        )
        print("✅ Admin password updated to: erichege56")
        return str(existing['_id'])
    
    # Create new admin user
    print(f"Creating new admin user: {admin_name}")
    
    admin_user = {
        'name': admin_name,
        'email': admin_email,
        'password': hash_password(admin_password),
        'phone': '+254700000001',
        'role': 'admin',
        'kyc_status': 'verified',
        'security_question': 'What is your favorite pet?',
        'security_answer': hash_password('dog'),
        'created_at': datetime.utcnow(),
        'updated_at': datetime.utcnow()
    }
    
    result = await db.users.insert_one(admin_user)
    admin_id = str(result.inserted_id)
    
    print("\n" + "="*60)
    print("✅ ADMIN USER CREATED SUCCESSFULLY!")
    print("="*60)
    print(f"   User ID: {admin_id}")
    print(f"   Name: {admin_name}")
    print(f"   Email: {admin_email}")
    print(f"   Password: {admin_password}")
    print(f"   Phone: +254700000001")
    print(f"   Role: admin")
    print("\n⚠️  IMPORTANT: Save these credentials!")
    
    return admin_id


async def create_platform_wallet():
    """Create or update platform wallet"""
    print("\n📊 Setting up platform wallet...")
    
    existing = await db.wallets.find_one({'user_id': PLATFORM_WALLET_ID})
    
    if existing:
        print(f"✅ Platform wallet already exists (Balance: KES {existing.get('balance', 0):.2f})")
        return
    
    platform_wallet = {
        'user_id': PLATFORM_WALLET_ID,
        'balance': 0.0,
        'total_earned': 0.0,
        'total_withdrawn': 0.0,
        'pending_balance': 0.0,
        'pending_deductions': 0.0,
        'created_at': datetime.utcnow(),
        'updated_at': datetime.utcnow()
    }
    
    await db.wallets.insert_one(platform_wallet)
    print("✅ Platform wallet created")


async def create_sample_data():
    """Create sample users, sellers, and pet listings for testing"""
    print("\n" + "="*60)
    print("CREATING SAMPLE DATA")
    print("="*60)
    
    # Sample base64 placeholder for images
    placeholder_image = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='
    
    # Real animal images from Pexels
    pet_images = {
        'golden_retriever': 'https://images.pexels.com/photos/27680249/pexels-photo-27680249.jpeg?auto=compress&cs=tinysrgb&w=800',
        'persian_cat': 'https://images.pexels.com/photos/30349168/pexels-photo-30349168.jpeg?auto=compress&cs=tinysrgb&w=800',
        'german_shepherd': 'https://images.pexels.com/photos/28704693/pexels-photo-28704693.jpeg?auto=compress&cs=tinysrgb&w=800',
        'rabbit': 'https://images.pexels.com/photos/35107899/pexels-photo-35107899.jpeg?auto=compress&cs=tinysrgb&w=800',
        'labrador': 'https://images.pexels.com/photos/28683175/pexels-photo-28683175.jpeg?auto=compress&cs=tinysrgb&w=800',
        'siamese_cat': 'https://images.pexels.com/photos/28192753/pexels-photo-28192753.jpeg?auto=compress&cs=tinysrgb&w=800',
    }
    
    # Create sample users
    users_data = [
        {
            'name': 'John Kamau',
            'email': 'john.kamau@petsoko.com',
            'phone': '+254712345678',
            'password': hash_password('password123'),
            'role': 'seller',
            'kyc_status': 'verified',
            'security_question': 'What was the name of your first pet?',
            'security_answer': hash_password('buddy'),
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        },
        {
            'name': 'Mary Wanjiru',
            'email': 'mary.wanjiru@petsoko.com',
            'phone': '+254723456789',
            'password': hash_password('password123'),
            'role': 'seller',
            'kyc_status': 'verified',
            'security_question': 'What city were you born in?',
            'security_answer': hash_password('nairobi'),
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        },
        {
            'name': 'Peter Omondi',
            'email': 'peter.omondi@petsoko.com',
            'phone': '+254734567890',
            'password': hash_password('password123'),
            'role': 'buyer',
            'kyc_status': 'verified',
            'security_question': 'What is your favorite color?',
            'security_answer': hash_password('blue'),
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        },
        {
            'name': 'Grace Achieng',
            'email': 'grace.achieng@petsoko.com',
            'phone': '+254745678901',
            'password': hash_password('password123'),
            'role': 'buyer',
            'kyc_status': 'verified',
            'security_question': 'What is your favorite book?',
            'security_answer': hash_password('the alchemist'),
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
    ]
    
    users_result = await db.users.insert_many(users_data)
    seller1_id = str(users_result.inserted_ids[0])
    seller2_id = str(users_result.inserted_ids[1])
    buyer1_id = str(users_result.inserted_ids[2])
    buyer2_id = str(users_result.inserted_ids[3])
    
    print(f"✅ Created {len(users_result.inserted_ids)} sample users")
    
    # Create seller profiles
    seller_profiles = [
        {
            'user_id': seller1_id,
            'business_name': 'Happy Paws Kenya',
            'license_file': placeholder_image,
            'rating': 4.8,
            'total_reviews': 24,
            'bank_details': {
                'bank_name': 'Equity Bank',
                'account_number': '1234567890',
                'account_name': 'Happy Paws Kenya'
            },
            'created_at': datetime.utcnow()
        },
        {
            'user_id': seller2_id,
            'business_name': 'Pet Paradise Nairobi',
            'license_file': placeholder_image,
            'rating': 4.5,
            'total_reviews': 18,
            'bank_details': {
                'bank_name': 'KCB Bank',
                'account_number': '0987654321',
                'account_name': 'Pet Paradise Nairobi'
            },
            'created_at': datetime.utcnow()
        }
    ]
    
    await db.seller_profiles.insert_many(seller_profiles)
    print(f"✅ Created {len(seller_profiles)} seller profiles")
    
    # Create wallets for all users
    wallets = []
    for user_id in [seller1_id, seller2_id, buyer1_id, buyer2_id]:
        wallets.append({
            'user_id': user_id,
            'balance': 0.0,
            'total_earned': 0.0,
            'total_withdrawn': 0.0,
            'pending_balance': 0.0,
            'pending_deductions': 0.0,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        })
    
    await db.wallets.insert_many(wallets)
    print(f"✅ Created {len(wallets)} user wallets")
    
    # Create sample pet listings
    pet_listings = [
        {
            'seller_id': seller1_id,
            'species': 'dog',
            'breed': 'Golden Retriever',
            'age_months': 8,
            'sex': 'Male',
            'color': 'Golden',
            'vaccinated': True,
            'vet_certificate_url': placeholder_image,
            'microchip_id': 'MC001234567',
            'description': 'Beautiful golden retriever puppy, very playful and friendly. Great with kids and other pets. Fully vaccinated and dewormed.',
            'price': 45000.0,
            'location': {
                'city': 'Nairobi',
                'region': 'Nairobi County',
                'lat': -1.286389,
                'lng': 36.817223
            },
            'photos': [pet_images['golden_retriever']],
            'status': 'active',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        },
        {
            'seller_id': seller1_id,
            'species': 'cat',
            'breed': 'Persian',
            'age_months': 6,
            'sex': 'Female',
            'color': 'White',
            'vaccinated': True,
            'vet_certificate_url': placeholder_image,
            'microchip_id': None,
            'description': 'Adorable Persian kitten with fluffy white coat. Very calm and affectionate. Perfect indoor companion.',
            'price': 25000.0,
            'location': {
                'city': 'Nairobi',
                'region': 'Nairobi County',
                'lat': -1.286389,
                'lng': 36.817223
            },
            'photos': [pet_images['persian_cat']],
            'status': 'active',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        },
        {
            'seller_id': seller2_id,
            'species': 'dog',
            'breed': 'German Shepherd',
            'age_months': 12,
            'sex': 'Male',
            'color': 'Black and Tan',
            'vaccinated': True,
            'vet_certificate_url': placeholder_image,
            'microchip_id': 'MC009876543',
            'description': 'Well-trained German Shepherd, excellent guard dog. Loyal and intelligent. Good with families.',
            'price': 55000.0,
            'location': {
                'city': 'Mombasa',
                'region': 'Mombasa County',
                'lat': -4.043477,
                'lng': 39.668206
            },
            'photos': [pet_images['german_shepherd']],
            'status': 'active',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        },
        {
            'seller_id': seller2_id,
            'species': 'rabbit',
            'breed': 'Holland Lop',
            'age_months': 4,
            'sex': 'Female',
            'color': 'Brown and White',
            'vaccinated': True,
            'vet_certificate_url': placeholder_image,
            'microchip_id': None,
            'description': 'Cute Holland Lop rabbit with floppy ears. Very gentle and easy to care for. Great for children.',
            'price': 8000.0,
            'location': {
                'city': 'Kisumu',
                'region': 'Kisumu County',
                'lat': -0.091702,
                'lng': 34.767956
            },
            'photos': [pet_images['rabbit']],
            'status': 'active',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        },
        {
            'seller_id': seller1_id,
            'species': 'dog',
            'breed': 'Labrador Retriever',
            'age_months': 10,
            'sex': 'Female',
            'color': 'Yellow',
            'vaccinated': True,
            'vet_certificate_url': placeholder_image,
            'microchip_id': 'MC005555555',
            'description': 'Friendly Labrador, loves to play fetch. Great family dog, very energetic and loves water.',
            'price': 40000.0,
            'location': {
                'city': 'Nakuru',
                'region': 'Nakuru County',
                'lat': -0.303099,
                'lng': 36.080025
            },
            'photos': [pet_images['labrador']],
            'status': 'active',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        },
        {
            'seller_id': seller2_id,
            'species': 'cat',
            'breed': 'Siamese',
            'age_months': 7,
            'sex': 'Male',
            'color': 'Seal Point',
            'vaccinated': True,
            'vet_certificate_url': placeholder_image,
            'microchip_id': None,
            'description': 'Beautiful Siamese cat with striking blue eyes. Very vocal and social. Loves attention.',
            'price': 20000.0,
            'location': {
                'city': 'Eldoret',
                'region': 'Uasin Gishu County',
                'lat': 0.514277,
                'lng': 35.269779
            },
            'photos': [pet_images['siamese_cat']],
            'status': 'active',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
    ]
    
    listings_result = await db.pet_listings.insert_many(pet_listings)
    print(f"✅ Created {len(listings_result.inserted_ids)} pet listings")
    
    print("\n" + "="*60)
    print("SAMPLE DATA SUMMARY")
    print("="*60)
    print(f"   Sellers: 2")
    print(f"   Buyers: 2")
    print(f"   Pet Listings: {len(listings_result.inserted_ids)}")
    print(f"   Wallets: {len(wallets) + 1} (including platform)")
    print("\nSample Login Credentials:")
    print("   Seller 1: john.kamau@petsoko.com / password123")
    print("   Seller 2: mary.wanjiru@petsoko.com / password123")
    print("   Buyer 1: peter.omondi@petsoko.com / password123")
    print("   Buyer 2: grace.achieng@petsoko.com / password123")


async def clean_database():
    """Clean all collections"""
    print("\n⚠️  CLEANING DATABASE...")
    collections = [
        'users', 'seller_profiles', 'pet_listings', 'orders', 
        'wallets', 'transactions', 'conversations', 'messages',
        'reviews', 'notifications', 'withdrawals', 'audit_logs'
    ]
    
    for collection in collections:
        result = await db[collection].delete_many({})
        if result.deleted_count > 0:
            print(f"   Deleted {result.deleted_count} documents from {collection}")
    
    print("✅ Database cleaned")


async def main():
    """Main seeding function"""
    try:
        # Check connection
        await client.server_info()
        print(f"✅ Connected to MongoDB: {db_name}")
        
        # Parse command line arguments
        args = sys.argv[1:]
        clean_mode = '--clean' in args
        with_sample = '--with-sample' in args
        
        if clean_mode:
            await clean_database()
        
        # Create admin user
        admin_id = await create_admin_user()
        
        # Create platform wallet
        await create_platform_wallet()
        
        # Create sample data if requested
        if with_sample:
            await create_sample_data()
        
        print("\n" + "="*60)
        print("NEXT STEPS")
        print("="*60)
        print("1. Start the backend server:")
        print("   cd backend")
        print("   uvicorn server:app --reload --host 0.0.0.0 --port 8000")
        print("\n2. Start the admin dashboard:")
        print("   cd adminPetSoko-main")
        print("   npm run dev")
        print("\n3. Login to admin dashboard:")
        print("   URL: http://localhost:3000/admin/login")
        print("   Email: erick@petsoko.com")
        print("   Password: erichege56")
        
        if with_sample:
            print("\n4. You can also test with sample users:")
            print("   Sellers and buyers created for testing")
        
        print("\n✅ Database seeding completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.close()


if __name__ == "__main__":
    print("🐾 PetSoko Database Seeding")
    print("="*60)
    
    # Check if .env exists
    env_path = Path(__file__).parent / '.env'
    if not env_path.exists():
        print("❌ Error: .env file not found")
        print("\nPlease create backend/.env file or use:")
        print("   backend/pet (1).env")
        sys.exit(1)
    
    print("\nUsage:")
    print("  python seed_admin.py              # Create admin only")
    print("  python seed_admin.py --with-sample  # Create admin + sample data")
    print("  python seed_admin.py --clean       # Clean all data and recreate")
    print("  python seed_admin.py --clean --with-sample  # Clean and full seed")
    print()
    
    asyncio.run(main())
