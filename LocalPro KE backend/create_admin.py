"""
Create Admin User Script for PetSoko

This script creates an admin user in the database.
Run this once to set up your admin account.

Usage:
    python create_admin.py

You will be prompted for admin credentials.
"""

from motor.motor_asyncio import AsyncIOMotorClient
import bcrypt
import asyncio
from datetime import datetime
import os
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

async def create_admin():
    try:
        # Connect to MongoDB
        mongo_url = os.environ.get('MONGO_URL')
        db_name = os.environ.get('DB_NAME', 'petsoko')
        
        if not mongo_url:
            print("❌ Error: MONGO_URL not found in .env file")
            print("Please set MONGO_URL in backend/.env")
            return
        
        print(f"🔌 Connecting to MongoDB...")
        print(f"   Database: {db_name}")
        
        client = AsyncIOMotorClient(mongo_url)
        db = client[db_name]
        
        # Test connection
        try:
            await client.server_info()
            print("✅ Connected to MongoDB successfully")
        except Exception as e:
            print(f"❌ Failed to connect to MongoDB: {e}")
            return
        
        # Get admin credentials
        print("\n" + "="*50)
        print("CREATE ADMIN USER")
        print("="*50)
        
        # Use default credentials or prompt
        email = input("Enter admin email (default: admin@petsoko.com): ").strip()
        if not email:
            email = "admin@petsoko.com"
        
        # Check if admin exists
        existing = await db.users.find_one({'email': email})
        if existing:
            print(f"\n⚠️  User with email {email} already exists!")
            choice = input("Do you want to update the password? (yes/no): ").strip().lower()
            if choice != 'yes':
                print("Operation cancelled.")
                client.close()
                return
            
            # Update password
            password = input("Enter new password: ").strip()
            if not password:
                print("❌ Password cannot be empty")
                client.close()
                return
            
            # Hash password
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            # Update user
            await db.users.update_one(
                {'email': email},
                {
                    '$set': {
                        'password': hashed.decode('utf-8'),
                        'role': 'admin',
                        'updated_at': datetime.utcnow()
                    }
                }
            )
            
            print("\n✅ Admin user updated successfully!")
            print(f"   Email: {email}")
            print(f"   Password: {password}")
            print(f"   Role: admin")
            
        else:
            # Create new admin user
            name = input("Enter admin name (default: Admin User): ").strip()
            if not name:
                name = "Admin User"
            
            password = input("Enter password (default: admin123): ").strip()
            if not password:
                password = "admin123"
                print("⚠️  Using default password: admin123")
                print("   Please change this after first login!")
            
            phone = input("Enter phone number (default: +254700000000): ").strip()
            if not phone:
                phone = "+254700000000"
            
            # Hash password
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            # Create admin user
            admin_user = {
                'name': name,
                'email': email,
                'password': hashed.decode('utf-8'),
                'phone': phone,
                'role': 'admin',
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow(),
            }
            
            result = await db.users.insert_one(admin_user)
            
            print("\n" + "="*50)
            print("✅ ADMIN USER CREATED SUCCESSFULLY!")
            print("="*50)
            print(f"   User ID: {result.inserted_id}")
            print(f"   Name: {name}")
            print(f"   Email: {email}")
            print(f"   Password: {password}")
            print(f"   Phone: {phone}")
            print(f"   Role: admin")
            print("\n⚠️  IMPORTANT: Save these credentials!")
            print("   You'll need them to login to the admin dashboard")
        
        # Close connection
        client.close()
        
        print("\n📝 Next steps:")
        print("   1. Start the backend server:")
        print("      uvicorn server:app --reload --host 0.0.0.0 --port 8000")
        print("\n   2. Login to admin dashboard at:")
        print("      http://localhost:3000/admin/login")
        print("\n   3. Use the diagnostics page to test connection:")
        print("      http://localhost:3000/admin/diagnostics")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("🐾 PetSoko Admin User Setup")
    print("-" * 50)
    
    # Check if .env exists
    env_path = Path(__file__).parent / '.env'
    if not env_path.exists():
        print("❌ Error: .env file not found")
        print("\nPlease create backend/.env file with:")
        print("   MONGO_URL=your_mongodb_connection_string")
        print("   DB_NAME=petsoko")
        print("\nExample:")
        print("   MONGO_URL=mongodb://localhost:27017")
        print("   DB_NAME=petsoko")
        exit(1)
    
    asyncio.run(create_admin())
