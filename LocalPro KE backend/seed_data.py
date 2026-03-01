import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime
import os
from dotenv import load_dotenv
from pathlib import Path
import bcrypt

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

async def seed_database():
    print("Starting database seeding...")
    
    # Clear existing data
    await db.users.delete_many({})
    await db.seller_profiles.delete_many({})
    await db.service_listings.delete_many({})
    await db.orders.delete_many({})
    print("Cleared existing data")
    
    # Create sample users
    users_data = [
        {
            'name': 'John Seller',
            'email': 'seller@petsoko.com',
            'phone': '+254712345678',
            'password': hash_password('password123'),
            'role': 'seller',
            'kyc_status': 'verified',
            'security_question': 'What was the name of your first pet?',
            'security_answer': hash_password('buddy'),
            'created_at': datetime.utcnow()
        },
        {
            'name': 'Jane Buyer',
            'email': 'buyer@petsoko.com',
            'phone': '+254723456789',
            'password': hash_password('password123'),
            'role': 'buyer',
            'kyc_status': 'verified',
            'security_question': 'What city were you born in?',
            'security_answer': hash_password('nairobi'),
            'created_at': datetime.utcnow()
        },
        {
            'name': 'Admin User',
            'email': 'admin@petsoko.com',
            'phone': '+254734567890',
            'password': hash_password('admin123'),
            'role': 'admin',
            'kyc_status': 'verified',
            'security_question': 'What is your favorite book?',
            'security_answer': hash_password('the alchemist'),
            'created_at': datetime.utcnow()
        }
    ]
    
    users_result = await db.users.insert_many(users_data)
    seller_id = str(users_result.inserted_ids[0])
    print(f"Created {len(users_result.inserted_ids)} users")
    
    # Create seller profile
    seller_profile = {
        'user_id': seller_id,
        'business_name': 'Happy Paws Kenya',
        'license_file': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
        'rating': 4.8,
        'bank_details': {
            'bank_name': 'Equity Bank',
            'account_number': '1234567890',
            'account_name': 'Happy Paws Kenya'
        },
        'created_at': datetime.utcnow()
    }
    
    await db.seller_profiles.insert_one(seller_profile)
    print("Created seller profile")
    
    # Sample base64 placeholder for certificates
    placeholder_cert = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='

    # Service-related images from Pexels
    service_images = {
        'grooming': 'https://images.pexels.com/photos/6568461/pexels-photo-6568461.jpeg?auto=compress&cs=tinysrgb&w=800',
        'veterinary': 'https://images.pexels.com/photos/6235241/pexels-photo-6235241.jpeg?auto=compress&cs=tinysrgb&w=800',
        'training': 'https://images.pexels.com/photos/4498185/pexels-photo-4498185.jpeg?auto=compress&cs=tinysrgb&w=800',
        'boarding': 'https://images.pexels.com/photos/4587998/pexels-photo-4587998.jpeg?auto=compress&cs=tinysrgb&w=800',
        'walking': 'https://images.pexels.com/photos/4588047/pexels-photo-4588047.jpeg?auto=compress&cs=tinysrgb&w=800',
        'sitting': 'https://images.pexels.com/photos/4498224/pexels-photo-4498224.jpeg?auto=compress&cs=tinysrgb&w=800',
        'daycare': 'https://images.pexels.com/photos/5255233/pexels-photo-5255233.jpeg?auto=compress&cs=tinysrgb&w=800',
        'mobile_vet': 'https://images.pexels.com/photos/6234407/pexels-photo-6234407.jpeg?auto=compress&cs=tinysrgb&w=800',
    }

    # Create sample service listings
    service_listings = [
        {
            'seller_id': seller_id,
            'service_category': 'grooming',
            'service_name': 'Premium Dog Grooming',
            'service_type': 'one-time',
            'duration_minutes': 90,
            'price': 3500,
            'price_unit': 'per_session',
            'description': 'Professional dog grooming including bath, haircut, nail trimming, and ear cleaning. We use premium organic products safe for all breeds.',
            'qualifications': 'Certified Pet Groomer with 5 years experience',
            'certifications': [placeholder_cert],
            'experience_years': 5,
            'services_included': ['Bath', 'Haircut', 'Nail Trimming', 'Ear Cleaning', 'Blow Dry'],
            'pet_types_accepted': ['dog'],
            'location': {'city': 'Nairobi', 'region': 'Westlands'},
            'service_location_type': 'at_business',
            'photos': [service_images['grooming']],
            'availability': {
                'days': ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'],
                'hours': {'start': '09:00', 'end': '18:00'}
            },
            'status': 'active',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        },
        {
            'seller_id': seller_id,
            'service_category': 'veterinary',
            'service_name': 'Complete Pet Health Checkup',
            'service_type': 'one-time',
            'duration_minutes': 45,
            'price': 2500,
            'price_unit': 'per_session',
            'description': 'Comprehensive veterinary health checkup including physical examination, vaccination review, and health consultation.',
            'qualifications': 'Licensed Veterinarian (DVM), 10 years experience',
            'certifications': [placeholder_cert],
            'experience_years': 10,
            'services_included': ['Physical Exam', 'Temperature Check', 'Weight Check', 'Health Consultation', 'Vaccination Advice'],
            'pet_types_accepted': ['dog', 'cat', 'rabbit', 'bird'],
            'location': {'city': 'Mombasa', 'region': 'Nyali'},
            'service_location_type': 'at_business',
            'photos': [service_images['veterinary']],
            'availability': {
                'days': ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'],
                'hours': {'start': '08:00', 'end': '17:00'}
            },
            'status': 'active',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        },
        {
            'seller_id': seller_id,
            'service_category': 'training',
            'service_name': 'Basic Obedience Training',
            'service_type': 'package',
            'duration_minutes': 60,
            'price': 15000,
            'price_unit': 'per_month',
            'description': 'Professional dog training program focusing on basic commands, leash manners, and socialization. 4 sessions per month.',
            'qualifications': 'Certified Dog Trainer (CPT), specializing in positive reinforcement',
            'certifications': [placeholder_cert],
            'experience_years': 7,
            'services_included': ['Sit/Stay/Come Commands', 'Leash Training', 'Socialization', 'Behavior Correction'],
            'pet_types_accepted': ['dog'],
            'location': {'city': 'Nairobi', 'region': 'Karen'},
            'service_location_type': 'at_customer',
            'photos': [service_images['training']],
            'availability': {
                'days': ['tuesday', 'thursday', 'saturday'],
                'hours': {'start': '14:00', 'end': '19:00'}
            },
            'status': 'active',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        },
        {
            'seller_id': seller_id,
            'service_category': 'boarding',
            'service_name': 'Pet Boarding & Care',
            'service_type': 'one-time',
            'duration_minutes': 1440,  # 24 hours
            'price': 1500,
            'price_unit': 'per_day',
            'description': 'Safe and comfortable boarding for your pets. Climate-controlled facility with 24/7 supervision, playtime, and feeding.',
            'qualifications': 'Professional Pet Care Facility, Licensed by Kenya Veterinary Board',
            'certifications': [placeholder_cert],
            'experience_years': 8,
            'services_included': ['24/7 Supervision', 'Feeding', 'Playtime', 'Comfortable Sleeping Area', 'Daily Updates'],
            'pet_types_accepted': ['dog', 'cat'],
            'location': {'city': 'Kisumu', 'region': 'Milimani'},
            'service_location_type': 'at_business',
            'photos': [service_images['boarding']],
            'availability': {
                'days': ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'],
                'hours': {'start': '00:00', 'end': '23:59'}
            },
            'status': 'active',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        },
        {
            'seller_id': seller_id,
            'service_category': 'walking',
            'service_name': 'Daily Dog Walking Service',
            'service_type': 'recurring',
            'duration_minutes': 45,
            'price': 800,
            'price_unit': 'per_session',
            'description': 'Professional dog walking service. We ensure your dog gets proper exercise and socialization. Available for daily, weekly, or custom schedules.',
            'qualifications': 'Experienced Dog Walker, insured and bonded',
            'certifications': [placeholder_cert],
            'experience_years': 4,
            'services_included': ['45-minute walk', 'Fresh water', 'Waste cleanup', 'Photo updates'],
            'pet_types_accepted': ['dog'],
            'location': {'city': 'Nairobi', 'region': 'Lavington'},
            'service_location_type': 'at_customer',
            'photos': [service_images['walking']],
            'availability': {
                'days': ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'],
                'hours': {'start': '06:00', 'end': '20:00'}
            },
            'status': 'active',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        },
        {
            'seller_id': seller_id,
            'service_category': 'sitting',
            'service_name': 'Pet Sitting at Your Home',
            'service_type': 'one-time',
            'duration_minutes': 480,  # 8 hours
            'price': 2000,
            'price_unit': 'per_day',
            'description': 'Reliable pet sitting service in the comfort of your home. Perfect for when you\'re away for the day or overnight.',
            'qualifications': 'Professional Pet Sitter with references',
            'certifications': [placeholder_cert],
            'experience_years': 6,
            'services_included': ['Feeding', 'Playtime', 'Medication if needed', 'Home security check', 'Regular updates'],
            'pet_types_accepted': ['dog', 'cat', 'bird', 'rabbit'],
            'location': {'city': 'Nakuru', 'region': 'Milimani'},
            'service_location_type': 'at_customer',
            'photos': [service_images['sitting']],
            'availability': {
                'days': ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'],
                'hours': {'start': '00:00', 'end': '23:59'}
            },
            'status': 'active',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        },
        {
            'seller_id': seller_id,
            'service_category': 'daycare',
            'service_name': 'Pet Daycare & Socialization',
            'service_type': 'recurring',
            'duration_minutes': 480,  # 8 hours
            'price': 1200,
            'price_unit': 'per_day',
            'description': 'Fun and safe daycare for your pets. Supervised play, socialization with other pets, and lots of love and attention.',
            'qualifications': 'Licensed Pet Daycare Facility',
            'certifications': [placeholder_cert],
            'experience_years': 5,
            'services_included': ['Supervised playtime', 'Socialization', 'Lunch included', 'Climate-controlled facility', 'Photo updates'],
            'pet_types_accepted': ['dog', 'cat'],
            'location': {'city': 'Eldoret', 'region': 'Pioneer'},
            'service_location_type': 'at_business',
            'photos': [service_images['daycare']],
            'availability': {
                'days': ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'],
                'hours': {'start': '07:00', 'end': '18:00'}
            },
            'status': 'active',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        },
        {
            'seller_id': seller_id,
            'service_category': 'grooming',
            'service_name': 'Cat Grooming & Spa',
            'service_type': 'one-time',
            'duration_minutes': 60,
            'price': 2500,
            'price_unit': 'per_session',
            'description': 'Specialized cat grooming service. Gentle handling for stressed or anxious cats. Includes bath, brush, nail trim, and ear cleaning.',
            'qualifications': 'Certified Cat Groomer, specializing in feline care',
            'certifications': [placeholder_cert],
            'experience_years': 3,
            'services_included': ['Bath', 'Brush/De-shedding', 'Nail Trimming', 'Ear Cleaning', 'Sanitary trim'],
            'pet_types_accepted': ['cat'],
            'location': {'city': 'Nairobi', 'region': 'Kileleshwa'},
            'service_location_type': 'at_business',
            'photos': [service_images['grooming']],
            'availability': {
                'days': ['wednesday', 'thursday', 'friday', 'saturday'],
                'hours': {'start': '10:00', 'end': '16:00'}
            },
            'status': 'active',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        },
        {
            'seller_id': seller_id,
            'service_category': 'veterinary',
            'service_name': 'Mobile Veterinary Service',
            'service_type': 'one-time',
            'duration_minutes': 60,
            'price': 3500,
            'price_unit': 'per_session',
            'description': 'We bring veterinary care to your doorstep. Full health checkups, vaccinations, and minor treatments at your home.',
            'qualifications': 'Licensed Mobile Veterinarian (DVM)',
            'certifications': [placeholder_cert],
            'experience_years': 12,
            'services_included': ['Home visit', 'Physical exam', 'Vaccinations', 'Minor treatments', 'Health consultation'],
            'pet_types_accepted': ['dog', 'cat', 'rabbit', 'bird'],
            'location': {'city': 'Thika', 'region': 'Blue Post'},
            'service_location_type': 'mobile',
            'photos': [service_images['mobile_vet']],
            'availability': {
                'days': ['monday', 'wednesday', 'friday'],
                'hours': {'start': '09:00', 'end': '17:00'}
            },
            'status': 'active',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        },
        {
            'seller_id': seller_id,
            'service_category': 'training',
            'service_name': 'Puppy Socialization Classes',
            'service_type': 'package',
            'duration_minutes': 90,
            'price': 8000,
            'price_unit': 'per_month',
            'description': 'Group puppy classes focusing on socialization, basic commands, and good manners. Perfect for puppies 8-16 weeks old.',
            'qualifications': 'Certified Puppy Trainer',
            'certifications': [placeholder_cert],
            'experience_years': 6,
            'services_included': ['Socialization with other puppies', 'Basic commands', 'Leash introduction', 'Bite inhibition', 'House training tips'],
            'pet_types_accepted': ['dog'],
            'location': {'city': 'Nairobi', 'region': 'Ruaka'},
            'service_location_type': 'at_business',
            'photos': [service_images['training']],
            'availability': {
                'days': ['saturday', 'sunday'],
                'hours': {'start': '10:00', 'end': '14:00'}
            },
            'status': 'active',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
    ]
    
    listings_result = await db.pet_listings.insert_many(pet_listings)
    print(f"Created {len(listings_result.inserted_ids)} pet listings")
    
    print("\nSeeding completed successfully!")
    print("\nTest Credentials:")
    print("Seller - Email: seller@petsoko.com, Password: password123")
    print("  Security Q: What was the name of your first pet? | A: buddy")
    print("\nBuyer - Email: buyer@petsoko.com, Password: password123")
    print("  Security Q: What city were you born in? | A: nairobi")
    print("\nAdmin - Email: admin@petsoko.com, Password: admin123")
    print("  Security Q: What is your favorite book? | A: the alchemist")

if __name__ == '__main__':
    asyncio.run(seed_database())
