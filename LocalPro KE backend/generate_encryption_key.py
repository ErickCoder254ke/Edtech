"""
Script to generate TOKEN_ENCRYPTION_KEY for Google Calendar token encryption
Run this once to generate a secure encryption key for your .env file
"""

from cryptography.fernet import Fernet

def generate_key():
    """Generate a new Fernet encryption key"""
    key = Fernet.generate_key()
    print("\n" + "="*70)
    print("TOKEN ENCRYPTION KEY GENERATED")
    print("="*70)
    print("\nAdd this line to your backend/.env file:")
    print(f"\nTOKEN_ENCRYPTION_KEY={key.decode()}\n")
    print("="*70)
    print("\n⚠️  IMPORTANT: Keep this key secret and never commit it to git!")
    print("="*70 + "\n")
    return key.decode()

if __name__ == "__main__":
    generate_key()
