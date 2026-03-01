"""
Google Calendar Integration Service
Handles OAuth authentication and calendar operations
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from urllib.parse import urlencode
import httpx
from bson import ObjectId
from cryptography.fernet import Fernet
from motor.motor_asyncio import AsyncIOMotorClient

logger = logging.getLogger(__name__)

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = os.environ.get('GOOGLE_REDIRECT_URI')

# Encryption key for storing tokens securely
ENCRYPTION_KEY = os.environ.get('TOKEN_ENCRYPTION_KEY')

# Google OAuth URLs
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_CALENDAR_API = "https://www.googleapis.com/calendar/v3"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

# OAuth Scopes for Calendar Integration
# Using incremental authorization:
# - Google Login (frontend) handles: openid, email, profile
# - Calendar OAuth (backend) requests only: calendar.events
CALENDAR_SCOPES = [
    "https://www.googleapis.com/auth/calendar.events"
]


class GoogleCalendarService:
    """Service for Google Calendar OAuth and API operations"""
    
    def __init__(self, db: AsyncIOMotorClient):
        self.db = db
        self.cipher = None
        
        # Initialize encryption if key is available
        if ENCRYPTION_KEY:
            try:
                self.cipher = Fernet(ENCRYPTION_KEY.encode())
            except Exception as e:
                logger.error(f"Failed to initialize encryption: {e}")
    
    def encrypt_token(self, token: str) -> str:
        """Encrypt OAuth token for secure storage"""
        if not self.cipher:
            logger.warning("Encryption not available, storing token in plaintext")
            return token
        
        try:
            return self.cipher.encrypt(token.encode()).decode()
        except Exception as e:
            logger.error(f"Token encryption failed: {e}")
            return token
    
    def decrypt_token(self, encrypted_token: str) -> str:
        """Decrypt OAuth token"""
        if not self.cipher:
            return encrypted_token
        
        try:
            return self.cipher.decrypt(encrypted_token.encode()).decode()
        except Exception as e:
            logger.error(f"Token decryption failed: {e}")
            return encrypted_token

    def _normalize_user_id(self, user_id: Any) -> Any:
        """Ensure Mongo lookups work with either ObjectId or string IDs."""
        if isinstance(user_id, ObjectId):
            return user_id
        if isinstance(user_id, str):
            try:
                return ObjectId(user_id)
            except Exception:
                return user_id
        return user_id
    
    def get_auth_url(self, state: str, redirect_uri: Optional[str] = None) -> str:
        """
        Generate Google OAuth authorization URL
        
        Args:
            state: Random state token for security
            redirect_uri: Optional custom redirect URI
        
        Returns:
            Authorization URL
        """
        params = {
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": redirect_uri or GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": " ".join(CALENDAR_SCOPES),
            "access_type": "offline",  # Get refresh token
            "prompt": "consent",  # Force consent screen to get refresh token
            "state": state
        }
        
        auth_url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
        return auth_url
    
    async def exchange_code_for_tokens(
        self,
        code: str,
        redirect_uri: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for access and refresh tokens
        
        Args:
            code: Authorization code from OAuth callback
            redirect_uri: Must match the one used in auth URL
        
        Returns:
            Dict containing access_token, refresh_token, expires_in, etc.
        """
        data = {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri or GOOGLE_REDIRECT_URI
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(GOOGLE_TOKEN_URL, data=data)
            
            if response.status_code != 200:
                error_data = response.json()
                logger.error(f"Token exchange failed: {error_data}")
                raise Exception(f"Failed to exchange code: {error_data.get('error_description', 'Unknown error')}")
            
            tokens = response.json()
            return tokens
    
    async def refresh_access_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh expired access token using refresh token
        
        Args:
            refresh_token: Refresh token from initial OAuth flow
        
        Returns:
            New access token and expiry information
        """
        data = {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(GOOGLE_TOKEN_URL, data=data)
            
            if response.status_code != 200:
                error_data = response.json()
                logger.error(f"Token refresh failed: {error_data}")
                raise Exception(f"Failed to refresh token: {error_data.get('error_description', 'Unknown error')}")
            
            return response.json()
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from Google"""
        headers = {"Authorization": f"Bearer {access_token}"}
        
        async with httpx.AsyncClient() as client:
            response = await client.get(GOOGLE_USERINFO_URL, headers=headers)
            
            if response.status_code != 200:
                raise Exception("Failed to get user info")
            
            return response.json()
    
    async def get_valid_access_token(self, user_id: str) -> Optional[str]:
        """
        Get valid access token for user, refreshing if necessary
        
        Args:
            user_id: User ID
        
        Returns:
            Valid access token or None if calendar not connected
        """
        user = await self.db.users.find_one({"_id": self._normalize_user_id(user_id)})
        
        if not user or not user.get("google_calendar", {}).get("connected"):
            return None
        
        calendar_data = user["google_calendar"]
        token_expiry = calendar_data.get("token_expiry")
        
        # Check if token is expired or will expire in next 5 minutes
        if token_expiry and datetime.utcnow() < (token_expiry - timedelta(minutes=5)):
            # Token is still valid
            access_token = self.decrypt_token(calendar_data["access_token"])
            return access_token
        
        # Token expired, refresh it
        try:
            refresh_token = self.decrypt_token(calendar_data["refresh_token"])
            new_tokens = await self.refresh_access_token(refresh_token)
            
            # Update user with new access token
            new_expiry = datetime.utcnow() + timedelta(seconds=new_tokens.get("expires_in", 3600))
            
            await self.db.users.update_one(
                {"_id": self._normalize_user_id(user_id)},
                {
                    "$set": {
                        "google_calendar.access_token": self.encrypt_token(new_tokens["access_token"]),
                        "google_calendar.token_expiry": new_expiry
                    }
                }
            )
            
            return new_tokens["access_token"]
            
        except Exception as e:
            logger.error(f"Failed to refresh token for user {user_id}: {e}")
            
            # Mark calendar as disconnected
            await self.db.users.update_one(
                {"_id": self._normalize_user_id(user_id)},
                {
                    "$set": {
                        "google_calendar.connected": False,
                        "google_calendar.sync_errors": calendar_data.get("sync_errors", 0) + 1
                    }
                }
            )
            
            return None
    
    async def list_calendars(self, access_token: str) -> List[Dict[str, Any]]:
        """List all calendars for the user"""
        headers = {"Authorization": f"Bearer {access_token}"}
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{GOOGLE_CALENDAR_API}/users/me/calendarList",
                headers=headers
            )
            
            if response.status_code != 200:
                raise Exception("Failed to list calendars")
            
            data = response.json()
            calendars = []
            
            for calendar in data.get("items", []):
                calendars.append({
                    "id": calendar["id"],
                    "name": calendar["summary"],
                    "primary": calendar.get("primary", False),
                    "color": calendar.get("backgroundColor", "#9fe1e7"),
                    "access_role": calendar.get("accessRole", "reader")
                })
            
            return calendars
    
    async def create_event(
        self,
        access_token: str,
        calendar_id: str,
        event_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a calendar event
        
        Args:
            access_token: Valid access token
            calendar_id: Calendar ID (usually email or "primary")
            event_data: Event details (summary, start, end, etc.)
        
        Returns:
            Created event data including event ID
        """
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{GOOGLE_CALENDAR_API}/calendars/{calendar_id}/events",
                headers=headers,
                json=event_data
            )
            
            if response.status_code not in [200, 201]:
                error_data = response.json()
                logger.error(f"Failed to create event: {error_data}")
                raise Exception(f"Failed to create event: {error_data.get('error', {}).get('message', 'Unknown error')}")
            
            return response.json()
    
    async def update_event(
        self,
        access_token: str,
        calendar_id: str,
        event_id: str,
        event_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update an existing calendar event"""
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.put(
                f"{GOOGLE_CALENDAR_API}/calendars/{calendar_id}/events/{event_id}",
                headers=headers,
                json=event_data
            )
            
            if response.status_code != 200:
                error_data = response.json()
                logger.error(f"Failed to update event: {error_data}")
                raise Exception(f"Failed to update event: {error_data.get('error', {}).get('message', 'Unknown error')}")
            
            return response.json()
    
    async def delete_event(
        self,
        access_token: str,
        calendar_id: str,
        event_id: str
    ) -> bool:
        """Delete a calendar event"""
        headers = {"Authorization": f"Bearer {access_token}"}
        
        async with httpx.AsyncClient() as client:
            response = await client.delete(
                f"{GOOGLE_CALENDAR_API}/calendars/{calendar_id}/events/{event_id}",
                headers=headers
            )
            
            # 204 = successfully deleted, 410 = already deleted
            if response.status_code in [204, 410]:
                return True
            
            logger.error(f"Failed to delete event {event_id}: {response.status_code}")
            return False
    
    async def get_events(
        self,
        access_token: str,
        calendar_id: str,
        time_min: datetime,
        time_max: datetime
    ) -> List[Dict[str, Any]]:
        """
        Get events in a time range
        
        Args:
            access_token: Valid access token
            calendar_id: Calendar ID
            time_min: Start of time range
            time_max: End of time range
        
        Returns:
            List of events
        """
        headers = {"Authorization": f"Bearer {access_token}"}
        
        params = {
            "timeMin": time_min.isoformat() + "Z",
            "timeMax": time_max.isoformat() + "Z",
            "singleEvents": True,
            "orderBy": "startTime"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{GOOGLE_CALENDAR_API}/calendars/{calendar_id}/events",
                headers=headers,
                params=params
            )
            
            if response.status_code != 200:
                error_data = response.json()
                logger.error(f"Failed to get events: {error_data}")
                raise Exception("Failed to get events")
            
            data = response.json()
            return data.get("items", [])
    
    async def check_availability(
        self,
        user_id: str,
        start_time: datetime,
        end_time: datetime
    ) -> bool:
        """
        Check if user is available in the given time range
        
        Args:
            user_id: User ID
            start_time: Start of booking
            end_time: End of booking
        
        Returns:
            True if available, False if has conflicts
        """
        access_token = await self.get_valid_access_token(user_id)
        
        if not access_token:
            # Calendar not connected, assume available
            return True
        
        user = await self.db.users.find_one({"_id": self._normalize_user_id(user_id)})
        calendar_id = user.get("google_calendar", {}).get("calendar_id", "primary")
        
        try:
            events = await self.get_events(access_token, calendar_id, start_time, end_time)
            
            # If any events found in this time range, there's a conflict
            return len(events) == 0
            
        except Exception as e:
            logger.error(f"Failed to check availability for user {user_id}: {e}")
            # On error, assume available (fail open)
            return True
    
    def format_booking_as_event(
        self,
        booking: Dict[str, Any],
        for_provider: bool = True
    ) -> Dict[str, Any]:
        """
        Format a PetSoko booking as a Google Calendar event
        
        Args:
            booking: Booking/order data
            for_provider: True for provider's calendar, False for customer's
        
        Returns:
            Google Calendar event format
        """
        # Parse booking date and time
        booking_datetime = booking["booking_date"]
        if isinstance(booking_datetime, str):
            booking_datetime = datetime.fromisoformat(booking_datetime.replace("Z", "+00:00"))
        
        # Calculate end time based on service duration (default 90 minutes)
        duration_minutes = booking.get("duration_minutes", 90)
        end_datetime = booking_datetime + timedelta(minutes=duration_minutes)
        
        # Create event summary
        if for_provider:
            summary = f"{booking.get('service_name', 'Service')} - {booking.get('customer_name', 'Customer')}"
        else:
            summary = f"{booking.get('service_name', 'Service')} Appointment"
        
        # Create description
        description_parts = []
        
        if for_provider:
            description_parts.append(f"**Customer:** {booking.get('customer_name', 'N/A')}")
            description_parts.append(f"**Contact:** {booking.get('customer_phone', 'N/A')}")
            description_parts.append(f"**Service:** {booking.get('service_name', 'N/A')}")
            description_parts.append(f"**Payment:** KSH {booking.get('total_amount', 0):,.2f} ({booking.get('payment_method', 'N/A').upper()})")
            description_parts.append(f"**Status:** {booking.get('payment_status', 'N/A').upper()}")
            if booking.get('service_status'):
                description_parts.append(f"**Service Status:** {str(booking.get('service_status')).upper()}")
            
            if booking.get('special_instructions'):
                description_parts.append(f"\n**Special Instructions:**\n{booking['special_instructions']}")
        else:
            description_parts.append(f"**Provider:** {booking.get('provider_name', 'N/A')}")
            description_parts.append(f"**Service:** {booking.get('service_name', 'N/A')}")
            description_parts.append(f"**Amount:** KSH {booking.get('total_amount', 0):,.2f}")
            if booking.get('service_status'):
                description_parts.append(f"**Service Status:** {str(booking.get('service_status')).upper()}")
            description_parts.append(f"**Booking ID:** {booking.get('_id', 'N/A')}")
        
        description = "\n".join(description_parts)
        
        # Create location
        location = booking.get("service_address", "")
        
        # Create event
        event = {
            "summary": summary,
            "description": description,
            "location": location,
            "start": {
                "dateTime": booking_datetime.isoformat(),
                "timeZone": "Africa/Nairobi"
            },
            "end": {
                "dateTime": end_datetime.isoformat(),
                "timeZone": "Africa/Nairobi"
            },
            "reminders": {
                "useDefault": False,
                "overrides": [
                    {"method": "popup", "minutes": 24 * 60},  # 1 day before
                    {"method": "popup", "minutes": 60},  # 1 hour before
                ]
            },
            "colorId": "2"  # Sage green for service bookings
        }
        
        # Add attendees if we have emails
        attendees = []
        if for_provider and booking.get("customer_email"):
            attendees.append({"email": booking["customer_email"]})
        elif not for_provider and booking.get("provider_email"):
            attendees.append({"email": booking["provider_email"]})
        
        if attendees:
            event["attendees"] = attendees
        
        return event


# Global instance
calendar_service: Optional[GoogleCalendarService] = None


def initialize_calendar_service(db: AsyncIOMotorClient):
    """Initialize the calendar service"""
    global calendar_service
    
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        logger.warning("Google Calendar credentials not configured. Calendar features will be disabled.")
        return
    
    calendar_service = GoogleCalendarService(db)
    logger.info("✅ Google Calendar service initialized")


def get_calendar_service() -> Optional[GoogleCalendarService]:
    """Get the calendar service instance"""
    return calendar_service
