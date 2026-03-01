"""
Google Calendar API Routes
OAuth flow and calendar management endpoints
"""

import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from google_calendar_service import get_calendar_service
from bson import ObjectId
import jwt

logger = logging.getLogger(__name__)

calendar_router = APIRouter(prefix="/api/calendar", tags=["Calendar"])

# NOTE: get_current_user dependency will be available when this router
# is imported in server.py where it's defined


# Pydantic Models

class InitiateAuthRequest(BaseModel):
    redirect_uri: Optional[str] = None


class InitiateAuthResponse(BaseModel):
    auth_url: str
    state: str


class OAuthCallbackRequest(BaseModel):
    code: str
    state: str
    redirect_uri: Optional[str] = None


class OAuthCallbackResponse(BaseModel):
    success: bool
    calendar_connected: bool
    primary_calendar_id: str
    calendars: list


class CalendarEvent(BaseModel):
    order_id: str
    sync_to: list = ["provider", "customer"]


class DisconnectResponse(BaseModel):
    success: bool
    message: str


# In-memory state storage (use Redis in production)
auth_states = {}


# Endpoints

# Auth dependency placeholder - will be replaced when imported in server.py
async def _get_current_user_placeholder():
    raise HTTPException(status_code=401, detail="Auth not configured")

@calendar_router.post("/auth/initiate", response_model=InitiateAuthResponse)
async def initiate_oauth(
    request: InitiateAuthRequest
):
    """
    Initiate Google OAuth flow for calendar access
    
    Returns authorization URL for user to visit
    """
    calendar_service = get_calendar_service()
    
    if not calendar_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google Calendar service not configured"
        )
    
    # Generate random state token for security
    state = secrets.token_urlsafe(32)
    
    # Store state with user ID (expires in 10 minutes)
    auth_states[state] = {
        "user_id": str(current_user["_id"]),
        "expires_at": datetime.utcnow() + timedelta(minutes=10)
    }
    
    # Generate authorization URL
    auth_url = calendar_service.get_auth_url(state, request.redirect_uri)
    
    return InitiateAuthResponse(
        auth_url=auth_url,
        state=state
    )


@calendar_router.post("/auth/callback", response_model=OAuthCallbackResponse)
async def oauth_callback(request: OAuthCallbackRequest):
    """
    Handle OAuth callback and store tokens
    
    Called after user authorizes calendar access
    """
    calendar_service = get_calendar_service()
    
    if not calendar_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google Calendar service not configured"
        )
    
    # Verify state token
    state_data = auth_states.get(request.state)
    
    if not state_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired state token"
        )
    
    # Check if state expired
    if datetime.utcnow() > state_data["expires_at"]:
        del auth_states[request.state]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="State token expired. Please try again."
        )
    
    user_id = state_data["user_id"]
    
    # Clean up state
    del auth_states[request.state]
    
    try:
        # Get user from database to use their email
        user = await calendar_service.db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Exchange authorization code for tokens
        tokens = await calendar_service.exchange_code_for_tokens(
            request.code,
            request.redirect_uri
        )

        # List user's calendars
        calendars = await calendar_service.list_calendars(tokens["access_token"])

        # Find primary calendar or use user's email as calendar ID
        primary_calendar = next(
            (cal for cal in calendars if cal.get("primary")),
            calendars[0] if calendars else {"id": user.get("email", "primary")}
        )

        # Calculate token expiry
        token_expiry = datetime.utcnow() + timedelta(seconds=tokens.get("expires_in", 3600))

        # Store tokens in database (encrypted)
        # Note: We store user's existing email/name from their account
        # since we don't request userinfo scopes (using incremental authorization)
        calendar_data = {
            "connected": True,
            "access_token": calendar_service.encrypt_token(tokens["access_token"]),
            "refresh_token": calendar_service.encrypt_token(tokens.get("refresh_token", "")),
            "token_expiry": token_expiry,
            "calendar_id": primary_calendar["id"],
            "sync_enabled": True,
            "last_sync": datetime.utcnow(),
            "sync_errors": 0,
            "google_email": user.get("email"),
            "google_name": user.get("name")
        }
        
        # Update user document
        result = await calendar_service.db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"google_calendar": calendar_data}}
        )
        
        if result.modified_count == 0:
            logger.warning(f"Failed to update user {user_id} with calendar data")
        
        logger.info(f"✅ Calendar connected for user {user_id}")
        
        return OAuthCallbackResponse(
            success=True,
            calendar_connected=True,
            primary_calendar_id=primary_calendar["id"],
            calendars=calendars
        )
        
    except Exception as e:
        logger.error(f"OAuth callback failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to connect calendar: {str(e)}"
        )


@calendar_router.delete("/disconnect", response_model=DisconnectResponse)
async def disconnect_calendar():
    """
    Disconnect Google Calendar and remove access
    """
    calendar_service = get_calendar_service()
    
    if not calendar_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google Calendar service not configured"
        )
    
    user_id = str(current_user["_id"])
    
    try:
        # Remove calendar connection from database
        result = await calendar_service.db.users.update_one(
            {"_id": ObjectId(user_id)},
            {
                "$set": {
                    "google_calendar.connected": False,
                    "google_calendar.sync_enabled": False
                },
                "$unset": {
                    "google_calendar.access_token": "",
                    "google_calendar.refresh_token": ""
                }
            }
        )
        
        if result.modified_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Calendar connection not found"
            )
        
        logger.info(f"✅ Calendar disconnected for user {user_id}")
        
        return DisconnectResponse(
            success=True,
            message="Calendar disconnected successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to disconnect calendar: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to disconnect calendar: {str(e)}"
        )


@calendar_router.get("/status")
async def get_calendar_status():
    """
    Get user's calendar connection status
    """
    calendar_service = get_calendar_service()
    
    if not calendar_service:
        return {
            "available": False,
            "connected": False,
            "message": "Google Calendar service not configured"
        }
    
    user_id = str(current_user["_id"])
    
    try:
        user = await calendar_service.db.users.find_one({"_id": ObjectId(user_id)})
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        calendar_data = user.get("google_calendar", {})
        
        return {
            "available": True,
            "connected": calendar_data.get("connected", False),
            "calendar_id": calendar_data.get("calendar_id"),
            "google_email": calendar_data.get("google_email"),
            "sync_enabled": calendar_data.get("sync_enabled", False),
            "last_sync": calendar_data.get("last_sync"),
            "sync_errors": calendar_data.get("sync_errors", 0)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get calendar status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@calendar_router.post("/events/create")
async def create_calendar_event(
    event_request: CalendarEvent
):
    """
    Manually create calendar event for a booking
    (Usually done automatically on booking creation)
    """
    calendar_service = get_calendar_service()
    
    if not calendar_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google Calendar service not configured"
        )
    
    try:
        # Get booking details
        booking = await calendar_service.db.orders.find_one(
            {"_id": ObjectId(event_request.order_id)}
        )
        
        if not booking:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Booking not found"
            )
        
        events_created = {}
        
        # Create event for provider
        if "provider" in event_request.sync_to:
            provider_id = str(booking["seller_id"])
            access_token = await calendar_service.get_valid_access_token(provider_id)
            
            if access_token:
                provider = await calendar_service.db.users.find_one({"_id": ObjectId(provider_id)})
                calendar_id = provider.get("google_calendar", {}).get("calendar_id", "primary")
                
                event_data = calendar_service.format_booking_as_event(booking, for_provider=True)
                created_event = await calendar_service.create_event(access_token, calendar_id, event_data)
                
                events_created["provider"] = {
                    "event_id": created_event["id"],
                    "calendar_link": created_event.get("htmlLink", "")
                }
                
                # Update booking with event ID
                await calendar_service.db.orders.update_one(
                    {"_id": booking["_id"]},
                    {
                        "$set": {
                            "calendar_events.provider_event_id": created_event["id"],
                            "calendar_events.calendar_sync_status": "synced"
                        }
                    }
                )
        
        # Create event for customer
        if "customer" in event_request.sync_to:
            customer_id = str(booking["buyer_id"])
            access_token = await calendar_service.get_valid_access_token(customer_id)
            
            if access_token:
                customer = await calendar_service.db.users.find_one({"_id": ObjectId(customer_id)})
                calendar_id = customer.get("google_calendar", {}).get("calendar_id", "primary")
                
                event_data = calendar_service.format_booking_as_event(booking, for_provider=False)
                created_event = await calendar_service.create_event(access_token, calendar_id, event_data)
                
                events_created["customer"] = {
                    "event_id": created_event["id"],
                    "calendar_link": created_event.get("htmlLink", "")
                }
                
                # Update booking with event ID
                await calendar_service.db.orders.update_one(
                    {"_id": booking["_id"]},
                    {
                        "$set": {
                            "calendar_events.customer_event_id": created_event["id"]
                        }
                    }
                )
        
        return {
            "success": True,
            "events_created": events_created
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create calendar event: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
