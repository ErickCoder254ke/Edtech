"""
Native WebSocket handler for Hermes-compatible React Native chat
Provides the same functionality as Socket.IO but using FastAPI's native WebSocket support
"""

from fastapi import WebSocket, WebSocketDisconnect
from typing import Dict, Set, Optional
import json
import logging
import uuid
from datetime import datetime
from bson import ObjectId
import jwt
import os
logger = logging.getLogger(__name__)

# JWT Configuration (should match server.py)
JWT_ALGORITHM = 'HS256'


def _get_jwt_secret() -> str:
    # Read at call time so dev-generated secrets set by server.py are honored
    return os.environ.get('JWT_SECRET', 'dev-secret-key')

# Store active WebSocket connections
# Format: { user_id: WebSocket }
ws_connections: Dict[str, WebSocket] = {}

# Store user_id by websocket (for cleanup on disconnect)
# Format: { websocket_id: user_id }
ws_to_user: Dict[int, str] = {}


def verify_jwt_token(token: str) -> Optional[str]:
    """Verify JWT token and return user_id if valid"""
    try:
        payload = jwt.decode(token, _get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        user_id = payload.get('user_id')
        return user_id
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid JWT token: {e}")
        return None
    except Exception as e:
        logger.error(f"Error verifying JWT: {e}")
        return None


class WebSocketConnectionManager:
    """Manages WebSocket connections for chat"""

    def __init__(self, db, moderation_service):
        self.db = db
        self.moderation_service = moderation_service
        self.authenticated_users: Dict[int, str] = {}  # ws_id -> user_id

    async def connect(self, websocket: WebSocket):
        """Accept WebSocket connection"""
        await websocket.accept()
        logger.info(f"WebSocket connection accepted: {id(websocket)}")

    async def disconnect(self, websocket: WebSocket):
        """Handle WebSocket disconnection"""
        ws_id = id(websocket)
        user_id = ws_to_user.get(ws_id)

        if user_id:
            # Remove from connections
            if ws_connections.get(user_id) == websocket:
                del ws_connections[user_id]
            del ws_to_user[ws_id]
            # Clean up authentication tracking
            if ws_id in self.authenticated_users:
                del self.authenticated_users[ws_id]
            logger.info(f"WebSocket disconnected: user {user_id}, ws {ws_id}")
        else:
            # Clean up authentication tracking even if no user registered
            if ws_id in self.authenticated_users:
                del self.authenticated_users[ws_id]
            logger.info(f"WebSocket disconnected: ws {ws_id} (no user registered)")

    async def register_user(self, websocket: WebSocket, user_id: str, token: Optional[str] = None):
        """Register a user with their WebSocket connection (requires JWT authentication)"""
        ws_id = id(websocket)

        # Verify token if provided
        if token:
            verified_user_id = verify_jwt_token(token)
            if not verified_user_id:
                await self.send_message(websocket, 'error', {
                    'message': 'Invalid or expired authentication token'
                })
                logger.warning(f"Failed authentication attempt for user {user_id}")
                return

            # Ensure the claimed user_id matches the token
            if verified_user_id != user_id:
                await self.send_message(websocket, 'error', {
                    'message': 'User ID mismatch with authentication token'
                })
                logger.warning(f"User ID mismatch: claimed {user_id}, token {verified_user_id}")
                return
        else:
            # Token is required for authentication
            await self.send_message(websocket, 'error', {
                'message': 'Authentication token required'
            })
            logger.warning(f"Registration attempt without token for user {user_id}")
            return

        # Store connections
        ws_connections[user_id] = websocket
        ws_to_user[ws_id] = user_id
        self.authenticated_users[ws_id] = user_id

        logger.info(f"User {user_id} registered with WebSocket {ws_id} (authenticated)")

        # Send registration confirmation
        await self.send_message(websocket, 'registered', {'user_id': user_id})

    async def send_message(self, websocket: WebSocket, message_type: str, data: dict):
        """Send a message to a specific WebSocket"""
        try:
            await websocket.send_json({
                'type': message_type,
                'data': data
            })
        except Exception as e:
            logger.error(f"Error sending message: {e}")

    async def send_to_user(self, user_id: str, message_type: str, data: dict):
        """Send a message to a specific user by user_id"""
        websocket = ws_connections.get(user_id)
        if websocket:
            await self.send_message(websocket, message_type, data)
            return True
        return False

    async def handle_send_message(self, websocket: WebSocket, data: dict):
        """Handle incoming chat message"""
        try:
            conversation_id = data.get('conversation_id')
            sender_id = data.get('sender_id')
            content = data.get('content')

            # Validate required fields
            if not conversation_id:
                await self.send_message(websocket, 'error', {
                    'message': 'Missing conversation_id'
                })
                return

            if not sender_id:
                await self.send_message(websocket, 'error', {
                    'message': 'Missing sender_id'
                })
                return

            if not content or not content.strip():
                await self.send_message(websocket, 'error', {
                    'message': 'Message content cannot be empty'
                })
                return

            # Verify sender is authenticated and matches the claimed sender_id
            ws_id = id(websocket)
            authenticated_user_id = self.authenticated_users.get(ws_id)

            if not authenticated_user_id:
                await self.send_message(websocket, 'error', {
                    'message': 'User not authenticated'
                })
                logger.warning(f"Unauthenticated message attempt from ws {ws_id}")
                return

            if authenticated_user_id != sender_id:
                await self.send_message(websocket, 'error', {
                    'message': 'Sender ID mismatch with authenticated user'
                })
                logger.warning(f"Sender impersonation attempt: authenticated as {authenticated_user_id}, claimed {sender_id}")
                return

            # Get conversation to find recipient
            conv = await self.db.conversations.find_one({'id': conversation_id})
            if not conv:
                await self.send_message(websocket, 'error', {
                    'message': 'Conversation not found'
                })
                return

            # Moderate message with enhanced detection
            try:
                moderation_result = await self.moderation_service.moderate_message(
                    content=content.strip(),
                    conversation_id=conversation_id,
                    sender_id=sender_id,
                    db=self.db
                )
            except Exception as mod_error:
                logger.error(f"Moderation error: {mod_error}", exc_info=True)
                await self.send_message(websocket, 'error', {
                    'message': 'Failed to process message content'
                })
                return

            # If blocked, store flagged message for admin review and notify sender
            if moderation_result['is_blocked']:
                message_data = {
                    'id': str(uuid.uuid4()),
                    'conversation_id': conversation_id,
                    'sender_id': sender_id,
                    'content_original': content,
                    'content_filtered': moderation_result.get('filtered_content', content),
                    'is_blocked': True,
                    'violation_type': moderation_result.get('violation_type'),
                    'timestamp': datetime.utcnow().isoformat(),
                    'status': 'blocked'
                }

                try:
                    await self.db.messages.insert_one(message_data)
                except Exception as save_error:
                    logger.error(f"Failed to save blocked message: {save_error}", exc_info=True)

                warning_data = {
                    'type': 'warning',
                    'message': moderation_result['warning_message'],
                    'violation_type': moderation_result['violation_type'],
                    'order_paid': moderation_result.get('order_paid', False)
                }
                await self.send_message(websocket, 'message_blocked', warning_data)
                return

            # Create message
            message_data = {
                'id': str(uuid.uuid4()),
                'conversation_id': conversation_id,
                'sender_id': sender_id,
                'content_original': content,
                'content_filtered': moderation_result['filtered_content'],
                'is_blocked': False,
                'violation_type': moderation_result.get('violation_type'),
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'sent'
            }

            # Save to DB
            await self.db.messages.insert_one(message_data)

            # Update conversation last message
            await self.db.conversations.update_one(
                {'id': conversation_id},
                {
                    '$set': {
                        'last_message': moderation_result['filtered_content'][:50],
                        'last_message_time': datetime.utcnow().isoformat()
                    }
                }
            )

            # Prepare message for sending
            send_data = {
                'id': message_data['id'],
                'conversation_id': conversation_id,
                'sender_id': sender_id,
                'content': moderation_result['filtered_content'],
                'timestamp': message_data['timestamp'],
                'status': 'delivered',
                'has_masked_content': moderation_result.get('has_masked_content', False),
                'order_paid': moderation_result.get('order_paid', False)
            }

            # Send confirmation to sender
            await self.send_message(websocket, 'message_sent', send_data)

            # If masked content, send warning
            if moderation_result.get('has_masked_content'):
                warning_data = {
                    'type': 'info',
                    'message': moderation_result['warning_message'],
                    'order_paid': moderation_result.get('order_paid', False)
                }
                await self.send_message(websocket, 'content_masked', warning_data)

            # Send to recipient if online
            recipient_id = conv['buyer_id'] if sender_id == conv['seller_id'] else conv['seller_id']
            recipient_sent = await self.send_to_user(recipient_id, 'new_message', send_data)

            if recipient_sent:
                logger.info(f"Message delivered to recipient {recipient_id}")
            else:
                logger.info(f"Recipient {recipient_id} is offline, message saved to DB")

            # Send push notification to recipient (whether online or offline)
            try:
                from notification_service import create_notification, NotificationType

                # Get sender name
                sender = await self.db.users.find_one({'_id': ObjectId(sender_id)})
                sender_name = sender.get('name', 'Someone') if sender else 'Someone'

                # Get service info for context
                service_listing = await self.db.service_listings.find_one({'_id': ObjectId(conv.get('service_id'))}) if conv.get('service_id') else None
                service_name = service_listing.get('service_name', 'a service') if service_listing else 'a service'

                # Create truncated message preview (first 50 chars)
                message_preview = moderation_result['filtered_content'][:50]
                if len(moderation_result['filtered_content']) > 50:
                    message_preview += '...'

                await create_notification(
                    db=self.db,
                    user_id=recipient_id,
                    notification_type=NotificationType.NEW_MESSAGE,
                    title=f"New message from {sender_name}",
                    message=f"About {service_name}: {message_preview}",
                    data={
                        'action': 'view_chat',
                        'conversation_id': conversation_id,
                        'sender_id': sender_id,
                        'service_id': conv.get('service_id')
                    },
                    send_push=True
                )
                logger.info(f"Push notification sent to {recipient_id} for new message")
            except Exception as notif_error:
                logger.error(f"Failed to send message notification: {notif_error}")

        except Exception as e:
            error_msg = str(e) if str(e) else 'An unexpected error occurred'
            logger.error(f"Error handling message: {error_msg}", exc_info=True)
            await self.send_message(websocket, 'error', {
                'message': 'Failed to send message. Please try again.'
            })

    async def handle_join_conversation(self, websocket: WebSocket, data: dict):
        """Handle conversation join request"""
        conversation_id = data.get('conversation_id')
        if conversation_id:
            logger.info(f"User joined conversation {conversation_id}")
            # In a more advanced implementation, you could track conversation rooms
            # For now, we just log it
            await self.send_message(websocket, 'conversation_joined', {
                'conversation_id': conversation_id
            })

    async def handle_message(self, websocket: WebSocket, message_text: str):
        """Handle incoming WebSocket message"""
        try:
            message = json.loads(message_text)
            message_type = message.get('type')
            data = message.get('data', {})

            logger.debug(f"Received message type: {message_type}")

            if message_type == 'register_user':
                user_id = data.get('user_id')
                token = data.get('token')
                if user_id:
                    await self.register_user(websocket, user_id, token)
                else:
                    await self.send_message(websocket, 'error', {
                        'message': 'Missing user_id in register_user'
                    })

            elif message_type == 'send_message':
                await self.handle_send_message(websocket, data)

            elif message_type == 'join_conversation':
                await self.handle_join_conversation(websocket, data)

            else:
                logger.warning(f"Unknown message type: {message_type}")
                await self.send_message(websocket, 'error', {
                    'message': f'Unknown message type: {message_type}'
                })

        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            await self.send_message(websocket, 'error', {
                'message': 'Invalid JSON format'
            })
        except Exception as e:
            logger.error(f"Error handling message: {e}", exc_info=True)
            await self.send_message(websocket, 'error', {
                'message': f'Internal error: {str(e)}'
            })


async def websocket_endpoint(websocket: WebSocket, db, moderation_service):
    """
    Main WebSocket endpoint handler
    Compatible with React Native Hermes engine
    """
    manager = WebSocketConnectionManager(db, moderation_service)

    await manager.connect(websocket)

    try:
        while True:
            # Receive text message
            message = await websocket.receive_text()
            await manager.handle_message(websocket, message)

    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected normally")
        await manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}", exc_info=True)
        await manager.disconnect(websocket)
