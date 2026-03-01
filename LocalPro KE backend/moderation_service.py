import re
import asyncio
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

# Cloudmersive NLP integration
try:
    import cloudmersive_nlp_api_client
    from cloudmersive_nlp_api_client.rest import ApiException
    HAS_NLP = True
except ImportError:
    HAS_NLP = False

load_dotenv()

class ModerationService:
    """
    Enhanced moderation service with:
    - Order-aware filtering (relaxed after payment)
    - Cross-message number chunk detection
    - Spelled-out number detection
    - Enhanced digit sequence detection
    """
    
    # Contact patterns
    PHONE_PATTERNS = [
        r'\b0[17]\d{8}\b',  # Kenyan mobile
        r'\+254\s?\d{9}',  # Kenya country code
        r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',  # General phone
        r'\b\d{10}\b',  # 10 digit number
    ]
    
    # Detect both full emails (user@domain.tld) and partial handles (user@domain)
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+(?:\.[A-Za-z]{2,})?\b'
    
    SOCIAL_PATTERNS = [
        r'\b(whatsapp|WhatsApp|wa\.me|watsap|watsapp)\b',
        r'\b(telegram|Telegram|t\.me|telgram)\b',
        r'\b(instagram|Instagram|insta|IG)\b',
        r'\b(facebook|Facebook|fb\.com|fb)\b',
        r'\b(twitter|Twitter|X\.com)\b',
        r'\b(tiktok|TikTok|snapchat|Snapchat)\b',
    ]

    # Additional patterns for contact attempts (common misspellings and workarounds)
    CONTACT_WORKAROUNDS = [
        r'\b(call me|text me|dm me|message me|reach me)\b',
        r'\b(my number|my phone|my email|my contact)\b',
        r'\b(contact.*(?:at|on)|reach.*(?:at|on))\b',
        r'@',  # Often used in social handles or email
        r'\b\w+\s*dot\s*com\b',  # "gmail dot com"
        r'\b\w+\s*at\s*\w+\s*dot\b',  # "john at gmail dot"
    ]
    
    OFF_PLATFORM_PATTERNS = [
        r"let's deal outside",
        r"pay me directly",
        r"come pick without ordering",
        r"meet outside",
        r"cash on delivery",
        r"pay cash",
        r"outside the platform",
        r"bypass",
        r"direct payment",
    ]
    
    OFFENSIVE_KEYWORDS = [
        'idiot', 'stupid', 'fool', 'scam', 'fraud', 'cheat',
        'liar', 'dumb', 'hate', 'kill', 'die', 'threat'
    ]
    
    # Spelled-out number mappings
    SPELLED_NUMBERS = {
        'zero': '0', 'one': '1', 'two': '2', 'three': '3', 'four': '4',
        'five': '5', 'six': '6', 'seven': '7', 'eight': '8', 'nine': '9',
        'o': '0',  # Common: "oh seven one"
        # Swahili
        'sifuri': '0', 'moja': '1', 'mbili': '2', 'tatu': '3', 'nne': '4',
        'tano': '5', 'sita': '6', 'saba': '7', 'nane': '8', 'tisa': '9',
    }
    
    # Recent message history per conversation (for chunk detection)
    # Format: {conversation_id: [(timestamp, content, sender_id), ...]}
    message_history: Dict[str, List[Tuple[datetime, str, str]]] = {}
    
    # Time window for chunk detection (5 minutes)
    CHUNK_DETECTION_WINDOW = timedelta(minutes=5)
    CONTACT_UNLOCK_WINDOW = timedelta(days=7)
    
    # Maximum history size per conversation
    MAX_HISTORY_SIZE = 10
    
    def __init__(self):
        self.cloudmersive_key = os.getenv('CLOUDMERSIVE_API_KEY', '66a15b96-9e2a-4ce8-be66-a48dce978b31')
        if HAS_NLP:
            self.configuration = cloudmersive_nlp_api_client.Configuration()
            self.configuration.api_key['Apikey'] = self.cloudmersive_key

    async def moderate_listing_content(self, content: str, field_name: str = 'content') -> Dict:
        """
        Moderate pet listing content (descriptions, breed names, etc.)
        Always strict - no order-based relaxation
        Allows legitimate numbers (ages, prices, weights) but blocks contact patterns

        Args:
            content: Content to moderate (description, breed, etc.)
            field_name: Name of the field being moderated (for error messages)

        Returns:
            Dict with moderation result
        """

        # Validate input
        if not content or not isinstance(content, str):
            return {
                'is_blocked': True,
                'has_masked_content': False,
                'filtered_content': '',
                'violation_type': 'invalid_content',
                'warning_message': f'Invalid {field_name}',
            }

        # Strip and check if empty after stripping
        content = content.strip()
        if not content:
            return {
                'is_blocked': True,
                'has_masked_content': False,
                'filtered_content': '',
                'violation_type': 'empty_content',
                'warning_message': f'{field_name.capitalize()} cannot be empty',
            }

        # Check for spelled-out numbers (phone number attempts)
        spelled_result = self._check_spelled_numbers(content)
        if spelled_result['is_blocked']:
            return {
                **spelled_result,
                'warning_message': f'🚫 Contact information is not allowed in {field_name}. All transactions must happen through PetSoko.'
            }

        # Check for suspicious digit sequences (but allow single reasonable numbers)
        # This is more lenient than chat - we allow things like "2 years", "$500", "3.5kg"
        digit_result = self._check_listing_digit_sequences(content)
        if digit_result['is_blocked']:
            return {
                **digit_result,
                'warning_message': f'🚫 Contact information is not allowed in {field_name}. All transactions must happen through PetSoko.'
            }

        # Rule-based checks (patterns)
        rule_result = self._rule_based_listing_check(content, field_name)
        if rule_result['is_blocked'] or rule_result['has_masked_content']:
            return rule_result

        # NLP check for offensive content
        if self.cloudmersive_key and HAS_NLP:
            nlp_result = await self._nlp_check(content)
            if nlp_result['is_blocked']:
                return {
                    **nlp_result,
                    'warning_message': f'Please keep {field_name} professional and appropriate.'
                }

        return {
            'is_blocked': False,
            'has_masked_content': False,
            'filtered_content': content,
            'violation_type': None,
            'warning_message': None,
        }

    def _check_listing_digit_sequences(self, content: str) -> Dict:
        """
        Check for suspicious digit sequences in listings
        More lenient than chat - allows prices, ages, weights
        But blocks phone-like patterns
        """

        # Find sequences of 7+ digits (likely phone numbers)
        long_sequences = re.findall(r'\d{7,}', content)
        if long_sequences:
            return {
                'is_blocked': True,
                'has_masked_content': False,
                'filtered_content': content,
                'violation_type': 'contact_details',
                'warning_message': '🚫 Contact information is not allowed.',
            }

        # Check for phone-like patterns: multiple groups of 3-4 digits
        # Pattern like "071 234 5678" or "071-234-5678"
        phone_pattern = r'\b\d{3}[\s\-\.]+\d{3}[\s\-\.]+\d{3,4}\b'
        if re.search(phone_pattern, content):
            return {
                'is_blocked': True,
                'has_masked_content': False,
                'filtered_content': content,
                'violation_type': 'contact_details',
                'warning_message': '🚫 Contact information is not allowed.',
            }

        # Check for sequences like "0712345678" or "+254712345678"
        mobile_pattern = r'[\+\d][\d\s\-\.]{8,}'
        matches = re.findall(mobile_pattern, content)
        for match in matches:
            # Remove non-digits to check
            digits_only = re.sub(r'\D', '', match)
            if len(digits_only) >= 9:  # Likely a phone number
                return {
                    'is_blocked': True,
                    'has_masked_content': False,
                    'filtered_content': content,
                    'violation_type': 'contact_details',
                    'warning_message': '🚫 Contact information is not allowed.',
                }

        return {
            'is_blocked': False,
            'has_masked_content': False,
            'filtered_content': content,
            'violation_type': None,
            'warning_message': None,
        }

    def _rule_based_listing_check(self, content: str, field_name: str) -> Dict:
        """Rule-based filtering for listing content"""

        filtered = content
        violations = []

        # Check for phone numbers
        for pattern in self.PHONE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    'is_blocked': True,
                    'has_masked_content': False,
                    'filtered_content': content,
                    'violation_type': 'contact_details',
                    'warning_message': f'🚫 Phone numbers are not allowed in {field_name}. All transactions must happen through PetSoko.',
                }

        # Check for emails
        if re.search(self.EMAIL_PATTERN, content, re.IGNORECASE):
            return {
                'is_blocked': True,
                'has_masked_content': False,
                'filtered_content': content,
                'violation_type': 'contact_details',
                'warning_message': f'🚫 Email addresses are not allowed in {field_name}. All transactions must happen through PetSoko.',
            }

        # Check for social media
        for pattern in self.SOCIAL_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    'is_blocked': True,
                    'has_masked_content': False,
                    'filtered_content': content,
                    'violation_type': 'contact_details',
                    'warning_message': f'🚫 Social media handles are not allowed in {field_name}. All transactions must happen through PetSoko.',
                }

        # Check for contact workarounds
        for pattern in self.CONTACT_WORKAROUNDS:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    'is_blocked': True,
                    'has_masked_content': False,
                    'filtered_content': content,
                    'violation_type': 'contact_details',
                    'warning_message': f'🚫 Contact information is not allowed in {field_name}. All communication must happen through PetSoko messaging.',
                }

        # Check for off-platform attempts
        for pattern in self.OFF_PLATFORM_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    'is_blocked': True,
                    'has_masked_content': False,
                    'filtered_content': content,
                    'violation_type': 'off_platform_transaction',
                    'warning_message': '🚫 All transactions must happen through PetSoko to stay protected.',
                }

        # Check for offensive language
        for keyword in self.OFFENSIVE_KEYWORDS:
            if re.search(rf'\b{keyword}\b', content, re.IGNORECASE):
                return {
                    'is_blocked': True,
                    'has_masked_content': False,
                    'filtered_content': content,
                    'violation_type': 'offensive_language',
                    'warning_message': f'Please keep {field_name} professional and appropriate.',
                }

        return {
            'is_blocked': False,
            'has_masked_content': False,
            'filtered_content': content,
            'violation_type': None,
            'warning_message': None,
        }
    
    async def moderate_message(
        self,
        content: str,
        conversation_id: Optional[str] = None,
        sender_id: Optional[str] = None,
        db = None
    ) -> Dict:
        """
        Main moderation function with order-aware and chunk detection

        Args:
            content: Message content
            conversation_id: ID of the conversation
            sender_id: ID of the message sender
            db: Database connection to check order status
        """

        # Validate input
        if not content or not isinstance(content, str):
            return {
                'is_blocked': True,
                'has_masked_content': False,
                'filtered_content': '',
                'violation_type': 'invalid_content',
                'warning_message': 'Invalid message content',
                'order_paid': False
            }

        # Check if order is paid (relaxed moderation)
        order_paid = False
        if db is not None and conversation_id:
            try:
                order_paid = await self._check_order_paid(conversation_id, db)
            except Exception as e:
                print(f"Error checking order status: {e}")
                # Continue with strict moderation if check fails
                order_paid = False
        
        # If order is paid, only check offensive language
        if order_paid:
            return await self._moderate_post_order(content)
        
        # Pre-order moderation: Full checks
        # 1. Check for number chunks across recent messages
        if conversation_id and sender_id:
            chunk_result = self._check_number_chunks(content, conversation_id, sender_id)
            if chunk_result['is_blocked']:
                # Still store for repeat-attempt detection
                self._add_to_history(conversation_id, content, sender_id)
                return chunk_result
        
        # 2. Check for spelled-out numbers
        spelled_number_result = self._check_spelled_numbers(content)
        if spelled_number_result['is_blocked']:
            if conversation_id and sender_id:
                self._add_to_history(conversation_id, content, sender_id)
            return spelled_number_result
        
        # 3. Check for suspicious digit sequences
        digit_sequence_result = self._check_digit_sequences(content)
        if digit_sequence_result['is_blocked']:
            if conversation_id and sender_id:
                self._add_to_history(conversation_id, content, sender_id)
            return digit_sequence_result
        
        # Store this message in history for future chunk detection
        if conversation_id and sender_id:
            self._add_to_history(conversation_id, content, sender_id)
        
        # 4. Rule-based checks (original patterns)
        rule_result = self._rule_based_check(content)
        
        if rule_result['is_blocked'] or rule_result['has_masked_content']:
            return rule_result
        
        # 5. NLP check for disguised patterns
        if self.cloudmersive_key and HAS_NLP:
            nlp_result = await self._nlp_check(content)
            
            if nlp_result['is_blocked']:
                return nlp_result
        
        return {
            'is_blocked': False,
            'has_masked_content': False,
            'filtered_content': content,
            'violation_type': None,
            'warning_message': None,
            'order_paid': False
        }
    
    async def _check_order_paid(self, conversation_id: str, db) -> bool:
        """Check if contact sharing should be unlocked for this conversation."""
        if db is None:
            return False

        try:
            # Get conversation details
            conv = await db.conversations.find_one({'id': conversation_id})
            if not conv:
                return False

            buyer_id = conv.get('buyer_id')
            seller_id = conv.get('seller_id')
            service_id = conv.get('service_id')

            # Validate we have all required IDs
            if not all([buyer_id, seller_id, service_id]):
                return False

            # Pull recent candidate orders and evaluate business state in Python.
            # Contact sharing remains unlocked only while order is actively in progress.
            unlock_cutoff = datetime.utcnow() - self.CONTACT_UNLOCK_WINDOW
            candidate_orders = await db.orders.find({
                'buyer_id': buyer_id,
                'seller_id': seller_id,
                'service_id': service_id,
                'payment_status': {'$in': ['paid', 'pending_cash_payment']},
                'created_at': {'$gte': unlock_cutoff}
            }).sort('created_at', -1).limit(20).to_list(20)

            for order in candidate_orders:
                payment_status = (order.get('payment_status') or '').lower()
                service_status = (order.get('service_status') or '').lower()
                delivery_status = (order.get('delivery_status') or '').lower()
                completed_by_customer = bool(order.get('service_completed_by_customer'))

                # Terminal states disable contact sharing immediately.
                if payment_status in {'cancelled', 'failed', 'refunded'}:
                    continue
                if service_status in {'completed', 'declined'}:
                    continue
                if delivery_status == 'confirmed':
                    continue
                if completed_by_customer:
                    continue

                # Any remaining paid active order keeps unlock on.
                return True

            return False
        except Exception as e:
            print(f"Error checking order status: {e}")
            return False

    def mask_contact_info(self, content: str) -> str:
        """
        Mask contact-like details in text while preserving general message readability.
        """
        if not content:
            return content

        masked = content

        for pattern in self.PHONE_PATTERNS:
            masked = re.sub(pattern, '[contact hidden]', masked, flags=re.IGNORECASE)

        masked = re.sub(self.EMAIL_PATTERN, '[contact hidden]', masked, flags=re.IGNORECASE)

        for pattern in self.SOCIAL_PATTERNS:
            masked = re.sub(pattern, '[contact hidden]', masked, flags=re.IGNORECASE)

        return masked
    
    async def _moderate_post_order(self, content: str) -> Dict:
        """Relaxed moderation after order is paid - only block offensive language"""
        
        # Check for offensive language (BLOCK completely)
        for keyword in self.OFFENSIVE_KEYWORDS:
            if re.search(rf'\b{keyword}\b', content, re.IGNORECASE):
                return {
                    'is_blocked': True,
                    'has_masked_content': False,
                    'filtered_content': content,
                    'violation_type': 'offensive_language',
                    'warning_message': 'Please keep conversations respectful and professional.',
                    'order_paid': True
                }
        
        # NLP check for profanity/hate speech
        if self.cloudmersive_key and HAS_NLP:
            nlp_result = await self._nlp_check(content)
            if nlp_result['is_blocked']:
                nlp_result['order_paid'] = True
                return nlp_result
        
        # Allow contact details after order is paid
        return {
            'is_blocked': False,
            'has_masked_content': False,
            'filtered_content': content,
            'violation_type': None,
            'warning_message': None,
            'order_paid': True
        }
    
    def _check_spelled_numbers(self, content: str) -> Dict:
        """Detect spelled-out phone numbers like 'zero seven one two three'"""
        
        # Convert to lowercase for matching
        lower_content = content.lower()
        
        # Find all spelled number words (English + Swahili)
        words = re.findall(
            r'(?:zero|one|two|three|four|five|six|seven|eight|nine|o|sifuri|moja|mbili|tatu|nne|tano|sita|saba|nane|tisa)',
            lower_content
        )
        
        # If we find 4+ spelled numbers in sequence, it's likely a phone number
        if len(words) >= 4:
            # Check if they appear close together (within 50 characters)
            # This is a simple heuristic - you could make it more sophisticated
            spelled_pattern = r'(?:zero|one|two|three|four|five|six|seven|eight|nine|o|sifuri|moja|mbili|tatu|nne|tano|sita|saba|nane|tisa)(?:\s+(?:zero|one|two|three|four|five|six|seven|eight|nine|o|sifuri|moja|mbili|tatu|nne|tano|sita|saba|nane|tisa)){3,}'
            
            if re.search(spelled_pattern, lower_content):
                return {
                    'is_blocked': True,
                    'has_masked_content': False,
                    'filtered_content': content,
                    'violation_type': 'contact_details_spelled',
                    'warning_message': '🔒 Contact sharing is only allowed while a paid booking is active. Once completed, contacts are hidden.',
                    'order_paid': False
                }
        
        return {
            'is_blocked': False,
            'has_masked_content': False,
            'filtered_content': content,
            'violation_type': None,
            'warning_message': None,
            'order_paid': False
        }

    def _split_spelled_tokens(self, word: str) -> List[str]:
        """
        Split a concatenated word into known number tokens (English + Swahili).
        Example: "sifurimoja" -> ["sifuri", "moja"]
        """
        tokens = []
        idx = 0
        word = word.lower()
        # Prefer longer tokens first to avoid partial matches
        token_keys = sorted(self.SPELLED_NUMBERS.keys(), key=len, reverse=True)

        while idx < len(word):
            matched = False
            for token in token_keys:
                if word.startswith(token, idx):
                    tokens.append(token)
                    idx += len(token)
                    matched = True
                    break
            if not matched:
                # Skip one character if no token matches
                idx += 1

        return tokens

    def _extract_number_digits(self, content: str) -> str:
        """
        Extract digits from numeric tokens and spelled-out number words in order.
        Example: "zero seven 34" -> "0734"
        """
        normalized = re.sub(r'[^a-zA-Z0-9]+', ' ', content.lower())
        raw_tokens = normalized.split()

        tokens: List[str] = []
        for raw in raw_tokens:
            if raw.isdigit():
                tokens.append(raw)
                continue
            # Direct match
            if raw in self.SPELLED_NUMBERS:
                tokens.append(raw)
                continue
            # Attempt to split concatenated words into number tokens
            tokens.extend(self._split_spelled_tokens(raw))

        digits: List[str] = []
        for token in tokens:
            if token.isdigit():
                digits.append(token)
            else:
                mapped = self.SPELLED_NUMBERS.get(token)
                if mapped is not None:
                    digits.append(mapped)

        return ''.join(digits)
    
    def _check_digit_sequences(self, content: str) -> Dict:
        """
        Detect suspicious digit sequences:
        - 4+ consecutive digits
        - Multiple groups of 3+ digits in one message
        """
        
        # Find all digit sequences of 4+ digits
        long_sequences = re.findall(r'\d{4,}', content)
        
        if long_sequences:
            return {
                'is_blocked': True,
                'has_masked_content': False,
                'filtered_content': content,
                'violation_type': 'suspicious_numbers',
                'warning_message': '🔒 Contact sharing is only allowed while a paid booking is active. Once completed, contacts are hidden.',
                'order_paid': False
            }
        
        # Find all digit sequences of 3+ digits
        digit_groups = re.findall(r'\d{3,}', content)
        
        # If there are 2+ groups of 3+ digits, it's suspicious
        if len(digit_groups) >= 2:
            return {
                'is_blocked': True,
                'has_masked_content': False,
                'filtered_content': content,
                'violation_type': 'suspicious_numbers',
                'warning_message': '🔒 Contact sharing is only allowed while a paid booking is active. Once completed, contacts are hidden.',
                'order_paid': False
            }
        
        return {
            'is_blocked': False,
            'has_masked_content': False,
            'filtered_content': content,
            'violation_type': None,
            'warning_message': None,
            'order_paid': False
        }
    
    def _check_number_chunks(self, content: str, conversation_id: str, sender_id: str) -> Dict:
        """
        Detect number chunking across messages
        Example: "071" then "2345678" within 5 minutes
        """
        
        # Get recent messages from this sender in this conversation
        recent_messages = self._get_recent_messages(conversation_id, sender_id)
        
        # Extract digits from current message (includes spelled-out numbers)
        current_digits = self._extract_number_digits(content)
        
        # If current message contains at least a tiny digit fragment,
        # evaluate aggregate chunking over the whole recent sender history.
        if len(current_digits) >= 1:
            digit_chunks: List[str] = []
            for _, prev_content, _ in recent_messages:
                prev_digits = self._extract_number_digits(prev_content)
                if len(prev_digits) >= 1:
                    digit_chunks.append(prev_digits)

            digit_chunks.append(current_digits)
            combined = ''.join(digit_chunks)

            # Catch evasions like pair-by-pair sending:
            # e.g. "01" -> "14" -> "09" -> ...
            if len(digit_chunks) >= 3 and len(combined) >= 6:
                return {
                    'is_blocked': True,
                    'has_masked_content': False,
                    'filtered_content': content,
                    'violation_type': 'number_chunking',
                    'warning_message': '🔒 Contact sharing is only allowed while a paid booking is active. Once completed, contacts are hidden.',
                    'order_paid': False
                }

            # Backstop: larger combined sequence from fewer chunks.
            if len(combined) >= 7 and len(digit_chunks) >= 2:
                return {
                    'is_blocked': True,
                    'has_masked_content': False,
                    'filtered_content': content,
                    'violation_type': 'number_chunking',
                    'warning_message': '🔒 Contact sharing is only allowed while a paid booking is active. Once completed, contacts are hidden.',
                    'order_paid': False
                }
        
        return {
            'is_blocked': False,
            'has_masked_content': False,
            'filtered_content': content,
            'violation_type': None,
            'warning_message': None,
            'order_paid': False
        }
    
    def _add_to_history(self, conversation_id: str, content: str, sender_id: str):
        """Add message to history for chunk detection"""
        
        if conversation_id not in self.message_history:
            self.message_history[conversation_id] = []
        
        # Add new message
        self.message_history[conversation_id].append((datetime.utcnow(), content, sender_id))
        
        # Keep only recent messages (within time window)
        cutoff_time = datetime.utcnow() - self.CHUNK_DETECTION_WINDOW
        self.message_history[conversation_id] = [
            (ts, msg, sid) for ts, msg, sid in self.message_history[conversation_id]
            if ts > cutoff_time
        ]
        
        # Limit history size
        if len(self.message_history[conversation_id]) > self.MAX_HISTORY_SIZE:
            self.message_history[conversation_id] = self.message_history[conversation_id][-self.MAX_HISTORY_SIZE:]
    
    def _get_recent_messages(self, conversation_id: str, sender_id: str) -> List[Tuple[datetime, str, str]]:
        """Get recent messages from this sender in this conversation"""
        
        if conversation_id not in self.message_history:
            return []
        
        cutoff_time = datetime.utcnow() - self.CHUNK_DETECTION_WINDOW
        
        # Filter messages from this sender within time window
        return [
            (ts, content, sid) for ts, content, sid in self.message_history[conversation_id]
            if sid == sender_id and ts > cutoff_time
        ]
    
    def _rule_based_check(self, content: str) -> Dict:
        """Original rule-based filtering with regex patterns"""
        
        filtered = content
        violations = []
        
        # Check for phone numbers
        for pattern in self.PHONE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                filtered = re.sub(pattern, '***', filtered, flags=re.IGNORECASE)
                violations.append('contact_details')
        
        # Check for emails
        if re.search(self.EMAIL_PATTERN, content, re.IGNORECASE):
            filtered = re.sub(self.EMAIL_PATTERN, '***', filtered, flags=re.IGNORECASE)
            violations.append('contact_details')
        
        # Check for social media
        for pattern in self.SOCIAL_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                filtered = re.sub(pattern, '***', filtered, flags=re.IGNORECASE)
                violations.append('contact_details')
        
        # Check for off-platform attempts (BLOCK completely)
        for pattern in self.OFF_PLATFORM_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    'is_blocked': True,
                    'has_masked_content': False,
                    'filtered_content': content,
                    'violation_type': 'off_platform_transaction',
                    'warning_message': '🚫 All transactions must happen through PetSoko to stay protected.',
                    'order_paid': False
                }
        
        # Check for offensive language (BLOCK completely)
        for keyword in self.OFFENSIVE_KEYWORDS:
            if re.search(rf'\b{keyword}\b', content, re.IGNORECASE):
                return {
                    'is_blocked': True,
                    'has_masked_content': False,
                    'filtered_content': content,
                    'violation_type': 'offensive_language',
                    'warning_message': 'Please keep conversations respectful and professional.',
                    'order_paid': False
                }
        
        # If contact details found, block pre-order messages
        if 'contact_details' in violations:
            return {
                'is_blocked': True,
                'has_masked_content': False,
                'filtered_content': content,
                'violation_type': 'contact_details',
                'warning_message': '🔒 Contact sharing is only allowed while a paid booking is active. Once completed, contacts are hidden.',
                'order_paid': False
            }
        
        return {
            'is_blocked': False,
            'has_masked_content': False,
            'filtered_content': content,
            'violation_type': None,
            'warning_message': None,
            'order_paid': False
        }
    
    async def _nlp_check(self, content: str) -> Dict:
        """NLP-based check using Cloudmersive for profanity and hate speech"""

        try:
            api_instance = cloudmersive_nlp_api_client.AnalyticsApi(
                cloudmersive_nlp_api_client.ApiClient(self.configuration)
            )

            # Check for profanity
            profanity_request = cloudmersive_nlp_api_client.ProfanityAnalysisRequest(
                text_to_analyze=content
            )
            profanity_response = api_instance.analytics_profanity(profanity_request)

            # Check for hate speech
            hate_speech_request = cloudmersive_nlp_api_client.HateSpeechAnalysisRequest(
                text_to_analyze=content
            )
            hate_speech_response = api_instance.analytics_hate_speech(hate_speech_request)

            # If profanity detected
            if profanity_response.successful and profanity_response.profanity_score_result > 0.5:
                return {
                    'is_blocked': True,
                    'has_masked_content': False,
                    'filtered_content': content,
                    'violation_type': 'offensive_language',
                    'warning_message': 'Please keep conversations respectful and professional.',
                    'order_paid': False
                }

            # If hate speech detected
            if hate_speech_response.successful and hate_speech_response.hate_speech_score_result > 0.5:
                return {
                    'is_blocked': True,
                    'has_masked_content': False,
                    'filtered_content': content,
                    'violation_type': 'offensive_language',
                    'warning_message': 'Please keep conversations respectful and professional.',
                    'order_paid': False
                }

            return {
                'is_blocked': False,
                'has_masked_content': False,
                'filtered_content': content,
                'violation_type': None,
                'warning_message': None,
                'order_paid': False
            }

        except ApiException as e:
            print(f"Cloudmersive API error: {e}")
            # On error, allow message but log
            return {
                'is_blocked': False,
                'has_masked_content': False,
                'filtered_content': content,
                'violation_type': None,
                'warning_message': None,
                'order_paid': False
            }
        except Exception as e:
            print(f"NLP check error: {e}")
            return {
                'is_blocked': False,
                'has_masked_content': False,
                'filtered_content': content,
                'violation_type': None,
                'warning_message': None,
                'order_paid': False
            }

# Singleton instance
moderation_service = ModerationService()
