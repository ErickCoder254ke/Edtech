import re
from typing import Any, Dict, Optional


class ModerationService:
    """
    Lightweight text moderation focused on user-entered short text fields.
    Current policy blocks:
    - Phone numbers and contact details
    - Email addresses
    - Social handle sharing attempts
    - Off-platform payment/coordination prompts
    - Basic offensive language
    """

    PHONE_PATTERNS = [
        r"\b0[17]\d{8}\b",  # Kenyan local formats like 07XXXXXXXX / 01XXXXXXXX
        r"\b(?:\+?254|254)\d{9}\b",  # Kenyan intl formats
        r"\b\d{10,13}\b",  # long digit runs
        r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",  # grouped number patterns
    ]
    EMAIL_PATTERN = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    SOCIAL_PATTERNS = [
        r"\b(?:whatsapp|wa\.me|telegram|t\.me|instagram|insta|facebook|fb\.com|tiktok|snapchat)\b",
        r"\b(?:dm me|text me|call me|reach me)\b",
        r"\b(?:my number|my contact|my phone|my email)\b",
    ]
    OFF_PLATFORM_PATTERNS = [
        r"\b(?:pay me directly|outside the platform|bypass the app|deal outside)\b",
    ]
    OFFENSIVE_KEYWORDS = {
        "idiot",
        "stupid",
        "fool",
        "scam",
        "fraud",
        "cheat",
        "liar",
        "dumb",
        "hate",
        "kill",
        "threat",
    }
    MAX_LEN_DEFAULT = 1000

    def _matches_any(self, text: str, patterns: list[str]) -> bool:
        return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)

    def moderate_text(
        self,
        *,
        text: Optional[str],
        field_name: str = "text",
        max_len: int = MAX_LEN_DEFAULT,
        allow_empty: bool = True,
    ) -> Dict[str, Any]:
        raw = (text or "").strip()
        if not raw:
            if allow_empty:
                return {
                    "is_blocked": False,
                    "violation_type": None,
                    "warning_message": None,
                    "clean_text": None,
                }
            return {
                "is_blocked": True,
                "violation_type": "empty",
                "warning_message": f"{field_name.capitalize()} cannot be empty.",
                "clean_text": "",
            }

        if len(raw) > max_len:
            return {
                "is_blocked": True,
                "violation_type": "too_long",
                "warning_message": f"{field_name.capitalize()} is too long (max {max_len} characters).",
                "clean_text": raw[:max_len],
            }

        if self._matches_any(raw, self.PHONE_PATTERNS):
            return {
                "is_blocked": True,
                "violation_type": "phone_number",
                "warning_message": f"Phone numbers are not allowed in {field_name}.",
                "clean_text": raw,
            }

        if re.search(self.EMAIL_PATTERN, raw, flags=re.IGNORECASE):
            return {
                "is_blocked": True,
                "violation_type": "email",
                "warning_message": f"Email addresses are not allowed in {field_name}.",
                "clean_text": raw,
            }

        if self._matches_any(raw, self.SOCIAL_PATTERNS):
            return {
                "is_blocked": True,
                "violation_type": "social_contact",
                "warning_message": f"Contact handles are not allowed in {field_name}.",
                "clean_text": raw,
            }

        if self._matches_any(raw, self.OFF_PLATFORM_PATTERNS):
            return {
                "is_blocked": True,
                "violation_type": "off_platform",
                "warning_message": "All class communication and payment must stay on the platform.",
                "clean_text": raw,
            }

        lowered = raw.lower()
        for token in self.OFFENSIVE_KEYWORDS:
            if re.search(rf"\b{re.escape(token)}\b", lowered):
                return {
                    "is_blocked": True,
                    "violation_type": "offensive_language",
                    "warning_message": f"Please keep {field_name} respectful.",
                    "clean_text": raw,
                }

        return {
            "is_blocked": False,
            "violation_type": None,
            "warning_message": None,
            "clean_text": raw,
        }


moderation_service = ModerationService()
