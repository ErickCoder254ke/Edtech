import base64
import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)


class MPesaService:
    """Daraja helper for STK Push + query."""

    def __init__(self) -> None:
        self.environment = os.getenv("MPESA_ENVIRONMENT", "sandbox").lower()
        self.consumer_key = os.getenv("MPESA_CONSUMER_KEY", "")
        self.consumer_secret = os.getenv("MPESA_CONSUMER_SECRET", "")
        self.shortcode = os.getenv("MPESA_LIPA_NA_MPESA_SHORTCODE", "")
        self.passkey = os.getenv("MPESA_LIPA_NA_MPESA_PASSKEY", "")
        self.callback_url = os.getenv("MPESA_CALLBACK_URL", "")
        self.timeout_seconds = int(os.getenv("MPESA_TIMEOUT_SECONDS", "25"))
        self.transaction_type = os.getenv("MPESA_TRANSACTION_TYPE", "CustomerPayBillOnline")
        self.account_reference_max_len = int(os.getenv("MPESA_ACCOUNT_REFERENCE_MAX_LEN", "12"))
        self.transaction_desc_max_len = int(os.getenv("MPESA_TRANSACTION_DESC_MAX_LEN", "50"))

        self.base_url = (
            "https://api.safaricom.co.ke"
            if self.environment == "production"
            else "https://sandbox.safaricom.co.ke"
        )

        self._access_token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None

    @property
    def enabled(self) -> bool:
        return bool(
            self.consumer_key
            and self.consumer_secret
            and self.shortcode
            and self.passkey
            and self.callback_url
        )

    @staticmethod
    def normalize_phone(phone_number: str) -> str:
        phone = phone_number.strip().replace(" ", "")
        if phone.startswith("+"):
            phone = phone[1:]
        if phone.startswith("0"):
            phone = f"254{phone[1:]}"
        if not phone.startswith("254"):
            phone = f"254{phone}"
        return phone

    def _generate_password(self) -> tuple[str, str]:
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        raw = f"{self.shortcode}{self.passkey}{timestamp}"
        return base64.b64encode(raw.encode("utf-8")).decode("utf-8"), timestamp

    async def get_access_token(self) -> Optional[str]:
        if self._access_token and self._token_expiry and datetime.utcnow() < self._token_expiry:
            return self._access_token

        auth = base64.b64encode(
            f"{self.consumer_key}:{self.consumer_secret}".encode("ascii")
        ).decode("ascii")
        headers = {"Authorization": f"Basic {auth}"}
        url = f"{self.base_url}/oauth/v1/generate?grant_type=client_credentials"

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                payload = response.json()
        except Exception as exc:
            logger.error("Daraja token request failed: %s", exc)
            return None

        token = payload.get("access_token")
        if not token:
            logger.error("Daraja token response missing access_token: %s", payload)
            return None

        self._access_token = token
        self._token_expiry = datetime.utcnow() + timedelta(minutes=59)
        return token

    async def stk_push(
        self,
        phone_number: str,
        amount: int,
        account_reference: str,
        transaction_desc: str,
    ) -> Dict[str, Any]:
        if not self.enabled:
            return {"success": False, "error": "M-Pesa is not configured"}

        token = await self.get_access_token()
        if not token:
            return {"success": False, "error": "Unable to authenticate with Daraja"}

        password, timestamp = self._generate_password()
        phone = self.normalize_phone(phone_number)

        payload = {
            "BusinessShortCode": self.shortcode,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": self.transaction_type,
            "Amount": int(amount),
            "PartyA": phone,
            "PartyB": self.shortcode,
            "PhoneNumber": phone,
            "CallBackURL": self.callback_url,
            "AccountReference": account_reference[: self.account_reference_max_len],
            "TransactionDesc": transaction_desc[: self.transaction_desc_max_len],
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(
                    f"{self.base_url}/mpesa/stkpush/v1/processrequest",
                    json=payload,
                    headers={"Authorization": f"Bearer {token}"},
                )
                data = response.json()
        except Exception as exc:
            logger.error("STK push request failed: %s", exc)
            return {"success": False, "error": str(exc)}

        ok = response.status_code == 200 and data.get("ResponseCode") == "0"
        if not ok:
            return {
                "success": False,
                "error": data.get("errorMessage", "STK push failed"),
                "response": data,
            }

        return {
            "success": True,
            "merchant_request_id": data.get("MerchantRequestID"),
            "checkout_request_id": data.get("CheckoutRequestID"),
            "response_code": data.get("ResponseCode"),
            "response_description": data.get("ResponseDescription"),
            "customer_message": data.get("CustomerMessage"),
        }

    async def stk_query(self, checkout_request_id: str) -> Dict[str, Any]:
        if not self.enabled:
            return {"success": False, "error": "M-Pesa is not configured"}

        token = await self.get_access_token()
        if not token:
            return {"success": False, "error": "Unable to authenticate with Daraja"}

        password, timestamp = self._generate_password()
        payload = {
            "BusinessShortCode": self.shortcode,
            "Password": password,
            "Timestamp": timestamp,
            "CheckoutRequestID": checkout_request_id,
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(
                    f"{self.base_url}/mpesa/stkpushquery/v1/query",
                    json=payload,
                    headers={"Authorization": f"Bearer {token}"},
                )
                data = response.json()
        except Exception as exc:
            logger.error("STK query request failed: %s", exc)
            return {"success": False, "error": str(exc)}

        return {
            "success": response.status_code == 200,
            "result_code": str(data.get("ResultCode", "")),
            "result_desc": data.get("ResultDesc", ""),
            "response": data,
        }
