import requests
import base64
from datetime import datetime
import os
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class MPesaService:
    """
    M-Pesa Daraja API Integration Service
    Handles STK Push (Lipa Na M-Pesa Online) and B2C payments
    """
    
    def __init__(self):
        self.environment = os.getenv('MPESA_ENVIRONMENT', 'sandbox')
        self.consumer_key = os.getenv('MPESA_CONSUMER_KEY')
        self.consumer_secret = os.getenv('MPESA_CONSUMER_SECRET')
        self.business_short_code = os.getenv('MPESA_BUSINESS_SHORT_CODE')
        self.lipa_na_mpesa_shortcode = os.getenv('MPESA_LIPA_NA_MPESA_SHORTCODE')
        self.passkey = os.getenv('MPESA_LIPA_NA_MPESA_PASSKEY')
        self.initiator_name = os.getenv('MPESA_INITIATOR_NAME')
        self.callback_url = os.getenv('MPESA_CALLBACK_URL', 'https://webhook.site/unique-url')
        
        # Set API URLs based on environment
        if self.environment == 'sandbox':
            self.base_url = 'https://sandbox.safaricom.co.ke'
        else:
            self.base_url = 'https://api.safaricom.co.ke'
        
        self.access_token = None
        self.token_expiry = None
    
    def get_access_token(self) -> Optional[str]:
        """
        Get OAuth access token from M-Pesa API
        Token is valid for 3600 seconds (1 hour)
        """
        try:
            # Check if we have a valid token
            if self.access_token and self.token_expiry:
                if datetime.utcnow() < self.token_expiry:
                    return self.access_token
            
            # Generate new token
            url = f'{self.base_url}/oauth/v1/generate?grant_type=client_credentials'
            
            # Create basic auth header
            auth_string = f'{self.consumer_key}:{self.consumer_secret}'
            auth_bytes = auth_string.encode('ascii')
            auth_base64 = base64.b64encode(auth_bytes).decode('ascii')
            
            headers = {
                'Authorization': f'Basic {auth_base64}'
            }
            
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            result = response.json()
            self.access_token = result.get('access_token')
            
            # Set expiry time (59 minutes from now to be safe)
            from datetime import timedelta
            self.token_expiry = datetime.utcnow() + timedelta(seconds=3540)
            
            logger.info('M-Pesa access token generated successfully')
            return self.access_token
            
        except Exception as e:
            logger.error(f'Error getting M-Pesa access token: {str(e)}')
            return None
    
    def generate_password(self) -> tuple[str, str]:
        """
        Generate password for STK Push
        Returns: (password, timestamp)
        """
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        data_to_encode = f'{self.lipa_na_mpesa_shortcode}{self.passkey}{timestamp}'
        encoded = base64.b64encode(data_to_encode.encode()).decode('utf-8')
        return encoded, timestamp
    
    def stk_push(
        self,
        phone_number: str,
        amount: int,
        account_reference: str,
        transaction_desc: str
    ) -> Dict[str, Any]:
        """
        Initiate STK Push (Lipa Na M-Pesa Online)
        
        Args:
            phone_number: Customer phone number (format: 254XXXXXXXXX)
            amount: Amount to be paid (minimum 1)
            account_reference: Reference for the transaction (e.g., order ID)
            transaction_desc: Description of the transaction
        
        Returns:
            Dict containing response from M-Pesa API
        """
        try:
            # Format phone number
            if phone_number.startswith('0'):
                phone_number = '254' + phone_number[1:]
            elif phone_number.startswith('+254'):
                phone_number = phone_number[1:]
            elif not phone_number.startswith('254'):
                phone_number = '254' + phone_number
            
            # Get access token
            access_token = self.get_access_token()
            if not access_token:
                return {
                    'success': False,
                    'error': 'Failed to get access token'
                }
            
            # Generate password and timestamp
            password, timestamp = self.generate_password()
            
            # Prepare request
            url = f'{self.base_url}/mpesa/stkpush/v1/processrequest'
            
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            payload = {
                'BusinessShortCode': self.lipa_na_mpesa_shortcode,
                'Password': password,
                'Timestamp': timestamp,
                'TransactionType': 'CustomerPayBillOnline',
                'Amount': int(amount),
                'PartyA': phone_number,
                'PartyB': self.lipa_na_mpesa_shortcode,
                'PhoneNumber': phone_number,
                'CallBackURL': self.callback_url,
                'AccountReference': account_reference,
                'TransactionDesc': transaction_desc
            }
            
            logger.info(f'Initiating STK Push for {phone_number}, amount: {amount}')
            
            response = requests.post(url, json=payload, headers=headers)
            result = response.json()
            
            if response.status_code == 200 and result.get('ResponseCode') == '0':
                logger.info(f'STK Push successful: {result.get("CheckoutRequestID")}')
                return {
                    'success': True,
                    'checkout_request_id': result.get('CheckoutRequestID'),
                    'merchant_request_id': result.get('MerchantRequestID'),
                    'response_code': result.get('ResponseCode'),
                    'response_description': result.get('ResponseDescription'),
                    'customer_message': result.get('CustomerMessage')
                }
            else:
                logger.error(f'STK Push failed: {result}')
                return {
                    'success': False,
                    'error': result.get('errorMessage', 'STK Push failed'),
                    'response': result
                }
                
        except Exception as e:
            logger.error(f'Error initiating STK Push: {str(e)}')
            return {
                'success': False,
                'error': str(e)
            }
    
    def stk_query(self, checkout_request_id: str) -> Dict[str, Any]:
        """
        Query STK Push transaction status
        
        Args:
            checkout_request_id: CheckoutRequestID from STK Push response
        
        Returns:
            Dict containing transaction status
        """
        try:
            access_token = self.get_access_token()
            if not access_token:
                return {
                    'success': False,
                    'error': 'Failed to get access token'
                }
            
            password, timestamp = self.generate_password()
            
            url = f'{self.base_url}/mpesa/stkpushquery/v1/query'
            
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            payload = {
                'BusinessShortCode': self.lipa_na_mpesa_shortcode,
                'Password': password,
                'Timestamp': timestamp,
                'CheckoutRequestID': checkout_request_id
            }
            
            response = requests.post(url, json=payload, headers=headers)
            result = response.json()
            
            return {
                'success': response.status_code == 200,
                'result_code': result.get('ResultCode'),
                'result_desc': result.get('ResultDesc'),
                'response': result
            }
            
        except Exception as e:
            logger.error(f'Error querying STK Push: {str(e)}')
            return {
                'success': False,
                'error': str(e)
            }
    
    def b2c_payment(
        self,
        phone_number: str,
        amount: int,
        remarks: str = 'Payment'
    ) -> Dict[str, Any]:
        """
        Send B2C payment (Business to Customer)
        Used for seller withdrawals
        
        Args:
            phone_number: Recipient phone number (format: 254XXXXXXXXX)
            amount: Amount to send (minimum 10)
            remarks: Transaction remarks
        
        Returns:
            Dict containing response from M-Pesa API
        """
        try:
            # Format phone number
            if phone_number.startswith('0'):
                phone_number = '254' + phone_number[1:]
            elif phone_number.startswith('+254'):
                phone_number = phone_number[1:]
            elif not phone_number.startswith('254'):
                phone_number = '254' + phone_number
            
            access_token = self.get_access_token()
            if not access_token:
                return {
                    'success': False,
                    'error': 'Failed to get access token'
                }
            
            url = f'{self.base_url}/mpesa/b2c/v1/paymentrequest'
            
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            # Note: For production, you need a security credential
            # For sandbox, use the test credential
            security_credential = 'Safaricom999!*!'  # Sandbox default
            
            payload = {
                'InitiatorName': self.initiator_name,
                'SecurityCredential': security_credential,
                'CommandID': 'BusinessPayment',
                'Amount': int(amount),
                'PartyA': self.business_short_code,
                'PartyB': phone_number,
                'Remarks': remarks,
                'QueueTimeOutURL': self.callback_url,
                'ResultURL': self.callback_url,
                'Occasion': 'Withdrawal'
            }
            
            logger.info(f'Initiating B2C payment to {phone_number}, amount: {amount}')
            
            response = requests.post(url, json=payload, headers=headers)
            result = response.json()
            
            if response.status_code == 200 and result.get('ResponseCode') == '0':
                logger.info(f'B2C payment initiated: {result.get("ConversationID")}')
                return {
                    'success': True,
                    'conversation_id': result.get('ConversationID'),
                    'originator_conversation_id': result.get('OriginatorConversationID'),
                    'response_code': result.get('ResponseCode'),
                    'response_description': result.get('ResponseDescription')
                }
            else:
                logger.error(f'B2C payment failed: {result}')
                return {
                    'success': False,
                    'error': result.get('errorMessage', 'B2C payment failed'),
                    'response': result
                }
                
        except Exception as e:
            logger.error(f'Error initiating B2C payment: {str(e)}')
            return {
                'success': False,
                'error': str(e)
            }


# Create singleton instance
mpesa_service = MPesaService()
