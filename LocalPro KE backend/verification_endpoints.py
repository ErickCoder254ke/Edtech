# ============================================================================
# SELLER VERIFICATION ENDPOINTS
# ============================================================================

# Add these models to server.py after existing Pydantic models (around line 350)

class VerificationStatus(str, Enum):
    NOT_SUBMITTED = "not_submitted"
    PENDING = "pending"
    PAYMENT_PENDING = "payment_pending"
    UNDER_REVIEW = "under_review"
    VERIFIED = "verified"
    REJECTED = "rejected"

class VerificationDocumentCreate(BaseModel):
    national_id_front_url: str
    national_id_back_url: str
    business_license_url: Optional[str] = None
    proof_of_address_url: Optional[str] = None
    selfie_url: Optional[str] = None
    agree_to_terms: bool

class VerificationPaymentRequest(BaseModel):
    verification_id: str
    payment_method: PaymentMethod  # wallet or mpesa
    phone_number: Optional[str] = None  # Required if mpesa

# Constants
VERIFICATION_FEE = 100.0  # 100 KES verification fee

# Add these endpoints to api_router before line 10137

@api_router.post("/verification/submit")
async def submit_verification(
    verification_data: VerificationDocumentCreate,
    current_user: dict = Depends(get_current_user)
):
    """Submit verification documents for seller verification"""
    try:
        # Check if user is a seller
        if current_user.get('role') != UserRole.SELLER:
            raise HTTPException(
                status_code=403,
                detail="Only sellers can submit verification"
            )
        
        # Check if already verified
        if current_user.get('kyc_status') == 'verified':
            raise HTTPException(
                status_code=400,
                detail="You are already verified"
            )
        
        # Check for terms agreement
        if not verification_data.agree_to_terms:
            raise HTTPException(
                status_code=400,
                detail="You must agree to the verification terms"
            )
        
        # Check if verification already submitted
        existing_verification = await db.verifications.find_one({
            'user_id': str(current_user['_id']),
            'status': {'$in': ['pending', 'payment_pending', 'under_review']}
        })
        
        if existing_verification:
            raise HTTPException(
                status_code=400,
                detail="Verification already submitted. Please wait for review."
            )
        
        # Create verification record
        verification = {
            'user_id': str(current_user['_id']),
            'user_name': current_user.get('name'),
            'user_email': current_user.get('email'),
            'user_phone': current_user.get('phone'),
            'documents': {
                'national_id_front_url': verification_data.national_id_front_url,
                'national_id_back_url': verification_data.national_id_back_url,
                'business_license_url': verification_data.business_license_url,
                'proof_of_address_url': verification_data.proof_of_address_url,
                'selfie_url': verification_data.selfie_url
            },
            'status': VerificationStatus.PAYMENT_PENDING,
            'verification_fee': VERIFICATION_FEE,
            'payment_status': 'pending',
            'agreed_to_terms': True,
            'submitted_at': datetime.utcnow(),
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        result = await db.verifications.insert_one(verification)
        verification_id = str(result.inserted_id)
        
        logger.info(f"✅ Verification submitted for user {current_user['_id']} - Verification ID: {verification_id}")
        
        return {
            'message': 'Verification submitted successfully. Please complete payment to continue.',
            'verification_id': verification_id,
            'verification_fee': VERIFICATION_FEE,
            'status': VerificationStatus.PAYMENT_PENDING
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error submitting verification: {e}")
        raise HTTPException(status_code=500, detail="Failed to submit verification")


@api_router.post("/verification/pay")
async def pay_verification_fee(
    payment_data: VerificationPaymentRequest,
    current_user: dict = Depends(get_current_user)
):
    """Process verification fee payment"""
    try:
        logger.info(f"🔄 Processing verification payment for user {current_user['_id']}, verification_id: {payment_data.verification_id}, method: {payment_data.payment_method}")

        # Validate verification_id format
        try:
            verification_obj_id = ObjectId(payment_data.verification_id)
        except Exception as e:
            logger.error(f"❌ Invalid verification_id format: {payment_data.verification_id} - {e}")
            raise HTTPException(status_code=400, detail=f"Invalid verification ID format")

        # Get verification
        verification = await db.verifications.find_one({
            '_id': verification_obj_id,
            'user_id': str(current_user['_id'])
        })

        if not verification:
            logger.error(f"❌ Verification not found: {payment_data.verification_id} for user {current_user['_id']}")
            raise HTTPException(status_code=404, detail="Verification not found or you don't have permission to access it")

        if verification.get('payment_status') == 'paid':
            logger.warning(f"⚠️ Verification {payment_data.verification_id} already paid")
            raise HTTPException(status_code=400, detail="Verification fee already paid")

        verification_fee = verification.get('verification_fee', VERIFICATION_FEE)
        logger.info(f"💰 Verification fee amount: KES {verification_fee}")
        
        if payment_data.payment_method == PaymentMethod.WALLET:
            # Process wallet payment
            logger.info(f"💳 Processing wallet payment for user {current_user['_id']}")
            user_wallet = await get_or_create_wallet(str(current_user['_id']))

            current_balance = float(user_wallet.get('balance', 0))
            logger.info(f"💰 User wallet balance: KES {current_balance}, Required: KES {verification_fee}")

            if current_balance < verification_fee:
                logger.warning(f"⚠️ Insufficient wallet balance for user {current_user['_id']}: has {current_balance}, needs {verification_fee}")
                raise HTTPException(
                    status_code=400,
                    detail=f"Insufficient wallet balance. You have KES {current_balance:.2f}, but need KES {verification_fee:.2f}. Please top up your wallet or use M-Pesa payment."
                )
            
            # Deduct from user wallet
            await db.wallets.update_one(
                {'user_id': str(current_user['_id'])},
                {'$inc': {'balance': -verification_fee}}
            )
            
            # Add to platform wallet
            platform_wallet = await get_or_create_wallet(PLATFORM_WALLET_ID)
            await db.wallets.update_one(
                {'user_id': PLATFORM_WALLET_ID},
                {'$inc': {'balance': verification_fee}}
            )
            
            # Create user deduction transaction
            await create_transaction(
                user_id=str(current_user['_id']),
                amount=-verification_fee,
                transaction_type=TransactionType.PLATFORM_FEE_VERIFICATION,
                status=TransactionStatus.COMPLETED,
                description=f'Seller verification fee (Verification ID: {payment_data.verification_id[:8]})',
                order_id=None
            )

            # Create platform earning transaction
            await create_transaction(
                user_id=PLATFORM_WALLET_ID,
                amount=verification_fee,
                transaction_type=TransactionType.PLATFORM_FEE_VERIFICATION,
                status=TransactionStatus.COMPLETED,
                description=f'Verification fee from {current_user["name"]} (Verification ID: {payment_data.verification_id[:8]})',
                order_id=None
            )
            
            # Update verification payment status
            await db.verifications.update_one(
                {'_id': ObjectId(payment_data.verification_id)},
                {
                    '$set': {
                        'payment_status': 'paid',
                        'payment_method': 'wallet',
                        'paid_at': datetime.utcnow(),
                        'status': VerificationStatus.UNDER_REVIEW,
                        'updated_at': datetime.utcnow()
                    }
                }
            )
            
            # Update user KYC status to pending
            await db.users.update_one(
                {'_id': current_user['_id']},
                {'$set': {'kyc_status': KYCStatus.PENDING}}
            )
            
            # Send notification
            await create_notification(
                db=db,
                user_id=str(current_user['_id']),
                notification_type=NotificationType.ORDER_UPDATE,
                title="Verification Submitted",
                message=f"Your verification has been submitted for review. You will be notified once reviewed.",
                data={'verification_id': payment_data.verification_id}
            )
            
            logger.info(f"✅ Verification fee paid for user {current_user['_id']} via wallet")
            
            return {
                'success': True,
                'message': 'Verification fee paid successfully. Your verification is now under review.',
                'payment_method': 'wallet',
                'amount': verification_fee,
                'status': VerificationStatus.UNDER_REVIEW
            }
        
        elif payment_data.payment_method == PaymentMethod.MPESA:
            # Validate phone number
            if not payment_data.phone_number:
                raise HTTPException(status_code=400, detail="Phone number required for M-Pesa payment")
            
            # Validate phone format
            phone = payment_data.phone_number.strip()
            if not phone.startswith('254'):
                if phone.startswith('0'):
                    phone = '254' + phone[1:]
                elif phone.startswith('+254'):
                    phone = phone[1:]
                elif phone.startswith('7') or phone.startswith('1'):
                    phone = '254' + phone
            
            if len(phone) != 12 or not phone.isdigit():
                raise HTTPException(status_code=400, detail="Invalid phone number format. Use format: 254XXXXXXXXX")
            
            # Initiate M-Pesa STK push
            result = mpesa_service.stk_push(
                phone_number=phone,
                amount=int(verification_fee),
                account_reference=f"VER{payment_data.verification_id[:8]}",
                transaction_desc=f"Seller verification fee - PetSoko"
            )
            
            if not result.get('success'):
                error_msg = result.get('errorMessage', 'M-Pesa payment failed')
                raise HTTPException(status_code=400, detail=f"Payment failed: {error_msg}")
            
            # Update verification with M-Pesa checkout ID
            await db.verifications.update_one(
                {'_id': ObjectId(payment_data.verification_id)},
                {
                    '$set': {
                        'payment_method': 'mpesa',
                        'mpesa_checkout_request_id': result.get('CheckoutRequestID'),
                        'mpesa_merchant_request_id': result.get('MerchantRequestID'),
                        'phone_number': phone,
                        'updated_at': datetime.utcnow()
                    }
                }
            )
            
            logger.info(f"✅ M-Pesa STK push initiated for verification {payment_data.verification_id}")
            
            return {
                'success': True,
                'message': 'M-Pesa payment initiated. Please complete payment on your phone.',
                'payment_method': 'mpesa',
                'amount': verification_fee,
                'checkout_request_id': result.get('CheckoutRequestID'),
                'merchant_request_id': result.get('MerchantRequestID')
            }
        
        else:
            raise HTTPException(status_code=400, detail="Invalid payment method. Use 'wallet' or 'mpesa'")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error processing verification payment for user {current_user['_id']}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to process payment. Please try again or contact support if the issue persists.")


@api_router.get("/verification/status")
async def get_verification_status(current_user: dict = Depends(get_current_user)):
    """Get current user's verification status"""
    try:
        # Get latest verification
        verification = await db.verifications.find_one(
            {'user_id': str(current_user['_id'])},
            sort=[('created_at', -1)]
        )
        
        if not verification:
            return {
                'has_verification': False,
                'status': VerificationStatus.NOT_SUBMITTED,
                'kyc_status': current_user.get('kyc_status', 'pending'),
                'verification_fee': VERIFICATION_FEE
            }
        
        return {
            'has_verification': True,
            'verification_id': str(verification['_id']),
            'status': verification.get('status'),
            'payment_status': verification.get('payment_status'),
            'kyc_status': current_user.get('kyc_status'),
            'submitted_at': verification.get('submitted_at'),
            'paid_at': verification.get('paid_at'),
            'reviewed_at': verification.get('reviewed_at'),
            'rejection_reason': verification.get('rejection_reason'),
            'verification_fee': verification.get('verification_fee', VERIFICATION_FEE)
        }
    
    except Exception as e:
        logger.error(f"Error getting verification status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get verification status")


# Admin endpoints for verification management

@api_router.get("/admin/verifications")
async def get_all_verifications(
    status: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """Get all verification requests (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        # Build query
        query = {}
        if status:
            query['status'] = status
        if search:
            query['$or'] = [
                {'user_name': {'$regex': search, '$options': 'i'}},
                {'user_email': {'$regex': search, '$options': 'i'}},
                {'user_phone': {'$regex': search, '$options': 'i'}}
            ]
        
        # Get total count
        total = await db.verifications.count_documents(query)
        
        # Get verifications with pagination
        skip = (page - 1) * limit
        verifications = await db.verifications.find(query).sort('created_at', -1).skip(skip).limit(limit).to_list(None)
        
        # Format response
        formatted_verifications = []
        for v in verifications:
            formatted_verifications.append({
                'id': str(v['_id']),
                'user_id': v['user_id'],
                'user_name': v.get('user_name'),
                'user_email': v.get('user_email'),
                'user_phone': v.get('user_phone'),
                'status': v.get('status'),
                'payment_status': v.get('payment_status'),
                'verification_fee': v.get('verification_fee', VERIFICATION_FEE),
                'documents': v.get('documents', {}),
                'submitted_at': v.get('submitted_at').isoformat() if v.get('submitted_at') else None,
                'paid_at': v.get('paid_at').isoformat() if v.get('paid_at') else None,
                'reviewed_at': v.get('reviewed_at').isoformat() if v.get('reviewed_at') else None,
                'reviewed_by': v.get('reviewed_by'),
                'rejection_reason': v.get('rejection_reason')
            })
        
        return {
            'verifications': formatted_verifications,
            'total': total,
            'page': page,
            'limit': limit,
            'totalPages': (total + limit - 1) // limit
        }
    
    except Exception as e:
        logger.error(f"Error getting verifications: {e}")
        raise HTTPException(status_code=500, detail="Failed to get verifications")


@api_router.get("/admin/verifications/{verification_id}")
async def get_verification_details(
    verification_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get verification details (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        verification = await db.verifications.find_one({'_id': ObjectId(verification_id)})
        
        if not verification:
            raise HTTPException(status_code=404, detail="Verification not found")
        
        # Get user details
        user = await db.users.find_one({'_id': ObjectId(verification['user_id'])})
        
        return {
            'id': str(verification['_id']),
            'user': {
                'id': verification['user_id'],
                'name': user.get('name') if user else verification.get('user_name'),
                'email': user.get('email') if user else verification.get('user_email'),
                'phone': user.get('phone') if user else verification.get('user_phone'),
                'kyc_status': user.get('kyc_status') if user else 'unknown'
            },
            'documents': verification.get('documents', {}),
            'status': verification.get('status'),
            'payment_status': verification.get('payment_status'),
            'payment_method': verification.get('payment_method'),
            'verification_fee': verification.get('verification_fee', VERIFICATION_FEE),
            'submitted_at': verification.get('submitted_at'),
            'paid_at': verification.get('paid_at'),
            'reviewed_at': verification.get('reviewed_at'),
            'reviewed_by': verification.get('reviewed_by'),
            'rejection_reason': verification.get('rejection_reason'),
            'created_at': verification.get('created_at'),
            'updated_at': verification.get('updated_at')
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting verification details: {e}")
        raise HTTPException(status_code=500, detail="Failed to get verification details")


@api_router.post("/admin/verifications/{verification_id}/approve")
async def approve_verification(
    verification_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Approve seller verification (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        verification = await db.verifications.find_one({'_id': ObjectId(verification_id)})
        
        if not verification:
            raise HTTPException(status_code=404, detail="Verification not found")
        
        if verification.get('payment_status') != 'paid':
            raise HTTPException(status_code=400, detail="Verification fee must be paid before approval")
        
        # Update verification status
        await db.verifications.update_one(
            {'_id': ObjectId(verification_id)},
            {
                '$set': {
                    'status': VerificationStatus.VERIFIED,
                    'reviewed_at': datetime.utcnow(),
                    'reviewed_by': str(current_user['_id']),
                    'updated_at': datetime.utcnow()
                }
            }
        )
        
        # Update user KYC status to verified
        await db.users.update_one(
            {'_id': ObjectId(verification['user_id'])},
            {
                '$set': {
                    'kyc_status': KYCStatus.VERIFIED,
                    'kyc_verified_at': datetime.utcnow(),
                    'kyc_verified_by': str(current_user['_id']),
                    'updated_at': datetime.utcnow()
                }
            }
        )
        
        # Send notification to user
        await create_notification(
            db=db,
            user_id=verification['user_id'],
            notification_type=NotificationType.ORDER_UPDATE,
            title="✅ Verification Approved!",
            message="Congratulations! Your seller verification has been approved. You now have a verified badge on your listings.",
            data={'verification_id': verification_id}
        )
        
        logger.info(f"✅ Verification {verification_id} approved by admin {current_user['name']}")
        
        return {
            'message': 'Verification approved successfully',
            'verification_id': verification_id,
            'user_id': verification['user_id']
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error approving verification: {e}")
        raise HTTPException(status_code=500, detail="Failed to approve verification")


@api_router.post("/admin/verifications/{verification_id}/reject")
async def reject_verification(
    verification_id: str,
    reason: str,
    current_user: dict = Depends(get_current_user)
):
    """Reject seller verification (admin only)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if not reason or len(reason.strip()) < 10:
        raise HTTPException(status_code=400, detail="Rejection reason must be at least 10 characters")
    
    try:
        verification = await db.verifications.find_one({'_id': ObjectId(verification_id)})
        
        if not verification:
            raise HTTPException(status_code=404, detail="Verification not found")
        
        # Update verification status
        await db.verifications.update_one(
            {'_id': ObjectId(verification_id)},
            {
                '$set': {
                    'status': VerificationStatus.REJECTED,
                    'rejection_reason': reason,
                    'reviewed_at': datetime.utcnow(),
                    'reviewed_by': str(current_user['_id']),
                    'updated_at': datetime.utcnow()
                }
            }
        )
        
        # Update user KYC status to rejected
        await db.users.update_one(
            {'_id': ObjectId(verification['user_id'])},
            {
                '$set': {
                    'kyc_status': KYCStatus.REJECTED,
                    'kyc_rejection_reason': reason,
                    'kyc_rejected_at': datetime.utcnow(),
                    'kyc_rejected_by': str(current_user['_id']),
                    'updated_at': datetime.utcnow()
                }
            }
        )
        
        # Send notification to user
        await create_notification(
            db=db,
            user_id=verification['user_id'],
            notification_type=NotificationType.ORDER_UPDATE,
            title="Verification Rejected",
            message=f"Your verification has been rejected. Reason: {reason}. You can submit a new verification with corrected documents.",
            data={'verification_id': verification_id, 'reason': reason}
        )
        
        logger.info(f"❌ Verification {verification_id} rejected by admin {current_user['name']}")
        
        return {
            'message': 'Verification rejected',
            'verification_id': verification_id,
            'user_id': verification['user_id'],
            'reason': reason
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error rejecting verification: {e}")
        raise HTTPException(status_code=500, detail="Failed to reject verification")
