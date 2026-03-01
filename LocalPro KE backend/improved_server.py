# This file contains the improved callback endpoint
# Copy this into server.py replacing the existing @api_router.post("/mpesa/callback") function

@api_router.post("/mpesa/callback")
async def mpesa_callback(callback_data: dict):
    """
    M-Pesa callback endpoint
    This is called by M-Pesa to confirm payment status
    Implements idempotency to handle duplicate callbacks
    """
    try:
        logger.info(f"M-Pesa callback received: {callback_data}")

        # Extract M-Pesa response data
        body = callback_data.get('Body', {})
        stk_callback = body.get('stkCallback', {})

        result_code = stk_callback.get('ResultCode')
        checkout_request_id = stk_callback.get('CheckoutRequestID')
        merchant_request_id = stk_callback.get('MerchantRequestID')

        if not checkout_request_id:
            logger.error("No CheckoutRequestID in callback")
            return {'ResultCode': 1, 'ResultDesc': 'No CheckoutRequestID'}

        # Find order by checkout request ID
        order = await db.orders.find_one({'mpesa_checkout_request_id': checkout_request_id})

        if not order:
            logger.error(f"No order found for CheckoutRequestID: {checkout_request_id}")
            return {'ResultCode': 1, 'ResultDesc': 'Order not found'}

        order_id = str(order['_id'])
        current_status = order.get('payment_status')
        payment_method = order.get('payment_method', PaymentMethod.MPESA)

        # Idempotency check - if already processed, return success
        if current_status in [PaymentStatus.PAID, PaymentStatus.PENDING_CASH_PAYMENT, PaymentStatus.FAILED]:
            logger.info(f"Order {order_id} already processed with status {current_status}. Ignoring duplicate callback.")
            return {'ResultCode': 0, 'ResultDesc': 'Already processed'}

        # Success (ResultCode 0)
        if result_code == 0:
            logger.info(f"Payment successful for order {order_id}, method: {payment_method}")

            # Extract callback metadata for audit trail
            callback_metadata = stk_callback.get('CallbackMetadata', {})
            items = callback_metadata.get('Item', [])
            
            # Parse M-Pesa transaction details
            mpesa_receipt_number = None
            amount_paid = None
            transaction_date = None
            phone_number = None
            
            for item in items:
                name = item.get('Name')
                value = item.get('Value')
                if name == 'MpesaReceiptNumber':
                    mpesa_receipt_number = value
                elif name == 'Amount':
                    amount_paid = value
                elif name == 'TransactionDate':
                    transaction_date = value
                elif name == 'PhoneNumber':
                    phone_number = value

            logger.info(f"M-Pesa Receipt: {mpesa_receipt_number}, Amount: {amount_paid}, Phone: {phone_number}")

            if payment_method == PaymentMethod.MPESA:
                # Full M-Pesa payment - split funds
                await split_payment(
                    order_id=order_id,
                    total_amount=order['price'],
                    seller_id=order['seller_id']
                )

                # Update order status to PAID with transaction details
                await db.orders.update_one(
                    {'_id': ObjectId(order_id)},
                    {
                        '$set': {
                            'payment_status': PaymentStatus.PAID,
                            'mpesa_receipt_number': mpesa_receipt_number,
                            'mpesa_transaction_date': transaction_date,
                            'amount_paid': amount_paid,
                            'updated_at': datetime.utcnow()
                        }
                    }
                )

                # Mark listing as sold
                await db.pet_listings.update_one(
                    {'_id': ObjectId(order['pet_id'])},
                    {'$set': {'status': ListingStatus.SOLD, 'updated_at': datetime.utcnow()}}
                )

                logger.info(f"✅ Full M-Pesa payment confirmed and funds split for order {order_id}")

            else:  # Cash payment - only platform fee was paid
                # Platform fee goes to platform wallet
                platform_txn = await create_transaction(
                    user_id=PLATFORM_WALLET_ID,
                    amount=order['platform_fee'],
                    transaction_type=TransactionType.PLATFORM_FEE,
                    status=TransactionStatus.COMPLETED,
                    description=f"5% platform fee for cash order {order_id}",
                    order_id=order_id
                )

                await update_wallet_balance(
                    PLATFORM_WALLET_ID,
                    order['platform_fee'],
                    str(platform_txn['_id'])
                )

                await db.wallets.update_one(
                    {'user_id': PLATFORM_WALLET_ID},
                    {'$inc': {'total_earned': order['platform_fee']}}
                )

                # Update order status to PENDING_CASH_PAYMENT with transaction details
                await db.orders.update_one(
                    {'_id': ObjectId(order_id)},
                    {
                        '$set': {
                            'payment_status': PaymentStatus.PENDING_CASH_PAYMENT,
                            'mpesa_receipt_number': mpesa_receipt_number,
                            'mpesa_transaction_date': transaction_date,
                            'amount_paid': amount_paid,
                            'updated_at': datetime.utcnow()
                        }
                    }
                )

                # Mark listing as sold
                await db.pet_listings.update_one(
                    {'_id': ObjectId(order['pet_id'])},
                    {'$set': {'status': ListingStatus.SOLD, 'updated_at': datetime.utcnow()}}
                )

                logger.info(f"✅ Platform fee paid for cash order {order_id}, awaiting cash payment at handover")

        # Failed or cancelled (ResultCode != 0)
        else:
            result_desc = stk_callback.get('ResultDesc', 'Payment failed or cancelled')
            logger.warning(f"❌ Payment failed for order {order_id}: ResultCode={result_code}, {result_desc}")

            # Update order status to FAILED with detailed error
            await db.orders.update_one(
                {'_id': ObjectId(order_id)},
                {
                    '$set': {
                        'payment_status': PaymentStatus.FAILED,
                        'payment_error_code': result_code,
                        'payment_error_message': result_desc,
                        'updated_at': datetime.utcnow()
                    }
                }
            )

        return {'ResultCode': 0, 'ResultDesc': 'Accepted'}

    except Exception as e:
        logger.error(f"❌ Error processing M-Pesa callback: {str(e)}", exc_info=True)
        return {'ResultCode': 1, 'ResultDesc': 'Internal server error'}


# Improved payment status endpoint
@api_router.get("/payment/status/{order_id}")
async def check_payment_status(
    order_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Check payment status for an order
    Used by frontend to poll for payment confirmation
    Returns detailed status information for UX
    """
    try:
        order = await db.orders.find_one({'_id': ObjectId(order_id)})
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        # Verify user is the buyer or seller
        if order['buyer_id'] != str(current_user['_id']) and order['seller_id'] != str(current_user['_id']):
            raise HTTPException(status_code=403, detail="Not authorized")

        payment_status = order.get('payment_status', PaymentStatus.PENDING)
        payment_method = order.get('payment_method', PaymentMethod.MPESA)

        response = {
            'order_id': order_id,
            'payment_status': payment_status,
            'payment_method': payment_method,
            'price': order['price'],
            'platform_fee': order['platform_fee'],
            'seller_amount': order['seller_amount'],
            'mpesa_receipt_number': order.get('mpesa_receipt_number'),
            'created_at': order['created_at'].isoformat() if order.get('created_at') else None,
            'updated_at': order['updated_at'].isoformat() if order.get('updated_at') else None
        }

        # Add specific messages and status details based on status
        if payment_status == PaymentStatus.PAID:
            if payment_method == PaymentMethod.MPESA:
                response['message'] = '🎉 Payment successful! Your order is confirmed.'
                response['status_title'] = 'Payment Successful'
                response['status_icon'] = 'checkmark-circle'
            else:
                response['message'] = '✅ Platform fee paid! Complete payment in cash at handover.'
                response['status_title'] = 'Payment Confirmed'
                response['status_icon'] = 'checkmark-circle'
        elif payment_status == PaymentStatus.PENDING_CASH_PAYMENT:
            response['message'] = f'Platform fee paid successfully. Pay KES {order["seller_amount"]:.2f} in cash to seller at pickup/delivery.'
            response['status_title'] = 'Awaiting Cash Payment'
            response['status_icon'] = 'cash'
            response['cash_amount_due'] = order['seller_amount']
        elif payment_status == PaymentStatus.FAILED:
            error_msg = order.get('payment_error_message', 'Payment failed or was cancelled')
            response['message'] = f'Payment failed: {error_msg}'
            response['status_title'] = 'Payment Failed'
            response['status_icon'] = 'close-circle'
            response['error_code'] = order.get('payment_error_code')
        elif payment_status == PaymentStatus.PENDING:
            # Calculate elapsed time
            created_at = order.get('created_at')
            if created_at:
                elapsed_seconds = (datetime.utcnow() - created_at).total_seconds()
                response['elapsed_seconds'] = int(elapsed_seconds)
                
                if elapsed_seconds > 90:
                    response['message'] = '⏱️ Still waiting... This is taking longer than usual. Please check your phone.'
                elif elapsed_seconds > 60:
                    response['message'] = '⏳ Waiting for M-Pesa confirmation... Please complete the prompt on your phone.'
                else:
                    response['message'] = '📱 Waiting for payment... Please check your phone for M-Pesa prompt.'
            else:
                response['message'] = 'Waiting for payment confirmation...'
            
            response['status_title'] = 'Processing Payment'
            response['status_icon'] = 'time'

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking payment status: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to check payment status")
