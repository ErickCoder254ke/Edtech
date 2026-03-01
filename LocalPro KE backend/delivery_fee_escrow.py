"""
Delivery Fee Escrow Logic
Handles delivery fee payments with escrow protection and auto-reversal functionality.

Key Features:
1. Delivery fees are held in escrow (pending_balance) until buyer confirms receipt
2. Auto-reversal to buyer's wallet if confirmation doesn't occur within 24 hours after delivery date
3. Seller cannot withdraw delivery fees while in escrow
4. Independent tracking from main pet payment
"""

from datetime import datetime, timedelta
from bson import ObjectId
import logging

logger = logging.getLogger(__name__)

# Import these from server.py when integrating
# from server import (
#     db, create_transaction, update_wallet_balance, get_or_create_wallet,
#     TransactionType, TransactionStatus, DeliveryFeeStatus, create_notification,
#     NotificationType
# )


async def hold_delivery_fee_pending(order_id: str, delivery_fee: float, buyer_id: str, seller_id: str, db, create_transaction, update_wallet_balance, get_or_create_wallet, TransactionType, TransactionStatus):
    """
    Hold delivery fee in seller's pending_balance (escrow) until buyer confirms receipt.
    
    This creates an escrow-like protection for delivery fees:
    - Buyer has paid the delivery fee
    - Seller is notified but cannot withdraw it yet
    - Amount is locked in seller's pending_balance
    - Will be released when buyer confirms receipt OR auto-reversed after 24 hours
    
    Args:
        order_id: The order ID
        delivery_fee: Amount to hold in escrow
        buyer_id: Buyer's user ID (for reversal tracking)
        seller_id: Seller's user ID
        db: Database connection
        create_transaction: Transaction creation function
        update_wallet_balance: Wallet update function
        get_or_create_wallet: Wallet getter function
        TransactionType: Transaction type enum
        TransactionStatus: Transaction status enum
    """
    try:
        # Ensure seller's wallet exists
        seller_wallet = await get_or_create_wallet(seller_id)
        
        # Add delivery fee to seller's pending_balance (ESCROW - not available for withdrawal)
        await db.wallets.update_one(
            {'user_id': seller_id},
            {
                '$inc': {'pending_balance': delivery_fee},
                '$set': {'updated_at': datetime.utcnow()}
            }
        )
        
        # Create PENDING transaction for delivery fee (seller side)
        # This transaction will be marked COMPLETED when buyer confirms receipt
        # or REVERSED if auto-reversal triggers
        seller_txn = await create_transaction(
            user_id=seller_id,
            amount=delivery_fee,
            transaction_type=TransactionType.DELIVERY_FEE_PAYMENT,
            status=TransactionStatus.PENDING,
            description=f"Delivery fee for order {order_id[:8]} (in escrow - awaiting buyer confirmation)",
            order_id=order_id
        )
        
        logger.info(
            f"✅ Delivery fee KSh {delivery_fee} held in escrow for order {order_id}. "
            f"Seller: {seller_id}, Pending txn: {str(seller_txn['_id'])}"
        )
        
        return seller_txn
        
    except Exception as e:
        logger.error(f"❌ Error holding delivery fee in escrow for order {order_id}: {str(e)}", exc_info=True)
        raise


async def release_delivery_fee_pending(order_id: str, seller_id: str, db, get_or_create_wallet, TransactionType, TransactionStatus):
    """
    Release delivery fee from escrow to seller's available balance.
    Called when buyer confirms receipt of the pet.
    
    This moves the delivery fee from pending_balance to balance, making it
    available for the seller to withdraw.
    
    Args:
        order_id: The order ID
        seller_id: Seller's user ID
        db: Database connection
        get_or_create_wallet: Wallet getter function
        TransactionType: Transaction type enum
        TransactionStatus: Transaction status enum
    """
    try:
        # Find the pending delivery fee transaction
        delivery_txn = await db.transactions.find_one({
            'order_id': order_id,
            'user_id': seller_id,
            'transaction_type': TransactionType.DELIVERY_FEE_PAYMENT,
            'status': TransactionStatus.PENDING
        })
        
        if not delivery_txn:
            logger.warning(f"No pending delivery fee transaction found for order {order_id}")
            return False
        
        delivery_fee = delivery_txn['amount']
        seller_wallet = await get_or_create_wallet(seller_id)
        current_balance = seller_wallet.get('balance', 0.0)
        
        # Move from pending_balance to available balance
        await db.wallets.update_one(
            {'user_id': seller_id},
            {
                '$inc': {
                    'pending_balance': -delivery_fee,  # Remove from escrow
                    'balance': delivery_fee,            # Add to available balance
                    'total_earned': delivery_fee        # Track total earnings
                },
                '$set': {'updated_at': datetime.utcnow()}
            }
        )
        
        # Mark transaction as COMPLETED
        await db.transactions.update_one(
            {'_id': delivery_txn['_id']},
            {
                '$set': {
                    'status': TransactionStatus.COMPLETED,
                    'description': f"Delivery fee released for order {order_id[:8]} (buyer confirmed receipt)",
                    'balance_before': current_balance,
                    'balance_after': current_balance + delivery_fee,
                    'updated_at': datetime.utcnow()
                }
            }
        )
        
        logger.info(
            f"✅ Delivery fee KSh {delivery_fee} released from escrow to seller {seller_id} "
            f"for order {order_id}"
        )
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Error releasing delivery fee for order {order_id}: {str(e)}", exc_info=True)
        raise


async def reverse_delivery_fee(order_id: str, delivery_fee: float, buyer_id: str, seller_id: str, reason: str, db, create_transaction, update_wallet_balance, get_or_create_wallet, TransactionType, TransactionStatus, create_notification, NotificationType):
    """
    Reverse delivery fee from seller's escrow back to buyer's wallet.
    Called when buyer doesn't confirm receipt within 24 hours after delivery date.
    
    This is the auto-reversal mechanism that protects buyers:
    - Removes delivery fee from seller's pending_balance
    - Credits the amount back to buyer's wallet
    - Marks the seller's transaction as REVERSED
    - Creates a refund transaction for the buyer
    - Notifies both parties
    
    Args:
        order_id: The order ID
        delivery_fee: Amount to reverse
        buyer_id: Buyer's user ID (receives the refund)
        seller_id: Seller's user ID (loses the escrowed amount)
        reason: Reason for reversal (for audit trail)
        db: Database connection
        create_transaction: Transaction creation function
        update_wallet_balance: Wallet update function
        get_or_create_wallet: Wallet getter function
        TransactionType: Transaction type enum
        TransactionStatus: Transaction status enum
        create_notification: Notification creation function
        NotificationType: Notification type enum
    """
    try:
        # Find the pending delivery fee transaction (seller side)
        delivery_txn = await db.transactions.find_one({
            'order_id': order_id,
            'user_id': seller_id,
            'transaction_type': TransactionType.DELIVERY_FEE_PAYMENT,
            'status': TransactionStatus.PENDING
        })
        
        if not delivery_txn:
            logger.warning(f"No pending delivery fee transaction to reverse for order {order_id}")
            return False
        
        # Ensure both wallets exist
        seller_wallet = await get_or_create_wallet(seller_id)
        buyer_wallet = await get_or_create_wallet(buyer_id)
        
        # Remove from seller's pending_balance (escrow)
        await db.wallets.update_one(
            {'user_id': seller_id},
            {
                '$inc': {'pending_balance': -delivery_fee},
                '$set': {'updated_at': datetime.utcnow()}
            }
        )
        
        # Mark seller's transaction as REVERSED
        await db.transactions.update_one(
            {'_id': delivery_txn['_id']},
            {
                '$set': {
                    'status': TransactionStatus.REVERSED,
                    'description': f"Delivery fee reversed for order {order_id[:8]} - {reason}",
                    'updated_at': datetime.utcnow()
                }
            }
        )
        
        # Credit buyer's wallet (refund)
        buyer_refund_txn = await create_transaction(
            user_id=buyer_id,
            amount=delivery_fee,
            transaction_type=TransactionType.REFUND,
            status=TransactionStatus.COMPLETED,
            description=f"Delivery fee refund for order {order_id[:8]} - {reason}",
            order_id=order_id
        )
        
        await update_wallet_balance(
            buyer_id,
            delivery_fee,
            str(buyer_refund_txn['_id'])
        )
        
        # Update order delivery_fee_status to indicate reversal
        await db.orders.update_one(
            {'_id': ObjectId(order_id)},
            {
                '$set': {
                    'delivery_fee_reversed': True,
                    'delivery_fee_reversed_at': datetime.utcnow(),
                    'delivery_fee_reversal_reason': reason,
                    'updated_at': datetime.utcnow()
                }
            }
        )
        
        logger.info(
            f"✅ Delivery fee KSh {delivery_fee} reversed from seller {seller_id} "
            f"to buyer {buyer_id} for order {order_id}. Reason: {reason}"
        )
        
        # Notify buyer about refund
        try:
            await create_notification(
                db=db,
                user_id=buyer_id,
                notification_type=NotificationType.REFUND,
                title="Delivery Fee Refunded 💰",
                message=f"Your delivery fee of KSh {int(delivery_fee)} has been refunded to your wallet. {reason}",
                data={
                    'action': 'view_wallet',
                    'order_id': order_id,
                    'amount': delivery_fee
                }
            )
        except Exception as e:
            logger.error(f"Failed to notify buyer about delivery fee refund: {e}")
        
        # Notify seller about reversal
        try:
            await create_notification(
                db=db,
                user_id=seller_id,
                notification_type=NotificationType.ORDER_CANCELLED,
                title="Delivery Fee Reversed ⚠️",
                message=f"Delivery fee of KSh {int(delivery_fee)} has been reversed. {reason}",
                data={
                    'action': 'view_order',
                    'order_id': order_id,
                    'amount': delivery_fee
                }
            )
        except Exception as e:
            logger.error(f"Failed to notify seller about delivery fee reversal: {e}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Error reversing delivery fee for order {order_id}: {str(e)}", exc_info=True)
        raise


async def check_and_process_auto_reversals(db, create_transaction, update_wallet_balance, get_or_create_wallet, TransactionType, TransactionStatus, create_notification, NotificationType):
    """
    Check for orders that need auto-reversal and process them.
    
    Auto-reversal criteria:
    - Order has a delivery fee in escrow (pending_balance)
    - 24 hours have passed since the agreed delivery date
    - Buyer has not confirmed receipt
    - Delivery fee has not been reversed yet
    
    This should be called periodically (e.g., every hour via a cron job or scheduler).
    
    Args:
        db: Database connection
        create_transaction: Transaction creation function
        update_wallet_balance: Wallet update function
        get_or_create_wallet: Wallet getter function
        TransactionType: Transaction type enum
        TransactionStatus: Transaction status enum
        create_notification: Notification creation function
        NotificationType: Notification type enum
        
    Returns:
        Number of orders processed for auto-reversal
    """
    try:
        # Find orders eligible for auto-reversal:
        # 1. Has pending delivery fee transaction
        # 2. Delivery date + 24 hours has passed
        # 3. Buyer hasn't confirmed receipt
        # 4. Not already reversed
        
        cutoff_time = datetime.utcnow() - timedelta(hours=24)
        
        # Find all pending delivery fee transactions
        pending_delivery_txns = db.transactions.find({
            'transaction_type': TransactionType.DELIVERY_FEE_PAYMENT,
            'status': TransactionStatus.PENDING
        })
        
        reversed_count = 0
        
        async for txn in pending_delivery_txns:
            order_id = txn.get('order_id')
            if not order_id:
                continue
            
            # Get the order
            order = await db.orders.find_one({'_id': ObjectId(order_id)})
            if not order:
                continue
            
            # Skip if already reversed
            if order.get('delivery_fee_reversed'):
                continue
            
            # Skip if buyer confirmed receipt
            if order.get('delivery_status') == 'confirmed':
                continue
            
            # Check if 24 hours have passed since delivery date or scheduled date
            delivery_date = order.get('scheduled_date') or order.get('created_at')
            if not delivery_date:
                continue
            
            # If 24 hours have passed since delivery date, reverse it
            if delivery_date < cutoff_time:
                delivery_fee = order.get('delivery_fee', 0)
                buyer_id = order.get('buyer_id')
                seller_id = order.get('seller_id')
                
                if delivery_fee > 0 and buyer_id and seller_id:
                    # Perform auto-reversal
                    success = await reverse_delivery_fee(
                        order_id=order_id,
                        delivery_fee=delivery_fee,
                        buyer_id=buyer_id,
                        seller_id=seller_id,
                        reason="Automatic reversal: Buyer did not confirm receipt within 24 hours of delivery date",
                        db=db,
                        create_transaction=create_transaction,
                        update_wallet_balance=update_wallet_balance,
                        get_or_create_wallet=get_or_create_wallet,
                        TransactionType=TransactionType,
                        TransactionStatus=TransactionStatus,
                        create_notification=create_notification,
                        NotificationType=NotificationType
                    )
                    
                    if success:
                        reversed_count += 1
                        logger.info(f"Auto-reversed delivery fee for order {order_id}")
        
        logger.info(f"Auto-reversal check completed. Reversed {reversed_count} delivery fees.")
        return reversed_count
        
    except Exception as e:
        logger.error(f"❌ Error in auto-reversal check: {str(e)}", exc_info=True)
        return 0
