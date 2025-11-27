"""
Razorpay Payment Service
Handles payment processing for Pro subscription
Based on: https://razorpay.com/docs/payments/server-integration/python/
"""

import os
import razorpay
import hashlib
from typing import Dict, Optional
from fastapi import HTTPException

class RazorpayService:
    """Service for handling Razorpay payments"""
    
    def __init__(self):
        self.key_id = os.getenv("RAZORPAY_KEY_ID")
        self.key_secret = os.getenv("RAZORPAY_KEY_SECRET")
        
        if not self.key_id or not self.key_secret:
            raise ValueError("RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET must be set in environment variables")
        
        # Initialize Razorpay client
        self.client = razorpay.Client(auth=(self.key_id, self.key_secret))
        
        # Set app details (recommended by Razorpay) - optional, may not be available in all versions
        try:
            if hasattr(self.client, 'set_app_details'):
                self.client.set_app_details({
                    "title": "Mataroo",
                    "version": "1.0.0"
                })
        except Exception as e:
            # Ignore if set_app_details is not available
            print(f"Note: set_app_details not available: {e}")
    
    def create_order(self, amount: int, currency: str = "USD", user_id: Optional[str] = None) -> Dict:
        """
        Create a Razorpay order for Pro subscription.
        
        Args:
            amount: Amount in dollars (will be converted to cents for USD, or rupees to paise for INR)
            currency: Currency code (default: USD)
            user_id: User ID for receipt tracking
            
        Returns:
            Order object with order_id
        """
        try:
            # Convert to smallest currency unit
            # For USD: dollars to cents ($5 = 500 cents)
            # For INR: rupees to paise (₹5 = 500 paise)
            if currency == "USD":
                amount_in_smallest_unit = amount * 100  # Convert dollars to cents
            else:
                amount_in_smallest_unit = amount * 100  # Convert rupees to paise (INR)
            
            # Generate short receipt ID (max 40 chars for Razorpay)
            # Use hash of user_id to keep it short but unique
            if user_id:
                # Create a short hash from user_id (first 16 chars of MD5 hash)
                user_hash = hashlib.md5(user_id.encode()).hexdigest()[:16]
                receipt = f"pro_{user_hash}"
            else:
                # Generate random receipt if no user_id
                receipt = f"pro_{os.urandom(8).hex()}"
            
            data = {
                "amount": amount_in_smallest_unit,
                "currency": currency,
                "receipt": receipt,  # Max 40 characters
                "notes": {
                    "user_id": user_id,
                    "plan": "pro",
                    "description": "Mataroo Pro Subscription - Monthly"
                }
            }
            
            order = self.client.order.create(data=data)
            return order
        
        except Exception as e:
            print(f"❌ Error creating Razorpay order: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Failed to create payment order: {str(e)}")
    
    def verify_payment(self, razorpay_order_id: str, razorpay_payment_id: str, razorpay_signature: str) -> bool:
        """
        Verify Razorpay payment signature to ensure payment authenticity.
        
        Args:
            razorpay_order_id: Order ID from Razorpay
            razorpay_payment_id: Payment ID from Razorpay
            razorpay_signature: Signature from Razorpay
            
        Returns:
            True if payment is verified, False otherwise
        """
        try:
            params_dict = {
                'razorpay_order_id': razorpay_order_id,
                'razorpay_payment_id': razorpay_payment_id,
                'razorpay_signature': razorpay_signature
            }
            
            # Verify payment signature
            self.client.utility.verify_payment_signature(params_dict)
            return True
        
        except razorpay.errors.SignatureVerificationError:
            print(f"❌ Payment signature verification failed")
            return False
        except Exception as e:
            print(f"❌ Error verifying payment: {str(e)}")
            return False
    
    def get_payment_details(self, payment_id: str) -> Optional[Dict]:
        """
        Get payment details from Razorpay.
        
        Args:
            payment_id: Razorpay payment ID
            
        Returns:
            Payment details or None
        """
        try:
            payment = self.client.payment.fetch(payment_id)
            return payment
        except Exception as e:
            print(f"❌ Error fetching payment details: {str(e)}")
            return None
    
    def get_order_details(self, order_id: str) -> Optional[Dict]:
        """
        Get order details from Razorpay.
        
        Args:
            order_id: Razorpay order ID
            
        Returns:
            Order details or None
        """
        try:
            order = self.client.order.fetch(order_id)
            return order
        except Exception as e:
            print(f"❌ Error fetching order details: {str(e)}")
            return None


# Singleton instance
_razorpay_service = None

def get_razorpay_service() -> RazorpayService:
    """Get or create Razorpay service instance"""
    global _razorpay_service
    if _razorpay_service is None:
        _razorpay_service = RazorpayService()
    return _razorpay_service

