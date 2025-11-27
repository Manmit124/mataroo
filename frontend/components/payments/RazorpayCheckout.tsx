"use client";

import { useEffect } from "react";
import { useAuth } from "@/hooks/auth/useAuth";
import { api } from "@/lib/api";

declare global {
  interface Window {
    Razorpay: any;
  }
}

interface RazorpayCheckoutProps {
  orderId: string;
  amount: number; // Amount in smallest unit (cents for USD, paise for INR)
  keyId: string;
  currency?: string; // Currency code (USD or INR)
  onSuccess: (paymentId: string, orderId: string, signature: string) => void;
  onError: (error: string) => void;
}

export function RazorpayCheckout({
  orderId,
  amount,
  keyId,
  currency = "USD",
  onSuccess,
  onError
}: RazorpayCheckoutProps) {
  const { user } = useAuth();

  useEffect(() => {
    // Load Razorpay script
    const script = document.createElement("script");
    script.src = "https://checkout.razorpay.com/v1/checkout.js";
    script.async = true;
    document.body.appendChild(script);

    return () => {
      // Cleanup
      document.body.removeChild(script);
    };
  }, []);

  const openCheckout = () => {
    if (!window.Razorpay) {
      onError("Razorpay script not loaded. Please refresh the page.");
      return;
    }

    const options = {
      key: keyId,
      amount: amount, // Amount in smallest unit (cents for USD, paise for INR)
      currency: currency,
      name: "Mataroo",
      description: "Pro Subscription - Monthly",
      order_id: orderId,
      handler: function (response: any) {
        // Payment successful
        onSuccess(
          response.razorpay_payment_id,
          response.razorpay_order_id,
          response.razorpay_signature
        );
      },
      prefill: {
        name: user?.email?.split("@")[0] || "",
        email: user?.email || "",
      },
      theme: {
        color: "#f97316", // Primary color (orange)
      },
      modal: {
        ondismiss: function() {
          onError("Payment cancelled");
        }
      }
    };

    const rzp = new window.Razorpay(options);
    rzp.open();
  };

  return (
    <button
      onClick={openCheckout}
      className="w-full"
    >
      {/* This component just provides the function, button is rendered by parent */}
    </button>
  );
}

// Hook to use Razorpay checkout
export function useRazorpayCheckout() {
  const openCheckout = async () => {
    try {
      // Create order
      const response = await api.post("/payments/create-order");
      
      if (!response.data.success) {
        throw new Error("Failed to create order");
      }

      const { order } = response.data;

      // Return checkout function
      return {
        orderId: order.id,
        amount: order.amount,
        keyId: order.key_id,
      };
    } catch (error: any) {
      throw new Error(error.response?.data?.detail || "Failed to create payment order");
    }
  };

  return { openCheckout };
}

