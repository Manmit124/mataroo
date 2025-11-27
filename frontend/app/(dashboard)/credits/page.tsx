"use client";

import { useSubscription } from "@/hooks/api/useSubscription";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { CheckCircle2, Crown, AlertCircle, Zap, Infinity } from "lucide-react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useState, useEffect } from "react";
import { useCreateOrder, useVerifyPayment } from "@/hooks/api/useSubscription";
import { useAuth } from "@/hooks/auth/useAuth";

declare global {
  interface Window {
    Razorpay: any;
  }
}

export default function CreditsPage() {
  const { data, isLoading } = useSubscription();
  const { user } = useAuth();
  const router = useRouter();
  const [isLoadingPayment, setIsLoadingPayment] = useState(false);
  const createOrder = useCreateOrder();
  const verifyPayment = useVerifyPayment();

  // Load Razorpay script
  useEffect(() => {
    const script = document.createElement("script");
    script.src = "https://checkout.razorpay.com/v1/checkout.js";
    script.async = true;
    document.body.appendChild(script);

    return () => {
      if (document.body.contains(script)) {
        document.body.removeChild(script);
      }
    };
  }, []);

  const handleUpgrade = async () => {
    setIsLoadingPayment(true);
    try {
      // Create order
      const orderResponse = await createOrder.mutateAsync();
      const order = orderResponse.order;

      if (!window.Razorpay) {
        throw new Error("Razorpay script not loaded. Please refresh the page.");
      }

      // Open Razorpay checkout
      const options = {
        key: order.key_id,
        amount: order.amount, // Amount in smallest unit (cents for USD, paise for INR)
        currency: order.currency || "USD",
        name: "Mataroo",
        description: "Pro Subscription - Monthly",
        order_id: order.id,
        handler: async function (response: any) {
          try {
            // Verify payment
            await verifyPayment.mutateAsync({
              razorpay_order_id: response.razorpay_order_id,
              razorpay_payment_id: response.razorpay_payment_id,
              razorpay_signature: response.razorpay_signature,
            });

            // Success - refresh page
            window.location.reload();
          } catch (error: any) {
            alert("Payment verification failed. Please contact support.");
            console.error("Payment verification error:", error);
          }
        },
        prefill: {
          name: user?.email?.split("@")[0] || "",
          email: user?.email || "",
        },
        theme: {
          color: "#f97316",
        },
        modal: {
          ondismiss: function() {
            setIsLoadingPayment(false);
          }
        }
      };

      const rzp = new window.Razorpay(options);
      rzp.open();
      rzp.on("payment.failed", function (response: any) {
        alert("Payment failed. Please try again.");
        setIsLoadingPayment(false);
      });
    } catch (error: any) {
      alert(error.message || "Failed to create payment order. Please try again.");
      console.error("Payment error:", error);
    } finally {
      setIsLoadingPayment(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex h-full items-center justify-center p-8">
        <div className="animate-pulse space-y-4 w-full max-w-2xl">
          <div className="h-8 bg-muted rounded w-1/3"></div>
          <div className="h-64 bg-muted rounded"></div>
        </div>
      </div>
    );
  }

  const subscription = data?.subscription;
  if (!subscription) {
    return (
      <div className="flex h-full items-center justify-center p-8">
        <Card>
          <CardContent className="p-6">
            <p className="text-muted-foreground">Unable to load subscription information.</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const isPro = subscription.plan_type === "pro";
  const postsUsed = subscription.posts_used || 0;
  const postsLimit = subscription.posts_limit || 5;
  const remaining = subscription.remaining;
  const isUnlimited = remaining === "unlimited" || postsLimit === -1;
  const usagePercentage = isUnlimited ? 0 : (postsUsed / postsLimit) * 100;
  const isNearLimit = !isUnlimited && postsUsed >= postsLimit * 0.8;
  const isAtLimit = !isUnlimited && postsUsed >= postsLimit;

  return (
    <div className="flex h-full flex-col p-8">
      <div className="w-full max-w-4xl mx-auto space-y-8">
        {/* Header */}
        <div>
          <h1 className="text-4xl font-bold mb-2">Credits & Subscription</h1>
          <p className="text-muted-foreground">
            Manage your subscription and track your usage
          </p>
        </div>

        {/* Current Plan Card */}
        <Card className={isPro ? "border-primary" : ""}>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {isPro ? (
                  <Crown className="h-6 w-6 text-primary" />
                ) : (
                  <CheckCircle2 className="h-6 w-6 text-muted-foreground" />
                )}
                <CardTitle className="text-2xl">
                  {isPro ? "Pro Plan" : "Free Plan"}
                </CardTitle>
              </div>
              {isPro && (
                <span className="text-xs bg-primary/10 text-primary px-3 py-1 rounded-full font-medium">
                  Active
                </span>
              )}
            </div>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Usage Stats */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-muted-foreground">
                  Posts used
                </span>
                <span className="text-sm font-semibold">
                  {isUnlimited ? (
                    <span className="flex items-center gap-1 text-primary">
                      <Infinity className="h-4 w-4" />
                      Unlimited
                    </span>
                  ) : (
                    `${postsUsed} / ${postsLimit}`
                  )}
                </span>
              </div>
              
              {!isUnlimited && (
                <>
                  <div className="w-full bg-muted rounded-full h-3">
                    <div
                      className={`h-3 rounded-full transition-all ${
                        isAtLimit
                          ? "bg-destructive"
                          : isNearLimit
                          ? "bg-orange-500"
                          : "bg-primary"
                      }`}
                      style={{ width: `${Math.min(usagePercentage, 100)}%` }}
                    />
                  </div>
                  
                  {isAtLimit && (
                    <div className="flex items-center gap-2 text-sm text-destructive bg-destructive/10 p-3 rounded-lg">
                      <AlertCircle className="h-4 w-4" />
                      <span>You've reached your monthly limit. Upgrade to Pro for unlimited posts.</span>
                    </div>
                  )}
                  
                  {isNearLimit && !isAtLimit && (
                    <div className="flex items-center gap-2 text-sm text-orange-500 bg-orange-500/10 p-3 rounded-lg">
                      <AlertCircle className="h-4 w-4" />
                      <span>You're running low on posts ({postsLimit - postsUsed} remaining).</span>
                    </div>
                  )}
                </>
              )}

              {isUnlimited && (
                <div className="flex items-center gap-2 text-sm text-primary bg-primary/10 p-3 rounded-lg">
                  <Zap className="h-4 w-4" />
                  <span>Unlimited posts available - post as much as you want!</span>
                </div>
              )}
            </div>

            {/* Action Button */}
            {!isPro && (
              <div className="border-t pt-6 space-y-4">
                <div className="text-center space-y-2">
                  <h3 className="text-lg font-semibold">Upgrade to Pro</h3>
                  <p className="text-sm text-muted-foreground">
                    Get unlimited posts and unlock all features
                  </p>
                </div>
                <Button 
                  className="w-full bg-primary hover:bg-primary/90 shadow-lg shadow-primary/20" 
                  size="lg"
                  onClick={handleUpgrade}
                  disabled={isLoadingPayment}
                >
                  {isLoadingPayment ? "Loading..." : "Upgrade to Pro - $5/month"}
                </Button>
                <p className="text-xs text-center text-muted-foreground">
                  Cancel anytime
                </p>
              </div>
            )}

            {isPro && (
              <div className="border-t pt-6">
                <div className="text-center space-y-2">
                  <div className="flex items-center justify-center gap-2 text-primary">
                    <Crown className="h-5 w-5" />
                    <p className="text-sm font-semibold">Your Pro subscription is active</p>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Enjoy unlimited posts and all premium features
                  </p>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Additional Info */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Need Help?</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground mb-4">
              Have questions about your subscription or credits? We're here to help.
            </p>
            <Link href="/pricing">
              <Button variant="outline" className="w-full">
                View Pricing Plans
              </Button>
            </Link>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

