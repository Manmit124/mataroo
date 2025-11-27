"use client";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Check, Sparkles, Zap } from "lucide-react";
import { useAuth } from "@/hooks/auth/useAuth";
import Link from "next/link";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useCreateOrder, useVerifyPayment } from "@/hooks/api/useSubscription";

declare global {
  interface Window {
    Razorpay: any;
  }
}

export function PricingSection() {
  const { user } = useAuth();
  const router = useRouter();
  const [isLoading, setIsLoading] = useState(false);
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

  const handleStartPro = async () => {
    if (!user) {
      router.push("/signup");
      return;
    }

    setIsLoading(true);
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

            // Success - redirect to dashboard
            router.push("/dashboard?upgraded=pro");
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
          color: "#f97316", // Primary color
        },
        modal: {
          ondismiss: function() {
            setIsLoading(false);
          }
        }
      };

      const rzp = new window.Razorpay(options);
      rzp.open();
      rzp.on("payment.failed", function (response: any) {
        alert("Payment failed. Please try again.");
        setIsLoading(false);
      });
    } catch (error: any) {
      alert(error.message || "Failed to create payment order. Please try again.");
      console.error("Payment error:", error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <section id="pricing" className="relative z-10 py-24 bg-background">
      <div className="container mx-auto px-4">
        <div className="text-center mb-16">
          <h2 className="text-4xl md:text-5xl font-bold mb-4">
            Simple, Transparent Pricing
          </h2>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Choose the plan that works for you. Start free, upgrade anytime.
          </p>
        </div>

        <div className="grid md:grid-cols-2 gap-8 max-w-5xl mx-auto">
          {/* Free Plan */}
          <Card className="border-2 hover:border-primary/50 transition-all">
            <CardHeader>
              <div className="flex items-center justify-between mb-2">
                <CardTitle className="text-2xl">Free</CardTitle>
                <div className="text-right">
                  <div className="text-xs text-muted-foreground mb-1">in USD</div>
                  <div className="text-3xl font-bold">$0</div>
                  <div className="text-xs text-muted-foreground mb-1 mt-2">in INR</div>
                  <div className="text-xl font-semibold">₹0</div>
                </div>
              </div>
              <CardDescription className="text-base">
                Perfect for trying Mataroo
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <Check className="h-5 w-5 text-green-500" />
                  <span>5 posts per month</span>
                </div>
                <div className="flex items-center gap-2">
                  <Check className="h-5 w-5 text-green-500" />
                  <span>AI-powered RAG personalization</span>
                </div>
                <div className="flex items-center gap-2">
                  <Check className="h-5 w-5 text-green-500" />
                  <span>Connect Twitter account</span>
                </div>
                <div className="flex items-center gap-2">
                  <Check className="h-5 w-5 text-green-500" />
                  <span>Connect GitHub account</span>
                </div>
                <div className="flex items-center gap-2">
                  <Check className="h-5 w-5 text-green-500" />
                  <span>30-day post history</span>
                </div>
                <div className="flex items-center gap-2">
                  <Check className="h-5 w-5 text-green-500" />
                  <span>Smart hashtag generation</span>
                </div>
                <div className="flex items-center gap-2">
                  <Check className="h-5 w-5 text-green-500" />
                  <span>Community support</span>
                </div>
              </div>
              
              <Link href={user ? "/dashboard" : "/signup"} className="block">
                <Button variant="outline" className="w-full" size="lg">
                  {user ? "Current Plan" : "Start Free"}
                </Button>
              </Link>
            </CardContent>
          </Card>

          {/* Pro Plan */}
          <Card className="border-2 border-primary relative hover:border-primary transition-all">
            <div className="absolute -top-4 left-1/2 -translate-x-1/2">
              <span className="bg-primary text-primary-foreground px-4 py-1 rounded-full text-sm font-medium">
                Most Popular
              </span>
            </div>
            <CardHeader>
              <div className="flex items-center justify-between mb-2">
                <CardTitle className="text-2xl">Pro</CardTitle>
                <div className="text-right">
                  <div className="text-xs text-muted-foreground mb-1">in USD</div>
                  <div className="text-3xl font-bold text-primary">$5<span className="text-lg">/month</span></div>
                  <div className="text-xs text-muted-foreground mb-1 mt-2">in INR</div>
                  <div className="text-xl font-semibold text-primary">₹440<span className="text-base">/month</span></div>
                </div>
              </div>
              <CardDescription className="text-base">
                For creators who post regularly
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <Zap className="h-5 w-5 text-primary" />
                  <span className="font-medium">Everything in Free, plus:</span>
                </div>
                <div className="flex items-center gap-2">
                  <Check className="h-5 w-5 text-primary" />
                  <span>Unlimited posts per month</span>
                </div>
                <div className="flex items-center gap-2">
                  <Check className="h-5 w-5 text-primary" />
                  <span>Unlimited post history</span>
                </div>
                <div className="flex items-center gap-2">
                  <Check className="h-5 w-5 text-primary" />
                  <span>Advanced hashtag generation</span>
                </div>
                <div className="flex items-center gap-2">
                  <Check className="h-5 w-5 text-primary" />
                  <span>Semantic search (find similar commits/posts)</span>
                </div>
                <div className="flex items-center gap-2">
                  <Check className="h-5 w-5 text-primary" />
                  <span>Priority AI insights</span>
                </div>
                <div className="flex items-center gap-2">
                  <Check className="h-5 w-5 text-primary" />
                  <span>Email support</span>
                </div>
                <div className="flex items-center gap-2">
                  <Check className="h-5 w-5 text-primary" />
                  <span>Early access to new features</span>
                </div>
              </div>
              
              <Button 
                className="w-full" 
                size="lg"
                onClick={handleStartPro}
                disabled={isLoading}
              >
                {isLoading ? "Loading..." : user ? "Upgrade to Pro" : "Start Pro Trial"}
              </Button>
              <p className="text-xs text-center text-muted-foreground">
                Cancel anytime. No credit card required for Free.
              </p>
            </CardContent>
          </Card>
        </div>

        {/* FAQ Section */}
        <div className="mt-20 max-w-3xl mx-auto">
          <h3 className="text-2xl font-bold text-center mb-8">Frequently Asked Questions</h3>
          <div className="space-y-6">
            <div>
              <h4 className="font-semibold mb-2">What is RAG personalization?</h4>
              <p className="text-muted-foreground">
                RAG (Retrieval Augmented Generation) uses your GitHub commits and Twitter writing style to generate posts that match your voice and reference your actual work.
              </p>
            </div>
            <div>
              <h4 className="font-semibold mb-2">Can I upgrade later?</h4>
              <p className="text-muted-foreground">
                Yes! You can upgrade to Pro anytime to unlock unlimited posts and advanced features.
              </p>
            </div>
            <div>
              <h4 className="font-semibold mb-2">What happens if I exceed 5 posts on Free?</h4>
              <p className="text-muted-foreground">
                You'll be prompted to upgrade to Pro for unlimited posts. Your existing posts remain accessible.
              </p>
            </div>
            <div>
              <h4 className="font-semibold mb-2">Do you store my data?</h4>
              <p className="text-muted-foreground">
                We only store what's necessary for personalization. You can delete your data anytime from settings.
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

