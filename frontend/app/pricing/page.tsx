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

export default function PricingPage() {
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
    <div className="min-h-screen bg-gradient-to-br from-background via-primary/5 to-background">
      {/* Navigation */}
      <nav className="relative z-10 border-b border-border backdrop-blur-sm bg-background/80">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <Link href="/" className="flex items-center gap-3">
              <span className="text-xl font-bold text-foreground">
                Mataroo
              </span>
            </Link>
            <div className="flex items-center gap-4">
              <Link href="/login">
                <Button variant="ghost">
                  Sign In
                </Button>
              </Link>
              <Link href="/signup">
                <Button>
                  Get Started
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </nav>

      {/* Pricing Section */}
      <section className="relative z-10 py-24 bg-background">
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
            <Card className="border-2 hover:border-primary/30 transition-all relative overflow-hidden">
              <div className="absolute top-0 right-0 w-32 h-32 bg-primary/5 rounded-full blur-3xl -mr-16 -mt-16"></div>
              <CardHeader className="relative">
                <div className="flex items-center justify-between mb-4">
                  <CardTitle className="text-3xl font-bold">Free</CardTitle>
                  <div className="text-right">
                    <div className="text-sm text-muted-foreground mb-1">in USD</div>
                    <div className="text-4xl font-bold">$0</div>
                    <div className="text-sm text-muted-foreground mb-1 mt-2">in INR</div>
                    <div className="text-2xl font-semibold">₹0</div>
                    <div className="text-sm text-muted-foreground mt-1">forever</div>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-6 relative">
                {/* Main Feature Highlight */}
                <div className="bg-muted/50 rounded-xl p-4 border-2 border-dashed">
                  <div className="text-center">
                    <div className="text-5xl font-bold text-foreground mb-2">5</div>
                    <div className="text-sm font-medium text-muted-foreground">Posts per month</div>
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <Check className="h-5 w-5 text-primary flex-shrink-0" />
                    <span className="text-sm">AI-powered RAG personalization</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Check className="h-5 w-5 text-primary flex-shrink-0" />
                    <span className="text-sm">Connect Twitter account</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Check className="h-5 w-5 text-primary flex-shrink-0" />
                    <span className="text-sm">Connect GitHub account</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Check className="h-5 w-5 text-primary flex-shrink-0" />
                    <span className="text-sm">30-day post history</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Check className="h-5 w-5 text-primary flex-shrink-0" />
                    <span className="text-sm">Hashtag generation</span>
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
            <Card className="border-2 border-primary relative hover:border-primary transition-all overflow-hidden bg-gradient-to-br from-primary/5 to-background">
              <div className="absolute top-0 right-0 w-40 h-40 bg-primary/20 rounded-full blur-3xl -mr-20 -mt-20"></div>
              <div className="absolute top-4 left-1/2 -translate-x-1/2 z-10">
                <span className="bg-primary text-primary-foreground px-3 py-1 rounded-full text-xs font-semibold shadow-lg">
                  Most Popular
                </span>
              </div>
              <CardHeader className="relative pt-8">
                <div className="flex items-center justify-between mb-4">
                  <CardTitle className="text-3xl font-bold">Pro</CardTitle>
                  <div className="text-right">
                    <div className="text-sm text-muted-foreground mb-1">in USD</div>
                    <div className="text-4xl font-bold text-primary">$5<span className="text-xl">/month</span></div>
                    <div className="text-sm text-muted-foreground mb-1 mt-2">in INR</div>
                    <div className="text-2xl font-semibold text-primary">₹440<span className="text-base">/month</span></div>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-6 relative">
                {/* Main Feature Highlight */}
                <div className="bg-primary/10 rounded-xl p-4 border-2 border-primary/30 relative overflow-hidden">
                  <div className="absolute inset-0 bg-gradient-to-br from-primary/20 to-transparent"></div>
                  <div className="text-center relative">
                    <div className="flex items-center justify-center gap-2 mb-2">
                      <Zap className="h-6 w-6 text-primary" />
                      <div className="text-5xl font-bold text-primary">∞</div>
                    </div>
                    <div className="text-sm font-semibold text-primary">Unlimited posts</div>
                    <div className="text-xs text-muted-foreground mt-1">Post as much as you want</div>
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <Check className="h-5 w-5 text-primary flex-shrink-0" />
                    <span className="text-sm font-medium">Everything in Free</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Check className="h-5 w-5 text-primary flex-shrink-0" />
                    <span className="text-sm">Unlimited post history</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Check className="h-5 w-5 text-primary flex-shrink-0" />
                    <span className="text-sm">Email support</span>
                  </div>
                </div>
                
                <Button 
                  className="w-full bg-primary hover:bg-primary/90 shadow-lg shadow-primary/20" 
                  size="lg"
                  onClick={handleStartPro}
                  disabled={isLoading}
                >
                  {isLoading ? "Loading..." : user ? "Upgrade to Pro" : "Start Pro - $5/month (₹440/month)"}
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

      {/* Footer */}
      <footer className="relative z-10 mt-0">
        {/* Black Section - Footer Content */}
        <div className="bg-black py-8">
          <div className="container mx-auto px-4">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
              <div>
                <h3 className="font-semibold mb-4 text-white">Mataroo</h3>
                <p className="text-sm text-gray-400">
                  AI-powered social media content generation and posting platform.
                </p>
              </div>
              <div>
                <h3 className="font-semibold mb-4 text-white">Legal</h3>
                <ul className="space-y-2 text-sm">
                  <li>
                    <Link href="/privacy" className="text-gray-400 hover:text-white transition-colors">
                      Privacy Policy
                    </Link>
                  </li>
                  <li>
                    <Link href="/terms" className="text-gray-400 hover:text-white transition-colors">
                      Terms & Conditions
                    </Link>
                  </li>
                  <li>
                    <Link href="/refund" className="text-gray-400 hover:text-white transition-colors">
                      Refund Policy
                    </Link>
                  </li>
                </ul>
              </div>
              <div>
                <h3 className="font-semibold mb-4 text-white">Support</h3>
                <ul className="space-y-2 text-sm">
                  <li>
                    <Link href="/contact" className="text-gray-400 hover:text-white transition-colors">
                      Contact Us
                    </Link>
                  </li>
                  <li>
                    <Link href="/pricing" className="text-gray-400 hover:text-white transition-colors">
                      Pricing
                    </Link>
                  </li>
                </ul>
              </div>
              <div>
                <h3 className="font-semibold mb-4 text-white">Contact</h3>
                <ul className="space-y-2 text-sm">
                  <li>
                    <a href="mailto:manmittiwade124@gmail.com" className="text-gray-400 hover:text-white transition-colors">
                      manmittiwade124@gmail.com
                    </a>
                  </li>
                </ul>
              </div>
            </div>
            <div className="border-t border-gray-800 pt-8 text-center text-sm text-gray-400">
              <p>&copy; {new Date().getFullYear()} Mataroo. All rights reserved.</p>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

