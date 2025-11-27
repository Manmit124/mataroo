"use client";

import { Button } from "@/components/ui/button";
import { Linkedin, MessageSquare, CheckCircle2, Clock, Sparkles, Github } from "lucide-react";
import { useConnections } from "@/hooks/api/useConnections";
import { XIcon } from "@/components/icons/XIcon";

interface AppCardProps {
  name: string;
  icon: React.ReactNode;
  description: string;
  isConnected: boolean;
  isComingSoon?: boolean;
  username?: string;
  onConnect?: () => void;
  onDisconnect?: () => void;
  isLoading?: boolean;
}

function AppCard({
  name,
  icon,
  description,
  isConnected,
  isComingSoon,
  username,
  onConnect,
  onDisconnect,
  isLoading
}: AppCardProps) {
  return (
    <div className="relative rounded-2xl border-2 bg-card/80 backdrop-blur-sm p-6 shadow-lg hover:shadow-xl transition-all">
      {isComingSoon && (
        <div className="absolute top-4 right-4 z-10">
          <span className="inline-flex items-center gap-1 rounded-full bg-orange-500/10 px-3 py-1.5 text-xs font-medium text-orange-500 ring-1 ring-inset ring-orange-500/20">
            <Clock className="h-3 w-3" />
            Coming Soon
          </span>
        </div>
      )}

      <div className="space-y-4">
        {/* Icon & Title */}
        <div className="flex items-start gap-4">
          <div className="flex h-14 w-14 items-center justify-center rounded-xl bg-primary/10">
            {icon}
          </div>
          <div className="flex-1">
            <h3 className="text-xl font-semibold">{name}</h3>
            {isConnected && username && (
              <div className="mt-1 flex items-center gap-1 text-sm text-muted-foreground">
                <CheckCircle2 className="h-4 w-4 text-green-500" />
                <span>@{username}</span>
              </div>
            )}
          </div>
        </div>

        {/* Description */}
        <p className="text-sm text-muted-foreground leading-relaxed">
          {description}
        </p>

        {/* Actions */}
        {!isComingSoon && (
          <div className="pt-2">
            {isConnected ? (
              <div className="space-y-3">
                <div className="flex items-center gap-2 text-sm font-medium text-green-500">
                  <CheckCircle2 className="h-4 w-4" />
                  Connected
                </div>
                <Button
                  variant="outline"
                  className="w-full rounded-xl"
                  onClick={onDisconnect}
                  disabled={isLoading}
                >
                  {isLoading ? "Disconnecting..." : "Disconnect"}
                </Button>
              </div>
            ) : (
              <Button
                className="w-full rounded-xl shadow-md"
                onClick={onConnect}
                disabled={isLoading}
              >
                {isLoading ? "Connecting..." : "Connect"}
              </Button>
            )}
          </div>
        )}

        {isComingSoon && (
          <div className="rounded-xl bg-muted/50 p-4 text-center text-sm text-muted-foreground">
            We're working on bringing {name} integration soon!
          </div>
        )}
      </div>
    </div>
  );
}

export function ConnectedApps() {
  const { connections, connectTwitter, connectGitHub, connectLinkedIn, disconnectAccount, isConnected, getConnection } = useConnections();

  const twitterConnection = getConnection("twitter");
  const isTwitterConnected = isConnected("twitter");

  const githubConnection = getConnection("github");
  const isGitHubConnected = isConnected("github");

  const linkedinConnection = getConnection("linkedin");
  const isLinkedinConnected = isConnected("linkedin");

  const handleConnectTwitter = () => {
    connectTwitter.mutate();
  };

  const handleDisconnectTwitter = () => {
    if (confirm("Are you sure you want to disconnect your X account?")) {
      disconnectAccount.mutate("twitter");
    }
  };

  const handleConnectGitHub = () => {
    connectGitHub.mutate();
  };

  const handleDisconnectGitHub = () => {
    if (confirm("Are you sure you want to disconnect your GitHub account?")) {
      disconnectAccount.mutate("github");
    }
  };

  const handleConnectLinkedIn = () => {
    connectLinkedIn.mutate();
  };

  const handleDisconnectLinkedIn = () => {
    if (confirm("Are you sure you want to disconnect your LinkedIn account?")) {
      disconnectAccount.mutate("linkedin");
    }
  };

  return (
    <div className="space-y-8">
      {/* Apps Grid */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        {/* X (Twitter) */}
        <AppCard
          name="X"
          icon={<XIcon className="h-7 w-7" />}
          description="Post to X and engage with your audience directly from Mataroo.com"
          isConnected={isTwitterConnected}
          username={twitterConnection?.platform_username}
          onConnect={handleConnectTwitter}
          onDisconnect={handleDisconnectTwitter}
          isLoading={connectTwitter.isPending || disconnectAccount.isPending}
        />

        {/* GitHub */}
        <AppCard
          name="GitHub"
          icon={<Github className="h-7 w-7 text-primary" />}
          description="Connect your GitHub to generate personalized content based on your code activity"
          isConnected={isGitHubConnected}
          username={githubConnection?.platform_username}
          onConnect={handleConnectGitHub}
          onDisconnect={handleDisconnectGitHub}
          isLoading={connectGitHub.isPending || disconnectAccount.isPending}
        />

        {/* LinkedIn */}
        <AppCard
          name="LinkedIn"
          icon={<Linkedin className="h-7 w-7 text-primary" />}
          description="Share professional content and grow your LinkedIn network"
          isConnected={isLinkedinConnected}
          username={linkedinConnection?.platform_username}
          onConnect={handleConnectLinkedIn}
          onDisconnect={handleDisconnectLinkedIn}
          isLoading={connectLinkedIn.isPending || disconnectAccount.isPending}
        />

        {/* Reddit */}
        <AppCard
          name="Reddit"
          icon={<MessageSquare className="h-7 w-7 text-primary" />}
          description="Post to your favorite subreddits and engage with communities"
          isConnected={false}
          isComingSoon={true}
        />
      </div>

      {/* Coming Soon Banner */}
      <div className="rounded-2xl border-2 border-dashed border-primary/20 bg-primary/5 p-8">
        <div className="flex flex-col items-center text-center space-y-3">
          <div className="rounded-full bg-primary/10 p-3">
            <Sparkles className="h-6 w-6 text-primary" />
          </div>
          <h3 className="text-lg font-semibold">More Platforms Coming Soon</h3>
          <p className="text-sm text-muted-foreground max-w-md">
            We're constantly adding new platform integrations. Stay tuned for Instagram, Facebook, and more!
          </p>
        </div>
      </div>
    </div>
  );
}

