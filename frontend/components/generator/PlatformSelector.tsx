"use client";

import { Linkedin, MessageCircle } from "lucide-react";
import { cn } from "@/lib/utils";
import { useConnections } from "@/hooks/api/useConnections";
import { XIcon } from "@/components/icons/XIcon";

export type Platform = "twitter" | "linkedin" | "reddit";

interface PlatformOption {
  id: Platform;
  name: string;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
  available: boolean;
}

interface PlatformSelectorProps {
  selected: Platform;
  onSelect: (platform: Platform) => void;
}

export function PlatformSelector({ selected, onSelect }: PlatformSelectorProps) {
  const { isConnected } = useConnections();

  const platforms: PlatformOption[] = [
    {
      id: "twitter",
      name: "X",
      icon: XIcon,
      color: "text-foreground",
      available: isConnected("twitter"),
    },
    {
      id: "linkedin",
      name: "LinkedIn",
      icon: Linkedin,
      color: "text-blue-700",
      available: isConnected("linkedin"),
    },
    {
      id: "reddit",
      name: "Reddit",
      icon: MessageCircle,
      color: "text-orange-500",
      available: false, // Phase 3
    },
  ];

  return (
    <div className="inline-flex items-center gap-2 rounded-full bg-muted/50 p-1.5 backdrop-blur-sm border">
      {platforms.map((platform) => {
        const Icon = platform.icon;
        const isSelected = selected === platform.id;
        const isDisabled = !platform.available;

        return (
          <button
            key={platform.id}
            onClick={() => !isDisabled && onSelect(platform.id)}
            disabled={isDisabled}
            className={cn(
              "relative flex items-center gap-2 rounded-full px-5 py-2.5 transition-all font-medium text-sm",
              isSelected
                ? "bg-primary text-primary-foreground shadow-lg scale-105"
                : isDisabled
                  ? "text-muted-foreground cursor-not-allowed opacity-50"
                  : "text-foreground hover:bg-background/80",
              !isDisabled && "cursor-pointer"
            )}
          >
            <Icon className="h-4 w-4" />
            <span>{platform.name}</span>
            {isDisabled && (
              <span className="ml-1 text-xs opacity-70">
                (Soon)
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

