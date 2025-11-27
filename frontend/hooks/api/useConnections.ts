"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createClient } from "@/lib/supabase/client";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface Connection {
  platform: string;
  platform_username?: string;
  is_active: boolean;
  connected_at?: string;
}

export interface ConnectionsResponse {
  success: boolean;
  connections: Connection[];
}

/**
 * Hook to manage social media connections
 */
export function useConnections() {
  const queryClient = useQueryClient();
  const supabase = createClient();

  // Fetch connected accounts
  const {
    data: connections,
    isLoading,
    error,
    refetch
  } = useQuery({
    queryKey: ["connections"],
    queryFn: async (): Promise<Connection[]> => {
      // Get session token
      const { data: { session } } = await supabase.auth.getSession();

      if (!session) {
        throw new Error("Not authenticated");
      }

      const response = await fetch(`${API_URL}/api/connections`, {
        headers: {
          "Authorization": `Bearer ${session.access_token}`,
        },
      });

      if (!response.ok) {
        throw new Error("Failed to fetch connections");
      }

      const data: ConnectionsResponse = await response.json();
      return data.connections;
    },
    staleTime: 5 * 60 * 1000, // 5 minutes
  });

  // Connect Twitter account
  const connectTwitter = useMutation({
    mutationFn: async () => {
      // Get session token
      const { data: { session } } = await supabase.auth.getSession();

      if (!session) {
        throw new Error("Not authenticated");
      }

      const response = await fetch(`${API_URL}/api/auth/twitter/login`, {
        headers: {
          "Authorization": `Bearer ${session.access_token}`,
        },
      });

      if (!response.ok) {
        throw new Error("Failed to initiate Twitter OAuth");
      }

      const data = await response.json();

      // Redirect to Twitter OAuth
      if (data.auth_url) {
        window.location.href = data.auth_url;
      }

      return data;
    },
    onError: (error) => {
      console.error("Error connecting Twitter:", error);
    },
  });

  // Connect GitHub account
  const connectGitHub = useMutation({
    mutationFn: async () => {
      // Get session token
      const { data: { session } } = await supabase.auth.getSession();

      if (!session) {
        throw new Error("Not authenticated");
      }

      const response = await fetch(`${API_URL}/api/auth/github/login`, {
        headers: {
          "Authorization": `Bearer ${session.access_token}`,
        },
      });

      if (!response.ok) {
        throw new Error("Failed to initiate GitHub OAuth");
      }

      const data = await response.json();

      // Redirect to GitHub OAuth
      if (data.auth_url) {
        window.location.href = data.auth_url;
      }

      return data;
    },
    onError: (error) => {
      console.error("Error connecting GitHub:", error);
    },
  });

  // Connect LinkedIn account
  const connectLinkedIn = useMutation({
    mutationFn: async () => {
      // Get session token
      const { data: { session } } = await supabase.auth.getSession();

      if (!session) {
        throw new Error("Not authenticated");
      }

      const response = await fetch(`${API_URL}/api/auth/linkedin/login`, {
        headers: {
          "Authorization": `Bearer ${session.access_token}`,
        },
      });

      if (!response.ok) {
        throw new Error("Failed to initiate LinkedIn OAuth");
      }

      const data = await response.json();

      // Redirect to LinkedIn OAuth
      if (data.auth_url) {
        window.location.href = data.auth_url;
      }

      return data;
    },
    onError: (error) => {
      console.error("Error connecting LinkedIn:", error);
    },
  });

  // Disconnect account
  const disconnectAccount = useMutation({
    mutationFn: async (platform: string) => {
      // Get session token
      const { data: { session } } = await supabase.auth.getSession();

      if (!session) {
        throw new Error("Not authenticated");
      }

      const response = await fetch(`${API_URL}/api/connections/${platform}`, {
        method: "DELETE",
        headers: {
          "Authorization": `Bearer ${session.access_token}`,
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to disconnect ${platform}`);
      }

      return await response.json();
    },
    onMutate: async (platform) => {
      // Cancel outgoing refetches
      await queryClient.cancelQueries({ queryKey: ["connections"] });

      // Snapshot previous value
      const previousConnections = queryClient.getQueryData<Connection[]>(["connections"]);

      // Optimistically update
      queryClient.setQueryData<Connection[]>(["connections"], (old) =>
        old ? old.filter((conn) => conn.platform !== platform) : []
      );

      return { previousConnections };
    },
    onError: (err, platform, context) => {
      // Rollback on error
      if (context?.previousConnections) {
        queryClient.setQueryData(["connections"], context.previousConnections);
      }
    },
    onSettled: (data, error, platform) => {
      // Refetch after mutation
      queryClient.invalidateQueries({ queryKey: ["connections"] });

      // If GitHub was disconnected, invalidate all GitHub-related queries
      if (platform === "github") {
        queryClient.invalidateQueries({ queryKey: ["github"] });
      }
    },
  });

  // Check if a platform is connected
  const isConnected = (platform: string): boolean => {
    return connections?.some((conn) => conn.platform === platform && conn.is_active) ?? false;
  };

  // Get connection for a platform
  const getConnection = (platform: string): Connection | undefined => {
    return connections?.find((conn) => conn.platform === platform);
  };

  return {
    connections: connections ?? [],
    isLoading,
    error,
    refetch,
    connectTwitter,
    connectGitHub,
    connectLinkedIn,
    disconnectAccount,
    isConnected,
    getConnection,
  };
}




