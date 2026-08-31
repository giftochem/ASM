import { QueryClient } from "@tanstack/react-query";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
      refetchOnWindowFocus: false,
    },
  },
});

/**
 * Called on logout and on session-expiry (see api/client.ts's
 * publishAuthState). Without this, a second identity signing in on the
 * same tab could serve the first identity's cached org-scoped data for
 * the same query keys until each query naturally refetches — this app is
 * multi-tenant, so stale cross-session cache is a real data leak, not
 * just a UX glitch.
 */
export function clearAuthenticatedCache(): void {
  queryClient.clear();
}
