import { createContext, useCallback, useEffect, useState, type ReactNode } from "react";
import { getMe, type CurrentUser } from "../api/auth";
import { subscribeAuthState } from "../api/client";
import { clearAuthenticatedCache } from "../lib/queryClient";
import { UnauthorizedError } from "../api/errors";

export interface AuthContextValue {
  user: CurrentUser | null;
  isLoading: boolean;
  isAuthenticated: boolean;
}

export const AuthContext = createContext<AuthContextValue | undefined>(undefined);

/**
 * Holds { user, isLoading, isAuthenticated } ONLY — no tokens, no CSRF
 * state (both live exclusively in cookies/lib/csrf.ts, per the approved
 * architecture). Sits OUTSIDE QueryClientProvider in the provider tree
 * (ErrorBoundary > AuthProvider > QueryClientProvider > RouterProvider),
 * so it deliberately does not use TanStack Query hooks: session state is
 * plain useState, seeded by GET /users/me on mount and kept in sync via
 * subscribeAuthState (see api/client.ts) rather than the query cache.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const loadCurrentUser = useCallback(async () => {
    try {
      const currentUser = await getMe();
      setUser(currentUser);
    } catch (error) {
      // No session yet (first visit) or an expired one — both resolve to
      // "signed out" here rather than surfacing as an app-level error.
      if (!(error instanceof UnauthorizedError)) {
        console.error("Failed to load current user", error);
      }
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadCurrentUser();
  }, [loadCurrentUser]);

  useEffect(() => {
    return subscribeAuthState((nextUser) => {
      // Cleared on every transition (login, register, logout) — not just
      // logout. A same-tab login-as-different-user must not be able to
      // see the previous identity's cached org-scoped queries, and a
      // fresh login/register also shouldn't inherit whatever ran before
      // any session existed.
      clearAuthenticatedCache();
      setUser(nextUser as CurrentUser | null);
      setIsLoading(false);
    });
  }, []);

  const value: AuthContextValue = {
    user,
    isLoading,
    isAuthenticated: user !== null,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
