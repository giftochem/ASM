import type { ReactNode } from "react";
import type { components } from "../types/api.generated";
import { useAuth } from "./useAuth";
import { NotAuthorizedPage } from "./NotAuthorizedPage";

type UserRole = components["schemas"]["UserRole"];

/**
 * UX convenience only — hides/blocks routes a role shouldn't normally
 * use. This is NOT the security boundary: every server endpoint enforces
 * RBAC independently via require_role() (app/dependencies.py). A user who
 * reaches a gated route anyway (e.g. by guessing a URL) can't do anything
 * with it — any mutation they attempt still gets the server's own 403.
 */
export function RequireRole({ roles, children }: { roles: UserRole[]; children: ReactNode }) {
  const { user, isLoading } = useAuth();

  if (isLoading) {
    return null;
  }
  if (!user || !roles.includes(user.role)) {
    return <NotAuthorizedPage />;
  }
  return <>{children}</>;
}
