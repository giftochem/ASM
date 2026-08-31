import { apiFetch } from "./client";
import type { components } from "../types/api.generated";

export type User = components["schemas"]["UserRead"];
export type UserRole = components["schemas"]["UserRole"];

export interface CreateUserPayload {
  email: string;
  password: string;
  full_name: string;
  role: UserRole;
}

export interface UpdateUserPayload {
  role?: UserRole;
  is_active?: boolean;
}

// All three of these are require_role(admin) server-side AND org-scoped
// (see app/api/routes/users.py). The admin gate is enforced by the
// server on every call — RequireRole around the Settings route is only
// a UX convenience, never the boundary.
export function listUsers(): Promise<User[]> {
  return apiFetch<User[]>("/users");
}

export function createUser(payload: CreateUserPayload): Promise<User> {
  return apiFetch<User>("/users", { method: "POST", body: payload });
}

// PATCH rejects an empty payload with 400 ("Provide at least one of
// role, is_active") and rejects self-modification with 400 ("Cannot
// modify your own role or active status via this endpoint") — the
// server's self-lockout guard. Cross-org user ids return 404, never 403.
export function updateUser(userId: string, payload: UpdateUserPayload): Promise<User> {
  return apiFetch<User>(`/users/${userId}`, { method: "PATCH", body: payload });
}
