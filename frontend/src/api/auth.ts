import { apiFetch, publishAuthState } from "./client";
import type { components } from "../types/api.generated";

export type CurrentUser = components["schemas"]["UserRead"];

export interface RegisterPayload {
  organization_name: string;
  email: string;
  password: string;
  full_name: string;
}

export async function register(payload: RegisterPayload): Promise<CurrentUser> {
  const user = await apiFetch<CurrentUser>("/auth/register", { method: "POST", body: payload });
  publishAuthState(user);
  return user;
}

export async function login(email: string, password: string): Promise<CurrentUser> {
  // OAuth2PasswordRequestForm on the backend expects
  // application/x-www-form-urlencoded, not JSON — see
  // app/api/routes/auth.py's `login` signature.
  const body = new URLSearchParams({ username: email, password });
  const user = await apiFetch<CurrentUser>("/auth/login", { method: "POST", body });
  publishAuthState(user);
  return user;
}

export async function logout(): Promise<void> {
  await apiFetch<void>("/auth/logout", { method: "POST" });
  publishAuthState(null);
}

export function getMe(): Promise<CurrentUser> {
  return apiFetch<CurrentUser>("/users/me");
}
