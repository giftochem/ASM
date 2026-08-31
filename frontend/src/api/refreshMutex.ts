import { getCsrfToken } from "../lib/csrf";

let inFlightRefresh: Promise<boolean> | null = null;

/**
 * Ensures at most one POST /auth/refresh is in flight at a time, no
 * matter how many concurrent requests hit a 401 simultaneously. Without
 * this, N concurrent 401s would each independently call /auth/refresh —
 * refresh-token rotation is single-use server-side (see
 * app/services/refresh_token_service.py), so only the first of those
 * concurrent calls would succeed and the rest would be treated as reuse
 * of an already-rotated token, tripping the server's reuse-detection and
 * revoking the whole session.
 *
 * Deliberately a raw `fetch`, not `apiFetch` — routing this through
 * apiFetch would re-enter its own 401 handling.
 */
export function ensureFreshSession(): Promise<boolean> {
  if (!inFlightRefresh) {
    inFlightRefresh = performRefresh().finally(() => {
      inFlightRefresh = null;
    });
  }
  return inFlightRefresh;
}

async function performRefresh(): Promise<boolean> {
  try {
    // POST /auth/refresh is not in CSRF_EXEMPT_PATHS, so it needs a valid
    // CSRF pair like any other unsafe request — its own cookie has the
    // same lifetime as refresh_token (see cookies.py set_auth_cookies),
    // so it's expected to still be present whenever refresh_token is.
    const csrfToken = getCsrfToken();
    const headers: HeadersInit = csrfToken ? { "X-CSRF-Token": csrfToken } : {};

    const response = await fetch("/auth/refresh", {
      method: "POST",
      credentials: "same-origin",
      headers,
    });
    return response.ok;
  } catch {
    return false;
  }
}
