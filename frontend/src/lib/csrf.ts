const CSRF_COOKIE_NAME = "csrf_token";

/**
 * Reads the csrf_token cookie fresh on every call. The server rotates this
 * value on every POST /auth/refresh (see backend app/api/routes/auth.py),
 * so caching it anywhere — React state, a module-level variable — would go
 * stale the moment a refresh happens, causing the next unsafe request to
 * fail CSRF validation with a stale token.
 */
export function getCsrfToken(): string | null {
  const match = document.cookie
    .split("; ")
    .find((row) => row.startsWith(`${CSRF_COOKIE_NAME}=`));
  if (!match) return null;
  return decodeURIComponent(match.slice(CSRF_COOKIE_NAME.length + 1));
}
