import { getCsrfToken } from "../lib/csrf";
import { ensureFreshSession } from "./refreshMutex";
import {
  ApiError,
  ForbiddenError,
  NotFoundError,
  RateLimitedError,
  ServiceUnavailableError,
  UnauthorizedError,
  type ForbiddenReason,
} from "./errors";

const CSRF_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

type AuthStateListener = (user: unknown | null) => void;
const authStateListeners = new Set<AuthStateListener>();

/**
 * A tiny pub/sub bridging session-state transitions (login, register,
 * logout, refresh-failure) into AuthProvider, which lives OUTSIDE
 * QueryClientProvider in the approved provider order (ErrorBoundary >
 * AuthProvider > QueryClientProvider > RouterProvider) and therefore
 * cannot use TanStack Query hooks itself. api/auth.ts calls
 * publishAuthState() after register/login/logout succeed; apiFetch below
 * calls it with `null` when an automatic refresh-on-401 fails. This file
 * is the only thing that observes every one of those transitions, so it
 * owns the broadcast.
 */
export function publishAuthState(user: unknown | null): void {
  authStateListeners.forEach((listener) => listener(user));
}

export function subscribeAuthState(listener: AuthStateListener): () => void {
  authStateListeners.add(listener);
  return () => authStateListeners.delete(listener);
}

interface ApiFetchOptions extends Omit<RequestInit, "body"> {
  body?: unknown;
  /** Internal: set on the retry attempt after a refresh, to prevent infinite retry loops. */
  _isRetry?: boolean;
}

async function parseJsonBody(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function extractDetailMessage(body: unknown, fallback: string): string {
  if (body && typeof body === "object") {
    const record = body as Record<string, unknown>;
    if (typeof record.detail === "string") return record.detail;
    if (Array.isArray(record.detail)) {
      const messages = record.detail
        .map((item) =>
          item && typeof item === "object" && typeof (item as Record<string, unknown>).msg === "string"
            ? ((item as Record<string, unknown>).msg as string)
            : null,
        )
        .filter((msg): msg is string => Boolean(msg));
      if (messages.length > 0) return messages.join("; ");
    }
    // slowapi's default 429 handler uses {"error": "..."} — a different
    // key than every other error response in this API (see errors.ts).
    if (typeof record.error === "string") return record.error;
  }
  return fallback;
}

function classifyForbidden(body: unknown): ForbiddenReason {
  const detail = body && typeof body === "object" ? (body as Record<string, unknown>).detail : undefined;
  if (typeof detail === "string") {
    if (detail === "CSRF token missing or invalid") return "csrf";
    if (detail.startsWith("Requires one of roles:")) return "rbac";
  }
  return "other";
}

function parseRetryAfterSeconds(header: string | null): number | null {
  if (!header) return null;
  const seconds = Number(header);
  return Number.isFinite(seconds) ? seconds : null;
}

function defaultMessageForStatus(status: number): string {
  switch (status) {
    case 401:
      return "Unauthorized";
    case 403:
      return "Forbidden";
    case 404:
      return "Not found";
    case 429:
      return "Rate limited";
    case 503:
      return "Service unavailable";
    default:
      return `Request failed with status ${status}`;
  }
}

async function toApiError(response: Response): Promise<ApiError> {
  const body = await parseJsonBody(response);
  const message = extractDetailMessage(body, defaultMessageForStatus(response.status));

  switch (response.status) {
    case 401:
      return new UnauthorizedError(message, body);
    case 403:
      return new ForbiddenError(classifyForbidden(body), message, body);
    case 404:
      return new NotFoundError(message, body);
    case 429:
      return new RateLimitedError(message, parseRetryAfterSeconds(response.headers.get("Retry-After")), body);
    case 503:
      return new ServiceUnavailableError(message, body);
    default:
      return new ApiError(message, response.status, body);
  }
}

function buildBody(body: unknown): { payload?: BodyInit; contentType?: string } {
  if (body === undefined) return {};
  if (body instanceof URLSearchParams) {
    return { payload: body, contentType: "application/x-www-form-urlencoded" };
  }
  return { payload: JSON.stringify(body), contentType: "application/json" };
}

async function performRequest(path: string, options: ApiFetchOptions): Promise<Response> {
  const { body, headers: callerHeaders, ...rest } = options;
  const method = (options.method ?? "GET").toUpperCase();
  const { payload, contentType } = buildBody(body);

  const headers = new Headers(callerHeaders);
  if (contentType && !headers.has("Content-Type")) {
    headers.set("Content-Type", contentType);
  }
  if (CSRF_METHODS.has(method)) {
    // Omitted gracefully (not thrown) when absent — true for the very
    // first register/login call, which is CSRF-exempt server-side
    // (see app/core/cookies.py CSRF_EXEMPT_PATHS) precisely because no
    // session cookie exists yet to ride.
    const csrfToken = getCsrfToken();
    if (csrfToken) {
      headers.set("X-CSRF-Token", csrfToken);
    }
  }

  return fetch(path, { ...rest, method, headers, credentials: "same-origin", body: payload });
}

/**
 * Shared session/refresh/error-mapping core for both apiFetch (JSON) and
 * apiFetchBlob (binary downloads) — the 401-retry-after-refresh dance
 * must behave identically for both, so it's implemented exactly once.
 * `onOk` handles the one place they genuinely differ: how to read a
 * successful response body.
 */
async function requestWithSessionRetry<T>(
  path: string,
  options: ApiFetchOptions,
  onOk: (response: Response) => Promise<T>,
): Promise<T> {
  const response = await performRequest(path, options);

  if (response.ok) {
    return onOk(response);
  }

  if (response.status === 401 && !options._isRetry && path !== "/auth/refresh") {
    const refreshed = await ensureFreshSession();
    if (refreshed) {
      return requestWithSessionRetry(path, { ...options, _isRetry: true }, onOk);
    }
    publishAuthState(null);
  }

  throw await toApiError(response);
}

/**
 * The sole HTTP transport for this app — every API call goes through
 * here so the session/CSRF/refresh/error-mapping contract only has to be
 * implemented once. See docs/auth-cookie-model.md for the server side.
 */
export async function apiFetch<T>(path: string, options: ApiFetchOptions = {}): Promise<T> {
  return requestWithSessionRetry(path, options, async (response) => {
    if (response.status === 204) {
      return undefined as T;
    }
    return (await response.json()) as T;
  });
}

export interface BlobDownload {
  blob: Blob;
  /** From the response's Content-Disposition header (FastAPI's
   * FileResponse sets this whenever a filename is passed — see
   * app/api/routes/reports.py download_report), so the frontend doesn't
   * need its own copy of the backend's naming convention. Null if the
   * header is somehow absent; callers should fall back to a sensible
   * default in that case, not assume it's always present.
   */
  filename: string | null;
}

function extractFilename(response: Response): string | null {
  const disposition = response.headers.get("Content-Disposition");
  if (!disposition) return null;
  const match = /filename="?([^";]+)"?/i.exec(disposition);
  return match ? match[1] : null;
}

/**
 * Sibling to apiFetch for binary responses (currently just report
 * downloads) — same CSRF/credentials/401-refresh-retry contract, but
 * reads the body as a Blob instead of parsing it as JSON. Introduced in
 * Step 5 specifically because GET /reports/{id}/download returns a raw
 * file, not JSON, which apiFetch cannot represent.
 */
export async function apiFetchBlob(path: string, options: ApiFetchOptions = {}): Promise<BlobDownload> {
  return requestWithSessionRetry(path, options, async (response) => ({
    blob: await response.blob(),
    filename: extractFilename(response),
  }));
}
