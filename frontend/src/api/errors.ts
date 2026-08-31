/**
 * Typed error taxonomy for the 401/403/404/429/503 contract. Every shape
 * here was read directly off the running backend, not assumed:
 *  - Normal HTTPException / route-raised errors: {"detail": "<string>"}
 *  - FastAPI 422 validation errors:              {"detail": [{msg, loc, type}, ...]}
 *  - CSRF middleware 403 (app/core/csrf_middleware.py):
 *      {"detail": "CSRF token missing or invalid"}
 *  - RBAC 403 (app/dependencies.py require_role): {"detail": "Requires one of roles: ..."}
 *  - slowapi 429 (its own default handler, NOT this app's convention):
 *      {"error": "Rate limit exceeded: ..."}  <- note "error", not "detail"
 *  - Redis-outage 503 (app/main.py):              {"detail": "Service temporarily unavailable..."}
 */
export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;

  constructor(message: string, status: number, detail?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

export class UnauthorizedError extends ApiError {
  constructor(message: string, detail?: unknown) {
    super(message, 401, detail);
    this.name = "UnauthorizedError";
  }
}

export type ForbiddenReason = "csrf" | "rbac" | "other";

export class ForbiddenError extends ApiError {
  readonly reason: ForbiddenReason;

  constructor(reason: ForbiddenReason, message: string, detail?: unknown) {
    super(message, 403, detail);
    this.name = "ForbiddenError";
    this.reason = reason;
  }
}

export class NotFoundError extends ApiError {
  constructor(message: string, detail?: unknown) {
    super(message, 404, detail);
    this.name = "NotFoundError";
  }
}

export class RateLimitedError extends ApiError {
  /**
   * Null today for every real response from this backend: slowapi's
   * Limiter is constructed without `headers_enabled=True` (see
   * app/services/rate_limit.py), so it never actually emits a
   * `Retry-After` header. Kept as a field (rather than dropped) because
   * it's part of the approved error taxonomy and becomes real the moment
   * that backend flag is flipped — reading a header that isn't there is
   * harmless, so this is forward-compatible, not speculative.
   */
  readonly retryAfterSeconds: number | null;

  constructor(message: string, retryAfterSeconds: number | null, detail?: unknown) {
    super(message, 429, detail);
    this.name = "RateLimitedError";
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export class ServiceUnavailableError extends ApiError {
  constructor(message: string, detail?: unknown) {
    super(message, 503, detail);
    this.name = "ServiceUnavailableError";
  }
}
