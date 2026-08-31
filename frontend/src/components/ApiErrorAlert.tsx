import {
  ApiError,
  ForbiddenError,
  NotFoundError,
  RateLimitedError,
  ServiceUnavailableError,
  UnauthorizedError,
} from "../api/errors";

function messageFor(error: ApiError): string {
  if (error instanceof UnauthorizedError) {
    return "Your session has expired. Please log in again.";
  }
  if (error instanceof ForbiddenError) {
    if (error.reason === "csrf") {
      return "Your session security check failed. Please refresh the page and try again.";
    }
    if (error.reason === "rbac") {
      return "You don't have permission to do that.";
    }
    return error.message;
  }
  if (error instanceof NotFoundError) {
    return "Not found.";
  }
  if (error instanceof RateLimitedError) {
    return error.retryAfterSeconds
      ? `Too many requests. Try again in ${error.retryAfterSeconds}s.`
      : "Too many requests. Please try again shortly.";
  }
  if (error instanceof ServiceUnavailableError) {
    return "Service temporarily unavailable. Please try again shortly.";
  }
  return error.message || "Something went wrong.";
}

export function ApiErrorAlert({ error }: { error: unknown }) {
  if (!(error instanceof ApiError)) {
    return null;
  }
  return (
    <div role="alert" className="rounded border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-800">
      {messageFor(error)}
    </div>
  );
}
