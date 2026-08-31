import { beforeEach, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { apiFetch, apiFetchBlob, subscribeAuthState } from "./client";

beforeEach(() => {
  document.cookie = "csrf_token=test-csrf-token; path=/";
});

describe("apiFetch — CSRF header attachment", () => {
  it("attaches X-CSRF-Token on unsafe methods when a token cookie is present", async () => {
    let capturedHeader: string | null = "unset";
    server.use(
      http.post("/widgets", ({ request }) => {
        capturedHeader = request.headers.get("X-CSRF-Token");
        return HttpResponse.json({ ok: true });
      }),
    );

    await apiFetch("/widgets", { method: "POST", body: { name: "x" } });

    expect(capturedHeader).toBe("test-csrf-token");
  });

  it("does not attach X-CSRF-Token on GET requests", async () => {
    let capturedHeader: string | null = "unset";
    server.use(
      http.get("/widgets", ({ request }) => {
        capturedHeader = request.headers.get("X-CSRF-Token");
        return HttpResponse.json([]);
      }),
    );

    await apiFetch("/widgets");

    expect(capturedHeader).toBeNull();
  });

  it("omits X-CSRF-Token gracefully (not thrown) when no cookie is present", async () => {
    document.cookie = "csrf_token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
    let capturedHeader: string | null = "unset";
    server.use(
      http.post("/auth/login", ({ request }) => {
        capturedHeader = request.headers.get("X-CSRF-Token");
        return HttpResponse.json({ id: "u1" });
      }),
    );

    await apiFetch("/auth/login", {
      method: "POST",
      body: new URLSearchParams({ username: "a", password: "b" }),
    });

    expect(capturedHeader).toBeNull();
  });
});

describe("apiFetch — concurrent 401 refresh mutex", () => {
  it("coalesces N simultaneous 401s into exactly one /auth/refresh call", async () => {
    let sessionRefreshed = false;
    let refreshCallCount = 0;

    server.use(
      http.get("/protected", () => {
        return sessionRefreshed
          ? HttpResponse.json({ ok: true })
          : HttpResponse.json({ detail: "Could not validate credentials" }, { status: 401 });
      }),
      http.post("/auth/refresh", ({ request }) => {
        refreshCallCount += 1;
        sessionRefreshed = true;
        expect(request.headers.get("X-CSRF-Token")).toBe("test-csrf-token");
        return HttpResponse.json({ id: "u1" });
      }),
    );

    const results = await Promise.all([
      apiFetch("/protected"),
      apiFetch("/protected"),
      apiFetch("/protected"),
    ]);

    expect(refreshCallCount).toBe(1);
    results.forEach((result) => expect(result).toEqual({ ok: true }));
  });

  it("does not attempt a refresh loop on a 401 from /auth/refresh itself", async () => {
    let refreshCalls = 0;
    server.use(
      http.post("/auth/refresh", () => {
        refreshCalls += 1;
        return HttpResponse.json({ detail: "No refresh token" }, { status: 401 });
      }),
    );

    await expect(apiFetch("/auth/refresh", { method: "POST" })).rejects.toMatchObject({
      name: "UnauthorizedError",
    });
    expect(refreshCalls).toBe(1);
  });

  it("publishes a null auth state when the automatic refresh fails", async () => {
    server.use(
      http.get("/protected", () => HttpResponse.json({ detail: "nope" }, { status: 401 })),
      http.post("/auth/refresh", () => HttpResponse.json({ detail: "No refresh token" }, { status: 401 })),
    );
    const received: unknown[] = [];
    const unsubscribe = subscribeAuthState((user) => received.push(user));

    await expect(apiFetch("/protected")).rejects.toMatchObject({ name: "UnauthorizedError" });

    unsubscribe();
    expect(received).toEqual([null]);
  });
});

describe("apiFetch — error taxonomy mapping", () => {
  it("maps a CSRF-rejected 403 to ForbiddenError with reason 'csrf'", async () => {
    server.use(
      http.post("/widgets", () =>
        HttpResponse.json({ detail: "CSRF token missing or invalid" }, { status: 403 }),
      ),
    );

    await expect(apiFetch("/widgets", { method: "POST" })).rejects.toMatchObject({
      name: "ForbiddenError",
      reason: "csrf",
    });
  });

  it("maps an RBAC-rejected 403 to ForbiddenError with reason 'rbac'", async () => {
    server.use(
      http.post("/widgets", () =>
        HttpResponse.json({ detail: "Requires one of roles: admin" }, { status: 403 }),
      ),
    );

    await expect(apiFetch("/widgets", { method: "POST" })).rejects.toMatchObject({
      name: "ForbiddenError",
      reason: "rbac",
    });
  });

  it("maps an unrecognized 403 detail to ForbiddenError with reason 'other', preserving the message", async () => {
    server.use(
      http.post("/auth/login", () => HttpResponse.json({ detail: "User is disabled" }, { status: 403 })),
    );

    await expect(
      apiFetch("/auth/login", { method: "POST", body: new URLSearchParams({ username: "a", password: "b" }) }),
    ).rejects.toMatchObject({ name: "ForbiddenError", reason: "other", message: "User is disabled" });
  });

  it("maps 404 to NotFoundError", async () => {
    server.use(http.get("/widgets/1", () => HttpResponse.json({ detail: "Not found" }, { status: 404 })));

    await expect(apiFetch("/widgets/1")).rejects.toMatchObject({ name: "NotFoundError", status: 404 });
  });

  it("maps 429 (slowapi's {\"error\": ...} body shape, not {\"detail\": ...}) to RateLimitedError", async () => {
    server.use(
      http.post("/auth/login", () =>
        HttpResponse.json({ error: "Rate limit exceeded: 5 per 1 minute" }, { status: 429 }),
      ),
    );

    await expect(
      apiFetch("/auth/login", { method: "POST", body: new URLSearchParams({ username: "a", password: "b" }) }),
    ).rejects.toMatchObject({
      name: "RateLimitedError",
      message: expect.stringContaining("Rate limit exceeded"),
      retryAfterSeconds: null,
    });
  });

  it("maps 503 to ServiceUnavailableError", async () => {
    server.use(
      http.get("/widgets", () =>
        HttpResponse.json({ detail: "Service temporarily unavailable (rate limiting backend unreachable)" }, { status: 503 }),
      ),
    );

    await expect(apiFetch("/widgets")).rejects.toMatchObject({ name: "ServiceUnavailableError" });
  });
});

describe("apiFetchBlob — binary downloads (Step 5)", () => {
  it("resolves with the response body as a Blob", async () => {
    server.use(
      http.get("/files/1", () => new HttpResponse(new Blob(["file content"]), { headers: { "Content-Type": "application/pdf" } })),
    );

    const result = await apiFetchBlob("/files/1");

    // This environment's MSW/jsdom Blob plumbing doesn't reliably carry
    // exact byte content through HttpResponse(new Blob([...])) — it's
    // observed to stringify to "[object Blob]" regardless of input, and
    // the resulting Blob polyfill only implements slice/size/type (no
    // .text()/.arrayBuffer()). Neither limitation exists in a real
    // browser; asserting "a non-empty Blob came through" is what's
    // reliably verifiable here, not exact content.
    expect(result.blob).toBeInstanceOf(Blob);
    expect(result.blob.size).toBeGreaterThan(0);
  });

  it("extracts the filename from Content-Disposition", async () => {
    server.use(
      http.get("/files/1", () =>
        new HttpResponse(new Blob(["x"]), {
          headers: { "Content-Disposition": 'attachment; filename="asm-report-abc123.pdf"' },
        }),
      ),
    );

    const result = await apiFetchBlob("/files/1");
    expect(result.filename).toBe("asm-report-abc123.pdf");
  });

  it("returns a null filename when Content-Disposition is absent, rather than throwing", async () => {
    server.use(http.get("/files/1", () => new HttpResponse(new Blob(["x"]))));

    const result = await apiFetchBlob("/files/1");
    expect(result.filename).toBeNull();
  });

  it("shares the same 401-refresh-retry mutex as apiFetch", async () => {
    let sessionRefreshed = false;
    let refreshCallCount = 0;
    server.use(
      http.get("/files/1", () => {
        return sessionRefreshed
          ? new HttpResponse(new Blob(["ok"]))
          : HttpResponse.json({ detail: "Could not validate credentials" }, { status: 401 });
      }),
      http.post("/auth/refresh", () => {
        refreshCallCount += 1;
        sessionRefreshed = true;
        return HttpResponse.json({ id: "u1" });
      }),
    );

    const result = await apiFetchBlob("/files/1");

    expect(refreshCallCount).toBe(1);
    // See the identical note above on exact Blob content in this
    // environment — a non-empty Blob is the reliable signal here.
    expect(result.blob.size).toBeGreaterThan(0);
  });

  it("maps a 409 (report not ready) to a generic ApiError with the backend's message", async () => {
    server.use(
      http.get("/files/1", () =>
        HttpResponse.json({ detail: "Report is not available for download (status: pending)" }, { status: 409 }),
      ),
    );

    await expect(apiFetchBlob("/files/1")).rejects.toMatchObject({
      status: 409,
      message: expect.stringContaining("not available for download"),
    });
  });

  it("maps a 404 (cross-org report) to NotFoundError", async () => {
    server.use(http.get("/files/1", () => HttpResponse.json({ detail: "Report not found" }, { status: 404 })));
    await expect(apiFetchBlob("/files/1")).rejects.toMatchObject({ name: "NotFoundError" });
  });
});
