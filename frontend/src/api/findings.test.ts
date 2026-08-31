import { describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { listFindings } from "./findings";
import { ForbiddenError, UnauthorizedError } from "./errors";

const fakeFinding = {
  id: "f1111111-1111-1111-1111-111111111111",
  scan_id: "s1111111-1111-1111-1111-111111111111",
  asset_id: "a1111111-1111-1111-1111-111111111111",
  module: "whois",
  title: "Registrar found",
  description: null,
  severity: "info" as const,
  confidence: 1,
  exposure: 1,
  exploitability: 0.5,
  evidence: null,
  created_at: "2026-01-01T00:00:00Z",
};

describe("api/findings.ts — request contract", () => {
  it("sends no query string when called with no params", async () => {
    let capturedUrl = "";
    server.use(
      http.get("/findings", ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json([fakeFinding]);
      }),
    );
    await listFindings();
    expect(new URL(capturedUrl).search).toBe("");
  });

  it("sends every provided filter/pagination param, and omits every omitted one", async () => {
    let capturedUrl = "";
    server.use(
      http.get("/findings", ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json([fakeFinding]);
      }),
    );

    await listFindings({ severity: "critical", module: "whois", limit: 10, offset: 20 });

    const search = new URL(capturedUrl).searchParams;
    expect(search.get("severity")).toBe("critical");
    expect(search.get("module")).toBe("whois");
    expect(search.get("limit")).toBe("10");
    expect(search.get("offset")).toBe("20");
    expect(search.has("asset_id")).toBe(false);
    expect(search.has("scan_id")).toBe(false);
  });

  it("sends asset_id and scan_id filters verbatim", async () => {
    let capturedUrl = "";
    server.use(
      http.get("/findings", ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json([]);
      }),
    );

    await listFindings({ asset_id: "asset-xyz", scan_id: "scan-xyz" });

    const search = new URL(capturedUrl).searchParams;
    expect(search.get("asset_id")).toBe("asset-xyz");
    expect(search.get("scan_id")).toBe("scan-xyz");
  });

  it("a foreign-org asset_id/scan_id filter (per the backend's join-based scoping) resolves to an empty list, not an error", async () => {
    server.use(http.get("/findings", () => HttpResponse.json([])));
    const result = await listFindings({ asset_id: "not-my-org-asset-id" });
    expect(result).toEqual([]);
  });

  it("surfaces 401 when unauthenticated", async () => {
    server.use(http.get("/findings", () => HttpResponse.json({ detail: "Could not validate credentials" }, { status: 401 })));
    await expect(listFindings()).rejects.toBeInstanceOf(UnauthorizedError);
  });

  it("surfaces a 422 for limit > 500 with a readable message", async () => {
    server.use(
      http.get("/findings", () =>
        HttpResponse.json(
          { detail: [{ type: "less_than_equal", loc: ["query", "limit"], msg: "Input should be less than or equal to 500" }] },
          { status: 422 },
        ),
      ),
    );
    await expect(listFindings({ limit: 501 })).rejects.toMatchObject({
      status: 422,
      message: expect.stringContaining("less than or equal to 500"),
    });
  });

  it("surfaces a 503 without crashing (Redis-outage-style backend failure)", async () => {
    server.use(http.get("/findings", () => HttpResponse.json({ detail: "Service temporarily unavailable" }, { status: 503 })));
    const error = await listFindings().catch((e) => e);
    expect(error.status).toBe(503);
  });

  it("does not attach a CSRF header (GET is a safe method)", async () => {
    let capturedHeader: string | null = "unset";
    server.use(
      http.get("/findings", ({ request }) => {
        capturedHeader = request.headers.get("X-CSRF-Token");
        return HttpResponse.json([]);
      }),
    );
    await listFindings();
    expect(capturedHeader).toBeNull();
  });

  it("a viewer-role 403 would not occur here — GET /findings has no require_role restriction — but a generic 403 still maps cleanly if ever returned", async () => {
    server.use(http.get("/findings", () => HttpResponse.json({ detail: "Requires one of roles: admin" }, { status: 403 })));
    await expect(listFindings()).rejects.toBeInstanceOf(ForbiddenError);
  });
});
