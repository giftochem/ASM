import { describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { listAuditLogs } from "./auditLogs";
import { ForbiddenError } from "./errors";

const fakeLog = {
  id: "l1111111-1111-1111-1111-111111111111",
  user_id: "u1",
  organization_id: "org-1",
  action: "auth.login",
  resource_type: "user",
  resource_id: "u1",
  outcome: "success" as const,
  details: null,
  ip_address: "203.0.113.5",
  created_at: "2026-01-01T00:00:00Z",
};

describe("api/auditLogs.ts — request contract", () => {
  it("sends no query string when called with no params", async () => {
    let capturedUrl = "";
    server.use(
      http.get("/audit-logs", ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json([fakeLog]);
      }),
    );
    await listAuditLogs();
    expect(new URL(capturedUrl).search).toBe("");
  });

  it("sends every provided filter/pagination param", async () => {
    let capturedUrl = "";
    server.use(
      http.get("/audit-logs", ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json([]);
      }),
    );

    await listAuditLogs({
      action: "user.update",
      resource_type: "user",
      user_id: "u1",
      start_date: "2026-01-01T00:00:00Z",
      end_date: "2026-01-02T00:00:00Z",
      limit: 10,
      offset: 5,
    });

    const search = new URL(capturedUrl).searchParams;
    expect(search.get("action")).toBe("user.update");
    expect(search.get("resource_type")).toBe("user");
    expect(search.get("user_id")).toBe("u1");
    expect(search.get("start_date")).toBe("2026-01-01T00:00:00Z");
    expect(search.get("end_date")).toBe("2026-01-02T00:00:00Z");
    expect(search.get("limit")).toBe("10");
    expect(search.get("offset")).toBe("5");
  });

  it("a foreign-org user_id filter (per the backend's org-scope-first filter order) resolves to an empty list, never that org's logs", async () => {
    server.use(http.get("/audit-logs", () => HttpResponse.json([])));
    const result = await listAuditLogs({ user_id: "not-my-org-user-id" });
    expect(result).toEqual([]);
  });

  it("surfaces a non-admin's RBAC 403 — GET /audit-logs is admin-only", async () => {
    server.use(
      http.get("/audit-logs", () => HttpResponse.json({ detail: "Requires one of roles: admin" }, { status: 403 })),
    );
    const error = await listAuditLogs().catch((e) => e);
    expect(error).toBeInstanceOf(ForbiddenError);
    expect((error as InstanceType<typeof ForbiddenError>).reason).toBe("rbac");
  });

  it("surfaces a 422 for limit > 500", async () => {
    server.use(
      http.get("/audit-logs", () =>
        HttpResponse.json(
          { detail: [{ type: "less_than_equal", loc: ["query", "limit"], msg: "Input should be less than or equal to 500" }] },
          { status: 422 },
        ),
      ),
    );
    await expect(listAuditLogs({ limit: 501 })).rejects.toMatchObject({ status: 422 });
  });
});
