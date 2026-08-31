import { describe, expect, it } from "vitest";
import { waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderHookWithProviders } from "../test/renderWithProviders";
import { useAuditLogs } from "./useAuditLogs";

function fakeLog(overrides: Record<string, unknown> = {}) {
  return {
    id: "l1",
    user_id: "u1",
    organization_id: "org-1",
    action: "auth.login",
    resource_type: "user",
    resource_id: "u1",
    outcome: "success",
    details: null,
    ip_address: "203.0.113.5",
    created_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

describe("useAuditLogs", () => {
  it("resolves with the filtered list", async () => {
    server.use(http.get("/audit-logs", () => HttpResponse.json([fakeLog()])));
    const { result } = renderHookWithProviders(() => useAuditLogs({}));
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toHaveLength(1);
  });

  it("surfaces an RBAC 403 as an error state", async () => {
    server.use(
      http.get("/audit-logs", () => HttpResponse.json({ detail: "Requires one of roles: admin" }, { status: 403 })),
    );
    const { result } = renderHookWithProviders(() => useAuditLogs({}));
    await waitFor(() => expect(result.current.isError).toBe(true));
  });

  it("two different user_id filters never collide in the cache — each resolves independently", async () => {
    server.use(
      http.get("/audit-logs", ({ request }) => {
        const userId = new URL(request.url).searchParams.get("user_id");
        if (userId === "user-a") return HttpResponse.json([fakeLog({ id: "l-a", user_id: "user-a" })]);
        if (userId === "user-b") return HttpResponse.json([fakeLog({ id: "l-b", user_id: "user-b" })]);
        return HttpResponse.json([]);
      }),
    );

    function useBoth() {
      return { a: useAuditLogs({ user_id: "user-a" }), b: useAuditLogs({ user_id: "user-b" }) };
    }

    const { result } = renderHookWithProviders(() => useBoth());
    await waitFor(() => expect(result.current.a.isSuccess && result.current.b.isSuccess).toBe(true));

    expect(result.current.a.data).toEqual([fakeLog({ id: "l-a", user_id: "user-a" })]);
    expect(result.current.b.data).toEqual([fakeLog({ id: "l-b", user_id: "user-b" })]);
  });
});
