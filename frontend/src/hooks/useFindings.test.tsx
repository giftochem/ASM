import { describe, expect, it } from "vitest";
import { waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderHookWithProviders } from "../test/renderWithProviders";
import { useFindings } from "./useFindings";

function fakeFinding(overrides: Record<string, unknown> = {}) {
  return {
    id: "f1",
    scan_id: "s1",
    asset_id: "a1",
    module: "whois",
    title: "x",
    description: null,
    severity: "info",
    confidence: 1,
    exposure: 1,
    exploitability: 0.5,
    evidence: null,
    created_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

describe("useFindings", () => {
  it("resolves with the filtered list", async () => {
    server.use(http.get("/findings", () => HttpResponse.json([fakeFinding()])));
    const { result } = renderHookWithProviders(() => useFindings({}));
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toHaveLength(1);
  });

  it("surfaces an error state without crashing", async () => {
    server.use(http.get("/findings", () => HttpResponse.json({ detail: "Service temporarily unavailable" }, { status: 503 })));
    const { result } = renderHookWithProviders(() => useFindings({}));
    await waitFor(() => expect(result.current.isError).toBe(true));
  });

  it("two different asset_id filters never collide in the cache — each gets its own data, never a merge", async () => {
    server.use(
      http.get("/findings", ({ request }) => {
        const assetId = new URL(request.url).searchParams.get("asset_id");
        if (assetId === "asset-a") return HttpResponse.json([fakeFinding({ id: "f-a", asset_id: "asset-a" })]);
        if (assetId === "asset-b") return HttpResponse.json([fakeFinding({ id: "f-b", asset_id: "asset-b" })]);
        return HttpResponse.json([]);
      }),
    );

    function useBoth() {
      return { a: useFindings({ asset_id: "asset-a" }), b: useFindings({ asset_id: "asset-b" }) };
    }

    const { result } = renderHookWithProviders(() => useBoth());

    await waitFor(() => expect(result.current.a.isSuccess && result.current.b.isSuccess).toBe(true));

    expect(result.current.a.data).toEqual([fakeFinding({ id: "f-a", asset_id: "asset-a" })]);
    expect(result.current.b.data).toEqual([fakeFinding({ id: "f-b", asset_id: "asset-b" })]);
  });
});
