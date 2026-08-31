import { describe, expect, it } from "vitest";
import { waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderHookWithProviders } from "../test/renderWithProviders";
import { useAssets } from "./useAssets";

const fakeAsset = {
  id: "11111111-1111-1111-1111-111111111111",
  organization_id: "22222222-2222-2222-2222-222222222222",
  asset_type: "domain" as const,
  value: "example.com",
  parent_asset_id: null,
  authorization_confirmed: false,
  authorization_confirmed_by: null,
  authorization_confirmed_at: null,
  notes: null,
  is_active: true,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  status: "active" as const,
  source: "manual" as const,
  confidence: 1.0,
  environment: null,
  criticality: null,
  owner: null,
  tags: [],
  first_seen: "2026-01-01T00:00:00Z",
  last_seen: "2026-01-01T00:00:00Z",
};

describe("useAssets", () => {
  it("resolves with the org's asset list", async () => {
    server.use(http.get("/assets", () => HttpResponse.json([fakeAsset])));

    const { result } = renderHookWithProviders(() => useAssets());

    expect(result.current.isLoading).toBe(true);
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([fakeAsset]);
  });

  it("surfaces a 503 (Redis outage) as an error state, not a crash", async () => {
    server.use(
      http.get("/assets", () =>
        HttpResponse.json({ detail: "Service temporarily unavailable (rate limiting backend unreachable)" }, { status: 503 }),
      ),
    );

    const { result } = renderHookWithProviders(() => useAssets());

    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(result.current.error).toMatchObject({ name: "ServiceUnavailableError" });
  });
});
