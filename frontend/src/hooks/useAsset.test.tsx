import { describe, expect, it } from "vitest";
import { waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderHookWithProviders } from "../test/renderWithProviders";
import { useAsset } from "./useAsset";

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
};

describe("useAsset", () => {
  it("resolves with a single asset", async () => {
    server.use(http.get("/assets/:id", () => HttpResponse.json(fakeAsset)));

    const { result } = renderHookWithProviders(() => useAsset(fakeAsset.id));

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(fakeAsset);
  });

  it("surfaces a cross-org 404 as a NotFoundError, matching the backend's ownership-boundary pattern", async () => {
    server.use(http.get("/assets/:id", () => HttpResponse.json({ detail: "Asset not found" }, { status: 404 })));

    const { result } = renderHookWithProviders(() => useAsset("other-org-asset-id"));

    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(result.current.error).toMatchObject({ name: "NotFoundError", status: 404 });
  });

  it("does not fetch when assetId is empty", () => {
    const { result } = renderHookWithProviders(() => useAsset(""));
    expect(result.current.fetchStatus).toBe("idle");
  });
});
