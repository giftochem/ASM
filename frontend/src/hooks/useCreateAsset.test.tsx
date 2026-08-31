import { describe, expect, it } from "vitest";
import { act, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderHookWithProviders } from "../test/renderWithProviders";
import { useAssets } from "./useAssets";
import { useCreateAsset } from "./useCreateAsset";

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

function useComposite() {
  return { list: useAssets(), create: useCreateAsset() };
}

describe("useCreateAsset", () => {
  it("invalidates and refetches the asset list on success", async () => {
    let listCallCount = 0;
    server.use(
      http.get("/assets", () => {
        listCallCount += 1;
        return HttpResponse.json(listCallCount === 1 ? [] : [fakeAsset]);
      }),
      http.post("/assets", () => HttpResponse.json(fakeAsset, { status: 201 })),
    );

    const { result } = renderHookWithProviders(() => useComposite());
    await waitFor(() => expect(result.current.list.data).toEqual([]));

    await act(async () => {
      await result.current.create.mutateAsync({ asset_type: "domain", value: "example.com" });
    });

    await waitFor(() => expect(result.current.list.data).toEqual([fakeAsset]));
    expect(listCallCount).toBe(2);
  });

  it("surfaces a 409 duplicate-asset error without touching the cached list", async () => {
    server.use(
      http.get("/assets", () => HttpResponse.json([])),
      http.post("/assets", () => HttpResponse.json({ detail: "Asset already exists" }, { status: 409 })),
    );

    const { result } = renderHookWithProviders(() => useComposite());
    await waitFor(() => expect(result.current.list.isSuccess).toBe(true));

    await act(async () => {
      await expect(
        result.current.create.mutateAsync({ asset_type: "domain", value: "example.com" }),
      ).rejects.toMatchObject({ status: 409 });
    });

    expect(result.current.list.data).toEqual([]);
  });
});
