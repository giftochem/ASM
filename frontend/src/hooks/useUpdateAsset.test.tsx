import { describe, expect, it } from "vitest";
import { act, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderHookWithProviders } from "../test/renderWithProviders";
import { useAsset } from "./useAsset";
import { useUpdateAsset } from "./useUpdateAsset";

const ASSET_ID = "11111111-1111-1111-1111-111111111111";
const OTHER_ASSET_ID = "33333333-3333-3333-3333-333333333333";

const fakeAsset = {
  id: ASSET_ID,
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

function useComposite(assetId: string) {
  return { asset: useAsset(assetId), update: useUpdateAsset(assetId) };
}

describe("useUpdateAsset", () => {
  it("writes the updated asset into the detail cache and invalidates only what derives from it", async () => {
    let getCallCount = 0;
    let patchedBody: unknown = null;
    server.use(
      http.get("/assets/:id", () => {
        getCallCount += 1;
        return HttpResponse.json(fakeAsset);
      }),
      http.patch("/assets/:id", async ({ request }) => {
        patchedBody = await request.json();
        return HttpResponse.json({ ...fakeAsset, criticality: "critical", updated_at: "2026-01-02T00:00:00Z" });
      }),
    );

    const { result, queryClient } = renderHookWithProviders(() => useComposite(ASSET_ID));
    await waitFor(() => expect(result.current.asset.isSuccess).toBe(true));

    // Cached (inactive) entries for everything that shows criticality,
    // environment or the change history, plus two that must be left alone.
    const derivedKeys = [
      ["assets", "detail", ASSET_ID, "risk"],
      ["assets", "detail", ASSET_ID, "observations", 20],
      ["assets", "detail", ASSET_ID, "graph", 2],
      ["assets", "list", {}],
      ["prioritized-assets", { limit: 200 }],
      ["activity", { limit: 10 }],
      ["summary"],
    ];
    const unrelatedKeys = [
      ["assets", "detail", OTHER_ASSET_ID],
      ["scans", "list"],
    ];
    for (const key of [...derivedKeys, ...unrelatedKeys]) {
      queryClient.setQueryData(key, { seeded: true });
    }

    await act(async () => {
      await result.current.update.mutateAsync({ criticality: "critical" });
    });

    expect(patchedBody).toEqual({ criticality: "critical" });
    await waitFor(() => expect(result.current.asset.data?.criticality).toBe("critical"));
    // The detail entry was written via setQueryData, not by a second GET
    // (invalidating it would race that write -- see useConfirmAuthorization).
    expect(getCallCount).toBe(1);
    expect(queryClient.getQueryState(["assets", "detail", ASSET_ID])?.isInvalidated).toBe(false);
    for (const key of derivedKeys) {
      expect(queryClient.getQueryState(key)?.isInvalidated, JSON.stringify(key)).toBe(true);
    }
    for (const key of unrelatedKeys) {
      expect(queryClient.getQueryState(key)?.isInvalidated, JSON.stringify(key)).toBe(false);
    }
  });

  it("surfaces a 422 without touching the cached asset", async () => {
    server.use(
      http.get("/assets/:id", () => HttpResponse.json(fakeAsset)),
      http.patch("/assets/:id", () =>
        HttpResponse.json(
          { detail: [{ type: "extra_forbidden", loc: ["body", "owner"], msg: "Extra inputs are not permitted" }] },
          { status: 422 },
        ),
      ),
    );

    const { result, queryClient } = renderHookWithProviders(() => useComposite(ASSET_ID));
    await waitFor(() => expect(result.current.asset.isSuccess).toBe(true));
    queryClient.setQueryData(["prioritized-assets", {}], { seeded: true });

    await act(async () => {
      await expect(result.current.update.mutateAsync({ criticality: "high" })).rejects.toMatchObject({
        status: 422,
        message: "Extra inputs are not permitted",
      });
    });

    expect(result.current.asset.data).toEqual(fakeAsset);
    expect(queryClient.getQueryState(["prioritized-assets", {}])?.isInvalidated).toBe(false);
  });
});
