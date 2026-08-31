import { describe, expect, it } from "vitest";
import { act, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderHookWithProviders } from "../test/renderWithProviders";
import { useAsset } from "./useAsset";
import { useRevokeAuthorization } from "./useRevokeAuthorization";

const confirmedAsset = {
  id: "11111111-1111-1111-1111-111111111111",
  organization_id: "22222222-2222-2222-2222-222222222222",
  asset_type: "domain" as const,
  value: "example.com",
  parent_asset_id: null,
  authorization_confirmed: true,
  authorization_confirmed_by: "user-1",
  authorization_confirmed_at: "2026-01-01T00:00:00Z",
  notes: null,
  is_active: true,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

function useComposite(assetId: string) {
  return { asset: useAsset(assetId), revoke: useRevokeAuthorization(assetId) };
}

describe("useRevokeAuthorization", () => {
  it("writes the revoked asset straight into the single-asset cache", async () => {
    server.use(
      http.get("/assets/:id", () => HttpResponse.json(confirmedAsset)),
      http.post("/assets/:id/revoke-authorization", () =>
        HttpResponse.json({
          ...confirmedAsset,
          authorization_confirmed: false,
          authorization_confirmed_by: null,
          authorization_confirmed_at: null,
        }),
      ),
    );

    const { result } = renderHookWithProviders(() => useComposite(confirmedAsset.id));
    await waitFor(() => expect(result.current.asset.data?.authorization_confirmed).toBe(true));

    await act(async () => {
      await result.current.revoke.mutateAsync({ reason: "engagement ended" });
    });

    await waitFor(() => expect(result.current.asset.data?.authorization_confirmed).toBe(false));
  });

  it("surfaces a viewer's 403 as ForbiddenError with reason 'rbac'", async () => {
    server.use(
      http.post("/assets/:id/revoke-authorization", () =>
        HttpResponse.json({ detail: "Requires one of roles: admin, analyst" }, { status: 403 }),
      ),
    );

    const { result } = renderHookWithProviders(() => useRevokeAuthorization(confirmedAsset.id));

    await act(async () => {
      await expect(result.current.mutateAsync({ reason: null })).rejects.toMatchObject({
        name: "ForbiddenError",
        reason: "rbac",
      });
    });
  });
});
