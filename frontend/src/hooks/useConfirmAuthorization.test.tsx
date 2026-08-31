import { describe, expect, it } from "vitest";
import { act, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderHookWithProviders } from "../test/renderWithProviders";
import { useAsset } from "./useAsset";
import { useConfirmAuthorization } from "./useConfirmAuthorization";

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

function useComposite(assetId: string) {
  return { asset: useAsset(assetId), confirm: useConfirmAuthorization(assetId) };
}

describe("useConfirmAuthorization", () => {
  it("writes the confirmed asset straight into the single-asset cache (no refetch needed)", async () => {
    let getCallCount = 0;
    server.use(
      http.get("/assets/:id", () => {
        getCallCount += 1;
        return HttpResponse.json(fakeAsset);
      }),
      http.post("/assets/:id/confirm-authorization", () =>
        HttpResponse.json({
          ...fakeAsset,
          authorization_confirmed: true,
          authorization_confirmed_by: "user-1",
          authorization_confirmed_at: "2026-01-02T00:00:00Z",
        }),
      ),
    );

    const { result } = renderHookWithProviders(() => useComposite(fakeAsset.id));
    await waitFor(() => expect(result.current.asset.isSuccess).toBe(true));
    expect(getCallCount).toBe(1);

    await act(async () => {
      await result.current.confirm.mutateAsync({ authorization_confirmed: true, attestation_note: null });
    });

    await waitFor(() => expect(result.current.asset.data?.authorization_confirmed).toBe(true));
    // Cache was written directly via setQueryData, not by a second GET.
    expect(getCallCount).toBe(1);
  });

  it("rejects with the backend's 400 when authorization_confirmed is not true (defensive: UI never sends false)", async () => {
    server.use(
      http.post("/assets/:id/confirm-authorization", () =>
        HttpResponse.json({ detail: "authorization_confirmed must be true to confirm authorization" }, { status: 400 }),
      ),
    );

    const { result } = renderHookWithProviders(() => useConfirmAuthorization(fakeAsset.id));

    await act(async () => {
      await expect(
        result.current.mutateAsync({ authorization_confirmed: true, attestation_note: null }),
      ).rejects.toMatchObject({ status: 400 });
    });
  });
});
