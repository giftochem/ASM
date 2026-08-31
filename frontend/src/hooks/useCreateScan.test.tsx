import { describe, expect, it } from "vitest";
import { act, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderHookWithProviders } from "../test/renderWithProviders";
import { useScan } from "./useScan";
import { useScans } from "./useScans";
import { useCreateScan } from "./useCreateScan";

const fakeScan = {
  id: "s1111111-1111-1111-1111-111111111111",
  asset_id: "a1111111-1111-1111-1111-111111111111",
  initiated_by: "u1",
  status: "queued" as const,
  modules_requested: ["whois"],
  started_at: null,
  completed_at: null,
  error_message: null,
  risk_score: null,
  risk_severity_band: null,
  created_at: "2026-01-01T00:00:00Z",
  findings: [] as never[],
};

function useComposite() {
  return { list: useScans(), detail: useScan(fakeScan.id), create: useCreateScan() };
}

describe("useCreateScan", () => {
  it("seeds the detail cache with the mutation response and invalidates the list", async () => {
    let listCallCount = 0;
    server.use(
      http.get("/scans", () => {
        listCallCount += 1;
        return HttpResponse.json(listCallCount === 1 ? [] : [fakeScan]);
      }),
      http.get("/scans/:id", () => HttpResponse.json(fakeScan)),
      http.post("/scans", () => HttpResponse.json(fakeScan, { status: 201 })),
    );

    const { result } = renderHookWithProviders(() => useComposite());
    await waitFor(() => expect(result.current.list.isSuccess).toBe(true));

    await act(async () => {
      await result.current.create.mutateAsync({ asset_id: fakeScan.asset_id, modules: ["whois"] });
    });

    // Detail view of the just-created scan reflects the mutation response
    // (TanStack Query's notifyManager batches the resulting re-render
    // asynchronously, so this needs waitFor rather than a synchronous read).
    await waitFor(() => expect(result.current.detail.data).toEqual(fakeScan));
    await waitFor(() => expect(result.current.list.data).toEqual([fakeScan]));
    expect(listCallCount).toBe(2);
  });

  it("does not clobber an unrelated, already-cached scan detail (list/detail key namespacing)", async () => {
    const otherScan = { ...fakeScan, id: "other-scan-id", status: "completed" as const };
    server.use(
      http.get("/scans", () => HttpResponse.json([otherScan])),
      http.get("/scans/:id", () => HttpResponse.json(otherScan)),
      http.post("/scans", () => HttpResponse.json(fakeScan, { status: 201 })),
    );

    function useOtherComposite() {
      return { otherDetail: useScan(otherScan.id), create: useCreateScan() };
    }

    const { result } = renderHookWithProviders(() => useOtherComposite());
    await waitFor(() => expect(result.current.otherDetail.data).toEqual(otherScan));

    await act(async () => {
      await result.current.create.mutateAsync({ asset_id: fakeScan.asset_id });
    });

    // Creating a new scan must not touch the cached data for a different one.
    await waitFor(() => expect(result.current.otherDetail.data).toEqual(otherScan));
  });

  it("surfaces the AuthorizationNotConfirmedError 403 without creating anything client-side", async () => {
    server.use(
      http.get("/scans", () => HttpResponse.json([])),
      http.post("/scans", () =>
        HttpResponse.json({ detail: "Asset 'example.com' does not have authorization_confirmed=true." }, { status: 403 }),
      ),
    );

    const { result } = renderHookWithProviders(() => useComposite());
    await waitFor(() => expect(result.current.list.isSuccess).toBe(true));

    await act(async () => {
      await expect(result.current.create.mutateAsync({ asset_id: fakeScan.asset_id })).rejects.toMatchObject({
        name: "ForbiddenError",
        reason: "other",
      });
    });

    expect(result.current.list.data).toEqual([]);
  });
});
