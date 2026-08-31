import { describe, expect, it } from "vitest";
import { act, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderHookWithProviders } from "../test/renderWithProviders";
import { useScan } from "./useScan";
import { useCancelScan } from "./useCancelScan";

const queuedScanResult = {
  id: "s1111111-1111-1111-1111-111111111111",
  asset_id: "a1",
  initiated_by: "u1",
  status: "queued" as const,
  modules_requested: ["whois"],
  started_at: null,
  completed_at: null,
  error_message: null,
  risk_score: null,
  risk_severity_band: null,
  created_at: "2026-01-01T00:00:00Z",
  findings: [{ id: "f1", scan_id: "s1", asset_id: "a1", module: "whois", title: "x", description: null, severity: "info" as const, confidence: 1, exposure: 1, exploitability: 0.5, evidence: null, created_at: "2026-01-01T00:00:00Z" }],
};

function useComposite() {
  return { detail: useScan(queuedScanResult.id), cancel: useCancelScan(queuedScanResult.id) };
}

describe("useCancelScan", () => {
  it("updates status to cancelled WITHOUT wiping findings from the cache (ScanRead response has no findings field)", async () => {
    server.use(
      http.get("/scans/:id", () => HttpResponse.json(queuedScanResult)),
      http.post("/scans/:id/cancel", () =>
        // POST /cancel responds with ScanRead — deliberately no `findings` key.
        HttpResponse.json({
          id: queuedScanResult.id,
          asset_id: queuedScanResult.asset_id,
          initiated_by: queuedScanResult.initiated_by,
          status: "cancelled",
          modules_requested: queuedScanResult.modules_requested,
          started_at: null,
          completed_at: "2026-01-01T00:00:05Z",
          error_message: null,
          risk_score: null,
          risk_severity_band: null,
          created_at: queuedScanResult.created_at,
        }),
      ),
    );

    const { result } = renderHookWithProviders(() => useComposite());
    await waitFor(() => expect(result.current.detail.data?.findings).toHaveLength(1));

    await act(async () => {
      await result.current.cancel.mutateAsync();
    });

    await waitFor(() => expect(result.current.detail.data?.status).toBe("cancelled"));
    // The regression this guards against: a naive overwrite would leave
    // `findings` undefined here, and any `.length` read on it would throw.
    expect(result.current.detail.data?.findings).toHaveLength(1);
  });

  it("surfaces a 409 when the scan already left 'queued' (race with the worker)", async () => {
    server.use(
      http.post("/scans/:id/cancel", () =>
        HttpResponse.json({ detail: "cannot cancel a scan in status 'running'" }, { status: 409 }),
      ),
    );

    const { result } = renderHookWithProviders(() => useCancelScan(queuedScanResult.id));

    await act(async () => {
      await expect(result.current.mutateAsync()).rejects.toMatchObject({ status: 409 });
    });
  });
});
