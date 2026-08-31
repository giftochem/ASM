import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderHookWithProviders } from "../test/renderWithProviders";
import { useScans } from "./useScans";

const queuedScan = {
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
};

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

/** See the identical helper (and its rationale) in useScan.test.tsx. */
async function pollUntil(check: () => void, { tickMs = 250, timeout = 10000 } = {}) {
  await vi.waitFor(
    async () => {
      await vi.advanceTimersByTimeAsync(tickMs);
      check();
    },
    { timeout, interval: 1 },
  );
}

describe("useScans", () => {
  it("fetches the unfiltered list when no assetId is given", async () => {
    let capturedUrl = "";
    server.use(
      http.get("/scans", ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json([]);
      }),
    );
    const { result } = renderHookWithProviders(() => useScans());
    await vi.waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(new URL(capturedUrl).search).toBe("");
  });

  it("fetches scoped to assetId when given", async () => {
    let capturedUrl = "";
    server.use(
      http.get("/scans", ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json([queuedScan]);
      }),
    );
    const { result } = renderHookWithProviders(() => useScans({ assetId: queuedScan.asset_id }));
    await vi.waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(new URL(capturedUrl).searchParams.get("asset_id")).toBe(queuedScan.asset_id);
  });

  it("does not fetch when assetId is an empty string (params not resolved yet, not 'no filter')", () => {
    const { result } = renderHookWithProviders(() => useScans({ assetId: "" }));
    expect(result.current.fetchStatus).toBe("idle");
  });

  it("polls while any scan is queued/running, and stops once everything is terminal", async () => {
    let callCount = 0;
    server.use(
      http.get("/scans", () => {
        callCount += 1;
        // First two calls: still queued. From the third call on: terminal.
        return HttpResponse.json([{ ...queuedScan, status: callCount < 3 ? "queued" : "completed" }]);
      }),
    );

    const { result } = renderHookWithProviders(() => useScans());
    await vi.waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(callCount).toBe(1);

    await pollUntil(() => expect(callCount).toBe(2));
    await pollUntil(() => expect(result.current.data?.[0].status).toBe("completed"));
    expect(callCount).toBe(3);

    // Now terminal — further time passing must NOT trigger another fetch.
    await vi.advanceTimersByTimeAsync(20000);
    expect(callCount).toBe(3);
  });
});
