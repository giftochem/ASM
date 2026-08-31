import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderHookWithProviders } from "../test/renderWithProviders";
import { useScan } from "./useScan";

const SCAN_ID = "s1111111-1111-1111-1111-111111111111";

function scanWithStatus(status: "queued" | "running" | "completed" | "failed" | "cancelled") {
  return {
    id: SCAN_ID,
    asset_id: "a1",
    initiated_by: "u1",
    status,
    modules_requested: ["whois"],
    started_at: status === "queued" ? null : "2026-01-01T00:00:00Z",
    completed_at: status === "queued" || status === "running" ? null : "2026-01-01T00:01:00Z",
    error_message: status === "failed" ? "whois: unexpected error" : null,
    risk_score: null,
    risk_severity_band: null,
    created_at: "2026-01-01T00:00:00Z",
    findings: [],
  };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

/** Ticks the fake clock forward in small increments from inside a
 * vi.waitFor retry callback, until `check` passes or the overall timeout
 * is exhausted. Advancing a single large increment once is flaky under
 * concurrent test-file load (TanStack Query's internal refetch promise
 * chain needs a variable number of microtask flushes to settle, and
 * `shouldAdvanceTime`'s real-time proportionality drifts under CPU
 * contention) — ticking repeatedly from within the retry, rather than
 * once from outside it, makes this deterministic regardless of how many
 * flushes are needed or how loaded the machine is.
 */
async function pollUntil(check: () => void, { tickMs = 250, timeout = 10000 } = {}) {
  await vi.waitFor(
    async () => {
      await vi.advanceTimersByTimeAsync(tickMs);
      check();
    },
    { timeout, interval: 1 },
  );
}

describe("useScan", () => {
  it("does not fetch when scanId is empty", () => {
    const { result } = renderHookWithProviders(() => useScan(""));
    expect(result.current.fetchStatus).toBe("idle");
  });

  it("polls every 3s while queued, and stops the instant status becomes terminal", async () => {
    let callCount = 0;
    server.use(
      http.get("/scans/:id", () => {
        callCount += 1;
        return HttpResponse.json(scanWithStatus(callCount < 3 ? "queued" : "completed"));
      }),
    );

    const { result } = renderHookWithProviders(() => useScan(SCAN_ID));
    await vi.waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(callCount).toBe(1);

    await pollUntil(() => expect(callCount).toBe(2));
    await pollUntil(() => expect(result.current.data?.status).toBe("completed"));
    expect(callCount).toBe(3);

    // Terminal now — no further polling, ever.
    await vi.advanceTimersByTimeAsync(30000);
    expect(callCount).toBe(3);
  });

  it("never polls a scan that is already terminal on first load", async () => {
    let callCount = 0;
    server.use(
      http.get("/scans/:id", () => {
        callCount += 1;
        return HttpResponse.json(scanWithStatus("failed"));
      }),
    );

    const { result } = renderHookWithProviders(() => useScan(SCAN_ID));
    await vi.waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(callCount).toBe(1);

    await vi.advanceTimersByTimeAsync(10000);
    expect(callCount).toBe(1);
  });
});
