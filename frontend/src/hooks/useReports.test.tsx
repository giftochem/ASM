import { describe, expect, it } from "vitest";
import { waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderHookWithProviders } from "../test/renderWithProviders";
import { useReports } from "./useReports";

const fakeReport = {
  id: "r1",
  scan_id: "s1",
  generated_by: "u1",
  format: "json" as const,
  status: "completed" as const,
  storage_path: "/app/reports/r1.json",
  generated_at: "2026-01-01T00:00:05Z",
  error_message: null,
  created_at: "2026-01-01T00:00:00Z",
};

describe("useReports", () => {
  it("resolves with the org's report list", async () => {
    server.use(http.get("/reports", () => HttpResponse.json([fakeReport])));
    const { result } = renderHookWithProviders(() => useReports());
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([fakeReport]);
  });

  it("surfaces an error state without crashing", async () => {
    server.use(http.get("/reports", () => HttpResponse.json({ detail: "Service temporarily unavailable" }, { status: 503 })));
    const { result } = renderHookWithProviders(() => useReports());
    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
