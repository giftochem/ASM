import { describe, expect, it } from "vitest";
import { act, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderHookWithProviders } from "../test/renderWithProviders";
import { useReports } from "./useReports";
import { useCreateReport } from "./useCreateReport";

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

function useComposite() {
  return { list: useReports(), create: useCreateReport() };
}

describe("useCreateReport", () => {
  it("invalidates and refetches the report list on success", async () => {
    let listCallCount = 0;
    server.use(
      http.get("/reports", () => {
        listCallCount += 1;
        return HttpResponse.json(listCallCount === 1 ? [] : [fakeReport]);
      }),
      http.post("/reports", () => HttpResponse.json(fakeReport, { status: 201 })),
    );

    const { result } = renderHookWithProviders(() => useComposite());
    await waitFor(() => expect(result.current.list.data).toEqual([]));

    await act(async () => {
      await result.current.create.mutateAsync({ scan_id: fakeReport.scan_id, format: "json" });
    });

    await waitFor(() => expect(result.current.list.data).toEqual([fakeReport]));
    expect(listCallCount).toBe(2);
  });

  it("surfaces a 404 for an unknown scan_id without touching the cached list", async () => {
    server.use(
      http.get("/reports", () => HttpResponse.json([])),
      http.post("/reports", () => HttpResponse.json({ detail: "Scan not found" }, { status: 404 })),
    );

    const { result } = renderHookWithProviders(() => useComposite());
    await waitFor(() => expect(result.current.list.isSuccess).toBe(true));

    await act(async () => {
      await expect(
        result.current.create.mutateAsync({ scan_id: "nope", format: "json" }),
      ).rejects.toMatchObject({ name: "NotFoundError" });
    });

    expect(result.current.list.data).toEqual([]);
  });
});
