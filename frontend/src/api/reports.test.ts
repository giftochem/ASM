import { beforeEach, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { createReport, downloadReport, getReport, listReports } from "./reports";
import { ForbiddenError, NotFoundError } from "./errors";

const fakeReport = {
  id: "r1111111-1111-1111-1111-111111111111",
  scan_id: "s1111111-1111-1111-1111-111111111111",
  generated_by: "u1",
  format: "json" as const,
  status: "completed" as const,
  storage_path: "/app/reports/r1.json",
  generated_at: "2026-01-01T00:00:05Z",
  error_message: null,
  created_at: "2026-01-01T00:00:00Z",
};

beforeEach(() => {
  document.cookie = "csrf_token=test-csrf-token; path=/";
});

describe("api/reports.ts — request contract", () => {
  it("listReports sends GET /reports with no query params (server has none)", async () => {
    let capturedUrl = "";
    server.use(
      http.get("/reports", ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json([fakeReport]);
      }),
    );
    await listReports();
    expect(new URL(capturedUrl).search).toBe("");
  });

  it("getReport on a cross-org id surfaces NotFoundError", async () => {
    server.use(http.get("/reports/:id", () => HttpResponse.json({ detail: "Report not found" }, { status: 404 })));
    await expect(getReport("not-mine")).rejects.toBeInstanceOf(NotFoundError);
  });

  it("createReport POSTs {scan_id, format} with the CSRF header attached", async () => {
    let capturedBody: unknown = null;
    let capturedCsrf: string | null = null;
    server.use(
      http.post("/reports", async ({ request }) => {
        capturedBody = await request.json();
        capturedCsrf = request.headers.get("X-CSRF-Token");
        return HttpResponse.json(fakeReport, { status: 201 });
      }),
    );

    await createReport({ scan_id: fakeReport.scan_id, format: "json" });

    expect(capturedBody).toEqual({ scan_id: fakeReport.scan_id, format: "json" });
    expect(capturedCsrf).toBe("test-csrf-token");
  });

  it("createReport resolves with the report already in its terminal state (no polling contract)", async () => {
    server.use(http.post("/reports", () => HttpResponse.json({ ...fakeReport, status: "completed" }, { status: 201 })));
    const result = await createReport({ scan_id: fakeReport.scan_id, format: "json" });
    expect(result.status).toBe("completed");
  });

  it("createReport surfaces a failed-generation response without throwing on the status itself (still a 201)", async () => {
    server.use(
      http.post("/reports", () =>
        HttpResponse.json({ ...fakeReport, status: "failed", error_message: "renderer crashed" }, { status: 201 }),
      ),
    );
    const result = await createReport({ scan_id: fakeReport.scan_id, format: "pdf" });
    expect(result.status).toBe("failed");
    expect(result.error_message).toBe("renderer crashed");
  });

  it("createReport surfaces a viewer's RBAC 403", async () => {
    server.use(
      http.post("/reports", () =>
        HttpResponse.json({ detail: "Requires one of roles: admin, analyst" }, { status: 403 }),
      ),
    );
    const error = await createReport({ scan_id: fakeReport.scan_id, format: "json" }).catch((e) => e);
    expect(error).toBeInstanceOf(ForbiddenError);
    expect((error as InstanceType<typeof ForbiddenError>).reason).toBe("rbac");
  });

  it("createReport surfaces a 404 for a nonexistent/cross-org scan_id", async () => {
    server.use(http.post("/reports", () => HttpResponse.json({ detail: "Scan not found" }, { status: 404 })));
    await expect(createReport({ scan_id: "not-mine", format: "json" })).rejects.toBeInstanceOf(NotFoundError);
  });

  it("downloadReport resolves with a Blob and the server-provided filename", async () => {
    server.use(
      http.get("/reports/:id/download", () =>
        new HttpResponse(new Blob(["%PDF-1.4 fake"]), {
          headers: {
            "Content-Type": "application/pdf",
            "Content-Disposition": `attachment; filename="asm-report-${fakeReport.id}.pdf"`,
          },
        }),
      ),
    );

    const result = await downloadReport(fakeReport.id);

    expect(result.filename).toBe(`asm-report-${fakeReport.id}.pdf`);
    // See the identical note in client.test.ts on this environment's
    // Blob/HttpResponse content-passthrough limitations — a non-empty
    // Blob instance is the reliable signal here, not exact byte length.
    expect(result.blob).toBeInstanceOf(Blob);
    expect(result.blob.size).toBeGreaterThan(0);
  });

  it("downloadReport surfaces a 409 when the report isn't completed yet", async () => {
    server.use(
      http.get("/reports/:id/download", () =>
        HttpResponse.json({ detail: "Report is not available for download (status: generating)" }, { status: 409 }),
      ),
    );
    await expect(downloadReport(fakeReport.id)).rejects.toMatchObject({ status: 409 });
  });

  it("downloadReport surfaces a 404 for a cross-org report id", async () => {
    server.use(http.get("/reports/:id/download", () => HttpResponse.json({ detail: "Report not found" }, { status: 404 })));
    await expect(downloadReport("not-mine")).rejects.toBeInstanceOf(NotFoundError);
  });
});
