import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes } from "react-router-dom";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderWithProviders } from "../test/renderWithProviders";
import { useAuth } from "../auth/useAuth";
import { ScanDetailPage } from "./ScanDetailPage";
import type { ScanResult } from "../api/scans";

vi.mock("../auth/useAuth");
const mockedUseAuth = vi.mocked(useAuth);

const SCAN_ID = "s1111111-1111-1111-1111-111111111111";
const ASSET_ID = "a1111111-1111-1111-1111-111111111111";

const confirmedAsset = {
  id: ASSET_ID,
  organization_id: "org-1",
  asset_type: "domain" as const,
  value: "example.com",
  parent_asset_id: null,
  authorization_confirmed: true,
  authorization_confirmed_by: "u1",
  authorization_confirmed_at: "2026-01-01T00:00:00Z",
  notes: null,
  is_active: true,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

function scanFixture(overrides: Partial<ScanResult> = {}): ScanResult {
  return { ...baseScan(), ...overrides };
}

function baseScan(): ScanResult {
  return {
    id: SCAN_ID,
    asset_id: ASSET_ID,
    initiated_by: "u1",
    status: "queued",
    modules_requested: ["whois", "dns"],
    started_at: null,
    completed_at: null,
    error_message: null,
    risk_score: null,
    risk_severity_band: null,
    created_at: "2026-01-01T00:00:00Z",
    findings: [],
  };
}

const adminUser = { id: "u1", organization_id: "org-1", role: "admin" as const };
const viewerUser = { id: "u2", organization_id: "org-1", role: "viewer" as const };

function mockAuth(user: typeof adminUser | typeof viewerUser) {
  mockedUseAuth.mockReturnValue({ user: user as never, isLoading: false, isAuthenticated: true });
}

function renderDetail() {
  return renderWithProviders(
    <Routes>
      <Route path="/scans/:scanId" element={<ScanDetailPage />} />
    </Routes>,
    { route: `/scans/${SCAN_ID}` },
  );
}

// jsdom lacks URL.createObjectURL/revokeObjectURL — added as static
// methods on the real URL class, NOT via vi.stubGlobal("URL", {...URL}),
// which spreads the class into a plain object and breaks its constructor
// (and with it, every `new URL(...)` call elsewhere, including MSW's).
const createObjectURL = vi.fn(() => "blob:mock-url");
const revokeObjectURL = vi.fn();

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  URL.createObjectURL = createObjectURL;
  URL.revokeObjectURL = revokeObjectURL;
  createObjectURL.mockClear();
  revokeObjectURL.mockClear();
  server.use(
    http.get("/assets/:id", () => HttpResponse.json(confirmedAsset)),
    // ScanDetailPage now also fetches the org's reports (Step 5 addition,
    // client-side filtered to this scan) — default to empty so every
    // pre-existing test keeps working; reports-specific tests below
    // override this with real data via server.use().
    http.get("/reports", () => HttpResponse.json([])),
  );
});

afterEach(() => {
  vi.useRealTimers();
  // @ts-expect-error — not part of the lib.dom types this project targets in jsdom
  delete URL.createObjectURL;
  // @ts-expect-error — same as above
  delete URL.revokeObjectURL;
});

describe("ScanDetailPage", () => {
  it("shows a loading state, then the scan", async () => {
    mockAuth(adminUser);
    server.use(http.get("/scans/:id", () => HttpResponse.json(scanFixture())));

    renderDetail();

    expect(screen.getByText(/loading scan/i)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("queued")).toBeInTheDocument());
  });

  it("shows a not-found state for a nonexistent/cross-org scan id", async () => {
    mockAuth(adminUser);
    server.use(http.get("/scans/:id", () => HttpResponse.json({ detail: "Scan not found" }, { status: 404 })));

    renderDetail();

    await waitFor(() => expect(screen.getByText(/scan not found/i)).toBeInTheDocument());
  });

  it("shows a generic error state without crashing", async () => {
    mockAuth(adminUser);
    server.use(http.get("/scans/:id", () => HttpResponse.json({ detail: "Service temporarily unavailable" }, { status: 503 })));

    renderDetail();

    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
  });

  it("shows Cancel for admin/analyst while queued, and hides it for viewer", async () => {
    mockAuth(adminUser);
    server.use(http.get("/scans/:id", () => HttpResponse.json(scanFixture())));
    renderDetail();
    await waitFor(() => expect(screen.getByRole("button", { name: /cancel scan/i })).toBeInTheDocument());
  });

  it("hides Cancel for a viewer even on a queued scan", async () => {
    mockAuth(viewerUser);
    server.use(http.get("/scans/:id", () => HttpResponse.json(scanFixture())));
    renderDetail();
    await waitFor(() => expect(screen.getByText("queued")).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /cancel scan/i })).not.toBeInTheDocument();
  });

  it("hides Cancel once the scan is running (only queued is cancelable server-side)", async () => {
    mockAuth(adminUser);
    server.use(http.get("/scans/:id", () => HttpResponse.json(scanFixture({ status: "running" }))));
    renderDetail();
    await waitFor(() => expect(screen.getByText("running")).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /cancel scan/i })).not.toBeInTheDocument();
  });

  it("runs the cancel flow and reflects the new status", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/scans/:id", () => HttpResponse.json(scanFixture())),
      http.post("/scans/:id/cancel", () => HttpResponse.json({ ...scanFixture(), status: "cancelled" })),
    );
    const user = userEvent.setup();

    renderDetail();
    await waitFor(() => expect(screen.getByRole("button", { name: /cancel scan/i })).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: /cancel scan/i }));

    await waitFor(() => expect(screen.getByText("cancelled")).toBeInTheDocument());
  });

  it("surfaces a 409 when cancel races a worker that already started the scan", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/scans/:id", () => HttpResponse.json(scanFixture())),
      http.post("/scans/:id/cancel", () =>
        HttpResponse.json({ detail: "cannot cancel a scan in status 'running'" }, { status: 409 }),
      ),
    );
    const user = userEvent.setup();

    renderDetail();
    await waitFor(() => expect(screen.getByRole("button", { name: /cancel scan/i })).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: /cancel scan/i }));

    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
  });

  it("shows the error_message for a failed scan", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/scans/:id", () =>
        HttpResponse.json(scanFixture({ status: "failed", error_message: "whois: unexpected error" })),
      ),
    );
    renderDetail();
    await waitFor(() => expect(screen.getByText("whois: unexpected error")).toBeInTheDocument());
  });

  it("renders findings with severity badges for a completed scan", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/scans/:id", () =>
        HttpResponse.json(
          scanFixture({
            status: "completed",
            findings: [
              {
                id: "f1",
                scan_id: SCAN_ID,
                asset_id: ASSET_ID,
                module: "whois",
                title: "Registrar found",
                description: null,
                severity: "info",
                confidence: 1,
                exposure: 1,
                exploitability: 0.5,
                evidence: null,
                created_at: "2026-01-01T00:00:00Z",
              },
            ],
          }),
        ),
      ),
    );
    renderDetail();
    await waitFor(() => expect(screen.getByText("Registrar found")).toBeInTheDocument());
    expect(screen.getByText("info")).toBeInTheDocument();
  });

  it("shows the revoked-authorization warning only once the asset is confirmed to be unauthorized (not during load)", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/scans/:id", () => HttpResponse.json(scanFixture({ status: "running" }))),
      http.get("/assets/:id", () => HttpResponse.json({ ...confirmedAsset, authorization_confirmed: false })),
    );
    renderDetail();

    await waitFor(() => expect(screen.getByText(/authorization has been revoked/i)).toBeInTheDocument());
  });

  it("does not show the revoked-authorization warning when the asset is still authorized", async () => {
    mockAuth(adminUser);
    server.use(http.get("/scans/:id", () => HttpResponse.json(scanFixture({ status: "running" }))));
    renderDetail();

    await waitFor(() => expect(screen.getByText("running")).toBeInTheDocument());
    expect(screen.queryByText(/authorization has been revoked/i)).not.toBeInTheDocument();
  });

  it("polls a queued scan and stops once it reaches a terminal state (no fetches after that)", async () => {
    mockAuth(adminUser);
    let callCount = 0;
    server.use(
      http.get("/scans/:id", () => {
        callCount += 1;
        return HttpResponse.json(scanFixture({ status: callCount < 2 ? "queued" : "completed" }));
      }),
    );

    renderDetail();
    await waitFor(() => expect(screen.getByText("queued")).toBeInTheDocument());
    expect(callCount).toBe(1);

    await vi.advanceTimersByTimeAsync(3000);
    await waitFor(() => expect(screen.getByText("completed")).toBeInTheDocument());
    expect(callCount).toBe(2);

    await vi.advanceTimersByTimeAsync(30000);
    expect(callCount).toBe(2);
  });

  it("never issues a POST while merely viewing a queued scan, even as polling advances", async () => {
    mockAuth(viewerUser);
    // No POST handlers registered — an accidental POST fails via MSW's
    // onUnhandledRequest: 'error'.
    server.use(http.get("/scans/:id", () => HttpResponse.json(scanFixture())));

    renderDetail();
    await waitFor(() => expect(screen.getByText("queued")).toBeInTheDocument());

    await vi.advanceTimersByTimeAsync(15000);
  });

  describe("reports section", () => {
    const completedScan = scanFixture({ status: "completed" });
    const report = {
      id: "report-1",
      scan_id: SCAN_ID,
      generated_by: "u1",
      format: "pdf" as const,
      status: "completed" as const,
      storage_path: "/app/reports/report-1.pdf",
      generated_at: "2026-01-01T00:00:05Z",
      error_message: null,
      created_at: "2026-01-01T00:00:00Z",
    };
    const otherScanReport = { ...report, id: "report-other", scan_id: "some-other-scan-id" };

    it("shows an empty state when there are no reports for this scan", async () => {
      mockAuth(adminUser);
      server.use(http.get("/scans/:id", () => HttpResponse.json(scanFixture())));
      renderDetail();
      await waitFor(() => expect(screen.getByText(/no reports yet for this scan/i)).toBeInTheDocument());
    });

    it("only shows reports whose scan_id matches this scan (client-side filter correctness)", async () => {
      mockAuth(adminUser);
      server.use(
        http.get("/scans/:id", () => HttpResponse.json(completedScan)),
        http.get("/reports", () => HttpResponse.json([report, otherScanReport])),
      );
      renderDetail();
      await waitFor(() => expect(screen.getByText("PDF")).toBeInTheDocument());
      // Only one row rendered, not two — the other scan's report must not leak in.
      expect(screen.getAllByText("PDF")).toHaveLength(1);
    });

    it("shows a 'Generate report' link only for admin/analyst on a completed scan", async () => {
      mockAuth(adminUser);
      server.use(http.get("/scans/:id", () => HttpResponse.json(completedScan)));
      renderDetail();
      await waitFor(() => expect(screen.getByText("completed")).toBeInTheDocument());
      expect(screen.getByRole("link", { name: /generate report/i })).toHaveAttribute(
        "href",
        `/reports?scan_id=${SCAN_ID}`,
      );
    });

    it("hides the 'Generate report' link for a viewer", async () => {
      mockAuth(viewerUser);
      server.use(http.get("/scans/:id", () => HttpResponse.json(completedScan)));
      renderDetail();
      await waitFor(() => expect(screen.getByText("completed")).toBeInTheDocument());
      expect(screen.queryByRole("link", { name: /generate report/i })).not.toBeInTheDocument();
    });

    it("hides the 'Generate report' link while the scan isn't completed yet", async () => {
      mockAuth(adminUser);
      server.use(http.get("/scans/:id", () => HttpResponse.json(scanFixture({ status: "running" }))));
      renderDetail();
      await waitFor(() => expect(screen.getByText("running")).toBeInTheDocument());
      expect(screen.queryByRole("link", { name: /generate report/i })).not.toBeInTheDocument();
    });

    it("downloads a report from the scan detail page", async () => {
      mockAuth(adminUser);
      server.use(
        http.get("/scans/:id", () => HttpResponse.json(completedScan)),
        http.get("/reports", () => HttpResponse.json([report])),
        http.get("/reports/:id/download", () =>
          new HttpResponse(new Blob(["%PDF-"]), {
            headers: { "Content-Disposition": 'attachment; filename="asm-report-report-1.pdf"' },
          }),
        ),
      );
      const user = userEvent.setup();

      renderDetail();
      await waitFor(() => expect(screen.getByText("PDF")).toBeInTheDocument());

      await user.click(screen.getByRole("button", { name: /download/i }));
      await waitFor(() => expect(createObjectURL).toHaveBeenCalled());
    });

    it("shows a pending/failed report without a download button", async () => {
      mockAuth(adminUser);
      server.use(
        http.get("/scans/:id", () => HttpResponse.json(completedScan)),
        http.get("/reports", () => HttpResponse.json([{ ...report, status: "failed", error_message: "renderer crashed" }])),
      );
      renderDetail();
      await waitFor(() => expect(screen.getByText("renderer crashed")).toBeInTheDocument());
      expect(screen.queryByRole("button", { name: /download/i })).not.toBeInTheDocument();
    });
  });
});
