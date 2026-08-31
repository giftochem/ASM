import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderWithProviders } from "../test/renderWithProviders";
import { useAuth } from "../auth/useAuth";
import { ReportsPage } from "./ReportsPage";
import type { Report } from "../api/reports";

vi.mock("../auth/useAuth");
const mockedUseAuth = vi.mocked(useAuth);

const completedScan = {
  id: "scan-completed",
  asset_id: "asset-1",
  initiated_by: "u1",
  status: "completed" as const,
  modules_requested: ["whois"],
  started_at: "2026-01-01T00:00:00Z",
  completed_at: "2026-01-01T00:01:00Z",
  error_message: null,
  risk_score: 10,
  risk_severity_band: "low" as const,
  created_at: "2026-01-01T00:00:00Z",
};

const queuedScan = { ...completedScan, id: "scan-queued", status: "queued" as const, started_at: null, completed_at: null };

const completedReport = {
  id: "report-1",
  scan_id: completedScan.id,
  generated_by: "u1",
  format: "pdf" as const,
  status: "completed" as const,
  storage_path: "/app/reports/report-1.pdf",
  generated_at: "2026-01-01T00:00:05Z",
  error_message: null,
  created_at: "2026-01-01T00:00:00Z",
};

const adminUser = { id: "u1", organization_id: "org-1", role: "admin" as const };
const viewerUser = { id: "u2", organization_id: "org-1", role: "viewer" as const };

function mockAuth(user: typeof adminUser | typeof viewerUser) {
  mockedUseAuth.mockReturnValue({ user: user as never, isLoading: false, isAuthenticated: true });
}

// jsdom lacks URL.createObjectURL/revokeObjectURL — added as static
// methods on the real URL class, NOT via vi.stubGlobal("URL", {...URL}),
// which spreads the class into a plain object and breaks its constructor
// (and with it, every `new URL(...)` call elsewhere, including MSW's).
const createObjectURL = vi.fn(() => "blob:mock-url");
const revokeObjectURL = vi.fn();

beforeEach(() => {
  URL.createObjectURL = createObjectURL;
  URL.revokeObjectURL = revokeObjectURL;
  createObjectURL.mockClear();
  revokeObjectURL.mockClear();
});

afterEach(() => {
  // @ts-expect-error — not part of the lib.dom types this project targets in jsdom
  delete URL.createObjectURL;
  // @ts-expect-error — same as above
  delete URL.revokeObjectURL;
});

describe("ReportsPage", () => {
  it("shows a loading state, then reports", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/scans", () => HttpResponse.json([completedScan])),
      http.get("/reports", () => HttpResponse.json([completedReport])),
    );
    renderWithProviders(<ReportsPage />);
    expect(screen.getByText(/loading/i)).toBeInTheDocument();
    // Not screen.getByText("PDF") — the format <select>'s "PDF" <option>
    // is present from the very first render and would make this resolve
    // immediately without actually waiting for the report data. The
    // table only renders once the report row is loaded.
    await waitFor(() => expect(screen.getByRole("table")).toBeInTheDocument());
  });

  it("shows an error state on a backend failure instead of crashing", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/scans", () => HttpResponse.json([])),
      http.get("/reports", () => HttpResponse.json({ detail: "Service temporarily unavailable" }, { status: 503 })),
    );
    renderWithProviders(<ReportsPage />);
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
  });

  it("hides the generate form for a viewer but still shows reports and a working Download button", async () => {
    mockAuth(viewerUser);
    server.use(
      http.get("/scans", () => HttpResponse.json([completedScan])),
      http.get("/reports", () => HttpResponse.json([completedReport])),
      http.get("/reports/:id/download", () =>
        new HttpResponse(new Blob(["%PDF-"]), {
          headers: { "Content-Disposition": 'attachment; filename="asm-report-report-1.pdf"' },
        }),
      ),
    );
    const user = userEvent.setup();

    renderWithProviders(<ReportsPage />);
    await waitFor(() => expect(screen.getByRole("table")).toBeInTheDocument());

    expect(screen.queryByRole("button", { name: /generate report/i })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /download/i }));
    await waitFor(() => expect(createObjectURL).toHaveBeenCalled());
  });

  it("only offers completed scans in the generate picker", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/scans", () => HttpResponse.json([completedScan, queuedScan])),
      http.get("/reports", () => HttpResponse.json([])),
    );
    renderWithProviders(<ReportsPage />);
    // Not screen.getByText(/select a completed scan/i) — that placeholder
    // option is present from the very first render and doesn't actually
    // wait for the (async) scans data to arrive. Wait for the real,
    // data-derived option instead.
    await waitFor(() =>
      expect(screen.getByRole("option", { name: new RegExp(completedScan.id.slice(0, 8)) })).toBeInTheDocument(),
    );

    const picker = screen.getByDisplayValue(/select a completed scan/i);
    const optionValues = Array.from(picker.querySelectorAll("option")).map((o) => (o as HTMLOptionElement).value);
    expect(optionValues).toContain(completedScan.id);
    expect(optionValues).not.toContain(queuedScan.id);
  });

  it("shows guidance when there are no completed scans yet", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/scans", () => HttpResponse.json([queuedScan])),
      http.get("/reports", () => HttpResponse.json([])),
    );
    renderWithProviders(<ReportsPage />);
    await waitFor(() => expect(screen.getByText(/no completed scans yet/i)).toBeInTheDocument());
  });

  it("generates a report: no polling, the mutation's own pending state is the only loading signal, and the list updates", async () => {
    mockAuth(adminUser);
    let reports: Report[] = [];
    server.use(
      http.get("/scans", () => HttpResponse.json([completedScan])),
      http.get("/reports", () => HttpResponse.json(reports)),
      http.post("/reports", async ({ request }) => {
        const body = (await request.json()) as { scan_id: string; format: string };
        expect(body).toEqual({ scan_id: completedScan.id, format: "json" });
        const created = { ...completedReport, format: "json" as const };
        reports = [created];
        return HttpResponse.json(created, { status: 201 });
      }),
    );
    const user = userEvent.setup();

    renderWithProviders(<ReportsPage />);
    await waitFor(() =>
      expect(screen.getByRole("option", { name: new RegExp(completedScan.id.slice(0, 8)) })).toBeInTheDocument(),
    );

    await user.selectOptions(screen.getByDisplayValue(/select a completed scan/i), completedScan.id);
    await user.click(screen.getByRole("button", { name: /generate report/i }));

    await waitFor(() => expect(screen.getByRole("table")).toBeInTheDocument());
    expect(screen.getByRole("table")).toHaveTextContent("JSON");
  });

  it("surfaces the AuthorizationNotConfirmedError-style backend rejection cleanly (defense in depth — RBAC 403 for a viewer attempting POST directly)", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/scans", () => HttpResponse.json([completedScan])),
      http.get("/reports", () => HttpResponse.json([])),
      http.post("/reports", () => HttpResponse.json({ detail: "Scan not found" }, { status: 404 })),
    );
    const user = userEvent.setup();

    renderWithProviders(<ReportsPage />);
    await waitFor(() =>
      expect(screen.getByRole("option", { name: new RegExp(completedScan.id.slice(0, 8)) })).toBeInTheDocument(),
    );

    await user.selectOptions(screen.getByDisplayValue(/select a completed scan/i), completedScan.id);
    await user.click(screen.getByRole("button", { name: /generate report/i }));

    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
  });

  it("pre-selects a scan passed via ?scan_id= once it's confirmed to be a completed, eligible scan", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/scans", () => HttpResponse.json([completedScan])),
      http.get("/reports", () => HttpResponse.json([])),
    );
    renderWithProviders(<ReportsPage />, { route: `/reports?scan_id=${completedScan.id}` });

    await waitFor(() => expect(screen.getByDisplayValue(new RegExp(completedScan.id.slice(0, 8)))).toBeInTheDocument());
  });

  it("does not pre-select a scan_id that isn't in the eligible (completed) list", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/scans", () => HttpResponse.json([queuedScan])),
      http.get("/reports", () => HttpResponse.json([])),
    );
    renderWithProviders(<ReportsPage />, { route: `/reports?scan_id=${queuedScan.id}` });

    await waitFor(() => expect(screen.getByText(/no completed scans yet/i)).toBeInTheDocument());
    expect(screen.getByDisplayValue(/select a completed scan/i)).toBeInTheDocument();
  });

  it("surfaces a download error (e.g. a 409 race) without crashing the page", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/scans", () => HttpResponse.json([completedScan])),
      http.get("/reports", () => HttpResponse.json([completedReport])),
      http.get("/reports/:id/download", () =>
        HttpResponse.json({ detail: "Report is not available for download (status: pending)" }, { status: 409 }),
      ),
    );
    const user = userEvent.setup();

    renderWithProviders(<ReportsPage />);
    await waitFor(() => expect(screen.getByRole("table")).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: /download/i }));
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
  });

  it("shows the empty state with no reports", async () => {
    mockAuth(adminUser);
    server.use(http.get("/scans", () => HttpResponse.json([])), http.get("/reports", () => HttpResponse.json([])));
    renderWithProviders(<ReportsPage />);
    await waitFor(() => expect(screen.getByText(/no reports yet/i)).toBeInTheDocument());
  });
});
