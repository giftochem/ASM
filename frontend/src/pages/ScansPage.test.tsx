import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes } from "react-router-dom";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderWithProviders } from "../test/renderWithProviders";
import { useAuth } from "../auth/useAuth";
import { ScansPage } from "./ScansPage";
import type { Scan } from "../api/scans";

vi.mock("../auth/useAuth");
const mockedUseAuth = vi.mocked(useAuth);

const confirmedDomain = {
  id: "asset-domain-confirmed",
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

const confirmedIp = {
  ...confirmedDomain,
  id: "asset-ip-confirmed",
  asset_type: "ip_address" as const,
  value: "203.0.113.5",
};

const unconfirmedDomain = {
  ...confirmedDomain,
  id: "asset-domain-unconfirmed",
  value: "unconfirmed.example.com",
  authorization_confirmed: false,
  authorization_confirmed_by: null,
  authorization_confirmed_at: null,
};

function fakeScan(overrides: Partial<Scan> = {}): Scan {
  return { ...baseScan, ...overrides };
}

const baseScan: Scan = {
  id: "scan-1",
  asset_id: confirmedDomain.id,
  initiated_by: "u1",
  status: "queued",
  modules_requested: ["whois"],
  started_at: null,
  completed_at: null,
  error_message: null,
  risk_score: null,
  risk_severity_band: null,
  created_at: "2026-01-01T00:00:00Z",
};

const adminUser = { id: "u1", organization_id: "org-1", role: "admin" as const };
const viewerUser = { id: "u2", organization_id: "org-1", role: "viewer" as const };

function mockAuth(user: typeof adminUser | typeof viewerUser) {
  mockedUseAuth.mockReturnValue({ user: user as never, isLoading: false, isAuthenticated: true });
}

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
});

afterEach(() => {
  vi.useRealTimers();
});

describe("ScansPage — safety-critical behavior", () => {
  it("hides the create-scan panel for a viewer but still shows the scan list (GET-only role)", async () => {
    mockAuth(viewerUser);
    server.use(
      http.get("/assets", () => HttpResponse.json([confirmedDomain])),
      http.get("/scans", () => HttpResponse.json([fakeScan()])),
    );

    renderWithProviders(<ScansPage />);

    await waitFor(() => expect(screen.getByText("whois")).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /start scan/i })).not.toBeInTheDocument();
  });

  it("only offers assets with authorization_confirmed=true in the target picker", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/assets", () => HttpResponse.json([confirmedDomain, unconfirmedDomain])),
      http.get("/scans", () => HttpResponse.json([])),
    );

    renderWithProviders(<ScansPage />);
    await waitFor(() => expect(screen.getByText(/select an asset/i)).toBeInTheDocument());

    const picker = screen.getByLabelText(/target asset/i);
    const optionValues = Array.from(picker.querySelectorAll("option")).map((o) => o.textContent);
    expect(optionValues.some((text) => text?.includes("example.com"))).toBe(true);
    expect(optionValues.some((text) => text?.includes("unconfirmed.example.com"))).toBe(false);
  });

  it("shows a guidance message with no eligible assets instead of a picker with nothing usable", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/assets", () => HttpResponse.json([unconfirmedDomain])),
      http.get("/scans", () => HttpResponse.json([])),
    );

    renderWithProviders(<ScansPage />);
    await waitFor(() => expect(screen.getByText(/no authorized assets yet/i)).toBeInTheDocument());
  });

  it("port_scanner requires an explicit acknowledgment checkbox before Start scan enables (active-scan guardrail)", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/assets", () => HttpResponse.json([confirmedIp])),
      http.get("/scans", () => HttpResponse.json([])),
    );
    const user = userEvent.setup();

    renderWithProviders(<ScansPage />);
    await waitFor(() => expect(screen.getByText(/select an asset/i)).toBeInTheDocument());

    await user.selectOptions(screen.getByLabelText(/target asset/i), confirmedIp.id);
    await user.click(screen.getByLabelText(/choose specific modules/i));
    await user.click(screen.getByLabelText(/port scan \(active\)/i));

    const startButton = screen.getByRole("button", { name: /start scan/i });
    expect(startButton).toBeDisabled();

    await user.click(screen.getByLabelText(/i understand port scanning/i));
    expect(startButton).not.toBeDisabled();
  });

  it("the default 'standard modules' submission omits `modules` entirely — never silently includes port_scanner", async () => {
    mockAuth(adminUser);
    let capturedBody: unknown = null;
    server.use(
      http.get("/assets", () => HttpResponse.json([confirmedIp])),
      http.get("/scans", () => HttpResponse.json([])),
      http.post("/scans", async ({ request }) => {
        capturedBody = await request.json();
        return HttpResponse.json(fakeScan({ id: "new-scan-id" }), { status: 201 });
      }),
    );
    const user = userEvent.setup();

    renderWithProviders(<ScansPage />);
    await waitFor(() => expect(screen.getByText(/select an asset/i)).toBeInTheDocument());

    await user.selectOptions(screen.getByLabelText(/target asset/i), confirmedIp.id);
    await user.click(screen.getByRole("button", { name: /start scan/i }));

    await waitFor(() => expect(capturedBody).not.toBeNull());
    expect(capturedBody).toEqual({ asset_id: confirmedIp.id });
    expect((capturedBody as { modules?: unknown }).modules).toBeUndefined();
  });

  it("switching the target asset clears any prior module selection", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/assets", () => HttpResponse.json([confirmedDomain, confirmedIp])),
      http.get("/scans", () => HttpResponse.json([])),
    );
    const user = userEvent.setup();

    renderWithProviders(<ScansPage />);
    await waitFor(() => expect(screen.getByText(/select an asset/i)).toBeInTheDocument());

    await user.selectOptions(screen.getByLabelText(/target asset/i), confirmedIp.id);
    await user.click(screen.getByLabelText(/choose specific modules/i));
    await user.click(screen.getByLabelText(/port scan \(active\)/i));
    expect(screen.getByLabelText(/port scan \(active\)/i)).toBeChecked();

    await user.selectOptions(screen.getByLabelText(/target asset/i), confirmedDomain.id);

    // Back to the default mode, and port_scanner isn't even offered for domain.
    expect(screen.getByLabelText(/run all standard modules/i)).toBeChecked();
    expect(screen.queryByLabelText(/port scan \(active\)/i)).not.toBeInTheDocument();
  });

  it("warns (without blocking) when a scan is already queued/running for the selected asset", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/assets", () => HttpResponse.json([confirmedDomain])),
      http.get("/scans", () => HttpResponse.json([fakeScan({ status: "running" })])),
    );
    const user = userEvent.setup();

    renderWithProviders(<ScansPage />);
    await waitFor(() => expect(screen.getByText(/select an asset/i)).toBeInTheDocument());

    await user.selectOptions(screen.getByLabelText(/target asset/i), confirmedDomain.id);

    await waitFor(() => expect(screen.getByText(/already queued or running/i)).toBeInTheDocument());
    expect(screen.getByRole("button", { name: /start scan/i })).not.toBeDisabled();
  });

  it("navigates to the new scan's detail page on successful creation", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/assets", () => HttpResponse.json([confirmedDomain])),
      http.get("/scans", () => HttpResponse.json([])),
      http.post("/scans", () => HttpResponse.json(fakeScan({ id: "brand-new-scan" }), { status: 201 })),
    );
    const user = userEvent.setup();

    renderWithProviders(
      <Routes>
        <Route path="/scans" element={<ScansPage />} />
        <Route path="/scans/:scanId" element={<div>Scan detail placeholder</div>} />
      </Routes>,
      { route: "/scans" },
    );
    await waitFor(() => expect(screen.getByText(/select an asset/i)).toBeInTheDocument());

    await user.selectOptions(screen.getByLabelText(/target asset/i), confirmedDomain.id);
    await user.click(screen.getByRole("button", { name: /start scan/i }));

    await waitFor(() => expect(screen.getByText(/scan detail placeholder/i)).toBeInTheDocument());
  });

  it("filters the visible scan list by status, client-side", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/assets", () => HttpResponse.json([confirmedDomain])),
      http.get("/scans", () =>
        HttpResponse.json([fakeScan({ id: "s-queued", status: "queued" }), fakeScan({ id: "s-done", status: "completed" })]),
      ),
    );
    const user = userEvent.setup();

    renderWithProviders(<ScansPage />);
    await waitFor(() => expect(screen.getAllByText("whois")).toHaveLength(2));

    await user.selectOptions(screen.getByDisplayValue("All statuses"), "completed");
    expect(screen.getAllByText("whois")).toHaveLength(1);
  });

  it("shows an error state on a backend failure instead of crashing", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/assets", () => HttpResponse.json([])),
      http.get("/scans", () => HttpResponse.json({ detail: "Service temporarily unavailable" }, { status: 503 })),
    );

    renderWithProviders(<ScansPage />);
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
  });

  it("never issues a POST while merely viewing the page, even while polling advances (no accidental scan execution)", async () => {
    mockAuth(viewerUser);
    // No POST /scans handler registered at all — MSW's onUnhandledRequest:
    // 'error' (test/setup.ts) means any POST here fails the test loudly.
    server.use(http.get("/assets", () => HttpResponse.json([])), http.get("/scans", () => HttpResponse.json([fakeScan()])));

    renderWithProviders(<ScansPage />);
    await waitFor(() => expect(screen.getByText("whois")).toBeInTheDocument());

    await vi.advanceTimersByTimeAsync(30000);
  });
});
