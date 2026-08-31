import { describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderWithProviders } from "../test/renderWithProviders";
import { useAuth } from "../auth/useAuth";
import { AlertsPage } from "./AlertsPage";
import type { Alert } from "../api/alerts";

vi.mock("../auth/useAuth");
const mockedUseAuth = vi.mocked(useAuth);

const adminUser = { id: "u1", organization_id: "org-1", role: "admin" as const };
const viewerUser = { id: "u2", organization_id: "org-1", role: "viewer" as const };

function mockAuth(user: typeof adminUser | typeof viewerUser) {
  mockedUseAuth.mockReturnValue({ user: user as never, isLoading: false, isAuthenticated: true });
}

function fakeAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: "alert-1",
    organization_id: "org-1",
    asset_id: "a1",
    asset_value: "example.com",
    asset_type: "domain",
    relationship_id: null,
    discovery_run_id: null,
    source_observation_id: null,
    alert_type: "certificate_changed",
    priority: "high",
    title: "TLS certificate changed for example.com",
    description: "The certificate rotated.",
    // openapi-typescript infers a bare `dict` schema as Record<string,
    // never> (no value type info in the OpenAPI schema) -- cast needed
    // for this fixture only; MSW serializes the real object regardless.
    evidence: { slot: "example.com:443" } as unknown as Alert["evidence"],
    status: "open",
    fingerprint: "fp-1",
    first_seen_at: "2026-01-01T00:00:00Z",
    last_seen_at: "2026-01-02T00:00:00Z",
    occurrence_count: 2,
    acknowledged_at: null,
    acknowledged_by: null,
    resolved_at: null,
    resolved_by: null,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-02T00:00:00Z",
    ...overrides,
  };
}

describe("AlertsPage", () => {
  it("shows a loading state, then the org's open alerts by default", async () => {
    mockAuth(adminUser);
    server.use(http.get("/alerts", () => HttpResponse.json([fakeAlert()])));

    renderWithProviders(<AlertsPage />);

    expect(screen.getByText(/loading/i)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("TLS certificate changed for example.com")).toBeInTheDocument());
  });

  it("requests only 'open' alerts by default via the status query parameter", async () => {
    mockAuth(adminUser);
    let capturedStatuses: string[] = [];
    server.use(
      http.get("/alerts", ({ request }) => {
        capturedStatuses = new URL(request.url).searchParams.getAll("status");
        return HttpResponse.json([fakeAlert()]);
      }),
    );

    renderWithProviders(<AlertsPage />);

    await waitFor(() => expect(capturedStatuses).toEqual(["open"]));
  });

  it("shows an empty state and an error state without crashing", async () => {
    mockAuth(adminUser);
    server.use(http.get("/alerts", () => HttpResponse.json([])));
    renderWithProviders(<AlertsPage />);
    await waitFor(() => expect(screen.getByText(/no alerts match this filter/i)).toBeInTheDocument());
  });

  it("shows an error state on failure instead of crashing", async () => {
    mockAuth(adminUser);
    server.use(http.get("/alerts", () => HttpResponse.json({ detail: "boom" }, { status: 500 })));
    renderWithProviders(<AlertsPage />);
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
  });

  it("opens a detail modal on row click showing evidence, and lets admin/analyst acknowledge then resolve", async () => {
    mockAuth(adminUser);
    let currentAlert = fakeAlert();
    server.use(
      http.get("/alerts", () => HttpResponse.json([currentAlert])),
      http.post("/alerts/:id/acknowledge", () => {
        currentAlert = { ...currentAlert, status: "acknowledged", acknowledged_at: "2026-01-03T00:00:00Z", acknowledged_by: "u1" };
        return HttpResponse.json(currentAlert);
      }),
      http.post("/alerts/:id/resolve", () => {
        currentAlert = { ...currentAlert, status: "resolved", resolved_at: "2026-01-04T00:00:00Z", resolved_by: "u1" };
        return HttpResponse.json(currentAlert);
      }),
    );
    const user = userEvent.setup();

    renderWithProviders(<AlertsPage />);
    await waitFor(() => expect(screen.getByText("TLS certificate changed for example.com")).toBeInTheDocument());

    await user.click(screen.getByText("TLS certificate changed for example.com"));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("The certificate rotated.")).toBeInTheDocument();

    await user.click(within(dialog).getByText(/evidence/i));
    expect(within(dialog).getByText(/example\.com:443/)).toBeInTheDocument();

    await user.click(within(dialog).getByRole("button", { name: /^acknowledge$/i }));
    await waitFor(() => expect(within(screen.getByRole("dialog")).getByText("acknowledged")).toBeInTheDocument());

    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: /^resolve$/i }));
    await waitFor(() => expect(within(screen.getByRole("dialog")).getByText("resolved")).toBeInTheDocument());
  });

  it("hides acknowledge/resolve actions for a viewer (RBAC visibility — UX guard only)", async () => {
    mockAuth(viewerUser);
    server.use(http.get("/alerts", () => HttpResponse.json([fakeAlert()])));
    const user = userEvent.setup();

    renderWithProviders(<AlertsPage />);
    await waitFor(() => expect(screen.getByText("TLS certificate changed for example.com")).toBeInTheDocument());

    await user.click(screen.getByText("TLS certificate changed for example.com"));
    const dialog = await screen.findByRole("dialog");

    expect(within(dialog).queryByRole("button", { name: /^acknowledge$/i })).not.toBeInTheDocument();
    expect(within(dialog).queryByRole("button", { name: /^resolve$/i })).not.toBeInTheDocument();
  });

  it("does not offer 'acknowledge' for an alert that is already acknowledged", async () => {
    mockAuth(adminUser);
    server.use(http.get("/alerts", () => HttpResponse.json([fakeAlert({ status: "acknowledged" })])));
    const user = userEvent.setup();

    renderWithProviders(<AlertsPage />);
    await waitFor(() => expect(screen.getByText("TLS certificate changed for example.com")).toBeInTheDocument());
    await user.click(screen.getByText("TLS certificate changed for example.com"));
    const dialog = await screen.findByRole("dialog");

    expect(within(dialog).queryByRole("button", { name: /^acknowledge$/i })).not.toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: /^resolve$/i })).toBeInTheDocument();
  });

  it("surfaces an acknowledge failure via ApiErrorAlert without closing the modal", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/alerts", () => HttpResponse.json([fakeAlert()])),
      http.post("/alerts/:id/acknowledge", () => HttpResponse.json({ detail: "Alert is not open" }, { status: 400 })),
    );
    const user = userEvent.setup();

    renderWithProviders(<AlertsPage />);
    await waitFor(() => expect(screen.getByText("TLS certificate changed for example.com")).toBeInTheDocument());
    await user.click(screen.getByText("TLS certificate changed for example.com"));
    const dialog = await screen.findByRole("dialog");

    await user.click(within(dialog).getByRole("button", { name: /^acknowledge$/i }));

    await waitFor(() => expect(within(screen.getByRole("dialog")).getByText("Alert is not open")).toBeInTheDocument());
  });
});
