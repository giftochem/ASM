import { describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderWithProviders } from "../test/renderWithProviders";
import { useAuth } from "../auth/useAuth";
import { OverviewPage } from "./OverviewPage";

vi.mock("../auth/useAuth");
const mockedUseAuth = vi.mocked(useAuth);

const adminUser = { id: "u1", organization_id: "org-1", role: "admin" as const };

function mockAuth() {
  mockedUseAuth.mockReturnValue({ user: adminUser as never, isLoading: false, isAuthenticated: true });
}

const emptySummary = {
  total_assets: 0,
  assets_by_type: {},
  assets_by_status: {},
  assets_by_criticality: {},
  total_relationships: 0,
  relationships_by_type: {},
  total_observations: 0,
  recent_observations_last_7_days: 0,
  isolated_asset_count: 0,
};

function mockEmptyOverview() {
  server.use(
    http.get("/assets/summary", () => HttpResponse.json(emptySummary)),
    http.get("/assets/activity", () => HttpResponse.json([])),
    http.get("/assets/prioritized", () => HttpResponse.json([])),
    http.get("/alerts", () => HttpResponse.json([])),
  );
}

describe("OverviewPage", () => {
  it("renders summary stats from GET /assets/summary", async () => {
    mockAuth();
    server.use(
      http.get("/assets/summary", () =>
        HttpResponse.json({ ...emptySummary, total_assets: 42, assets_by_type: { domain: 30, ip_address: 12 } }),
      ),
      http.get("/assets/activity", () => HttpResponse.json([])),
      http.get("/assets/prioritized", () => HttpResponse.json([])),
      http.get("/alerts", () => HttpResponse.json([])),
    );

    renderWithProviders(<OverviewPage />);

    await waitFor(() => expect(screen.getByText("42")).toBeInTheDocument());
  });

  it("shows useful empty states when there is nothing to report", async () => {
    mockAuth();
    mockEmptyOverview();

    renderWithProviders(<OverviewPage />);

    await waitFor(() => expect(screen.getByText(/no open alerts/i)).toBeInTheDocument());
    expect(screen.getByText(/no high-priority assets/i)).toBeInTheDocument();
    expect(screen.getByText(/no new assets discovered/i)).toBeInTheDocument();
    expect(screen.getByText(/no recent activity/i)).toBeInTheDocument();
  });

  it("lists open alerts and high-priority assets when present", async () => {
    mockAuth();
    server.use(
      http.get("/assets/summary", () => HttpResponse.json(emptySummary)),
      http.get("/assets/activity", () => HttpResponse.json([])),
      http.get("/assets/prioritized", () =>
        HttpResponse.json([
          {
            asset_id: "a1",
            asset_type: "domain",
            asset_value: "critical-asset.example.com",
            priority: "critical",
            confidence_label: "high",
            confidence_value: 0.9,
            dimensions: {
              exposure: "high",
              business_criticality: "critical",
              change_recency: "high",
              connectivity_relevance: "none",
              evidence_confidence: "high",
            },
            reasons: [],
            evaluated_at: "2026-01-01T00:00:00Z",
          },
        ]),
      ),
      http.get("/alerts", () =>
        HttpResponse.json([
          {
            id: "alert-1",
            organization_id: "org-1",
            asset_id: "a1",
            asset_value: "critical-asset.example.com",
            asset_type: "domain",
            relationship_id: null,
            discovery_run_id: null,
            source_observation_id: null,
            alert_type: "certificate_changed",
            priority: "high",
            title: "TLS certificate changed",
            description: "The certificate rotated.",
            evidence: null,
            status: "open",
            fingerprint: "fp",
            first_seen_at: "2026-01-01T00:00:00Z",
            last_seen_at: "2026-01-01T00:00:00Z",
            occurrence_count: 1,
            acknowledged_at: null,
            acknowledged_by: null,
            resolved_at: null,
            resolved_by: null,
            created_at: "2026-01-01T00:00:00Z",
            updated_at: "2026-01-01T00:00:00Z",
          },
        ]),
      ),
    );

    renderWithProviders(<OverviewPage />);

    await waitFor(() => expect(screen.getByText("TLS certificate changed")).toBeInTheDocument());
    expect(screen.getAllByText("critical-asset.example.com").length).toBeGreaterThan(0);
  });

  it("shows an error state for a failed sub-request without crashing the whole page", async () => {
    mockAuth();
    server.use(
      http.get("/assets/summary", () => HttpResponse.json({ detail: "Service temporarily unavailable" }, { status: 503 })),
      http.get("/assets/activity", () => HttpResponse.json([])),
      http.get("/assets/prioritized", () => HttpResponse.json([])),
      http.get("/alerts", () => HttpResponse.json([])),
    );

    renderWithProviders(<OverviewPage />);

    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
    // The rest of the page still renders despite the summary failing.
    expect(screen.getByText(/no open alerts/i)).toBeInTheDocument();
  });
});
