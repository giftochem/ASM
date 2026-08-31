import { describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderWithProviders } from "../test/renderWithProviders";
import { useAuth } from "../auth/useAuth";
import { PrioritizedAssetsPage } from "./PrioritizedAssetsPage";

vi.mock("../auth/useAuth");
const mockedUseAuth = vi.mocked(useAuth);

function mockAuth() {
  mockedUseAuth.mockReturnValue({
    user: { id: "u1", organization_id: "org-1", role: "admin" } as never,
    isLoading: false,
    isAuthenticated: true,
  });
}

function fakeResult(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    asset_id: "a1",
    asset_type: "domain",
    asset_value: "example.com",
    priority: "high",
    confidence_label: "medium",
    confidence_value: 0.7,
    dimensions: {
      exposure: "high",
      business_criticality: "unknown",
      change_recency: "high",
      connectivity_relevance: "none",
      evidence_confidence: "medium",
    },
    reasons: [{ signal: "http_exposed", impact: "high", description: "Asset responds to HTTP/HTTPS requests" }],
    evaluated_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

describe("PrioritizedAssetsPage", () => {
  it("shows a loading state, then the reasons behind each asset's priority", async () => {
    mockAuth();
    server.use(http.get("/assets/prioritized", () => HttpResponse.json([fakeResult()])));

    renderWithProviders(<PrioritizedAssetsPage />);

    expect(screen.getByText(/loading/i)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("Asset responds to HTTP/HTTPS requests")).toBeInTheDocument());
    expect(screen.getByText(/exposure: high/i)).toBeInTheDocument();
  });

  it("shows an empty state and an error state without crashing", async () => {
    mockAuth();
    server.use(http.get("/assets/prioritized", () => HttpResponse.json([])));
    renderWithProviders(<PrioritizedAssetsPage />);
    await waitFor(() => expect(screen.getByText(/no assets match this filter/i)).toBeInTheDocument());
  });

  it("shows an error state on failure instead of crashing", async () => {
    mockAuth();
    server.use(http.get("/assets/prioritized", () => HttpResponse.json({ detail: "boom" }, { status: 500 })));
    renderWithProviders(<PrioritizedAssetsPage />);
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
  });

  it("filters by priority as a server-side query parameter", async () => {
    mockAuth();
    let capturedPriorities: string[] = [];
    server.use(
      http.get("/assets/prioritized", ({ request }) => {
        capturedPriorities = new URL(request.url).searchParams.getAll("priority");
        return HttpResponse.json([fakeResult()]);
      }),
    );
    const user = userEvent.setup();

    renderWithProviders(<PrioritizedAssetsPage />);
    await waitFor(() => expect(screen.getByText("example.com")).toBeInTheDocument());

    await user.selectOptions(screen.getByLabelText(/filter by priority/i), "critical");

    await waitFor(() => expect(capturedPriorities).toEqual(["critical"]));
  });
});
