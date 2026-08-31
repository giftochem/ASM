import { describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderWithProviders } from "../test/renderWithProviders";
import { useAuth } from "../auth/useAuth";
import { ChangeTimelinePage } from "./ChangeTimelinePage";

vi.mock("../auth/useAuth");
const mockedUseAuth = vi.mocked(useAuth);

function mockAuth() {
  mockedUseAuth.mockReturnValue({
    user: { id: "u1", organization_id: "org-1", role: "admin" } as never,
    isLoading: false,
    isAuthenticated: true,
  });
}

function entry(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: "obs-1",
    asset_id: "a1",
    asset_type: "domain",
    asset_value: "example.com",
    change_type: "certificate_changed",
    field_name: "example.com:443",
    previous_value: null,
    current_value: null,
    observed_at: "2026-01-01T00:00:00Z",
    source: "discovery",
    confidence: 1.0,
    ...overrides,
  };
}

describe("ChangeTimelinePage", () => {
  it("shows a loading state, then translates change_type into a human-readable label", async () => {
    mockAuth();
    server.use(http.get("/assets/activity", () => HttpResponse.json([entry()])));

    renderWithProviders(<ChangeTimelinePage />);

    expect(screen.getByText(/loading/i)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("TLS certificate changed")).toBeInTheDocument());
  });

  it("shows an empty state when there is no activity", async () => {
    mockAuth();
    server.use(http.get("/assets/activity", () => HttpResponse.json([])));

    renderWithProviders(<ChangeTimelinePage />);

    await waitFor(() => expect(screen.getByText(/no activity recorded/i)).toBeInTheDocument());
  });

  it("shows an error state on failure instead of crashing", async () => {
    mockAuth();
    server.use(http.get("/assets/activity", () => HttpResponse.json({ detail: "boom" }, { status: 500 })));

    renderWithProviders(<ChangeTimelinePage />);

    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
  });

  it("filters by change category as a server-side change_type query parameter", async () => {
    mockAuth();
    let capturedParams: string[] = [];
    server.use(
      http.get("/assets/activity", ({ request }) => {
        capturedParams = new URL(request.url).searchParams.getAll("change_type");
        return HttpResponse.json([entry()]);
      }),
    );
    const user = userEvent.setup();

    renderWithProviders(<ChangeTimelinePage />);
    await waitFor(() => expect(screen.getByText("TLS certificate changed")).toBeInTheDocument());

    await user.selectOptions(screen.getByLabelText(/filter by change category/i), "DNS changes");

    await waitFor(() => expect(capturedParams).toEqual(["dns_records_observed"]));
  });

  it("shows a 'Load more' button only on a full page, and pages forward via keyset params", async () => {
    mockAuth();
    const fullPage = Array.from({ length: 30 }, (_, i) => entry({ id: `obs-${i}`, asset_value: `asset-${i}.example.com` }));
    const secondPage = [entry({ id: "obs-last", asset_value: "final.example.com" })];
    server.use(
      http.get("/assets/activity", ({ request }) => {
        const hasCursor = new URL(request.url).searchParams.has("before_id");
        return HttpResponse.json(hasCursor ? secondPage : fullPage);
      }),
    );
    const user = userEvent.setup();

    renderWithProviders(<ChangeTimelinePage />);
    await waitFor(() => expect(screen.getByText("asset-0.example.com")).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: /load more/i }));

    await waitFor(() => expect(screen.getByText("final.example.com")).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /load more/i })).not.toBeInTheDocument();
  });
});
