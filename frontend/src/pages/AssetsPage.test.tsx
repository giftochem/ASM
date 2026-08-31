import { describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderWithProviders } from "../test/renderWithProviders";
import { useAuth } from "../auth/useAuth";
import { AssetsPage } from "./AssetsPage";
import type { Asset } from "../api/assets";

vi.mock("../auth/useAuth");
const mockedUseAuth = vi.mocked(useAuth);

const baseAsset = {
  organization_id: "org-1",
  parent_asset_id: null,
  authorization_confirmed: true,
  authorization_confirmed_by: "user-1",
  authorization_confirmed_at: "2026-01-01T00:00:00Z",
  notes: null,
  is_active: true,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  status: "active" as const,
  source: "manual" as const,
  confidence: 1.0,
  environment: null,
  criticality: null,
  owner: null,
  tags: [],
  first_seen: "2026-01-01T00:00:00Z",
  last_seen: "2026-01-01T00:00:00Z",
};

const domainAsset = {
  ...baseAsset,
  id: "11111111-1111-1111-1111-111111111111",
  asset_type: "domain" as const,
  value: "example.com",
};

const ipAsset = {
  ...baseAsset,
  id: "22222222-2222-2222-2222-222222222222",
  asset_type: "ip_address" as const,
  value: "203.0.113.5",
  authorization_confirmed: false,
  authorization_confirmed_by: null,
  authorization_confirmed_at: null,
};

const adminUser = { id: "u1", organization_id: "org-1", role: "admin" as const };
const viewerUser = { id: "u2", organization_id: "org-1", role: "viewer" as const };

function mockAuth(user: typeof adminUser | typeof viewerUser) {
  mockedUseAuth.mockReturnValue({
    user: user as never,
    isLoading: false,
    isAuthenticated: true,
  });
}

function mockAssetsAndPriorities(assets: Asset[]) {
  server.use(
    http.get("/assets", () => HttpResponse.json(assets)),
    http.get("/assets/prioritized", () => HttpResponse.json([])),
  );
}

describe("AssetsPage", () => {
  it("shows a loading state, then the org's assets", async () => {
    mockAuth(adminUser);
    mockAssetsAndPriorities([domainAsset, ipAsset]);

    renderWithProviders(<AssetsPage />);

    expect(screen.getByText(/loading/i)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("example.com")).toBeInTheDocument());
    expect(screen.getByText("203.0.113.5")).toBeInTheDocument();
  });

  it("shows an error state on failure instead of crashing", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/assets", () => HttpResponse.json({ detail: "Service temporarily unavailable" }, { status: 503 })),
      http.get("/assets/prioritized", () => HttpResponse.json([])),
    );

    renderWithProviders(<AssetsPage />);

    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
  });

  it("applies filters as server-side query parameters, not client-side filtering", async () => {
    mockAuth(adminUser);
    let capturedUrl = "";
    server.use(
      http.get("/assets", ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json([domainAsset]);
      }),
      http.get("/assets/prioritized", () => HttpResponse.json([])),
    );
    const user = userEvent.setup();

    renderWithProviders(<AssetsPage />);
    await waitFor(() => expect(screen.getByText("example.com")).toBeInTheDocument());

    await user.selectOptions(screen.getByLabelText(/filter by type/i), "ip_address");

    await waitFor(() => {
      const params = new URL(capturedUrl).searchParams;
      expect(params.getAll("asset_type")).toEqual(["ip_address"]);
    });
  });

  it("debounces search text into a server-side `search` query parameter", async () => {
    mockAuth(adminUser);
    const capturedSearches: (string | null)[] = [];
    server.use(
      http.get("/assets", ({ request }) => {
        capturedSearches.push(new URL(request.url).searchParams.get("search"));
        return HttpResponse.json([domainAsset]);
      }),
      http.get("/assets/prioritized", () => HttpResponse.json([])),
    );
    const user = userEvent.setup();

    renderWithProviders(<AssetsPage />);
    await waitFor(() => expect(screen.getByText("example.com")).toBeInTheDocument());

    await user.type(screen.getByPlaceholderText("Search value..."), "example");

    await waitFor(() => expect(capturedSearches).toContain("example"), { timeout: 2000 });
  });

  it("shows a priority badge joined from GET /assets/prioritized by asset id", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/assets", () => HttpResponse.json([domainAsset])),
      http.get("/assets/prioritized", () =>
        HttpResponse.json([
          {
            asset_id: domainAsset.id,
            asset_type: "domain",
            asset_value: "example.com",
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
    );

    renderWithProviders(<AssetsPage />);
    await waitFor(() => expect(screen.getByText("critical")).toBeInTheDocument());
  });

  it("hides the create form for a viewer (UX guard only — server enforces the real boundary)", async () => {
    mockAuth(viewerUser);
    mockAssetsAndPriorities([]);

    renderWithProviders(<AssetsPage />);
    await waitFor(() => expect(screen.getByText(/no assets match this filter/i)).toBeInTheDocument());

    expect(screen.queryByRole("button", { name: /add asset/i })).not.toBeInTheDocument();
  });

  it("creates an asset and reflects it in the list", async () => {
    mockAuth(adminUser);
    let assets: Asset[] = [domainAsset];
    server.use(
      http.get("/assets", () => HttpResponse.json(assets)),
      http.get("/assets/prioritized", () => HttpResponse.json([])),
      http.post("/assets", async ({ request }) => {
        const body = (await request.json()) as { asset_type: string; value: string };
        const created = { ...ipAsset, value: body.value };
        assets = [...assets, created];
        return HttpResponse.json(created, { status: 201 });
      }),
    );
    const user = userEvent.setup();

    renderWithProviders(<AssetsPage />);
    await waitFor(() => expect(screen.getByText("example.com")).toBeInTheDocument());

    await user.type(screen.getByPlaceholderText("e.g. example.com"), "203.0.113.9");
    await user.click(screen.getByRole("button", { name: /^add asset$/i }));

    await waitFor(() => expect(screen.getByText("203.0.113.9")).toBeInTheDocument());
  });

  it("surfaces a 409 duplicate-asset error without losing the form input", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/assets", () => HttpResponse.json([domainAsset])),
      http.get("/assets/prioritized", () => HttpResponse.json([])),
      http.post("/assets", () => HttpResponse.json({ detail: "Asset already exists" }, { status: 409 })),
    );
    const user = userEvent.setup();

    renderWithProviders(<AssetsPage />);
    await waitFor(() => expect(screen.getByText("example.com")).toBeInTheDocument());

    await user.type(screen.getByPlaceholderText("e.g. example.com"), "example.com");
    await user.click(screen.getByRole("button", { name: /^add asset$/i }));

    await waitFor(() => expect(screen.getByText("Asset already exists")).toBeInTheDocument());
  });

  it("shows a 'Load more' button only when a full page was returned, and fetches the next keyset page", async () => {
    mockAuth(adminUser);
    const page1 = Array.from({ length: 50 }, (_, i) => ({
      ...baseAsset,
      id: `page1-${i}`,
      asset_type: "domain" as const,
      value: `page1-${i}.example.com`,
    }));
    const page2 = [{ ...baseAsset, id: "page2-0", asset_type: "domain" as const, value: "page2-0.example.com" }];
    let calls = 0;
    server.use(
      http.get("/assets", ({ request }) => {
        calls += 1;
        const hasCursor = new URL(request.url).searchParams.has("after_value");
        return HttpResponse.json(hasCursor ? page2 : page1);
      }),
      http.get("/assets/prioritized", () => HttpResponse.json([])),
    );
    const user = userEvent.setup();

    renderWithProviders(<AssetsPage />);
    await waitFor(() => expect(screen.getByText("page1-0.example.com")).toBeInTheDocument());

    const loadMore = screen.getByRole("button", { name: /load more/i });
    await user.click(loadMore);

    await waitFor(() => expect(screen.getByText("page2-0.example.com")).toBeInTheDocument());
    expect(calls).toBe(2);
    // A short (< 50) second page means there is no third page to load.
    expect(screen.queryByRole("button", { name: /load more/i })).not.toBeInTheDocument();
  });
});
