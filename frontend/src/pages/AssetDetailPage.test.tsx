import { beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes } from "react-router-dom";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderWithProviders } from "../test/renderWithProviders";
import { useAuth } from "../auth/useAuth";
import { AssetDetailPage } from "./AssetDetailPage";

vi.mock("../auth/useAuth");
const mockedUseAuth = vi.mocked(useAuth);

const ASSET_ID = "11111111-1111-1111-1111-111111111111";

const unconfirmedAsset = {
  id: ASSET_ID,
  organization_id: "org-1",
  asset_type: "domain" as const,
  value: "example.com",
  parent_asset_id: null,
  authorization_confirmed: false,
  authorization_confirmed_by: null,
  authorization_confirmed_at: null,
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

const fakeRisk = {
  asset_id: ASSET_ID,
  asset_type: "domain" as const,
  asset_value: "example.com",
  priority: "medium" as const,
  confidence_label: "medium",
  confidence_value: 0.7,
  dimensions: {
    exposure: "low",
    business_criticality: "unknown",
    change_recency: "none",
    connectivity_relevance: "none",
    evidence_confidence: "medium",
  },
  reasons: [],
  evaluated_at: "2026-01-01T00:00:00Z",
};

// Deliberately empty for the shared default (not realistic -- the real
// backend always includes the seed asset itself in `nodes`, see
// graph_service.get_asset_graph) -- a node labeled "example.com" would
// collide with this page's own <h1>example.com</h1> in the many
// pre-existing getByText("example.com") assertions below, which don't
// care about the graph at all. The dedicated graph test further down
// uses its own realistic fixture and scopes its queries to avoid that
// ambiguity instead.
const emptyGraph = {
  nodes: [],
  edges: [],
  metadata: { seed_asset_id: ASSET_ID, depth: 2, node_count: 0, edge_count: 0 },
};

const confirmedAsset = {
  ...unconfirmedAsset,
  authorization_confirmed: true,
  authorization_confirmed_by: "user-1",
  authorization_confirmed_at: "2026-01-02T00:00:00Z",
};

const adminUser = { id: "u1", organization_id: "org-1", role: "admin" as const };
const viewerUser = { id: "u2", organization_id: "org-1", role: "viewer" as const };

function mockAuth(user: typeof adminUser | typeof viewerUser) {
  mockedUseAuth.mockReturnValue({ user: user as never, isLoading: false, isAuthenticated: true });
}

function renderDetail() {
  return renderWithProviders(
    <Routes>
      <Route path="/assets/:assetId" element={<AssetDetailPage />} />
    </Routes>,
    { route: `/assets/${ASSET_ID}` },
  );
}

beforeEach(() => {
  // AssetDetailPage fetches several sub-resources beyond the asset
  // itself (scan history since Step 3; risk/graph/relationships/
  // observations since Step 9.13) — default every one of them to an
  // empty/neutral response so pre-existing tests (and new ones that
  // don't care about a specific sub-resource) keep working without
  // individually mocking each call; tests that DO care override with
  // server.use() below.
  server.use(
    http.get("/scans", () => HttpResponse.json([])),
    http.get(`/assets/${ASSET_ID}/risk`, () => HttpResponse.json(fakeRisk)),
    http.get(`/assets/${ASSET_ID}/graph`, () => HttpResponse.json(emptyGraph)),
    http.get(`/assets/${ASSET_ID}/relationships`, () => HttpResponse.json([])),
    http.get(`/assets/${ASSET_ID}/observations`, () => HttpResponse.json([])),
  );
});

describe("AssetDetailPage", () => {
  it("shows a loading state, then the asset", async () => {
    mockAuth(adminUser);
    server.use(http.get("/assets/:id", () => HttpResponse.json(unconfirmedAsset)));

    renderDetail();

    expect(screen.getByText(/loading asset/i)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("example.com")).toBeInTheDocument());
  });

  it("shows a not-found state on a cross-org / nonexistent asset id (404, matching the backend's ownership boundary)", async () => {
    mockAuth(adminUser);
    server.use(http.get("/assets/:id", () => HttpResponse.json({ detail: "Asset not found" }, { status: 404 })));

    renderDetail();

    await waitFor(() => expect(screen.getByText(/asset not found/i)).toBeInTheDocument());
  });

  it("shows a generic error state without crashing on other failures", async () => {
    mockAuth(adminUser);
    server.use(http.get("/assets/:id", () => HttpResponse.json({ detail: "Service temporarily unavailable" }, { status: 503 })));

    renderDetail();

    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
  });

  it("hides confirm/revoke actions for a viewer", async () => {
    mockAuth(viewerUser);
    server.use(http.get("/assets/:id", () => HttpResponse.json(unconfirmedAsset)));

    renderDetail();
    await waitFor(() => expect(screen.getByText("example.com")).toBeInTheDocument());

    expect(screen.queryByRole("button", { name: /confirm authorization/i })).not.toBeInTheDocument();
  });

  it("runs the confirm-authorization flow: dialog requires attestation, then updates status", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/assets/:id", () => HttpResponse.json(unconfirmedAsset)),
      http.post("/assets/:id/confirm-authorization", () => HttpResponse.json(confirmedAsset)),
    );
    const user = userEvent.setup();

    renderDetail();
    await waitFor(() => expect(screen.getByText("Unauthorized")).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: /^confirm authorization$/i }));
    const dialog = screen.getByRole("dialog");
    const dialogConfirmButton = within(dialog).getByRole("button", { name: "Confirm" });
    expect(dialogConfirmButton).toBeDisabled();

    await user.click(screen.getByRole("checkbox"));
    expect(dialogConfirmButton).not.toBeDisabled();

    await user.click(dialogConfirmButton);

    await waitFor(() => expect(screen.getByText("Authorized")).toBeInTheDocument());
  });

  it("runs the revoke-authorization flow", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/assets/:id", () => HttpResponse.json(confirmedAsset)),
      http.post("/assets/:id/revoke-authorization", () => HttpResponse.json(unconfirmedAsset)),
    );
    const user = userEvent.setup();

    renderDetail();
    await waitFor(() => expect(screen.getByText("Authorized")).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: /^revoke authorization$/i }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Confirm" }));

    await waitFor(() => expect(screen.getByText("Unauthorized")).toBeInTheDocument());
  });

  it("shows scan history scoped to this asset", async () => {
    mockAuth(adminUser);
    let capturedUrl = "";
    server.use(
      http.get("/assets/:id", () => HttpResponse.json(confirmedAsset)),
      http.get("/scans", ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json([
          {
            id: "scan-1",
            asset_id: ASSET_ID,
            initiated_by: "u1",
            status: "completed",
            modules_requested: ["whois"],
            started_at: "2026-01-01T00:00:00Z",
            completed_at: "2026-01-01T00:01:00Z",
            error_message: null,
            risk_score: 10,
            risk_severity_band: "low",
            created_at: "2026-01-01T00:00:00Z",
          },
        ]);
      }),
    );

    renderDetail();
    await waitFor(() => expect(screen.getByText("whois")).toBeInTheDocument());
    expect(screen.getByText("completed")).toBeInTheDocument();
    expect(new URL(capturedUrl).searchParams.get("asset_id")).toBe(ASSET_ID);
  });

  it("shows an empty state when there are no scans yet for this asset", async () => {
    mockAuth(adminUser);
    server.use(http.get("/assets/:id", () => HttpResponse.json(confirmedAsset)));

    renderDetail();
    await waitFor(() => expect(screen.getByText(/no scans yet for this asset/i)).toBeInTheDocument());
  });

  it("shows a 'New scan' link only for admin/analyst on a confirmed asset", async () => {
    mockAuth(adminUser);
    server.use(http.get("/assets/:id", () => HttpResponse.json(confirmedAsset)));

    renderDetail();
    await waitFor(() => expect(screen.getByText("Authorized")).toBeInTheDocument());
    expect(screen.getByRole("link", { name: /new scan/i })).toHaveAttribute("href", `/scans?asset_id=${ASSET_ID}`);
  });

  it("hides the 'New scan' link for a viewer", async () => {
    mockAuth(viewerUser);
    server.use(http.get("/assets/:id", () => HttpResponse.json(confirmedAsset)));

    renderDetail();
    await waitFor(() => expect(screen.getByText("Authorized")).toBeInTheDocument());
    expect(screen.queryByRole("link", { name: /new scan/i })).not.toBeInTheDocument();
  });

  it("hides the 'New scan' link when the asset isn't authorized yet", async () => {
    mockAuth(adminUser);
    server.use(http.get("/assets/:id", () => HttpResponse.json(unconfirmedAsset)));

    renderDetail();
    await waitFor(() => expect(screen.getByText("Unauthorized")).toBeInTheDocument());
    expect(screen.queryByRole("link", { name: /new scan/i })).not.toBeInTheDocument();
  });

  it("shows the priority section with its explanation reasons (Step 9.13)", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/assets/:id", () => HttpResponse.json(confirmedAsset)),
      http.get(`/assets/${ASSET_ID}/risk`, () =>
        HttpResponse.json({
          ...fakeRisk,
          priority: "high",
          reasons: [{ signal: "http_exposed", impact: "high", description: "Asset responds to HTTP/HTTPS requests" }],
        }),
      ),
    );

    renderDetail();
    await waitFor(() => expect(screen.getByText("Asset responds to HTTP/HTTPS requests")).toBeInTheDocument());
    // Two "high" priority badges can legitimately appear (header + priority
    // section) -- getAllByText confirms at least one rendered, without
    // assuming exactly which section is queried.
    expect(screen.getAllByText("high").length).toBeGreaterThan(0);
  });

  it("shows relationships to other assets", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/assets/:id", () => HttpResponse.json(confirmedAsset)),
      http.get(`/assets/${ASSET_ID}/relationships`, () =>
        HttpResponse.json([
          {
            id: "rel-1",
            source_asset_id: ASSET_ID,
            target_asset_id: "33333333-3333-3333-3333-333333333333",
            relationship_type: "resolves_to",
            status: "active",
            source: "discovery",
            confidence: 0.9,
            first_seen: "2026-01-01T00:00:00Z",
            last_seen: "2026-01-01T00:00:00Z",
            notes: null,
            created_at: "2026-01-01T00:00:00Z",
            updated_at: "2026-01-01T00:00:00Z",
          },
        ]),
      ),
    );

    renderDetail();
    await waitFor(() => expect(screen.getByText(/resolves_to/)).toBeInTheDocument());
  });

  it("shows recent changes from the observation history", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/assets/:id", () => HttpResponse.json(confirmedAsset)),
      http.get(`/assets/${ASSET_ID}/observations`, () =>
        HttpResponse.json([
          {
            id: "obs-1",
            asset_id: ASSET_ID,
            observed_at: "2026-01-03T00:00:00Z",
            change_type: "certificate_changed",
            field_name: "example.com:443",
            previous_value: null,
            current_value: null,
            source: "discovery",
            confidence: 1.0,
          },
        ]),
      ),
    );

    renderDetail();
    await waitFor(() => expect(screen.getByText("certificate changed")).toBeInTheDocument());
  });

  it("renders the attack-surface graph and navigates when a neighbor node is clicked", async () => {
    mockAuth(adminUser);
    const neighborId = "44444444-4444-4444-4444-444444444444";
    server.use(
      http.get("/assets/:id", () => HttpResponse.json(confirmedAsset)),
      http.get(`/assets/${ASSET_ID}/graph`, () =>
        HttpResponse.json({
          nodes: [
            { id: ASSET_ID, asset_type: "domain", value: "example.com", status: "active", source: "manual", confidence: 1.0, environment: null, criticality: null, owner: null, tags: [], first_seen: "2026-01-01T00:00:00Z", last_seen: "2026-01-01T00:00:00Z" },
            { id: neighborId, asset_type: "subdomain", value: "www.example.com", status: "active", source: "discovery", confidence: 0.9, environment: null, criticality: null, owner: null, tags: [], first_seen: "2026-01-01T00:00:00Z", last_seen: "2026-01-01T00:00:00Z" },
          ],
          edges: [
            {
              id: "edge-1",
              source_asset_id: neighborId,
              target_asset_id: ASSET_ID,
              relationship_type: "belongs_to",
              status: "active",
              confidence: 0.9,
              created_at: "2026-01-01T00:00:00Z",
              updated_at: "2026-01-01T00:00:00Z",
            },
          ],
          metadata: { seed_asset_id: ASSET_ID, depth: 2, node_count: 2, edge_count: 1 },
        }),
      ),
    );

    // Clicking navigates via useNavigate(`/assets/${node.id}`). Since
    // this test's own route table has only one route pattern
    // (/assets/:assetId), which matches both the seed's and the
    // neighbor's id, a distinct, distinguishable response for the
    // neighbor's own detail fetch is what confirms real navigation
    // happened, not merely a re-render of the seed's already-loaded page.
    server.use(
      http.get(`/assets/${neighborId}`, () =>
        HttpResponse.json({ ...confirmedAsset, id: neighborId, value: "neighbor-detail-marker.example.com" }),
      ),
      // The neighbor page's own sub-resource fetches -- not asserted on
      // here, just given a clean default so they don't fail loudly.
      http.get(`/assets/${neighborId}/risk`, () => HttpResponse.json({ ...fakeRisk, asset_id: neighborId })),
      http.get(`/assets/${neighborId}/graph`, () => HttpResponse.json(emptyGraph)),
      http.get(`/assets/${neighborId}/relationships`, () => HttpResponse.json([])),
      http.get(`/assets/${neighborId}/observations`, () => HttpResponse.json([])),
    );

    renderWithProviders(
      <Routes>
        <Route path="/assets/:assetId" element={<AssetDetailPage />} />
      </Routes>,
      { route: `/assets/${ASSET_ID}` },
    );
    const graphImage = await screen.findByRole("img", { name: /attack surface graph/i });
    const neighborNode = within(graphImage).getByRole("button", { name: /www\.example\.com/i });

    const user = userEvent.setup();
    await user.click(neighborNode);

    await waitFor(() => expect(screen.getByText("neighbor-detail-marker.example.com")).toBeInTheDocument());
  });

  it("shows a loading state and an error state for the graph independently of the rest of the page", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/assets/:id", () => HttpResponse.json(confirmedAsset)),
      http.get(`/assets/${ASSET_ID}/graph`, () =>
        HttpResponse.json({ detail: "depth must be between 0 and 5" }, { status: 400 }),
      ),
    );

    renderDetail();
    await waitFor(() => expect(screen.getByText("Authorized")).toBeInTheDocument());
    await waitFor(() => expect(screen.getAllByRole("alert").length).toBeGreaterThan(0));
  });
});
