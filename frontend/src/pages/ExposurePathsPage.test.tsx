import { afterEach, describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderWithProviders } from "../test/renderWithProviders";
import { DISCLAIMER, ExposurePathsPage } from "./ExposurePathsPage";
import type { EntryEvidence, ExposurePath, ExposurePathsResponse, PathAsset } from "../api/exposurePaths";

const ENDPOINT = "/assets/exposure-paths";
const ASSESSED = "2026-10-19T12:00:00Z";
const CONFIRMED = "2026-10-18T09:30:00Z";

function asset(id: string, value: string, overrides: Partial<PathAsset> = {}): PathAsset {
  return { asset_id: id, asset_type: "domain", value, criticality: null, environment: null, ...overrides };
}

function evidence(overrides: Partial<EntryEvidence> = {}): EntryEvidence {
  return {
    evidence_type: "http_response",
    source: "discovery:http",
    subject: "https",
    freshness: "current",
    first_confirmed_at: "2026-10-01T08:00:00Z",
    last_confirmed_at: CONFIRMED,
    latest_attempt_at: CONFIRMED,
    inconclusive_attempts: 0,
    latest_inconclusive_at: null,
    discovery_run_id: "run-http-1",
    scan_id: null,
    result_id: "result-http-1",
    observation_id: null,
    limitations: [],
    ...overrides,
  };
}

const API = asset("a-api", "api.example.com", { criticality: "critical" });
const SITE = asset("a-site", "www.example.com");
const DB_IP = asset("a-db", "198.51.100.10", { asset_type: "ip_address", criticality: "critical" });
const EDGE = asset("a-edge", "203.0.113.5", { asset_type: "ip_address" });
const APP = asset("a-app", "app.example.com");
const BACKEND = asset("a-backend", "backend.app.example.com", { asset_type: "subdomain", criticality: "high" });

const NOT_ASSESSED = "Exploitability, privilege escalation and lateral movement have not been assessed.";

const zeroHop: ExposurePath = {
  entry_point: API,
  target: API,
  hop_count: 0,
  is_zero_hop: true,
  basis: "direct_exposure",
  nodes: [API],
  steps: [],
  entry_evidence: [evidence({ evidence_type: "tls_handshake", source: "discovery:certificate", subject: "api.example.com:443" })],
  interpretation: `Observed exposure: api.example.com has current observed service exposure (TLS handshake) and is itself marked critical. ${NOT_ASSESSED}`,
  limitations: [NOT_ASSESSED],
};

const oneHop: ExposurePath = {
  entry_point: SITE,
  target: DB_IP,
  hop_count: 1,
  is_zero_hop: false,
  basis: "observed_dns_association",
  nodes: [SITE, DB_IP],
  steps: [
    {
      relationship_id: "rel-dns-1",
      relationship_type: "resolves_to",
      from_asset_id: SITE.asset_id,
      to_asset_id: DB_IP.asset_id,
      direction: "forward",
      basis: "observed_dns_association",
      relationship_source: "discovery",
      rule: "dns_resolution_forward",
      reason: "www.example.com resolves to 198.51.100.10 (followed forward only)",
      dns_evidence: {
        result_id: "dns-result-1",
        discovery_run_id: "dns-run-1",
        observed_at: "2026-10-18T07:00:00Z",
        record_type: "A",
        freshness: "current",
      },
      analyst_assertion: null,
    },
  ],
  entry_evidence: [evidence()],
  interpretation: `Observed infrastructure association: www.example.com has current observed service exposure (HTTP response) and is associated with 198.51.100.10 (marked critical) only through DNS resolution records. ${NOT_ASSESSED}`,
  limitations: [NOT_ASSESSED, "DNS resolution records show name-to-address association only; they do not prove that compromise can propagate between assets."],
};

const multiHop: ExposurePath = {
  entry_point: EDGE,
  target: BACKEND,
  hop_count: 2,
  is_zero_hop: false,
  basis: "observed_dns_and_analyst_asserted",
  nodes: [EDGE, APP, BACKEND],
  steps: [
    {
      relationship_id: "rel-hosts-1",
      relationship_type: "hosts",
      from_asset_id: EDGE.asset_id,
      to_asset_id: APP.asset_id,
      direction: "forward",
      basis: "analyst_asserted",
      relationship_source: "manual",
      rule: "analyst_entered_forward",
      reason: "analyst-entered hosting: 203.0.113.5 -> app.example.com",
      dns_evidence: null,
      analyst_assertion: { audit_log_id: "audit-77", asserted_at: "2026-10-10T10:00:00Z" },
    },
    {
      relationship_id: "rel-cname-1",
      relationship_type: "resolves_to",
      from_asset_id: APP.asset_id,
      to_asset_id: BACKEND.asset_id,
      direction: "forward",
      basis: "observed_dns_association",
      relationship_source: "discovery",
      rule: "dns_resolution_forward",
      reason: "app.example.com resolves to backend.app.example.com",
      dns_evidence: {
        result_id: "dns-result-2",
        discovery_run_id: "dns-run-2",
        observed_at: "2026-10-17T07:00:00Z",
        record_type: "CNAME",
        freshness: "current",
      },
      analyst_assertion: null,
    },
  ],
  entry_evidence: [
    evidence({
      evidence_type: "open_port",
      source: "scan:port_scanner",
      subject: "443/tcp",
      discovery_run_id: null,
      scan_id: "scan-9",
      result_id: "port-row-9",
      inconclusive_attempts: 3,
      latest_inconclusive_at: "2026-10-18T20:00:00Z",
      limitations: ["3 inconclusive attempt(s) since the last confirmation neither confirmed nor contradicted it"],
    }),
  ],
  interpretation: `Mixed path: 203.0.113.5 has current observed service exposure (open port) and is linked to backend.app.example.com (marked high). ${NOT_ASSESSED}`,
  limitations: [NOT_ASSESSED, "Includes analyst-asserted relationships: entered by an analyst and recorded in the audit log, not independently observed."],
};

function response(overrides: Partial<ExposurePathsResponse> = {}): ExposurePathsResponse {
  const paths = overrides.paths ?? [oneHop, multiHop, zeroHop];
  return {
    disclaimer: DISCLAIMER,
    organization_id: "org-1",
    assessed_at: ASSESSED,
    freshness_window_seconds: 7 * 24 * 3600,
    limits: { max_hops: 3, max_targets: 25, max_paths: 100, max_nodes: 500 },
    path_count: paths.length,
    eligible_target_count: 3,
    examined_target_count: 3,
    examined_node_count: 6,
    evaluated_relationship_count: 2,
    entry_point_count: 3,
    truncated: false,
    truncation_reasons: [],
    limitations: ["Only assets explicitly marked high or critical are targets; unclassified assets are never treated as targets."],
    ...overrides,
    paths,
  };
}

function serve(body: ExposurePathsResponse | (() => Response)) {
  const requests: string[] = [];
  server.use(
    http.get(ENDPOINT, ({ request }) => {
      requests.push(request.url);
      return typeof body === "function" ? body() : HttpResponse.json(body);
    }),
  );
  return requests;
}

const pathCards = () => within(screen.getByRole("list", { name: "Exposure paths" })).getAllByRole("listitem", { name: "" });

function cardFor(text: string) {
  const card = screen
    .getAllByRole("listitem")
    .find((item) => item.parentElement?.getAttribute("aria-label") === "Exposure paths" && item.textContent?.includes(text));
  if (!card) throw new Error(`no path card containing ${text}`);
  return card;
}

async function expand(card: HTMLElement) {
  await userEvent.setup().click(within(card).getByRole("button", { name: "Show details" }));
}

afterEach(() => {
  server.events.removeAllListeners();
});

describe("ExposurePathsPage", () => {
  it("shows the disclaimer while loading, then the summary and paths in API order", async () => {
    serve(response());

    renderWithProviders(<ExposurePathsPage />);

    expect(screen.getByText(DISCLAIMER)).toBeInTheDocument();
    expect(screen.getByText("Loading...")).toBeInTheDocument();
    await screen.findByRole("list", { name: "Exposure paths" });

    const summary = screen.getByRole("region", { name: "Assessment summary" });
    expect(within(summary).getByText("Paths returned")).toBeInTheDocument();
    expect(within(summary).getByText("High/critical targets")).toBeInTheDocument();
    expect(within(summary).getByText("Observed entry points")).toBeInTheDocument();
    expect(within(summary).getByText(new Date(ASSESSED).toLocaleString())).toBeInTheDocument();
    expect(within(summary).getByText("Complete within the selected limits.", { exact: false })).toBeInTheDocument();
    expect(within(summary).getByText(/confirmed within the last 7 days/)).toBeInTheDocument();
    expect(screen.getByText(DISCLAIMER)).toBeInTheDocument();

    const order = pathCards().map((card) => card.querySelector("a")?.textContent);
    expect(order).toEqual(["www.example.com", "203.0.113.5", "api.example.com"]);
  });

  it("renders a zero-hop path as direct exposure, without a relationship", async () => {
    serve(response({ paths: [zeroHop] }));
    renderWithProviders(<ExposurePathsPage />);

    const card = await screen.findByText("is itself an observed entry point").then(() => cardFor("api.example.com"));
    expect(within(card).getByText("Zero-hop: direct exposure")).toBeInTheDocument();
    expect(within(card).getByText("Observed service exposure")).toBeInTheDocument();
    expect(within(card).queryByText("→")).not.toBeInTheDocument();

    await expand(card);
    expect(within(card).getByText(/None: the target itself has observed service exposure/)).toBeInTheDocument();
    expect(within(card).queryByRole("list", { name: "Relationship steps" })).not.toBeInTheDocument();
    expect(within(card).getByText(/TLS handshake/, { selector: "div" })).toBeInTheDocument();
  });

  it("renders a one-hop observed DNS path with its DNS evidence", async () => {
    serve(response({ paths: [oneHop] }));
    renderWithProviders(<ExposurePathsPage />);
    const card = await screen.findByText("www.example.com").then(() => cardFor("www.example.com"));

    expect(within(card).getByText("1 hop")).toBeInTheDocument();
    expect(within(card).getByText("Observed infrastructure association (DNS)")).toBeInTheDocument();
    expect(within(card).getByText("critical")).toBeInTheDocument();

    await expand(card);
    const steps = within(card).getByRole("list", { name: "Relationship steps" });
    expect(within(steps).getByText("resolves_to (forward)")).toBeInTheDocument();
    expect(within(steps).getByText(/Observed DNS association · recorded by discovery/)).toBeInTheDocument();
    expect(within(steps).getByText(/DNS evidence: A record observed/)).toHaveTextContent("dns-result-1");
    expect(within(card).getByText(/do not prove that compromise can propagate/)).toBeInTheDocument();
  });

  it("renders a multi-hop path with ordered steps and analyst provenance", async () => {
    serve(response({ paths: [multiHop] }));
    renderWithProviders(<ExposurePathsPage />);
    const card = await screen.findByText("203.0.113.5").then(() => cardFor("203.0.113.5"));

    expect(within(card).getByText("2 hops")).toBeInTheDocument();
    expect(within(card).getByText("Observed DNS association and analyst-entered relationship")).toBeInTheDocument();
    expect(within(card).getByText("high")).toBeInTheDocument();

    await expand(card);
    const nodes = within(within(card).getByRole("list", { name: "Path assets" })).getAllByRole("listitem");
    expect(nodes.map((node) => node.querySelector("a")?.textContent)).toEqual([
      "203.0.113.5",
      "app.example.com",
      "backend.app.example.com",
    ]);
    expect(nodes.map((node) => node.lastElementChild?.textContent)).toEqual(["entry point", "intermediate", "target, high"]);

    const steps = within(within(card).getByRole("list", { name: "Relationship steps" })).getAllByRole("listitem");
    expect(steps.map((step) => step.firstElementChild?.textContent)).toEqual([
      "203.0.113.5 hosts (forward) app.example.com",
      "app.example.com resolves_to (forward) backend.app.example.com",
    ]);
    expect(steps[0]).toHaveTextContent("Analyst-entered relationship · entered manually");
    expect(steps[0]).toHaveTextContent("audit record audit-77");
    expect(steps[1]).toHaveTextContent("Observed DNS association · recorded by discovery");
    expect(steps[1]).toHaveTextContent("CNAME record observed");
  });

  it("labels HTTP, TLS and open-port evidence with source, timestamps and ids", async () => {
    serve(response());
    renderWithProviders(<ExposurePathsPage />);
    await screen.findByRole("list", { name: "Exposure paths" });

    expect(within(cardFor("www.example.com")).getByText(/Evidence: HTTP response/)).toBeInTheDocument();
    expect(within(cardFor("api.example.com")).getByText(/Evidence: TLS handshake/)).toBeInTheDocument();
    expect(within(cardFor("203.0.113.5")).getByText(/Evidence: Open port/)).toBeInTheDocument();

    const card = cardFor("www.example.com");
    await expand(card);
    const item = within(within(card).getByRole("list", { name: "Entry-point evidence" })).getAllByRole("listitem")[0];
    expect(item).toHaveTextContent("via discovery:http · current");
    expect(item).toHaveTextContent(new Date(CONFIRMED).toLocaleString());
    expect(item).toHaveTextContent(new Date("2026-10-01T08:00:00Z").toLocaleString());
    expect(item).toHaveTextContent("result result-http-1 · discovery run run-http-1");
  });

  it("shows inconclusive attempts and evidence limitations", async () => {
    serve(response({ paths: [multiHop] }));
    renderWithProviders(<ExposurePathsPage />);
    const card = await screen.findByText("203.0.113.5").then(() => cardFor("203.0.113.5"));
    await expand(card);

    const item = within(within(card).getByRole("list", { name: "Entry-point evidence" })).getAllByRole("listitem")[0];
    expect(item).toHaveTextContent(`3 (latest ${new Date("2026-10-18T20:00:00Z").toLocaleString()})`);
    expect(item).toHaveTextContent("neither confirmed nor contradicted it");
    expect(item).toHaveTextContent("scan scan-9");
  });

  it("derives the freshness rule from the API and shows result-level limitations", async () => {
    serve(response({ freshness_window_seconds: 2 * 24 * 3600 }));
    renderWithProviders(<ExposurePathsPage />);
    await screen.findByRole("list", { name: "Exposure paths" });

    expect(screen.getByText(/confirmed within the last 2 days/)).toBeInTheDocument();
    const about = screen.getByRole("region", { name: "About these results" });
    expect(within(about).getByText(/unclassified assets are never treated as targets/)).toBeInTheDocument();
  });

  it("explains a missing-criticality organization without claiming there is no exposure", async () => {
    serve(response({ paths: [], eligible_target_count: 0, examined_target_count: 0, entry_point_count: 0 }));
    renderWithProviders(<ExposurePathsPage />);

    const empty = await screen.findByRole("region", { name: "No paths" });
    expect(empty).toHaveTextContent("No assets are marked high or critical");
    expect(within(empty).getByRole("link", { name: "asset list" })).toHaveAttribute("href", "/assets");
    expect(screen.queryByText(/no exposure/i)).not.toBeInTheDocument();
  });

  it("explains an empty result with no current entry points using the API's window", async () => {
    serve(response({ paths: [], entry_point_count: 0 }));
    renderWithProviders(<ExposurePathsPage />);

    const empty = await screen.findByRole("region", { name: "No paths" });
    expect(empty).toHaveTextContent("No qualifying exposure paths were found within this assessment (3 hops)");
    expect(empty).toHaveTextContent("confirmed within the last 7 days");
    expect(within(empty).getByRole("link", { name: "Monitoring" })).toHaveAttribute("href", "/monitoring");
  });

  it("explains an empty result that does have entry points", async () => {
    serve(response({ paths: [], entry_point_count: 2 }));
    renderWithProviders(<ExposurePathsPage />);

    const empty = await screen.findByRole("region", { name: "No paths" });
    expect(empty).toHaveTextContent("no permitted relationship leads from an observed entry point");
  });

  it("shows truncation reasons and never presents a truncated result as complete", async () => {
    serve(
      response({
        paths: [oneHop],
        truncated: true,
        truncation_reasons: [
          { limit: "max_paths", detail: "more than 1 paths were found; only the first 1 are returned" },
          { limit: "evidence_budget", detail: "the evidence budget (20000 rows) was reached: 4 examined assets' evidence wasn't fully examined" },
        ],
      }),
    );
    renderWithProviders(<ExposurePathsPage />);

    const truncation = await screen.findByRole("region", { name: "Truncation" });
    expect(truncation).toHaveTextContent("more paths may exist than are shown");
    expect(truncation).toHaveTextContent("max_paths");
    expect(truncation).toHaveTextContent("evidence_budget");
    expect(truncation).toHaveTextContent("wasn't fully examined");
    expect(screen.getByText("Paths returned (incomplete)")).toBeInTheDocument();
    expect(screen.queryByText("Complete within the selected limits.", { exact: false })).not.toBeInTheDocument();
  });

  it("does not call an empty truncated result a conclusion", async () => {
    serve(response({ paths: [], truncated: true, truncation_reasons: [{ limit: "max_nodes", detail: "the search reached more than 500 assets" }] }));
    renderWithProviders(<ExposurePathsPage />);

    const empty = await screen.findByRole("region", { name: "No paths" });
    expect(empty).toHaveTextContent("this is not a complete result");
    expect(empty).not.toHaveTextContent("No qualifying exposure paths were found");
  });

  it("sends only the chosen limits and shows the server's message for a rejected value", async () => {
    const requests: string[] = [];
    server.use(
      http.get(ENDPOINT, ({ request }) => {
        requests.push(request.url);
        const hops = new URL(request.url).searchParams.get("max_hops");
        return hops === "1"
          ? HttpResponse.json({ detail: "max_hops must be between 0 and 3" }, { status: 400 })
          : HttpResponse.json(response());
      }),
    );
    const user = userEvent.setup();
    renderWithProviders(<ExposurePathsPage />);
    await screen.findByRole("list", { name: "Exposure paths" });

    await user.selectOptions(screen.getByRole("combobox", { name: "Max paths" }), "25");
    await user.selectOptions(screen.getByRole("combobox", { name: "Max hops" }), "1");

    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("max_hops must be between 0 and 3"));
    const params = requests.map((url) => Object.fromEntries(new URL(url).searchParams));
    expect(params).toEqual([
      { max_hops: "3", max_paths: "100" },
      { max_hops: "3", max_paths: "25" },
      { max_hops: "1", max_paths: "25" },
    ]);
    expect(screen.getAllByRole("option").map((option) => (option as HTMLOptionElement).value)).toEqual([
      "0", "1", "2", "3", "10", "25", "50", "100",
    ]);
  });

  it("shows the session-expired message on 401", async () => {
    serve(() => HttpResponse.json({ detail: "Could not validate credentials" }, { status: 401 }));
    renderWithProviders(<ExposurePathsPage />);

    expect(await screen.findByRole("alert")).toHaveTextContent("Your session has expired. Please log in again.");
    expect(screen.getByText(DISCLAIMER)).toBeInTheDocument();
  });

  it("shows a backend error and recovers on retry", async () => {
    let calls = 0;
    serve(() => {
      calls += 1;
      return calls === 1
        ? HttpResponse.json({ detail: "Service temporarily unavailable" }, { status: 503 })
        : HttpResponse.json(response({ paths: [zeroHop] }));
    });
    const user = userEvent.setup();
    renderWithProviders(<ExposurePathsPage />);

    expect(await screen.findByRole("alert")).toHaveTextContent("Service temporarily unavailable");
    await user.click(screen.getByRole("button", { name: "Refresh" }));

    await screen.findByRole("list", { name: "Exposure paths" });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(calls).toBe(2);
  });

  it("refreshes on demand only, re-evaluating through the read-only endpoint", async () => {
    const seen: string[] = [];
    server.events.on("request:start", ({ request }) => {
      seen.push(`${request.method} ${new URL(request.url).pathname}`);
    });
    let calls = 0;
    serve(() => {
      calls += 1;
      return HttpResponse.json(response({ assessed_at: calls === 1 ? ASSESSED : "2026-10-19T12:05:00Z" }));
    });
    const user = userEvent.setup();
    renderWithProviders(<ExposurePathsPage />);
    await screen.findByText(new Date(ASSESSED).toLocaleString());

    await user.click(screen.getByRole("button", { name: "Refresh" }));
    await screen.findByText(new Date("2026-10-19T12:05:00Z").toLocaleString());

    expect(calls).toBe(2);
    expect(seen).toEqual([`GET ${ENDPOINT}`, `GET ${ENDPOINT}`]); // no discovery, scan or other request
    expect(screen.getByText(/never starts discovery or scanning/)).toBeInTheDocument();
  });

  it("shows a refreshing state while re-evaluating", async () => {
    let release!: () => void;
    let calls = 0;
    server.use(
      http.get(ENDPOINT, async () => {
        calls += 1;
        if (calls === 2) {
          await new Promise<void>((resolve) => {
            release = resolve;
          });
        }
        return HttpResponse.json(response());
      }),
    );
    const user = userEvent.setup();
    renderWithProviders(<ExposurePathsPage />);
    await screen.findByRole("list", { name: "Exposure paths" });

    await user.click(screen.getByRole("button", { name: "Refresh" }));

    expect(await screen.findByRole("button", { name: "Refreshing..." })).toBeDisabled();
    release();
    expect(await screen.findByRole("button", { name: "Refresh" })).toBeEnabled();
  });

  it("links entry points and targets to their asset pages", async () => {
    serve(response({ paths: [oneHop] }));
    renderWithProviders(<ExposurePathsPage />);
    const card = await screen.findByText("www.example.com").then(() => cardFor("www.example.com"));

    expect(within(card).getByRole("link", { name: "www.example.com" })).toHaveAttribute("href", "/assets/a-site");
    expect(within(card).getByRole("link", { name: "198.51.100.10" })).toHaveAttribute("href", "/assets/a-db");
  });

  it("renders untrusted names and evidence strings as text", async () => {
    const hostile = asset("a-evil", '<img src=x onerror="window.__pwned=1">', { criticality: "critical" });
    serve(
      response({
        paths: [
          {
            ...zeroHop,
            entry_point: hostile,
            target: hostile,
            nodes: [hostile],
            interpretation: "<script>window.__pwned=2</script>",
            entry_evidence: [evidence({ subject: "<b>bold</b>", limitations: ['<a href="javascript:alert(1)">x</a>'] })],
          },
        ],
        limitations: ["<iframe src=//evil></iframe>"],
      }),
    );
    const { container } = renderWithProviders(<ExposurePathsPage />);
    const card = await screen.findByText('<img src=x onerror="window.__pwned=1">').then(() =>
      cardFor('<img src=x onerror="window.__pwned=1">'),
    );
    await expand(card);

    expect(screen.getByText("<script>window.__pwned=2</script>")).toBeInTheDocument();
    expect(screen.getByText('<a href="javascript:alert(1)">x</a>')).toBeInTheDocument();
    expect(container.querySelector("img, script, iframe, b")).toBeNull();
    expect(container.querySelector('a[href^="javascript:"]')).toBeNull();
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });

  it("handles null and missing optional values without inventing data", async () => {
    const unset = asset("a-unset", "unset.example.com");
    serve(
      response({
        paths: [
          {
            ...multiHop,
            target: { ...BACKEND, criticality: null },
            nodes: [EDGE, APP, { ...BACKEND, criticality: null }],
            steps: [
              { ...multiHop.steps[0], analyst_assertion: null },
              { ...multiHop.steps[1], dns_evidence: multiHop.steps[1].dns_evidence && { ...multiHop.steps[1].dns_evidence, record_type: null } },
            ],
            entry_evidence: [evidence({ first_confirmed_at: null, latest_attempt_at: null, latest_inconclusive_at: null, result_id: null, discovery_run_id: null })],
          },
          { ...zeroHop, entry_point: unset, target: unset, nodes: [unset], entry_evidence: [] },
        ],
      }),
    );
    renderWithProviders(<ExposurePathsPage />);
    const card = await screen.findByText("203.0.113.5").then(() => cardFor("203.0.113.5"));

    expect(within(card).getByText("criticality not set")).toBeInTheDocument();
    await expand(card);
    expect(within(card).getByText("Analyst assertion record not provided.")).toBeInTheDocument();
    expect(within(card).getByText(/record type not recorded record observed/)).toBeInTheDocument();
    const item = within(within(card).getByRole("list", { name: "Entry-point evidence" })).getAllByRole("listitem")[0];
    expect(item).toHaveTextContent("First confirmednot determined");
    expect(item).toHaveTextContent("Latest attempt—");
    expect(within(cardFor("unset.example.com")).getByText(/Evidence: none listed/)).toBeInTheDocument();
  });
});
