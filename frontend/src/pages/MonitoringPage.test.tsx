import { describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderWithProviders } from "../test/renderWithProviders";
import { useAuth } from "../auth/useAuth";
import { MonitoringPage } from "./MonitoringPage";

vi.mock("../auth/useAuth");
const mockedUseAuth = vi.mocked(useAuth);

const adminUser = { id: "u1", organization_id: "org-1", role: "admin" as const };
const viewerUser = { id: "u2", organization_id: "org-1", role: "viewer" as const };

function mockAuth(user: typeof adminUser | typeof viewerUser) {
  mockedUseAuth.mockReturnValue({ user: user as never, isLoading: false, isAuthenticated: true });
}

const confirmedDomain = {
  id: "asset-1",
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

const providers = [
  { name: "stub", applicable_seed_types: ["domain", "subdomain"], depends_on: [] },
  { name: "cloud", applicable_seed_types: ["ip_address"], depends_on: ["network"] },
];

function fakeSchedule(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: "sched-1",
    organization_id: "org-1",
    seed_asset_id: "asset-1",
    seed_asset_value: "example.com",
    seed_asset_type: "domain",
    last_run_status: null,
    provider_name: "stub",
    enabled: true,
    interval_hours: 24,
    next_run_at: "2026-01-02T00:00:00Z",
    last_run_at: null,
    last_run_id: null,
    disabled_reason: null,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

function mockBaseline(schedules: ReturnType<typeof fakeSchedule>[]) {
  server.use(
    http.get("/assets", () => HttpResponse.json([confirmedDomain])),
    http.get("/discovery/providers", () => HttpResponse.json(providers)),
    http.get("/discovery/schedules", () => HttpResponse.json(schedules)),
  );
}

describe("MonitoringPage", () => {
  it("shows a loading state, then existing schedules with provider/asset/interval/state", async () => {
    mockAuth(adminUser);
    mockBaseline([fakeSchedule()]);

    renderWithProviders(<MonitoringPage />);

    expect(screen.getByText(/loading schedules/i)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("example.com")).toBeInTheDocument());
    // "stub" also appears as an <option> in the create form's provider
    // picker -- scope to the schedule table specifically.
    const row = screen.getByText("example.com").closest("tr")!;
    expect(within(row).getByText("stub")).toBeInTheDocument();
    expect(within(row).getByText("24h")).toBeInTheDocument();
    expect(within(row).getByText("Enabled")).toBeInTheDocument();
  });

  it("says scheduled re-checks need the beat scheduler, without promising automatic runs", async () => {
    mockAuth(adminUser);
    mockBaseline([]);
    renderWithProviders(<MonitoringPage />);

    const intro = screen.getByText(/recurring discovery/i);
    expect(intro).toHaveTextContent(/only while the Celery beat scheduler is running/i);
    expect(intro).toHaveTextContent(/production Compose file doesn't run it/i);
    expect(intro).not.toHaveTextContent(/re-checked automatically/i);
  });

  it("shows an empty state and an error state without crashing", async () => {
    mockAuth(adminUser);
    mockBaseline([]);
    renderWithProviders(<MonitoringPage />);
    await waitFor(() => expect(screen.getByText(/no discovery schedules yet/i)).toBeInTheDocument());
  });

  it("shows an error state on failure instead of crashing", async () => {
    mockAuth(adminUser);
    server.use(
      http.get("/assets", () => HttpResponse.json([confirmedDomain])),
      http.get("/discovery/providers", () => HttpResponse.json(providers)),
      http.get("/discovery/schedules", () => HttpResponse.json({ detail: "boom" }, { status: 500 })),
    );
    renderWithProviders(<MonitoringPage />);
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
  });

  it("shows a disabled schedule's reason", async () => {
    mockAuth(adminUser);
    mockBaseline([fakeSchedule({ enabled: false, disabled_reason: "Authorization was revoked" })]);
    renderWithProviders(<MonitoringPage />);
    await waitFor(() => expect(screen.getByText("Authorization was revoked")).toBeInTheDocument());
    expect(screen.getByText("Disabled")).toBeInTheDocument();
  });

  it("offers only providers compatible with the selected asset's type", async () => {
    mockAuth(adminUser);
    mockBaseline([]);
    const user = userEvent.setup();

    renderWithProviders(<MonitoringPage />);
    // Wait for the actual asset option, not just the static form
    // heading -- GET /assets resolves asynchronously, and the "New
    // schedule" text is present even before that data has loaded.
    await waitFor(() => expect(within(screen.getByLabelText("Asset")).getByText("example.com (domain)")).toBeInTheDocument());

    await user.selectOptions(screen.getByLabelText("Asset"), "asset-1");

    const providerSelect = screen.getByLabelText("Provider");
    expect(within(providerSelect).getByText("stub")).toBeInTheDocument();
    expect(within(providerSelect).queryByText("cloud")).not.toBeInTheDocument();
  });

  it("creates a schedule and reflects it in the list", async () => {
    mockAuth(adminUser);
    let schedules: ReturnType<typeof fakeSchedule>[] = [];
    server.use(
      http.get("/assets", () => HttpResponse.json([confirmedDomain])),
      http.get("/discovery/providers", () => HttpResponse.json(providers)),
      http.get("/discovery/schedules", () => HttpResponse.json(schedules)),
      http.post("/discovery/schedules", async ({ request }) => {
        const body = (await request.json()) as { seed_asset_id: string; provider_name: string; interval_hours: number };
        const created = fakeSchedule({ id: "new-sched", interval_hours: body.interval_hours });
        schedules = [...schedules, created];
        return HttpResponse.json(created, { status: 201 });
      }),
    );
    const user = userEvent.setup();

    renderWithProviders(<MonitoringPage />);
    await waitFor(() => expect(within(screen.getByLabelText("Asset")).getByText("example.com (domain)")).toBeInTheDocument());

    await user.selectOptions(screen.getByLabelText("Asset"), "asset-1");
    await user.selectOptions(screen.getByLabelText("Provider"), "stub");
    await user.click(screen.getByRole("button", { name: /create schedule/i }));

    await waitFor(() => expect(screen.getByText("example.com")).toBeInTheDocument());
  });

  it("hides the create form for a viewer but still shows edit/enable/delete actions as hidden too (RBAC visibility)", async () => {
    mockAuth(viewerUser);
    mockBaseline([fakeSchedule()]);

    renderWithProviders(<MonitoringPage />);
    await waitFor(() => expect(screen.getByText("example.com")).toBeInTheDocument());

    expect(screen.queryByText(/new schedule/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /run now/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^disable$/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^delete$/i })).not.toBeInTheDocument();
  });

  it("toggles a schedule enabled/disabled", async () => {
    mockAuth(adminUser);
    let schedule = fakeSchedule();
    server.use(
      http.get("/assets", () => HttpResponse.json([confirmedDomain])),
      http.get("/discovery/providers", () => HttpResponse.json(providers)),
      http.get("/discovery/schedules", () => HttpResponse.json([schedule])),
      http.patch("/discovery/schedules/:id", async ({ request }) => {
        const body = (await request.json()) as { enabled?: boolean };
        schedule = { ...schedule, enabled: body.enabled ?? schedule.enabled };
        return HttpResponse.json(schedule);
      }),
    );
    const user = userEvent.setup();

    renderWithProviders(<MonitoringPage />);
    await waitFor(() => expect(screen.getByText("Enabled")).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: /^disable$/i }));

    await waitFor(() => expect(screen.getByText("Disabled")).toBeInTheDocument());
  });

  it("deletes a schedule after confirmation", async () => {
    mockAuth(adminUser);
    let schedules = [fakeSchedule()];
    server.use(
      http.get("/assets", () => HttpResponse.json([confirmedDomain])),
      http.get("/discovery/providers", () => HttpResponse.json(providers)),
      http.get("/discovery/schedules", () => HttpResponse.json(schedules)),
      http.delete("/discovery/schedules/:id", () => {
        schedules = [];
        return new HttpResponse(null, { status: 204 });
      }),
    );
    const user = userEvent.setup();

    renderWithProviders(<MonitoringPage />);
    await waitFor(() => expect(screen.getByText("example.com")).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: /^delete$/i }));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Confirm" }));

    await waitFor(() => expect(screen.getByText(/no discovery schedules yet/i)).toBeInTheDocument());
  });

  it("manually triggers a run and shows its live status", async () => {
    mockAuth(adminUser);
    const schedule = fakeSchedule();
    server.use(
      http.get("/assets", () => HttpResponse.json([confirmedDomain])),
      http.get("/discovery/providers", () => HttpResponse.json(providers)),
      http.get("/discovery/schedules", () => HttpResponse.json([schedule])),
      http.post("/discovery/schedules/:id/run", () =>
        HttpResponse.json({
          id: "run-1",
          organization_id: "org-1",
          seed_asset_id: "asset-1",
          initiated_by: "u1",
          provider_name: "stub",
          status: "queued",
          started_at: null,
          completed_at: null,
          error_message: null,
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        }),
      ),
      http.get("/discovery/runs/run-1", () =>
        HttpResponse.json({
          id: "run-1",
          organization_id: "org-1",
          seed_asset_id: "asset-1",
          initiated_by: "u1",
          provider_name: "stub",
          status: "completed",
          started_at: "2026-01-01T00:00:01Z",
          completed_at: "2026-01-01T00:00:02Z",
          error_message: null,
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:02Z",
        }),
      ),
    );
    const user = userEvent.setup();

    renderWithProviders(<MonitoringPage />);
    await waitFor(() => expect(screen.getByText("example.com")).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: /run now/i }));

    await waitFor(() => expect(screen.getByText("completed")).toBeInTheDocument());
  });

  it("cannot trigger a disabled schedule (the control is disabled, matching the server's own 400)", async () => {
    mockAuth(adminUser);
    mockBaseline([fakeSchedule({ enabled: false, disabled_reason: "Authorization was revoked" })]);

    renderWithProviders(<MonitoringPage />);
    await waitFor(() => expect(screen.getByText("example.com")).toBeInTheDocument());

    expect(screen.getByRole("button", { name: /run now/i })).toBeDisabled();
  });
});
