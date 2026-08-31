import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "../../test/server";
import { renderWithProviders } from "../../test/renderWithProviders";
import { AuditLogsPage } from "./AuditLogsPage";

const userA = {
  id: "user-a",
  organization_id: "org-1",
  email: "a@example.com",
  full_name: "User A",
  role: "admin" as const,
  is_active: true,
  created_at: "2026-01-01T00:00:00Z",
};

function fakeLog(overrides: Record<string, unknown> = {}) {
  return {
    id: `l-${Math.random().toString(36).slice(2)}`,
    user_id: userA.id,
    organization_id: "org-1",
    action: "auth.login",
    resource_type: "user",
    resource_id: userA.id,
    outcome: "success",
    details: null,
    ip_address: "203.0.113.5",
    created_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

describe("AuditLogsPage", () => {
  it("shows a loading state, then log entries", async () => {
    server.use(
      http.get("/users", () => HttpResponse.json([userA])),
      http.get("/audit-logs", () => HttpResponse.json([fakeLog()])),
    );
    renderWithProviders(<AuditLogsPage />);
    expect(screen.getByText(/loading/i)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("table")).toBeInTheDocument());
    // Not a bare screen.getByText("auth.login") — that string also
    // appears as a static <option> in the action filter dropdown, so an
    // unscoped query is ambiguous once both load. Scope to the table.
    expect(screen.getByRole("table")).toHaveTextContent("auth.login");
  });

  it("shows an error state instead of crashing", async () => {
    server.use(
      http.get("/users", () => HttpResponse.json([])),
      http.get("/audit-logs", () => HttpResponse.json({ detail: "Service temporarily unavailable" }, { status: 503 })),
    );
    renderWithProviders(<AuditLogsPage />);
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
  });

  it("resolves the actor's email from the users list instead of showing a raw id", async () => {
    server.use(
      http.get("/users", () => HttpResponse.json([userA])),
      http.get("/audit-logs", () => HttpResponse.json([fakeLog({ user_id: userA.id })])),
    );
    renderWithProviders(<AuditLogsPage />);
    // Not a bare screen.getByText("a@example.com") — the same email is
    // also the static option text in the "Filter by user" dropdown, so
    // an unscoped query is ambiguous once both have loaded.
    await waitFor(() => expect(screen.getByRole("table")).toHaveTextContent("a@example.com"));
  });

  it("filters by action, sent to the server", async () => {
    let capturedAction: string | null = "unset";
    server.use(
      http.get("/users", () => HttpResponse.json([userA])),
      http.get("/audit-logs", ({ request }) => {
        capturedAction = new URL(request.url).searchParams.get("action");
        return HttpResponse.json([]);
      }),
    );
    const user = userEvent.setup();

    renderWithProviders(<AuditLogsPage />);
    await waitFor(() => expect(capturedAction).toBeNull());

    await user.selectOptions(screen.getByLabelText("Filter by action"), "user.update");
    await waitFor(() => expect(capturedAction).toBe("user.update"));
  });

  it("filtering by user renders an empty result cleanly when the backend returns none — the same response shape it returns for a foreign-org user_id (the user_id dropdown itself only ever offers same-org users from useUsers(), so a cross-org id can't be selected through this UI at all; the underlying request contract for that case is covered directly in api/auditLogs.test.ts and useAuditLogs.test.tsx)", async () => {
    let capturedUserId: string | null = "unset";
    server.use(
      http.get("/users", () => HttpResponse.json([userA])),
      http.get("/audit-logs", ({ request }) => {
        capturedUserId = new URL(request.url).searchParams.get("user_id");
        return HttpResponse.json([]);
      }),
    );
    const user = userEvent.setup();

    renderWithProviders(<AuditLogsPage />);
    // Not a bare "is the select present" wait — it's present (with only
    // the static "All users" option) from the very first render. Wait
    // for the actual data-derived option instead.
    await waitFor(() => expect(screen.getByRole("option", { name: userA.email })).toBeInTheDocument());

    await user.selectOptions(screen.getByLabelText("Filter by user"), userA.id);

    await waitFor(() => expect(capturedUserId).toBe(userA.id));
    expect(screen.getByText(/no audit log entries match/i)).toBeInTheDocument();
  });

  it("resets to page 1 when a filter changes while on a later page", async () => {
    let capturedOffset: string | null = "unset";
    server.use(
      http.get("/users", () => HttpResponse.json([userA])),
      http.get("/audit-logs", ({ request }) => {
        capturedOffset = new URL(request.url).searchParams.get("offset");
        return HttpResponse.json(Array.from({ length: 25 }, () => fakeLog()));
      }),
    );
    const user = userEvent.setup();

    renderWithProviders(<AuditLogsPage />);
    await waitFor(() => expect(capturedOffset).toBe("0"));
    await waitFor(() => expect(screen.getByRole("button", { name: "Next" })).not.toBeDisabled());
    await user.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(capturedOffset).toBe("25"));

    await user.selectOptions(screen.getByLabelText("Filter by action"), "auth.logout");
    await waitFor(() => expect(capturedOffset).toBe("0"));
    expect(screen.getByText("Page 1")).toBeInTheDocument();
  });

  it("paginates: Next disabled on a short page, enabled on a full page", async () => {
    server.use(
      http.get("/users", () => HttpResponse.json([userA])),
      http.get("/audit-logs", ({ request }) => {
        const offset = new URL(request.url).searchParams.get("offset");
        const count = offset === "0" ? 25 : 3;
        return HttpResponse.json(Array.from({ length: count }, () => fakeLog()));
      }),
    );

    renderWithProviders(<AuditLogsPage />);
    await waitFor(() => expect(screen.getByRole("button", { name: "Next" })).not.toBeDisabled());
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
  });
});
