import { describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderWithProviders } from "../test/renderWithProviders";
import { useAuth } from "../auth/useAuth";
import { AppShell } from "./AppShell";

vi.mock("../auth/useAuth");
const mockedUseAuth = vi.mocked(useAuth);

const adminUser = { id: "u1", email: "admin@example.com", organization_id: "org-1", role: "admin" as const };
const viewerUser = { id: "u2", email: "viewer@example.com", organization_id: "org-1", role: "viewer" as const };

function mockAuth(user: typeof adminUser | typeof viewerUser) {
  mockedUseAuth.mockReturnValue({ user: user as never, isLoading: false, isAuthenticated: true });
}

describe("AppShell", () => {
  it("renders every primary nav destination", () => {
    mockAuth(adminUser);
    renderWithProviders(<AppShell />);

    for (const label of ["Overview", "Attack Surface", "Change Timeline", "Prioritized Assets", "Exposure Paths", "Alerts", "Monitoring", "Scans", "Findings", "Reports"]) {
      expect(screen.getByRole("link", { name: label })).toBeInTheDocument();
    }
  });

  it("shows Settings only for an admin", () => {
    mockAuth(adminUser);
    renderWithProviders(<AppShell />);
    expect(screen.getByRole("link", { name: "Settings" })).toBeInTheDocument();
  });

  it("hides Settings for a non-admin (RBAC visibility — UX guard only, server enforces the real boundary)", () => {
    mockAuth(viewerUser);
    renderWithProviders(<AppShell />);
    expect(screen.queryByRole("link", { name: "Settings" })).not.toBeInTheDocument();
  });

  it("shows the current user's email and role", () => {
    mockAuth(viewerUser);
    renderWithProviders(<AppShell />);
    expect(screen.getByText("viewer@example.com")).toBeInTheDocument();
    expect(screen.getByText("(viewer)")).toBeInTheDocument();
  });

  it("logs out on click and surfaces a failure instead of crashing", async () => {
    mockAuth(adminUser);
    server.use(http.post("/auth/logout", () => HttpResponse.json({ detail: "boom" }, { status: 500 })));
    const user = userEvent.setup();

    renderWithProviders(<AppShell />);
    await user.click(screen.getByRole("button", { name: /log out/i }));

    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
  });
});
