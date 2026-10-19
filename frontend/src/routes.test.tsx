import { describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { Navigate, Route, Routes } from "react-router-dom";
import { http, HttpResponse } from "msw";
import { server } from "./test/server";
import { renderWithProviders } from "./test/renderWithProviders";
import { useAuth } from "./auth/useAuth";
import { RequireAuth } from "./auth/RequireAuth";
import { RequireRole } from "./auth/RequireRole";
import { AppShell } from "./components/AppShell";
import { AlertsPage } from "./pages/AlertsPage";
import { ExposurePathsPage } from "./pages/ExposurePathsPage";
import { SettingsPage } from "./pages/SettingsPage";
import { UsersPage } from "./pages/settings/UsersPage";

vi.mock("./auth/useAuth");
const mockedUseAuth = vi.mocked(useAuth);

// Step 9.13 restructured routes.tsx so every authenticated page renders
// under one shared AppShell layout route, instead of each route
// individually wrapping itself in RequireAuth (see routes.tsx's own
// comment). RequireAuth/RequireRole's own gating logic is already
// covered in isolation by auth/RequireAuth.test.tsx and
// auth/RequireRole.test.tsx -- what's worth proving here is that the
// same nested composition routes.tsx now uses (RequireAuth > AppShell >
// page, and RequireAuth > RequireRole > SettingsPage) still protects
// pages correctly once actually nested together.
//
// This intentionally mirrors routes.tsx's route tree as JSX rather than
// importing and driving the real `router` object through RouterProvider:
// every other test in this codebase renders via a plain <MemoryRouter>/
// <Routes> (see test/renderWithProviders.tsx), and RouterProvider's data-
// router (loaders/fetchers, used by createBrowserRouter/createMemoryRouter)
// hits a real cross-realm AbortSignal incompatibility between jsdom and
// MSW/undici in this environment -- unrelated to routes.tsx's own logic,
// and avoided entirely by testing the same composition declaratively.
function renderRouteTreeAt(route: string) {
  return renderWithProviders(
    <Routes>
      <Route
        element={
          <RequireAuth>
            <AppShell />
          </RequireAuth>
        }
      >
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/exposure-paths" element={<ExposurePathsPage />} />
        <Route
          path="/settings"
          element={
            <RequireRole roles={["admin"]}>
              <SettingsPage />
            </RequireRole>
          }
        >
          <Route index element={<Navigate to="/settings/users" replace />} />
          <Route path="users" element={<UsersPage />} />
        </Route>
      </Route>
      <Route path="/login" element={<h1>Log in</h1>} />
    </Routes>,
    { route },
  );
}

describe("protected routes (routes.tsx composition)", () => {
  it("redirects an unauthenticated visitor away from a new Step 9.13 route", async () => {
    mockedUseAuth.mockReturnValue({ user: null, isLoading: false, isAuthenticated: false });

    renderRouteTreeAt("/alerts");

    await waitFor(() => expect(screen.getByRole("heading", { name: /log in/i })).toBeInTheDocument());
  });

  it("renders the requested page inside AppShell for an authenticated admin", async () => {
    mockedUseAuth.mockReturnValue({
      user: { id: "u1", email: "admin@example.com", organization_id: "org-1", role: "admin" } as never,
      isLoading: false,
      isAuthenticated: true,
    });
    server.use(http.get("/alerts", () => HttpResponse.json([])));

    renderRouteTreeAt("/alerts");

    // AppShell's own nav (not part of AlertsPage itself) proves the
    // page is actually rendering inside the shared shell, not standalone.
    await waitFor(() => expect(screen.getByRole("link", { name: "Overview" })).toBeInTheDocument());
    expect(screen.getByRole("heading", { name: "Alerts" })).toBeInTheDocument();
  });

  it("serves /exposure-paths inside AppShell for any authenticated role, and only then", async () => {
    mockedUseAuth.mockReturnValue({ user: null, isLoading: false, isAuthenticated: false });
    const { unmount } = renderRouteTreeAt("/exposure-paths");
    await waitFor(() => expect(screen.getByRole("heading", { name: /log in/i })).toBeInTheDocument());
    unmount();

    mockedUseAuth.mockReturnValue({
      user: { id: "u2", email: "viewer@example.com", organization_id: "org-1", role: "viewer" } as never,
      isLoading: false,
      isAuthenticated: true,
    });
    server.use(http.get("/assets/exposure-paths", () => HttpResponse.json({ detail: "Service temporarily unavailable" }, { status: 503 })));
    renderRouteTreeAt("/exposure-paths");

    await waitFor(() => expect(screen.getByRole("link", { name: "Exposure Paths" })).toBeInTheDocument());
    expect(screen.getByRole("heading", { name: "Exposure Paths" })).toBeInTheDocument();
  });

  it("still gates /settings behind RequireRole(['admin']) within the restructured tree", async () => {
    mockedUseAuth.mockReturnValue({
      user: { id: "u2", email: "viewer@example.com", organization_id: "org-1", role: "viewer" } as never,
      isLoading: false,
      isAuthenticated: true,
    });

    renderRouteTreeAt("/settings/users");

    await waitFor(() => expect(screen.getByText(/not authorized/i)).toBeInTheDocument());
  });

  it("lets an authenticated admin reach /settings/users", async () => {
    mockedUseAuth.mockReturnValue({
      user: { id: "u1", email: "admin@example.com", organization_id: "org-1", role: "admin" } as never,
      isLoading: false,
      isAuthenticated: true,
    });
    server.use(http.get("/users", () => HttpResponse.json([])));

    renderRouteTreeAt("/settings/users");

    await waitFor(() => expect(screen.getByRole("link", { name: "Overview" })).toBeInTheDocument());
  });
});
