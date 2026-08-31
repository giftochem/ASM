import { createBrowserRouter, Navigate } from "react-router-dom";
import { RequireAuth } from "./auth/RequireAuth";
import { RequireRole } from "./auth/RequireRole";
import { AppShell } from "./components/AppShell";
import { LoginPage } from "./pages/LoginPage";
import { RegisterPage } from "./pages/RegisterPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { OverviewPage } from "./pages/OverviewPage";
import { AssetsPage } from "./pages/AssetsPage";
import { AssetDetailPage } from "./pages/AssetDetailPage";
import { ChangeTimelinePage } from "./pages/ChangeTimelinePage";
import { AlertsPage } from "./pages/AlertsPage";
import { PrioritizedAssetsPage } from "./pages/PrioritizedAssetsPage";
import { MonitoringPage } from "./pages/MonitoringPage";
import { ScansPage } from "./pages/ScansPage";
import { ScanDetailPage } from "./pages/ScanDetailPage";
import { FindingsPage } from "./pages/FindingsPage";
import { ReportsPage } from "./pages/ReportsPage";
import { SettingsPage } from "./pages/SettingsPage";
import { UsersPage } from "./pages/settings/UsersPage";
import { AuditLogsPage } from "./pages/settings/AuditLogsPage";

// Step 9.13: every authenticated route now renders inside AppShell (the
// persistent nav/header layout that didn't exist before this step) via
// a single parent layout route, rather than each route wrapping itself
// individually. RequireAuth still gates the whole subtree exactly as
// before -- this only changes how the JSX tree composes the pages, not
// which paths exist or what protects them.
export const router = createBrowserRouter([
  {
    element: (
      <RequireAuth>
        <AppShell />
      </RequireAuth>
    ),
    children: [
      { index: true, element: <OverviewPage /> },
      { path: "assets", element: <AssetsPage /> },
      { path: "assets/:assetId", element: <AssetDetailPage /> },
      { path: "changes", element: <ChangeTimelinePage /> },
      { path: "alerts", element: <AlertsPage /> },
      { path: "prioritized", element: <PrioritizedAssetsPage /> },
      { path: "monitoring", element: <MonitoringPage /> },
      { path: "scans", element: <ScansPage /> },
      { path: "scans/:scanId", element: <ScanDetailPage /> },
      { path: "findings", element: <FindingsPage /> },
      { path: "reports", element: <ReportsPage /> },
      {
        path: "settings",
        element: (
          <RequireRole roles={["admin"]}>
            <SettingsPage />
          </RequireRole>
        ),
        children: [
          { index: true, element: <Navigate to="/settings/users" replace /> },
          { path: "users", element: <UsersPage /> },
          { path: "audit-logs", element: <AuditLogsPage /> },
        ],
      },
    ],
  },
  { path: "/login", element: <LoginPage /> },
  { path: "/register", element: <RegisterPage /> },
  { path: "*", element: <NotFoundPage /> },
]);
