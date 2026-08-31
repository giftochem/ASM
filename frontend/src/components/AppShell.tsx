import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { logout } from "../api/auth";
import { useAuth } from "../auth/useAuth";
import { ApiErrorAlert } from "./ApiErrorAlert";

interface NavItem {
  to: string;
  label: string;
  end?: boolean;
}

interface NavGroup {
  heading: string;
  items: NavItem[];
}

// Mirrors the product framing from Step 9.13's own spec: DISCOVER ->
// UNDERSTAND -> CHANGE -> PRIORITIZE -> ACT. Grouping the nav this way
// is a deliberate product decision, not just a menu -- it's meant to be
// legible as "what does my organization expose, what changed, what
// needs attention" at a glance, not just an alphabetical page list.
const NAV_GROUPS: NavGroup[] = [
  {
    heading: "Discover",
    items: [
      { to: "/", label: "Overview", end: true },
      { to: "/assets", label: "Attack Surface" },
    ],
  },
  {
    heading: "Understand & Prioritize",
    items: [
      { to: "/changes", label: "Change Timeline" },
      { to: "/prioritized", label: "Prioritized Assets" },
    ],
  },
  {
    heading: "Act",
    items: [
      { to: "/alerts", label: "Alerts" },
      { to: "/monitoring", label: "Monitoring" },
    ],
  },
  {
    heading: "Operate",
    items: [
      { to: "/scans", label: "Scans" },
      { to: "/findings", label: "Findings" },
      { to: "/reports", label: "Reports" },
    ],
  },
];

const navLinkClassName = ({ isActive }: { isActive: boolean }) =>
  `block rounded px-3 py-1.5 text-sm ${isActive ? "bg-slate-900 text-white" : "text-slate-700 hover:bg-slate-100"}`;

// The one persistent layout wrapping every authenticated route (see
// routes.tsx) -- did not exist before Step 9.13 (every page was its own
// island). Purely a UX/navigation shell: it renders no data of its own
// and enforces nothing -- RequireAuth still gates the whole subtree,
// and RequireRole still gates /settings specifically, both unchanged.
export function AppShell() {
  const { user } = useAuth();
  const [logoutError, setLogoutError] = useState<unknown>(null);

  const handleLogout = async () => {
    setLogoutError(null);
    try {
      await logout();
    } catch (error) {
      setLogoutError(error);
    }
  };

  return (
    <div className="flex min-h-screen bg-slate-50">
      <aside className="w-56 shrink-0 border-r bg-white px-3 py-4">
        <div className="mb-6 px-2 text-sm font-bold tracking-wide text-slate-900">ASM</div>
        <nav className="flex flex-col gap-4">
          {NAV_GROUPS.map((group) => (
            <div key={group.heading}>
              <div className="mb-1 px-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
                {group.heading}
              </div>
              <div className="flex flex-col gap-0.5">
                {group.items.map((item) => (
                  <NavLink key={item.to} to={item.to} end={item.end} className={navLinkClassName}>
                    {item.label}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
          {user?.role === "admin" ? (
            <div>
              <div className="mb-1 px-2 text-xs font-semibold uppercase tracking-wide text-slate-400">Admin</div>
              <NavLink to="/settings" className={navLinkClassName}>
                Settings
              </NavLink>
            </div>
          ) : null}
        </nav>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between border-b bg-white px-6 py-3">
          <span className="text-sm text-slate-500">
            {user?.email} <span className="text-xs text-slate-400">({user?.role})</span>
          </span>
          <button
            type="button"
            onClick={handleLogout}
            className="rounded border px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50"
          >
            Log out
          </button>
        </header>
        {logoutError ? (
          <div className="px-6 pt-3">
            <ApiErrorAlert error={logoutError} />
          </div>
        ) : null}
        <main className="flex-1 overflow-y-auto px-6 py-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
