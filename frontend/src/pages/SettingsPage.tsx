import { NavLink, Outlet } from "react-router-dom";

const linkClass = ({ isActive }: { isActive: boolean }) =>
  `rounded px-3 py-1 text-sm ${isActive ? "bg-slate-900 text-white" : "border"}`;

/**
 * Admin-only subtree layout. The RequireRole(admin) wrapper lives on the
 * route (see routes.tsx), not here — and it is UX only. Every endpoint
 * beneath this page (GET/POST/PATCH /users, GET /audit-logs) independently
 * enforces require_role(admin) server-side and scopes results to the
 * caller's own organization, so a non-admin reaching this subtree by URL
 * still cannot read or change anything.
 */
export function SettingsPage() {
  return (
    <div className="mx-auto mt-10 max-w-4xl">
      <h1 className="mb-4 text-xl font-semibold">Settings</h1>
      <nav className="mb-6 flex gap-2">
        <NavLink to="/settings/users" className={linkClass}>
          Users
        </NavLink>
        <NavLink to="/settings/audit-logs" className={linkClass}>
          Audit logs
        </NavLink>
      </nav>
      <Outlet />
    </div>
  );
}
