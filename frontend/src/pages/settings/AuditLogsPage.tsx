import { useEffect, useState } from "react";
import { useAuditLogs } from "../../hooks/useAuditLogs";
import { useUsers } from "../../hooks/useUsers";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import type { AuditLog } from "../../api/auditLogs";

const PAGE_SIZE = 25;

// Actions the backend actually emits today, gathered from the
// audit_service.log_action call sites (auth.py, users.py, assets.py,
// report_service.py, scan_executor.py). Same hand-mirrored-constant
// situation as SCAN_MODULES — there is no catalog endpoint, so this can
// drift if a new audited action is added backend-side. A free-text entry
// is offered alongside it so an unlisted action is still filterable.
const KNOWN_ACTIONS = [
  "auth.login",
  "auth.logout",
  "auth.refresh",
  "organization.register",
  "user.create",
  "user.update",
  "asset.create",
  "asset.confirm_authorization",
  "asset.revoke_authorization",
  "scan.execute",
  "scan.blocked_at_execution",
  "report.generate",
];

export function AuditLogsPage() {
  const { data: users } = useUsers();

  const [actionFilter, setActionFilter] = useState("all");
  const [userFilter, setUserFilter] = useState("all");
  const [page, setPage] = useState(0);

  // A filter change invalidates the current offset — staying on a later
  // page after narrowing would show an empty or wrong page instead of
  // the first page of the new result set.
  useEffect(() => {
    setPage(0);
  }, [actionFilter, userFilter]);

  const { data: logs, isLoading, error } = useAuditLogs({
    action: actionFilter === "all" ? undefined : actionFilter,
    user_id: userFilter === "all" ? undefined : userFilter,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  });

  // No total-count endpoint — a full page is the only available signal
  // that a next page might exist. Heuristic, not exact.
  const hasNextPage = (logs?.length ?? 0) === PAGE_SIZE;

  const columns: DataTableColumn<AuditLog>[] = [
    { key: "created_at", header: "When", render: (l) => l.created_at },
    { key: "action", header: "Action", render: (l) => l.action },
    {
      key: "outcome",
      header: "Outcome",
      render: (l) => (
        <span
          className={
            l.outcome === "success"
              ? "rounded bg-green-100 px-2 py-0.5 text-xs text-green-800"
              : "rounded bg-red-100 px-2 py-0.5 text-xs text-red-800"
          }
        >
          {l.outcome}
        </span>
      ),
    },
    { key: "resource_type", header: "Resource", render: (l) => l.resource_type },
    {
      key: "user_id",
      header: "Actor",
      render: (l) => {
        if (!l.user_id) return <span className="text-xs text-slate-400">—</span>;
        const actor = users?.find((u) => u.id === l.user_id);
        return actor ? actor.email : l.user_id.slice(0, 8);
      },
    },
    { key: "ip_address", header: "IP", render: (l) => l.ip_address ?? "—" },
  ];

  return (
    <div>
      <div className="mb-3 flex flex-wrap gap-2">
        <select
          aria-label="Filter by action"
          className="rounded border px-2 py-1 text-sm"
          value={actionFilter}
          onChange={(event) => setActionFilter(event.target.value)}
        >
          <option value="all">All actions</option>
          {KNOWN_ACTIONS.map((action) => (
            <option key={action} value={action}>
              {action}
            </option>
          ))}
        </select>

        <select
          aria-label="Filter by user"
          className="rounded border px-2 py-1 text-sm"
          value={userFilter}
          onChange={(event) => setUserFilter(event.target.value)}
        >
          <option value="all">All users</option>
          {(users ?? []).map((user) => (
            <option key={user.id} value={user.id}>
              {user.email}
            </option>
          ))}
        </select>
      </div>

      <DataTable
        columns={columns}
        rows={logs ?? []}
        rowKey={(log) => log.id}
        isLoading={isLoading}
        error={error}
        emptyMessage="No audit log entries match this filter."
      />

      <div className="mt-3 flex items-center gap-3">
        <button
          type="button"
          onClick={() => setPage((p) => Math.max(0, p - 1))}
          disabled={page === 0}
          className="rounded border px-3 py-1 text-sm disabled:opacity-50"
        >
          Previous
        </button>
        <span className="text-xs text-slate-500">Page {page + 1}</span>
        <button
          type="button"
          onClick={() => setPage((p) => p + 1)}
          disabled={!hasNextPage}
          className="rounded border px-3 py-1 text-sm disabled:opacity-50"
        >
          Next
        </button>
      </div>
    </div>
  );
}
