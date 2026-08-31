import { useState } from "react";
import { Link } from "react-router-dom";
import { useAlerts } from "../hooks/useAlerts";
import { useAcknowledgeAlert } from "../hooks/useAcknowledgeAlert";
import { useResolveAlert } from "../hooks/useResolveAlert";
import { useAuth } from "../auth/useAuth";
import { ApiErrorAlert } from "../components/ApiErrorAlert";
import { DataTable, type DataTableColumn } from "../components/DataTable";
import { AlertStatusBadge } from "../components/AlertStatusBadge";
import { PriorityBadge } from "../components/PriorityBadge";
import type { Alert, AlertStatus } from "../api/alerts";

const CAN_ACT_ROLES = new Set(["admin", "analyst"]);
const STATUS_OPTIONS: AlertStatus[] = ["open", "acknowledged", "resolved"];

function formatDateTime(value: string): string {
  return new Date(value).toLocaleString();
}

function AlertDetailModal({ alert, onClose }: { alert: Alert; onClose: () => void }) {
  const { user } = useAuth();
  const acknowledge = useAcknowledgeAlert(alert.id);
  const resolve = useResolveAlert(alert.id);
  const canAct = user ? CAN_ACT_ROLES.has(user.role) : false;

  return (
    <div role="dialog" aria-modal="true" aria-label={alert.title} className="fixed inset-0 z-10 flex items-center justify-center bg-black/40 p-4">
      <div className="max-h-[85vh] w-full max-w-lg overflow-y-auto rounded bg-white p-5 shadow-lg">
        <div className="mb-2 flex items-start justify-between gap-2">
          <h2 className="text-lg font-semibold">{alert.title}</h2>
          <AlertStatusBadge status={alert.status} />
        </div>
        <div className="mb-3 flex items-center gap-2">
          <PriorityBadge priority={alert.priority} />
          <span className="text-xs text-slate-400">{alert.alert_type.replaceAll("_", " ")}</span>
        </div>
        <p className="mb-3 text-sm text-slate-700">{alert.description}</p>

        {alert.asset_value ? (
          <p className="mb-3 text-sm">
            Asset:{" "}
            <Link to={`/assets/${alert.asset_id}`} className="font-mono text-xs underline">
              {alert.asset_value}
            </Link>
          </p>
        ) : null}

        <dl className="mb-3 grid grid-cols-2 gap-y-1 text-xs text-slate-500">
          <dt>First seen</dt>
          <dd>{formatDateTime(alert.first_seen_at)}</dd>
          <dt>Last seen</dt>
          <dd>{formatDateTime(alert.last_seen_at)}</dd>
          <dt>Occurrences</dt>
          <dd>{alert.occurrence_count}</dd>
        </dl>

        {alert.evidence ? (
          <details className="mb-3">
            <summary className="cursor-pointer text-xs text-slate-500">Evidence</summary>
            <pre className="mt-1 max-h-40 overflow-auto rounded bg-slate-50 p-2 text-xs">
              {JSON.stringify(alert.evidence, null, 2)}
            </pre>
          </details>
        ) : null}

        {acknowledge.error ? <ApiErrorAlert error={acknowledge.error} /> : null}
        {resolve.error ? <ApiErrorAlert error={resolve.error} /> : null}

        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded border px-3 py-2 text-sm">
            Close
          </button>
          {canAct && alert.status === "open" ? (
            <button
              type="button"
              onClick={() => acknowledge.mutate()}
              disabled={acknowledge.isPending}
              className="rounded border px-3 py-2 text-sm disabled:opacity-50"
            >
              {acknowledge.isPending ? "Working..." : "Acknowledge"}
            </button>
          ) : null}
          {canAct && alert.status !== "resolved" ? (
            <button
              type="button"
              onClick={() => resolve.mutate()}
              disabled={resolve.isPending}
              className="rounded bg-slate-900 px-3 py-2 text-sm text-white disabled:opacity-50"
            >
              {resolve.isPending ? "Working..." : "Resolve"}
            </button>
          ) : null}
        </div>
      </div>
    </div>
  );
}

export function AlertsPage() {
  const [statusFilter, setStatusFilter] = useState<AlertStatus | "all">("open");
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);

  const { data: alerts, isLoading, error } = useAlerts({
    status: statusFilter === "all" ? undefined : [statusFilter],
    limit: 100,
  });

  const selectedAlert = alerts?.find((a) => a.id === selectedAlertId) ?? null;

  const columns: DataTableColumn<Alert>[] = [
    { key: "title", header: "Alert", render: (alert) => <span className="text-sm">{alert.title}</span> },
    {
      key: "asset",
      header: "Asset",
      render: (alert) => (alert.asset_value ? <span className="font-mono text-xs">{alert.asset_value}</span> : "—"),
    },
    { key: "priority", header: "Priority", render: (alert) => <PriorityBadge priority={alert.priority} /> },
    { key: "occurrence_count", header: "Occurrences", render: (alert) => <span className="text-xs">{alert.occurrence_count}</span> },
    { key: "last_seen_at", header: "Last seen", render: (alert) => <span className="text-xs">{formatDateTime(alert.last_seen_at)}</span> },
    { key: "status", header: "Status", render: (alert) => <AlertStatusBadge status={alert.status} /> },
  ];

  return (
    <div>
      <h1 className="mb-1 text-xl font-semibold text-slate-900">Alerts</h1>
      <p className="mb-4 text-sm text-slate-500">
        Meaningful changes to your attack surface that deserve a human's attention.
      </p>

      <div className="mb-3">
        <select
          aria-label="Filter by status"
          className="rounded border px-2 py-1 text-sm"
          value={statusFilter}
          onChange={(event) => setStatusFilter(event.target.value as AlertStatus | "all")}
        >
          <option value="all">All statuses</option>
          {STATUS_OPTIONS.map((status) => (
            <option key={status} value={status}>
              {status}
            </option>
          ))}
        </select>
      </div>

      <DataTable
        columns={columns}
        rows={alerts ?? []}
        rowKey={(alert) => alert.id}
        isLoading={isLoading}
        error={error}
        emptyMessage="No alerts match this filter."
        onRowClick={(alert) => setSelectedAlertId(alert.id)}
      />

      {selectedAlert ? <AlertDetailModal alert={selectedAlert} onClose={() => setSelectedAlertId(null)} /> : null}
    </div>
  );
}
