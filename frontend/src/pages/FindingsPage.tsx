import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useFindings } from "../hooks/useFindings";
import { DataTable, type DataTableColumn } from "../components/DataTable";
import { SeverityBadge } from "../components/SeverityBadge";
import { SCAN_MODULES } from "../api/scans";
import type { Finding, FindingSeverity } from "../api/findings";

const PAGE_SIZE = 25;

const SEVERITY_FILTERS: Array<FindingSeverity | "all"> = ["all", "info", "low", "medium", "high", "critical"];

const columns: DataTableColumn<Finding>[] = [
  { key: "severity", header: "Severity", render: (f) => <SeverityBadge severity={f.severity} /> },
  { key: "title", header: "Title", render: (f) => f.title },
  { key: "module", header: "Module", render: (f) => f.module },
  {
    key: "asset",
    header: "Asset",
    render: (f) => (
      <Link to={`/assets/${f.asset_id}`} className="underline" onClick={(e) => e.stopPropagation()}>
        {f.asset_id.slice(0, 8)}
      </Link>
    ),
  },
  {
    key: "scan",
    header: "Scan",
    render: (f) => (
      <Link to={`/scans/${f.scan_id}`} className="underline" onClick={(e) => e.stopPropagation()}>
        {f.scan_id.slice(0, 8)}
      </Link>
    ),
  },
  { key: "created_at", header: "Found", render: (f) => f.created_at },
];

// Read-only page, no create/mutate actions — every authenticated role can
// see it (GET /findings has no require_role restriction, see
// app/api/routes/findings.py), so unlike Assets/Scans there is no
// role-based UI gate here at all.
export function FindingsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const assetIdFilter = searchParams.get("asset_id") ?? undefined;
  const scanIdFilter = searchParams.get("scan_id") ?? undefined;

  const [severityFilter, setSeverityFilter] = useState<FindingSeverity | "all">("all");
  const [moduleFilter, setModuleFilter] = useState<string>("all");
  const [page, setPage] = useState(0);

  // Any filter change invalidates the current page offset — landing on a
  // stale offset after narrowing a filter would silently show the wrong
  // (or an empty) page instead of the actual first page of new results.
  useEffect(() => {
    setPage(0);
  }, [severityFilter, moduleFilter, assetIdFilter, scanIdFilter]);

  const params = {
    severity: severityFilter === "all" ? undefined : severityFilter,
    module: moduleFilter === "all" ? undefined : moduleFilter,
    asset_id: assetIdFilter,
    scan_id: scanIdFilter,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  };

  const { data: findings, isLoading, error } = useFindings(params);

  // No total-count endpoint — a full page is the only signal a next page
  // might exist. Standard limit/offset heuristic, not exact.
  const hasNextPage = (findings?.length ?? 0) === PAGE_SIZE;

  const clearResourceFilter = () => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete("asset_id");
      next.delete("scan_id");
      return next;
    });
  };

  return (
    <div className="mx-auto mt-10 max-w-4xl">
      <h1 className="mb-4 text-xl font-semibold">Findings</h1>

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <select
          className="rounded border px-2 py-1 text-sm"
          value={severityFilter}
          onChange={(event) => setSeverityFilter(event.target.value as FindingSeverity | "all")}
        >
          {SEVERITY_FILTERS.map((severity) => (
            <option key={severity} value={severity}>
              {severity === "all" ? "All severities" : severity}
            </option>
          ))}
        </select>

        <select
          className="rounded border px-2 py-1 text-sm"
          value={moduleFilter}
          onChange={(event) => setModuleFilter(event.target.value)}
        >
          <option value="all">All modules</option>
          {SCAN_MODULES.map((module) => (
            <option key={module.name} value={module.name}>
              {module.label}
            </option>
          ))}
        </select>

        {assetIdFilter || scanIdFilter ? (
          <button type="button" onClick={clearResourceFilter} className="text-sm underline">
            Clear {assetIdFilter ? "asset" : "scan"} filter
          </button>
        ) : null}
      </div>

      <DataTable
        columns={columns}
        rows={findings ?? []}
        rowKey={(finding) => finding.id}
        isLoading={isLoading}
        error={error}
        emptyMessage="No findings match this filter."
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
