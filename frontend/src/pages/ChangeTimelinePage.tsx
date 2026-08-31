import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useInfiniteActivityFeed } from "../hooks/useInfiniteActivityFeed";
import { DataTable, type DataTableColumn } from "../components/DataTable";
import type { ActivityFeedItem, ChangeType } from "../api/activity";

// Plain-language label for each ChangeType this endpoint can emit --
// "Make the event understandable to a non-expert customer" (Step 9.13
// spec). Purely presentational: the underlying value/meaning is 100%
// backend-defined (app/core/enums.py's ChangeType), this only translates
// the label, never reinterprets the event.
const CHANGE_TYPE_LABELS: Record<ChangeType, string> = {
  asset_created: "New asset discovered",
  asset_updated: "Asset details changed",
  asset_status_changed: "Asset status changed",
  relationship_created: "New relationship discovered",
  relationship_updated: "Relationship reconfirmed",
  relationship_removed: "Relationship disappeared",
  dns_records_observed: "DNS records observed",
  certificate_observed: "TLS certificate observed",
  certificate_changed: "TLS certificate changed",
  certificate_transparency_observed: "Certificate Transparency evidence observed",
  http_observed: "HTTP/HTTPS reachability observed",
  http_changed: "HTTP/HTTPS behavior changed",
  network_observed: "Network/ASN details observed",
  network_changed: "Network/ASN details changed",
  infrastructure_observed: "Cloud/infrastructure classification observed",
  infrastructure_changed: "Cloud/infrastructure classification changed",
};

const CHANGE_TYPE_FILTER_GROUPS: { label: string; types: ChangeType[] }[] = [
  { label: "New assets", types: ["asset_created"] },
  { label: "Asset changes", types: ["asset_updated", "asset_status_changed"] },
  { label: "Relationship changes", types: ["relationship_created", "relationship_updated", "relationship_removed"] },
  { label: "Certificate changes", types: ["certificate_observed", "certificate_changed", "certificate_transparency_observed"] },
  { label: "DNS changes", types: ["dns_records_observed"] },
  { label: "HTTP changes", types: ["http_observed", "http_changed"] },
  { label: "Infrastructure changes", types: ["network_observed", "network_changed", "infrastructure_observed", "infrastructure_changed"] },
];

function formatDateTime(value: string): string {
  return new Date(value).toLocaleString();
}

export function ChangeTimelinePage() {
  const [groupFilter, setGroupFilter] = useState("all");

  const changeTypeFilter = useMemo(() => {
    if (groupFilter === "all") return undefined;
    return CHANGE_TYPE_FILTER_GROUPS.find((g) => g.label === groupFilter)?.types;
  }, [groupFilter]);

  const { data, isLoading, error, fetchNextPage, hasNextPage, isFetchingNextPage } = useInfiniteActivityFeed({
    change_type: changeTypeFilter,
  });
  const entries = useMemo(() => data?.pages.flat() ?? [], [data]);

  const columns: DataTableColumn<ActivityFeedItem>[] = [
    {
      key: "observed_at",
      header: "When",
      render: (entry) => <span className="text-xs">{formatDateTime(entry.observed_at)}</span>,
    },
    {
      key: "asset",
      header: "Asset",
      render: (entry) => (
        <Link to={`/assets/${entry.asset_id}`} className="font-mono text-xs hover:underline">
          {entry.asset_value}
        </Link>
      ),
    },
    {
      key: "change_type",
      header: "Change",
      render: (entry) => <span>{CHANGE_TYPE_LABELS[entry.change_type] ?? entry.change_type}</span>,
    },
    {
      key: "detail",
      header: "Detail",
      render: (entry) => <span className="text-xs text-slate-500">{entry.field_name ?? "—"}</span>,
    },
    {
      key: "source",
      header: "Source",
      render: (entry) => <span className="text-xs text-slate-400">{entry.source}</span>,
    },
  ];

  return (
    <div>
      <h1 className="mb-1 text-xl font-semibold text-slate-900">Change Timeline</h1>
      <p className="mb-4 text-sm text-slate-500">
        A chronological record of everything discovery has observed about your organization's attack surface.
      </p>

      <div className="mb-3">
        <select
          aria-label="Filter by change category"
          className="rounded border px-2 py-1 text-sm"
          value={groupFilter}
          onChange={(event) => setGroupFilter(event.target.value)}
        >
          <option value="all">All changes</option>
          {CHANGE_TYPE_FILTER_GROUPS.map((group) => (
            <option key={group.label} value={group.label}>
              {group.label}
            </option>
          ))}
        </select>
      </div>

      <DataTable
        columns={columns}
        rows={entries}
        rowKey={(entry) => entry.id}
        isLoading={isLoading}
        error={error}
        emptyMessage="No activity recorded yet."
      />

      {hasNextPage ? (
        <div className="mt-3">
          <button
            type="button"
            onClick={() => fetchNextPage()}
            disabled={isFetchingNextPage}
            className="rounded border px-3 py-1.5 text-sm disabled:opacity-50"
          >
            {isFetchingNextPage ? "Loading..." : "Load more"}
          </button>
        </div>
      ) : null}
    </div>
  );
}
