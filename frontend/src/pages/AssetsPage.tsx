import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useInfiniteAssets, type AssetsFilters } from "../hooks/useInfiniteAssets";
import { useCreateAsset } from "../hooks/useCreateAsset";
import { usePrioritizedAssets } from "../hooks/usePrioritizedAssets";
import { useAuth } from "../auth/useAuth";
import { ApiErrorAlert } from "../components/ApiErrorAlert";
import { DataTable, type DataTableColumn } from "../components/DataTable";
import { AssetStatusBadge } from "../components/AssetStatusBadge";
import { PriorityBadge } from "../components/PriorityBadge";
import type { Asset, AssetCriticality, AssetEnvironment, AssetType, LifecycleStatus } from "../api/assets";
import type { PriorityLevel } from "../api/prioritization";

// Types actually creatable via POST /assets (see
// app/core/validation.py:normalize_asset_value) -- service/
// tls_certificate/web3_*/rpc_endpoint are reserved, not creatable, and
// deliberately excluded here (a 422 gives the same answer server-side,
// but there is no reason to offer them in the picker at all).
const CREATABLE_ASSET_TYPES: AssetType[] = [
  "domain",
  "subdomain",
  "ip_address",
  "ip_range",
  "url",
  "asn",
  "http_endpoint",
  "api",
  "cloud_resource",
  "repository",
];
const ASSET_TYPE_FILTER_OPTIONS: AssetType[] = CREATABLE_ASSET_TYPES;
const STATUS_OPTIONS: LifecycleStatus[] = ["first_seen", "active", "stale", "disappeared"];
const ENVIRONMENT_OPTIONS: AssetEnvironment[] = ["production", "staging", "development", "test", "unknown"];
const CRITICALITY_OPTIONS: AssetCriticality[] = ["low", "medium", "high", "critical"];

const createSchema = z.object({
  asset_type: z.enum(CREATABLE_ASSET_TYPES as [AssetType, ...AssetType[]]),
  value: z.string().min(1, "Value is required").max(255),
  notes: z.string().optional(),
});

type CreateFormValues = z.infer<typeof createSchema>;

// Only admin/analyst can create assets server-side (require_role in
// app/api/routes/assets.py). This hides the form for other roles as a UX
// convenience; the server enforces the real boundary regardless.
const CAN_CREATE_ROLES = new Set(["admin", "analyst"]);

function formatDateTime(value: string): string {
  return new Date(value).toLocaleString();
}

export function AssetsPage() {
  const { user } = useAuth();
  const createAsset = useCreateAsset();

  const [typeFilter, setTypeFilter] = useState<AssetType | "all">("all");
  const [statusFilter, setStatusFilter] = useState<LifecycleStatus | "all">("all");
  const [environmentFilter, setEnvironmentFilter] = useState<AssetEnvironment | "all">("all");
  const [criticalityFilter, setCriticalityFilter] = useState<AssetCriticality | "all">("all");
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");

  useEffect(() => {
    const timeout = setTimeout(() => setDebouncedSearch(search), 300);
    return () => clearTimeout(timeout);
  }, [search]);

  const filters: AssetsFilters = useMemo(
    () => ({
      asset_type: typeFilter === "all" ? undefined : [typeFilter],
      status: statusFilter === "all" ? undefined : [statusFilter],
      environment: environmentFilter === "all" ? undefined : [environmentFilter],
      criticality: criticalityFilter === "all" ? undefined : [criticalityFilter],
      search: debouncedSearch || undefined,
    }),
    [typeFilter, statusFilter, environmentFilter, criticalityFilter, debouncedSearch],
  );

  // Step 9.13: GET /assets now supports server-side filtering (see
  // api/assets.ts) -- every filter above is applied backend-side, not
  // by fetching everything and filtering in the browser.
  const {
    data,
    isLoading,
    error,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteAssets(filters);
  const assets = useMemo(() => data?.pages.flat() ?? [], [data]);

  // Priority is displayed best-effort by joining the already-computed
  // GET /assets/prioritized result (Step 9.10, reused as-is -- never
  // recomputed here) by asset_id. Capped at the endpoint's own max
  // (200): an organization with more assets than that simply shows no
  // priority badge for the excess, a disclosed limitation rather than
  // an N+1 per-row priority fetch.
  const { data: priorities } = usePrioritizedAssets({ limit: 200 });
  const priorityByAssetId = useMemo(() => {
    const map = new Map<string, PriorityLevel>();
    priorities?.forEach((p) => map.set(p.asset_id, p.priority));
    return map;
  }, [priorities]);

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<CreateFormValues>({
    resolver: zodResolver(createSchema),
    defaultValues: { asset_type: "domain", value: "", notes: "" },
  });

  const onSubmit = async (values: CreateFormValues) => {
    try {
      await createAsset.mutateAsync({
        asset_type: values.asset_type,
        value: values.value,
        notes: values.notes || null,
      });
      reset();
    } catch {
      // surfaced via createAsset.error below
    }
  };

  const canCreate = user ? CAN_CREATE_ROLES.has(user.role) : false;

  const columns: DataTableColumn<Asset>[] = [
    {
      key: "value",
      header: "Asset",
      render: (asset) => (
        <Link to={`/assets/${asset.id}`} className="font-mono text-sm text-slate-900 hover:underline">
          {asset.value}
        </Link>
      ),
    },
    { key: "asset_type", header: "Type", render: (asset) => <span className="text-xs">{asset.asset_type}</span> },
    { key: "status", header: "Status", render: (asset) => <AssetStatusBadge status={asset.status} /> },
    {
      key: "priority",
      header: "Priority",
      render: (asset) => {
        const priority = priorityByAssetId.get(asset.id);
        return priority ? <PriorityBadge priority={priority} /> : <span className="text-xs text-slate-400">—</span>;
      },
    },
    {
      key: "environment",
      header: "Environment",
      render: (asset) => <span className="text-xs">{asset.environment ?? "—"}</span>,
    },
    {
      key: "criticality",
      header: "Criticality",
      render: (asset) => <span className="text-xs">{asset.criticality ?? "—"}</span>,
    },
    { key: "last_seen", header: "Last seen", render: (asset) => <span className="text-xs">{formatDateTime(asset.last_seen)}</span> },
  ];

  return (
    <div>
      <h1 className="mb-1 text-xl font-semibold text-slate-900">Attack Surface</h1>
      <p className="mb-4 text-sm text-slate-500">Every asset your organization has confirmed or discovered.</p>

      {canCreate ? (
        <form onSubmit={handleSubmit(onSubmit)} className="mb-6 flex flex-col gap-2 rounded border bg-white p-4" noValidate>
          <h2 className="text-sm font-semibold">Add asset</h2>
          <div className="flex gap-2">
            <select className="rounded border px-2 py-1 text-sm" {...register("asset_type")}>
              {CREATABLE_ASSET_TYPES.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
            <input
              placeholder="e.g. example.com"
              className="flex-1 rounded border px-2 py-1 text-sm"
              {...register("value")}
            />
          </div>
          {errors.value && <span className="text-xs text-red-600">{errors.value.message}</span>}
          <input placeholder="Notes (optional)" className="rounded border px-2 py-1 text-sm" {...register("notes")} />
          {createAsset.error ? <ApiErrorAlert error={createAsset.error} /> : null}
          <button
            type="submit"
            disabled={isSubmitting}
            className="self-start rounded bg-slate-900 px-3 py-2 text-sm text-white disabled:opacity-50"
          >
            {isSubmitting ? "Adding..." : "Add asset"}
          </button>
        </form>
      ) : null}

      <div className="mb-3 flex flex-wrap gap-2">
        <select
          aria-label="Filter by type"
          className="rounded border px-2 py-1 text-sm"
          value={typeFilter}
          onChange={(event) => setTypeFilter(event.target.value as AssetType | "all")}
        >
          <option value="all">All types</option>
          {ASSET_TYPE_FILTER_OPTIONS.map((type) => (
            <option key={type} value={type}>
              {type}
            </option>
          ))}
        </select>
        <select
          aria-label="Filter by status"
          className="rounded border px-2 py-1 text-sm"
          value={statusFilter}
          onChange={(event) => setStatusFilter(event.target.value as LifecycleStatus | "all")}
        >
          <option value="all">All statuses</option>
          {STATUS_OPTIONS.map((status) => (
            <option key={status} value={status}>
              {status}
            </option>
          ))}
        </select>
        <select
          aria-label="Filter by environment"
          className="rounded border px-2 py-1 text-sm"
          value={environmentFilter}
          onChange={(event) => setEnvironmentFilter(event.target.value as AssetEnvironment | "all")}
        >
          <option value="all">All environments</option>
          {ENVIRONMENT_OPTIONS.map((env) => (
            <option key={env} value={env}>
              {env}
            </option>
          ))}
        </select>
        <select
          aria-label="Filter by criticality"
          className="rounded border px-2 py-1 text-sm"
          value={criticalityFilter}
          onChange={(event) => setCriticalityFilter(event.target.value as AssetCriticality | "all")}
        >
          <option value="all">All criticalities</option>
          {CRITICALITY_OPTIONS.map((crit) => (
            <option key={crit} value={crit}>
              {crit}
            </option>
          ))}
        </select>
        <input
          placeholder="Search value..."
          className="flex-1 rounded border px-2 py-1 text-sm"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
      </div>

      <DataTable
        columns={columns}
        rows={assets}
        rowKey={(asset) => asset.id}
        isLoading={isLoading}
        error={error}
        emptyMessage="No assets match this filter."
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
