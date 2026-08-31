import type { LifecycleStatus } from "../api/assets";

const STYLES: Record<LifecycleStatus, string> = {
  first_seen: "bg-sky-100 text-sky-800",
  active: "bg-green-100 text-green-800",
  stale: "bg-amber-100 text-amber-800",
  disappeared: "bg-slate-200 text-slate-600",
};

const LABELS: Record<LifecycleStatus, string> = {
  first_seen: "New",
  active: "Active",
  stale: "Stale",
  disappeared: "Disappeared",
};

export function AssetStatusBadge({ status }: { status: LifecycleStatus }) {
  return <span className={`rounded px-2 py-0.5 text-xs font-medium ${STYLES[status]}`}>{LABELS[status]}</span>;
}
