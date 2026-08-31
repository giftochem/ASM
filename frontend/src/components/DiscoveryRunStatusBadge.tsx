import type { DiscoveryRunStatus } from "../api/discovery";

const STYLES: Record<DiscoveryRunStatus, string> = {
  queued: "bg-slate-100 text-slate-700",
  running: "bg-sky-100 text-sky-800",
  completed: "bg-green-100 text-green-800",
  failed: "bg-red-100 text-red-800",
  cancelled: "bg-amber-100 text-amber-800",
};

export function DiscoveryRunStatusBadge({ status }: { status: DiscoveryRunStatus }) {
  return <span className={`rounded px-2 py-0.5 text-xs font-medium ${STYLES[status]}`}>{status}</span>;
}
