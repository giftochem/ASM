import type { ScanStatus } from "../api/scans";

const STYLES: Record<ScanStatus, string> = {
  queued: "bg-slate-100 text-slate-700",
  running: "bg-blue-100 text-blue-800",
  completed: "bg-green-100 text-green-800",
  failed: "bg-red-100 text-red-800",
  cancelled: "bg-amber-100 text-amber-800",
};

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  return <span className={`rounded px-2 py-0.5 text-xs ${STYLES[status]}`}>{status}</span>;
}
