import type { ReportStatus } from "../api/reports";

const STYLES: Record<ReportStatus, string> = {
  pending: "bg-slate-100 text-slate-700",
  generating: "bg-blue-100 text-blue-800",
  completed: "bg-green-100 text-green-800",
  failed: "bg-red-100 text-red-800",
};

export function ReportStatusBadge({ status }: { status: ReportStatus }) {
  return <span className={`rounded px-2 py-0.5 text-xs ${STYLES[status]}`}>{status}</span>;
}
