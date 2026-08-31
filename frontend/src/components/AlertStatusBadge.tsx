import type { AlertStatus } from "../api/alerts";

const STYLES: Record<AlertStatus, string> = {
  open: "bg-red-100 text-red-800",
  acknowledged: "bg-amber-100 text-amber-800",
  resolved: "bg-green-100 text-green-800",
};

export function AlertStatusBadge({ status }: { status: AlertStatus }) {
  return <span className={`rounded px-2 py-0.5 text-xs font-medium ${STYLES[status]}`}>{status}</span>;
}
