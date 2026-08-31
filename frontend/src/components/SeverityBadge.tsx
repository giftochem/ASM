type Severity = "info" | "minimal" | "low" | "medium" | "high" | "critical";

const STYLES: Record<Severity, string> = {
  info: "bg-slate-100 text-slate-700",
  minimal: "bg-slate-100 text-slate-700",
  low: "bg-sky-100 text-sky-800",
  medium: "bg-amber-100 text-amber-800",
  high: "bg-orange-100 text-orange-800",
  critical: "bg-red-100 text-red-800",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`rounded px-2 py-0.5 text-xs ${STYLES[severity]}`}>{severity}</span>;
}
