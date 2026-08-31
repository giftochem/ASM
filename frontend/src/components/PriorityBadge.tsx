// Shared by Alert.priority (AlertPriority) and AssetPriority.priority
// (PriorityLevel) -- Step 9.12 deliberately gave AlertPriority the exact
// same 5-value vocabulary as PriorityLevel (see backend
// app/core/enums.py), so one badge covers both rather than two
// near-identical components.
type Priority = "informational" | "low" | "medium" | "high" | "critical";

const STYLES: Record<Priority, string> = {
  informational: "bg-slate-100 text-slate-700",
  low: "bg-sky-100 text-sky-800",
  medium: "bg-amber-100 text-amber-800",
  high: "bg-orange-100 text-orange-800",
  critical: "bg-red-100 text-red-800",
};

export function PriorityBadge({ priority }: { priority: Priority }) {
  return <span className={`rounded px-2 py-0.5 text-xs font-medium ${STYLES[priority]}`}>{priority}</span>;
}
