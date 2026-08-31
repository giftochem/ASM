import type { ReactNode } from "react";
import { Link } from "react-router-dom";

interface StatCardProps {
  label: string;
  value: ReactNode;
  to?: string;
  hint?: string;
}

// Small, reusable stat tile for the Overview page -- deliberately plain
// (no icon library exists in this project, see frontend architecture
// notes) so it's just a bordered box with a big number, consistent with
// every other hand-rolled Tailwind component already in components/.
export function StatCard({ label, value, to, hint }: StatCardProps) {
  const boxClassName = `rounded border bg-white p-4 ${to ? "transition hover:border-slate-300 hover:shadow-sm" : ""}`;
  const content = (
    <div className={boxClassName}>
      <div className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-1 text-2xl font-semibold text-slate-900">{value}</div>
      {hint ? <div className="mt-1 text-xs text-slate-400">{hint}</div> : null}
    </div>
  );

  if (to) {
    return (
      <Link to={to} className="block">
        {content}
      </Link>
    );
  }
  return content;
}
