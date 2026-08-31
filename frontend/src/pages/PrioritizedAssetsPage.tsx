import { useState } from "react";
import { Link } from "react-router-dom";
import { usePrioritizedAssets } from "../hooks/usePrioritizedAssets";
import { ApiErrorAlert } from "../components/ApiErrorAlert";
import { PriorityBadge } from "../components/PriorityBadge";
import type { PriorityLevel } from "../api/prioritization";

const PRIORITY_OPTIONS: PriorityLevel[] = ["critical", "high", "medium", "low", "informational"];
const LIMIT = 100;

// Step 9.10/9.13: this page never computes priority itself -- it only
// displays exactly what GET /assets/prioritized already returned
// (priority, dimensions, reasons, confidence), the same
// batched/explainable evaluation the backend already proved correct.
export function PrioritizedAssetsPage() {
  const [priorityFilter, setPriorityFilter] = useState<PriorityLevel | "all">("all");

  const { data: results, isLoading, error } = usePrioritizedAssets({
    priority: priorityFilter === "all" ? undefined : [priorityFilter],
    limit: LIMIT,
  });

  return (
    <div>
      <h1 className="mb-1 text-xl font-semibold text-slate-900">Prioritized Assets</h1>
      <p className="mb-4 text-sm text-slate-500">
        What should you investigate first? Explainable, computed fresh from exposure, business context, recent
        change, and connectivity -- never a guarantee of exploitability.
      </p>

      <div className="mb-3">
        <select
          aria-label="Filter by priority"
          className="rounded border px-2 py-1 text-sm"
          value={priorityFilter}
          onChange={(event) => setPriorityFilter(event.target.value as PriorityLevel | "all")}
        >
          <option value="all">All priorities</option>
          {PRIORITY_OPTIONS.map((level) => (
            <option key={level} value={level}>
              {level}
            </option>
          ))}
        </select>
      </div>

      {isLoading ? <p className="text-sm text-slate-500">Loading...</p> : null}
      {error ? <ApiErrorAlert error={error} /> : null}
      {!isLoading && !error && (results?.length ?? 0) === 0 ? (
        <p className="text-sm text-slate-500">No assets match this filter.</p>
      ) : null}

      {results && results.length > 0 ? (
        <ul className="flex flex-col gap-3">
          {results.map((result) => (
            <li key={result.asset_id} className="rounded border bg-white p-4">
              <div className="mb-1 flex items-center justify-between gap-2">
                <Link to={`/assets/${result.asset_id}`} className="font-mono text-sm hover:underline">
                  {result.asset_value}
                </Link>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-400">
                    {result.confidence_label} confidence ({result.confidence_value.toFixed(2)})
                  </span>
                  <PriorityBadge priority={result.priority} />
                </div>
              </div>
              <div className="mb-2 grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-slate-500 sm:grid-cols-5">
                <span>Exposure: {result.dimensions.exposure}</span>
                <span>Business: {result.dimensions.business_criticality}</span>
                <span>Change: {result.dimensions.change_recency}</span>
                <span>Connectivity: {result.dimensions.connectivity_relevance}</span>
                <span>Evidence: {result.dimensions.evidence_confidence}</span>
              </div>
              {result.reasons.length > 0 ? (
                <ul className="space-y-1 text-sm">
                  {result.reasons.map((reason, index) => (
                    <li key={`${reason.signal}-${index}`} className="flex items-start justify-between gap-2 rounded bg-slate-50 px-2 py-1">
                      <span className="text-slate-700">{reason.description}</span>
                      <span className="shrink-0 text-xs text-slate-400">{reason.impact}</span>
                    </li>
                  ))}
                </ul>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
