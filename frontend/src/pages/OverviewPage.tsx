import { Link } from "react-router-dom";
import { useAttackSurfaceSummary } from "../hooks/useAttackSurfaceSummary";
import { useActivityFeed } from "../hooks/useActivityFeed";
import { usePrioritizedAssets } from "../hooks/usePrioritizedAssets";
import { useAlerts } from "../hooks/useAlerts";
import { StatCard } from "../components/StatCard";
import { PriorityBadge } from "../components/PriorityBadge";
import { ApiErrorAlert } from "../components/ApiErrorAlert";

const RECENT_ACTIVITY_LIMIT = 8;
const HIGH_PRIORITY_LIMIT = 5;
const OPEN_ALERTS_LIMIT = 5;

function formatDateTime(value: string): string {
  return new Date(value).toLocaleString();
}

function humanizeChangeType(changeType: string): string {
  return changeType.replaceAll("_", " ");
}

// Step 9.13: the landing page -- answers "what does my organization
// expose, what changed, what needs attention" by composing four
// already-existing, already-tested read endpoints (summary, activity,
// prioritized, alerts). Computes and stores nothing of its own.
export function OverviewPage() {
  const { data: summary, isLoading: summaryLoading, error: summaryError } = useAttackSurfaceSummary();
  const { data: recentActivity, isLoading: activityLoading, error: activityError } = useActivityFeed({
    limit: RECENT_ACTIVITY_LIMIT,
  });
  const { data: newAssets } = useActivityFeed({ change_type: ["asset_created"], limit: 5 });
  const {
    data: highPriorityAssets,
    isLoading: priorityLoading,
    error: priorityError,
  } = usePrioritizedAssets({ priority: ["high", "critical"], limit: HIGH_PRIORITY_LIMIT });
  const {
    data: openAlerts,
    isLoading: alertsLoading,
    error: alertsError,
  } = useAlerts({ status: ["open"], limit: OPEN_ALERTS_LIMIT });

  return (
    <div>
      <h1 className="mb-1 text-xl font-semibold text-slate-900">Overview</h1>
      <p className="mb-6 text-sm text-slate-500">
        What your organization exposes, what changed, and what needs attention.
      </p>

      {summaryError ? <ApiErrorAlert error={summaryError} /> : null}
      {summaryLoading ? <p className="text-sm text-slate-500">Loading summary...</p> : null}

      {summary ? (
        <div className="mb-8 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          <StatCard label="Total assets" value={summary.total_assets} to="/assets" />
          <StatCard
            label="Asset types"
            value={Object.keys(summary.assets_by_type).length}
            hint={Object.entries(summary.assets_by_type)
              .map(([type, count]) => `${type}: ${count}`)
              .join(", ")}
            to="/assets"
          />
          <StatCard
            label="Relationships"
            value={summary.total_relationships}
            hint={`${summary.isolated_asset_count} isolated asset(s)`}
          />
          <StatCard
            label="Open alerts"
            value={openAlerts?.length ?? "—"}
            to="/alerts"
          />
          <StatCard
            label="Changes (7d)"
            value={summary.recent_observations_last_7_days}
            to="/changes"
          />
        </div>
      ) : null}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <section>
          <div className="mb-2 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-900">High-priority assets</h2>
            <Link to="/prioritized" className="text-xs text-slate-500 underline">
              View all
            </Link>
          </div>
          {priorityLoading ? <p className="text-sm text-slate-500">Loading...</p> : null}
          {priorityError ? <ApiErrorAlert error={priorityError} /> : null}
          {!priorityLoading && !priorityError && (highPriorityAssets?.length ?? 0) === 0 ? (
            <p className="text-sm text-slate-500">No high-priority assets right now.</p>
          ) : null}
          {highPriorityAssets && highPriorityAssets.length > 0 ? (
            <ul className="divide-y rounded border bg-white text-sm">
              {highPriorityAssets.map((item) => (
                <li key={item.asset_id}>
                  <Link
                    to={`/assets/${item.asset_id}`}
                    className="flex items-center justify-between px-3 py-2 hover:bg-slate-50"
                  >
                    <span className="truncate font-mono text-xs">{item.asset_value}</span>
                    <PriorityBadge priority={item.priority} />
                  </Link>
                </li>
              ))}
            </ul>
          ) : null}
        </section>

        <section>
          <div className="mb-2 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-900">Open alerts</h2>
            <Link to="/alerts" className="text-xs text-slate-500 underline">
              View all
            </Link>
          </div>
          {alertsLoading ? <p className="text-sm text-slate-500">Loading...</p> : null}
          {alertsError ? <ApiErrorAlert error={alertsError} /> : null}
          {!alertsLoading && !alertsError && (openAlerts?.length ?? 0) === 0 ? (
            <p className="text-sm text-slate-500">No open alerts. Nothing needs attention right now.</p>
          ) : null}
          {openAlerts && openAlerts.length > 0 ? (
            <ul className="divide-y rounded border bg-white text-sm">
              {openAlerts.map((alert) => (
                <li key={alert.id} className="flex items-center justify-between gap-2 px-3 py-2">
                  <div className="min-w-0">
                    <div className="truncate">{alert.title}</div>
                    {alert.asset_value ? (
                      <div className="truncate font-mono text-xs text-slate-400">{alert.asset_value}</div>
                    ) : null}
                  </div>
                  <PriorityBadge priority={alert.priority} />
                </li>
              ))}
            </ul>
          ) : null}
        </section>

        <section>
          <h2 className="mb-2 text-sm font-semibold text-slate-900">Newly discovered assets</h2>
          {(newAssets?.length ?? 0) === 0 ? (
            <p className="text-sm text-slate-500">No new assets discovered recently.</p>
          ) : (
            <ul className="divide-y rounded border bg-white text-sm">
              {(newAssets ?? []).map((entry) => (
                <li key={entry.id}>
                  <Link
                    to={`/assets/${entry.asset_id}`}
                    className="flex items-center justify-between px-3 py-2 hover:bg-slate-50"
                  >
                    <span className="truncate font-mono text-xs">{entry.asset_value}</span>
                    <span className="text-xs text-slate-400">{formatDateTime(entry.observed_at)}</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section>
          <div className="mb-2 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-900">Recent activity</h2>
            <Link to="/changes" className="text-xs text-slate-500 underline">
              View all
            </Link>
          </div>
          {activityLoading ? <p className="text-sm text-slate-500">Loading...</p> : null}
          {activityError ? <ApiErrorAlert error={activityError} /> : null}
          {!activityLoading && !activityError && (recentActivity?.length ?? 0) === 0 ? (
            <p className="text-sm text-slate-500">No recent activity.</p>
          ) : null}
          {recentActivity && recentActivity.length > 0 ? (
            <ul className="divide-y rounded border bg-white text-sm">
              {recentActivity.map((entry) => (
                <li key={entry.id} className="px-3 py-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate font-mono text-xs">{entry.asset_value}</span>
                    <span className="text-xs text-slate-400">{formatDateTime(entry.observed_at)}</span>
                  </div>
                  <div className="text-xs text-slate-500">{humanizeChangeType(entry.change_type)}</div>
                </li>
              ))}
            </ul>
          ) : null}
        </section>
      </div>
    </div>
  );
}
