import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useExposurePaths } from "../hooks/useExposurePaths";
import { ApiErrorAlert } from "../components/ApiErrorAlert";
import { StatCard } from "../components/StatCard";
import type {
  EntryEvidence,
  ExposurePath,
  ExposurePathsResponse,
  PathAsset,
  PathBasis,
  PathStep,
  StepBasis,
} from "../api/exposurePaths";

// Stage C: a thin view over GET /assets/exposure-paths. Everything shown
// comes straight from the response, in the order it was returned --
// nothing is scored, ranked, inferred or recomputed here.

export const DISCLAIMER = "Observed exposure paths; exploitability not assessed.";

const HOP_OPTIONS = [0, 1, 2, 3];
const PATH_LIMIT_OPTIONS = [10, 25, 50, 100];
const DEFAULT_MAX_HOPS = 3;
const DEFAULT_MAX_PATHS = 100;

const BASIS_LABELS: Record<PathBasis, string> = {
  direct_exposure: "Observed service exposure",
  observed_dns_association: "Observed infrastructure association (DNS)",
  analyst_asserted: "Analyst-entered relationship",
  observed_dns_and_analyst_asserted: "Observed DNS association and analyst-entered relationship",
};

const STEP_BASIS_LABELS: Record<StepBasis, string> = {
  observed_dns_association: "Observed DNS association",
  analyst_asserted: "Analyst-entered relationship",
};

// The contract types these as plain strings: known values get a label,
// anything else is shown exactly as the API sent it.
const EVIDENCE_LABELS: Record<string, string> = {
  http_response: "HTTP response",
  tls_handshake: "TLS handshake",
  open_port: "Open port",
};

function formatDateTime(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString() : "—";
}

function formatWindow(seconds: number): string {
  const days = seconds / 86400;
  return Number.isInteger(days) ? `${days} day${days === 1 ? "" : "s"}` : `${Math.round(seconds / 3600)} hours`;
}

function evidenceLabel(evidenceType: string): string {
  return EVIDENCE_LABELS[evidenceType] ?? evidenceType;
}

function AssetLink({ asset }: { asset: PathAsset }) {
  return (
    <Link to={`/assets/${asset.asset_id}`} className="font-mono hover:underline">
      {asset.value}
    </Link>
  );
}

function Tag({ children, tone = "slate" }: { children: ReactNode; tone?: "slate" | "amber" | "red" | "sky" }) {
  const tones = {
    slate: "bg-slate-100 text-slate-700",
    amber: "bg-amber-100 text-amber-800",
    red: "bg-red-100 text-red-800",
    sky: "bg-sky-100 text-sky-800",
  };
  return <span className={`rounded px-2 py-0.5 text-xs ${tones[tone]}`}>{children}</span>;
}

function criticalityTag(criticality: PathAsset["criticality"]) {
  if (criticality === null) {
    return <Tag>criticality not set</Tag>;
  }
  return <Tag tone={criticality === "critical" ? "red" : "amber"}>{criticality}</Tag>;
}

export function ExposurePathsPage() {
  const [maxHops, setMaxHops] = useState(DEFAULT_MAX_HOPS);
  const [maxPaths, setMaxPaths] = useState(DEFAULT_MAX_PATHS);
  const { data, isLoading, isFetching, error, refetch } = useExposurePaths({ max_hops: maxHops, max_paths: maxPaths });

  return (
    <div className="max-w-5xl">
      <h1 className="mb-1 text-xl font-semibold text-slate-900">Exposure Paths</h1>
      <p className="mb-3 text-sm text-slate-500">
        Paths from assets with recently observed service exposure to assets explicitly marked high or critical, built
        only from stored evidence and relationships.
      </p>
      <p className="mb-4 rounded border border-slate-300 bg-slate-50 px-3 py-2 text-sm font-medium text-slate-700">
        {DISCLAIMER}
      </p>

      <div className="mb-4 flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-xs text-slate-500">
          Max hops
          <select
            aria-label="Max hops"
            className="rounded border px-2 py-1 text-sm text-slate-900"
            value={maxHops}
            onChange={(event) => setMaxHops(Number(event.target.value))}
          >
            {HOP_OPTIONS.map((hops) => (
              <option key={hops} value={hops}>
                {hops}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs text-slate-500">
          Max paths
          <select
            aria-label="Max paths"
            className="rounded border px-2 py-1 text-sm text-slate-900"
            value={maxPaths}
            onChange={(event) => setMaxPaths(Number(event.target.value))}
          >
            {PATH_LIMIT_OPTIONS.map((limit) => (
              <option key={limit} value={limit}>
                {limit}
              </option>
            ))}
          </select>
        </label>
        <button
          type="button"
          onClick={() => refetch()}
          disabled={isFetching}
          className="rounded border px-3 py-1.5 text-sm disabled:opacity-50"
        >
          {isFetching && !isLoading ? "Refreshing..." : "Refresh"}
        </button>
        <span className="text-xs text-slate-500">
          Refresh re-evaluates stored evidence only; it never starts discovery or scanning.
        </span>
      </div>

      {isLoading ? <p className="text-sm text-slate-500">Loading...</p> : null}
      {error ? (
        <div className="mb-4">
          <ApiErrorAlert error={error} />
          {data ? <p className="mt-1 text-xs text-slate-500">Showing the previous assessment below.</p> : null}
        </div>
      ) : null}
      {data ? <Results data={data} /> : null}
    </div>
  );
}

function Results({ data }: { data: ExposurePathsResponse }) {
  const freshnessWindow = formatWindow(data.freshness_window_seconds);
  return (
    <>
      <section aria-label="Assessment summary" className="mb-4">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <StatCard
            label={data.truncated ? "Paths returned (incomplete)" : "Paths returned"}
            value={data.path_count}
            hint={`up to ${data.limits.max_paths} paths, ${data.limits.max_hops} hops`}
          />
          <StatCard
            label="High/critical targets"
            value={data.eligible_target_count}
            hint={
              data.examined_target_count < data.eligible_target_count
                ? `${data.examined_target_count} examined`
                : "explicitly marked high or critical"
            }
          />
          <StatCard label="Observed entry points" value={data.entry_point_count} hint="among examined assets" />
          <StatCard label="Assessed at" value={<span className="text-base">{formatDateTime(data.assessed_at)}</span>} />
        </div>
        <p className="mt-2 text-sm text-slate-600">
          {data.truncated
            ? "Results are incomplete: a safety limit was reached (see below)."
            : "Complete within the selected limits."}{" "}
          Entry points need service evidence confirmed within the last {freshnessWindow}.
        </p>
      </section>

      {data.truncated ? (
        <section aria-label="Truncation" className="mb-4 rounded border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900">
          <p className="font-medium">This assessment was truncated, so more paths may exist than are shown.</p>
          <ul className="mt-1 list-disc pl-5">
            {data.truncation_reasons.map((reason) => (
              <li key={reason.limit}>
                <span className="font-mono text-xs">{reason.limit}</span>: {reason.detail}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {data.paths.length === 0 ? <EmptyState data={data} freshnessWindow={freshnessWindow} /> : null}

      {data.paths.length > 0 ? (
        <ol aria-label="Exposure paths" className="flex flex-col gap-3">
          {data.paths.map((path, index) => (
            <PathCard key={`${index}-${path.entry_point.asset_id}-${path.target.asset_id}`} path={path} freshnessWindow={freshnessWindow} />
          ))}
        </ol>
      ) : null}

      {data.limitations.length > 0 ? (
        <section aria-label="About these results" className="mt-6 text-xs text-slate-500">
          <h2 className="mb-1 font-semibold text-slate-600">About these results</h2>
          <ul className="list-disc space-y-0.5 pl-5">
            {data.limitations.map((limitation, index) => (
              <li key={`${index}-${limitation}`}>{limitation}</li>
            ))}
          </ul>
        </section>
      ) : null}
    </>
  );
}

function EmptyState({ data, freshnessWindow }: { data: ExposurePathsResponse; freshnessWindow: string }) {
  let message: ReactNode;
  if (data.eligible_target_count === 0) {
    message = (
      <>
        No assets are marked high or critical. Exposure paths are only assessed toward assets with an explicit business
        criticality -- nothing is treated as important by default. Set criticality on an asset's detail page, starting
        from the <Link to="/assets" className="underline">asset list</Link>.
      </>
    );
  } else if (data.truncated) {
    message =
      "No paths were found in the part of the attack surface that was examined, but the assessment was truncated, so this is not a complete result.";
  } else if (data.entry_point_count === 0) {
    message = (
      <>
        No qualifying exposure paths were found within this assessment ({data.limits.max_hops} hops). None of the examined
        assets has service evidence -- an HTTP response, TLS handshake or open port -- confirmed within the last{" "}
        {freshnessWindow}. Older or contradicted evidence doesn't count; evidence is refreshed by discovery runs and
        scans (see <Link to="/monitoring" className="underline">Monitoring</Link>).
      </>
    );
  } else {
    message = `No qualifying exposure paths were found within this assessment (${data.limits.max_hops} hops): no permitted relationship leads from an observed entry point to a high or critical asset within that limit.`;
  }
  return (
    <section aria-label="No paths" className="rounded border bg-white p-4 text-sm text-slate-600">
      {message}
    </section>
  );
}

function PathCard({ path, freshnessWindow }: { path: ExposurePath; freshnessWindow: string }) {
  const [expanded, setExpanded] = useState(false);
  const evidenceKinds = Array.from(new Set(path.entry_evidence.map((e) => evidenceLabel(e.evidence_type))));
  const latestConfirmation = path.entry_evidence
    .map((e) => e.last_confirmed_at)
    .filter((value): value is string => value !== null)
    .sort()
    .at(-1);

  return (
    <li className="rounded border bg-white p-4">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        {path.is_zero_hop ? (
          <>
            <AssetLink asset={path.target} />
            <span className="text-slate-500">is itself an observed entry point</span>
          </>
        ) : (
          <>
            <AssetLink asset={path.entry_point} />
            <span aria-hidden="true" className="text-slate-400">
              →
            </span>
            <AssetLink asset={path.target} />
          </>
        )}
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        {criticalityTag(path.target.criticality)}
        <Tag tone="sky">{path.is_zero_hop ? "Zero-hop: direct exposure" : `${path.hop_count} hop${path.hop_count === 1 ? "" : "s"}`}</Tag>
        <Tag>{BASIS_LABELS[path.basis] ?? path.basis}</Tag>
        <Tag>
          Evidence: {evidenceKinds.join(", ") || "none listed"}
          {latestConfirmation ? ` · last confirmed ${formatDateTime(latestConfirmation)}` : ""}
        </Tag>
        <Tag>Exploitability: not assessed</Tag>
      </div>
      <button
        type="button"
        aria-expanded={expanded}
        onClick={() => setExpanded((open) => !open)}
        className="mt-2 text-xs text-slate-600 underline"
      >
        {expanded ? "Hide details" : "Show details"}
      </button>
      {expanded ? <PathDetails path={path} freshnessWindow={freshnessWindow} /> : null}
    </li>
  );
}

function PathDetails({ path, freshnessWindow }: { path: ExposurePath; freshnessWindow: string }) {
  const valueOf = new Map(path.nodes.map((node) => [node.asset_id, node.value]));
  return (
    <div className="mt-3 space-y-4 border-t pt-3 text-sm">
      <p className="text-slate-700">{path.interpretation}</p>

      <div>
        <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">Assets</h3>
        <ol aria-label="Path assets" className="list-decimal space-y-1 pl-5">
          {path.nodes.map((node, index) => (
            <li key={node.asset_id}>
              <AssetLink asset={node} /> <span className="text-xs text-slate-500">({node.asset_type})</span>{" "}
              <span className="text-xs text-slate-500">{nodeRole(index, path.nodes.length, node)}</span>
            </li>
          ))}
        </ol>
      </div>

      <div>
        <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">Relationship steps</h3>
        {path.steps.length === 0 ? (
          <p className="text-slate-600">
            None: the target itself has observed service exposure, so no relationship is involved.
          </p>
        ) : (
          <ol aria-label="Relationship steps" className="list-decimal space-y-2 pl-5">
            {path.steps.map((step) => (
              <StepItem key={step.relationship_id} step={step} valueOf={valueOf} />
            ))}
          </ol>
        )}
      </div>

      <div>
        <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">Entry-point evidence</h3>
        <p className="mb-1 text-xs text-slate-500">
          Only evidence confirmed within the last {freshnessWindow}, with nothing since contradicting it, qualifies. It
          shows the service responded then -- not that it is reachable now.
        </p>
        <ul aria-label="Entry-point evidence" className="space-y-2">
          {path.entry_evidence.map((evidence) => (
            <EvidenceItem key={`${evidence.source}-${evidence.subject}-${evidence.evidence_type}`} evidence={evidence} />
          ))}
        </ul>
      </div>

      <div>
        <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">Limitations</h3>
        <ul aria-label="Path limitations" className="list-disc space-y-0.5 pl-5 text-slate-600">
          {path.limitations.map((limitation, index) => (
            <li key={`${index}-${limitation}`}>{limitation}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function nodeRole(index: number, count: number, node: PathAsset): string {
  const target = `target, ${node.criticality ?? "criticality not set"}`;
  if (count === 1) return `entry point and ${target}`;
  if (index === 0) return "entry point";
  if (index === count - 1) return target;
  return "intermediate";
}

const RELATIONSHIP_SOURCE_LABELS: Record<string, string> = {
  discovery: "recorded by discovery",
  manual: "entered manually",
};

function StepItem({ step, valueOf }: { step: PathStep; valueOf: Map<string, string> }) {
  return (
    <li>
      <div>
        <span className="font-mono">{valueOf.get(step.from_asset_id) ?? step.from_asset_id}</span>{" "}
        <span className="text-slate-500">
          {step.relationship_type} ({step.direction})
        </span>{" "}
        <span className="font-mono">{valueOf.get(step.to_asset_id) ?? step.to_asset_id}</span>
      </div>
      <div className="text-xs text-slate-500">
        {STEP_BASIS_LABELS[step.basis] ?? step.basis} ·{" "}
        {RELATIONSHIP_SOURCE_LABELS[step.relationship_source] ?? step.relationship_source}
      </div>
      {step.dns_evidence ? (
        <div className="text-xs text-slate-500">
          DNS evidence: {step.dns_evidence.record_type ?? "record type not recorded"} record observed{" "}
          {formatDateTime(step.dns_evidence.observed_at)} ({step.dns_evidence.freshness}) · result{" "}
          <span className="font-mono">{step.dns_evidence.result_id}</span>
        </div>
      ) : null}
      {step.analyst_assertion ? (
        <div className="text-xs text-slate-500">
          Asserted by an analyst {formatDateTime(step.analyst_assertion.asserted_at)} · audit record{" "}
          <span className="font-mono">{step.analyst_assertion.audit_log_id}</span>
        </div>
      ) : null}
      {step.basis === "analyst_asserted" && !step.analyst_assertion ? (
        <div className="text-xs text-slate-500">Analyst assertion record not provided.</div>
      ) : null}
      {step.basis === "observed_dns_association" && !step.dns_evidence ? (
        <div className="text-xs text-slate-500">DNS evidence not provided.</div>
      ) : null}
      <div className="text-xs text-slate-400">{step.reason}</div>
    </li>
  );
}

function EvidenceItem({ evidence }: { evidence: EntryEvidence }) {
  return (
    <li className="rounded bg-slate-50 px-2 py-1.5">
      <div>
        {evidenceLabel(evidence.evidence_type)} <span className="font-mono text-xs">{evidence.subject}</span>{" "}
        <span className="text-xs text-slate-500">
          via {evidence.source} · {evidence.freshness}
        </span>
      </div>
      <dl className="mt-1 grid grid-cols-2 gap-x-3 text-xs text-slate-500 sm:grid-cols-4">
        <dt>First confirmed</dt>
        <dd>{evidence.first_confirmed_at ? formatDateTime(evidence.first_confirmed_at) : "not determined"}</dd>
        <dt>Last confirmed</dt>
        <dd>{formatDateTime(evidence.last_confirmed_at)}</dd>
        <dt>Latest attempt</dt>
        <dd>{formatDateTime(evidence.latest_attempt_at)}</dd>
        <dt>Inconclusive attempts since</dt>
        <dd>
          {evidence.inconclusive_attempts}
          {evidence.latest_inconclusive_at ? ` (latest ${formatDateTime(evidence.latest_inconclusive_at)})` : ""}
        </dd>
      </dl>
      {evidence.limitations.length > 0 ? (
        <ul className="mt-1 list-disc pl-5 text-xs text-slate-500">
          {evidence.limitations.map((limitation, index) => (
            <li key={`${index}-${limitation}`}>{limitation}</li>
          ))}
        </ul>
      ) : null}
      <div className="mt-1 text-xs text-slate-400">
        {[
          evidence.result_id ? `result ${evidence.result_id}` : null,
          evidence.discovery_run_id ? `discovery run ${evidence.discovery_run_id}` : null,
          evidence.scan_id ? `scan ${evidence.scan_id}` : null,
          evidence.observation_id ? `observation ${evidence.observation_id}` : null,
        ]
          .filter(Boolean)
          .join(" · ")}
      </div>
    </li>
  );
}
