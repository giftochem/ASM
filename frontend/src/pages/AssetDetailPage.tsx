import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useAsset } from "../hooks/useAsset";
import { useConfirmAuthorization } from "../hooks/useConfirmAuthorization";
import { useRevokeAuthorization } from "../hooks/useRevokeAuthorization";
import { useUpdateAsset } from "../hooks/useUpdateAsset";
import { useScans } from "../hooks/useScans";
import { useAssetRisk } from "../hooks/useAssetRisk";
import { useAssetGraph } from "../hooks/useAssetGraph";
import { useAssetRelationships } from "../hooks/useAssetRelationships";
import { useAssetObservations } from "../hooks/useAssetObservations";
import { useAuth } from "../auth/useAuth";
import { ApiErrorAlert } from "../components/ApiErrorAlert";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { ScanStatusBadge } from "../components/ScanStatusBadge";
import { AssetStatusBadge } from "../components/AssetStatusBadge";
import { PriorityBadge } from "../components/PriorityBadge";
import { GraphView } from "../components/GraphView";
import { NotFoundError } from "../api/errors";
import type { Asset, AssetCriticality, AssetEnvironment, AssetUpdatePayload, GraphNode } from "../api/assets";

const AUTHORIZATION_DISCLAIMER =
  "You must own this asset, or hold explicit written permission (e.g. a signed pentest/MSSP engagement) to test it. Scanning systems without authorization may violate the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), or equivalent laws elsewhere.";

const CAN_MANAGE_ROLES = new Set(["admin", "analyst"]);
const CRITICALITY_OPTIONS: AssetCriticality[] = ["low", "medium", "high", "critical"];
const ENVIRONMENT_OPTIONS: AssetEnvironment[] = ["production", "staging", "development", "test", "unknown"];
const DEFAULT_GRAPH_DEPTH = 2;
const MAX_GRAPH_DEPTH = 5;

function formatDateTime(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}

function humanizeChangeType(changeType: string): string {
  return changeType.replaceAll("_", " ");
}

// Stage A.1: criticality and environment, the human-set business context
// prioritization reads. Rendered with key={assetId}: the route keeps this
// page mounted when the graph navigates to another asset, and an unsaved
// selection (or a save still in flight) must never land on that asset.
function BusinessContext({ assetId, asset, canManage }: { assetId: string; asset: Asset; canManage: boolean }) {
  const updateAsset = useUpdateAsset(assetId);
  // null means untouched: the control shows the stored value.
  const [draftCriticality, setDraftCriticality] = useState<AssetCriticality | "" | null>(null);
  const [draftEnvironment, setDraftEnvironment] = useState<AssetEnvironment | "" | null>(null);
  const [saved, setSaved] = useState(false);

  // "" is the "Not set" option. Only the fields that differ from what's
  // stored are sent; one sent as null clears the stored value.
  const criticality = draftCriticality ?? asset.criticality ?? "";
  const environment = draftEnvironment ?? asset.environment ?? "";
  const changes: AssetUpdatePayload = {};
  if (criticality !== (asset.criticality ?? "")) {
    changes.criticality = criticality || null;
  }
  if (environment !== (asset.environment ?? "")) {
    changes.environment = environment || null;
  }
  const hasChanges = Object.keys(changes).length > 0;

  const handleSave = async () => {
    setSaved(false);
    try {
      await updateAsset.mutateAsync(changes);
      setDraftCriticality(null);
      setDraftEnvironment(null);
      setSaved(true);
    } catch {
      // surfaced via updateAsset.error below
    }
  };

  return (
    <div className="mt-4 border-t pt-3">
      <h3 className="mb-2 text-sm font-semibold">Business context</h3>
      <dl className="grid grid-cols-2 gap-y-2 text-sm">
        <dt className="text-slate-500">Criticality</dt>
        <dd>
          {canManage ? (
            <select
              aria-label="Criticality"
              className="rounded border px-2 py-1 text-sm disabled:opacity-50"
              value={criticality}
              disabled={updateAsset.isPending}
              onChange={(event) => {
                setDraftCriticality(event.target.value as AssetCriticality | "");
                setSaved(false);
              }}
            >
              <option value="">Not set</option>
              {CRITICALITY_OPTIONS.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          ) : (
            asset.criticality ?? "—"
          )}
        </dd>
        <dt className="text-slate-500">Environment</dt>
        <dd>
          {canManage ? (
            <select
              aria-label="Environment"
              className="rounded border px-2 py-1 text-sm disabled:opacity-50"
              value={environment}
              disabled={updateAsset.isPending}
              onChange={(event) => {
                setDraftEnvironment(event.target.value as AssetEnvironment | "");
                setSaved(false);
              }}
            >
              <option value="">Not set</option>
              {ENVIRONMENT_OPTIONS.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          ) : (
            asset.environment ?? "—"
          )}
        </dd>
      </dl>
      {canManage ? (
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={handleSave}
            disabled={!hasChanges || updateAsset.isPending}
            className="rounded bg-slate-900 px-3 py-2 text-sm text-white disabled:opacity-50"
          >
            {updateAsset.isPending ? "Saving..." : "Save"}
          </button>
          {/* Always mounted so screen readers announce the text when it appears. */}
          <span role="status" className="text-sm text-green-700">
            {saved ? "Business context saved." : ""}
          </span>
        </div>
      ) : null}
      {updateAsset.error ? (
        <div className="mt-2">
          <ApiErrorAlert error={updateAsset.error} />
        </div>
      ) : null}
    </div>
  );
}

export function AssetDetailPage() {
  const { assetId } = useParams<{ assetId: string }>();
  const navigate = useNavigate();
  const { user } = useAuth();
  const { data: asset, isLoading, error } = useAsset(assetId ?? "");
  const confirmAuthorization = useConfirmAuthorization(assetId ?? "");
  const revokeAuthorization = useRevokeAuthorization(assetId ?? "");
  const { data: scans, isLoading: scansLoading } = useScans({ assetId: assetId ?? "" });
  const { data: risk, isLoading: riskLoading, error: riskError } = useAssetRisk(assetId ?? "");
  const { data: relationships, isLoading: relationshipsLoading } = useAssetRelationships(assetId ?? "");
  const { data: observations, isLoading: observationsLoading } = useAssetObservations(assetId ?? "", 20);

  const [graphDepth, setGraphDepth] = useState(DEFAULT_GRAPH_DEPTH);
  const { data: graph, isLoading: graphLoading, error: graphError } = useAssetGraph(assetId ?? "", graphDepth);

  const [confirmDialogOpen, setConfirmDialogOpen] = useState(false);
  const [revokeDialogOpen, setRevokeDialogOpen] = useState(false);
  const [attested, setAttested] = useState(false);
  const [attestationNote, setAttestationNote] = useState("");
  const [revokeReason, setRevokeReason] = useState("");

  const canManage = user ? CAN_MANAGE_ROLES.has(user.role) : false;

  if (isLoading) {
    return <p className="text-sm text-slate-500">Loading asset...</p>;
  }

  if (error instanceof NotFoundError) {
    return (
      <div>
        <p className="text-sm text-slate-600">Asset not found.</p>
        <Link to="/assets" className="text-sm underline">
          Back to assets
        </Link>
      </div>
    );
  }

  if (error || !asset) {
    return <ApiErrorAlert error={error} />;
  }

  const closeConfirmDialog = () => {
    setConfirmDialogOpen(false);
    setAttested(false);
    setAttestationNote("");
  };

  const handleConfirm = async () => {
    try {
      await confirmAuthorization.mutateAsync({ authorization_confirmed: true, attestation_note: attestationNote || null });
      closeConfirmDialog();
    } catch {
      // surfaced via confirmAuthorization.error below the dialog trigger
    }
  };

  const handleRevoke = async () => {
    try {
      await revokeAuthorization.mutateAsync({ reason: revokeReason || null });
      setRevokeDialogOpen(false);
      setRevokeReason("");
    } catch {
      // surfaced via revokeAuthorization.error below
    }
  };

  const handleGraphNodeClick = (node: GraphNode) => {
    if (node.id !== asset.id) {
      navigate(`/assets/${node.id}`);
    }
  };

  return (
    <div className="max-w-5xl">
      <Link to="/assets" className="text-sm underline">
        Back to assets
      </Link>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <h1 className="text-xl font-semibold">{asset.value}</h1>
        <AssetStatusBadge status={asset.status} />
        {risk ? <PriorityBadge priority={risk.priority} /> : null}
      </div>
      <p className="mb-4 text-sm text-slate-500">{asset.asset_type}</p>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* --- Identity --- */}
        <section className="rounded border bg-white p-4">
          <h2 className="mb-3 text-sm font-semibold">Identity</h2>
          <dl className="grid grid-cols-2 gap-y-2 text-sm">
            <dt className="text-slate-500">Authorization</dt>
            <dd>
              <span
                className={
                  asset.authorization_confirmed
                    ? "rounded bg-green-100 px-2 py-0.5 text-xs text-green-800"
                    : "rounded bg-amber-100 px-2 py-0.5 text-xs text-amber-800"
                }
              >
                {asset.authorization_confirmed ? "Authorized" : "Unauthorized"}
              </span>
            </dd>
            <dt className="text-slate-500">Owner</dt>
            <dd>{asset.owner ?? "—"}</dd>
            <dt className="text-slate-500">Tags</dt>
            <dd>{asset.tags.length > 0 ? asset.tags.join(", ") : "—"}</dd>
            <dt className="text-slate-500">First seen</dt>
            <dd>{formatDateTime(asset.first_seen)}</dd>
            <dt className="text-slate-500">Last seen</dt>
            <dd>{formatDateTime(asset.last_seen)}</dd>
          </dl>
          {asset.notes ? <p className="mt-3 text-sm text-slate-700">{asset.notes}</p> : null}

          {canManage ? (
            <div className="mt-4 flex gap-2">
              {!asset.authorization_confirmed ? (
                <button
                  type="button"
                  onClick={() => setConfirmDialogOpen(true)}
                  className="rounded bg-slate-900 px-3 py-2 text-sm text-white"
                >
                  Confirm authorization
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => setRevokeDialogOpen(true)}
                  className="rounded border border-red-300 px-3 py-2 text-sm text-red-700"
                >
                  Revoke authorization
                </button>
              )}
            </div>
          ) : null}
          {confirmAuthorization.error ? (
            <div className="mt-2">
              <ApiErrorAlert error={confirmAuthorization.error} />
            </div>
          ) : null}
          {revokeAuthorization.error ? (
            <div className="mt-2">
              <ApiErrorAlert error={revokeAuthorization.error} />
            </div>
          ) : null}

          <BusinessContext key={assetId} assetId={assetId ?? ""} asset={asset} canManage={canManage} />
        </section>

        {/* --- Priority --- */}
        <section className="rounded border bg-white p-4">
          <h2 className="mb-3 text-sm font-semibold">Priority</h2>
          {riskLoading ? <p className="text-sm text-slate-500">Loading...</p> : null}
          {riskError ? <ApiErrorAlert error={riskError} /> : null}
          {risk ? (
            <>
              <div className="mb-2 flex items-center gap-2">
                <PriorityBadge priority={risk.priority} />
                <span className="text-xs text-slate-500">
                  {risk.confidence_label} confidence ({risk.confidence_value.toFixed(2)})
                </span>
              </div>
              <p className="mb-2 text-xs text-slate-500">
                Not a guarantee of exploitability -- an explainable prioritization signal based on exposure,
                business context, recent change, and connectivity.
              </p>
              {risk.reasons.length > 0 ? (
                <ul className="space-y-1.5 text-sm">
                  {risk.reasons.map((reason, index) => (
                    <li key={`${reason.signal}-${index}`} className="flex items-start justify-between gap-2 rounded bg-slate-50 px-2 py-1.5">
                      <span className="text-slate-700">{reason.description}</span>
                      <span className="shrink-0 text-xs text-slate-400">{reason.impact}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-slate-500">No contributing signals.</p>
              )}
            </>
          ) : null}
        </section>

        {/* --- Relationships --- */}
        <section className="rounded border bg-white p-4">
          <h2 className="mb-3 text-sm font-semibold">Relationships</h2>
          {relationshipsLoading ? <p className="text-sm text-slate-500">Loading...</p> : null}
          {!relationshipsLoading && (relationships?.length ?? 0) === 0 ? (
            <p className="text-sm text-slate-500">No relationships to other assets.</p>
          ) : null}
          {relationships && relationships.length > 0 ? (
            <ul className="divide-y text-sm">
              {relationships.map((rel) => {
                const otherAssetId = rel.source_asset_id === asset.id ? rel.target_asset_id : rel.source_asset_id;
                const direction = rel.source_asset_id === asset.id ? "→" : "←";
                return (
                  <li key={rel.id} className="flex items-center justify-between gap-2 py-1.5">
                    <Link to={`/assets/${otherAssetId}`} className="truncate font-mono text-xs hover:underline">
                      {direction} {rel.relationship_type} {otherAssetId.slice(0, 8)}
                    </Link>
                    <span className="shrink-0 text-xs text-slate-400">{rel.status}</span>
                  </li>
                );
              })}
            </ul>
          ) : null}
        </section>

        {/* --- Recent changes / observations --- */}
        <section className="rounded border bg-white p-4">
          <h2 className="mb-3 text-sm font-semibold">Recent changes</h2>
          {observationsLoading ? <p className="text-sm text-slate-500">Loading...</p> : null}
          {!observationsLoading && (observations?.length ?? 0) === 0 ? (
            <p className="text-sm text-slate-500">No observations recorded yet.</p>
          ) : null}
          {observations && observations.length > 0 ? (
            <ul className="divide-y text-sm">
              {observations.map((obs) => (
                <li key={obs.id} className="py-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-slate-700">{humanizeChangeType(obs.change_type)}</span>
                    <span className="text-xs text-slate-400">{formatDateTime(obs.observed_at)}</span>
                  </div>
                  {obs.field_name ? <div className="text-xs text-slate-400">{obs.field_name}</div> : null}
                </li>
              ))}
            </ul>
          ) : null}
        </section>
      </div>

      {/* --- Attack-surface graph --- */}
      <section className="mt-6 rounded border bg-white p-4">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold">Attack-surface graph</h2>
          <label className="flex items-center gap-2 text-xs text-slate-500">
            Depth
            <select
              className="rounded border px-2 py-1 text-sm"
              value={graphDepth}
              onChange={(event) => setGraphDepth(Number(event.target.value))}
            >
              {Array.from({ length: MAX_GRAPH_DEPTH + 1 }, (_, depth) => depth).map((depth) => (
                <option key={depth} value={depth}>
                  {depth}
                </option>
              ))}
            </select>
          </label>
        </div>
        {graphLoading ? <p className="text-sm text-slate-500">Loading graph...</p> : null}
        {graphError ? <ApiErrorAlert error={graphError} /> : null}
        {graph ? (
          <>
            <GraphView nodes={graph.nodes} edges={graph.edges} seedAssetId={asset.id} onNodeClick={handleGraphNodeClick} />
            <p className="mt-2 text-xs text-slate-400">
              {graph.metadata.node_count} asset(s), {graph.metadata.edge_count} relationship(s) within {graphDepth} hop(s).
              Click a node to inspect that asset.
            </p>
          </>
        ) : null}
      </section>

      {/* --- Scan history --- */}
      <section className="mt-6">
        <div className="mb-2 flex items-center justify-between">
          <h2 className="text-sm font-semibold">Scan history</h2>
          {canManage && asset.authorization_confirmed ? (
            <Link to={`/scans?asset_id=${asset.id}`} className="text-sm underline">
              New scan
            </Link>
          ) : null}
        </div>
        {scansLoading ? <p className="text-sm text-slate-500">Loading scans...</p> : null}
        {!scansLoading && (!scans || scans.length === 0) ? (
          <p className="text-sm text-slate-500">No scans yet for this asset.</p>
        ) : null}
        {scans && scans.length > 0 ? (
          <ul className="divide-y rounded border bg-white text-sm">
            {scans.map((scan) => (
              <li key={scan.id}>
                <Link to={`/scans/${scan.id}`} className="flex items-center justify-between px-3 py-2 hover:bg-slate-50">
                  <span className="font-mono text-xs text-slate-500">{scan.id.slice(0, 8)}</span>
                  <span>{scan.modules_requested.join(", ")}</span>
                  <ScanStatusBadge status={scan.status} />
                </Link>
              </li>
            ))}
          </ul>
        ) : null}
      </section>

      <ConfirmDialog
        open={confirmDialogOpen}
        title="Confirm authorization"
        onConfirm={handleConfirm}
        onCancel={closeConfirmDialog}
        isConfirming={confirmAuthorization.isPending}
        confirmDisabled={!attested}
      >
        <p className="mb-3">{AUTHORIZATION_DISCLAIMER}</p>
        <label className="mb-2 flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            checked={attested}
            onChange={(event) => setAttested(event.target.checked)}
            className="mt-0.5"
          />
          I attest that I own this asset or have explicit written permission to test it.
        </label>
        <textarea
          placeholder="Attestation note (optional) — e.g. engagement reference"
          className="w-full rounded border px-2 py-1 text-sm"
          value={attestationNote}
          onChange={(event) => setAttestationNote(event.target.value)}
        />
      </ConfirmDialog>

      <ConfirmDialog
        open={revokeDialogOpen}
        title="Revoke authorization"
        onConfirm={handleRevoke}
        onCancel={() => setRevokeDialogOpen(false)}
        isConfirming={revokeAuthorization.isPending}
      >
        <p className="mb-2">
          This immediately blocks new scans against this asset. A scan already running is stopped at its next
          module boundary (see scan_executor's fail-closed re-check), not instantly.
        </p>
        <textarea
          placeholder="Reason (optional)"
          className="w-full rounded border px-2 py-1 text-sm"
          value={revokeReason}
          onChange={(event) => setRevokeReason(event.target.value)}
        />
      </ConfirmDialog>
    </div>
  );
}
