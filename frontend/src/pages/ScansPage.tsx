import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useAssets } from "../hooks/useAssets";
import { useScans } from "../hooks/useScans";
import { useCreateScan } from "../hooks/useCreateScan";
import { useAuth } from "../auth/useAuth";
import { ApiErrorAlert } from "../components/ApiErrorAlert";
import { ScanStatusBadge } from "../components/ScanStatusBadge";
import { modulesForAssetType, SCAN_MODULES, type ScanStatus } from "../api/scans";

// Only admin/analyst can create/cancel scans server-side (require_role in
// app/api/routes/scans.py). UX-only gate; the server enforces the real
// boundary regardless.
const CAN_SCAN_ROLES = new Set(["admin", "analyst"]);

const STATUS_FILTERS: Array<ScanStatus | "all"> = ["all", "queued", "running", "completed", "failed", "cancelled"];

export function ScansPage() {
  const [searchParams] = useSearchParams();
  const preselectedAssetId = searchParams.get("asset_id") ?? undefined;
  const navigate = useNavigate();
  const { user } = useAuth();

  const { data: assets } = useAssets();
  const { data: scans, isLoading, error } = useScans(preselectedAssetId ? { assetId: preselectedAssetId } : undefined);
  const createScan = useCreateScan();

  const [statusFilter, setStatusFilter] = useState<ScanStatus | "all">("all");
  const [selectedAssetId, setSelectedAssetId] = useState(preselectedAssetId ?? "");
  const [moduleMode, setModuleMode] = useState<"standard" | "custom">("standard");
  const [selectedModules, setSelectedModules] = useState<Set<string>>(new Set());
  const [portScannerAcknowledged, setPortScannerAcknowledged] = useState(false);

  // Confirmed-only — a caller literally cannot pick an unconfirmed asset
  // through this form. The server re-validates authorization_confirmed
  // regardless (see scan_service.validate_scan_request); this just keeps
  // the common case from ever reaching that rejection.
  const eligibleAssets = useMemo(() => (assets ?? []).filter((asset) => asset.authorization_confirmed), [assets]);

  const selectedAsset = eligibleAssets.find((asset) => asset.id === selectedAssetId);
  const availableModules = selectedAsset ? modulesForAssetType(selectedAsset.asset_type) : [];
  const standardModules = availableModules.filter((module) => !module.requiresExplicitOptIn);

  // Changing the target asset invalidates any prior module selection —
  // a module valid for the old asset_type may not apply to the new one.
  useEffect(() => {
    setModuleMode("standard");
    setSelectedModules(new Set());
    setPortScannerAcknowledged(false);
  }, [selectedAssetId]);

  const portScannerSelected = selectedModules.has("port_scanner");

  const inProgressForSelectedAsset = (scans ?? []).some(
    (scan) => scan.asset_id === selectedAssetId && (scan.status === "queued" || scan.status === "running"),
  );

  const filteredScans = useMemo(() => {
    if (!scans) return [];
    if (statusFilter === "all") return scans;
    return scans.filter((scan) => scan.status === statusFilter);
  }, [scans, statusFilter]);

  const canCreate = user ? CAN_SCAN_ROLES.has(user.role) : false;

  const canSubmit =
    Boolean(selectedAssetId) &&
    availableModules.length > 0 &&
    (moduleMode === "standard" ? standardModules.length > 0 : selectedModules.size > 0) &&
    (!portScannerSelected || portScannerAcknowledged);

  const toggleModule = (name: string) => {
    setSelectedModules((prev) => {
      const next = new Set(prev);
      if (next.has(name)) {
        next.delete(name);
      } else {
        next.add(name);
      }
      return next;
    });
    if (name === "port_scanner") {
      setPortScannerAcknowledged(false);
    }
  };

  const handleSubmit = async () => {
    if (!canSubmit) return;
    try {
      const scan = await createScan.mutateAsync({
        asset_id: selectedAssetId,
        modules: moduleMode === "custom" ? Array.from(selectedModules) : undefined,
      });
      navigate(`/scans/${scan.id}`);
    } catch {
      // surfaced via createScan.error below
    }
  };

  return (
    <div className="mx-auto mt-10 max-w-3xl">
      <h1 className="mb-4 text-xl font-semibold">Scans</h1>

      {canCreate ? (
        <div className="mb-6 rounded border p-4">
          <h2 className="mb-2 text-sm font-semibold">Run a scan</h2>

          <label className="mb-2 flex flex-col gap-1 text-sm">
            Target asset (authorized only)
            <select
              className="rounded border px-2 py-1"
              value={selectedAssetId}
              onChange={(event) => setSelectedAssetId(event.target.value)}
            >
              <option value="">Select an asset...</option>
              {eligibleAssets.map((asset) => (
                <option key={asset.id} value={asset.id}>
                  {asset.value} ({asset.asset_type})
                </option>
              ))}
            </select>
          </label>

          {!selectedAssetId && eligibleAssets.length === 0 ? (
            <p className="mb-2 text-sm text-slate-500">
              No authorized assets yet.{" "}
              <Link to="/assets" className="underline">
                Confirm an asset's authorization
              </Link>{" "}
              first.
            </p>
          ) : null}

          {selectedAsset ? (
            availableModules.length === 0 ? (
              <p className="mb-2 text-sm text-slate-500">
                No scan modules are available for asset type '{selectedAsset.asset_type}' yet.
              </p>
            ) : (
              <div className="mb-2 flex flex-col gap-2 text-sm">
                <div className="flex gap-4">
                  <label className="flex items-center gap-1">
                    <input
                      type="radio"
                      name="module-mode"
                      checked={moduleMode === "standard"}
                      onChange={() => setModuleMode("standard")}
                    />
                    Run all standard modules ({standardModules.map((module) => module.label).join(", ") || "none"})
                  </label>
                  <label className="flex items-center gap-1">
                    <input
                      type="radio"
                      name="module-mode"
                      checked={moduleMode === "custom"}
                      onChange={() => setModuleMode("custom")}
                    />
                    Choose specific modules
                  </label>
                </div>

                {moduleMode === "custom" ? (
                  <div className="flex flex-col gap-1 pl-4">
                    {availableModules.map((module) => (
                      <label key={module.name} className="flex items-center gap-2">
                        <input
                          type="checkbox"
                          checked={selectedModules.has(module.name)}
                          onChange={() => toggleModule(module.name)}
                        />
                        {module.label}
                        {module.requiresExplicitOptIn ? (
                          <span className="text-xs text-amber-700">(active scan — explicit opt-in required)</span>
                        ) : null}
                      </label>
                    ))}
                    {portScannerSelected ? (
                      <label className="mt-1 flex items-start gap-2 rounded bg-amber-50 p-2 text-xs text-amber-900">
                        <input
                          type="checkbox"
                          checked={portScannerAcknowledged}
                          onChange={(event) => setPortScannerAcknowledged(event.target.checked)}
                          className="mt-0.5"
                        />
                        I understand port scanning actively probes the target and will only run this against assets
                        I'm authorized to test.
                      </label>
                    ) : null}
                  </div>
                ) : null}
              </div>
            )
          ) : null}

          {inProgressForSelectedAsset ? (
            <p className="mb-2 rounded bg-amber-50 px-2 py-1 text-xs text-amber-900">
              A scan is already queued or running for this asset. The backend does not block starting another one —
              this is just a heads-up.
            </p>
          ) : null}

          {createScan.error ? <ApiErrorAlert error={createScan.error} /> : null}

          <button
            type="button"
            onClick={handleSubmit}
            disabled={!canSubmit || createScan.isPending}
            className="rounded bg-slate-900 px-3 py-2 text-sm text-white disabled:opacity-50"
          >
            {createScan.isPending ? "Starting..." : "Start scan"}
          </button>
        </div>
      ) : null}

      <div className="mb-3 flex items-center gap-2">
        <select
          className="rounded border px-2 py-1 text-sm"
          value={statusFilter}
          onChange={(event) => setStatusFilter(event.target.value as ScanStatus | "all")}
        >
          {STATUS_FILTERS.map((status) => (
            <option key={status} value={status}>
              {status === "all" ? "All statuses" : status}
            </option>
          ))}
        </select>
        {preselectedAssetId ? (
          <Link to="/scans" className="text-sm underline">
            Clear asset filter
          </Link>
        ) : null}
      </div>

      {isLoading ? <p className="text-sm text-slate-500">Loading scans...</p> : null}
      {error ? <ApiErrorAlert error={error} /> : null}

      {!isLoading && !error ? (
        filteredScans.length === 0 ? (
          <p className="text-sm text-slate-500">No scans match this filter.</p>
        ) : (
          <ul className="divide-y rounded border">
            {filteredScans.map((scan) => (
              <li key={scan.id}>
                <Link to={`/scans/${scan.id}`} className="flex items-center justify-between px-3 py-2 text-sm hover:bg-slate-50">
                  <span className="font-mono text-xs text-slate-500">{scan.id.slice(0, 8)}</span>
                  <span>{scan.modules_requested.join(", ")}</span>
                  <ScanStatusBadge status={scan.status} />
                </Link>
              </li>
            ))}
          </ul>
        )
      ) : null}

      <p className="mt-3 text-xs text-slate-400">
        Available modules today: {SCAN_MODULES.map((module) => module.label).join(", ")}.
      </p>
    </div>
  );
}
