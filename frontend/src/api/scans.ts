import { apiFetch } from "./client";
import type { components } from "../types/api.generated";
import type { AssetType } from "./assets";

export type Scan = components["schemas"]["ScanRead"];
export type ScanResult = components["schemas"]["ScanResult"];
export type ScanStatus = components["schemas"]["ScanStatus"];

export interface CreateScanPayload {
  asset_id: string;
  // Omitted (undefined) => backend runs every module that supports the
  // asset's type AND does not require explicit opt-in (see
  // app/services/scan_service.py validate_scan_request). An explicit list
  // is the ONLY way to run an opt-in module (currently just port_scanner)
  // — the backend will never include one in the "run everything" default.
  modules?: string[];
}

// Mirrors app/scanners/registry.py's MODULE_REGISTRY (name,
// applicable_asset_types, requires_explicit_opt_in) exactly, read
// directly from backend source as of Step 3. There is no catalog
// endpoint (e.g. GET /scan-modules) — this list can silently drift from
// the real registry if a module is added/changed backend-side without a
// matching frontend update. Flagged as a real gap, not papered over.
export interface ScanModuleInfo {
  name: string;
  label: string;
  assetTypes: AssetType[];
  requiresExplicitOptIn: boolean;
}

export const SCAN_MODULES: ScanModuleInfo[] = [
  { name: "whois", label: "WHOIS", assetTypes: ["domain"], requiresExplicitOptIn: false },
  { name: "dns", label: "DNS", assetTypes: ["domain", "subdomain"], requiresExplicitOptIn: false },
  {
    name: "ssl",
    label: "TLS/SSL",
    assetTypes: ["domain", "subdomain", "ip_address", "url"],
    requiresExplicitOptIn: false,
  },
  {
    name: "technology",
    label: "Technology fingerprint",
    assetTypes: ["domain", "subdomain", "ip_address", "url"],
    requiresExplicitOptIn: false,
  },
  {
    name: "security_headers",
    label: "Security headers",
    assetTypes: ["domain", "subdomain", "ip_address", "url"],
    requiresExplicitOptIn: false,
  },
  {
    name: "port_scanner",
    label: "Port scan (active)",
    assetTypes: ["ip_address"],
    requiresExplicitOptIn: true,
  },
];

export function modulesForAssetType(assetType: AssetType): ScanModuleInfo[] {
  return SCAN_MODULES.filter((module) => module.assetTypes.includes(assetType));
}

const TERMINAL_STATUSES: ScanStatus[] = ["completed", "failed", "cancelled"];

export function isTerminalStatus(status: ScanStatus): boolean {
  return TERMINAL_STATUSES.includes(status);
}

// GET /scans has no pagination (same situation as GET /assets — see
// app/api/routes/scans.py list_scans); asset_id is the one real
// server-side filter (added Step 0).
export function listScans(assetId?: string): Promise<Scan[]> {
  const query = assetId ? `?asset_id=${encodeURIComponent(assetId)}` : "";
  return apiFetch<Scan[]>(`/scans${query}`);
}

export function getScan(scanId: string): Promise<ScanResult> {
  return apiFetch<ScanResult>(`/scans/${scanId}`);
}

export function createScan(payload: CreateScanPayload): Promise<ScanResult> {
  return apiFetch<ScanResult>("/scans", { method: "POST", body: payload });
}

export function cancelScan(scanId: string): Promise<Scan> {
  return apiFetch<Scan>(`/scans/${scanId}/cancel`, { method: "POST" });
}
