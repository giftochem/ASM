import { apiFetch } from "./client";
import type { components } from "../types/api.generated";
import type { AssetCriticality, AssetEnvironment, AssetType } from "./assets";

export type AssetPriority = components["schemas"]["AssetPriority"];
export type PriorityLevel = components["schemas"]["PriorityLevel"];

// Step 9.10/9.13: GET /assets/prioritized -- explainable, on-demand asset
// prioritization (existing endpoint, unmodified server-side). Computed
// fresh on every call, never persisted. This is the ONLY source of
// priority in this app -- never recompute or approximate it client-side.
export interface ListPrioritizedAssetsParams {
  asset_type?: AssetType[];
  environment?: AssetEnvironment[];
  criticality?: AssetCriticality[];
  priority?: PriorityLevel[];
  limit?: number;
}

function buildPrioritizedQuery(params: ListPrioritizedAssetsParams): string {
  const query = new URLSearchParams();
  params.asset_type?.forEach((v) => query.append("asset_type", v));
  params.environment?.forEach((v) => query.append("environment", v));
  params.criticality?.forEach((v) => query.append("criticality", v));
  params.priority?.forEach((v) => query.append("priority", v));
  if (params.limit !== undefined) query.set("limit", String(params.limit));
  return query.toString();
}

export function listPrioritizedAssets(params: ListPrioritizedAssetsParams = {}): Promise<AssetPriority[]> {
  const qs = buildPrioritizedQuery(params);
  return apiFetch<AssetPriority[]>(`/assets/prioritized${qs ? `?${qs}` : ""}`);
}

export function getAssetRisk(assetId: string): Promise<AssetPriority> {
  return apiFetch<AssetPriority>(`/assets/${assetId}/risk`);
}
