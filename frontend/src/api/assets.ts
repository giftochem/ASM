import { apiFetch } from "./client";
import type { components } from "../types/api.generated";

export type Asset = components["schemas"]["AssetRead"];
export type AssetType = components["schemas"]["AssetType"];
export type LifecycleStatus = components["schemas"]["LifecycleStatus"];
export type AssetEnvironment = components["schemas"]["AssetEnvironment"];
export type AssetCriticality = components["schemas"]["AssetCriticality"];
export type AssetGraph = components["schemas"]["AssetGraphResponse"];
export type GraphNode = components["schemas"]["GraphNode"];
export type GraphEdge = components["schemas"]["GraphEdge"];
export type AssetRelationship = components["schemas"]["AssetRelationshipRead"];
export type Observation = components["schemas"]["ObservationRead"];

export interface CreateAssetPayload {
  asset_type: AssetType;
  value: string;
  notes?: string | null;
}

export interface ConfirmAuthorizationPayload {
  authorization_confirmed: true;
  attestation_note?: string | null;
}

export interface RevokeAuthorizationPayload {
  reason?: string | null;
}

// Step 9.13: GET /assets grew optional server-side filtering + keyset
// pagination (see app/api/routes/assets.py) -- every param here is
// optional and additive. Passing no params at all preserves the
// original, still-supported "full unbounded org-scoped list" behavior.
export interface ListAssetsParams {
  asset_type?: AssetType[];
  status?: LifecycleStatus[];
  environment?: AssetEnvironment[];
  criticality?: AssetCriticality[];
  search?: string;
  after_value?: string;
  after_id?: string;
  limit?: number;
}

function buildAssetsQuery(params: ListAssetsParams): string {
  const query = new URLSearchParams();
  params.asset_type?.forEach((v) => query.append("asset_type", v));
  params.status?.forEach((v) => query.append("status", v));
  params.environment?.forEach((v) => query.append("environment", v));
  params.criticality?.forEach((v) => query.append("criticality", v));
  if (params.search) query.set("search", params.search);
  if (params.after_value !== undefined) query.set("after_value", params.after_value);
  if (params.after_id !== undefined) query.set("after_id", params.after_id);
  if (params.limit !== undefined) query.set("limit", String(params.limit));
  return query.toString();
}

export function listAssets(params: ListAssetsParams = {}): Promise<Asset[]> {
  const qs = buildAssetsQuery(params);
  return apiFetch<Asset[]>(`/assets${qs ? `?${qs}` : ""}`);
}

export function getAsset(assetId: string): Promise<Asset> {
  return apiFetch<Asset>(`/assets/${assetId}`);
}

export function createAsset(payload: CreateAssetPayload): Promise<Asset> {
  return apiFetch<Asset>("/assets", { method: "POST", body: payload });
}

export function confirmAuthorization(assetId: string, payload: ConfirmAuthorizationPayload): Promise<Asset> {
  return apiFetch<Asset>(`/assets/${assetId}/confirm-authorization`, { method: "POST", body: payload });
}

export function revokeAuthorization(assetId: string, payload: RevokeAuthorizationPayload): Promise<Asset> {
  return apiFetch<Asset>(`/assets/${assetId}/revoke-authorization`, { method: "POST", body: payload });
}

// Step 9.13: N-hop neighborhood graph for one asset (Step 9.8's existing
// GET /assets/{id}/graph, unmodified server-side). `depth` is validated
// server-side too (0..MAX_GRAPH_DEPTH) -- a caller passing an
// out-of-range value gets a 400, not a silently clamped result.
export function getAssetGraph(assetId: string, depth: number): Promise<AssetGraph> {
  return apiFetch<AssetGraph>(`/assets/${assetId}/graph?depth=${depth}`);
}

// Step 8/9.13: both directions (an asset can be the source or target of
// a relationship) -- existing endpoint, unmodified server-side.
export function getAssetRelationships(assetId: string): Promise<AssetRelationship[]> {
  return apiFetch<AssetRelationship[]>(`/assets/${assetId}/relationships`);
}

export function getAssetObservations(assetId: string, limit = 50): Promise<Observation[]> {
  return apiFetch<Observation[]>(`/assets/${assetId}/observations?limit=${limit}`);
}
