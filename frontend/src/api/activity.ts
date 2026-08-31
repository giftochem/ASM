import { apiFetch } from "./client";
import type { components } from "../types/api.generated";

export type ActivityFeedItem = components["schemas"]["ActivityFeedItem"];
export type ChangeType = components["schemas"]["ChangeType"];
export type AssetType = components["schemas"]["AssetType"];

// Step 9.9/9.13: GET /assets/activity -- organization-wide, chronological
// feed of Observations across every asset (existing endpoint, unmodified
// server-side). Keyset-paginated: pass before_observed_at+before_id
// together (from the last item of the previous page) to page backward.
export interface ListActivityParams {
  since?: string;
  change_type?: ChangeType[];
  asset_type?: AssetType[];
  before_observed_at?: string;
  before_id?: string;
  limit?: number;
}

function buildActivityQuery(params: ListActivityParams): string {
  const query = new URLSearchParams();
  if (params.since) query.set("since", params.since);
  params.change_type?.forEach((v) => query.append("change_type", v));
  params.asset_type?.forEach((v) => query.append("asset_type", v));
  if (params.before_observed_at !== undefined) query.set("before_observed_at", params.before_observed_at);
  if (params.before_id !== undefined) query.set("before_id", params.before_id);
  if (params.limit !== undefined) query.set("limit", String(params.limit));
  return query.toString();
}

export function listActivity(params: ListActivityParams = {}): Promise<ActivityFeedItem[]> {
  const qs = buildActivityQuery(params);
  return apiFetch<ActivityFeedItem[]>(`/assets/activity${qs ? `?${qs}` : ""}`);
}
