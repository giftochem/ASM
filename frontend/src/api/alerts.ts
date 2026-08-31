import { apiFetch } from "./client";
import type { components } from "../types/api.generated";

export type Alert = components["schemas"]["AlertRead"];
export type AlertStatus = components["schemas"]["AlertStatus"];
export type AlertPriority = components["schemas"]["AlertPriority"];
export type AlertType = components["schemas"]["AlertType"];

// Step 9.12/9.13: GET /alerts -- keyset-paginated via
// before_last_seen_at+before_id (existing endpoint, unmodified
// server-side other than the 9.13 asset_value/asset_type denormalization).
export interface ListAlertsParams {
  status?: AlertStatus[];
  priority?: AlertPriority[];
  alert_type?: AlertType[];
  asset_id?: string;
  before_last_seen_at?: string;
  before_id?: string;
  limit?: number;
}

function buildAlertsQuery(params: ListAlertsParams): string {
  const query = new URLSearchParams();
  params.status?.forEach((v) => query.append("status", v));
  params.priority?.forEach((v) => query.append("priority", v));
  params.alert_type?.forEach((v) => query.append("alert_type", v));
  if (params.asset_id) query.set("asset_id", params.asset_id);
  if (params.before_last_seen_at !== undefined) query.set("before_last_seen_at", params.before_last_seen_at);
  if (params.before_id !== undefined) query.set("before_id", params.before_id);
  if (params.limit !== undefined) query.set("limit", String(params.limit));
  return query.toString();
}

export function listAlerts(params: ListAlertsParams = {}): Promise<Alert[]> {
  const qs = buildAlertsQuery(params);
  return apiFetch<Alert[]>(`/alerts${qs ? `?${qs}` : ""}`);
}

export function getAlert(alertId: string): Promise<Alert> {
  return apiFetch<Alert>(`/alerts/${alertId}`);
}

export function acknowledgeAlert(alertId: string): Promise<Alert> {
  return apiFetch<Alert>(`/alerts/${alertId}/acknowledge`, { method: "POST" });
}

export function resolveAlert(alertId: string): Promise<Alert> {
  return apiFetch<Alert>(`/alerts/${alertId}/resolve`, { method: "POST" });
}
