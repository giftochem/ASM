import { apiFetch } from "./client";
import type { components } from "../types/api.generated";

export type AuditLog = components["schemas"]["AuditLogRead"];
export type AuditOutcome = components["schemas"]["AuditOutcome"];

export interface ListAuditLogsParams {
  action?: string;
  resource_type?: string;
  user_id?: string;
  start_date?: string;
  end_date?: string;
  limit?: number;
  offset?: number;
}

// Admin-only AND always org-scoped server-side: the
// AuditLog.organization_id == current_user.organization_id filter is
// applied BEFORE any of the user-supplied filters (see
// app/api/routes/audit_logs.py), so passing another org's user_id can
// only ever narrow to zero rows — it can never surface their audit
// trail. Same join-order guarantee as GET /findings.
export function listAuditLogs(params: ListAuditLogsParams = {}): Promise<AuditLog[]> {
  const query = new URLSearchParams();
  if (params.action) query.set("action", params.action);
  if (params.resource_type) query.set("resource_type", params.resource_type);
  if (params.user_id) query.set("user_id", params.user_id);
  if (params.start_date) query.set("start_date", params.start_date);
  if (params.end_date) query.set("end_date", params.end_date);
  if (params.limit !== undefined) query.set("limit", String(params.limit));
  if (params.offset !== undefined) query.set("offset", String(params.offset));
  const qs = query.toString();
  return apiFetch<AuditLog[]>(`/audit-logs${qs ? `?${qs}` : ""}`);
}
