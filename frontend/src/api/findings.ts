import { apiFetch } from "./client";
import type { components } from "../types/api.generated";

export type Finding = components["schemas"]["FindingRead"];
export type FindingSeverity = components["schemas"]["FindingSeverity"];

export interface ListFindingsParams {
  severity?: FindingSeverity;
  module?: string;
  asset_id?: string;
  scan_id?: string;
  limit?: number;
  offset?: number;
}

// GET /findings is org-scoped via a JOIN on Asset.organization_id BEFORE
// any of severity/module/asset_id/scan_id filters apply (see
// app/api/routes/findings.py list_findings) — passing another org's real
// asset_id or scan_id can only ever narrow to zero rows, never surface
// that org's data. There is no GET /findings/{finding_id} endpoint at
// all today, so finding_id isn't a usable manipulation vector either way.
export function listFindings(params: ListFindingsParams = {}): Promise<Finding[]> {
  const query = new URLSearchParams();
  if (params.severity) query.set("severity", params.severity);
  if (params.module) query.set("module", params.module);
  if (params.asset_id) query.set("asset_id", params.asset_id);
  if (params.scan_id) query.set("scan_id", params.scan_id);
  if (params.limit !== undefined) query.set("limit", String(params.limit));
  if (params.offset !== undefined) query.set("offset", String(params.offset));
  const qs = query.toString();
  return apiFetch<Finding[]>(`/findings${qs ? `?${qs}` : ""}`);
}
