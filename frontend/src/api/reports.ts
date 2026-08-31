import { apiFetch, apiFetchBlob, type BlobDownload } from "./client";
import type { components } from "../types/api.generated";

export type Report = components["schemas"]["ReportRead"];
export type ReportFormat = components["schemas"]["ReportFormat"];
export type ReportStatus = components["schemas"]["ReportStatus"];

export interface CreateReportPayload {
  scan_id: string;
  format: ReportFormat;
}

// GET /reports has no filters at all (no scan_id, no pagination) — unlike
// Assets/Scans/Findings. See app/api/routes/reports.py list_reports.
export function listReports(): Promise<Report[]> {
  return apiFetch<Report[]>("/reports");
}

export function getReport(reportId: string): Promise<Report> {
  return apiFetch<Report>(`/reports/${reportId}`);
}

export function createReport(payload: CreateReportPayload): Promise<Report> {
  // Generation is fully synchronous server-side (see
  // app/services/report_service.py) — this call blocks for the entire
  // render and returns the report already in its terminal
  // completed/failed state, never `pending`/`generating`. No polling
  // hook exists or is needed for reports, unlike Scans.
  return apiFetch<Report>("/reports", { method: "POST", body: payload });
}

// Returns status !== 'completed' as a 409 server-side — callers should
// only offer this action for completed reports (see ReportsPage).
export function downloadReport(reportId: string): Promise<BlobDownload> {
  return apiFetchBlob(`/reports/${reportId}/download`);
}
