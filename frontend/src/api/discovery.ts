import { apiFetch } from "./client";
import type { components } from "../types/api.generated";

export type DiscoverySchedule = components["schemas"]["DiscoveryScheduleRead"];
export type DiscoveryProvider = components["schemas"]["DiscoveryProviderInfo"];
export type DiscoveryRun = components["schemas"]["DiscoveryRunRead"];
export type DiscoveryRunStatus = components["schemas"]["DiscoveryRunStatus"];

// Step 9.13: read-only catalog over the existing provider registry
// (Step 9.11 registered these providers; there was no way to list them
// from the API before this) -- lets the schedule-creation form offer
// only valid provider_name/asset_type combinations without
// hand-mirroring app/discovery/registry.py client-side.
export function listDiscoveryProviders(): Promise<DiscoveryProvider[]> {
  return apiFetch<DiscoveryProvider[]>("/discovery/providers");
}

export function listDiscoverySchedules(): Promise<DiscoverySchedule[]> {
  return apiFetch<DiscoverySchedule[]>("/discovery/schedules");
}

export function getDiscoverySchedule(scheduleId: string): Promise<DiscoverySchedule> {
  return apiFetch<DiscoverySchedule>(`/discovery/schedules/${scheduleId}`);
}

export interface CreateDiscoverySchedulePayload {
  seed_asset_id: string;
  provider_name: string;
  interval_hours: number;
}

export function createDiscoverySchedule(payload: CreateDiscoverySchedulePayload): Promise<DiscoverySchedule> {
  return apiFetch<DiscoverySchedule>("/discovery/schedules", { method: "POST", body: payload });
}

export interface UpdateDiscoverySchedulePayload {
  enabled?: boolean;
  interval_hours?: number;
}

export function updateDiscoverySchedule(
  scheduleId: string,
  payload: UpdateDiscoverySchedulePayload,
): Promise<DiscoverySchedule> {
  return apiFetch<DiscoverySchedule>(`/discovery/schedules/${scheduleId}`, { method: "PATCH", body: payload });
}

export function deleteDiscoverySchedule(scheduleId: string): Promise<void> {
  return apiFetch<void>(`/discovery/schedules/${scheduleId}`, { method: "DELETE" });
}

// Enqueues execution -- the provider runs in the background worker, not
// inside this request (see discovery_scheduler_executor.py). The
// returned run is normally still "queued"; poll GET /discovery/runs/{id}
// (getDiscoveryRun below) to observe it reach a terminal status.
export function triggerDiscoverySchedule(scheduleId: string): Promise<DiscoveryRun> {
  return apiFetch<DiscoveryRun>(`/discovery/schedules/${scheduleId}/run`, { method: "POST" });
}

export function getDiscoveryRun(runId: string): Promise<DiscoveryRun> {
  return apiFetch<DiscoveryRun>(`/discovery/runs/${runId}`);
}

const TERMINAL_RUN_STATUSES: DiscoveryRunStatus[] = ["completed", "failed", "cancelled"];

export function isTerminalRunStatus(status: DiscoveryRunStatus): boolean {
  return TERMINAL_RUN_STATUSES.includes(status);
}
