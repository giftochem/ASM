import { apiFetch } from "./client";
import type { components } from "../types/api.generated";

export type AttackSurfaceSummary = components["schemas"]["AttackSurfaceSummary"];

// Step 9.8/9.13: GET /assets/summary -- descriptive inventory statistics
// only (existing endpoint, unmodified server-side). Explicitly NOT a risk
// score -- see the backend docstring on graph_service.get_attack_surface_summary.
export function getAttackSurfaceSummary(): Promise<AttackSurfaceSummary> {
  return apiFetch<AttackSurfaceSummary>("/assets/summary");
}
