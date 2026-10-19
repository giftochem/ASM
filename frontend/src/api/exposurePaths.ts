import { apiFetch } from "./client";
import type { components } from "../types/api.generated";

// Stage B's GET /assets/exposure-paths, typed from the generated contract.
// Observed exposure paths only -- the backend never assesses
// exploitability, and nothing here adds or recomputes anything.
export type ExposurePathsResponse = components["schemas"]["ExposurePathsResponse"];
export type ExposurePath = components["schemas"]["ExposurePathRead"];
export type PathStep = components["schemas"]["PathStepRead"];
export type PathAsset = components["schemas"]["PathAssetRef"];
export type EntryEvidence = components["schemas"]["EntryEvidenceRef"];
export type PathBasis = components["schemas"]["PathBasis"];
export type StepBasis = components["schemas"]["StepBasis"];
export type PathTruncation = components["schemas"]["PathTruncation"];

// The two limits the page exposes; max_targets/max_nodes stay at the
// backend's safe defaults, and as_of is left to the backend (now).
export interface ExposurePathsParams {
  max_hops?: number;
  max_paths?: number;
}

export function getExposurePaths(params: ExposurePathsParams = {}): Promise<ExposurePathsResponse> {
  const query = new URLSearchParams();
  if (params.max_hops !== undefined) query.set("max_hops", String(params.max_hops));
  if (params.max_paths !== undefined) query.set("max_paths", String(params.max_paths));
  const qs = query.toString();
  return apiFetch<ExposurePathsResponse>(`/assets/exposure-paths${qs ? `?${qs}` : ""}`);
}
