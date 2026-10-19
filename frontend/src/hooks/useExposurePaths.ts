import { useQuery } from "@tanstack/react-query";
import { getExposurePaths, type ExposurePathsParams } from "../api/exposurePaths";

export function exposurePathsQueryKey(params: ExposurePathsParams) {
  return ["exposure-paths", params] as const;
}

// Read-only and on demand: no polling (the app-wide defaults already
// disable focus refetching and retries). A refresh only re-evaluates
// stored evidence server-side; it never starts discovery or scanning.
export function useExposurePaths(params: ExposurePathsParams) {
  return useQuery({
    queryKey: exposurePathsQueryKey(params),
    queryFn: () => getExposurePaths(params),
  });
}
