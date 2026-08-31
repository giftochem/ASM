import { useQuery } from "@tanstack/react-query";
import { getAttackSurfaceSummary } from "../api/summary";

export const attackSurfaceSummaryQueryKey = ["summary"] as const;

export function useAttackSurfaceSummary() {
  return useQuery({
    queryKey: attackSurfaceSummaryQueryKey,
    queryFn: getAttackSurfaceSummary,
  });
}
