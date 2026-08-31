import { useQuery } from "@tanstack/react-query";
import { listPrioritizedAssets, type ListPrioritizedAssetsParams } from "../api/prioritization";

export function prioritizedAssetsQueryKey(params: ListPrioritizedAssetsParams) {
  return ["prioritized-assets", params] as const;
}

export function usePrioritizedAssets(params: ListPrioritizedAssetsParams = {}) {
  return useQuery({
    queryKey: prioritizedAssetsQueryKey(params),
    queryFn: () => listPrioritizedAssets(params),
  });
}
