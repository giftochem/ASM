import { useQuery } from "@tanstack/react-query";
import { getAssetRisk } from "../api/prioritization";

export function assetRiskQueryKey(assetId: string) {
  return ["assets", "detail", assetId, "risk"] as const;
}

export function useAssetRisk(assetId: string) {
  return useQuery({
    queryKey: assetRiskQueryKey(assetId),
    queryFn: () => getAssetRisk(assetId),
    enabled: Boolean(assetId),
  });
}
