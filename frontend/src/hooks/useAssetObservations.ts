import { useQuery } from "@tanstack/react-query";
import { getAssetObservations } from "../api/assets";

export function assetObservationsQueryKey(assetId: string, limit: number) {
  return ["assets", "detail", assetId, "observations", limit] as const;
}

export function useAssetObservations(assetId: string, limit = 50) {
  return useQuery({
    queryKey: assetObservationsQueryKey(assetId, limit),
    queryFn: () => getAssetObservations(assetId, limit),
    enabled: Boolean(assetId),
  });
}
