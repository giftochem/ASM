import { useQuery } from "@tanstack/react-query";
import { getAssetRelationships } from "../api/assets";

export function assetRelationshipsQueryKey(assetId: string) {
  return ["assets", "detail", assetId, "relationships"] as const;
}

export function useAssetRelationships(assetId: string) {
  return useQuery({
    queryKey: assetRelationshipsQueryKey(assetId),
    queryFn: () => getAssetRelationships(assetId),
    enabled: Boolean(assetId),
  });
}
