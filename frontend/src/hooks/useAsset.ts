import { useQuery } from "@tanstack/react-query";
import { getAsset } from "../api/assets";

// "detail" as an explicit second segment -- see assetsListQueryKey's
// comment in useAssets.ts for why this shape is load-bearing, not
// decorative: it's what lets list-query invalidation ignore this key.
export function assetQueryKey(assetId: string) {
  return ["assets", "detail", assetId] as const;
}

export function useAsset(assetId: string) {
  return useQuery({
    queryKey: assetQueryKey(assetId),
    queryFn: () => getAsset(assetId),
    enabled: Boolean(assetId),
  });
}
