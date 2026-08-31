import { useQuery } from "@tanstack/react-query";
import { getAssetGraph } from "../api/assets";

export function assetGraphQueryKey(assetId: string, depth: number) {
  return ["assets", "detail", assetId, "graph", depth] as const;
}

export function useAssetGraph(assetId: string, depth: number) {
  return useQuery({
    queryKey: assetGraphQueryKey(assetId, depth),
    queryFn: () => getAssetGraph(assetId, depth),
    enabled: Boolean(assetId),
  });
}
