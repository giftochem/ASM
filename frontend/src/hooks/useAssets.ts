import { useQuery } from "@tanstack/react-query";
import { listAssets, type ListAssetsParams } from "../api/assets";

// "list" as an explicit second segment (not just ["assets", params])
// deliberately distinguishes every list-query cache entry from
// ["assets", "detail", assetId] (see useAsset.ts) -- this is what lets
// useCreateAsset/useConfirmAuthorization/useRevokeAuthorization
// invalidate every list variant (any filter/pagination combination)
// with one non-exact ["assets", "list"] match, without also touching
// any currently-mounted detail query. The full params object is still
// part of the key, so a distinct filter/pagination combination is
// always its own cache entry (mirrors useFindings' identical reasoning).
export function assetsListQueryKey(params: ListAssetsParams = {}) {
  return ["assets", "list", params] as const;
}

export function useAssets(params: ListAssetsParams = {}) {
  return useQuery({
    queryKey: assetsListQueryKey(params),
    queryFn: () => listAssets(params),
  });
}
