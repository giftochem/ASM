import { useMutation, useQueryClient } from "@tanstack/react-query";
import { confirmAuthorization, type Asset, type ConfirmAuthorizationPayload } from "../api/assets";
import { assetQueryKey } from "./useAsset";

export function useConfirmAuthorization(assetId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: ConfirmAuthorizationPayload) => confirmAuthorization(assetId, payload),
    onSuccess: (asset: Asset) => {
      queryClient.setQueryData(assetQueryKey(assetId), asset);
      // Only list queries (any filter/pagination combination) -- never
      // ["assets", "detail", assetId], which would race the setQueryData
      // write above with a refetch. See assetsListQueryKey's comment in
      // useAssets.ts for why the key shape guarantees this split.
      queryClient.invalidateQueries({ queryKey: ["assets", "list"] });
    },
  });
}
