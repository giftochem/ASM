import { useMutation, useQueryClient } from "@tanstack/react-query";
import { revokeAuthorization, type Asset, type RevokeAuthorizationPayload } from "../api/assets";
import { assetQueryKey } from "./useAsset";

export function useRevokeAuthorization(assetId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: RevokeAuthorizationPayload) => revokeAuthorization(assetId, payload),
    onSuccess: (asset: Asset) => {
      queryClient.setQueryData(assetQueryKey(assetId), asset);
      // See the identical comment in useConfirmAuthorization.
      queryClient.invalidateQueries({ queryKey: ["assets", "list"] });
    },
  });
}
