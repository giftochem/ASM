import { useMutation, useQueryClient } from "@tanstack/react-query";
import { createAsset, type CreateAssetPayload } from "../api/assets";

export function useCreateAsset() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateAssetPayload) => createAsset(payload),
    onSuccess: () => {
      // Matches every ["assets", "list", ...] cache entry (any
      // filter/pagination combination) without touching
      // ["assets", "detail", assetId] -- see assetsListQueryKey's
      // comment in useAssets.ts for why the key shape guarantees this.
      queryClient.invalidateQueries({ queryKey: ["assets", "list"] });
    },
  });
}
