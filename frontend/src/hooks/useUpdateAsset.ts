import { useMutation, useQueryClient } from "@tanstack/react-query";
import { updateAsset, type Asset, type AssetUpdatePayload } from "../api/assets";
import { assetQueryKey } from "./useAsset";
import { assetRiskQueryKey } from "./useAssetRisk";
import { attackSurfaceSummaryQueryKey } from "./useAttackSurfaceSummary";

export function useUpdateAsset(assetId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: AssetUpdatePayload) => updateAsset(assetId, payload),
    onSuccess: (asset: Asset) => {
      queryClient.setQueryData(assetQueryKey(assetId), asset);
      // Never the bare ["assets", "detail", assetId] key -- that would race
      // the write above (see useConfirmAuthorization). Only what derives
      // from criticality/environment: this asset's priority, its change
      // history (the update records an Observation) and graph nodes, plus
      // every list, feed and summary that shows them.
      const derivedQueryKeys = [
        assetRiskQueryKey(assetId),
        ["assets", "detail", assetId, "observations"],
        ["assets", "detail", assetId, "graph"],
        ["assets", "list"],
        ["prioritized-assets"],
        ["activity"],
        attackSurfaceSummaryQueryKey,
      ];
      for (const queryKey of derivedQueryKeys) {
        queryClient.invalidateQueries({ queryKey });
      }
    },
  });
}
