import { useMutation, useQueryClient } from "@tanstack/react-query";
import { acknowledgeAlert, type Alert } from "../api/alerts";
import { alertQueryKey } from "./useAlert";

export function useAcknowledgeAlert(alertId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => acknowledgeAlert(alertId),
    onSuccess: (alert: Alert) => {
      queryClient.setQueryData(alertQueryKey(alertId), alert);
      // Matches every ["alerts", "list", ...] cache entry without
      // touching ["alerts", "detail", alertId] -- same key-shape
      // reasoning as assetsListQueryKey in useAssets.ts.
      queryClient.invalidateQueries({ queryKey: ["alerts", "list"] });
    },
  });
}
