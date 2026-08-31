import { useMutation, useQueryClient } from "@tanstack/react-query";
import { resolveAlert, type Alert } from "../api/alerts";
import { alertQueryKey } from "./useAlert";

export function useResolveAlert(alertId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => resolveAlert(alertId),
    onSuccess: (alert: Alert) => {
      queryClient.setQueryData(alertQueryKey(alertId), alert);
      queryClient.invalidateQueries({ queryKey: ["alerts", "list"] });
    },
  });
}
