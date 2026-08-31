import { useQuery } from "@tanstack/react-query";
import { getAlert } from "../api/alerts";

export function alertQueryKey(alertId: string) {
  return ["alerts", "detail", alertId] as const;
}

export function useAlert(alertId: string) {
  return useQuery({
    queryKey: alertQueryKey(alertId),
    queryFn: () => getAlert(alertId),
    enabled: Boolean(alertId),
  });
}
