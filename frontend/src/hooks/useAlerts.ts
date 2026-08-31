import { useQuery } from "@tanstack/react-query";
import { listAlerts, type ListAlertsParams } from "../api/alerts";

export function alertsListQueryKey(params: ListAlertsParams) {
  return ["alerts", "list", params] as const;
}

export function useAlerts(params: ListAlertsParams = {}) {
  return useQuery({
    queryKey: alertsListQueryKey(params),
    queryFn: () => listAlerts(params),
  });
}
