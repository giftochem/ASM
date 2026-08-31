import { useQuery } from "@tanstack/react-query";
import { listAuditLogs, type ListAuditLogsParams } from "../api/auditLogs";

// Full params object in the key — a distinct filter/pagination
// combination is always a distinct cache entry, so switching filters can
// never render a stale or merged result from a previous combination.
// Same pattern as useFindings.
export function auditLogsQueryKey(params: ListAuditLogsParams) {
  return ["auditLogs", params] as const;
}

export function useAuditLogs(params: ListAuditLogsParams) {
  return useQuery({
    queryKey: auditLogsQueryKey(params),
    queryFn: () => listAuditLogs(params),
  });
}
