import { useQuery } from "@tanstack/react-query";
import { getScan, isTerminalStatus } from "../api/scans";

export function scanQueryKey(scanId: string) {
  return ["scans", "detail", scanId] as const;
}

// Polls only while the scan is still queued/running; stops the instant
// status becomes terminal (completed/failed/cancelled) and on unmount —
// TanStack Query owns the interval/cleanup, nothing here needs its own
// timer or effect.
export function useScan(scanId: string) {
  return useQuery({
    queryKey: scanQueryKey(scanId),
    queryFn: () => getScan(scanId),
    enabled: Boolean(scanId),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status && !isTerminalStatus(status) ? 3000 : false;
    },
  });
}
