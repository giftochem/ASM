import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getDiscoveryRun, isTerminalRunStatus } from "../api/discovery";
import { discoverySchedulesQueryKey } from "./useDiscoverySchedules";

export function discoveryRunQueryKey(runId: string) {
  return ["discovery-runs", "detail", runId] as const;
}

// Polls only while the run is still queued/running, mirroring useScan's
// identical pattern -- stops the instant status becomes terminal. Also
// refreshes the schedules list once the run finishes, since
// last_run_status/last_run_at/enabled/disabled_reason on the owning
// schedule can all change as a direct result.
export function useDiscoveryRun(runId: string) {
  const queryClient = useQueryClient();
  return useQuery({
    queryKey: discoveryRunQueryKey(runId),
    queryFn: async () => {
      const run = await getDiscoveryRun(runId);
      if (isTerminalRunStatus(run.status)) {
        queryClient.invalidateQueries({ queryKey: discoverySchedulesQueryKey, exact: true });
      }
      return run;
    },
    enabled: Boolean(runId),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status && !isTerminalRunStatus(status) ? 2000 : false;
    },
  });
}
