import { useMutation, useQueryClient } from "@tanstack/react-query";
import { triggerDiscoverySchedule } from "../api/discovery";
import { discoverySchedulesQueryKey } from "./useDiscoverySchedules";

// Enqueues execution -- the provider runs in the background worker (see
// discovery_scheduler_executor.py), never inside this request. The
// mutation resolves once the run is queued, not once it completes; the
// caller polls useDiscoveryRun(run.id) to observe the terminal status.
export function useTriggerDiscoverySchedule(scheduleId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => triggerDiscoverySchedule(scheduleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: discoverySchedulesQueryKey, exact: true });
    },
  });
}
