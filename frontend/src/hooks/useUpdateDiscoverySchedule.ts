import { useMutation, useQueryClient } from "@tanstack/react-query";
import { updateDiscoverySchedule, type UpdateDiscoverySchedulePayload } from "../api/discovery";
import { discoverySchedulesQueryKey } from "./useDiscoverySchedules";

export function useUpdateDiscoverySchedule(scheduleId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: UpdateDiscoverySchedulePayload) => updateDiscoverySchedule(scheduleId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: discoverySchedulesQueryKey, exact: true });
    },
  });
}
