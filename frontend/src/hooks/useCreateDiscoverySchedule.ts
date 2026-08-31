import { useMutation, useQueryClient } from "@tanstack/react-query";
import { createDiscoverySchedule, type CreateDiscoverySchedulePayload } from "../api/discovery";
import { discoverySchedulesQueryKey } from "./useDiscoverySchedules";

export function useCreateDiscoverySchedule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateDiscoverySchedulePayload) => createDiscoverySchedule(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: discoverySchedulesQueryKey, exact: true });
    },
  });
}
