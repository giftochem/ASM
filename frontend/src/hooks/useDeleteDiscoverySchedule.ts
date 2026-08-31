import { useMutation, useQueryClient } from "@tanstack/react-query";
import { deleteDiscoverySchedule } from "../api/discovery";
import { discoverySchedulesQueryKey } from "./useDiscoverySchedules";

export function useDeleteDiscoverySchedule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (scheduleId: string) => deleteDiscoverySchedule(scheduleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: discoverySchedulesQueryKey, exact: true });
    },
  });
}
