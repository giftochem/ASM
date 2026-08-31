import { useQuery } from "@tanstack/react-query";
import { listDiscoverySchedules } from "../api/discovery";

export const discoverySchedulesQueryKey = ["discovery-schedules", "list"] as const;

export function useDiscoverySchedules() {
  return useQuery({
    queryKey: discoverySchedulesQueryKey,
    queryFn: listDiscoverySchedules,
  });
}
