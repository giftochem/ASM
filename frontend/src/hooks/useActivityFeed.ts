import { useQuery } from "@tanstack/react-query";
import { listActivity, type ListActivityParams } from "../api/activity";

export function activityFeedQueryKey(params: ListActivityParams) {
  return ["activity", params] as const;
}

export function useActivityFeed(params: ListActivityParams = {}) {
  return useQuery({
    queryKey: activityFeedQueryKey(params),
    queryFn: () => listActivity(params),
  });
}
