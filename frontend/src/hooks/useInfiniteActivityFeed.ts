import { useInfiniteQuery } from "@tanstack/react-query";
import { listActivity, type ActivityFeedItem, type ListActivityParams } from "../api/activity";

export const ACTIVITY_PAGE_SIZE = 30;

export interface ActivityFilters {
  since?: string;
  change_type?: ListActivityParams["change_type"];
  asset_type?: ListActivityParams["asset_type"];
}

interface ActivityCursor {
  before_observed_at: string;
  before_id: string;
}

export function activityExplorerQueryKey(filters: ActivityFilters) {
  return ["activity", "explorer", filters] as const;
}

function nextCursorOf(page: ActivityFeedItem[]): ActivityCursor | undefined {
  const last = page[page.length - 1];
  return last ? { before_observed_at: last.observed_at, before_id: last.id } : undefined;
}

// Change Timeline's data source -- server-side filtered, keyset-paginated
// "Load more" over the existing GET /assets/activity (Step 9.9),
// mirroring useInfiniteAssets' identical shape/reasoning.
export function useInfiniteActivityFeed(filters: ActivityFilters) {
  return useInfiniteQuery({
    queryKey: activityExplorerQueryKey(filters),
    queryFn: ({ pageParam }: { pageParam?: ActivityCursor }) =>
      listActivity({ ...filters, ...pageParam, limit: ACTIVITY_PAGE_SIZE }),
    initialPageParam: undefined as ActivityCursor | undefined,
    getNextPageParam: (lastPage: ActivityFeedItem[]) =>
      lastPage.length === ACTIVITY_PAGE_SIZE ? nextCursorOf(lastPage) : undefined,
  });
}
