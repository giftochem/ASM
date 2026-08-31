import { useInfiniteQuery } from "@tanstack/react-query";
import { listAssets, type Asset, type ListAssetsParams } from "../api/assets";

export const ASSETS_PAGE_SIZE = 50;

export interface AssetsFilters {
  asset_type?: ListAssetsParams["asset_type"];
  status?: ListAssetsParams["status"];
  environment?: ListAssetsParams["environment"];
  criticality?: ListAssetsParams["criticality"];
  search?: string;
}

interface AssetsCursor {
  after_value: string;
  after_id: string;
}

// The Attack Surface Explorer's data source -- server-side filtered
// (GET /assets, Step 9.13) with keyset "Load more" pagination via
// useInfiniteQuery, TanStack Query's purpose-built tool for exactly
// this accumulate-pages-by-cursor shape (already the library this app
// uses everywhere; this is just its pagination-specific hook, not a
// new dependency). A distinct filter combination is a distinct query
// (filters are part of the key), so changing a filter starts a fresh,
// empty page sequence rather than mixing cursors across combinations.
export function assetsExplorerQueryKey(filters: AssetsFilters) {
  return ["assets", "list", "explorer", filters] as const;
}

function lastCursorOf(page: Asset[]): AssetsCursor | undefined {
  const last = page[page.length - 1];
  return last ? { after_value: last.value, after_id: last.id } : undefined;
}

export function useInfiniteAssets(filters: AssetsFilters) {
  return useInfiniteQuery({
    queryKey: assetsExplorerQueryKey(filters),
    queryFn: ({ pageParam }: { pageParam?: AssetsCursor }) =>
      listAssets({ ...filters, ...pageParam, limit: ASSETS_PAGE_SIZE }),
    initialPageParam: undefined as AssetsCursor | undefined,
    getNextPageParam: (lastPage: Asset[]) =>
      lastPage.length === ASSETS_PAGE_SIZE ? lastCursorOf(lastPage) : undefined,
  });
}
