import { useQuery } from "@tanstack/react-query";
import { listScans, type Scan } from "../api/scans";

// 'list'/'detail' namespacing (see useScan.ts) means an unqualified
// invalidateQueries({queryKey: ['scans', 'list']}) prefix-matches every
// list variant here without ever touching a ['scans', 'detail', id]
// entry — unlike Step 2's Assets hooks, which needed an explicit
// `exact: true` to avoid that same collision after it showed up as a
// real test failure (see useConfirmAuthorization.ts).
export function scansListQueryKey(filters?: { assetId?: string }) {
  return filters?.assetId ? (["scans", "list", { assetId: filters.assetId }] as const) : (["scans", "list"] as const);
}

function anyNonTerminal(scans: Scan[] | undefined): boolean {
  if (!scans) return false;
  return scans.some((scan) => scan.status === "queued" || scan.status === "running");
}

export function useScans(filters?: { assetId?: string }) {
  // Distinguishes "no filter" (fetch every org scan — filters is
  // undefined) from "filter to an assetId that hasn't resolved yet"
  // (filters = {assetId: ""} — e.g. AssetDetailPage before useParams
  // settles). The latter must not fall through to fetching the
  // unfiltered full list.
  const hasAssetFilter = filters !== undefined && "assetId" in filters;
  const assetId = filters?.assetId;

  return useQuery({
    queryKey: scansListQueryKey(filters),
    queryFn: () => listScans(assetId),
    enabled: !hasAssetFilter || Boolean(assetId),
    refetchInterval: (query) => (anyNonTerminal(query.state.data) ? 5000 : false),
  });
}
