import { useQuery } from "@tanstack/react-query";
import { listFindings, type ListFindingsParams } from "../api/findings";

// The full params object is the query key — a distinct filter/pagination
// combination (including a different asset_id or scan_id) is always a
// distinct cache entry. This is what guarantees switching filters can
// never show a stale or merged result from a previous combination: each
// key's data is independent, never unioned.
export function findingsQueryKey(params: ListFindingsParams) {
  return ["findings", params] as const;
}

export function useFindings(params: ListFindingsParams) {
  return useQuery({
    queryKey: findingsQueryKey(params),
    queryFn: () => listFindings(params),
  });
}
