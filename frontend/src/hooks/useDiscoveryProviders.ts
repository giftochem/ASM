import { useQuery } from "@tanstack/react-query";
import { listDiscoveryProviders } from "../api/discovery";

export const discoveryProvidersQueryKey = ["discovery-providers"] as const;

export function useDiscoveryProviders() {
  return useQuery({
    queryKey: discoveryProvidersQueryKey,
    queryFn: listDiscoveryProviders,
    // The provider catalog is identical for every organization and
    // changes only on a backend deploy -- safe to treat as effectively
    // static within a session rather than refetching it repeatedly.
    staleTime: Infinity,
  });
}
