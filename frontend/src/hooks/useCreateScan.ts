import { useMutation, useQueryClient } from "@tanstack/react-query";
import { createScan, type CreateScanPayload, type ScanResult } from "../api/scans";
import { scansListQueryKey } from "./useScans";
import { scanQueryKey } from "./useScan";

export function useCreateScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateScanPayload) => createScan(payload),
    onSuccess: (scan: ScanResult) => {
      // Seed the detail cache with the response we already have, so an
      // immediate post-create navigation to /scans/:id renders instantly
      // instead of waiting on a redundant GET.
      queryClient.setQueryData(scanQueryKey(scan.id), scan);
      queryClient.invalidateQueries({ queryKey: scansListQueryKey() });
    },
  });
}
