import { useMutation, useQueryClient } from "@tanstack/react-query";
import { cancelScan, type Scan, type ScanResult } from "../api/scans";
import { scansListQueryKey } from "./useScans";
import { scanQueryKey } from "./useScan";

export function useCancelScan(scanId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => cancelScan(scanId),
    onSuccess: (scan: Scan) => {
      // POST /scans/{id}/cancel responds with ScanRead, not ScanResult —
      // it has no `findings` field. The cached detail query holds a
      // ScanResult (from GET /scans/{id}), so a bare overwrite would wipe
      // `findings` to undefined and crash anything reading scan.findings.
      // A cancelable scan is always still `queued` (409 otherwise) and so
      // never has findings yet, but merging is the correct fix regardless
      // of that invariant holding.
      queryClient.setQueryData<ScanResult>(scanQueryKey(scanId), (previous) =>
        previous ? { ...previous, ...scan } : { ...scan, findings: [] },
      );
      queryClient.invalidateQueries({ queryKey: scansListQueryKey() });
    },
  });
}
