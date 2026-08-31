import { useQuery } from "@tanstack/react-query";
import { listReports } from "../api/reports";

// A flat key is safe here (no prefix-collision risk to guard against like
// Assets/Scans needed) — there is no per-report detail query hook in
// Step 5's approved file list, so nothing else is ever cached under
// ['reports', ...] that a broad invalidate could clobber.
export const reportsQueryKey = ["reports"] as const;

export function useReports() {
  return useQuery({
    queryKey: reportsQueryKey,
    queryFn: listReports,
  });
}
