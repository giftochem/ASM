import { useMutation, useQueryClient } from "@tanstack/react-query";
import { createReport, type CreateReportPayload } from "../api/reports";
import { reportsQueryKey } from "./useReports";

// No polling hook exists for reports (unlike useScan) — generation is
// synchronous server-side, so the mutation's own pending state is the
// only loading indicator a caller needs (see api/reports.ts createReport).
export function useCreateReport() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateReportPayload) => createReport(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: reportsQueryKey });
    },
  });
}
