import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { useReports } from "../hooks/useReports";
import { useCreateReport } from "../hooks/useCreateReport";
import { useScans } from "../hooks/useScans";
import { useAuth } from "../auth/useAuth";
import { downloadReport, type Report, type ReportFormat } from "../api/reports";
import { triggerBlobDownload } from "../lib/downloadBlob";
import { ApiErrorAlert } from "../components/ApiErrorAlert";
import { DataTable, type DataTableColumn } from "../components/DataTable";
import { ReportStatusBadge } from "../components/ReportStatusBadge";

const REPORT_FORMATS: ReportFormat[] = ["json", "csv", "pdf"];

// Only admin/analyst can generate reports server-side (require_role in
// app/api/routes/reports.py). List/get/download have no role restriction
// at all — a viewer can download a report an admin generated (verified
// against the real backend test suite), so this UX gate is intentionally
// narrower than "hide the whole page for viewers".
const CAN_GENERATE_ROLES = new Set(["admin", "analyst"]);

function fallbackFilename(report: Report): string {
  return `asm-report-${report.id}.${report.format}`;
}

export function ReportsPage() {
  const [searchParams] = useSearchParams();
  const preselectedScanId = searchParams.get("scan_id") ?? undefined;

  const { user } = useAuth();
  const { data: reports, isLoading, error } = useReports();
  const { data: scans } = useScans();
  const createReport = useCreateReport();
  const downloadMutation = useMutation({
    mutationFn: (report: Report) => downloadReport(report.id).then((result) => ({ report, result })),
    onSuccess: ({ report, result }) => {
      triggerBlobDownload(result.blob, result.filename ?? fallbackFilename(report));
    },
  });

  const [selectedScanId, setSelectedScanId] = useState("");
  const [format, setFormat] = useState<ReportFormat>("json");

  // A report can technically be generated for a non-completed scan (the
  // backend doesn't block it — see report_service.build_report_data,
  // which just produces a degenerate summary), but that's not a useful
  // action to offer, so the picker only lists completed scans.
  const completedScans = (scans ?? []).filter((scan) => scan.status === "completed");

  // Pre-selects a scan linked in from ScanDetailPage's "Generate report"
  // link (?scan_id=...). Only takes effect once that scan is confirmed
  // to actually be in the eligible (completed) list — a link to a
  // not-yet-completed scan just leaves the picker on its default state
  // rather than silently selecting something invalid.
  useEffect(() => {
    if (preselectedScanId && completedScans.some((scan) => scan.id === preselectedScanId)) {
      setSelectedScanId(preselectedScanId);
    }
  }, [preselectedScanId, scans]);

  const canGenerate = user ? CAN_GENERATE_ROLES.has(user.role) : false;

  const handleGenerate = async () => {
    if (!selectedScanId) return;
    try {
      await createReport.mutateAsync({ scan_id: selectedScanId, format });
      setSelectedScanId("");
    } catch {
      // surfaced via createReport.error below
    }
  };

  const columns: DataTableColumn<Report>[] = [
    { key: "format", header: "Format", render: (r) => r.format.toUpperCase() },
    { key: "status", header: "Status", render: (r) => <ReportStatusBadge status={r.status} /> },
    { key: "created_at", header: "Created", render: (r) => r.created_at },
    {
      key: "action",
      header: "",
      render: (r) =>
        r.status === "completed" ? (
          <button
            type="button"
            onClick={() => downloadMutation.mutate(r)}
            disabled={downloadMutation.isPending}
            className="rounded border px-2 py-1 text-xs disabled:opacity-50"
          >
            Download
          </button>
        ) : r.status === "failed" ? (
          <span className="text-xs text-red-700">{r.error_message ?? "Failed"}</span>
        ) : (
          <span className="text-xs text-slate-400">Not ready</span>
        ),
    },
  ];

  return (
    <div className="mx-auto mt-10 max-w-3xl">
      <h1 className="mb-4 text-xl font-semibold">Reports</h1>

      {canGenerate ? (
        <div className="mb-6 flex flex-col gap-2 rounded border p-4">
          <h2 className="text-sm font-semibold">Generate a report</h2>
          <div className="flex gap-2">
            <select
              className="flex-1 rounded border px-2 py-1 text-sm"
              value={selectedScanId}
              onChange={(event) => setSelectedScanId(event.target.value)}
            >
              <option value="">Select a completed scan...</option>
              {completedScans.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  {scan.id.slice(0, 8)} — {scan.modules_requested.join(", ")}
                </option>
              ))}
            </select>
            <select
              className="rounded border px-2 py-1 text-sm"
              value={format}
              onChange={(event) => setFormat(event.target.value as ReportFormat)}
            >
              {REPORT_FORMATS.map((f) => (
                <option key={f} value={f}>
                  {f.toUpperCase()}
                </option>
              ))}
            </select>
          </div>
          {!selectedScanId && completedScans.length === 0 ? (
            <p className="text-sm text-slate-500">No completed scans yet — a report needs one to summarize.</p>
          ) : null}
          {createReport.error ? <ApiErrorAlert error={createReport.error} /> : null}
          <button
            type="button"
            onClick={handleGenerate}
            disabled={!selectedScanId || createReport.isPending}
            className="self-start rounded bg-slate-900 px-3 py-2 text-sm text-white disabled:opacity-50"
          >
            {createReport.isPending ? "Generating..." : "Generate report"}
          </button>
        </div>
      ) : null}

      {downloadMutation.error ? <ApiErrorAlert error={downloadMutation.error} /> : null}

      <DataTable
        columns={columns}
        rows={reports ?? []}
        rowKey={(report) => report.id}
        isLoading={isLoading}
        error={error}
        emptyMessage="No reports yet."
      />
    </div>
  );
}
