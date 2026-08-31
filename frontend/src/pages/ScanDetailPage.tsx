import { Link, useParams } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { useScan } from "../hooks/useScan";
import { useAsset } from "../hooks/useAsset";
import { useCancelScan } from "../hooks/useCancelScan";
import { useReports } from "../hooks/useReports";
import { useAuth } from "../auth/useAuth";
import { ApiErrorAlert } from "../components/ApiErrorAlert";
import { ScanStatusBadge } from "../components/ScanStatusBadge";
import { SeverityBadge } from "../components/SeverityBadge";
import { ReportStatusBadge } from "../components/ReportStatusBadge";
import { NotFoundError } from "../api/errors";
import { downloadReport, type Report } from "../api/reports";
import { triggerBlobDownload } from "../lib/downloadBlob";

const CAN_CANCEL_ROLES = new Set(["admin", "analyst"]);
const CAN_GENERATE_REPORT_ROLES = new Set(["admin", "analyst"]);

export function ScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const { user } = useAuth();
  const { data: scan, isLoading, error } = useScan(scanId ?? "");
  const { data: asset } = useAsset(scan?.asset_id ?? "");
  const cancelScan = useCancelScan(scanId ?? "");
  // GET /reports has no scan_id filter server-side (unlike GET /scans),
  // so this is a client-side filter over the full org list — same
  // pattern Assets used for client-side filtering, not the server-side
  // pattern Scans/Findings use.
  const { data: allReports, isLoading: reportsLoading } = useReports();
  const reportsForScan = (allReports ?? []).filter((report) => report.scan_id === scanId);
  const downloadMutation = useMutation({
    mutationFn: (report: Report) => downloadReport(report.id).then((result) => ({ report, result })),
    onSuccess: ({ report, result }) => {
      triggerBlobDownload(result.blob, result.filename ?? `asm-report-${report.id}.${report.format}`);
    },
  });

  if (isLoading) {
    return <p className="mx-auto mt-10 max-w-2xl text-sm text-slate-500">Loading scan...</p>;
  }

  if (error instanceof NotFoundError) {
    return (
      <div className="mx-auto mt-10 max-w-2xl">
        <p className="text-sm text-slate-600">Scan not found.</p>
        <Link to="/scans" className="text-sm underline">
          Back to scans
        </Link>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="mx-auto mt-10 max-w-2xl">
        <ApiErrorAlert error={error} />
      </div>
    );
  }

  const canCancel = user ? CAN_CANCEL_ROLES.has(user.role) : false;

  const handleCancel = async () => {
    try {
      await cancelScan.mutateAsync();
    } catch {
      // surfaced via cancelScan.error below
    }
  };

  return (
    <div className="mx-auto mt-10 max-w-2xl">
      <Link to="/scans" className="text-sm underline">
        Back to scans
      </Link>

      <div className="mb-1 mt-2 flex items-center gap-2">
        <h1 className="text-xl font-semibold">Scan {scan.id.slice(0, 8)}</h1>
        <ScanStatusBadge status={scan.status} />
      </div>
      {asset ? (
        <p className="mb-4 text-sm text-slate-600">
          Target:{" "}
          <Link to={`/assets/${asset.id}`} className="underline">
            {asset.value}
          </Link>{" "}
          ({asset.asset_type})
        </p>
      ) : null}

      <div className="mb-4 rounded border p-4 text-sm">
        <p>Modules: {scan.modules_requested.join(", ")}</p>
        {scan.started_at ? <p className="mt-1 text-xs text-slate-500">Started: {scan.started_at}</p> : null}
        {scan.completed_at ? <p className="mt-1 text-xs text-slate-500">Completed: {scan.completed_at}</p> : null}
        {scan.risk_severity_band ? (
          <p className="mt-2">
            Risk: <SeverityBadge severity={scan.risk_severity_band} />{" "}
            {scan.risk_score !== null ? `(${scan.risk_score})` : null}
          </p>
        ) : null}
        {scan.error_message ? (
          <p className="mt-2 rounded bg-red-50 px-2 py-1 text-red-800">{scan.error_message}</p>
        ) : null}
        {(scan.status === "queued" || scan.status === "running") && asset && !asset.authorization_confirmed ? (
          <p className="mt-2 rounded bg-amber-50 px-2 py-1 text-amber-900">
            This asset's authorization has been revoked. Execution will refuse to proceed (or stop before its next
            module) on this fail-closed guardrail rather than continue running.
          </p>
        ) : null}
      </div>

      {canCancel && scan.status === "queued" ? (
        <div className="mb-4">
          <button
            type="button"
            onClick={handleCancel}
            disabled={cancelScan.isPending}
            className="rounded border border-red-300 px-3 py-2 text-sm text-red-700 disabled:opacity-50"
          >
            {cancelScan.isPending ? "Cancelling..." : "Cancel scan"}
          </button>
          {cancelScan.error ? (
            <div className="mt-2">
              <ApiErrorAlert error={cancelScan.error} />
            </div>
          ) : null}
        </div>
      ) : null}

      <h2 className="mb-2 text-sm font-semibold">Findings ({scan.findings.length})</h2>
      {scan.findings.length === 0 ? (
        <p className="text-sm text-slate-500">
          {scan.status === "queued" || scan.status === "running" ? "No findings yet." : "No findings."}
        </p>
      ) : (
        <ul className="divide-y rounded border text-sm">
          {scan.findings.map((finding) => (
            <li key={finding.id} className="flex items-center justify-between gap-2 px-3 py-2">
              <span>
                <span className="font-medium">{finding.title}</span>{" "}
                <span className="text-xs text-slate-400">({finding.module})</span>
              </span>
              <SeverityBadge severity={finding.severity} />
            </li>
          ))}
        </ul>
      )}

      <div className="mt-6">
        <div className="mb-2 flex items-center justify-between">
          <h2 className="text-sm font-semibold">Reports</h2>
          {user && CAN_GENERATE_REPORT_ROLES.has(user.role) && scan.status === "completed" ? (
            <Link to={`/reports?scan_id=${scan.id}`} className="text-sm underline">
              Generate report
            </Link>
          ) : null}
        </div>
        {downloadMutation.error ? <ApiErrorAlert error={downloadMutation.error} /> : null}
        {reportsLoading ? <p className="text-sm text-slate-500">Loading reports...</p> : null}
        {!reportsLoading && reportsForScan.length === 0 ? (
          <p className="text-sm text-slate-500">No reports yet for this scan.</p>
        ) : null}
        {reportsForScan.length > 0 ? (
          <ul className="divide-y rounded border text-sm">
            {reportsForScan.map((report) => (
              <li key={report.id} className="flex items-center justify-between px-3 py-2">
                <span>{report.format.toUpperCase()}</span>
                <ReportStatusBadge status={report.status} />
                {report.status === "completed" ? (
                  <button
                    type="button"
                    onClick={() => downloadMutation.mutate(report)}
                    disabled={downloadMutation.isPending}
                    className="rounded border px-2 py-1 text-xs disabled:opacity-50"
                  >
                    Download
                  </button>
                ) : (
                  <span className="text-xs text-slate-400">
                    {report.status === "failed" ? report.error_message ?? "Failed" : "Not ready"}
                  </span>
                )}
              </li>
            ))}
          </ul>
        ) : null}
      </div>
    </div>
  );
}
