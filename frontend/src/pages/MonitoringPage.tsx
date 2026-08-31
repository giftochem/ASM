import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useAssets } from "../hooks/useAssets";
import { useDiscoveryProviders } from "../hooks/useDiscoveryProviders";
import { useDiscoverySchedules } from "../hooks/useDiscoverySchedules";
import { useCreateDiscoverySchedule } from "../hooks/useCreateDiscoverySchedule";
import { useUpdateDiscoverySchedule } from "../hooks/useUpdateDiscoverySchedule";
import { useDeleteDiscoverySchedule } from "../hooks/useDeleteDiscoverySchedule";
import { useTriggerDiscoverySchedule } from "../hooks/useTriggerDiscoverySchedule";
import { useDiscoveryRun } from "../hooks/useDiscoveryRun";
import { useAuth } from "../auth/useAuth";
import { ApiErrorAlert } from "../components/ApiErrorAlert";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { DiscoveryRunStatusBadge } from "../components/DiscoveryRunStatusBadge";
import type { DiscoverySchedule } from "../api/discovery";

// Only admin/analyst can manage schedules server-side (require_role in
// app/api/routes/discovery.py). UX-only gate; the server enforces the
// real boundary regardless.
const CAN_MANAGE_ROLES = new Set(["admin", "analyst"]);
const MIN_INTERVAL_HOURS = 1;
const MAX_INTERVAL_HOURS = 24 * 30;

const createSchema = z.object({
  seed_asset_id: z.string().min(1, "Select an asset"),
  provider_name: z.string().min(1, "Select a provider"),
  interval_hours: z.coerce.number().int().min(MIN_INTERVAL_HOURS).max(MAX_INTERVAL_HOURS),
});

type CreateFormValues = z.infer<typeof createSchema>;

function formatDateTime(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}

function ScheduleRow({
  schedule,
  canManage,
  onRequestDelete,
}: {
  schedule: DiscoverySchedule;
  canManage: boolean;
  onRequestDelete: (schedule: DiscoverySchedule) => void;
}) {
  const updateSchedule = useUpdateDiscoverySchedule(schedule.id);
  const triggerSchedule = useTriggerDiscoverySchedule(schedule.id);
  const [editingInterval, setEditingInterval] = useState(false);
  const [intervalValue, setIntervalValue] = useState(schedule.interval_hours);
  const [triggeredRunId, setTriggeredRunId] = useState<string | null>(null);

  // Polls the just-triggered run until it reaches a terminal status,
  // which also refreshes this list's last_run_status/next_run_at (see
  // useDiscoveryRun) -- gives immediate feedback without the operator
  // needing to manually refresh the page.
  const { data: triggeredRun } = useDiscoveryRun(triggeredRunId ?? "");

  const handleToggleEnabled = () => {
    updateSchedule.mutate({ enabled: !schedule.enabled });
  };

  const handleSaveInterval = () => {
    updateSchedule.mutate(
      { interval_hours: intervalValue },
      { onSuccess: () => setEditingInterval(false) },
    );
  };

  const handleTrigger = async () => {
    try {
      const run = await triggerSchedule.mutateAsync();
      setTriggeredRunId(run.id);
    } catch {
      // surfaced via triggerSchedule.error below
    }
  };

  return (
    <>
      <tr>
        <td className="px-3 py-2">
          <Link to={`/assets/${schedule.seed_asset_id}`} className="font-mono text-xs hover:underline">
            {schedule.seed_asset_value}
          </Link>
        </td>
        <td className="px-3 py-2 text-xs">{schedule.provider_name}</td>
        <td className="px-3 py-2">
          {editingInterval ? (
            <div className="flex items-center gap-1">
              <input
                type="number"
                min={MIN_INTERVAL_HOURS}
                max={MAX_INTERVAL_HOURS}
                value={intervalValue}
                onChange={(event) => setIntervalValue(Number(event.target.value))}
                className="w-16 rounded border px-1 py-0.5 text-xs"
              />
              <button type="button" onClick={handleSaveInterval} disabled={updateSchedule.isPending} className="text-xs underline">
                Save
              </button>
              <button type="button" onClick={() => setEditingInterval(false)} className="text-xs text-slate-400">
                Cancel
              </button>
            </div>
          ) : (
            <span className="text-xs">
              {schedule.interval_hours}h{" "}
              {canManage ? (
                <button type="button" onClick={() => setEditingInterval(true)} className="text-slate-400 underline">
                  edit
                </button>
              ) : null}
            </span>
          )}
        </td>
        <td className="px-3 py-2">
          <span
            className={
              schedule.enabled
                ? "rounded bg-green-100 px-2 py-0.5 text-xs text-green-800"
                : "rounded bg-slate-200 px-2 py-0.5 text-xs text-slate-600"
            }
            title={schedule.disabled_reason ?? undefined}
          >
            {schedule.enabled ? "Enabled" : "Disabled"}
          </span>
          {schedule.disabled_reason ? <div className="mt-0.5 text-xs text-red-600">{schedule.disabled_reason}</div> : null}
        </td>
        <td className="px-3 py-2 text-xs">{formatDateTime(schedule.next_run_at)}</td>
        <td className="px-3 py-2">
          <div className="text-xs">{formatDateTime(schedule.last_run_at)}</div>
          {triggeredRun ? (
            <DiscoveryRunStatusBadge status={triggeredRun.status} />
          ) : schedule.last_run_status ? (
            <DiscoveryRunStatusBadge status={schedule.last_run_status} />
          ) : null}
        </td>
        {canManage ? (
          <td className="px-3 py-2">
            <div className="flex flex-wrap gap-2 text-xs">
              <button type="button" onClick={handleTrigger} disabled={triggerSchedule.isPending || !schedule.enabled} className="underline disabled:opacity-50">
                {triggerSchedule.isPending ? "Triggering..." : "Run now"}
              </button>
              <button type="button" onClick={handleToggleEnabled} disabled={updateSchedule.isPending} className="underline disabled:opacity-50">
                {schedule.enabled ? "Disable" : "Enable"}
              </button>
              <button type="button" onClick={() => onRequestDelete(schedule)} className="text-red-700 underline">
                Delete
              </button>
            </div>
            {triggerSchedule.error ? <ApiErrorAlert error={triggerSchedule.error} /> : null}
            {updateSchedule.error ? <ApiErrorAlert error={updateSchedule.error} /> : null}
          </td>
        ) : null}
      </tr>
    </>
  );
}

export function MonitoringPage() {
  const { user } = useAuth();
  const { data: assets } = useAssets();
  const { data: providers } = useDiscoveryProviders();
  const { data: schedules, isLoading, error } = useDiscoverySchedules();
  const createSchedule = useCreateDiscoverySchedule();
  const deleteSchedule = useDeleteDiscoverySchedule();

  // Owned here, not per-row: ConfirmDialog renders a position:fixed
  // overlay <div>, which is invalid HTML nested inside a <tbody>/<tr>
  // (a real bug caught by a test's DOM-nesting warning) -- one shared
  // dialog outside the <table> entirely, parameterized by whichever
  // schedule is pending deletion, is both the fix and the simpler shape.
  const [scheduleToDelete, setScheduleToDelete] = useState<DiscoverySchedule | null>(null);

  const canManage = user ? CAN_MANAGE_ROLES.has(user.role) : false;

  // Confirmed-only, same reasoning as ScansPage's identical filter: a
  // schedule cannot target an unauthorized asset server-side either
  // (discovery_schedule_service.validate_schedule_request).
  const eligibleAssets = useMemo(() => (assets ?? []).filter((asset) => asset.authorization_confirmed), [assets]);

  const {
    register,
    handleSubmit,
    watch,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<CreateFormValues>({
    resolver: zodResolver(createSchema),
    defaultValues: { seed_asset_id: "", provider_name: "", interval_hours: 24 },
  });

  const selectedAssetId = watch("seed_asset_id");
  const selectedAsset = eligibleAssets.find((asset) => asset.id === selectedAssetId);
  const compatibleProviders = useMemo(
    () => (providers ?? []).filter((p) => !selectedAsset || p.applicable_seed_types.includes(selectedAsset.asset_type)),
    [providers, selectedAsset],
  );

  const onSubmit = async (values: CreateFormValues) => {
    try {
      await createSchedule.mutateAsync(values);
      reset();
    } catch {
      // surfaced via createSchedule.error below
    }
  };

  const handleConfirmDelete = async () => {
    if (!scheduleToDelete) return;
    try {
      await deleteSchedule.mutateAsync(scheduleToDelete.id);
      setScheduleToDelete(null);
    } catch {
      // surfaced via deleteSchedule.error below
    }
  };

  return (
    <div>
      <h1 className="mb-1 text-xl font-semibold text-slate-900">Continuous Monitoring</h1>
      <p className="mb-4 text-sm text-slate-500">
        Recurring discovery -- your attack surface is re-checked automatically on the interval you set.
      </p>

      {canManage ? (
        <form onSubmit={handleSubmit(onSubmit)} className="mb-6 flex flex-col gap-2 rounded border bg-white p-4" noValidate>
          <h2 className="text-sm font-semibold">New schedule</h2>
          <div className="flex flex-wrap gap-2">
            <select aria-label="Asset" className="rounded border px-2 py-1 text-sm" {...register("seed_asset_id")}>
              <option value="">Select an asset...</option>
              {eligibleAssets.map((asset) => (
                <option key={asset.id} value={asset.id}>
                  {asset.value} ({asset.asset_type})
                </option>
              ))}
            </select>
            <select
              aria-label="Provider"
              className="rounded border px-2 py-1 text-sm"
              {...register("provider_name")}
              disabled={!selectedAssetId}
            >
              <option value="">Select a provider...</option>
              {compatibleProviders.map((provider) => (
                <option key={provider.name} value={provider.name}>
                  {provider.name}
                </option>
              ))}
            </select>
            <input
              type="number"
              min={MIN_INTERVAL_HOURS}
              max={MAX_INTERVAL_HOURS}
              className="w-24 rounded border px-2 py-1 text-sm"
              {...register("interval_hours")}
            />
            <span className="self-center text-xs text-slate-400">hours</span>
          </div>
          {selectedAssetId && selectedAsset && compatibleProviders.length === 0 ? (
            <p className="text-xs text-slate-500">No provider supports asset type '{selectedAsset?.asset_type}' yet.</p>
          ) : null}
          {!selectedAssetId && eligibleAssets.length === 0 ? (
            <p className="text-sm text-slate-500">
              No authorized assets yet.{" "}
              <Link to="/assets" className="underline">
                Confirm an asset's authorization
              </Link>{" "}
              first.
            </p>
          ) : null}
          {errors.seed_asset_id || errors.provider_name || errors.interval_hours ? (
            <span className="text-xs text-red-600">
              {errors.seed_asset_id?.message || errors.provider_name?.message || errors.interval_hours?.message}
            </span>
          ) : null}
          {createSchedule.error ? <ApiErrorAlert error={createSchedule.error} /> : null}
          <button
            type="submit"
            disabled={isSubmitting}
            className="self-start rounded bg-slate-900 px-3 py-2 text-sm text-white disabled:opacity-50"
          >
            {isSubmitting ? "Creating..." : "Create schedule"}
          </button>
        </form>
      ) : null}

      {isLoading ? <p className="text-sm text-slate-500">Loading schedules...</p> : null}
      {error ? <ApiErrorAlert error={error} /> : null}
      {!isLoading && !error && (schedules?.length ?? 0) === 0 ? (
        <p className="text-sm text-slate-500">No discovery schedules yet.</p>
      ) : null}

      {schedules && schedules.length > 0 ? (
        <div className="overflow-x-auto rounded border bg-white">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-50">
              <tr>
                <th className="px-3 py-2 font-medium text-slate-600">Asset</th>
                <th className="px-3 py-2 font-medium text-slate-600">Provider</th>
                <th className="px-3 py-2 font-medium text-slate-600">Interval</th>
                <th className="px-3 py-2 font-medium text-slate-600">State</th>
                <th className="px-3 py-2 font-medium text-slate-600">Next run</th>
                <th className="px-3 py-2 font-medium text-slate-600">Last run</th>
                {canManage ? <th className="px-3 py-2 font-medium text-slate-600">Actions</th> : null}
              </tr>
            </thead>
            <tbody className="divide-y">
              {schedules.map((schedule) => (
                <ScheduleRow
                  key={schedule.id}
                  schedule={schedule}
                  canManage={canManage}
                  onRequestDelete={setScheduleToDelete}
                />
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      <ConfirmDialog
        open={scheduleToDelete !== null}
        title="Delete schedule"
        onConfirm={handleConfirmDelete}
        onCancel={() => setScheduleToDelete(null)}
        isConfirming={deleteSchedule.isPending}
      >
        {scheduleToDelete ? (
          <p>
            This stops recurring discovery for{" "}
            <span className="font-mono text-xs">{scheduleToDelete.seed_asset_value}</span> via{" "}
            {scheduleToDelete.provider_name}. It does not affect any past discovery results already recorded.
          </p>
        ) : null}
        {deleteSchedule.error ? <ApiErrorAlert error={deleteSchedule.error} /> : null}
      </ConfirmDialog>
    </div>
  );
}
