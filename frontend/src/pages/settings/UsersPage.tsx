import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useUsers } from "../../hooks/useUsers";
import { useCreateUser } from "../../hooks/useCreateUser";
import { useUpdateUser } from "../../hooks/useUpdateUser";
import { useAuth } from "../../auth/useAuth";
import { ApiErrorAlert } from "../../components/ApiErrorAlert";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import type { User, UserRole } from "../../api/users";

const ROLES: UserRole[] = ["admin", "analyst", "viewer"];

const createSchema = z.object({
  full_name: z.string().min(1, "Full name is required"),
  email: z.string().email("Enter a valid email address"),
  // Mirrors the backend's Field(min_length=12) on UserCreate
  // (app/schemas/user.py) so the common case never round-trips to a 422.
  password: z.string().min(12, "Password must be at least 12 characters"),
  role: z.enum(["admin", "analyst", "viewer"]),
});

type CreateFormValues = z.infer<typeof createSchema>;

export function UsersPage() {
  const { user: currentUser } = useAuth();
  const { data: users, isLoading, error } = useUsers();
  const createUser = useCreateUser();
  const updateUser = useUpdateUser();
  const [rowError, setRowError] = useState<unknown>(null);

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<CreateFormValues>({
    resolver: zodResolver(createSchema),
    defaultValues: { full_name: "", email: "", password: "", role: "viewer" },
  });

  const onCreate = async (values: CreateFormValues) => {
    try {
      await createUser.mutateAsync(values);
      reset();
    } catch {
      // surfaced via createUser.error below
    }
  };

  const applyUpdate = async (userId: string, payload: { role?: UserRole; is_active?: boolean }) => {
    setRowError(null);
    try {
      await updateUser.mutateAsync({ userId, payload });
    } catch (err) {
      setRowError(err);
    }
  };

  // The server rejects an admin modifying their OWN role/is_active with a
  // 400 (self-lockout guard in app/api/routes/users.py). Disabling the
  // controls on one's own row mirrors that rule in the UI so the action
  // isn't offered at all — the server still rejects it regardless.
  const isSelf = (row: User) => row.id === currentUser?.id;

  const columns: DataTableColumn<User>[] = [
    { key: "full_name", header: "Name", render: (u) => u.full_name },
    { key: "email", header: "Email", render: (u) => u.email },
    {
      key: "role",
      header: "Role",
      render: (u) => (
        <select
          aria-label={`Role for ${u.email}`}
          className="rounded border px-2 py-1 text-xs disabled:opacity-50"
          value={u.role}
          disabled={isSelf(u) || updateUser.isPending}
          onChange={(event) => applyUpdate(u.id, { role: event.target.value as UserRole })}
        >
          {ROLES.map((role) => (
            <option key={role} value={role}>
              {role}
            </option>
          ))}
        </select>
      ),
    },
    {
      key: "is_active",
      header: "Status",
      render: (u) => (
        <button
          type="button"
          aria-label={`${u.is_active ? "Deactivate" : "Activate"} ${u.email}`}
          className="rounded border px-2 py-1 text-xs disabled:opacity-50"
          disabled={isSelf(u) || updateUser.isPending}
          onClick={() => applyUpdate(u.id, { is_active: !u.is_active })}
        >
          {u.is_active ? "Active" : "Inactive"}
        </button>
      ),
    },
    { key: "created_at", header: "Created", render: (u) => u.created_at },
  ];

  return (
    <div>
      <form onSubmit={handleSubmit(onCreate)} className="mb-6 flex flex-col gap-2 rounded border p-4" noValidate>
        <h2 className="text-sm font-semibold">Add a user</h2>
        <div className="flex flex-wrap gap-2">
          <input placeholder="Full name" className="rounded border px-2 py-1 text-sm" {...register("full_name")} />
          <input placeholder="Email" type="email" className="rounded border px-2 py-1 text-sm" {...register("email")} />
          <input
            placeholder="Temporary password"
            type="password"
            className="rounded border px-2 py-1 text-sm"
            {...register("password")}
          />
          <select aria-label="New user role" className="rounded border px-2 py-1 text-sm" {...register("role")}>
            {ROLES.map((role) => (
              <option key={role} value={role}>
                {role}
              </option>
            ))}
          </select>
        </div>
        {errors.full_name && <span className="text-xs text-red-600">{errors.full_name.message}</span>}
        {errors.email && <span className="text-xs text-red-600">{errors.email.message}</span>}
        {errors.password && <span className="text-xs text-red-600">{errors.password.message}</span>}
        {createUser.error ? <ApiErrorAlert error={createUser.error} /> : null}
        <button
          type="submit"
          disabled={isSubmitting}
          className="self-start rounded bg-slate-900 px-3 py-2 text-sm text-white disabled:opacity-50"
        >
          {isSubmitting ? "Adding..." : "Add user"}
        </button>
      </form>

      {rowError ? <ApiErrorAlert error={rowError} /> : null}

      <DataTable
        columns={columns}
        rows={users ?? []}
        rowKey={(user) => user.id}
        isLoading={isLoading}
        error={error}
        emptyMessage="No users yet."
      />
    </div>
  );
}
