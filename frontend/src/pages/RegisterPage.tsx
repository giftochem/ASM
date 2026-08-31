import { useState } from "react";
import { Link, Navigate, useNavigate } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { register as registerAccount } from "../api/auth";
import { useAuth } from "../auth/useAuth";
import { ApiErrorAlert } from "../components/ApiErrorAlert";

const schema = z.object({
  organization_name: z.string().min(1, "Organization name is required"),
  full_name: z.string().min(1, "Full name is required"),
  email: z.string().email("Enter a valid email address"),
  // Mirrors the backend's Field(min_length=12) on UserCreate/RegisterRequest
  // (app/schemas/auth.py) so the common case never round-trips to a 422.
  password: z.string().min(12, "Password must be at least 12 characters"),
});

type FormValues = z.infer<typeof schema>;

export function RegisterPage() {
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<FormValues>({ resolver: zodResolver(schema) });
  const [submitError, setSubmitError] = useState<unknown>(null);
  const { isAuthenticated } = useAuth();
  const navigate = useNavigate();

  if (isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  const onSubmit = async (values: FormValues) => {
    setSubmitError(null);
    try {
      // Registration also issues a session (see backend _issue_session),
      // so a successful register logs the caller in immediately.
      await registerAccount(values);
      navigate("/", { replace: true });
    } catch (error) {
      setSubmitError(error);
    }
  };

  return (
    <div className="mx-auto mt-16 max-w-sm">
      <h1 className="mb-4 text-xl font-semibold">Create your organization</h1>
      <form onSubmit={handleSubmit(onSubmit)} className="flex flex-col gap-3" noValidate>
        <label className="flex flex-col gap-1 text-sm">
          Organization name
          <input className="rounded border px-2 py-1" {...register("organization_name")} />
          {errors.organization_name && (
            <span className="text-xs text-red-600">{errors.organization_name.message}</span>
          )}
        </label>
        <label className="flex flex-col gap-1 text-sm">
          Your full name
          <input className="rounded border px-2 py-1" {...register("full_name")} />
          {errors.full_name && <span className="text-xs text-red-600">{errors.full_name.message}</span>}
        </label>
        <label className="flex flex-col gap-1 text-sm">
          Email
          <input type="email" className="rounded border px-2 py-1" {...register("email")} />
          {errors.email && <span className="text-xs text-red-600">{errors.email.message}</span>}
        </label>
        <label className="flex flex-col gap-1 text-sm">
          Password
          <input type="password" className="rounded border px-2 py-1" {...register("password")} />
          {errors.password && <span className="text-xs text-red-600">{errors.password.message}</span>}
        </label>
        {submitError ? <ApiErrorAlert error={submitError} /> : null}
        <button
          type="submit"
          disabled={isSubmitting}
          className="rounded bg-slate-900 px-3 py-2 text-white disabled:opacity-50"
        >
          {isSubmitting ? "Creating..." : "Create organization"}
        </button>
      </form>
      <p className="mt-3 text-sm">
        Already have an account?{" "}
        <Link to="/login" className="underline">
          Log in
        </Link>
      </p>
    </div>
  );
}
