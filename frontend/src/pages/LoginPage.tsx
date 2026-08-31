import { useState } from "react";
import { Link, Navigate, useLocation, useNavigate, type Location } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { login } from "../api/auth";
import { useAuth } from "../auth/useAuth";
import { ApiErrorAlert } from "../components/ApiErrorAlert";
import { UnauthorizedError } from "../api/errors";

const schema = z.object({
  email: z.string().email("Enter a valid email address"),
  password: z.string().min(1, "Password is required"),
});

type FormValues = z.infer<typeof schema>;

export function LoginPage() {
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<FormValues>({ resolver: zodResolver(schema) });
  const [submitError, setSubmitError] = useState<unknown>(null);
  const { isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  if (isAuthenticated) {
    const redirectTo = (location.state as { from?: Location } | null)?.from?.pathname ?? "/";
    return <Navigate to={redirectTo} replace />;
  }

  const onSubmit = async (values: FormValues) => {
    setSubmitError(null);
    try {
      await login(values.email, values.password);
      const redirectTo = (location.state as { from?: Location } | null)?.from?.pathname ?? "/";
      navigate(redirectTo, { replace: true });
    } catch (error) {
      setSubmitError(error);
    }
  };

  return (
    <div className="mx-auto mt-16 max-w-sm">
      <h1 className="mb-4 text-xl font-semibold">Log in</h1>
      <form onSubmit={handleSubmit(onSubmit)} className="flex flex-col gap-3" noValidate>
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
        {submitError instanceof UnauthorizedError ? (
          // A failed login attempt is a 401 from THIS endpoint specifically,
          // not a session expiring — ApiErrorAlert's generic UnauthorizedError
          // copy ("Your session has expired...") is correct everywhere else
          // in the app but wrong here (Step 7A remediation, finding M-3).
          // ApiErrorAlert itself is untouched; this is a login-page-local
          // override only.
          <div role="alert" className="rounded border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-800">
            Incorrect email or password.
          </div>
        ) : submitError ? (
          <ApiErrorAlert error={submitError} />
        ) : null}
        <button
          type="submit"
          disabled={isSubmitting}
          className="rounded bg-slate-900 px-3 py-2 text-white disabled:opacity-50"
        >
          {isSubmitting ? "Logging in..." : "Log in"}
        </button>
      </form>
      <p className="mt-3 text-sm">
        Need an account?{" "}
        <Link to="/register" className="underline">
          Register
        </Link>
      </p>
    </div>
  );
}
