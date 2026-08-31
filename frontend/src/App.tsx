import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "react-router-dom";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { AuthProvider } from "./auth/AuthProvider";
import { queryClient } from "./lib/queryClient";
import { router } from "./routes";

// Provider order per the approved architecture: ErrorBoundary > AuthProvider
// > QueryClientProvider > RouterProvider. AuthProvider does not depend on
// QueryClientProvider (see auth/AuthProvider.tsx) so this order is safe.
export function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <QueryClientProvider client={queryClient}>
          <RouterProvider router={router} />
        </QueryClientProvider>
      </AuthProvider>
    </ErrorBoundary>
  );
}
