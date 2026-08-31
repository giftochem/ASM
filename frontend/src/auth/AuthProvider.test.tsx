import { afterEach, describe, expect, it } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { login, logout } from "../api/auth";
import { queryClient } from "../lib/queryClient";
import { AuthProvider } from "./AuthProvider";
import { useAuth } from "./useAuth";

const fakeUserA = {
  id: "11111111-1111-1111-1111-111111111111",
  organization_id: "22222222-2222-2222-2222-222222222222",
  email: "a@example.com",
  full_name: "User A",
  role: "admin" as const,
  is_active: true,
  created_at: "2026-01-01T00:00:00Z",
};

const fakeUserB = {
  ...fakeUserA,
  id: "33333333-3333-3333-3333-333333333333",
  email: "b@example.com",
  full_name: "User B",
};

function Consumer() {
  const { user, isLoading, isAuthenticated } = useAuth();
  return (
    <div>
      <div data-testid="isLoading">{String(isLoading)}</div>
      <div data-testid="isAuthenticated">{String(isAuthenticated)}</div>
      <div data-testid="email">{user?.email ?? ""}</div>
    </div>
  );
}

afterEach(() => {
  queryClient.clear();
});

describe("AuthProvider", () => {
  it("resolves to signed-out state when there is no session", async () => {
    render(
      <AuthProvider>
        <Consumer />
      </AuthProvider>,
    );

    expect(screen.getByTestId("isLoading").textContent).toBe("true");
    await waitFor(() => expect(screen.getByTestId("isLoading").textContent).toBe("false"));
    expect(screen.getByTestId("isAuthenticated").textContent).toBe("false");
  });

  it("resolves to signed-in state when GET /users/me succeeds", async () => {
    server.use(http.get("/users/me", () => HttpResponse.json(fakeUserA)));

    render(
      <AuthProvider>
        <Consumer />
      </AuthProvider>,
    );

    await waitFor(() => expect(screen.getByTestId("isAuthenticated").textContent).toBe("true"));
    expect(screen.getByTestId("email").textContent).toBe("a@example.com");
  });

  it("clears the query cache and signs out on logout", async () => {
    server.use(http.get("/users/me", () => HttpResponse.json(fakeUserA)));
    render(
      <AuthProvider>
        <Consumer />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByTestId("isAuthenticated").textContent).toBe("true"));

    queryClient.setQueryData(["assets"], [{ id: "user-a-asset" }]);
    expect(queryClient.getQueryData(["assets"])).toBeDefined();

    server.use(http.post("/auth/logout", () => new HttpResponse(null, { status: 204 })));
    await act(() => logout());

    await waitFor(() => expect(screen.getByTestId("isAuthenticated").textContent).toBe("false"));
    expect(queryClient.getQueryData(["assets"])).toBeUndefined();
  });

  it("clears the query cache when a different user logs in over an existing session", async () => {
    server.use(http.get("/users/me", () => HttpResponse.json(fakeUserA)));
    render(
      <AuthProvider>
        <Consumer />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByTestId("email").textContent).toBe("a@example.com"));

    queryClient.setQueryData(["assets"], [{ id: "user-a-asset" }]);

    server.use(http.post("/auth/login", () => HttpResponse.json(fakeUserB)));
    await act(() => login("b@example.com", "correct-horse-battery"));

    await waitFor(() => expect(screen.getByTestId("email").textContent).toBe("b@example.com"));
    expect(queryClient.getQueryData(["assets"])).toBeUndefined();
  });
});
