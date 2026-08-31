import { describe, expect, it } from "vitest";
import { waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderHookWithProviders } from "../test/renderWithProviders";
import { useUsers } from "./useUsers";

const fakeUser = {
  id: "u1",
  organization_id: "org-1",
  email: "person@example.com",
  full_name: "Person One",
  role: "viewer" as const,
  is_active: true,
  created_at: "2026-01-01T00:00:00Z",
};

describe("useUsers", () => {
  it("resolves with the org's user list", async () => {
    server.use(http.get("/users", () => HttpResponse.json([fakeUser])));
    const { result } = renderHookWithProviders(() => useUsers());
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([fakeUser]);
  });

  it("surfaces a non-admin's RBAC 403 as an error state, not a crash", async () => {
    server.use(
      http.get("/users", () => HttpResponse.json({ detail: "Requires one of roles: admin" }, { status: 403 })),
    );
    const { result } = renderHookWithProviders(() => useUsers());
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(result.current.error).toMatchObject({ name: "ForbiddenError", reason: "rbac" });
  });
});
