import { describe, expect, it } from "vitest";
import { act, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderHookWithProviders } from "../test/renderWithProviders";
import { useUsers } from "./useUsers";
import { useUpdateUser } from "./useUpdateUser";

const userA = {
  id: "u-a",
  organization_id: "org-1",
  email: "a@example.com",
  full_name: "User A",
  role: "viewer" as const,
  is_active: true,
  created_at: "2026-01-01T00:00:00Z",
};
const userB = { ...userA, id: "u-b", email: "b@example.com", full_name: "User B" };

function useComposite() {
  return { list: useUsers(), update: useUpdateUser() };
}

describe("useUpdateUser", () => {
  it("patches only the affected row in the cached list, in place, without a refetch", async () => {
    let listCallCount = 0;
    server.use(
      http.get("/users", () => {
        listCallCount += 1;
        return HttpResponse.json([userA, userB]);
      }),
      http.patch("/users/:id", () => HttpResponse.json({ ...userA, role: "analyst" })),
    );

    const { result } = renderHookWithProviders(() => useComposite());
    await waitFor(() => expect(result.current.list.data).toHaveLength(2));
    expect(listCallCount).toBe(1);

    await act(async () => {
      await result.current.update.mutateAsync({ userId: userA.id, payload: { role: "analyst" } });
    });

    await waitFor(() => expect(result.current.list.data?.find((u) => u.id === userA.id)?.role).toBe("analyst"));
    // userB's row must be untouched.
    expect(result.current.list.data?.find((u) => u.id === userB.id)).toEqual(userB);
    // Patched in place via setQueryData, not a second GET.
    expect(listCallCount).toBe(1);
  });

  it("surfaces a 404 for a cross-org user id", async () => {
    server.use(http.patch("/users/:id", () => HttpResponse.json({ detail: "User not found" }, { status: 404 })));
    const { result } = renderHookWithProviders(() => useUpdateUser());
    await act(async () => {
      await expect(
        result.current.mutateAsync({ userId: "not-mine", payload: { role: "admin" } }),
      ).rejects.toMatchObject({ name: "NotFoundError" });
    });
  });

  it("surfaces the server's self-lockout 400", async () => {
    server.use(
      http.patch("/users/:id", () =>
        HttpResponse.json({ detail: "Cannot modify your own role or active status via this endpoint" }, { status: 400 }),
      ),
    );
    const { result } = renderHookWithProviders(() => useUpdateUser());
    await act(async () => {
      await expect(
        result.current.mutateAsync({ userId: userA.id, payload: { role: "admin" } }),
      ).rejects.toMatchObject({ status: 400 });
    });
  });
});
