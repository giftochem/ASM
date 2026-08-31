import { describe, expect, it } from "vitest";
import { act, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderHookWithProviders } from "../test/renderWithProviders";
import { useUsers } from "./useUsers";
import { useCreateUser } from "./useCreateUser";

const fakeUser = {
  id: "u1",
  organization_id: "org-1",
  email: "new@example.com",
  full_name: "New Person",
  role: "viewer" as const,
  is_active: true,
  created_at: "2026-01-01T00:00:00Z",
};

function useComposite() {
  return { list: useUsers(), create: useCreateUser() };
}

describe("useCreateUser", () => {
  it("invalidates and refetches the user list on success", async () => {
    let listCallCount = 0;
    server.use(
      http.get("/users", () => {
        listCallCount += 1;
        return HttpResponse.json(listCallCount === 1 ? [] : [fakeUser]);
      }),
      http.post("/users", () => HttpResponse.json(fakeUser, { status: 201 })),
    );

    const { result } = renderHookWithProviders(() => useComposite());
    await waitFor(() => expect(result.current.list.data).toEqual([]));

    await act(async () => {
      await result.current.create.mutateAsync({
        email: fakeUser.email,
        password: "correct-horse-battery",
        full_name: fakeUser.full_name,
        role: "viewer",
      });
    });

    await waitFor(() => expect(result.current.list.data).toEqual([fakeUser]));
    expect(listCallCount).toBe(2);
  });

  it("surfaces a 409 duplicate-email error without touching the cached list", async () => {
    server.use(
      http.get("/users", () => HttpResponse.json([])),
      http.post("/users", () => HttpResponse.json({ detail: "Email already registered" }, { status: 409 })),
    );

    const { result } = renderHookWithProviders(() => useComposite());
    await waitFor(() => expect(result.current.list.isSuccess).toBe(true));

    await act(async () => {
      await expect(
        result.current.create.mutateAsync({
          email: "dup@example.com",
          password: "correct-horse-battery",
          full_name: "X",
          role: "viewer",
        }),
      ).rejects.toMatchObject({ status: 409 });
    });

    expect(result.current.list.data).toEqual([]);
  });
});
