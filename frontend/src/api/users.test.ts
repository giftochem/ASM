import { beforeEach, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { createUser, listUsers, updateUser } from "./users";
import { ForbiddenError, NotFoundError } from "./errors";

const fakeUser = {
  id: "u1111111-1111-1111-1111-111111111111",
  organization_id: "org-1",
  email: "person@example.com",
  full_name: "Person One",
  role: "viewer" as const,
  is_active: true,
  created_at: "2026-01-01T00:00:00Z",
};

beforeEach(() => {
  document.cookie = "csrf_token=test-csrf-token; path=/";
});

describe("api/users.ts — request contract", () => {
  it("listUsers sends GET /users with no query params", async () => {
    let capturedUrl = "";
    server.use(
      http.get("/users", ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json([fakeUser]);
      }),
    );
    await listUsers();
    expect(new URL(capturedUrl).search).toBe("");
  });

  it("listUsers surfaces a non-admin's RBAC 403 — GET /users is admin-only, unlike GET /assets etc.", async () => {
    server.use(
      http.get("/users", () => HttpResponse.json({ detail: "Requires one of roles: admin" }, { status: 403 })),
    );
    const error = await listUsers().catch((e) => e);
    expect(error).toBeInstanceOf(ForbiddenError);
    expect((error as InstanceType<typeof ForbiddenError>).reason).toBe("rbac");
  });

  it("createUser POSTs the exact UserCreate shape with the CSRF header attached", async () => {
    let capturedBody: unknown = null;
    let capturedCsrf: string | null = null;
    server.use(
      http.post("/users", async ({ request }) => {
        capturedBody = await request.json();
        capturedCsrf = request.headers.get("X-CSRF-Token");
        return HttpResponse.json(fakeUser, { status: 201 });
      }),
    );

    await createUser({ email: "a@example.com", password: "correct-horse-battery", full_name: "A", role: "analyst" });

    expect(capturedBody).toEqual({
      email: "a@example.com",
      password: "correct-horse-battery",
      full_name: "A",
      role: "analyst",
    });
    expect(capturedCsrf).toBe("test-csrf-token");
  });

  it("createUser surfaces a 409 when the email is already registered (backend uniqueness is global, not org-scoped)", async () => {
    server.use(http.post("/users", () => HttpResponse.json({ detail: "Email already registered" }, { status: 409 })));
    await expect(
      createUser({ email: "dup@example.com", password: "correct-horse-battery", full_name: "A", role: "viewer" }),
    ).rejects.toMatchObject({ status: 409 });
  });

  it("createUser surfaces a non-admin's RBAC 403", async () => {
    server.use(
      http.post("/users", () => HttpResponse.json({ detail: "Requires one of roles: admin" }, { status: 403 })),
    );
    const error = await createUser({
      email: "a@example.com",
      password: "correct-horse-battery",
      full_name: "A",
      role: "viewer",
    }).catch((e) => e);
    expect(error).toBeInstanceOf(ForbiddenError);
    expect((error as InstanceType<typeof ForbiddenError>).reason).toBe("rbac");
  });

  it("updateUser PATCHes the exact payload with the CSRF header attached", async () => {
    let capturedBody: unknown = null;
    let capturedCsrf: string | null = null;
    server.use(
      http.patch("/users/:id", async ({ request }) => {
        capturedBody = await request.json();
        capturedCsrf = request.headers.get("X-CSRF-Token");
        return HttpResponse.json({ ...fakeUser, role: "analyst" });
      }),
    );

    await updateUser(fakeUser.id, { role: "analyst" });

    expect(capturedBody).toEqual({ role: "analyst" });
    expect(capturedCsrf).toBe("test-csrf-token");
  });

  it("updateUser on a cross-org user id surfaces NotFoundError (404, never 403 — matches every other ownership-boundary endpoint)", async () => {
    server.use(http.patch("/users/:id", () => HttpResponse.json({ detail: "User not found" }, { status: 404 })));
    await expect(updateUser("not-my-org-user", { role: "admin" })).rejects.toBeInstanceOf(NotFoundError);
  });

  it("updateUser surfaces the server's self-lockout 400 verbatim (defense in depth — the UI disables this, but confirms the server rejects it if ever reached)", async () => {
    server.use(
      http.patch("/users/:id", () =>
        HttpResponse.json({ detail: "Cannot modify your own role or active status via this endpoint" }, { status: 400 }),
      ),
    );
    await expect(updateUser(fakeUser.id, { role: "admin" })).rejects.toMatchObject({
      status: 400,
      message: expect.stringContaining("Cannot modify your own"),
    });
  });

  it("updateUser surfaces the server's empty-payload 400", async () => {
    server.use(
      http.patch("/users/:id", () =>
        HttpResponse.json({ detail: "Provide at least one of role, is_active" }, { status: 400 }),
      ),
    );
    await expect(updateUser(fakeUser.id, {})).rejects.toMatchObject({ status: 400 });
  });

  it("updateUser surfaces a non-admin's RBAC 403", async () => {
    server.use(
      http.patch("/users/:id", () => HttpResponse.json({ detail: "Requires one of roles: admin" }, { status: 403 })),
    );
    const error = await updateUser(fakeUser.id, { is_active: false }).catch((e) => e);
    expect(error).toBeInstanceOf(ForbiddenError);
    expect((error as InstanceType<typeof ForbiddenError>).reason).toBe("rbac");
  });
});
