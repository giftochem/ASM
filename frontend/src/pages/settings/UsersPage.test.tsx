import { describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "../../test/server";
import { renderWithProviders } from "../../test/renderWithProviders";
import { useAuth } from "../../auth/useAuth";
import { UsersPage } from "./UsersPage";

vi.mock("../../auth/useAuth");
const mockedUseAuth = vi.mocked(useAuth);

const currentAdmin = {
  id: "admin-self",
  organization_id: "org-1",
  email: "admin@example.com",
  full_name: "Admin Self",
  role: "admin" as const,
  is_active: true,
  created_at: "2026-01-01T00:00:00Z",
};

const otherUser = {
  id: "other-user",
  organization_id: "org-1",
  email: "other@example.com",
  full_name: "Other User",
  role: "viewer" as const,
  is_active: true,
  created_at: "2026-01-01T00:00:00Z",
};

function mockAuth() {
  mockedUseAuth.mockReturnValue({ user: currentAdmin as never, isLoading: false, isAuthenticated: true });
}

describe("UsersPage", () => {
  it("shows a loading state, then users", async () => {
    mockAuth();
    server.use(http.get("/users", () => HttpResponse.json([otherUser])));
    renderWithProviders(<UsersPage />);
    expect(screen.getByText(/loading/i)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("table")).toBeInTheDocument());
  });

  it("shows an error state on a backend failure instead of crashing", async () => {
    mockAuth();
    server.use(http.get("/users", () => HttpResponse.json({ detail: "Service temporarily unavailable" }, { status: 503 })));
    renderWithProviders(<UsersPage />);
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
  });

  it("disables role and status controls on the signed-in admin's own row (self-lockout guardrail)", async () => {
    mockAuth();
    server.use(http.get("/users", () => HttpResponse.json([currentAdmin, otherUser])));
    renderWithProviders(<UsersPage />);
    await waitFor(() => expect(screen.getByRole("table")).toBeInTheDocument());

    expect(screen.getByLabelText(`Role for ${currentAdmin.email}`)).toBeDisabled();
    expect(screen.getByLabelText(/deactivate admin@example.com/i)).toBeDisabled();

    // The other row must remain fully interactive.
    expect(screen.getByLabelText(`Role for ${otherUser.email}`)).not.toBeDisabled();
    expect(screen.getByLabelText(/deactivate other@example.com/i)).not.toBeDisabled();
  });

  it("changes another user's role", async () => {
    mockAuth();
    server.use(
      http.get("/users", () => HttpResponse.json([otherUser])),
      http.patch("/users/:id", async ({ request }) => {
        const body = (await request.json()) as { role: string };
        expect(body).toEqual({ role: "analyst" });
        return HttpResponse.json({ ...otherUser, role: "analyst" });
      }),
    );
    const user = userEvent.setup();

    renderWithProviders(<UsersPage />);
    await waitFor(() => expect(screen.getByRole("table")).toBeInTheDocument());

    await user.selectOptions(screen.getByLabelText(`Role for ${otherUser.email}`), "analyst");

    await waitFor(() => expect(screen.getByLabelText(`Role for ${otherUser.email}`)).toHaveValue("analyst"));
  });

  it("toggles another user's active status", async () => {
    mockAuth();
    server.use(
      http.get("/users", () => HttpResponse.json([otherUser])),
      http.patch("/users/:id", async ({ request }) => {
        const body = (await request.json()) as { is_active: boolean };
        expect(body).toEqual({ is_active: false });
        return HttpResponse.json({ ...otherUser, is_active: false });
      }),
    );
    const user = userEvent.setup();

    renderWithProviders(<UsersPage />);
    await waitFor(() => expect(screen.getByRole("table")).toBeInTheDocument());

    await user.click(screen.getByLabelText(/deactivate other@example.com/i));

    await waitFor(() => expect(screen.getByRole("button", { name: /activate other@example.com/i })).toBeInTheDocument());
  });

  it("surfaces a row-level error (e.g. a 404 race on a deleted-elsewhere user) without crashing the page", async () => {
    mockAuth();
    server.use(
      http.get("/users", () => HttpResponse.json([otherUser])),
      http.patch("/users/:id", () => HttpResponse.json({ detail: "User not found" }, { status: 404 })),
    );
    const user = userEvent.setup();

    renderWithProviders(<UsersPage />);
    await waitFor(() => expect(screen.getByRole("table")).toBeInTheDocument());

    await user.click(screen.getByLabelText(/deactivate other@example.com/i));

    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
  });

  it("creates a user and reflects it in the list", async () => {
    mockAuth();
    let users = [otherUser];
    server.use(
      http.get("/users", () => HttpResponse.json(users)),
      http.post("/users", async ({ request }) => {
        const body = (await request.json()) as { email: string; full_name: string; role: string };
        const created = { ...otherUser, id: "new-user", email: body.email, full_name: body.full_name, role: body.role as "viewer" };
        users = [...users, created];
        return HttpResponse.json(created, { status: 201 });
      }),
    );
    const user = userEvent.setup();

    renderWithProviders(<UsersPage />);
    await waitFor(() => expect(screen.getByRole("table")).toBeInTheDocument());

    await user.type(screen.getByPlaceholderText("Full name"), "New Analyst");
    await user.type(screen.getByPlaceholderText("Email"), "newanalyst@example.com");
    await user.type(screen.getByPlaceholderText("Temporary password"), "correct-horse-battery");
    await user.selectOptions(screen.getByLabelText("New user role"), "analyst");
    await user.click(screen.getByRole("button", { name: /^add user$/i }));

    await waitFor(() => expect(screen.getByText("newanalyst@example.com")).toBeInTheDocument());
  });

  it("surfaces a 409 duplicate-email error on create", async () => {
    mockAuth();
    server.use(
      http.get("/users", () => HttpResponse.json([])),
      http.post("/users", () => HttpResponse.json({ detail: "Email already registered" }, { status: 409 })),
    );
    const user = userEvent.setup();

    renderWithProviders(<UsersPage />);
    await waitFor(() => expect(screen.getByText(/no users yet/i)).toBeInTheDocument());

    await user.type(screen.getByPlaceholderText("Full name"), "Dup");
    await user.type(screen.getByPlaceholderText("Email"), "dup@example.com");
    await user.type(screen.getByPlaceholderText("Temporary password"), "correct-horse-battery");
    await user.click(screen.getByRole("button", { name: /^add user$/i }));

    await waitFor(() => expect(screen.getByText("Email already registered")).toBeInTheDocument());
  });

  it("rejects a too-short password client-side before ever calling the server", async () => {
    mockAuth();
    let postCalled = false;
    server.use(
      http.get("/users", () => HttpResponse.json([])),
      http.post("/users", () => {
        postCalled = true;
        return HttpResponse.json(otherUser, { status: 201 });
      }),
    );
    const user = userEvent.setup();

    renderWithProviders(<UsersPage />);
    await waitFor(() => expect(screen.getByText(/no users yet/i)).toBeInTheDocument());

    await user.type(screen.getByPlaceholderText("Full name"), "Short Pw");
    await user.type(screen.getByPlaceholderText("Email"), "shortpw@example.com");
    await user.type(screen.getByPlaceholderText("Temporary password"), "tooshort");
    await user.click(screen.getByRole("button", { name: /^add user$/i }));

    await waitFor(() => expect(screen.getByText(/at least 12 characters/i)).toBeInTheDocument());
    expect(postCalled).toBe(false);
  });
});
