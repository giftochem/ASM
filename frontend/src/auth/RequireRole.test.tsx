import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { RequireRole } from "./RequireRole";
import { useAuth } from "./useAuth";

vi.mock("./useAuth");
const mockedUseAuth = vi.mocked(useAuth);

const baseUser = {
  id: "11111111-1111-1111-1111-111111111111",
  organization_id: "22222222-2222-2222-2222-222222222222",
  email: "a@example.com",
  full_name: "A One",
  is_active: true,
  created_at: "2026-01-01T00:00:00Z",
};

describe("RequireRole", () => {
  it("renders nothing while the session check is loading", () => {
    mockedUseAuth.mockReturnValue({ user: null, isLoading: true, isAuthenticated: false });
    const { container } = render(
      <RequireRole roles={["admin"]}>
        <div>Admin content</div>
      </RequireRole>,
    );
    expect(container.textContent).toBe("");
  });

  it("shows NotAuthorizedPage when the user's role is not permitted (UX guard, not the security boundary)", () => {
    mockedUseAuth.mockReturnValue({
      user: { ...baseUser, role: "viewer" },
      isLoading: false,
      isAuthenticated: true,
    });
    render(
      <RequireRole roles={["admin"]}>
        <div>Admin content</div>
      </RequireRole>,
    );
    expect(screen.getByText(/not authorized/i)).toBeInTheDocument();
    expect(screen.queryByText("Admin content")).not.toBeInTheDocument();
  });

  it("renders children when the user's role is permitted", () => {
    mockedUseAuth.mockReturnValue({
      user: { ...baseUser, role: "admin" },
      isLoading: false,
      isAuthenticated: true,
    });
    render(
      <RequireRole roles={["admin"]}>
        <div>Admin content</div>
      </RequireRole>,
    );
    expect(screen.getByText("Admin content")).toBeInTheDocument();
  });
});
