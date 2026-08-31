import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { RequireAuth } from "./RequireAuth";
import { useAuth } from "./useAuth";

vi.mock("./useAuth");
const mockedUseAuth = vi.mocked(useAuth);

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route
          path="/protected"
          element={
            <RequireAuth>
              <div>Protected content</div>
            </RequireAuth>
          }
        />
        <Route path="/login" element={<div>Login page</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("RequireAuth", () => {
  it("renders nothing while the session check is loading", () => {
    mockedUseAuth.mockReturnValue({ user: null, isLoading: true, isAuthenticated: false });
    const { container } = renderAt("/protected");
    expect(container.textContent).toBe("");
  });

  it("redirects to /login when not authenticated", () => {
    mockedUseAuth.mockReturnValue({ user: null, isLoading: false, isAuthenticated: false });
    renderAt("/protected");
    expect(screen.getByText("Login page")).toBeInTheDocument();
  });

  it("renders children when authenticated", () => {
    mockedUseAuth.mockReturnValue({ user: null, isLoading: false, isAuthenticated: true });
    renderAt("/protected");
    expect(screen.getByText("Protected content")).toBeInTheDocument();
  });
});
