import { describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderWithProviders } from "../test/renderWithProviders";
import { useAuth } from "../auth/useAuth";
import { LoginPage } from "./LoginPage";

vi.mock("../auth/useAuth");
const mockedUseAuth = vi.mocked(useAuth);

function mockUnauthenticated() {
  mockedUseAuth.mockReturnValue({ user: null, isLoading: false, isAuthenticated: false });
}

async function submitLogin(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText("Email"), "someone@example.com");
  await user.type(screen.getByLabelText("Password"), "wrong-password");
  await user.click(screen.getByRole("button", { name: /log in/i }));
}

describe("LoginPage — failed-login messaging (Step 7A remediation, finding M-3)", () => {
  it("shows 'Incorrect email or password' for a failed login, not the generic session-expired copy", async () => {
    mockUnauthenticated();
    server.use(http.post("/auth/login", () => HttpResponse.json({ detail: "Incorrect email or password" }, { status: 401 })));
    const user = userEvent.setup();

    renderWithProviders(<LoginPage />);
    await submitLogin(user);

    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Incorrect email or password"));
    expect(screen.queryByText(/session has expired/i)).not.toBeInTheDocument();
  });

  it("still uses the generic ApiErrorAlert copy for a non-401 error (e.g. account-lockout 429)", async () => {
    mockUnauthenticated();
    server.use(
      http.post("/auth/login", () =>
        HttpResponse.json({ detail: "Too many failed login attempts. Try again later." }, { status: 429 }),
      ),
    );
    const user = userEvent.setup();

    renderWithProviders(<LoginPage />);
    await submitLogin(user);

    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/too many requests/i));
  });

  it("clears the previous error on a new submit attempt", async () => {
    mockUnauthenticated();
    server.use(http.post("/auth/login", () => HttpResponse.json({ detail: "Incorrect email or password" }, { status: 401 })));
    const user = userEvent.setup();

    renderWithProviders(<LoginPage />);
    await submitLogin(user);
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());

    server.use(http.post("/auth/login", () => HttpResponse.json({ id: "u1" })));
    await user.click(screen.getByRole("button", { name: /log in/i }));

    await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
  });
});
