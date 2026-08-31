import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { renderWithProviders } from "../test/renderWithProviders";
import { SettingsPage } from "./SettingsPage";

function StubUsersPage() {
  return <div>Users content</div>;
}
function StubAuditLogsPage() {
  return <div>Audit logs content</div>;
}

function renderSettings(route: string) {
  return renderWithProviders(
    <Routes>
      <Route path="/settings" element={<SettingsPage />}>
        <Route path="users" element={<StubUsersPage />} />
        <Route path="audit-logs" element={<StubAuditLogsPage />} />
      </Route>
    </Routes>,
    { route },
  );
}

describe("SettingsPage", () => {
  it("renders the sub-nav and the matched child route", () => {
    renderSettings("/settings/users");
    expect(screen.getByRole("link", { name: "Users" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Audit logs" })).toBeInTheDocument();
    expect(screen.getByText("Users content")).toBeInTheDocument();
    expect(screen.queryByText("Audit logs content")).not.toBeInTheDocument();
  });

  it("renders the other child route when navigated there", () => {
    renderSettings("/settings/audit-logs");
    expect(screen.getByText("Audit logs content")).toBeInTheDocument();
    expect(screen.queryByText("Users content")).not.toBeInTheDocument();
  });
});
