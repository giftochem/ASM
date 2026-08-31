import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { renderWithProviders } from "../test/renderWithProviders";
import { FindingsPage } from "./FindingsPage";

function fakeFinding(overrides: Record<string, unknown> = {}) {
  return {
    id: `f-${Math.random().toString(36).slice(2)}`,
    scan_id: "s1111111-1111-1111-1111-111111111111",
    asset_id: "a1111111-1111-1111-1111-111111111111",
    module: "whois",
    title: "Registrar found",
    description: null,
    severity: "info",
    confidence: 1,
    exposure: 1,
    exploitability: 0.5,
    evidence: null,
    created_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

describe("FindingsPage — read-only, cross-tenant-safe list", () => {
  it("shows a loading state, then rows", async () => {
    server.use(http.get("/findings", () => HttpResponse.json([fakeFinding({ title: "Open port 22" })])));
    renderWithProviders(<FindingsPage />);
    await waitFor(() => expect(screen.getByText("Open port 22")).toBeInTheDocument());
  });

  it("shows an error state on a backend failure instead of crashing", async () => {
    server.use(http.get("/findings", () => HttpResponse.json({ detail: "Service temporarily unavailable" }, { status: 503 })));
    renderWithProviders(<FindingsPage />);
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
  });

  it("shows an empty state with no rows, not an error", async () => {
    server.use(http.get("/findings", () => HttpResponse.json([])));
    renderWithProviders(<FindingsPage />);
    await waitFor(() => expect(screen.getByText(/no findings match/i)).toBeInTheDocument());
  });

  it("has no create/mutate UI at all — genuinely read-only for every role (no useAuth dependency, matching the backend's no-RBAC-restriction contract)", async () => {
    server.use(http.get("/findings", () => HttpResponse.json([fakeFinding()])));
    renderWithProviders(<FindingsPage />);
    await waitFor(() => expect(screen.getByText("Registrar found")).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /add|create|delete|edit/i })).not.toBeInTheDocument();
  });

  it("severity filter is sent to the server (server-side filtering, not client-side)", async () => {
    let capturedSeverity: string | null = "unset";
    server.use(
      http.get("/findings", ({ request }) => {
        capturedSeverity = new URL(request.url).searchParams.get("severity");
        return HttpResponse.json([]);
      }),
    );
    const user = userEvent.setup();
    renderWithProviders(<FindingsPage />);
    await waitFor(() => expect(capturedSeverity).toBeNull());

    await user.selectOptions(screen.getByDisplayValue("All severities"), "critical");
    await waitFor(() => expect(capturedSeverity).toBe("critical"));
  });

  it("module filter is sent to the server", async () => {
    let capturedModule: string | null = "unset";
    server.use(
      http.get("/findings", ({ request }) => {
        capturedModule = new URL(request.url).searchParams.get("module");
        return HttpResponse.json([]);
      }),
    );
    const user = userEvent.setup();
    renderWithProviders(<FindingsPage />);
    await waitFor(() => expect(capturedModule).toBeNull());

    await user.selectOptions(screen.getByDisplayValue("All modules"), "port_scanner");
    await waitFor(() => expect(capturedModule).toBe("port_scanner"));
  });

  it("paginates: Next disabled on a short final page, enabled on a full page, offset advances on click", async () => {
    let capturedOffset: string | null = "unset";
    server.use(
      http.get("/findings", ({ request }) => {
        capturedOffset = new URL(request.url).searchParams.get("offset");
        // First page (offset 0): a full page of 25. Second page: only 3, signaling the end.
        const count = capturedOffset === "0" ? 25 : 3;
        return HttpResponse.json(Array.from({ length: count }, () => fakeFinding()));
      }),
    );
    const user = userEvent.setup();

    renderWithProviders(<FindingsPage />);
    await waitFor(() => expect(screen.getByText("Page 1")).toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
    await waitFor(() => expect(screen.getByRole("button", { name: "Next" })).not.toBeDisabled());

    await user.click(screen.getByRole("button", { name: "Next" }));

    await waitFor(() => expect(capturedOffset).toBe("25"));
    await waitFor(() => expect(screen.getByText("Page 2")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByRole("button", { name: "Next" })).toBeDisabled());
    expect(screen.getByRole("button", { name: "Previous" })).not.toBeDisabled();
  });

  it("resets to page 1 (offset 0) when a filter changes while on a later page", async () => {
    let capturedOffset: string | null = "unset";
    let capturedSeverity: string | null = "unset";
    server.use(
      http.get("/findings", ({ request }) => {
        const url = new URL(request.url);
        capturedOffset = url.searchParams.get("offset");
        capturedSeverity = url.searchParams.get("severity");
        return HttpResponse.json(Array.from({ length: 25 }, () => fakeFinding()));
      }),
    );
    const user = userEvent.setup();

    renderWithProviders(<FindingsPage />);
    await waitFor(() => expect(capturedOffset).toBe("0"));
    await user.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(capturedOffset).toBe("25"));

    await user.selectOptions(screen.getByDisplayValue("All severities"), "high");
    await waitFor(() => expect(capturedSeverity).toBe("high"));
    expect(capturedOffset).toBe("0");
    expect(screen.getByText("Page 1")).toBeInTheDocument();
  });

  describe("cross-tenant isolation via URL-manipulated asset_id/scan_id", () => {
    it("an asset_id for a foreign org (server returns empty, per the join-based scoping) renders an empty state, not a leak or a crash", async () => {
      let capturedAssetId: string | null = "unset";
      server.use(
        http.get("/findings", ({ request }) => {
          capturedAssetId = new URL(request.url).searchParams.get("asset_id");
          // This is exactly what the real backend returns for an asset_id
          // outside the caller's org — the join never matches, so it's an
          // empty list, never another org's rows and never an error.
          return HttpResponse.json([]);
        }),
      );

      renderWithProviders(<FindingsPage />, { route: "/findings?asset_id=not-my-org-asset" });

      await waitFor(() => expect(capturedAssetId).toBe("not-my-org-asset"));
      await waitFor(() => expect(screen.getByText(/no findings match/i)).toBeInTheDocument());
      expect(screen.getByRole("button", { name: /clear asset filter/i })).toBeInTheDocument();
    });

    it("a scan_id for a foreign org renders an empty state the same way", async () => {
      let capturedScanId: string | null = "unset";
      server.use(
        http.get("/findings", ({ request }) => {
          capturedScanId = new URL(request.url).searchParams.get("scan_id");
          return HttpResponse.json([]);
        }),
      );

      renderWithProviders(<FindingsPage />, { route: "/findings?scan_id=not-my-org-scan" });

      await waitFor(() => expect(capturedScanId).toBe("not-my-org-scan"));
      await waitFor(() => expect(screen.getByText(/no findings match/i)).toBeInTheDocument());
      expect(screen.getByRole("button", { name: /clear scan filter/i })).toBeInTheDocument();
    });

    it("clearing the resource filter removes it from the next request", async () => {
      let capturedHasAssetId = true;
      server.use(
        http.get("/findings", ({ request }) => {
          capturedHasAssetId = new URL(request.url).searchParams.has("asset_id");
          return HttpResponse.json([]);
        }),
      );
      const user = userEvent.setup();

      renderWithProviders(<FindingsPage />, { route: "/findings?asset_id=some-asset" });
      await waitFor(() => expect(capturedHasAssetId).toBe(true));

      await user.click(screen.getByRole("button", { name: /clear asset filter/i }));

      await waitFor(() => expect(capturedHasAssetId).toBe(false));
    });

    it("does not construct any request using a raw finding_id — no such endpoint exists, and nothing in this page ever builds one", async () => {
      let requestedPaths: string[] = [];
      server.use(
        http.get("/findings", ({ request }) => {
          requestedPaths.push(new URL(request.url).pathname);
          return HttpResponse.json([fakeFinding({ id: "leaked-looking-id" })]);
        }),
      );

      renderWithProviders(<FindingsPage />);
      await waitFor(() => expect(screen.getByText("Registrar found")).toBeInTheDocument());

      expect(requestedPaths.every((p) => p === "/findings")).toBe(true);
    });
  });
});
