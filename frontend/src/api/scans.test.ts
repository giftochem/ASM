import { beforeEach, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import {
  cancelScan,
  createScan,
  getScan,
  isTerminalStatus,
  listScans,
  modulesForAssetType,
  SCAN_MODULES,
} from "./scans";
import { ForbiddenError, NotFoundError } from "./errors";

const fakeScan = {
  id: "s1111111-1111-1111-1111-111111111111",
  asset_id: "a1111111-1111-1111-1111-111111111111",
  initiated_by: "u1111111-1111-1111-1111-111111111111",
  status: "queued" as const,
  modules_requested: ["whois"],
  started_at: null,
  completed_at: null,
  error_message: null,
  risk_score: null,
  risk_severity_band: null,
  created_at: "2026-01-01T00:00:00Z",
  findings: [],
};

beforeEach(() => {
  document.cookie = "csrf_token=test-csrf-token; path=/";
});

describe("SCAN_MODULES / modulesForAssetType — mirrors app/scanners/registry.py", () => {
  it("port_scanner only applies to ip_address and requires explicit opt-in", () => {
    const portScanner = SCAN_MODULES.find((m) => m.name === "port_scanner");
    expect(portScanner?.assetTypes).toEqual(["ip_address"]);
    expect(portScanner?.requiresExplicitOptIn).toBe(true);
  });

  it("whois only applies to domain", () => {
    expect(modulesForAssetType("domain").map((m) => m.name)).toContain("whois");
    expect(modulesForAssetType("subdomain").map((m) => m.name)).not.toContain("whois");
  });

  it("ip_range has no applicable modules at all (matches the backend: no module supports it)", () => {
    expect(modulesForAssetType("ip_range")).toEqual([]);
  });

  it("no module other than port_scanner requires explicit opt-in", () => {
    const optInModules = SCAN_MODULES.filter((m) => m.requiresExplicitOptIn);
    expect(optInModules.map((m) => m.name)).toEqual(["port_scanner"]);
  });
});

describe("isTerminalStatus", () => {
  it("queued/running are not terminal; completed/failed/cancelled are", () => {
    expect(isTerminalStatus("queued")).toBe(false);
    expect(isTerminalStatus("running")).toBe(false);
    expect(isTerminalStatus("completed")).toBe(true);
    expect(isTerminalStatus("failed")).toBe(true);
    expect(isTerminalStatus("cancelled")).toBe(true);
  });
});

describe("api/scans.ts — request contract", () => {
  it("listScans() with no assetId sends no query string", async () => {
    let capturedUrl = "";
    server.use(
      http.get("/scans", ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json([fakeScan]);
      }),
    );
    await listScans();
    expect(new URL(capturedUrl).search).toBe("");
  });

  it("listScans(assetId) sends ?asset_id=", async () => {
    let capturedUrl = "";
    server.use(
      http.get("/scans", ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json([fakeScan]);
      }),
    );
    await listScans(fakeScan.asset_id);
    expect(new URL(capturedUrl).searchParams.get("asset_id")).toBe(fakeScan.asset_id);
  });

  it("getScan on a cross-org id surfaces NotFoundError", async () => {
    server.use(http.get("/scans/:id", () => HttpResponse.json({ detail: "Scan not found" }, { status: 404 })));
    await expect(getScan("nope")).rejects.toBeInstanceOf(NotFoundError);
  });

  it("createScan POSTs {asset_id, modules} with the CSRF header attached", async () => {
    let capturedBody: unknown = null;
    let capturedCsrf: string | null = null;
    server.use(
      http.post("/scans", async ({ request }) => {
        capturedBody = await request.json();
        capturedCsrf = request.headers.get("X-CSRF-Token");
        return HttpResponse.json(fakeScan, { status: 201 });
      }),
    );

    await createScan({ asset_id: fakeScan.asset_id, modules: ["whois"] });

    expect(capturedBody).toEqual({ asset_id: fakeScan.asset_id, modules: ["whois"] });
    expect(capturedCsrf).toBe("test-csrf-token");
  });

  it("createScan omits `modules` entirely (not null) when undefined, matching the backend's default-modules contract", async () => {
    let capturedBody: unknown = null;
    server.use(
      http.post("/scans", async ({ request }) => {
        capturedBody = await request.json();
        return HttpResponse.json(fakeScan, { status: 201 });
      }),
    );

    await createScan({ asset_id: fakeScan.asset_id });

    expect(capturedBody).toEqual({ asset_id: fakeScan.asset_id });
  });

  it("createScan surfaces the exact AuthorizationNotConfirmedError message on a 403 (guardrail defense-in-depth)", async () => {
    const message =
      "Asset 'example.com' does not have authorization_confirmed=true. Confirm authorization via POST /assets/{id}/confirm-authorization before scanning.";
    server.use(http.post("/scans", () => HttpResponse.json({ detail: message }, { status: 403 })));

    const error = await createScan({ asset_id: fakeScan.asset_id }).catch((e) => e);
    expect(error).toBeInstanceOf(ForbiddenError);
    expect((error as InstanceType<typeof ForbiddenError>).reason).toBe("other");
    expect((error as Error).message).toBe(message);
  });

  it("createScan surfaces a viewer's RBAC 403", async () => {
    server.use(
      http.post("/scans", () =>
        HttpResponse.json({ detail: "Requires one of roles: admin, analyst" }, { status: 403 }),
      ),
    );
    const error = await createScan({ asset_id: fakeScan.asset_id }).catch((e) => e);
    expect(error).toBeInstanceOf(ForbiddenError);
    expect((error as InstanceType<typeof ForbiddenError>).reason).toBe("rbac");
  });

  it("createScan surfaces a 400 for an unsupported module/asset_type combination", async () => {
    server.use(
      http.post("/scans", () =>
        HttpResponse.json({ detail: "module 'port_scanner' does not support asset_type 'domain'" }, { status: 400 }),
      ),
    );
    await expect(createScan({ asset_id: fakeScan.asset_id, modules: ["port_scanner"] })).rejects.toMatchObject({
      status: 400,
      message: expect.stringContaining("does not support asset_type"),
    });
  });

  it("createScan surfaces a 404 for a nonexistent/cross-org asset", async () => {
    server.use(http.post("/scans", () => HttpResponse.json({ detail: "Asset not found" }, { status: 404 })));
    await expect(createScan({ asset_id: "does-not-exist" })).rejects.toBeInstanceOf(NotFoundError);
  });

  it("cancelScan POSTs to /scans/:id/cancel", async () => {
    server.use(
      http.post("/scans/:id/cancel", () => HttpResponse.json({ ...fakeScan, status: "cancelled" as const })),
    );
    const result = await cancelScan(fakeScan.id);
    expect(result.status).toBe("cancelled");
  });

  it("cancelScan surfaces a 409 when the scan is no longer queued (race with the worker)", async () => {
    server.use(
      http.post("/scans/:id/cancel", () =>
        HttpResponse.json({ detail: "cannot cancel a scan in status 'running'" }, { status: 409 }),
      ),
    );
    await expect(cancelScan(fakeScan.id)).rejects.toMatchObject({ status: 409 });
  });
});
