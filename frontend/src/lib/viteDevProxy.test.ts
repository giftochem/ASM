// @vitest-environment node
//
// Stage D.1: the real Vite dev server, from the real vite.config.ts, in
// front of a stub backend that records what reaches it. Proves the dev
// proxy itself -- not a mock of it -- serves SPA page loads and passes
// every API request through unchanged.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import http, { type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { createServer, type ViteDevServer } from "vite";
import { http as mswHttp, passthrough } from "msw";
import { server as msw } from "../test/server";
import { BUILD_ASSETS_DIR } from "./spaPageLoads";

const UUID = "11111111-2222-3333-4444-555555555555";
const HTML = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

let backend: http.Server;
let vite: ViteDevServer;
let base: string;
const reachedBackend: { method: string; url: string; csrf: string | undefined }[] = [];

beforeAll(async () => {
  backend = http.createServer((req: IncomingMessage, res) => {
    reachedBackend.push({ method: req.method ?? "", url: req.url ?? "", csrf: req.headers["x-csrf-token"] as string | undefined });
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ stub_api: true, method: req.method, url: req.url }));
  });
  await new Promise<void>((resolve) => backend.listen(0, "127.0.0.1", resolve));
  process.env.VITE_API_PROXY_TARGET = `http://127.0.0.1:${(backend.address() as AddressInfo).port}`;

  vite = await createServer({
    configFile: path.resolve(__dirname, "../../vite.config.ts"),
    root: path.resolve(__dirname, "../.."),
    logLevel: "silent",
    optimizeDeps: { noDiscovery: true, include: [] },
    server: { host: "127.0.0.1", port: 0, hmr: false },
  });
  await vite.listen();
  base = `http://127.0.0.1:${(vite.httpServer!.address() as AddressInfo).port}`;
}, 60_000);

afterAll(async () => {
  await vite?.close();
  await new Promise<void>((resolve) => backend?.close(() => resolve()));
  delete process.env.VITE_API_PROXY_TARGET;
});

beforeEach(() => {
  // The global test setup's MSW server intercepts outgoing requests; these
  // local ones (to Vite, and Vite's proxy to the stub) must really happen.
  msw.use(mswHttp.all(/^http:\/\/127\.0\.0\.1:\d+\//, () => passthrough()));
  reachedBackend.length = 0;
});

async function request(method: string, url: string, headers: Record<string, string> = {}) {
  const response = await fetch(`${base}${url}`, { method, headers, body: ["POST", "PATCH"].includes(method) ? "{}" : undefined });
  return { status: response.status, type: response.headers.get("content-type") ?? "", body: await response.text() };
}

describe("production build (real vite.config.ts)", () => {
  it("puts the bundles in the directory that stays out of the API's paths", () => {
    expect(vite.config.build.assetsDir).toBe(BUILD_ASSETS_DIR);
    expect(BUILD_ASSETS_DIR).not.toBe("assets");
  });
});

describe("Vite dev proxy (real vite.config.ts)", () => {
  it.each(["/assets", "/assets?search=example", `/assets/${UUID}`, "/alerts", "/scans", `/scans/${UUID}`, "/findings", "/reports"])(
    "serves the SPA for a page load of %s without contacting the API",
    async (url) => {
      const response = await request("GET", url, { Accept: HTML });

      expect(response.status).toBe(200);
      expect(response.type).toContain("text/html");
      expect(response.body).toContain('<div id="root">');
      expect(reachedBackend).toEqual([]);
    },
  );

  it.each(["/", "/exposure-paths", "/settings/users", "/no-such-page"])("serves the SPA for %s, which the API doesn't use", async (url) => {
    const response = await request("GET", url, { Accept: HTML });

    expect(response.body).toContain('<div id="root">');
    expect(reachedBackend).toEqual([]);
  });

  it.each([
    ["GET", "/assets", "*/*"],
    ["GET", `/assets/${UUID}`, "application/json"],
    ["GET", "/assets/exposure-paths?max_hops=1", "*/*"],
    ["GET", "/assets/activity", HTML],
    ["GET", `/reports/${UUID}/download`, HTML],
    ["GET", "/users/me", HTML],
    ["POST", "/assets", HTML],
    ["PATCH", `/assets/${UUID}`, HTML],
    ["DELETE", `/scans/${UUID}`, HTML],
  ])("passes %s %s (Accept %s) to the API unchanged", async (method, url, accept) => {
    const response = await request(method, url, { Accept: accept, "X-CSRF-Token": "csrf-from-cookie" });

    expect(response.type).toContain("application/json");
    expect(JSON.parse(response.body)).toEqual({ stub_api: true, method, url });
    expect(reachedBackend).toEqual([{ method, url, csrf: "csrf-from-cookie" }]);
  });
});
