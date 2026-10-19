import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import type { RouteObject } from "react-router-dom";
import { router } from "../routes";
import { API_PATH_PREFIXES, BUILD_ASSETS_DIR, isSpaPageLoad } from "./spaPageLoads";

const UUID = "11111111-2222-3333-4444-555555555555";
const HTML = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

// [path (with any query string), is it an SPA page sharing its path with the API?]
const PATHS: [string, boolean][] = [
  ["/assets", true],
  ["/assets/", true],
  ["/assets?search=example&status=active", true],
  [`/assets/${UUID}`, true],
  [`/assets/${UUID.toUpperCase()}`, true],
  ["/alerts", true],
  ["/scans", true],
  [`/scans?asset_id=${UUID}`, true],
  [`/scans/${UUID}`, true],
  ["/findings", true],
  ["/reports", true],
  ["/assets/activity", false],
  ["/assets/summary", false],
  ["/assets/exposure-paths", false],
  ["/assets/not-a-uuid", false],
  [`/assets/${UUID}/graph`, false],
  [`/assets/${UUID}/relationships`, false],
  [`/reports/${UUID}`, false],
  [`/reports/${UUID}/download`, false],
  [`/alerts/${UUID}`, false],
  [`/findings/${UUID}`, false],
  ["/audit-logs", false],
  ["/users/me", false],
  ["/auth/login", false],
  ["/discovery/providers", false],
  ["/health", false],
  ["/assetsx", false],
];

describe("isSpaPageLoad", () => {
  it.each(PATHS)("a browser page load of %s gets the SPA: %s", (path, sharedPage) => {
    expect(isSpaPageLoad("GET", path, HTML)).toBe(sharedPage);
  });

  it("covers HEAD page loads and any Accept spelling of text/html", () => {
    expect(isSpaPageLoad("HEAD", `/assets/${UUID}`, HTML)).toBe(true);
    expect(isSpaPageLoad("GET", "/alerts", "TEXT/HTML")).toBe(true);
  });

  it.each([
    ["GET", "*/*"],
    ["GET", "application/json"],
    ["GET", undefined],
    ["POST", HTML],
    ["PATCH", HTML],
    ["PUT", HTML],
    ["DELETE", HTML],
    ["OPTIONS", HTML],
    [undefined, HTML],
  ])("never diverts %s with Accept %s -- API calls and writes keep reaching the API", (method, accept) => {
    expect(isSpaPageLoad(method, `/assets/${UUID}`, accept)).toBe(false);
    expect(isSpaPageLoad(method, "/assets", accept)).toBe(false);
  });
});

function appPaths(routes: RouteObject[], parent = ""): string[] {
  return routes.flatMap((route) => {
    const own = route.index ? parent : route.path ? `${parent}/${route.path}`.replace(/\/+/g, "/") : parent;
    const children = route.children ? appPaths(route.children, own) : [];
    return route.path || route.index ? [own || "/", ...children] : children;
  });
}

describe("every SPA route the proxies would send to the API is covered", () => {
  const samples = appPaths(router.routes)
    .filter((path) => path !== "/*" && !path.includes("*"))
    .map((path) => path.replace(/:[^/]+/g, UUID));

  it("finds the app's routes", () => {
    expect(samples).toEqual(expect.arrayContaining(["/assets", `/assets/${UUID}`, "/exposure-paths", "/settings/users"]));
  });

  it.each(appPaths(router.routes).filter((path) => !path.includes("*")))("%s", (route) => {
    const sample = route.replace(/:[^/]+/g, UUID);
    // Both proxies match API prefixes as plain prefixes (Vite: startsWith;
    // nginx: an unanchored-at-the-end regex), so any page they'd proxy
    // must be rescued by the page-load rule.
    const proxied = API_PATH_PREFIXES.some((prefix) => sample.startsWith(prefix));
    if (proxied) {
      expect(isSpaPageLoad("GET", sample, HTML)).toBe(true);
    } else {
      expect(isSpaPageLoad("GET", sample, HTML)).toBe(false);
    }
  });
});

describe("the production build's static files stay out of the API's paths", () => {
  it("bundles live under a prefix no API route or page uses", () => {
    // viteDevProxy.test.ts checks the real config builds into this directory.
    const bundle = `/${BUILD_ASSETS_DIR}/index-abc123.js`;
    expect(API_PATH_PREFIXES.some((prefix) => bundle.startsWith(prefix))).toBe(false);
    expect(
      appPaths(router.routes).some((route) => route === `/${BUILD_ASSETS_DIR}` || route.startsWith(`/${BUILD_ASSETS_DIR}/`)),
    ).toBe(false);
  });
});

describe("docker/nginx/nginx.conf implements the same rule", () => {
  const conf = readFileSync(path.resolve(__dirname, "../../../docker/nginx/nginx.conf"), "utf8");

  function mapBlock(header: string): string {
    const start = conf.indexOf(header);
    expect(start, `missing ${header}`).toBeGreaterThanOrEqual(0);
    // The block's own closing brace (a line of its own) -- not the } of a
    // regex quantifier such as {8}.
    return conf.slice(start, conf.indexOf("\n}", start));
  }

  function mapRegexes(block: string): RegExp[] {
    return [...block.matchAll(/"~(\*?)([^"]+)"\s+1;/g)].map(([, insensitive, pattern]) => new RegExp(pattern, insensitive ? "i" : ""));
  }

  const pagePaths = mapRegexes(mapBlock("map $request_uri $asm_spa_page_path {"));
  const pageLoad = mapRegexes(mapBlock('map "$request_method:$asm_spa_page_path:$http_accept" $asm_spa_page_load {'));

  it.each(PATHS)("nginx agrees on %s", (path, sharedPage) => {
    expect(pagePaths.some((pattern) => pattern.test(path))).toBe(sharedPage);
  });

  it("nginx diverts only GET/HEAD page loads", () => {
    const loads = (method: string, accept: string) => pageLoad.some((pattern) => pattern.test(`${method}:1:${accept}`));
    expect(loads("GET", HTML)).toBe(true);
    expect(loads("HEAD", "TEXT/HTML")).toBe(true);
    for (const method of ["POST", "PATCH", "PUT", "DELETE", "OPTIONS"]) {
      expect(loads(method, HTML)).toBe(false);
    }
    expect(loads("GET", "*/*")).toBe(false);
    expect(loads("GET", "application/json")).toBe(false);
    expect(pageLoad.some((pattern) => pattern.test(`GET:0:${HTML}`))).toBe(false);
  });

  it("nginx proxies the same API prefixes, and rescues page loads inside the API location", () => {
    const location = conf.match(/location ~ \^\/\(([^)]+)\) \{([\s\S]*?)\n {4}\}/);
    expect(location).not.toBeNull();
    const prefixes = location![1].split("|").map((prefix) => `/${prefix.replace("\\.", ".")}`);
    expect(prefixes.filter((prefix) => !["/docs", "/redoc", "/openapi.json"].includes(prefix)).sort()).toEqual(
      [...API_PATH_PREFIXES].sort(),
    );
    expect(location![2]).toMatch(/if \(\$asm_spa_page_load\) \{\s*rewrite \^ \/index\.html last;\s*\}/);
    expect(location![2].indexOf("rewrite")).toBeLessThan(location![2].indexOf("proxy_pass"));
  });
});
