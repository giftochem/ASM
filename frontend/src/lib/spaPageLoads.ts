// Stage D.1: the SPA and the API share one origin, and some SPA pages use
// the same paths as API endpoints (/assets, /assets/<id>, /alerts,
// /scans, /scans/<id>, /findings, /reports). Proxies route by path, so a
// browser page load of one of those pages -- a hard refresh, a bookmark,
// a new tab -- used to reach the API and show JSON or a 401.
//
// The fix: a request is served the SPA instead only when it is a browser
// page load (GET/HEAD whose Accept includes text/html -- fetch() sends
// */*) AND its path is exactly one of those page shapes. Everything else
// under an API prefix -- every API call, every write, /assets/activity,
// /reports/<id>/download, /docs -- still goes to the API untouched.
//
// docker/nginx/nginx.conf implements the same rule for production
// (spaPageLoads.test.ts checks the two agree), and vite.config.ts uses
// this module for development.

// Top-level API prefixes proxied to the backend (vite.config.ts and
// nginx.conf both list these).
export const API_PATH_PREFIXES = [
  "/auth",
  "/users",
  "/assets",
  "/scans",
  "/reports",
  "/audit-logs",
  "/findings",
  "/discovery",
  "/alerts",
  "/health",
] as const;

// Where the production build puts its JS/CSS (vite.config.ts
// build.assetsDir). Vite's default, "assets", would put the bundles behind
// the API's own /assets prefix -- nginx proxies them to the API and the SPA
// can never start -- so they live under a prefix no API route or page uses.
export const BUILD_ASSETS_DIR = "static";

const UUID = "[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}";

// The SPA pages whose paths are also API endpoints. Ids are UUID-shaped,
// so a static API route such as /assets/activity is never one of them.
export const SPA_PAGES_SHARED_WITH_API: readonly RegExp[] = [
  /^\/(assets|alerts|scans|findings|reports)\/?$/,
  new RegExp(`^/(assets|scans)/${UUID}/?$`),
];

export function isSpaPageLoad(method: string | undefined, url: string | undefined, accept: string | undefined): boolean {
  if (method !== "GET" && method !== "HEAD") return false;
  if (!accept || !accept.toLowerCase().includes("text/html")) return false;
  const path = (url ?? "").split(/[?#]/, 1)[0];
  return SPA_PAGES_SHARED_WITH_API.some((page) => page.test(path));
}
