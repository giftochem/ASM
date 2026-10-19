/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { API_PATH_PREFIXES, BUILD_ASSETS_DIR, isSpaPageLoad } from "./src/lib/spaPageLoads";

// Inside docker/frontend-dev (Step 7), this resolves to the backend's
// internal-network hostname ("app"); on the host it defaults to
// localhost, since the frontend-dev docker service doesn't exist yet.
const apiProxyTarget = process.env.VITE_API_PROXY_TARGET ?? "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  build: {
    // Not Vite's default "assets": that is the API's own /assets prefix, so
    // nginx would send the app's JS and CSS to the API and the SPA could
    // never start (see src/lib/spaPageLoads.ts).
    assetsDir: BUILD_ASSETS_DIR,
  },
  server: {
    proxy: Object.fromEntries(
      API_PATH_PREFIXES.map((path) => [
        path,
        {
          target: apiProxyTarget,
          changeOrigin: true,
          // A browser page load of an SPA page that shares its path with
          // the API gets the SPA, not the API (see src/lib/spaPageLoads.ts).
          bypass: (req) => (isSpaPageLoad(req.method, req.url, req.headers.accept) ? "/index.html" : undefined),
        },
      ]),
    ),
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
  },
});
