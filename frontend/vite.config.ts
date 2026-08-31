/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Inside docker/frontend-dev (Step 7), this resolves to the backend's
// internal-network hostname ("app"); on the host it defaults to
// localhost, since the frontend-dev docker service doesn't exist yet.
const apiProxyTarget = process.env.VITE_API_PROXY_TARGET ?? "http://localhost:8000";

const proxiedApiPaths = [
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
];

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: Object.fromEntries(
      proxiedApiPaths.map((path) => [path, { target: apiProxyTarget, changeOrigin: true }]),
    ),
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
  },
});
