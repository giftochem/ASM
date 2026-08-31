import { http, HttpResponse } from "msw";

// Baseline: signed-out state, matching a fresh browser with no session
// cookies. Individual tests override these via server.use(...).
export const handlers = [
  http.get("/users/me", () => {
    return HttpResponse.json({ detail: "Could not validate credentials" }, { status: 401 });
  }),
  http.post("/auth/refresh", () => {
    return HttpResponse.json({ detail: "No refresh token" }, { status: 401 });
  }),
];
