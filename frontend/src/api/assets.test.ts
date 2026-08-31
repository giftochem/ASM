import { beforeEach, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import {
  confirmAuthorization,
  createAsset,
  getAsset,
  listAssets,
  revokeAuthorization,
} from "./assets";
import { NotFoundError, ForbiddenError } from "./errors";

const fakeAsset = {
  id: "11111111-1111-1111-1111-111111111111",
  organization_id: "22222222-2222-2222-2222-222222222222",
  asset_type: "domain" as const,
  value: "example.com",
  parent_asset_id: null,
  authorization_confirmed: false,
  authorization_confirmed_by: null,
  authorization_confirmed_at: null,
  notes: null,
  is_active: true,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

beforeEach(() => {
  document.cookie = "csrf_token=test-csrf-token; path=/";
});

describe("api/assets.ts — request contract", () => {
  it("listAssets sends GET /assets with no query params (server has none)", async () => {
    let capturedUrl = "";
    server.use(
      http.get("/assets", ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json([fakeAsset]);
      }),
    );

    const result = await listAssets();

    expect(new URL(capturedUrl).search).toBe("");
    expect(result).toEqual([fakeAsset]);
  });

  it("getAsset sends GET /assets/:id", async () => {
    server.use(
      http.get("/assets/:id", ({ params }) => {
        expect(params.id).toBe(fakeAsset.id);
        return HttpResponse.json(fakeAsset);
      }),
    );

    const result = await getAsset(fakeAsset.id);
    expect(result).toEqual(fakeAsset);
  });

  it("getAsset on a cross-org id surfaces NotFoundError (404, never 403 — see _get_org_asset_or_404)", async () => {
    server.use(http.get("/assets/:id", () => HttpResponse.json({ detail: "Asset not found" }, { status: 404 })));

    await expect(getAsset("does-not-exist")).rejects.toBeInstanceOf(NotFoundError);
  });

  it("createAsset POSTs the exact AssetCreate shape with the CSRF header attached", async () => {
    let capturedBody: unknown = null;
    let capturedCsrf: string | null = null;
    server.use(
      http.post("/assets", async ({ request }) => {
        capturedBody = await request.json();
        capturedCsrf = request.headers.get("X-CSRF-Token");
        return HttpResponse.json(fakeAsset, { status: 201 });
      }),
    );

    await createAsset({ asset_type: "domain", value: "example.com", notes: null });

    expect(capturedBody).toEqual({ asset_type: "domain", value: "example.com", notes: null });
    expect(capturedCsrf).toBe("test-csrf-token");
  });

  it("createAsset surfaces a viewer's 403 as ForbiddenError with reason 'rbac'", async () => {
    server.use(
      http.post("/assets", () =>
        HttpResponse.json({ detail: "Requires one of roles: admin, analyst" }, { status: 403 }),
      ),
    );

    const error = await createAsset({ asset_type: "domain", value: "example.com" }).catch((e) => e);
    expect(error).toBeInstanceOf(ForbiddenError);
    expect((error as InstanceType<typeof ForbiddenError>).reason).toBe("rbac");
  });

  it("createAsset surfaces a duplicate-asset 409 with the backend's message", async () => {
    server.use(http.post("/assets", () => HttpResponse.json({ detail: "Asset already exists" }, { status: 409 })));

    await expect(createAsset({ asset_type: "domain", value: "example.com" })).rejects.toMatchObject({
      status: 409,
      message: "Asset already exists",
    });
  });

  it("createAsset surfaces a 422 value-validation error with a readable message (Pydantic model_validator shape)", async () => {
    server.use(
      http.post("/assets", () =>
        HttpResponse.json(
          {
            detail: [
              {
                type: "value_error",
                loc: ["body"],
                msg: "Value error, 'not a domain!' must have at least a domain and a TLD label",
              },
            ],
          },
          { status: 422 },
        ),
      ),
    );

    await expect(createAsset({ asset_type: "domain", value: "not a domain!" })).rejects.toMatchObject({
      status: 422,
      message: expect.stringContaining("must have at least a domain and a TLD label"),
    });
  });

  it("confirmAuthorization POSTs authorization_confirmed=true with the optional note", async () => {
    let capturedBody: unknown = null;
    server.use(
      http.post("/assets/:id/confirm-authorization", async ({ request }) => {
        capturedBody = await request.json();
        return HttpResponse.json({ ...fakeAsset, authorization_confirmed: true });
      }),
    );

    const result = await confirmAuthorization(fakeAsset.id, {
      authorization_confirmed: true,
      attestation_note: "engagement #123",
    });

    expect(capturedBody).toEqual({ authorization_confirmed: true, attestation_note: "engagement #123" });
    expect(result.authorization_confirmed).toBe(true);
  });

  it("revokeAuthorization POSTs the optional reason", async () => {
    let capturedBody: unknown = null;
    server.use(
      http.post("/assets/:id/revoke-authorization", async ({ request }) => {
        capturedBody = await request.json();
        return HttpResponse.json({ ...fakeAsset, authorization_confirmed: false });
      }),
    );

    const result = await revokeAuthorization(fakeAsset.id, { reason: "engagement ended" });

    expect(capturedBody).toEqual({ reason: "engagement ended" });
    expect(result.authorization_confirmed).toBe(false);
  });
});
