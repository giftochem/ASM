# Production deployment posture (Step 7B)

This covers what changes between the dev setup (`docker-compose.yml`) and
the production one (`docker-compose.prod.yml`), and the one-time setup
steps the latter depends on. It does not cover CI/CD or secrets-manager
integration — those are separate, not-yet-scoped work.

## What's different in `docker-compose.prod.yml`

- `app` and `worker` run the image exactly as built (`COPY . .` at build
  time) — no source bind-mount, no `--reload`. Editing files on the host
  no longer changes running behavior; rebuild the image instead.
- `app` has no host port mapping. It's reachable only via `nginx`, over
  the internal `asm_net` network.
- `nginx` terminates TLS on 443 (redirecting 80 → 443) and either proxies
  to `app` (known API route prefixes) or serves the built frontend as a
  static SPA. See `docker/nginx/nginx.conf` for the exact route list —
  if a new top-level router prefix is added to
  `backend/app/api/routes/__init__.py`, add it there too, or requests to
  it will silently fall through to the SPA and get `index.html` instead
  of an API response.
- `nginx` sits on `asm_net` at a pinned address (`172.28.0.10`), which
  `app`'s `TRUSTED_PROXY_IPS_RAW` names deterministically (hardcoded in
  this file — see the comment on `app`'s `environment:` block).

## One-time setup

1. **Build the frontend.**
   ```
   cd frontend
   npm ci
   npm run build
   ```
   This produces `frontend/dist/`, which `nginx` serves directly via bind
   mount. Re-run this after any frontend change and before restarting
   `nginx` — there's no auto-rebuild in the prod file.

2. **Generate a TLS cert.**
   ```
   docker\nginx\generate-self-signed-cert.ps1
   ```
   Self-signed, `CN=localhost`, valid 365 days — browsers will show a
   trust warning, which is expected until a real domain exists. Output
   goes to `docker/nginx/certs/` (gitignored — same rule as `.env`: a
   private key, even a throwaway one, is never committed). When a real
   domain and CA-issued cert (Let's Encrypt/ACME or otherwise) exist,
   replace `fullchain.pem`/`privkey.pem` in that directory with the real
   ones — nothing else needs to change.

3. **Nothing to do here** — `docker-compose.prod.yml` sets
   `TRUSTED_PROXY_IPS_RAW` itself (hardcoded to nginx's pinned network
   address), so `app/core/client_ip.py` trusts `nginx`'s
   `X-Forwarded-For` automatically. Don't add this to the shared `.env`
   instead: `.env` is read by both compose files, and a value only
   correct for the prod topology broke `docker-compose.yml`'s own test
   suite guard (`test_default_trusted_proxy_ips_is_empty`) the first time
   this was tried — see the comment on `docker-compose.prod.yml`'s `app`
   service.

4. **Also nothing to do here** — `docker-compose.prod.yml` hardcodes
   `ENVIRONMENT: production`, same reasoning as step 3: it's
   unconditionally correct for this file, and putting it in the shared
   `.env` instead would flip the *dev* stack's cookies to `Secure` too
   (`app/config.py`'s `cookie_secure`), which plain-HTTP dev traffic
   can't carry — browsers silently drop them.

5. **Set `ALLOWED_ORIGINS` in `.env`** to the real origin you'll serve
   this on (e.g. `https://your-domain.example`). Same-origin requests
   (frontend and API both behind the same `nginx`) don't strictly need
   CORS to succeed, but the value should still reflect reality rather
   than the dev default (`http://localhost:3000`).

## Running it

```
docker compose -p asm-prod -f docker-compose.prod.yml up -d --build
```

The explicit `-p asm-prod` matters if `docker-compose.yml`'s dev stack
might ever be running on the same host: Compose's project name defaults
to the directory name regardless of which `-f` file you pass, so without
`-p` this would collide with the dev stack's containers/network (same
project name `asm`) instead of standing up a separate one. Discovered
empirically while verifying this file, not assumed — see the note in the
prod compose file if the two stacks need to run side by side for
verification again.

First run against a fresh volume also needs migrations:
```
docker exec asm-prod-app-1 alembic -c alembic.ini upgrade head
```

## Known gaps, deliberately out of scope for this pass

- **No real CA-issued cert / ACME automation.** Self-signed only, by
  explicit choice (no domain exists yet) — see step 2 above for the
  swap-in path when one does.
- **FastAPI's `/docs`, `/redoc`, `/openapi.json` are still reachable**
  through `nginx` in this config, same as `app` always exposed them.
  Worth reconsidering before a real public launch; not changed here
  since it wasn't part of this batch's scope.
- **No CI/CD pipeline** building/pushing these images — deployment here
  still means running `docker compose` by hand on the target host.
