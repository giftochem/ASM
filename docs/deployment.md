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
  of an API response. Some SPA pages share paths with the API (`/assets`,
  `/assets/<id>`, `/alerts`, `/scans`, `/scans/<id>`, `/findings`,
  `/reports`): a browser page load of one of those (GET/HEAD with an
  `Accept` that includes `text/html`) gets the SPA; every other request
  to those paths still reaches the API. The build puts its JS/CSS under
  `/static/`, never `/assets/` (the API's prefix). After changing the
  config, run `sh docker/nginx/test-routing.sh` — it checks the real
  config in the real image against a stub API (needs Docker and the
  certificates from step 2 below).
- `nginx` sits on `asm_net` at a pinned address (`172.28.0.10`), which
  `app`'s `TRUSTED_PROXY_IPS_RAW` names deterministically (hardcoded in
  this file — see the comment on `app`'s `environment:` block).
- `nginx` publishes ports 80/443 on `127.0.0.1` only: by default the
  stack is reachable from this machine and nothing else. See
  [Exposing it beyond this machine](#exposing-it-beyond-this-machine).
- There is no `beat` service, so discovery schedules are never dispatched
  automatically in this configuration (a manual "Run now" is still
  executed by `worker`). Scheduled monitoring needs `beat`, which only
  `docker-compose.yml` runs today.

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
   Self-signed, `CN=localhost`, valid 365 days — for local testing only.
   Browsers will show a trust warning, which is expected. Output
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
   `ENVIRONMENT: production` on both `app` and `worker` (the worker's
   test-only discovery provider gate depends on it), same reasoning as
   step 3: it's unconditionally correct for this file, and putting it in
   the shared `.env` instead would flip the *dev* stack's cookies to
   `Secure` too (`app/config.py`'s `cookie_secure`), which plain-HTTP dev
   traffic can't carry — browsers silently drop them.

5. **Give production its own `.env` — never the development one.** Both
   compose files read `./.env` from the directory they're run in, so
   starting this file from your development checkout reuses the dev
   `JWT_SECRET_KEY` and database password. Run production from a
   separate checkout or export of the release commit (e.g.
   `git archive <commit> | tar -x -C ../asm-release`), do steps 1–2 and
   everything below from that directory, and create its `.env` from
   `.env.example` with new values for `JWT_SECRET_KEY`,
   `POSTGRES_PASSWORD` (and the matching `DATABASE_URL`), plus
   `ALLOWED_ORIGINS` set to the origin you serve (`https://localhost`
   for the default loopback setup). The database password is fixed when
   a volume is first initialized: changing `POSTGRES_PASSWORD` later
   doesn't change it, and reusing a project name (`-p asm-prod`) reuses
   that project's existing volume.

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

The app is then at `https://localhost`, on this machine only.

## Exposing it beyond this machine

Not recommended for this beta. Before publishing it on any network:

- **Self-registration is open.** Anyone who can reach the instance can
  create an organization and its admin account, attest authorization for
  targets of their choosing, and run discovery from this host. Keep it
  to trusted networks; it is not safe to expose to the internet.
- Replace the self-signed certificate with one for the real hostname
  (step 2), and consider the `/docs` gap below.
- On Docker Desktop for Windows, Windows Firewall commonly has an allow
  rule for Docker's backend covering every port, including on Public
  networks, so anything published on all interfaces is reachable from
  the network — the loopback binding is what keeps the default setup
  local.

Then publish nginx on all interfaces with an extra, uncommitted Compose
file passed as a second `-f` (`!override` replaces the port list rather
than appending to it):
```yaml
services:
  nginx:
    ports: !override
      - "80:80"
      - "443:443"
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
